/* DO NOT EDIT
	This filter was automatically generated
	from wkssvc.idl and wkssvc.cnf.

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
#include "packet-dcerpc-wkssvc.h"

void proto_register_dcerpc_wkssvc(void);
void proto_reg_handoff_dcerpc_wkssvc(void);

/* Ett declarations */
static gint ett_dcerpc_wkssvc = -1;
static gint ett_wkssvc_lsa_String = -1;
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
static gint ett_wkssvc_wkssvc_NetWkstaInfo1028 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo1032 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo1033 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo1041 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo1042 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo1043 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo1044 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo1045 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo1046 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo1047 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo1048 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo1049 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo1050 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo1051 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo1052 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo1053 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo1054 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo1055 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo1056 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo1057 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo1058 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo1059 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo1060 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo1061 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo1062 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo = -1;
static gint ett_wkssvc_wkssvc_NetrWkstaUserInfo0 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaEnumUsersCtr0 = -1;
static gint ett_wkssvc_wkssvc_NetrWkstaUserInfo1 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaEnumUsersCtr1 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaEnumUsersCtr = -1;
static gint ett_wkssvc_wkssvc_NetWkstaEnumUsersInfo = -1;
static gint ett_wkssvc_wkssvc_NetrWkstaUserInfo1101 = -1;
static gint ett_wkssvc_wkssvc_NetrWkstaUserInfo = -1;
static gint ett_wkssvc_wkssvc_NetWkstaTransportInfo0 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaTransportCtr0 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaTransportCtr = -1;
static gint ett_wkssvc_wkssvc_NetWkstaTransportInfo = -1;
static gint ett_wkssvc_wkssvc_NetrUseInfo3 = -1;
static gint ett_wkssvc_wkssvc_NetrUseInfo2 = -1;
static gint ett_wkssvc_wkssvc_NetrUseInfo1 = -1;
static gint ett_wkssvc_wkssvc_NetrUseInfo0 = -1;
static gint ett_wkssvc_wkssvc_NetrUseGetInfoCtr = -1;
static gint ett_wkssvc_wkssvc_NetrUseEnumCtr2 = -1;
static gint ett_wkssvc_wkssvc_NetrUseEnumCtr1 = -1;
static gint ett_wkssvc_wkssvc_NetrUseEnumCtr0 = -1;
static gint ett_wkssvc_wkssvc_NetrUseEnumCtr = -1;
static gint ett_wkssvc_wkssvc_NetrUseEnumInfo = -1;
static gint ett_wkssvc_wkssvc_NetrWorkstationStatistics = -1;
static gint ett_wkssvc_wkssvc_renameflags = -1;
static gint ett_wkssvc_wkssvc_PasswordBuffer = -1;
static gint ett_wkssvc_wkssvc_joinflags = -1;
static gint ett_wkssvc_wkssvc_ComputerNamesCtr = -1;


/* Header field declarations */
static gint hf_wkssvc_wkssvc_NetrUseInfo2_use_count = -1;
static gint hf_wkssvc_wkssvc_NetWkstaTransportInfo0_quality_of_service = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1045_pipe_maximum = -1;
static gint hf_wkssvc_wkssvc_NetrUseInfo2_password = -1;
static gint hf_wkssvc_wkssvc_NetrJoinDomain2_join_flags = -1;
static gint hf_wkssvc_wkssvc_NetrUseEnumCtr_ctr1 = -1;
static gint hf_wkssvc_wkssvc_NetrWkstaUserSetInfo_level = -1;
static gint hf_wkssvc_wkssvc_NetrUseEnum_entries_read = -1;
static gint hf_wkssvc_wkssvc_NetrSetPrimaryComputername_EncryptedPassword = -1;
static gint hf_wkssvc_wkssvc_NetrWkstaUserSetInfo_parm_err = -1;
static gint hf_wkssvc_wkssvc_NetrUseEnum_info = -1;
static gint hf_wkssvc_wkssvc_NetrSetPrimaryComputername_Account = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown14 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaEnumUsersCtr_user0 = -1;
static gint hf_wkssvc_wkssvc_NetrGetJoinableOus_domain_name = -1;
static gint hf_wkssvc_wkssvc_NetrUseInfo2_user_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo101_version_major = -1;
static gint hf_wkssvc_wkssvc_NetrWkstaUserInfo1_other_domains = -1;
static gint hf_wkssvc_wkssvc_NetrGetJoinableOus_Account = -1;
static gint hf_wkssvc_wkssvc_NetWkstaTransportCtr_ctr0 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_dgram_event_reset_freq = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo102_lan_root = -1;
static gint hf_wkssvc_wkssvc_NetrWkstaUserInfo1_user_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info502 = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown32 = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown29 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1055_use_raw_write = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1051 = -1;
static gint hf_wkssvc_wkssvc_NetrValidateName2_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_dormant_file_limit = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_maximum_collection_count = -1;
static gint hf_wkssvc_wkssvc_NetrMessageBufferSend_server_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_use_write_raw_data = -1;
static gint hf_wkssvc_wkssvc_NetrEnumerateComputerNames_Reserved = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_size_char_buf = -1;
static gint hf_wkssvc_wkssvc_NetWkstaTransportCtr0_array = -1;
static gint hf_wkssvc_wkssvc_NetrEnumerateComputerNames_name_type = -1;
static gint hf_wkssvc_wkssvc_NetrUseAdd_parm_err = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown9 = -1;
static gint hf_wkssvc_wkssvc_NetrGetJoinableOus2_num_ous = -1;
static gint hf_wkssvc_wkssvc_NetrRenameMachineInDomain_server_name = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown38 = -1;
static gint hf_wkssvc_wkssvc_NetrWkstaUserInfo1101_other_domains = -1;
static gint hf_wkssvc_wkssvc_NetWkstaGetInfo_level = -1;
static gint hf_wkssvc_wkssvc_NetrUseInfo1_ref_count = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown4 = -1;
static gint hf_wkssvc_wkssvc_NetrJoinDomain2_domain_name = -1;
static gint hf_wkssvc_wkssvc_NetrUseEnumCtr_ctr2 = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown3 = -1;
static gint hf_wkssvc_wkssvc_NetrJoinDomain_join_flags = -1;
static gint hf_wkssvc_wkssvc_NetrUseDel_use_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_buf_files_deny_write = -1;
static gint hf_wkssvc_wkssvc_NetrUseGetInfo_use_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1060 = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatisticsGet_unknown4 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1057 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaTransportInfo_level = -1;
static gint hf_wkssvc_wkssvc_NetWkstaTransportInfo0_name = -1;
static gint hf_wkssvc_wkssvc_NetrUseEnumCtr1_array = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown20 = -1;
static gint hf_wkssvc_wkssvc_NetrUseEnum_server_name = -1;
static gint hf_wkssvc_lsa_String_name_size = -1;
static gint hf_wkssvc_wkssvc_NetWkstaEnumUsersCtr1_entries_read = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown37 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1058 = -1;
static gint hf_wkssvc_lsa_String_name_len = -1;
static gint hf_wkssvc_wkssvc_NetrUseGetInfo_server_name = -1;
static gint hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_ACCOUNT_DELETE = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1043_lock_maximum = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown24 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo102_domain_name = -1;
static gint hf_wkssvc_wkssvc_NetrUseDel_force_cond = -1;
static gint hf_wkssvc_wkssvc_NetWkstaEnumUsers_resume_handle = -1;
static gint hf_wkssvc_wkssvc_NetrUseEnumCtr0_count = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1053_utilize_nt_caching = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_num_srv_announce_buffers = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo100_platform_id = -1;
static gint hf_wkssvc_wkssvc_NetrSetPrimaryComputername_primary_name = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown36 = -1;
static gint hf_wkssvc_wkssvc_NetrUseGetInfoCtr_info0 = -1;
static gint hf_wkssvc_wkssvc_NetrUseGetInfo_ctr = -1;
static gint hf_wkssvc_wkssvc_NetrUseInfo3_unknown2 = -1;
static gint hf_wkssvc_wkssvc_NetrWkstaUserInfo_info1 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1048_use_opportunistic_locking = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown27 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaTransportInfo0_vc_count = -1;
static gint hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_EncryptedPassword = -1;
static gint hf_wkssvc_wkssvc_NetrAddAlternateComputerName_Account = -1;
static gint hf_wkssvc_wkssvc_NetrWkstaUserGetInfo_info = -1;
static gint hf_wkssvc_wkssvc_NetWkstaEnumUsers_entries_read = -1;
static gint hf_wkssvc_wkssvc_NetWkstaEnumUsers_prefmaxlen = -1;
static gint hf_wkssvc_wkssvc_NetrWkstaUserInfo1_logon_domain = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown16 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_log_election_packets = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_use_raw_read = -1;
static gint hf_wkssvc_wkssvc_NetrGetJoinableOus_unknown = -1;
static gint hf_wkssvc_wkssvc_NetrSetPrimaryComputername_Reserved = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1027_errorlog_sz = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1052 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1012_maximum_collection_count = -1;
static gint hf_wkssvc_wkssvc_NetrJoinDomain2_admin_account = -1;
static gint hf_wkssvc_wkssvc_NetrUseEnumCtr_ctr0 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1050_use_close_behind = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_use_unlock_behind = -1;
static gint hf_wkssvc_wkssvc_NetWkstaEnumUsersCtr_user1 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo102_version_minor = -1;
static gint hf_wkssvc_wkssvc_ComputerNamesCtr_count = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1048 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1018_session_timeout = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_keep_connection = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown31 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_max_commands = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_lock_quota = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown40 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1033_max_threads = -1;
static gint hf_wkssvc_wkssvc_NetrUseAdd_level = -1;
static gint hf_wkssvc_wkssvc_renameflags_WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown25 = -1;
static gint hf_wkssvc_wkssvc_NetrUseDel_server_name = -1;
static gint hf_wkssvc_wkssvc_NetrWkstaUserInfo1_logon_server = -1;
static gint hf_wkssvc_wkssvc_PasswordBuffer_data = -1;
static gint hf_wkssvc_wkssvc_NetrUseInfo3_unknown1 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_cache_file_timeout = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_num_mailslot_buffers = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1055 = -1;
static gint hf_wkssvc_wkssvc_NetrRenameMachineInDomain_password = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown13 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_utilize_nt_caching = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1061_use_512_byte_max_transfer = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatisticsGet_info = -1;
static gint hf_wkssvc_wkssvc_NetWkstaSetInfo_server_name = -1;
static gint hf_wkssvc_wkssvc_NetrJoinDomain2_encrypted_password = -1;
static gint hf_wkssvc_wkssvc_NetrUseEnum_prefmaxlen = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown2 = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatisticsGet_server_name = -1;
static gint hf_wkssvc_wkssvc_NetrWkstaTransportDel_server_name = -1;
static gint hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_DEFER_SPN = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1010_char_wait = -1;
static gint hf_wkssvc_wkssvc_NetrRenameMachineInDomain_RenameOptions = -1;
static gint hf_wkssvc_wkssvc_NetWkstaEnumUsers_server_name = -1;
static gint hf_wkssvc_wkssvc_NetrRenameMachineInDomain_Account = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown23 = -1;
static gint hf_wkssvc_wkssvc_NetrUseEnumInfo_ctr = -1;
static gint hf_wkssvc_wkssvc_NetWkstaEnumUsersInfo_ctr = -1;
static gint hf_wkssvc_wkssvc_NetWkstaEnumUsersCtr0_user0 = -1;
static gint hf_wkssvc_lsa_String_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_buf_read_only_files = -1;
static gint hf_wkssvc_wkssvc_NetrUnjoinDomain_server_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo101_lan_root = -1;
static gint hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_JOIN_TYPE = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_buf_named_pipes = -1;
static gint hf_wkssvc_wkssvc_NetrUseInfo2_ref_count = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1044_pipe_increment = -1;
static gint hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_DOMAIN_JOIN_IF_JOINED = -1;
static gint hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_AlternateMachineNameToRemove = -1;
static gint hf_wkssvc_wkssvc_NetrUseEnumCtr2_array = -1;
static gint hf_wkssvc_wkssvc_NetWkstaGetInfo_info = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_max_illegal_dgram_events = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1047 = -1;
static gint hf_wkssvc_wkssvc_NetrValidateName_Password = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1028_print_buf_time = -1;
static gint hf_wkssvc_wkssvc_NetrUseGetInfoCtr_info3 = -1;
static gint hf_wkssvc_wkssvc_NetrGetJoinableOus2_Account = -1;
static gint hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_RenameOptions = -1;
static gint hf_wkssvc_wkssvc_NetrWkstaUserInfo_info1101 = -1;
static gint hf_wkssvc_wkssvc_NetrJoinDomain2_account_name = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown17 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1013 = -1;
static gint hf_wkssvc_wkssvc_NetrValidateName2_server_name = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown34 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1018 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaEnumUsersCtr0_entries_read = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1057_use_encryption = -1;
static gint hf_wkssvc_wkssvc_NetrUseInfo1_status = -1;
static gint hf_wkssvc_wkssvc_NetWkstaTransportInfo0_wan_link = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown35 = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown7 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaSetInfo_parm_error = -1;
static gint hf_wkssvc_wkssvc_NetrUseInfo0_remote = -1;
static gint hf_wkssvc_wkssvc_NetrWkstaUserInfo_info0 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1060_force_core_create_mode = -1;
static gint hf_wkssvc_wkssvc_NetrWkstaUserInfo0_user_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info101 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaTransportInfo0_address = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown39 = -1;
static gint hf_wkssvc_wkssvc_NetrUseEnumCtr2_count = -1;
static gint hf_wkssvc_wkssvc_NetrGetJoinInformation_name_buffer = -1;
static gint hf_wkssvc_wkssvc_NetrRenameMachineInDomain_NewMachineName = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_lock_maximum = -1;
static gint hf_wkssvc_wkssvc_NetrUnjoinDomain_Account = -1;
static gint hf_wkssvc_wkssvc_NetrWkstaUserGetInfo_level = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1049 = -1;
static gint hf_wkssvc_wkssvc_NetrGetJoinableOus_num_ous = -1;
static gint hf_wkssvc_wkssvc_NetrUseInfo2_asg_type = -1;
static gint hf_wkssvc_wkssvc_NetrUseInfo1_password = -1;
static gint hf_wkssvc_wkssvc_NetrJoinDomain_unknown = -1;
static gint hf_wkssvc_wkssvc_NetrUseInfo1_local = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1054_use_raw_read = -1;
static gint hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_server_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1023_size_char_buf = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo100_domain_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaTransportEnum_max_buffer = -1;
static gint hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_JOIN_DC_ACCOUNT = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1042 = -1;
static gint hf_wkssvc_wkssvc_NetrWkstaUserSetInfo_unknown = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1045 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1011 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1049_use_unlock_behind = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1062_read_ahead_throughput = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1056_use_write_raw_data = -1;
static gint hf_wkssvc_wkssvc_NetrWkstaTransportAdd_info0 = -1;
static gint hf_wkssvc_wkssvc_NetrValidateName_name = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown18 = -1;
static gint hf_wkssvc_wkssvc_NetrMessageBufferSend_message_size = -1;
static gint hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_JOIN_UNSECURE = -1;
static gint hf_wkssvc_wkssvc_ComputerNamesCtr_computer_name = -1;
static gint hf_wkssvc_wkssvc_NetrValidateName2_name_type = -1;
static gint hf_wkssvc_wkssvc_NetrValidateName2_Account = -1;
static gint hf_wkssvc_wkssvc_NetrGetJoinableOus_server_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaTransportEnum_total_entries = -1;
static gint hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_WIN9X_UPGRADE = -1;
static gint hf_wkssvc_wkssvc_NetrValidateName2_EncryptedPassword = -1;
static gint hf_wkssvc_wkssvc_NetrWkstaTransportDel_unknown3 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1062 = -1;
static gint hf_wkssvc_wkssvc_NetrWkstaUserGetInfo_unknown = -1;
static gint hf_wkssvc_wkssvc_NetrAddAlternateComputerName_server_name = -1;
static gint hf_wkssvc_wkssvc_NetrJoinDomain2_server_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info102 = -1;
static gint hf_wkssvc_wkssvc_NetrJoinDomain_Account = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1046_dormant_file_limit = -1;
static gint hf_wkssvc_wkssvc_NetrWkstaTransportAdd_parm_err = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo102_version_major = -1;
static gint hf_wkssvc_platform_id = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown22 = -1;
static gint hf_wkssvc_wkssvc_NetrUseInfo1_use_count = -1;
static gint hf_wkssvc_wkssvc_NetrUnjoinDomain2_server_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_use_512_byte_max_transfer = -1;
static gint hf_wkssvc_wkssvc_NetWkstaTransportEnum_info = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1033 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1046 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaSetInfo_info = -1;
static gint hf_wkssvc_wkssvc_NetrMessageBufferSend_message_sender_name = -1;
static gint hf_wkssvc_wkssvc_NetrUseInfo1_remote = -1;
static gint hf_wkssvc_wkssvc_NetrUseInfo2_domain_name = -1;
static gint hf_wkssvc_wkssvc_NetrUseEnumCtr1_count = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1047_cache_file_timeout = -1;
static gint hf_wkssvc_wkssvc_NetrUseGetInfoCtr_info2 = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown30 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1028 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info100 = -1;
static gint hf_wkssvc_wkssvc_NetrLogonDomainNameDel_domain_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1013_keep_connection = -1;
static gint hf_wkssvc_wkssvc_NetrEnumerateComputerNames_server_name = -1;
static gint hf_wkssvc_wkssvc_NetrWkstaUserSetInfo_info = -1;
static gint hf_wkssvc_wkssvc_NetrMessageBufferSend_message_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_session_timeout = -1;
static gint hf_wkssvc_wkssvc_NetrUseEnumCtr0_array = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown6 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaTransportInfo_ctr = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_collection_time = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1054 = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown10 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1032_wrk_heuristics = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo101_version_minor = -1;
static gint hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_MACHINE_PWD_PASSED = -1;
static gint hf_wkssvc_wkssvc_NetrWkstaTransportAdd_level = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown33 = -1;
static gint hf_wkssvc_wkssvc_NetrEnumerateComputerNames_ctr = -1;
static gint hf_wkssvc_wkssvc_NetWkstaTransportEnum_server_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_max_threads = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1042_lock_increment = -1;
static gint hf_wkssvc_wkssvc_NetrUseGetInfo_level = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1050 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_lock_increment = -1;
static gint hf_wkssvc_wkssvc_NetrUseInfo2_local = -1;
static gint hf_wkssvc_wkssvc_NetrValidateName_server_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1041 = -1;
static gint hf_wkssvc_wkssvc_NetrUseInfo2_status = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown12 = -1;
static gint hf_wkssvc_wkssvc_NetrJoinDomain_account_ou = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatisticsGet_unknown3 = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown19 = -1;
static gint hf_wkssvc_wkssvc_NetrAddAlternateComputerName_EncryptedPassword = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1058_buf_files_deny_write = -1;
static gint hf_wkssvc_wkssvc_NetrUnjoinDomain2_account = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatisticsGet_unknown2 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1043 = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown21 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo102_server_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_use_encryption = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1059 = -1;
static gint hf_wkssvc_wkssvc_NetrValidateName_name_type = -1;
static gint hf_wkssvc_wkssvc_NetrMessageBufferSend_message_buffer = -1;
static gint hf_wkssvc_wkssvc_NetWkstaTransportCtr0_count = -1;
static gint hf_wkssvc_wkssvc_NetrUseEnumInfo_level = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1041_lock_quota = -1;
static gint hf_wkssvc_wkssvc_NetrUseAdd_ctr = -1;
static gint hf_wkssvc_wkssvc_NetrUseEnum_resume_handle = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo100_version_major = -1;
static gint hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_Reserved = -1;
static gint hf_wkssvc_wkssvc_NetrUseAdd_server_name = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown11 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1012 = -1;
static gint hf_wkssvc_wkssvc_NetrUnjoinDomain_password = -1;
static gint hf_wkssvc_werror = -1;
static gint hf_wkssvc_wkssvc_NetrGetJoinableOus2_domain_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_pipe_increment = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1044 = -1;
static gint hf_wkssvc_wkssvc_NetrGetJoinableOus2_EncryptedPassword = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1010 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1051_buf_named_pipes = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_read_ahead_throughput = -1;
static gint hf_wkssvc_wkssvc_NetrGetJoinableOus_ous = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown5 = -1;
static gint hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_NewMachineName = -1;
static gint hf_wkssvc_wkssvc_NetrWkstaTransportDel_transport_name = -1;
static gint hf_wkssvc_wkssvc_NetrUseInfo0_local = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_use_raw_write = -1;
static gint hf_wkssvc_wkssvc_NetrGetJoinableOus2_ous = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo101_server_name = -1;
static gint hf_wkssvc_wkssvc_NetrGetJoinableOus2_server_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1059_buf_read_only_files = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo100_version_minor = -1;
static gint hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_use_close_behind = -1;
static gint hf_wkssvc_opnum = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_force_core_create_mode = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1011_collection_time = -1;
static gint hf_wkssvc_wkssvc_NetrGetJoinInformation_server_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo101_domain_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1061 = -1;
static gint hf_wkssvc_wkssvc_NetrUseGetInfoCtr_info1 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaEnumUsersInfo_level = -1;
static gint hf_wkssvc_wkssvc_NetrSetPrimaryComputername_server_name = -1;
static gint hf_wkssvc_wkssvc_NetrUnjoinDomain_unjoin_flags = -1;
static gint hf_wkssvc_wkssvc_NetWkstaTransportEnum_resume_handle = -1;
static gint hf_wkssvc_wkssvc_NetrJoinDomain_server_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo102_platform_id = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown8 = -1;
static gint hf_wkssvc_wkssvc_NetrAddAlternateComputerName_Reserved = -1;
static gint hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_JOIN_WITH_NEW_NAME = -1;
static gint hf_wkssvc_wkssvc_NetrWkstaTransportAdd_server_name = -1;
static gint hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_server_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo101_platform_id = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_use_opportunistic_locking = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo100_server_name = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown28 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaEnumUsersCtr1_user1 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaGetInfo_server_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1023 = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown15 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_use_lock_read_unlock = -1;
static gint hf_wkssvc_wkssvc_NetrUseInfo1_asg_type = -1;
static gint hf_wkssvc_wkssvc_NetrUnjoinDomain2_unjoin_flags = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown1 = -1;
static gint hf_wkssvc_wkssvc_NetrLogonDomainNameAdd_domain_name = -1;
static gint hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown26 = -1;
static gint hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_Account = -1;
static gint hf_wkssvc_wkssvc_NetWkstaEnumUsers_info = -1;
static gint hf_wkssvc_wkssvc_NetrGetJoinInformation_name_type = -1;
static gint hf_wkssvc_wkssvc_NetrAddAlternateComputerName_NewAlternateMachineName = -1;
static gint hf_wkssvc_wkssvc_NetrUnjoinDomain2_encrypted_password = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_char_wait = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_pipe_maximum = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1027 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1052_use_lock_read_unlock = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1056 = -1;
static gint hf_wkssvc_wkssvc_NetrValidateName_Account = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1032 = -1;
static gint hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_Account = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1053 = -1;
static gint hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_EncryptedPassword = -1;
static gint hf_wkssvc_wkssvc_NetWkstaSetInfo_level = -1;
static gint hf_wkssvc_wkssvc_NetrJoinDomain_domain_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo102_logged_on_users = -1;
static gint hf_wkssvc_wkssvc_NetrUseInfo2_remote = -1;

static gint proto_dcerpc_wkssvc = -1;
/* Version information */


static e_guid_t uuid_dcerpc_wkssvc = {
	0x6bffd098, 0xa112, 0x3610,
	{ 0x98, 0x33, 0x46, 0xc3, 0xf8, 0x7e, 0x34, 0x5a }
};
static guint16 ver_dcerpc_wkssvc = 1;

static int wkssvc_dissect_element_lsa_String_name_len(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_lsa_String_name_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_lsa_String_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_lsa_String_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo100_platform_id(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo100_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo100_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo100_domain_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo100_domain_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo100_version_major(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo100_version_minor(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo101_platform_id(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo101_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo101_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo101_domain_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo101_domain_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo101_version_major(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo101_version_minor(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo101_lan_root(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo101_lan_root_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo102_platform_id(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo102_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo102_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo102_domain_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo102_domain_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo102_version_major(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo102_version_minor(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo102_lan_root(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo102_lan_root_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo102_logged_on_users(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_char_wait(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_collection_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_maximum_collection_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_keep_connection(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_max_commands(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_session_timeout(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_size_char_buf(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_max_threads(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_lock_quota(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_lock_increment(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_lock_maximum(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_pipe_increment(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_pipe_maximum(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_cache_file_timeout(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_dormant_file_limit(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_read_ahead_throughput(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_num_mailslot_buffers(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_num_srv_announce_buffers(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_max_illegal_dgram_events(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_dgram_event_reset_freq(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_log_election_packets(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_use_opportunistic_locking(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_use_unlock_behind(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_use_close_behind(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_buf_named_pipes(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_use_lock_read_unlock(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_utilize_nt_caching(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_use_raw_read(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_use_raw_write(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_use_write_raw_data(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_use_encryption(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_buf_files_deny_write(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_buf_read_only_files(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_force_core_create_mode(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo502_use_512_byte_max_transfer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo1010_char_wait(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo1011_collection_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo1012_maximum_collection_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo1013_keep_connection(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo1018_session_timeout(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo1023_size_char_buf(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo1027_errorlog_sz(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo1028_print_buf_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo1032_wrk_heuristics(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo1033_max_threads(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo1041_lock_quota(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo1042_lock_increment(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo1043_lock_maximum(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo1044_pipe_increment(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo1045_pipe_maximum(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo1046_dormant_file_limit(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo1047_cache_file_timeout(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo1048_use_opportunistic_locking(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo1049_use_unlock_behind(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo1050_use_close_behind(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo1051_buf_named_pipes(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo1052_use_lock_read_unlock(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo1053_utilize_nt_caching(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo1054_use_raw_read(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo1055_use_raw_write(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo1056_use_write_raw_data(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo1057_use_encryption(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo1058_buf_files_deny_write(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo1059_buf_read_only_files(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo1060_force_core_create_mode(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo1061_use_512_byte_max_transfer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo1062_read_ahead_throughput(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info100(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info100_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info101(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info101_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info102(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info102_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info502(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info502_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1010(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1010_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1011(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1011_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1012(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1012_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1013(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1013_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1018(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1018_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1023(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1023_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1027(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1027_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1028(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1028_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1032(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1032_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1033(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1033_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1041(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1041_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1042(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1042_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1043(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1043_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1044(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1044_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1045(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1045_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1046(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1046_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1047(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1047_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1048(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1048_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1049(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1049_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1050(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1050_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1051(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1051_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1052(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1052_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1053(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1053_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1054(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1054_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1055(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1055_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1056(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1056_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1057(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1057_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1058(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1058_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1059(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1059_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1060(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1060_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1061(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1061_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1062(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaInfo_info1062_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaUserInfo0_user_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaUserInfo0_user_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaEnumUsersCtr0_entries_read(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaEnumUsersCtr0_user0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaEnumUsersCtr0_user0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaEnumUsersCtr0_user0__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaUserInfo1_user_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaUserInfo1_user_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaUserInfo1_logon_domain(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaUserInfo1_logon_domain_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaUserInfo1_other_domains(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaUserInfo1_other_domains_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaUserInfo1_logon_server(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaUserInfo1_logon_server_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaEnumUsersCtr1_entries_read(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaEnumUsersCtr1_user1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaEnumUsersCtr1_user1_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaEnumUsersCtr1_user1__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaEnumUsersCtr_user0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaEnumUsersCtr_user0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaEnumUsersCtr_user1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaEnumUsersCtr_user1_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaEnumUsersInfo_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaEnumUsersInfo_ctr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaUserInfo1101_other_domains(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaUserInfo1101_other_domains_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaUserInfo_info0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaUserInfo_info0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaUserInfo_info1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaUserInfo_info1_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaUserInfo_info1101(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaUserInfo_info1101_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaTransportInfo0_quality_of_service(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaTransportInfo0_vc_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaTransportInfo0_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaTransportInfo0_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaTransportInfo0_address(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaTransportInfo0_address_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaTransportInfo0_wan_link(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaTransportCtr0_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaTransportCtr0_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaTransportCtr0_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaTransportCtr0_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaTransportCtr_ctr0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaTransportCtr_ctr0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaTransportInfo_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaTransportInfo_ctr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseInfo3_unknown1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseInfo3_unknown1_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseInfo3_unknown2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseInfo3_unknown2_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseInfo2_local(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseInfo2_local_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseInfo2_remote(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseInfo2_remote_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseInfo2_password(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseInfo2_password_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseInfo2_status(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseInfo2_asg_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseInfo2_ref_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseInfo2_use_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseInfo2_user_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseInfo2_user_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseInfo2_domain_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseInfo2_domain_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseInfo1_local(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseInfo1_local_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseInfo1_remote(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseInfo1_remote_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseInfo1_password(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseInfo1_password_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseInfo1_status(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseInfo1_asg_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseInfo1_ref_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseInfo1_use_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseInfo0_local(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseInfo0_local_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseInfo0_remote(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseInfo0_remote_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseGetInfoCtr_info0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseGetInfoCtr_info0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseGetInfoCtr_info1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseGetInfoCtr_info1_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseGetInfoCtr_info2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseGetInfoCtr_info2_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseGetInfoCtr_info3(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseGetInfoCtr_info3_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseEnumCtr2_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseEnumCtr2_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseEnumCtr2_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseEnumCtr2_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseEnumCtr1_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseEnumCtr1_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseEnumCtr1_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseEnumCtr1_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseEnumCtr0_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseEnumCtr0_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseEnumCtr0_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseEnumCtr0_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseEnumCtr_ctr0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseEnumCtr_ctr0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseEnumCtr_ctr1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseEnumCtr_ctr1_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseEnumCtr_ctr2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseEnumCtr_ctr2_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseEnumInfo_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseEnumInfo_ctr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown3(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown4(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown5(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown6(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown7(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown8(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown9(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown10(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown11(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown12(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown13(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown14(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown15(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown16(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown17(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown18(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown19(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown20(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown21(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown22(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown23(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown24(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown25(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown26(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown27(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown28(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown29(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown30(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown31(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown32(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown33(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown34(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown35(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown36(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown37(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown38(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown39(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatistics_unknown40(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static const true_false_string wkssvc_renameflags_WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE_tfs = {
   "WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE is SET",
   "WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE is NOT SET",
};
const value_string wkssvc_wkssvc_NetValidateNameType_vals[] = {
	{ NetSetupUnknown, "NetSetupUnknown" },
	{ NetSetupMachine, "NetSetupMachine" },
	{ NetSetupWorkgroup, "NetSetupWorkgroup" },
	{ NetSetupDomain, "NetSetupDomain" },
	{ NetSetupNonExistentDomain, "NetSetupNonExistentDomain" },
	{ NetSetupDnsMachine, "NetSetupDnsMachine" },
{ 0, NULL }
};
const value_string wkssvc_wkssvc_NetJoinStatus_vals[] = {
	{ NetSetupUnknownStatus, "NetSetupUnknownStatus" },
	{ NetSetupUnjoined, "NetSetupUnjoined" },
	{ NetSetupWorkgroupName, "NetSetupWorkgroupName" },
	{ NetSetupDomainName, "NetSetupDomainName" },
{ 0, NULL }
};
static int wkssvc_dissect_element_PasswordBuffer_data(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_PasswordBuffer_data_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static const true_false_string wkssvc_joinflags_WKSSVC_JOIN_FLAGS_JOIN_WITH_NEW_NAME_tfs = {
   "WKSSVC_JOIN_FLAGS_JOIN_WITH_NEW_NAME is SET",
   "WKSSVC_JOIN_FLAGS_JOIN_WITH_NEW_NAME is NOT SET",
};
static const true_false_string wkssvc_joinflags_WKSSVC_JOIN_FLAGS_JOIN_DC_ACCOUNT_tfs = {
   "WKSSVC_JOIN_FLAGS_JOIN_DC_ACCOUNT is SET",
   "WKSSVC_JOIN_FLAGS_JOIN_DC_ACCOUNT is NOT SET",
};
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
const value_string wkssvc_wkssvc_ComputerNameType_vals[] = {
	{ NetPrimaryComputerName, "NetPrimaryComputerName" },
	{ NetAlternateComputerNames, "NetAlternateComputerNames" },
	{ NetAllComputerNames, "NetAllComputerNames" },
	{ NetComputerNameTypeMax, "NetComputerNameTypeMax" },
{ 0, NULL }
};
static int wkssvc_dissect_element_ComputerNamesCtr_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_ComputerNamesCtr_computer_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_ComputerNamesCtr_computer_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_ComputerNamesCtr_computer_name__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaGetInfo_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaGetInfo_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaGetInfo_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaGetInfo_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaGetInfo_info_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaSetInfo_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaSetInfo_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaSetInfo_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaSetInfo_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaSetInfo_info_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaSetInfo_parm_error(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaSetInfo_parm_error_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaEnumUsers_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaEnumUsers_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaEnumUsers_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaEnumUsers_info_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaEnumUsers_prefmaxlen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaEnumUsers_entries_read(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaEnumUsers_entries_read_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaEnumUsers_resume_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaEnumUsers_resume_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaUserGetInfo_unknown(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaUserGetInfo_unknown_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaUserGetInfo_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaUserGetInfo_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaUserGetInfo_info_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaUserSetInfo_unknown(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaUserSetInfo_unknown_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaUserSetInfo_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaUserSetInfo_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaUserSetInfo_info_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaUserSetInfo_parm_err(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaUserSetInfo_parm_err_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaTransportEnum_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaTransportEnum_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaTransportEnum_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaTransportEnum_info_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaTransportEnum_max_buffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaTransportEnum_total_entries(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaTransportEnum_total_entries_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaTransportEnum_resume_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetWkstaTransportEnum_resume_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaTransportAdd_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaTransportAdd_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaTransportAdd_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaTransportAdd_info0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaTransportAdd_info0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaTransportAdd_parm_err(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaTransportAdd_parm_err_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaTransportDel_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaTransportDel_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaTransportDel_transport_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaTransportDel_transport_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWkstaTransportDel_unknown3(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseAdd_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseAdd_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseAdd_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseAdd_ctr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseAdd_ctr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseAdd_parm_err(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseAdd_parm_err_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseGetInfo_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseGetInfo_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseGetInfo_use_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseGetInfo_use_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseGetInfo_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseGetInfo_ctr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseGetInfo_ctr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseDel_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseDel_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseDel_use_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseDel_use_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseDel_force_cond(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseEnum_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseEnum_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseEnum_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseEnum_info_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseEnum_prefmaxlen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseEnum_entries_read(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseEnum_entries_read_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseEnum_resume_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUseEnum_resume_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrMessageBufferSend_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrMessageBufferSend_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrMessageBufferSend_message_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrMessageBufferSend_message_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrMessageBufferSend_message_sender_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrMessageBufferSend_message_sender_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrMessageBufferSend_message_buffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrMessageBufferSend_message_buffer_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrMessageBufferSend_message_buffer__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrMessageBufferSend_message_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatisticsGet_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatisticsGet_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatisticsGet_unknown2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatisticsGet_unknown2_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatisticsGet_unknown3(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatisticsGet_unknown4(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatisticsGet_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatisticsGet_info_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrWorkstationStatisticsGet_info__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrLogonDomainNameAdd_domain_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrLogonDomainNameAdd_domain_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrLogonDomainNameDel_domain_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrLogonDomainNameDel_domain_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrJoinDomain_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrJoinDomain_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrJoinDomain_domain_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrJoinDomain_domain_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrJoinDomain_account_ou(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrJoinDomain_account_ou_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrJoinDomain_Account(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrJoinDomain_Account_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrJoinDomain_unknown(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrJoinDomain_unknown_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrJoinDomain_join_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUnjoinDomain_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUnjoinDomain_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUnjoinDomain_Account(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUnjoinDomain_Account_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUnjoinDomain_password(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUnjoinDomain_password_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUnjoinDomain_unjoin_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrRenameMachineInDomain_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrRenameMachineInDomain_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrRenameMachineInDomain_NewMachineName(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrRenameMachineInDomain_NewMachineName_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrRenameMachineInDomain_Account(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrRenameMachineInDomain_Account_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrRenameMachineInDomain_password(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrRenameMachineInDomain_password_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrRenameMachineInDomain_RenameOptions(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrValidateName_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrValidateName_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrValidateName_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrValidateName_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrValidateName_Account(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrValidateName_Account_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrValidateName_Password(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrValidateName_Password_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrValidateName_name_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinInformation_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinInformation_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinInformation_name_buffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinInformation_name_buffer_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinInformation_name_buffer__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinInformation_name_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinInformation_name_type_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinableOus_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinableOus_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinableOus_domain_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinableOus_domain_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinableOus_Account(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinableOus_Account_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinableOus_unknown(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinableOus_unknown_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinableOus_num_ous(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinableOus_num_ous_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinableOus_ous(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinableOus_ous_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinableOus_ous__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinableOus_ous___(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinableOus_ous____(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrJoinDomain2_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrJoinDomain2_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrJoinDomain2_domain_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrJoinDomain2_domain_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrJoinDomain2_account_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrJoinDomain2_account_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrJoinDomain2_admin_account(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrJoinDomain2_admin_account_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrJoinDomain2_encrypted_password(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrJoinDomain2_encrypted_password_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrJoinDomain2_join_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUnjoinDomain2_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUnjoinDomain2_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUnjoinDomain2_account(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUnjoinDomain2_account_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUnjoinDomain2_encrypted_password(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUnjoinDomain2_encrypted_password_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrUnjoinDomain2_unjoin_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrRenameMachineInDomain2_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrRenameMachineInDomain2_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrRenameMachineInDomain2_NewMachineName(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrRenameMachineInDomain2_NewMachineName_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrRenameMachineInDomain2_Account(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrRenameMachineInDomain2_Account_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrRenameMachineInDomain2_EncryptedPassword(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrRenameMachineInDomain2_EncryptedPassword_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrRenameMachineInDomain2_RenameOptions(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrValidateName2_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrValidateName2_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrValidateName2_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrValidateName2_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrValidateName2_Account(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrValidateName2_Account_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrValidateName2_EncryptedPassword(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrValidateName2_EncryptedPassword_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrValidateName2_name_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinableOus2_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinableOus2_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinableOus2_domain_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinableOus2_domain_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinableOus2_Account(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinableOus2_Account_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinableOus2_EncryptedPassword(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinableOus2_EncryptedPassword_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinableOus2_num_ous(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinableOus2_num_ous_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinableOus2_ous(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinableOus2_ous_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinableOus2_ous__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinableOus2_ous___(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrGetJoinableOus2_ous____(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrAddAlternateComputerName_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrAddAlternateComputerName_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrAddAlternateComputerName_NewAlternateMachineName(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrAddAlternateComputerName_NewAlternateMachineName_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrAddAlternateComputerName_Account(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrAddAlternateComputerName_Account_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrAddAlternateComputerName_EncryptedPassword(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrAddAlternateComputerName_EncryptedPassword_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrAddAlternateComputerName_Reserved(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrRemoveAlternateComputerName_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrRemoveAlternateComputerName_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrRemoveAlternateComputerName_AlternateMachineNameToRemove(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrRemoveAlternateComputerName_AlternateMachineNameToRemove_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrRemoveAlternateComputerName_Account(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrRemoveAlternateComputerName_Account_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrRemoveAlternateComputerName_EncryptedPassword(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrRemoveAlternateComputerName_EncryptedPassword_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrRemoveAlternateComputerName_Reserved(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrSetPrimaryComputername_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrSetPrimaryComputername_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrSetPrimaryComputername_primary_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrSetPrimaryComputername_primary_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrSetPrimaryComputername_Account(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrSetPrimaryComputername_Account_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrSetPrimaryComputername_EncryptedPassword(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrSetPrimaryComputername_EncryptedPassword_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrSetPrimaryComputername_Reserved(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrEnumerateComputerNames_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrEnumerateComputerNames_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrEnumerateComputerNames_name_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrEnumerateComputerNames_Reserved(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrEnumerateComputerNames_ctr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrEnumerateComputerNames_ctr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int wkssvc_dissect_element_NetrEnumerateComputerNames_ctr__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
/* Bug in pidl.  Can not handle these dependencies properly yet */
static int
wkssvc_dissect_struct_srvsvc_PlatformId(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hf_index _U_, guint32 param _U_)
{
	offset = srvsvc_dissect_enum_PlatformId(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_platform_id,0);
	return offset;
}
static int
cnf_dissect_lsa_String(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, dcerpc_info *di, guint8 *drep, guint32 param, int hfindex)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;
	header_field_info *hf_info;
	ALIGN_TO_4_BYTES;
	old_offset = offset;
	hf_info=proto_registrar_get_nth(hfindex);
	if (parent_tree) {
		tree = proto_tree_add_subtree_format(parent_tree, tvb, offset, 0, ett_wkssvc_lsa_String, &item, "%s: ", hf_info->name);
	}
	
	offset = wkssvc_dissect_element_lsa_String_name_len(tvb, offset, pinfo, tree, di, drep);
	offset = wkssvc_dissect_element_lsa_String_name_size(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_ndr_pointer_cb(
		tvb, offset, pinfo, tree, di, drep,
		dissect_ndr_wchar_cvstring, NDR_POINTER_UNIQUE,
		hf_info->name, hfindex, cb_wstr_postprocess,
		GINT_TO_POINTER(param));
	proto_item_set_len(item, offset-old_offset);
	return offset;
}
static int
cnf_dissect_hyper(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, guint32 param _U_, int hfindex)
{
	offset = dissect_ndr_uint64(tvb, offset, pinfo, tree, di, drep, hfindex, NULL);
	return offset;
}


/* IDL: struct { */
/* IDL: 	[value(strlen_m_term(name)*2)] uint16 name_len; */
/* IDL: 	[value(strlen_m_term(name)*2)] uint16 name_size; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *name; */
/* IDL: } */

static int
wkssvc_dissect_element_lsa_String_name_len(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_lsa_String_name_len, 0);

	return offset;
}

static int
wkssvc_dissect_element_lsa_String_name_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_lsa_String_name_size, 0);

	return offset;
}

static int
wkssvc_dissect_element_lsa_String_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_lsa_String_name_, NDR_POINTER_UNIQUE, "Pointer to Name (uint16)",hf_wkssvc_lsa_String_name);

	return offset;
}

static int
wkssvc_dissect_element_lsa_String_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_lsa_String_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

int
wkssvc_dissect_struct_lsa_String(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_lsa_String);
	}
	
	offset = wkssvc_dissect_element_lsa_String_name_len(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_lsa_String_name_size(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_lsa_String_name(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	srvsvc_PlatformId platform_id; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *server_name; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *domain_name; */
/* IDL: 	uint32 version_major; */
/* IDL: 	uint32 version_minor; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo100_platform_id(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_srvsvc_PlatformId(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo100_platform_id,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo100_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo100_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetWkstaInfo100_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo100_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetWkstaInfo100_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo100_domain_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo100_domain_name_, NDR_POINTER_UNIQUE, "Pointer to Domain Name (uint16)",hf_wkssvc_wkssvc_NetWkstaInfo100_domain_name);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo100_domain_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetWkstaInfo100_domain_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo100_version_major(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo100_version_major, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo100_version_minor(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo100_version_minor, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo100(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
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
	
	offset = wkssvc_dissect_element_NetWkstaInfo100_platform_id(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo100_server_name(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo100_domain_name(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo100_version_major(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo100_version_minor(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	srvsvc_PlatformId platform_id; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *server_name; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *domain_name; */
/* IDL: 	uint32 version_major; */
/* IDL: 	uint32 version_minor; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *lan_root; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo101_platform_id(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_srvsvc_PlatformId(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo101_platform_id,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo101_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo101_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetWkstaInfo101_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo101_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetWkstaInfo101_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo101_domain_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo101_domain_name_, NDR_POINTER_UNIQUE, "Pointer to Domain Name (uint16)",hf_wkssvc_wkssvc_NetWkstaInfo101_domain_name);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo101_domain_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetWkstaInfo101_domain_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo101_version_major(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo101_version_major, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo101_version_minor(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo101_version_minor, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo101_lan_root(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo101_lan_root_, NDR_POINTER_UNIQUE, "Pointer to Lan Root (uint16)",hf_wkssvc_wkssvc_NetWkstaInfo101_lan_root);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo101_lan_root_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetWkstaInfo101_lan_root, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo101(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
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
	
	offset = wkssvc_dissect_element_NetWkstaInfo101_platform_id(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo101_server_name(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo101_domain_name(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo101_version_major(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo101_version_minor(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo101_lan_root(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	srvsvc_PlatformId platform_id; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *server_name; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *domain_name; */
/* IDL: 	uint32 version_major; */
/* IDL: 	uint32 version_minor; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *lan_root; */
/* IDL: 	uint32 logged_on_users; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo102_platform_id(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_srvsvc_PlatformId(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo102_platform_id,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo102_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo102_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetWkstaInfo102_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo102_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetWkstaInfo102_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo102_domain_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo102_domain_name_, NDR_POINTER_UNIQUE, "Pointer to Domain Name (uint16)",hf_wkssvc_wkssvc_NetWkstaInfo102_domain_name);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo102_domain_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetWkstaInfo102_domain_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo102_version_major(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo102_version_major, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo102_version_minor(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo102_version_minor, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo102_lan_root(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo102_lan_root_, NDR_POINTER_UNIQUE, "Pointer to Lan Root (uint16)",hf_wkssvc_wkssvc_NetWkstaInfo102_lan_root);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo102_lan_root_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetWkstaInfo102_lan_root, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo102_logged_on_users(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo102_logged_on_users, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo102(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
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
	
	offset = wkssvc_dissect_element_NetWkstaInfo102_platform_id(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo102_server_name(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo102_domain_name(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo102_version_major(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo102_version_minor(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo102_lan_root(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo102_logged_on_users(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
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
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo502_char_wait(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_char_wait, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_collection_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_collection_time, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_maximum_collection_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_maximum_collection_count, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_keep_connection(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_keep_connection, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_max_commands(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_max_commands, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_session_timeout(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_session_timeout, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_size_char_buf(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_size_char_buf, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_max_threads(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_max_threads, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_lock_quota(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_lock_quota, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_lock_increment(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_lock_increment, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_lock_maximum(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_lock_maximum, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_pipe_increment(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_pipe_increment, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_pipe_maximum(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_pipe_maximum, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_cache_file_timeout(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_cache_file_timeout, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_dormant_file_limit(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_dormant_file_limit, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_read_ahead_throughput(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_read_ahead_throughput, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_num_mailslot_buffers(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_num_mailslot_buffers, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_num_srv_announce_buffers(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_num_srv_announce_buffers, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_max_illegal_dgram_events(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_max_illegal_dgram_events, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_dgram_event_reset_freq(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_dgram_event_reset_freq, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_log_election_packets(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_log_election_packets, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_use_opportunistic_locking(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_use_opportunistic_locking, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_use_unlock_behind(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_use_unlock_behind, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_use_close_behind(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_use_close_behind, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_buf_named_pipes(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_buf_named_pipes, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_use_lock_read_unlock(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_use_lock_read_unlock, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_utilize_nt_caching(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_utilize_nt_caching, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_use_raw_read(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_use_raw_read, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_use_raw_write(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_use_raw_write, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_use_write_raw_data(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_use_write_raw_data, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_use_encryption(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_use_encryption, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_buf_files_deny_write(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_buf_files_deny_write, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_buf_read_only_files(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_buf_read_only_files, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_force_core_create_mode(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_force_core_create_mode, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_use_512_byte_max_transfer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_use_512_byte_max_transfer, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo502(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
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
	
	offset = wkssvc_dissect_element_NetWkstaInfo502_char_wait(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_collection_time(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_maximum_collection_count(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_keep_connection(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_max_commands(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_session_timeout(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_size_char_buf(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_max_threads(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_lock_quota(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_lock_increment(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_lock_maximum(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_pipe_increment(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_pipe_maximum(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_cache_file_timeout(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_dormant_file_limit(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_read_ahead_throughput(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_num_mailslot_buffers(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_num_srv_announce_buffers(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_max_illegal_dgram_events(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_dgram_event_reset_freq(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_log_election_packets(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_use_opportunistic_locking(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_use_unlock_behind(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_use_close_behind(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_buf_named_pipes(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_use_lock_read_unlock(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_utilize_nt_caching(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_use_raw_read(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_use_raw_write(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_use_write_raw_data(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_use_encryption(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_buf_files_deny_write(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_buf_read_only_files(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_force_core_create_mode(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_use_512_byte_max_transfer(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 char_wait; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo1010_char_wait(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo1010_char_wait, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1010(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
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
	
	offset = wkssvc_dissect_element_NetWkstaInfo1010_char_wait(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 collection_time; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo1011_collection_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo1011_collection_time, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1011(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
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
	
	offset = wkssvc_dissect_element_NetWkstaInfo1011_collection_time(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 maximum_collection_count; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo1012_maximum_collection_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo1012_maximum_collection_count, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1012(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
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
	
	offset = wkssvc_dissect_element_NetWkstaInfo1012_maximum_collection_count(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 keep_connection; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo1013_keep_connection(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo1013_keep_connection, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1013(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
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
	
	offset = wkssvc_dissect_element_NetWkstaInfo1013_keep_connection(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 session_timeout; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo1018_session_timeout(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo1018_session_timeout, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1018(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
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
	
	offset = wkssvc_dissect_element_NetWkstaInfo1018_session_timeout(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 size_char_buf; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo1023_size_char_buf(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo1023_size_char_buf, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1023(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
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
	
	offset = wkssvc_dissect_element_NetWkstaInfo1023_size_char_buf(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 errorlog_sz; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo1027_errorlog_sz(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo1027_errorlog_sz, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1027(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
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
	
	offset = wkssvc_dissect_element_NetWkstaInfo1027_errorlog_sz(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 print_buf_time; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo1028_print_buf_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo1028_print_buf_time, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1028(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo1028);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo1028_print_buf_time(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 wrk_heuristics; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo1032_wrk_heuristics(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo1032_wrk_heuristics, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1032(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo1032);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo1032_wrk_heuristics(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 max_threads; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo1033_max_threads(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo1033_max_threads, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1033(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
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
	
	offset = wkssvc_dissect_element_NetWkstaInfo1033_max_threads(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 lock_quota; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo1041_lock_quota(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo1041_lock_quota, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1041(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo1041);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo1041_lock_quota(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 lock_increment; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo1042_lock_increment(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo1042_lock_increment, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1042(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo1042);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo1042_lock_increment(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 lock_maximum; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo1043_lock_maximum(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo1043_lock_maximum, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1043(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo1043);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo1043_lock_maximum(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 pipe_increment; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo1044_pipe_increment(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo1044_pipe_increment, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1044(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo1044);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo1044_pipe_increment(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 pipe_maximum; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo1045_pipe_maximum(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo1045_pipe_maximum, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1045(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo1045);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo1045_pipe_maximum(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 dormant_file_limit; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo1046_dormant_file_limit(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo1046_dormant_file_limit, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1046(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo1046);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo1046_dormant_file_limit(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 cache_file_timeout; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo1047_cache_file_timeout(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo1047_cache_file_timeout, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1047(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo1047);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo1047_cache_file_timeout(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 use_opportunistic_locking; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo1048_use_opportunistic_locking(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo1048_use_opportunistic_locking, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1048(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo1048);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo1048_use_opportunistic_locking(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 use_unlock_behind; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo1049_use_unlock_behind(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo1049_use_unlock_behind, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1049(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo1049);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo1049_use_unlock_behind(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 use_close_behind; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo1050_use_close_behind(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo1050_use_close_behind, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1050(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo1050);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo1050_use_close_behind(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 buf_named_pipes; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo1051_buf_named_pipes(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo1051_buf_named_pipes, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1051(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo1051);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo1051_buf_named_pipes(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 use_lock_read_unlock; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo1052_use_lock_read_unlock(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo1052_use_lock_read_unlock, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1052(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo1052);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo1052_use_lock_read_unlock(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 utilize_nt_caching; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo1053_utilize_nt_caching(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo1053_utilize_nt_caching, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1053(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo1053);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo1053_utilize_nt_caching(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 use_raw_read; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo1054_use_raw_read(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo1054_use_raw_read, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1054(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo1054);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo1054_use_raw_read(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 use_raw_write; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo1055_use_raw_write(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo1055_use_raw_write, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1055(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo1055);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo1055_use_raw_write(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 use_write_raw_data; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo1056_use_write_raw_data(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo1056_use_write_raw_data, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1056(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo1056);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo1056_use_write_raw_data(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 use_encryption; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo1057_use_encryption(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo1057_use_encryption, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1057(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo1057);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo1057_use_encryption(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 buf_files_deny_write; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo1058_buf_files_deny_write(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo1058_buf_files_deny_write, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1058(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo1058);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo1058_buf_files_deny_write(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 buf_read_only_files; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo1059_buf_read_only_files(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo1059_buf_read_only_files, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1059(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo1059);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo1059_buf_read_only_files(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 force_core_create_mode; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo1060_force_core_create_mode(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo1060_force_core_create_mode, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1060(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo1060);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo1060_force_core_create_mode(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 use_512_byte_max_transfer; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo1061_use_512_byte_max_transfer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo1061_use_512_byte_max_transfer, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1061(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo1061);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo1061_use_512_byte_max_transfer(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 read_ahead_throughput; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo1062_read_ahead_throughput(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaInfo1062_read_ahead_throughput, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1062(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo1062);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo1062_read_ahead_throughput(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: union { */
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
/* IDL: [case(1028)] [unique(1)] [case(1028)] wkssvc_NetWkstaInfo1028 *info1028; */
/* IDL: [case(1032)] [unique(1)] [case(1032)] wkssvc_NetWkstaInfo1032 *info1032; */
/* IDL: [case(1033)] [unique(1)] [case(1033)] wkssvc_NetWkstaInfo1033 *info1033; */
/* IDL: [case(1041)] [unique(1)] [case(1041)] wkssvc_NetWkstaInfo1041 *info1041; */
/* IDL: [case(1042)] [unique(1)] [case(1042)] wkssvc_NetWkstaInfo1042 *info1042; */
/* IDL: [case(1043)] [unique(1)] [case(1043)] wkssvc_NetWkstaInfo1043 *info1043; */
/* IDL: [case(1044)] [unique(1)] [case(1044)] wkssvc_NetWkstaInfo1044 *info1044; */
/* IDL: [case(1045)] [unique(1)] [case(1045)] wkssvc_NetWkstaInfo1045 *info1045; */
/* IDL: [case(1046)] [unique(1)] [case(1046)] wkssvc_NetWkstaInfo1046 *info1046; */
/* IDL: [case(1047)] [unique(1)] [case(1047)] wkssvc_NetWkstaInfo1047 *info1047; */
/* IDL: [case(1048)] [unique(1)] [case(1048)] wkssvc_NetWkstaInfo1048 *info1048; */
/* IDL: [case(1049)] [unique(1)] [case(1049)] wkssvc_NetWkstaInfo1049 *info1049; */
/* IDL: [case(1050)] [unique(1)] [case(1050)] wkssvc_NetWkstaInfo1050 *info1050; */
/* IDL: [case(1051)] [unique(1)] [case(1051)] wkssvc_NetWkstaInfo1051 *info1051; */
/* IDL: [case(1052)] [unique(1)] [case(1052)] wkssvc_NetWkstaInfo1052 *info1052; */
/* IDL: [case(1053)] [unique(1)] [case(1053)] wkssvc_NetWkstaInfo1053 *info1053; */
/* IDL: [case(1054)] [unique(1)] [case(1054)] wkssvc_NetWkstaInfo1054 *info1054; */
/* IDL: [case(1055)] [unique(1)] [case(1055)] wkssvc_NetWkstaInfo1055 *info1055; */
/* IDL: [case(1056)] [unique(1)] [case(1056)] wkssvc_NetWkstaInfo1056 *info1056; */
/* IDL: [case(1057)] [unique(1)] [case(1057)] wkssvc_NetWkstaInfo1057 *info1057; */
/* IDL: [case(1058)] [unique(1)] [case(1058)] wkssvc_NetWkstaInfo1058 *info1058; */
/* IDL: [case(1059)] [unique(1)] [case(1059)] wkssvc_NetWkstaInfo1059 *info1059; */
/* IDL: [case(1060)] [unique(1)] [case(1060)] wkssvc_NetWkstaInfo1060 *info1060; */
/* IDL: [case(1061)] [unique(1)] [case(1061)] wkssvc_NetWkstaInfo1061 *info1061; */
/* IDL: [case(1062)] [unique(1)] [case(1062)] wkssvc_NetWkstaInfo1062 *info1062; */
/* IDL: [default] ; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaInfo_info100(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info100_, NDR_POINTER_UNIQUE, "Pointer to Info100 (wkssvc_NetWkstaInfo100)",hf_wkssvc_wkssvc_NetWkstaInfo_info100);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info100_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo100(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info100,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info101(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info101_, NDR_POINTER_UNIQUE, "Pointer to Info101 (wkssvc_NetWkstaInfo101)",hf_wkssvc_wkssvc_NetWkstaInfo_info101);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info101_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo101(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info101,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info102(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info102_, NDR_POINTER_UNIQUE, "Pointer to Info102 (wkssvc_NetWkstaInfo102)",hf_wkssvc_wkssvc_NetWkstaInfo_info102);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info102_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo102(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info102,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info502(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info502_, NDR_POINTER_UNIQUE, "Pointer to Info502 (wkssvc_NetWkstaInfo502)",hf_wkssvc_wkssvc_NetWkstaInfo_info502);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info502_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo502(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info502,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1010(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info1010_, NDR_POINTER_UNIQUE, "Pointer to Info1010 (wkssvc_NetWkstaInfo1010)",hf_wkssvc_wkssvc_NetWkstaInfo_info1010);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1010_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1010(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1010,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1011(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info1011_, NDR_POINTER_UNIQUE, "Pointer to Info1011 (wkssvc_NetWkstaInfo1011)",hf_wkssvc_wkssvc_NetWkstaInfo_info1011);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1011_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1011(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1011,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1012(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info1012_, NDR_POINTER_UNIQUE, "Pointer to Info1012 (wkssvc_NetWkstaInfo1012)",hf_wkssvc_wkssvc_NetWkstaInfo_info1012);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1012_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1012(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1012,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1013(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info1013_, NDR_POINTER_UNIQUE, "Pointer to Info1013 (wkssvc_NetWkstaInfo1013)",hf_wkssvc_wkssvc_NetWkstaInfo_info1013);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1013_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1013(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1013,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1018(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info1018_, NDR_POINTER_UNIQUE, "Pointer to Info1018 (wkssvc_NetWkstaInfo1018)",hf_wkssvc_wkssvc_NetWkstaInfo_info1018);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1018_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1018(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1018,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1023(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info1023_, NDR_POINTER_UNIQUE, "Pointer to Info1023 (wkssvc_NetWkstaInfo1023)",hf_wkssvc_wkssvc_NetWkstaInfo_info1023);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1023_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1023(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1023,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1027(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info1027_, NDR_POINTER_UNIQUE, "Pointer to Info1027 (wkssvc_NetWkstaInfo1027)",hf_wkssvc_wkssvc_NetWkstaInfo_info1027);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1027_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1027(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1027,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1028(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info1028_, NDR_POINTER_UNIQUE, "Pointer to Info1028 (wkssvc_NetWkstaInfo1028)",hf_wkssvc_wkssvc_NetWkstaInfo_info1028);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1028_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1028(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1028,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1032(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info1032_, NDR_POINTER_UNIQUE, "Pointer to Info1032 (wkssvc_NetWkstaInfo1032)",hf_wkssvc_wkssvc_NetWkstaInfo_info1032);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1032_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1032(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1032,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1033(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info1033_, NDR_POINTER_UNIQUE, "Pointer to Info1033 (wkssvc_NetWkstaInfo1033)",hf_wkssvc_wkssvc_NetWkstaInfo_info1033);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1033_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1033(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1033,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1041(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info1041_, NDR_POINTER_UNIQUE, "Pointer to Info1041 (wkssvc_NetWkstaInfo1041)",hf_wkssvc_wkssvc_NetWkstaInfo_info1041);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1041_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1041(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1041,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1042(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info1042_, NDR_POINTER_UNIQUE, "Pointer to Info1042 (wkssvc_NetWkstaInfo1042)",hf_wkssvc_wkssvc_NetWkstaInfo_info1042);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1042_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1042(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1042,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1043(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info1043_, NDR_POINTER_UNIQUE, "Pointer to Info1043 (wkssvc_NetWkstaInfo1043)",hf_wkssvc_wkssvc_NetWkstaInfo_info1043);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1043_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1043(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1043,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1044(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info1044_, NDR_POINTER_UNIQUE, "Pointer to Info1044 (wkssvc_NetWkstaInfo1044)",hf_wkssvc_wkssvc_NetWkstaInfo_info1044);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1044_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1044(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1044,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1045(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info1045_, NDR_POINTER_UNIQUE, "Pointer to Info1045 (wkssvc_NetWkstaInfo1045)",hf_wkssvc_wkssvc_NetWkstaInfo_info1045);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1045_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1045(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1045,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1046(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info1046_, NDR_POINTER_UNIQUE, "Pointer to Info1046 (wkssvc_NetWkstaInfo1046)",hf_wkssvc_wkssvc_NetWkstaInfo_info1046);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1046_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1046(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1046,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1047(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info1047_, NDR_POINTER_UNIQUE, "Pointer to Info1047 (wkssvc_NetWkstaInfo1047)",hf_wkssvc_wkssvc_NetWkstaInfo_info1047);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1047_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1047(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1047,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1048(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info1048_, NDR_POINTER_UNIQUE, "Pointer to Info1048 (wkssvc_NetWkstaInfo1048)",hf_wkssvc_wkssvc_NetWkstaInfo_info1048);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1048_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1048(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1048,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1049(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info1049_, NDR_POINTER_UNIQUE, "Pointer to Info1049 (wkssvc_NetWkstaInfo1049)",hf_wkssvc_wkssvc_NetWkstaInfo_info1049);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1049_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1049(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1049,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1050(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info1050_, NDR_POINTER_UNIQUE, "Pointer to Info1050 (wkssvc_NetWkstaInfo1050)",hf_wkssvc_wkssvc_NetWkstaInfo_info1050);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1050_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1050(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1050,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1051(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info1051_, NDR_POINTER_UNIQUE, "Pointer to Info1051 (wkssvc_NetWkstaInfo1051)",hf_wkssvc_wkssvc_NetWkstaInfo_info1051);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1051_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1051(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1051,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1052(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info1052_, NDR_POINTER_UNIQUE, "Pointer to Info1052 (wkssvc_NetWkstaInfo1052)",hf_wkssvc_wkssvc_NetWkstaInfo_info1052);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1052_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1052(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1052,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1053(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info1053_, NDR_POINTER_UNIQUE, "Pointer to Info1053 (wkssvc_NetWkstaInfo1053)",hf_wkssvc_wkssvc_NetWkstaInfo_info1053);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1053_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1053(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1053,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1054(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info1054_, NDR_POINTER_UNIQUE, "Pointer to Info1054 (wkssvc_NetWkstaInfo1054)",hf_wkssvc_wkssvc_NetWkstaInfo_info1054);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1054_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1054(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1054,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1055(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info1055_, NDR_POINTER_UNIQUE, "Pointer to Info1055 (wkssvc_NetWkstaInfo1055)",hf_wkssvc_wkssvc_NetWkstaInfo_info1055);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1055_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1055(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1055,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1056(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info1056_, NDR_POINTER_UNIQUE, "Pointer to Info1056 (wkssvc_NetWkstaInfo1056)",hf_wkssvc_wkssvc_NetWkstaInfo_info1056);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1056_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1056(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1056,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1057(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info1057_, NDR_POINTER_UNIQUE, "Pointer to Info1057 (wkssvc_NetWkstaInfo1057)",hf_wkssvc_wkssvc_NetWkstaInfo_info1057);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1057_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1057(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1057,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1058(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info1058_, NDR_POINTER_UNIQUE, "Pointer to Info1058 (wkssvc_NetWkstaInfo1058)",hf_wkssvc_wkssvc_NetWkstaInfo_info1058);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1058_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1058(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1058,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1059(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info1059_, NDR_POINTER_UNIQUE, "Pointer to Info1059 (wkssvc_NetWkstaInfo1059)",hf_wkssvc_wkssvc_NetWkstaInfo_info1059);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1059_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1059(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1059,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1060(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info1060_, NDR_POINTER_UNIQUE, "Pointer to Info1060 (wkssvc_NetWkstaInfo1060)",hf_wkssvc_wkssvc_NetWkstaInfo_info1060);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1060_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1060(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1060,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1061(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info1061_, NDR_POINTER_UNIQUE, "Pointer to Info1061 (wkssvc_NetWkstaInfo1061)",hf_wkssvc_wkssvc_NetWkstaInfo_info1061);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1061_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1061(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1061,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1062(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaInfo_info1062_, NDR_POINTER_UNIQUE, "Pointer to Info1062 (wkssvc_NetWkstaInfo1062)",hf_wkssvc_wkssvc_NetWkstaInfo_info1062);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1062_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1062(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1062,0);

	return offset;
}

static int
wkssvc_dissect_NetWkstaInfo(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;
	guint32 level;

	old_offset = offset;
	if (parent_tree) {
		tree = proto_tree_add_subtree(parent_tree, tvb, offset, -1, ett_wkssvc_wkssvc_NetWkstaInfo, &item, "wkssvc_NetWkstaInfo");
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_index, &level);
	ALIGN_TO_4_BYTES;

	switch(level) {
		case 100:
			offset = wkssvc_dissect_element_NetWkstaInfo_info100(tvb, offset, pinfo, tree, di, drep);
		break;

		case 101:
			offset = wkssvc_dissect_element_NetWkstaInfo_info101(tvb, offset, pinfo, tree, di, drep);
		break;

		case 102:
			offset = wkssvc_dissect_element_NetWkstaInfo_info102(tvb, offset, pinfo, tree, di, drep);
		break;

		case 502:
			offset = wkssvc_dissect_element_NetWkstaInfo_info502(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1010:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1010(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1011:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1011(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1012:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1012(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1013:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1013(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1018:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1018(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1023:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1023(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1027:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1027(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1028:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1028(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1032:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1032(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1033:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1033(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1041:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1041(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1042:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1042(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1043:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1043(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1044:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1044(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1045:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1045(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1046:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1046(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1047:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1047(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1048:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1048(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1049:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1049(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1050:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1050(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1051:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1051(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1052:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1052(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1053:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1053(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1054:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1054(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1055:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1055(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1056:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1056(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1057:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1057(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1058:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1058(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1059:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1059(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1060:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1060(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1061:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1061(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1062:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1062(tvb, offset, pinfo, tree, di, drep);
		break;

		default:
		break;
	}
	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: struct { */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *user_name; */
/* IDL: } */

static int
wkssvc_dissect_element_NetrWkstaUserInfo0_user_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrWkstaUserInfo0_user_name_, NDR_POINTER_UNIQUE, "Pointer to User Name (uint16)",hf_wkssvc_wkssvc_NetrWkstaUserInfo0_user_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaUserInfo0_user_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrWkstaUserInfo0_user_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

int
wkssvc_dissect_struct_NetrWkstaUserInfo0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetrWkstaUserInfo0);
	}
	
	offset = wkssvc_dissect_element_NetrWkstaUserInfo0_user_name(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 entries_read; */
/* IDL: 	[unique(1)] [size_is(entries_read)] wkssvc_NetrWkstaUserInfo0 *user0; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaEnumUsersCtr0_entries_read(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaEnumUsersCtr0_entries_read, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaEnumUsersCtr0_user0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaEnumUsersCtr0_user0_, NDR_POINTER_UNIQUE, "Pointer to User0 (wkssvc_NetrWkstaUserInfo0)",hf_wkssvc_wkssvc_NetWkstaEnumUsersCtr0_user0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaEnumUsersCtr0_user0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaEnumUsersCtr0_user0__);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaEnumUsersCtr0_user0__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetrWkstaUserInfo0(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaEnumUsersCtr0_user0,0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaEnumUsersCtr0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaEnumUsersCtr0);
	}
	
	offset = wkssvc_dissect_element_NetWkstaEnumUsersCtr0_entries_read(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaEnumUsersCtr0_user0(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *user_name; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *logon_domain; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *other_domains; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *logon_server; */
/* IDL: } */

static int
wkssvc_dissect_element_NetrWkstaUserInfo1_user_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrWkstaUserInfo1_user_name_, NDR_POINTER_UNIQUE, "Pointer to User Name (uint16)",hf_wkssvc_wkssvc_NetrWkstaUserInfo1_user_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaUserInfo1_user_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrWkstaUserInfo1_user_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaUserInfo1_logon_domain(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrWkstaUserInfo1_logon_domain_, NDR_POINTER_UNIQUE, "Pointer to Logon Domain (uint16)",hf_wkssvc_wkssvc_NetrWkstaUserInfo1_logon_domain);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaUserInfo1_logon_domain_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrWkstaUserInfo1_logon_domain, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaUserInfo1_other_domains(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrWkstaUserInfo1_other_domains_, NDR_POINTER_UNIQUE, "Pointer to Other Domains (uint16)",hf_wkssvc_wkssvc_NetrWkstaUserInfo1_other_domains);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaUserInfo1_other_domains_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrWkstaUserInfo1_other_domains, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaUserInfo1_logon_server(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrWkstaUserInfo1_logon_server_, NDR_POINTER_UNIQUE, "Pointer to Logon Server (uint16)",hf_wkssvc_wkssvc_NetrWkstaUserInfo1_logon_server);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaUserInfo1_logon_server_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrWkstaUserInfo1_logon_server, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

int
wkssvc_dissect_struct_NetrWkstaUserInfo1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetrWkstaUserInfo1);
	}
	
	offset = wkssvc_dissect_element_NetrWkstaUserInfo1_user_name(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWkstaUserInfo1_logon_domain(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWkstaUserInfo1_other_domains(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWkstaUserInfo1_logon_server(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 entries_read; */
/* IDL: 	[unique(1)] [size_is(entries_read)] wkssvc_NetrWkstaUserInfo1 *user1; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaEnumUsersCtr1_entries_read(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaEnumUsersCtr1_entries_read, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaEnumUsersCtr1_user1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaEnumUsersCtr1_user1_, NDR_POINTER_UNIQUE, "Pointer to User1 (wkssvc_NetrWkstaUserInfo1)",hf_wkssvc_wkssvc_NetWkstaEnumUsersCtr1_user1);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaEnumUsersCtr1_user1_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaEnumUsersCtr1_user1__);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaEnumUsersCtr1_user1__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetrWkstaUserInfo1(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaEnumUsersCtr1_user1,0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaEnumUsersCtr1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaEnumUsersCtr1);
	}
	
	offset = wkssvc_dissect_element_NetWkstaEnumUsersCtr1_entries_read(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaEnumUsersCtr1_user1(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: [switch_type(uint32)] union { */
/* IDL: [case(0)] [unique(1)] [case(0)] wkssvc_NetWkstaEnumUsersCtr0 *user0; */
/* IDL: [case(1)] [unique(1)] [case(1)] wkssvc_NetWkstaEnumUsersCtr1 *user1; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaEnumUsersCtr_user0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaEnumUsersCtr_user0_, NDR_POINTER_UNIQUE, "Pointer to User0 (wkssvc_NetWkstaEnumUsersCtr0)",hf_wkssvc_wkssvc_NetWkstaEnumUsersCtr_user0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaEnumUsersCtr_user0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaEnumUsersCtr0(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaEnumUsersCtr_user0,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaEnumUsersCtr_user1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaEnumUsersCtr_user1_, NDR_POINTER_UNIQUE, "Pointer to User1 (wkssvc_NetWkstaEnumUsersCtr1)",hf_wkssvc_wkssvc_NetWkstaEnumUsersCtr_user1);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaEnumUsersCtr_user1_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaEnumUsersCtr1(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaEnumUsersCtr_user1,0);

	return offset;
}

static int
wkssvc_dissect_NetWkstaEnumUsersCtr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;
	guint32 level;

	old_offset = offset;
	if (parent_tree) {
		tree = proto_tree_add_subtree(parent_tree, tvb, offset, -1, ett_wkssvc_wkssvc_NetWkstaEnumUsersCtr, &item, "wkssvc_NetWkstaEnumUsersCtr");
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_index, &level);
	ALIGN_TO_4_BYTES;

	switch(level) {
		case 0:
			offset = wkssvc_dissect_element_NetWkstaEnumUsersCtr_user0(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1:
			offset = wkssvc_dissect_element_NetWkstaEnumUsersCtr_user1(tvb, offset, pinfo, tree, di, drep);
		break;
	}
	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: struct { */
/* IDL: 	uint32 level; */
/* IDL: 	[switch_is(level)] wkssvc_NetWkstaEnumUsersCtr ctr; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaEnumUsersInfo_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaEnumUsersInfo_level, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaEnumUsersInfo_ctr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_NetWkstaEnumUsersCtr(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaEnumUsersInfo_ctr, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaEnumUsersInfo(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaEnumUsersInfo);
	}
	
	offset = wkssvc_dissect_element_NetWkstaEnumUsersInfo_level(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaEnumUsersInfo_ctr(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *other_domains; */
/* IDL: } */

static int
wkssvc_dissect_element_NetrWkstaUserInfo1101_other_domains(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrWkstaUserInfo1101_other_domains_, NDR_POINTER_UNIQUE, "Pointer to Other Domains (uint16)",hf_wkssvc_wkssvc_NetrWkstaUserInfo1101_other_domains);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaUserInfo1101_other_domains_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrWkstaUserInfo1101_other_domains, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

int
wkssvc_dissect_struct_NetrWkstaUserInfo1101(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetrWkstaUserInfo1101);
	}
	
	offset = wkssvc_dissect_element_NetrWkstaUserInfo1101_other_domains(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: [switch_type(uint32)] union { */
/* IDL: [case(0)] [unique(1)] [case(0)] wkssvc_NetrWkstaUserInfo0 *info0; */
/* IDL: [case(1)] [unique(1)] [case(1)] wkssvc_NetrWkstaUserInfo1 *info1; */
/* IDL: [case(1101)] [unique(1)] [case(1101)] wkssvc_NetrWkstaUserInfo1101 *info1101; */
/* IDL: } */

static int
wkssvc_dissect_element_NetrWkstaUserInfo_info0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrWkstaUserInfo_info0_, NDR_POINTER_UNIQUE, "Pointer to Info0 (wkssvc_NetrWkstaUserInfo0)",hf_wkssvc_wkssvc_NetrWkstaUserInfo_info0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaUserInfo_info0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetrWkstaUserInfo0(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetrWkstaUserInfo_info0,0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaUserInfo_info1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrWkstaUserInfo_info1_, NDR_POINTER_UNIQUE, "Pointer to Info1 (wkssvc_NetrWkstaUserInfo1)",hf_wkssvc_wkssvc_NetrWkstaUserInfo_info1);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaUserInfo_info1_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetrWkstaUserInfo1(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetrWkstaUserInfo_info1,0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaUserInfo_info1101(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrWkstaUserInfo_info1101_, NDR_POINTER_UNIQUE, "Pointer to Info1101 (wkssvc_NetrWkstaUserInfo1101)",hf_wkssvc_wkssvc_NetrWkstaUserInfo_info1101);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaUserInfo_info1101_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetrWkstaUserInfo1101(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetrWkstaUserInfo_info1101,0);

	return offset;
}

static int
wkssvc_dissect_NetrWkstaUserInfo(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;
	guint32 level;

	old_offset = offset;
	if (parent_tree) {
		tree = proto_tree_add_subtree(parent_tree, tvb, offset, -1, ett_wkssvc_wkssvc_NetrWkstaUserInfo, &item, "wkssvc_NetrWkstaUserInfo");
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_index, &level);
	ALIGN_TO_4_BYTES;

	switch(level) {
		case 0:
			offset = wkssvc_dissect_element_NetrWkstaUserInfo_info0(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1:
			offset = wkssvc_dissect_element_NetrWkstaUserInfo_info1(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1101:
			offset = wkssvc_dissect_element_NetrWkstaUserInfo_info1101(tvb, offset, pinfo, tree, di, drep);
		break;
	}
	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: struct { */
/* IDL: 	uint32 quality_of_service; */
/* IDL: 	uint32 vc_count; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *name; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *address; */
/* IDL: 	uint32 wan_link; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaTransportInfo0_quality_of_service(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaTransportInfo0_quality_of_service, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportInfo0_vc_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaTransportInfo0_vc_count, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportInfo0_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaTransportInfo0_name_, NDR_POINTER_UNIQUE, "Pointer to Name (uint16)",hf_wkssvc_wkssvc_NetWkstaTransportInfo0_name);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportInfo0_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetWkstaTransportInfo0_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportInfo0_address(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaTransportInfo0_address_, NDR_POINTER_UNIQUE, "Pointer to Address (uint16)",hf_wkssvc_wkssvc_NetWkstaTransportInfo0_address);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportInfo0_address_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetWkstaTransportInfo0_address, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportInfo0_wan_link(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaTransportInfo0_wan_link, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaTransportInfo0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
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
	
	offset = wkssvc_dissect_element_NetWkstaTransportInfo0_quality_of_service(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaTransportInfo0_vc_count(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaTransportInfo0_name(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaTransportInfo0_address(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaTransportInfo0_wan_link(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [size_is(count)] wkssvc_NetWkstaTransportInfo0 *array; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaTransportCtr0_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaTransportCtr0_count, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportCtr0_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaTransportCtr0_array_, NDR_POINTER_UNIQUE, "Pointer to Array (wkssvc_NetWkstaTransportInfo0)",hf_wkssvc_wkssvc_NetWkstaTransportCtr0_array);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportCtr0_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaTransportCtr0_array__);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportCtr0_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaTransportInfo0(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaTransportCtr0_array,0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaTransportCtr0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
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
	
	offset = wkssvc_dissect_element_NetWkstaTransportCtr0_count(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaTransportCtr0_array(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: union { */
/* IDL: [case(0)] [unique(1)] [case(0)] wkssvc_NetWkstaTransportCtr0 *ctr0; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaTransportCtr_ctr0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaTransportCtr_ctr0_, NDR_POINTER_UNIQUE, "Pointer to Ctr0 (wkssvc_NetWkstaTransportCtr0)",hf_wkssvc_wkssvc_NetWkstaTransportCtr_ctr0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportCtr_ctr0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaTransportCtr0(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaTransportCtr_ctr0,0);

	return offset;
}

static int
wkssvc_dissect_NetWkstaTransportCtr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;
	guint32 level;

	old_offset = offset;
	if (parent_tree) {
		tree = proto_tree_add_subtree(parent_tree, tvb, offset, -1, ett_wkssvc_wkssvc_NetWkstaTransportCtr, &item, "wkssvc_NetWkstaTransportCtr");
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_index, &level);
	ALIGN_TO_4_BYTES;

	switch(level) {
		case 0:
			offset = wkssvc_dissect_element_NetWkstaTransportCtr_ctr0(tvb, offset, pinfo, tree, di, drep);
		break;
	}
	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: struct { */
/* IDL: 	uint32 level; */
/* IDL: 	[switch_is(level)] wkssvc_NetWkstaTransportCtr ctr; */
/* IDL: } */

static int
wkssvc_dissect_element_NetWkstaTransportInfo_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaTransportInfo_level, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportInfo_ctr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_NetWkstaTransportCtr(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaTransportInfo_ctr, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaTransportInfo(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaTransportInfo);
	}
	
	offset = wkssvc_dissect_element_NetWkstaTransportInfo_level(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetWkstaTransportInfo_ctr(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *unknown1; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *unknown2; */
/* IDL: } */

static int
wkssvc_dissect_element_NetrUseInfo3_unknown1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseInfo3_unknown1_, NDR_POINTER_UNIQUE, "Pointer to Unknown1 (uint16)",hf_wkssvc_wkssvc_NetrUseInfo3_unknown1);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseInfo3_unknown1_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrUseInfo3_unknown1, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseInfo3_unknown2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseInfo3_unknown2_, NDR_POINTER_UNIQUE, "Pointer to Unknown2 (uint16)",hf_wkssvc_wkssvc_NetrUseInfo3_unknown2);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseInfo3_unknown2_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrUseInfo3_unknown2, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

int
wkssvc_dissect_struct_NetrUseInfo3(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetrUseInfo3);
	}
	
	offset = wkssvc_dissect_element_NetrUseInfo3_unknown1(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrUseInfo3_unknown2(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *local; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *remote; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *password; */
/* IDL: 	uint32 status; */
/* IDL: 	uint32 asg_type; */
/* IDL: 	uint32 ref_count; */
/* IDL: 	uint32 use_count; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *user_name; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *domain_name; */
/* IDL: } */

static int
wkssvc_dissect_element_NetrUseInfo2_local(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseInfo2_local_, NDR_POINTER_UNIQUE, "Pointer to Local (uint16)",hf_wkssvc_wkssvc_NetrUseInfo2_local);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseInfo2_local_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrUseInfo2_local, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseInfo2_remote(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseInfo2_remote_, NDR_POINTER_UNIQUE, "Pointer to Remote (uint16)",hf_wkssvc_wkssvc_NetrUseInfo2_remote);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseInfo2_remote_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrUseInfo2_remote, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseInfo2_password(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseInfo2_password_, NDR_POINTER_UNIQUE, "Pointer to Password (uint16)",hf_wkssvc_wkssvc_NetrUseInfo2_password);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseInfo2_password_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrUseInfo2_password, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseInfo2_status(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrUseInfo2_status, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseInfo2_asg_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrUseInfo2_asg_type, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseInfo2_ref_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrUseInfo2_ref_count, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseInfo2_use_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrUseInfo2_use_count, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseInfo2_user_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseInfo2_user_name_, NDR_POINTER_UNIQUE, "Pointer to User Name (uint16)",hf_wkssvc_wkssvc_NetrUseInfo2_user_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseInfo2_user_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrUseInfo2_user_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseInfo2_domain_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseInfo2_domain_name_, NDR_POINTER_UNIQUE, "Pointer to Domain Name (uint16)",hf_wkssvc_wkssvc_NetrUseInfo2_domain_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseInfo2_domain_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrUseInfo2_domain_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

int
wkssvc_dissect_struct_NetrUseInfo2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetrUseInfo2);
	}
	
	offset = wkssvc_dissect_element_NetrUseInfo2_local(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrUseInfo2_remote(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrUseInfo2_password(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrUseInfo2_status(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrUseInfo2_asg_type(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrUseInfo2_ref_count(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrUseInfo2_use_count(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrUseInfo2_user_name(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrUseInfo2_domain_name(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *local; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *remote; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *password; */
/* IDL: 	uint32 status; */
/* IDL: 	uint32 asg_type; */
/* IDL: 	uint32 ref_count; */
/* IDL: 	uint32 use_count; */
/* IDL: } */

static int
wkssvc_dissect_element_NetrUseInfo1_local(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseInfo1_local_, NDR_POINTER_UNIQUE, "Pointer to Local (uint16)",hf_wkssvc_wkssvc_NetrUseInfo1_local);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseInfo1_local_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrUseInfo1_local, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseInfo1_remote(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseInfo1_remote_, NDR_POINTER_UNIQUE, "Pointer to Remote (uint16)",hf_wkssvc_wkssvc_NetrUseInfo1_remote);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseInfo1_remote_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrUseInfo1_remote, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseInfo1_password(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseInfo1_password_, NDR_POINTER_UNIQUE, "Pointer to Password (uint16)",hf_wkssvc_wkssvc_NetrUseInfo1_password);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseInfo1_password_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrUseInfo1_password, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseInfo1_status(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrUseInfo1_status, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseInfo1_asg_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrUseInfo1_asg_type, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseInfo1_ref_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrUseInfo1_ref_count, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseInfo1_use_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrUseInfo1_use_count, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetrUseInfo1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetrUseInfo1);
	}
	
	offset = wkssvc_dissect_element_NetrUseInfo1_local(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrUseInfo1_remote(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrUseInfo1_password(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrUseInfo1_status(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrUseInfo1_asg_type(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrUseInfo1_ref_count(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrUseInfo1_use_count(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *local; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *remote; */
/* IDL: } */

static int
wkssvc_dissect_element_NetrUseInfo0_local(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseInfo0_local_, NDR_POINTER_UNIQUE, "Pointer to Local (uint16)",hf_wkssvc_wkssvc_NetrUseInfo0_local);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseInfo0_local_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrUseInfo0_local, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseInfo0_remote(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseInfo0_remote_, NDR_POINTER_UNIQUE, "Pointer to Remote (uint16)",hf_wkssvc_wkssvc_NetrUseInfo0_remote);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseInfo0_remote_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrUseInfo0_remote, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

int
wkssvc_dissect_struct_NetrUseInfo0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetrUseInfo0);
	}
	
	offset = wkssvc_dissect_element_NetrUseInfo0_local(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrUseInfo0_remote(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: [switch_type(uint32)] union { */
/* IDL: [case(0)] [unique(1)] [case(0)] wkssvc_NetrUseInfo0 *info0; */
/* IDL: [case(1)] [unique(1)] [case(1)] wkssvc_NetrUseInfo1 *info1; */
/* IDL: [case(2)] [unique(1)] [case(2)] wkssvc_NetrUseInfo2 *info2; */
/* IDL: [case(3)] [unique(1)] [case(3)] wkssvc_NetrUseInfo3 *info3; */
/* IDL: } */

static int
wkssvc_dissect_element_NetrUseGetInfoCtr_info0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseGetInfoCtr_info0_, NDR_POINTER_UNIQUE, "Pointer to Info0 (wkssvc_NetrUseInfo0)",hf_wkssvc_wkssvc_NetrUseGetInfoCtr_info0);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseGetInfoCtr_info0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetrUseInfo0(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetrUseGetInfoCtr_info0,0);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseGetInfoCtr_info1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseGetInfoCtr_info1_, NDR_POINTER_UNIQUE, "Pointer to Info1 (wkssvc_NetrUseInfo1)",hf_wkssvc_wkssvc_NetrUseGetInfoCtr_info1);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseGetInfoCtr_info1_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetrUseInfo1(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetrUseGetInfoCtr_info1,0);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseGetInfoCtr_info2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseGetInfoCtr_info2_, NDR_POINTER_UNIQUE, "Pointer to Info2 (wkssvc_NetrUseInfo2)",hf_wkssvc_wkssvc_NetrUseGetInfoCtr_info2);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseGetInfoCtr_info2_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetrUseInfo2(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetrUseGetInfoCtr_info2,0);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseGetInfoCtr_info3(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseGetInfoCtr_info3_, NDR_POINTER_UNIQUE, "Pointer to Info3 (wkssvc_NetrUseInfo3)",hf_wkssvc_wkssvc_NetrUseGetInfoCtr_info3);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseGetInfoCtr_info3_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetrUseInfo3(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetrUseGetInfoCtr_info3,0);

	return offset;
}

static int
wkssvc_dissect_NetrUseGetInfoCtr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;
	guint32 level;

	old_offset = offset;
	if (parent_tree) {
		tree = proto_tree_add_subtree(parent_tree, tvb, offset, -1, ett_wkssvc_wkssvc_NetrUseGetInfoCtr, &item, "wkssvc_NetrUseGetInfoCtr");
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_index, &level);
	ALIGN_TO_4_BYTES;

	switch(level) {
		case 0:
			offset = wkssvc_dissect_element_NetrUseGetInfoCtr_info0(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1:
			offset = wkssvc_dissect_element_NetrUseGetInfoCtr_info1(tvb, offset, pinfo, tree, di, drep);
		break;

		case 2:
			offset = wkssvc_dissect_element_NetrUseGetInfoCtr_info2(tvb, offset, pinfo, tree, di, drep);
		break;

		case 3:
			offset = wkssvc_dissect_element_NetrUseGetInfoCtr_info3(tvb, offset, pinfo, tree, di, drep);
		break;
	}
	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [size_is(count)] wkssvc_NetrUseInfo2 *array; */
/* IDL: } */

static int
wkssvc_dissect_element_NetrUseEnumCtr2_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrUseEnumCtr2_count, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseEnumCtr2_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseEnumCtr2_array_, NDR_POINTER_UNIQUE, "Pointer to Array (wkssvc_NetrUseInfo2)",hf_wkssvc_wkssvc_NetrUseEnumCtr2_array);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseEnumCtr2_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseEnumCtr2_array__);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseEnumCtr2_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetrUseInfo2(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetrUseEnumCtr2_array,0);

	return offset;
}

int
wkssvc_dissect_struct_NetrUseEnumCtr2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetrUseEnumCtr2);
	}
	
	offset = wkssvc_dissect_element_NetrUseEnumCtr2_count(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrUseEnumCtr2_array(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [size_is(count)] wkssvc_NetrUseInfo1 *array; */
/* IDL: } */

static int
wkssvc_dissect_element_NetrUseEnumCtr1_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrUseEnumCtr1_count, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseEnumCtr1_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseEnumCtr1_array_, NDR_POINTER_UNIQUE, "Pointer to Array (wkssvc_NetrUseInfo1)",hf_wkssvc_wkssvc_NetrUseEnumCtr1_array);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseEnumCtr1_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseEnumCtr1_array__);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseEnumCtr1_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetrUseInfo1(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetrUseEnumCtr1_array,0);

	return offset;
}

int
wkssvc_dissect_struct_NetrUseEnumCtr1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetrUseEnumCtr1);
	}
	
	offset = wkssvc_dissect_element_NetrUseEnumCtr1_count(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrUseEnumCtr1_array(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [size_is(count)] wkssvc_NetrUseInfo0 *array; */
/* IDL: } */

static int
wkssvc_dissect_element_NetrUseEnumCtr0_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrUseEnumCtr0_count, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseEnumCtr0_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseEnumCtr0_array_, NDR_POINTER_UNIQUE, "Pointer to Array (wkssvc_NetrUseInfo0)",hf_wkssvc_wkssvc_NetrUseEnumCtr0_array);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseEnumCtr0_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseEnumCtr0_array__);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseEnumCtr0_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetrUseInfo0(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetrUseEnumCtr0_array,0);

	return offset;
}

int
wkssvc_dissect_struct_NetrUseEnumCtr0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetrUseEnumCtr0);
	}
	
	offset = wkssvc_dissect_element_NetrUseEnumCtr0_count(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrUseEnumCtr0_array(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: [switch_type(uint32)] union { */
/* IDL: [case(0)] [unique(1)] [case(0)] wkssvc_NetrUseEnumCtr0 *ctr0; */
/* IDL: [case(1)] [unique(1)] [case(1)] wkssvc_NetrUseEnumCtr1 *ctr1; */
/* IDL: [case(2)] [unique(1)] [case(2)] wkssvc_NetrUseEnumCtr2 *ctr2; */
/* IDL: } */

static int
wkssvc_dissect_element_NetrUseEnumCtr_ctr0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseEnumCtr_ctr0_, NDR_POINTER_UNIQUE, "Pointer to Ctr0 (wkssvc_NetrUseEnumCtr0)",hf_wkssvc_wkssvc_NetrUseEnumCtr_ctr0);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseEnumCtr_ctr0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetrUseEnumCtr0(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetrUseEnumCtr_ctr0,0);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseEnumCtr_ctr1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseEnumCtr_ctr1_, NDR_POINTER_UNIQUE, "Pointer to Ctr1 (wkssvc_NetrUseEnumCtr1)",hf_wkssvc_wkssvc_NetrUseEnumCtr_ctr1);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseEnumCtr_ctr1_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetrUseEnumCtr1(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetrUseEnumCtr_ctr1,0);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseEnumCtr_ctr2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseEnumCtr_ctr2_, NDR_POINTER_UNIQUE, "Pointer to Ctr2 (wkssvc_NetrUseEnumCtr2)",hf_wkssvc_wkssvc_NetrUseEnumCtr_ctr2);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseEnumCtr_ctr2_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetrUseEnumCtr2(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetrUseEnumCtr_ctr2,0);

	return offset;
}

static int
wkssvc_dissect_NetrUseEnumCtr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;
	guint32 level;

	old_offset = offset;
	if (parent_tree) {
		tree = proto_tree_add_subtree(parent_tree, tvb, offset, -1, ett_wkssvc_wkssvc_NetrUseEnumCtr, &item, "wkssvc_NetrUseEnumCtr");
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_index, &level);
	ALIGN_TO_4_BYTES;

	switch(level) {
		case 0:
			offset = wkssvc_dissect_element_NetrUseEnumCtr_ctr0(tvb, offset, pinfo, tree, di, drep);
		break;

		case 1:
			offset = wkssvc_dissect_element_NetrUseEnumCtr_ctr1(tvb, offset, pinfo, tree, di, drep);
		break;

		case 2:
			offset = wkssvc_dissect_element_NetrUseEnumCtr_ctr2(tvb, offset, pinfo, tree, di, drep);
		break;
	}
	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: struct { */
/* IDL: 	uint32 level; */
/* IDL: 	[switch_is(level)] wkssvc_NetrUseEnumCtr ctr; */
/* IDL: } */

static int
wkssvc_dissect_element_NetrUseEnumInfo_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrUseEnumInfo_level, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseEnumInfo_ctr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_NetrUseEnumCtr(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrUseEnumInfo_ctr, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetrUseEnumInfo(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetrUseEnumInfo);
	}
	
	offset = wkssvc_dissect_element_NetrUseEnumInfo_level(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrUseEnumInfo_ctr(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	hyper unknown1; */
/* IDL: 	hyper unknown2; */
/* IDL: 	hyper unknown3; */
/* IDL: 	hyper unknown4; */
/* IDL: 	hyper unknown5; */
/* IDL: 	hyper unknown6; */
/* IDL: 	hyper unknown7; */
/* IDL: 	hyper unknown8; */
/* IDL: 	hyper unknown9; */
/* IDL: 	hyper unknown10; */
/* IDL: 	hyper unknown11; */
/* IDL: 	hyper unknown12; */
/* IDL: 	hyper unknown13; */
/* IDL: 	uint32 unknown14; */
/* IDL: 	uint32 unknown15; */
/* IDL: 	uint32 unknown16; */
/* IDL: 	uint32 unknown17; */
/* IDL: 	uint32 unknown18; */
/* IDL: 	uint32 unknown19; */
/* IDL: 	uint32 unknown20; */
/* IDL: 	uint32 unknown21; */
/* IDL: 	uint32 unknown22; */
/* IDL: 	uint32 unknown23; */
/* IDL: 	uint32 unknown24; */
/* IDL: 	uint32 unknown25; */
/* IDL: 	uint32 unknown26; */
/* IDL: 	uint32 unknown27; */
/* IDL: 	uint32 unknown28; */
/* IDL: 	uint32 unknown29; */
/* IDL: 	uint32 unknown30; */
/* IDL: 	uint32 unknown31; */
/* IDL: 	uint32 unknown32; */
/* IDL: 	uint32 unknown33; */
/* IDL: 	uint32 unknown34; */
/* IDL: 	uint32 unknown35; */
/* IDL: 	uint32 unknown36; */
/* IDL: 	uint32 unknown37; */
/* IDL: 	uint32 unknown38; */
/* IDL: 	uint32 unknown39; */
/* IDL: 	uint32 unknown40; */
/* IDL: } */

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_hyper(tvb, offset, pinfo, tree, di, drep, 0, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown1);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_hyper(tvb, offset, pinfo, tree, di, drep, 0, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown2);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown3(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_hyper(tvb, offset, pinfo, tree, di, drep, 0, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown3);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown4(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_hyper(tvb, offset, pinfo, tree, di, drep, 0, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown4);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown5(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_hyper(tvb, offset, pinfo, tree, di, drep, 0, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown5);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown6(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_hyper(tvb, offset, pinfo, tree, di, drep, 0, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown6);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown7(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_hyper(tvb, offset, pinfo, tree, di, drep, 0, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown7);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown8(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_hyper(tvb, offset, pinfo, tree, di, drep, 0, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown8);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown9(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_hyper(tvb, offset, pinfo, tree, di, drep, 0, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown9);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown10(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_hyper(tvb, offset, pinfo, tree, di, drep, 0, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown10);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown11(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_hyper(tvb, offset, pinfo, tree, di, drep, 0, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown11);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown12(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_hyper(tvb, offset, pinfo, tree, di, drep, 0, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown12);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown13(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_hyper(tvb, offset, pinfo, tree, di, drep, 0, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown13);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown14(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown14, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown15(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown15, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown16(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown16, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown17(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown17, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown18(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown18, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown19(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown19, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown20(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown20, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown21(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown21, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown22(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown22, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown23(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown23, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown24(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown24, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown25(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown25, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown26(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown26, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown27(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown27, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown28(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown28, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown29(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown29, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown30(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown30, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown31(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown31, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown32(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown32, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown33(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown33, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown34(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown34, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown35(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown35, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown36(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown36, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown37(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown37, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown38(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown38, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown39(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown39, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatistics_unknown40(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown40, 0);

	return offset;
}

int
wkssvc_dissect_struct_NetrWorkstationStatistics(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_8_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetrWorkstationStatistics);
	}
	
	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown1(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown2(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown3(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown4(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown5(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown6(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown7(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown8(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown9(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown10(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown11(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown12(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown13(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown14(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown15(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown16(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown17(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown18(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown19(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown20(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown21(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown22(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown23(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown24(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown25(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown26(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown27(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown28(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown29(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown30(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown31(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown32(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown33(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown34(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown35(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown36(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown37(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown38(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown39(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_NetrWorkstationStatistics_unknown40(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: bitmap { */
/* IDL: 	WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE =  0x00000002 , */
/* IDL: } */

int
wkssvc_dissect_bitmap_renameflags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	guint32 flags;
	ALIGN_TO_4_BYTES;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, 4, TRUE);
		tree = proto_item_add_subtree(item,ett_wkssvc_wkssvc_renameflags);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, di, drep, -1, &flags);
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


/* IDL: enum { */
/* IDL: 	NetSetupUnknown=0, */
/* IDL: 	NetSetupMachine=1, */
/* IDL: 	NetSetupWorkgroup=2, */
/* IDL: 	NetSetupDomain=3, */
/* IDL: 	NetSetupNonExistentDomain=4, */
/* IDL: 	NetSetupDnsMachine=5, */
/* IDL: } */

int
wkssvc_dissect_enum_NetValidateNameType(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_)
{
	guint16 parameter=0;
	if(param){
		parameter=(guint16)*param;
	}
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, di, drep, hf_index, &parameter);
	if(param){
		*param=(guint32)parameter;
	}
	return offset;
}


/* IDL: enum { */
/* IDL: 	NetSetupUnknownStatus=0, */
/* IDL: 	NetSetupUnjoined=1, */
/* IDL: 	NetSetupWorkgroupName=2, */
/* IDL: 	NetSetupDomainName=3, */
/* IDL: } */

int
wkssvc_dissect_enum_NetJoinStatus(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_)
{
	guint16 parameter=0;
	if(param){
		parameter=(guint16)*param;
	}
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, di, drep, hf_index, &parameter);
	if(param){
		*param=(guint32)parameter;
	}
	return offset;
}


/* IDL: struct { */
/* IDL: 	uint8 data[524]; */
/* IDL: } */

static int
wkssvc_dissect_element_PasswordBuffer_data(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	int i;
	for (i = 0; i < 524; i++)
		offset = wkssvc_dissect_element_PasswordBuffer_data_(tvb, offset, pinfo, tree, di, drep);

	return offset;
}

static int
wkssvc_dissect_element_PasswordBuffer_data_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_PasswordBuffer_data, 0);

	return offset;
}

int
wkssvc_dissect_struct_PasswordBuffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;


	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_PasswordBuffer);
	}
	
	offset = wkssvc_dissect_element_PasswordBuffer_data(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: bitmap { */
/* IDL: 	WKSSVC_JOIN_FLAGS_JOIN_WITH_NEW_NAME =  0x00000400 , */
/* IDL: 	WKSSVC_JOIN_FLAGS_JOIN_DC_ACCOUNT =  0x00000200 , */
/* IDL: 	WKSSVC_JOIN_FLAGS_DEFER_SPN =  0x00000100 , */
/* IDL: 	WKSSVC_JOIN_FLAGS_MACHINE_PWD_PASSED =  0x00000080 , */
/* IDL: 	WKSSVC_JOIN_FLAGS_JOIN_UNSECURE =  0x00000040 , */
/* IDL: 	WKSSVC_JOIN_FLAGS_DOMAIN_JOIN_IF_JOINED =  0x00000020 , */
/* IDL: 	WKSSVC_JOIN_FLAGS_WIN9X_UPGRADE =  0x00000010 , */
/* IDL: 	WKSSVC_JOIN_FLAGS_ACCOUNT_DELETE =  0x00000004 , */
/* IDL: 	WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE =  0x00000002 , */
/* IDL: 	WKSSVC_JOIN_FLAGS_JOIN_TYPE =  0x00000001 , */
/* IDL: } */

int
wkssvc_dissect_bitmap_joinflags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	guint32 flags;
	ALIGN_TO_4_BYTES;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, 4, TRUE);
		tree = proto_item_add_subtree(item,ett_wkssvc_wkssvc_joinflags);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, di, drep, -1, &flags);
	proto_item_append_text(item, ": ");

	if (!flags)
		proto_item_append_text(item, "(No values set)");

	proto_tree_add_boolean(tree, hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_JOIN_WITH_NEW_NAME, tvb, offset-4, 4, flags);
	if (flags&( 0x00000400 )){
		proto_item_append_text(item, "WKSSVC_JOIN_FLAGS_JOIN_WITH_NEW_NAME");
		if (flags & (~( 0x00000400 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000400 ));

	proto_tree_add_boolean(tree, hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_JOIN_DC_ACCOUNT, tvb, offset-4, 4, flags);
	if (flags&( 0x00000200 )){
		proto_item_append_text(item, "WKSSVC_JOIN_FLAGS_JOIN_DC_ACCOUNT");
		if (flags & (~( 0x00000200 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000200 ));

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


/* IDL: enum { */
/* IDL: 	NetPrimaryComputerName=0, */
/* IDL: 	NetAlternateComputerNames=1, */
/* IDL: 	NetAllComputerNames=2, */
/* IDL: 	NetComputerNameTypeMax=3, */
/* IDL: } */

int
wkssvc_dissect_enum_ComputerNameType(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_)
{
	guint16 parameter=0;
	if(param){
		parameter=(guint16)*param;
	}
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, di, drep, hf_index, &parameter);
	if(param){
		*param=(guint32)parameter;
	}
	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [size_is(count)] lsa_String *computer_name; */
/* IDL: } */

static int
wkssvc_dissect_element_ComputerNamesCtr_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_ComputerNamesCtr_count, 0);

	return offset;
}

static int
wkssvc_dissect_element_ComputerNamesCtr_computer_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_ComputerNamesCtr_computer_name_, NDR_POINTER_UNIQUE, "Pointer to Computer Name (lsa_String)",hf_wkssvc_wkssvc_ComputerNamesCtr_computer_name);

	return offset;
}

static int
wkssvc_dissect_element_ComputerNamesCtr_computer_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_ComputerNamesCtr_computer_name__);

	return offset;
}

static int
wkssvc_dissect_element_ComputerNamesCtr_computer_name__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_lsa_String(tvb, offset, pinfo, tree, di, drep, 0, hf_wkssvc_wkssvc_ComputerNamesCtr_computer_name);

	return offset;
}

int
wkssvc_dissect_struct_ComputerNamesCtr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_ComputerNamesCtr);
	}
	
	offset = wkssvc_dissect_element_ComputerNamesCtr_count(tvb, offset, pinfo, tree, di, drep);

	offset = wkssvc_dissect_element_ComputerNamesCtr_computer_name(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaGetInfo_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaGetInfo_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetWkstaGetInfo_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaGetInfo_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetWkstaGetInfo_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaGetInfo_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaGetInfo_level, PIDL_SET_COL_INFO);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaGetInfo_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaGetInfo_info_, NDR_POINTER_REF, "Pointer to Info (wkssvc_NetWkstaInfo)",hf_wkssvc_wkssvc_NetWkstaGetInfo_info);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaGetInfo_info_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_NetWkstaInfo(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaGetInfo_info, 0);

	return offset;
}

/* IDL: WERROR wkssvc_NetWkstaGetInfo( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_name, */
/* IDL: [in] uint32 level, */
/* IDL: [out] [ref] [switch_is(level)] wkssvc_NetWkstaInfo *info */
/* IDL: ); */

static int
wkssvc_dissect_NetWkstaGetInfo_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="NetWkstaGetInfo";
	offset = wkssvc_dissect_element_NetWkstaGetInfo_info(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetWkstaGetInfo_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="NetWkstaGetInfo";
	offset = wkssvc_dissect_element_NetWkstaGetInfo_server_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetWkstaGetInfo_level(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetWkstaSetInfo_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaSetInfo_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetWkstaSetInfo_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaSetInfo_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetWkstaSetInfo_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaSetInfo_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaSetInfo_level, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaSetInfo_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaSetInfo_info_, NDR_POINTER_REF, "Pointer to Info (wkssvc_NetWkstaInfo)",hf_wkssvc_wkssvc_NetWkstaSetInfo_info);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaSetInfo_info_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_NetWkstaInfo(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaSetInfo_info, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaSetInfo_parm_error(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaSetInfo_parm_error_, NDR_POINTER_REF, "Pointer to Parm Error (uint32)",hf_wkssvc_wkssvc_NetWkstaSetInfo_parm_error);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaSetInfo_parm_error_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaSetInfo_parm_error, 0);

	return offset;
}

/* IDL: WERROR wkssvc_NetWkstaSetInfo( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_name, */
/* IDL: [in] uint32 level, */
/* IDL: [in] [ref] [switch_is(level)] wkssvc_NetWkstaInfo *info, */
/* IDL: [out] [in] [ref] uint32 *parm_error */
/* IDL: ); */

static int
wkssvc_dissect_NetWkstaSetInfo_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="NetWkstaSetInfo";
	offset = wkssvc_dissect_element_NetWkstaSetInfo_parm_error(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetWkstaSetInfo_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="NetWkstaSetInfo";
	offset = wkssvc_dissect_element_NetWkstaSetInfo_server_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetWkstaSetInfo_level(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetWkstaSetInfo_info(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetWkstaSetInfo_parm_error(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetWkstaEnumUsers_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaEnumUsers_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetWkstaEnumUsers_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaEnumUsers_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetWkstaEnumUsers_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaEnumUsers_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaEnumUsers_info_, NDR_POINTER_REF, "Pointer to Info (wkssvc_NetWkstaEnumUsersInfo)",hf_wkssvc_wkssvc_NetWkstaEnumUsers_info);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaEnumUsers_info_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaEnumUsersInfo(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaEnumUsers_info,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaEnumUsers_prefmaxlen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaEnumUsers_prefmaxlen, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaEnumUsers_entries_read(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaEnumUsers_entries_read_, NDR_POINTER_REF, "Pointer to Entries Read (uint32)",hf_wkssvc_wkssvc_NetWkstaEnumUsers_entries_read);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaEnumUsers_entries_read_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaEnumUsers_entries_read, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaEnumUsers_resume_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaEnumUsers_resume_handle_, NDR_POINTER_UNIQUE, "Pointer to Resume Handle (uint32)",hf_wkssvc_wkssvc_NetWkstaEnumUsers_resume_handle);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaEnumUsers_resume_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaEnumUsers_resume_handle, 0);

	return offset;
}

/* IDL: WERROR wkssvc_NetWkstaEnumUsers( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_name, */
/* IDL: [out] [in] [ref] wkssvc_NetWkstaEnumUsersInfo *info, */
/* IDL: [in] uint32 prefmaxlen, */
/* IDL: [out] [ref] uint32 *entries_read, */
/* IDL: [unique(1)] [out] [in] uint32 *resume_handle */
/* IDL: ); */

static int
wkssvc_dissect_NetWkstaEnumUsers_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="NetWkstaEnumUsers";
	offset = wkssvc_dissect_element_NetWkstaEnumUsers_info(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = wkssvc_dissect_element_NetWkstaEnumUsers_entries_read(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = wkssvc_dissect_element_NetWkstaEnumUsers_resume_handle(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetWkstaEnumUsers_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="NetWkstaEnumUsers";
	offset = wkssvc_dissect_element_NetWkstaEnumUsers_server_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetWkstaEnumUsers_info(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetWkstaEnumUsers_prefmaxlen(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetWkstaEnumUsers_resume_handle(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaUserGetInfo_unknown(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrWkstaUserGetInfo_unknown_, NDR_POINTER_UNIQUE, "Pointer to Unknown (uint16)",hf_wkssvc_wkssvc_NetrWkstaUserGetInfo_unknown);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaUserGetInfo_unknown_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrWkstaUserGetInfo_unknown, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaUserGetInfo_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWkstaUserGetInfo_level, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaUserGetInfo_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrWkstaUserGetInfo_info_, NDR_POINTER_REF, "Pointer to Info (wkssvc_NetrWkstaUserInfo)",hf_wkssvc_wkssvc_NetrWkstaUserGetInfo_info);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaUserGetInfo_info_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_NetrWkstaUserInfo(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWkstaUserGetInfo_info, 0);

	return offset;
}

/* IDL: WERROR wkssvc_NetrWkstaUserGetInfo( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *unknown, */
/* IDL: [in] uint32 level, */
/* IDL: [out] [ref] [switch_is(level)] wkssvc_NetrWkstaUserInfo *info */
/* IDL: ); */

static int
wkssvc_dissect_NetrWkstaUserGetInfo_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="NetrWkstaUserGetInfo";
	offset = wkssvc_dissect_element_NetrWkstaUserGetInfo_info(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetrWkstaUserGetInfo_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="NetrWkstaUserGetInfo";
	offset = wkssvc_dissect_element_NetrWkstaUserGetInfo_unknown(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrWkstaUserGetInfo_level(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaUserSetInfo_unknown(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrWkstaUserSetInfo_unknown_, NDR_POINTER_UNIQUE, "Pointer to Unknown (uint16)",hf_wkssvc_wkssvc_NetrWkstaUserSetInfo_unknown);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaUserSetInfo_unknown_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrWkstaUserSetInfo_unknown, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaUserSetInfo_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWkstaUserSetInfo_level, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaUserSetInfo_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrWkstaUserSetInfo_info_, NDR_POINTER_REF, "Pointer to Info (wkssvc_NetrWkstaUserInfo)",hf_wkssvc_wkssvc_NetrWkstaUserSetInfo_info);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaUserSetInfo_info_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_NetrWkstaUserInfo(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWkstaUserSetInfo_info, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaUserSetInfo_parm_err(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrWkstaUserSetInfo_parm_err_, NDR_POINTER_UNIQUE, "Pointer to Parm Err (uint32)",hf_wkssvc_wkssvc_NetrWkstaUserSetInfo_parm_err);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaUserSetInfo_parm_err_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWkstaUserSetInfo_parm_err, 0);

	return offset;
}

/* IDL: WERROR wkssvc_NetrWkstaUserSetInfo( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *unknown, */
/* IDL: [in] uint32 level, */
/* IDL: [ref] [in] [switch_is(level)] wkssvc_NetrWkstaUserInfo *info, */
/* IDL: [unique(1)] [out] [in] uint32 *parm_err */
/* IDL: ); */

static int
wkssvc_dissect_NetrWkstaUserSetInfo_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="NetrWkstaUserSetInfo";
	offset = wkssvc_dissect_element_NetrWkstaUserSetInfo_parm_err(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetrWkstaUserSetInfo_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="NetrWkstaUserSetInfo";
	offset = wkssvc_dissect_element_NetrWkstaUserSetInfo_unknown(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrWkstaUserSetInfo_level(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrWkstaUserSetInfo_info(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrWkstaUserSetInfo_parm_err(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportEnum_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaTransportEnum_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetWkstaTransportEnum_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportEnum_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetWkstaTransportEnum_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportEnum_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaTransportEnum_info_, NDR_POINTER_REF, "Pointer to Info (wkssvc_NetWkstaTransportInfo)",hf_wkssvc_wkssvc_NetWkstaTransportEnum_info);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportEnum_info_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaTransportInfo(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetWkstaTransportEnum_info,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportEnum_max_buffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaTransportEnum_max_buffer, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportEnum_total_entries(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaTransportEnum_total_entries_, NDR_POINTER_REF, "Pointer to Total Entries (uint32)",hf_wkssvc_wkssvc_NetWkstaTransportEnum_total_entries);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportEnum_total_entries_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaTransportEnum_total_entries, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportEnum_resume_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetWkstaTransportEnum_resume_handle_, NDR_POINTER_UNIQUE, "Pointer to Resume Handle (uint32)",hf_wkssvc_wkssvc_NetWkstaTransportEnum_resume_handle);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportEnum_resume_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetWkstaTransportEnum_resume_handle, 0);

	return offset;
}

/* IDL: WERROR wkssvc_NetWkstaTransportEnum( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_name, */
/* IDL: [out] [in] [ref] wkssvc_NetWkstaTransportInfo *info, */
/* IDL: [in] uint32 max_buffer, */
/* IDL: [out] [ref] uint32 *total_entries, */
/* IDL: [unique(1)] [out] [in] uint32 *resume_handle */
/* IDL: ); */

static int
wkssvc_dissect_NetWkstaTransportEnum_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="NetWkstaTransportEnum";
	offset = wkssvc_dissect_element_NetWkstaTransportEnum_info(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = wkssvc_dissect_element_NetWkstaTransportEnum_total_entries(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = wkssvc_dissect_element_NetWkstaTransportEnum_resume_handle(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetWkstaTransportEnum_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="NetWkstaTransportEnum";
	offset = wkssvc_dissect_element_NetWkstaTransportEnum_server_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetWkstaTransportEnum_info(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetWkstaTransportEnum_max_buffer(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetWkstaTransportEnum_resume_handle(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaTransportAdd_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrWkstaTransportAdd_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetrWkstaTransportAdd_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaTransportAdd_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrWkstaTransportAdd_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaTransportAdd_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWkstaTransportAdd_level, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaTransportAdd_info0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrWkstaTransportAdd_info0_, NDR_POINTER_REF, "Pointer to Info0 (wkssvc_NetWkstaTransportInfo0)",hf_wkssvc_wkssvc_NetrWkstaTransportAdd_info0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaTransportAdd_info0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetWkstaTransportInfo0(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetrWkstaTransportAdd_info0,0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaTransportAdd_parm_err(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrWkstaTransportAdd_parm_err_, NDR_POINTER_UNIQUE, "Pointer to Parm Err (uint32)",hf_wkssvc_wkssvc_NetrWkstaTransportAdd_parm_err);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaTransportAdd_parm_err_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWkstaTransportAdd_parm_err, 0);

	return offset;
}

/* IDL: WERROR wkssvc_NetrWkstaTransportAdd( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_name, */
/* IDL: [in] uint32 level, */
/* IDL: [in] [ref] wkssvc_NetWkstaTransportInfo0 *info0, */
/* IDL: [unique(1)] [out] [in] uint32 *parm_err */
/* IDL: ); */

static int
wkssvc_dissect_NetrWkstaTransportAdd_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="NetrWkstaTransportAdd";
	offset = wkssvc_dissect_element_NetrWkstaTransportAdd_parm_err(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetrWkstaTransportAdd_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="NetrWkstaTransportAdd";
	offset = wkssvc_dissect_element_NetrWkstaTransportAdd_server_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrWkstaTransportAdd_level(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrWkstaTransportAdd_info0(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrWkstaTransportAdd_parm_err(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaTransportDel_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrWkstaTransportDel_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetrWkstaTransportDel_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaTransportDel_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrWkstaTransportDel_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaTransportDel_transport_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrWkstaTransportDel_transport_name_, NDR_POINTER_UNIQUE, "Pointer to Transport Name (uint16)",hf_wkssvc_wkssvc_NetrWkstaTransportDel_transport_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaTransportDel_transport_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrWkstaTransportDel_transport_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrWkstaTransportDel_unknown3(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWkstaTransportDel_unknown3, 0);

	return offset;
}

/* IDL: WERROR wkssvc_NetrWkstaTransportDel( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_name, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *transport_name, */
/* IDL: [in] uint32 unknown3 */
/* IDL: ); */

static int
wkssvc_dissect_NetrWkstaTransportDel_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="NetrWkstaTransportDel";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetrWkstaTransportDel_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="NetrWkstaTransportDel";
	offset = wkssvc_dissect_element_NetrWkstaTransportDel_server_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrWkstaTransportDel_transport_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrWkstaTransportDel_unknown3(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetrUseAdd_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseAdd_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetrUseAdd_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseAdd_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrUseAdd_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseAdd_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrUseAdd_level, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseAdd_ctr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseAdd_ctr_, NDR_POINTER_REF, "Pointer to Ctr (wkssvc_NetrUseGetInfoCtr)",hf_wkssvc_wkssvc_NetrUseAdd_ctr);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseAdd_ctr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_NetrUseGetInfoCtr(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrUseAdd_ctr, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseAdd_parm_err(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseAdd_parm_err_, NDR_POINTER_UNIQUE, "Pointer to Parm Err (uint32)",hf_wkssvc_wkssvc_NetrUseAdd_parm_err);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseAdd_parm_err_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrUseAdd_parm_err, 0);

	return offset;
}

/* IDL: WERROR wkssvc_NetrUseAdd( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_name, */
/* IDL: [in] uint32 level, */
/* IDL: [ref] [in] [switch_is(level)] wkssvc_NetrUseGetInfoCtr *ctr, */
/* IDL: [unique(1)] [out] [in] uint32 *parm_err */
/* IDL: ); */

static int
wkssvc_dissect_NetrUseAdd_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="NetrUseAdd";
	offset = wkssvc_dissect_element_NetrUseAdd_parm_err(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetrUseAdd_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="NetrUseAdd";
	offset = wkssvc_dissect_element_NetrUseAdd_server_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrUseAdd_level(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrUseAdd_ctr(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrUseAdd_parm_err(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetrUseGetInfo_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseGetInfo_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetrUseGetInfo_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseGetInfo_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrUseGetInfo_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseGetInfo_use_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseGetInfo_use_name_, NDR_POINTER_REF, "Pointer to Use Name (uint16)",hf_wkssvc_wkssvc_NetrUseGetInfo_use_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseGetInfo_use_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrUseGetInfo_use_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseGetInfo_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrUseGetInfo_level, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseGetInfo_ctr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseGetInfo_ctr_, NDR_POINTER_REF, "Pointer to Ctr (wkssvc_NetrUseGetInfoCtr)",hf_wkssvc_wkssvc_NetrUseGetInfo_ctr);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseGetInfo_ctr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_NetrUseGetInfoCtr(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrUseGetInfo_ctr, 0);

	return offset;
}

/* IDL: WERROR wkssvc_NetrUseGetInfo( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_name, */
/* IDL: [ref] [in] [charset(UTF16)] uint16 *use_name, */
/* IDL: [in] uint32 level, */
/* IDL: [out] [ref] [switch_is(level)] wkssvc_NetrUseGetInfoCtr *ctr */
/* IDL: ); */

static int
wkssvc_dissect_NetrUseGetInfo_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="NetrUseGetInfo";
	offset = wkssvc_dissect_element_NetrUseGetInfo_ctr(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetrUseGetInfo_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="NetrUseGetInfo";
	offset = wkssvc_dissect_element_NetrUseGetInfo_server_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrUseGetInfo_use_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrUseGetInfo_level(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetrUseDel_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseDel_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetrUseDel_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseDel_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrUseDel_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseDel_use_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseDel_use_name_, NDR_POINTER_REF, "Pointer to Use Name (uint16)",hf_wkssvc_wkssvc_NetrUseDel_use_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseDel_use_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrUseDel_use_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseDel_force_cond(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrUseDel_force_cond, 0);

	return offset;
}

/* IDL: WERROR wkssvc_NetrUseDel( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_name, */
/* IDL: [ref] [in] [charset(UTF16)] uint16 *use_name, */
/* IDL: [in] uint32 force_cond */
/* IDL: ); */

static int
wkssvc_dissect_NetrUseDel_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="NetrUseDel";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetrUseDel_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="NetrUseDel";
	offset = wkssvc_dissect_element_NetrUseDel_server_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrUseDel_use_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrUseDel_force_cond(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetrUseEnum_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseEnum_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetrUseEnum_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseEnum_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrUseEnum_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseEnum_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseEnum_info_, NDR_POINTER_REF, "Pointer to Info (wkssvc_NetrUseEnumInfo)",hf_wkssvc_wkssvc_NetrUseEnum_info);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseEnum_info_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetrUseEnumInfo(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetrUseEnum_info,0);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseEnum_prefmaxlen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrUseEnum_prefmaxlen, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseEnum_entries_read(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseEnum_entries_read_, NDR_POINTER_REF, "Pointer to Entries Read (uint32)",hf_wkssvc_wkssvc_NetrUseEnum_entries_read);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseEnum_entries_read_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrUseEnum_entries_read, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseEnum_resume_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUseEnum_resume_handle_, NDR_POINTER_UNIQUE, "Pointer to Resume Handle (uint32)",hf_wkssvc_wkssvc_NetrUseEnum_resume_handle);

	return offset;
}

static int
wkssvc_dissect_element_NetrUseEnum_resume_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrUseEnum_resume_handle, 0);

	return offset;
}

/* IDL: WERROR wkssvc_NetrUseEnum( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_name, */
/* IDL: [out] [in] [ref] wkssvc_NetrUseEnumInfo *info, */
/* IDL: [in] uint32 prefmaxlen, */
/* IDL: [out] [ref] uint32 *entries_read, */
/* IDL: [unique(1)] [out] [in] uint32 *resume_handle */
/* IDL: ); */

static int
wkssvc_dissect_NetrUseEnum_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="NetrUseEnum";
	offset = wkssvc_dissect_element_NetrUseEnum_info(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = wkssvc_dissect_element_NetrUseEnum_entries_read(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = wkssvc_dissect_element_NetrUseEnum_resume_handle(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetrUseEnum_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="NetrUseEnum";
	offset = wkssvc_dissect_element_NetrUseEnum_server_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrUseEnum_info(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrUseEnum_prefmaxlen(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrUseEnum_resume_handle(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetrMessageBufferSend_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrMessageBufferSend_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetrMessageBufferSend_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrMessageBufferSend_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrMessageBufferSend_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrMessageBufferSend_message_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrMessageBufferSend_message_name_, NDR_POINTER_REF, "Pointer to Message Name (uint16)",hf_wkssvc_wkssvc_NetrMessageBufferSend_message_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrMessageBufferSend_message_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrMessageBufferSend_message_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrMessageBufferSend_message_sender_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrMessageBufferSend_message_sender_name_, NDR_POINTER_UNIQUE, "Pointer to Message Sender Name (uint16)",hf_wkssvc_wkssvc_NetrMessageBufferSend_message_sender_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrMessageBufferSend_message_sender_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrMessageBufferSend_message_sender_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrMessageBufferSend_message_buffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrMessageBufferSend_message_buffer_, NDR_POINTER_REF, "Pointer to Message Buffer (uint8)",hf_wkssvc_wkssvc_NetrMessageBufferSend_message_buffer);

	return offset;
}

static int
wkssvc_dissect_element_NetrMessageBufferSend_message_buffer_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrMessageBufferSend_message_buffer__);

	return offset;
}

static int
wkssvc_dissect_element_NetrMessageBufferSend_message_buffer__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrMessageBufferSend_message_buffer, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrMessageBufferSend_message_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrMessageBufferSend_message_size, 0);

	return offset;
}

/* IDL: WERROR wkssvc_NetrMessageBufferSend( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_name, */
/* IDL: [ref] [in] [charset(UTF16)] uint16 *message_name, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *message_sender_name, */
/* IDL: [ref] [in] [size_is(message_size)] uint8 *message_buffer, */
/* IDL: [in] uint32 message_size */
/* IDL: ); */

static int
wkssvc_dissect_NetrMessageBufferSend_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="NetrMessageBufferSend";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetrMessageBufferSend_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="NetrMessageBufferSend";
	offset = wkssvc_dissect_element_NetrMessageBufferSend_server_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrMessageBufferSend_message_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrMessageBufferSend_message_sender_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrMessageBufferSend_message_buffer(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrMessageBufferSend_message_size(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatisticsGet_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrWorkstationStatisticsGet_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetrWorkstationStatisticsGet_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatisticsGet_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrWorkstationStatisticsGet_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatisticsGet_unknown2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrWorkstationStatisticsGet_unknown2_, NDR_POINTER_UNIQUE, "Pointer to Unknown2 (uint16)",hf_wkssvc_wkssvc_NetrWorkstationStatisticsGet_unknown2);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatisticsGet_unknown2_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrWorkstationStatisticsGet_unknown2, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatisticsGet_unknown3(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWorkstationStatisticsGet_unknown3, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatisticsGet_unknown4(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrWorkstationStatisticsGet_unknown4, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatisticsGet_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrWorkstationStatisticsGet_info_, NDR_POINTER_REF, "Pointer to Info (wkssvc_NetrWorkstationStatistics)",hf_wkssvc_wkssvc_NetrWorkstationStatisticsGet_info);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatisticsGet_info_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrWorkstationStatisticsGet_info__, NDR_POINTER_REF, "Pointer to Info (wkssvc_NetrWorkstationStatistics)",hf_wkssvc_wkssvc_NetrWorkstationStatisticsGet_info);

	return offset;
}

static int
wkssvc_dissect_element_NetrWorkstationStatisticsGet_info__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_NetrWorkstationStatistics(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetrWorkstationStatisticsGet_info,0);

	return offset;
}

/* IDL: WERROR wkssvc_NetrWorkstationStatisticsGet( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_name, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *unknown2, */
/* IDL: [in] uint32 unknown3, */
/* IDL: [in] uint32 unknown4, */
/* IDL: [out] [ref] wkssvc_NetrWorkstationStatistics **info */
/* IDL: ); */

static int
wkssvc_dissect_NetrWorkstationStatisticsGet_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="NetrWorkstationStatisticsGet";
	offset = wkssvc_dissect_element_NetrWorkstationStatisticsGet_info(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetrWorkstationStatisticsGet_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="NetrWorkstationStatisticsGet";
	offset = wkssvc_dissect_element_NetrWorkstationStatisticsGet_server_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrWorkstationStatisticsGet_unknown2(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrWorkstationStatisticsGet_unknown3(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrWorkstationStatisticsGet_unknown4(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetrLogonDomainNameAdd_domain_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrLogonDomainNameAdd_domain_name_, NDR_POINTER_REF, "Pointer to Domain Name (uint16)",hf_wkssvc_wkssvc_NetrLogonDomainNameAdd_domain_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrLogonDomainNameAdd_domain_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrLogonDomainNameAdd_domain_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

/* IDL: WERROR wkssvc_NetrLogonDomainNameAdd( */
/* IDL: [ref] [in] [charset(UTF16)] uint16 *domain_name */
/* IDL: ); */

static int
wkssvc_dissect_NetrLogonDomainNameAdd_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="NetrLogonDomainNameAdd";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetrLogonDomainNameAdd_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="NetrLogonDomainNameAdd";
	offset = wkssvc_dissect_element_NetrLogonDomainNameAdd_domain_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetrLogonDomainNameDel_domain_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrLogonDomainNameDel_domain_name_, NDR_POINTER_REF, "Pointer to Domain Name (uint16)",hf_wkssvc_wkssvc_NetrLogonDomainNameDel_domain_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrLogonDomainNameDel_domain_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrLogonDomainNameDel_domain_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

/* IDL: WERROR wkssvc_NetrLogonDomainNameDel( */
/* IDL: [ref] [in] [charset(UTF16)] uint16 *domain_name */
/* IDL: ); */

static int
wkssvc_dissect_NetrLogonDomainNameDel_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="NetrLogonDomainNameDel";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetrLogonDomainNameDel_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="NetrLogonDomainNameDel";
	offset = wkssvc_dissect_element_NetrLogonDomainNameDel_domain_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrJoinDomain_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetrJoinDomain_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrJoinDomain_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain_domain_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrJoinDomain_domain_name_, NDR_POINTER_REF, "Pointer to Domain Name (uint16)",hf_wkssvc_wkssvc_NetrJoinDomain_domain_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain_domain_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrJoinDomain_domain_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain_account_ou(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrJoinDomain_account_ou_, NDR_POINTER_UNIQUE, "Pointer to Account Ou (uint16)",hf_wkssvc_wkssvc_NetrJoinDomain_account_ou);

	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain_account_ou_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrJoinDomain_account_ou, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain_Account(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrJoinDomain_Account_, NDR_POINTER_UNIQUE, "Pointer to Account (uint16)",hf_wkssvc_wkssvc_NetrJoinDomain_Account);

	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain_Account_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrJoinDomain_Account, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain_unknown(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrJoinDomain_unknown_, NDR_POINTER_UNIQUE, "Pointer to Unknown (uint16)",hf_wkssvc_wkssvc_NetrJoinDomain_unknown);

	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain_unknown_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrJoinDomain_unknown, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain_join_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_bitmap_joinflags(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrJoinDomain_join_flags, 0);

	return offset;
}

/* IDL: WERROR wkssvc_NetrJoinDomain( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_name, */
/* IDL: [ref] [in] [charset(UTF16)] uint16 *domain_name, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *account_ou, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *Account, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *unknown, */
/* IDL: [in] wkssvc_joinflags join_flags */
/* IDL: ); */

static int
wkssvc_dissect_NetrJoinDomain_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="NetrJoinDomain";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetrJoinDomain_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="NetrJoinDomain";
	offset = wkssvc_dissect_element_NetrJoinDomain_server_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrJoinDomain_domain_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrJoinDomain_account_ou(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrJoinDomain_Account(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrJoinDomain_unknown(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrJoinDomain_join_flags(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetrUnjoinDomain_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUnjoinDomain_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetrUnjoinDomain_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrUnjoinDomain_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrUnjoinDomain_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrUnjoinDomain_Account(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUnjoinDomain_Account_, NDR_POINTER_UNIQUE, "Pointer to Account (uint16)",hf_wkssvc_wkssvc_NetrUnjoinDomain_Account);

	return offset;
}

static int
wkssvc_dissect_element_NetrUnjoinDomain_Account_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrUnjoinDomain_Account, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrUnjoinDomain_password(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUnjoinDomain_password_, NDR_POINTER_UNIQUE, "Pointer to Password (uint16)",hf_wkssvc_wkssvc_NetrUnjoinDomain_password);

	return offset;
}

static int
wkssvc_dissect_element_NetrUnjoinDomain_password_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrUnjoinDomain_password, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrUnjoinDomain_unjoin_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_bitmap_joinflags(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrUnjoinDomain_unjoin_flags, 0);

	return offset;
}

/* IDL: WERROR wkssvc_NetrUnjoinDomain( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_name, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *Account, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *password, */
/* IDL: [in] wkssvc_joinflags unjoin_flags */
/* IDL: ); */

static int
wkssvc_dissect_NetrUnjoinDomain_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="NetrUnjoinDomain";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetrUnjoinDomain_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="NetrUnjoinDomain";
	offset = wkssvc_dissect_element_NetrUnjoinDomain_server_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrUnjoinDomain_Account(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrUnjoinDomain_password(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrUnjoinDomain_unjoin_flags(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetrRenameMachineInDomain_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrRenameMachineInDomain_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetrRenameMachineInDomain_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrRenameMachineInDomain_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrRenameMachineInDomain_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrRenameMachineInDomain_NewMachineName(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrRenameMachineInDomain_NewMachineName_, NDR_POINTER_UNIQUE, "Pointer to Newmachinename (uint16)",hf_wkssvc_wkssvc_NetrRenameMachineInDomain_NewMachineName);

	return offset;
}

static int
wkssvc_dissect_element_NetrRenameMachineInDomain_NewMachineName_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrRenameMachineInDomain_NewMachineName, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrRenameMachineInDomain_Account(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrRenameMachineInDomain_Account_, NDR_POINTER_UNIQUE, "Pointer to Account (uint16)",hf_wkssvc_wkssvc_NetrRenameMachineInDomain_Account);

	return offset;
}

static int
wkssvc_dissect_element_NetrRenameMachineInDomain_Account_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrRenameMachineInDomain_Account, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrRenameMachineInDomain_password(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrRenameMachineInDomain_password_, NDR_POINTER_UNIQUE, "Pointer to Password (uint16)",hf_wkssvc_wkssvc_NetrRenameMachineInDomain_password);

	return offset;
}

static int
wkssvc_dissect_element_NetrRenameMachineInDomain_password_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrRenameMachineInDomain_password, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrRenameMachineInDomain_RenameOptions(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_bitmap_renameflags(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrRenameMachineInDomain_RenameOptions, 0);

	return offset;
}

/* IDL: WERROR wkssvc_NetrRenameMachineInDomain( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_name, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *NewMachineName, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *Account, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *password, */
/* IDL: [in] wkssvc_renameflags RenameOptions */
/* IDL: ); */

static int
wkssvc_dissect_NetrRenameMachineInDomain_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="NetrRenameMachineInDomain";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetrRenameMachineInDomain_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="NetrRenameMachineInDomain";
	offset = wkssvc_dissect_element_NetrRenameMachineInDomain_server_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrRenameMachineInDomain_NewMachineName(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrRenameMachineInDomain_Account(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrRenameMachineInDomain_password(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrRenameMachineInDomain_RenameOptions(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetrValidateName_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrValidateName_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetrValidateName_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrValidateName_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrValidateName_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrValidateName_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrValidateName_name_, NDR_POINTER_REF, "Pointer to Name (uint16)",hf_wkssvc_wkssvc_NetrValidateName_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrValidateName_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrValidateName_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrValidateName_Account(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrValidateName_Account_, NDR_POINTER_UNIQUE, "Pointer to Account (uint16)",hf_wkssvc_wkssvc_NetrValidateName_Account);

	return offset;
}

static int
wkssvc_dissect_element_NetrValidateName_Account_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrValidateName_Account, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrValidateName_Password(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrValidateName_Password_, NDR_POINTER_UNIQUE, "Pointer to Password (uint16)",hf_wkssvc_wkssvc_NetrValidateName_Password);

	return offset;
}

static int
wkssvc_dissect_element_NetrValidateName_Password_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrValidateName_Password, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrValidateName_name_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_enum_NetValidateNameType(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrValidateName_name_type, 0);

	return offset;
}

/* IDL: WERROR wkssvc_NetrValidateName( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_name, */
/* IDL: [ref] [in] [charset(UTF16)] uint16 *name, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *Account, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *Password, */
/* IDL: [in] wkssvc_NetValidateNameType name_type */
/* IDL: ); */

static int
wkssvc_dissect_NetrValidateName_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="NetrValidateName";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetrValidateName_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="NetrValidateName";
	offset = wkssvc_dissect_element_NetrValidateName_server_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrValidateName_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrValidateName_Account(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrValidateName_Password(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrValidateName_name_type(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinInformation_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrGetJoinInformation_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetrGetJoinInformation_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinInformation_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrGetJoinInformation_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinInformation_name_buffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrGetJoinInformation_name_buffer_, NDR_POINTER_REF, "Pointer to Name Buffer (uint16)",hf_wkssvc_wkssvc_NetrGetJoinInformation_name_buffer);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinInformation_name_buffer_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrGetJoinInformation_name_buffer__, NDR_POINTER_REF, "Pointer to Name Buffer (uint16)",hf_wkssvc_wkssvc_NetrGetJoinInformation_name_buffer);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinInformation_name_buffer__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrGetJoinInformation_name_buffer, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinInformation_name_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrGetJoinInformation_name_type_, NDR_POINTER_REF, "Pointer to Name Type (wkssvc_NetJoinStatus)",hf_wkssvc_wkssvc_NetrGetJoinInformation_name_type);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinInformation_name_type_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_enum_NetJoinStatus(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrGetJoinInformation_name_type, 0);

	return offset;
}

/* IDL: WERROR wkssvc_NetrGetJoinInformation( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_name, */
/* IDL: [out] [ref] [in] [charset(UTF16)] uint16 **name_buffer, */
/* IDL: [out] [ref] wkssvc_NetJoinStatus *name_type */
/* IDL: ); */

static int
wkssvc_dissect_NetrGetJoinInformation_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="NetrGetJoinInformation";
	offset = wkssvc_dissect_element_NetrGetJoinInformation_name_buffer(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = wkssvc_dissect_element_NetrGetJoinInformation_name_type(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetrGetJoinInformation_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="NetrGetJoinInformation";
	offset = wkssvc_dissect_element_NetrGetJoinInformation_server_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrGetJoinInformation_name_buffer(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinableOus_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrGetJoinableOus_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetrGetJoinableOus_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinableOus_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrGetJoinableOus_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinableOus_domain_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrGetJoinableOus_domain_name_, NDR_POINTER_REF, "Pointer to Domain Name (uint16)",hf_wkssvc_wkssvc_NetrGetJoinableOus_domain_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinableOus_domain_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrGetJoinableOus_domain_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinableOus_Account(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrGetJoinableOus_Account_, NDR_POINTER_UNIQUE, "Pointer to Account (uint16)",hf_wkssvc_wkssvc_NetrGetJoinableOus_Account);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinableOus_Account_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrGetJoinableOus_Account, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinableOus_unknown(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrGetJoinableOus_unknown_, NDR_POINTER_UNIQUE, "Pointer to Unknown (uint16)",hf_wkssvc_wkssvc_NetrGetJoinableOus_unknown);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinableOus_unknown_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrGetJoinableOus_unknown, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinableOus_num_ous(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrGetJoinableOus_num_ous_, NDR_POINTER_REF, "Pointer to Num Ous (uint32)",hf_wkssvc_wkssvc_NetrGetJoinableOus_num_ous);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinableOus_num_ous_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrGetJoinableOus_num_ous, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinableOus_ous(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrGetJoinableOus_ous_, NDR_POINTER_REF, "Pointer to Ous (uint16)",hf_wkssvc_wkssvc_NetrGetJoinableOus_ous);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinableOus_ous_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrGetJoinableOus_ous__);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinableOus_ous__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrGetJoinableOus_ous___, NDR_POINTER_REF, "Pointer to Ous (uint16)",hf_wkssvc_wkssvc_NetrGetJoinableOus_ous);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinableOus_ous___(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrGetJoinableOus_ous____, NDR_POINTER_REF, "Pointer to Ous (uint16)",hf_wkssvc_wkssvc_NetrGetJoinableOus_ous);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinableOus_ous____(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrGetJoinableOus_ous, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

/* IDL: WERROR wkssvc_NetrGetJoinableOus( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_name, */
/* IDL: [ref] [in] [charset(UTF16)] uint16 *domain_name, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *Account, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *unknown, */
/* IDL: [out] [in] [ref] uint32 *num_ous, */
/* IDL: [out] [ref] [charset(UTF16)] [size_is(*num_ous)] uint16 ***ous */
/* IDL: ); */

static int
wkssvc_dissect_NetrGetJoinableOus_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="NetrGetJoinableOus";
	offset = wkssvc_dissect_element_NetrGetJoinableOus_num_ous(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = wkssvc_dissect_element_NetrGetJoinableOus_ous(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetrGetJoinableOus_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="NetrGetJoinableOus";
	offset = wkssvc_dissect_element_NetrGetJoinableOus_server_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrGetJoinableOus_domain_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrGetJoinableOus_Account(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrGetJoinableOus_unknown(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrGetJoinableOus_num_ous(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain2_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrJoinDomain2_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetrJoinDomain2_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain2_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrJoinDomain2_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain2_domain_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrJoinDomain2_domain_name_, NDR_POINTER_REF, "Pointer to Domain Name (uint16)",hf_wkssvc_wkssvc_NetrJoinDomain2_domain_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain2_domain_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrJoinDomain2_domain_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain2_account_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrJoinDomain2_account_name_, NDR_POINTER_UNIQUE, "Pointer to Account Name (uint16)",hf_wkssvc_wkssvc_NetrJoinDomain2_account_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain2_account_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrJoinDomain2_account_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain2_admin_account(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrJoinDomain2_admin_account_, NDR_POINTER_UNIQUE, "Pointer to Admin Account (uint16)",hf_wkssvc_wkssvc_NetrJoinDomain2_admin_account);

	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain2_admin_account_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrJoinDomain2_admin_account, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain2_encrypted_password(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrJoinDomain2_encrypted_password_, NDR_POINTER_UNIQUE, "Pointer to Encrypted Password (wkssvc_PasswordBuffer)",hf_wkssvc_wkssvc_NetrJoinDomain2_encrypted_password);

	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain2_encrypted_password_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_PasswordBuffer(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetrJoinDomain2_encrypted_password,0);

	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain2_join_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_bitmap_joinflags(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrJoinDomain2_join_flags, 0);

	return offset;
}

/* IDL: WERROR wkssvc_NetrJoinDomain2( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_name, */
/* IDL: [ref] [in] [charset(UTF16)] uint16 *domain_name, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *account_name, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *admin_account, */
/* IDL: [unique(1)] [in] wkssvc_PasswordBuffer *encrypted_password, */
/* IDL: [in] wkssvc_joinflags join_flags */
/* IDL: ); */

static int
wkssvc_dissect_NetrJoinDomain2_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="NetrJoinDomain2";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetrJoinDomain2_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="NetrJoinDomain2";
	offset = wkssvc_dissect_element_NetrJoinDomain2_server_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrJoinDomain2_domain_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrJoinDomain2_account_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrJoinDomain2_admin_account(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrJoinDomain2_encrypted_password(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrJoinDomain2_join_flags(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetrUnjoinDomain2_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUnjoinDomain2_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetrUnjoinDomain2_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrUnjoinDomain2_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrUnjoinDomain2_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrUnjoinDomain2_account(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUnjoinDomain2_account_, NDR_POINTER_UNIQUE, "Pointer to Account (uint16)",hf_wkssvc_wkssvc_NetrUnjoinDomain2_account);

	return offset;
}

static int
wkssvc_dissect_element_NetrUnjoinDomain2_account_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrUnjoinDomain2_account, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrUnjoinDomain2_encrypted_password(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrUnjoinDomain2_encrypted_password_, NDR_POINTER_UNIQUE, "Pointer to Encrypted Password (wkssvc_PasswordBuffer)",hf_wkssvc_wkssvc_NetrUnjoinDomain2_encrypted_password);

	return offset;
}

static int
wkssvc_dissect_element_NetrUnjoinDomain2_encrypted_password_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_PasswordBuffer(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetrUnjoinDomain2_encrypted_password,0);

	return offset;
}

static int
wkssvc_dissect_element_NetrUnjoinDomain2_unjoin_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_bitmap_joinflags(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrUnjoinDomain2_unjoin_flags, 0);

	return offset;
}

/* IDL: WERROR wkssvc_NetrUnjoinDomain2( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_name, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *account, */
/* IDL: [unique(1)] [in] wkssvc_PasswordBuffer *encrypted_password, */
/* IDL: [in] wkssvc_joinflags unjoin_flags */
/* IDL: ); */

static int
wkssvc_dissect_NetrUnjoinDomain2_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="NetrUnjoinDomain2";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetrUnjoinDomain2_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="NetrUnjoinDomain2";
	offset = wkssvc_dissect_element_NetrUnjoinDomain2_server_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrUnjoinDomain2_account(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrUnjoinDomain2_encrypted_password(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrUnjoinDomain2_unjoin_flags(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetrRenameMachineInDomain2_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrRenameMachineInDomain2_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrRenameMachineInDomain2_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrRenameMachineInDomain2_NewMachineName(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrRenameMachineInDomain2_NewMachineName_, NDR_POINTER_UNIQUE, "Pointer to Newmachinename (uint16)",hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_NewMachineName);

	return offset;
}

static int
wkssvc_dissect_element_NetrRenameMachineInDomain2_NewMachineName_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_NewMachineName, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrRenameMachineInDomain2_Account(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrRenameMachineInDomain2_Account_, NDR_POINTER_UNIQUE, "Pointer to Account (uint16)",hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_Account);

	return offset;
}

static int
wkssvc_dissect_element_NetrRenameMachineInDomain2_Account_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_Account, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrRenameMachineInDomain2_EncryptedPassword(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrRenameMachineInDomain2_EncryptedPassword_, NDR_POINTER_UNIQUE, "Pointer to Encryptedpassword (wkssvc_PasswordBuffer)",hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_EncryptedPassword);

	return offset;
}

static int
wkssvc_dissect_element_NetrRenameMachineInDomain2_EncryptedPassword_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_PasswordBuffer(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_EncryptedPassword,0);

	return offset;
}

static int
wkssvc_dissect_element_NetrRenameMachineInDomain2_RenameOptions(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_bitmap_renameflags(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_RenameOptions, 0);

	return offset;
}

/* IDL: WERROR wkssvc_NetrRenameMachineInDomain2( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_name, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *NewMachineName, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *Account, */
/* IDL: [unique(1)] [in] wkssvc_PasswordBuffer *EncryptedPassword, */
/* IDL: [in] wkssvc_renameflags RenameOptions */
/* IDL: ); */

static int
wkssvc_dissect_NetrRenameMachineInDomain2_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="NetrRenameMachineInDomain2";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetrRenameMachineInDomain2_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="NetrRenameMachineInDomain2";
	offset = wkssvc_dissect_element_NetrRenameMachineInDomain2_server_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrRenameMachineInDomain2_NewMachineName(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrRenameMachineInDomain2_Account(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrRenameMachineInDomain2_EncryptedPassword(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrRenameMachineInDomain2_RenameOptions(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetrValidateName2_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrValidateName2_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetrValidateName2_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrValidateName2_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrValidateName2_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrValidateName2_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrValidateName2_name_, NDR_POINTER_REF, "Pointer to Name (uint16)",hf_wkssvc_wkssvc_NetrValidateName2_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrValidateName2_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrValidateName2_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrValidateName2_Account(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrValidateName2_Account_, NDR_POINTER_UNIQUE, "Pointer to Account (uint16)",hf_wkssvc_wkssvc_NetrValidateName2_Account);

	return offset;
}

static int
wkssvc_dissect_element_NetrValidateName2_Account_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrValidateName2_Account, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrValidateName2_EncryptedPassword(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrValidateName2_EncryptedPassword_, NDR_POINTER_UNIQUE, "Pointer to Encryptedpassword (wkssvc_PasswordBuffer)",hf_wkssvc_wkssvc_NetrValidateName2_EncryptedPassword);

	return offset;
}

static int
wkssvc_dissect_element_NetrValidateName2_EncryptedPassword_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_PasswordBuffer(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetrValidateName2_EncryptedPassword,0);

	return offset;
}

static int
wkssvc_dissect_element_NetrValidateName2_name_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_enum_NetValidateNameType(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrValidateName2_name_type, 0);

	return offset;
}

/* IDL: WERROR wkssvc_NetrValidateName2( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_name, */
/* IDL: [ref] [in] [charset(UTF16)] uint16 *name, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *Account, */
/* IDL: [unique(1)] [in] wkssvc_PasswordBuffer *EncryptedPassword, */
/* IDL: [in] wkssvc_NetValidateNameType name_type */
/* IDL: ); */

static int
wkssvc_dissect_NetrValidateName2_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="NetrValidateName2";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetrValidateName2_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="NetrValidateName2";
	offset = wkssvc_dissect_element_NetrValidateName2_server_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrValidateName2_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrValidateName2_Account(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrValidateName2_EncryptedPassword(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrValidateName2_name_type(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinableOus2_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrGetJoinableOus2_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetrGetJoinableOus2_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinableOus2_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrGetJoinableOus2_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinableOus2_domain_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrGetJoinableOus2_domain_name_, NDR_POINTER_REF, "Pointer to Domain Name (uint16)",hf_wkssvc_wkssvc_NetrGetJoinableOus2_domain_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinableOus2_domain_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrGetJoinableOus2_domain_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinableOus2_Account(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrGetJoinableOus2_Account_, NDR_POINTER_UNIQUE, "Pointer to Account (uint16)",hf_wkssvc_wkssvc_NetrGetJoinableOus2_Account);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinableOus2_Account_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrGetJoinableOus2_Account, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinableOus2_EncryptedPassword(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrGetJoinableOus2_EncryptedPassword_, NDR_POINTER_UNIQUE, "Pointer to Encryptedpassword (wkssvc_PasswordBuffer)",hf_wkssvc_wkssvc_NetrGetJoinableOus2_EncryptedPassword);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinableOus2_EncryptedPassword_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_PasswordBuffer(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetrGetJoinableOus2_EncryptedPassword,0);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinableOus2_num_ous(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrGetJoinableOus2_num_ous_, NDR_POINTER_REF, "Pointer to Num Ous (uint32)",hf_wkssvc_wkssvc_NetrGetJoinableOus2_num_ous);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinableOus2_num_ous_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrGetJoinableOus2_num_ous, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinableOus2_ous(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrGetJoinableOus2_ous_, NDR_POINTER_REF, "Pointer to Ous (uint16)",hf_wkssvc_wkssvc_NetrGetJoinableOus2_ous);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinableOus2_ous_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrGetJoinableOus2_ous__);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinableOus2_ous__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrGetJoinableOus2_ous___, NDR_POINTER_REF, "Pointer to Ous (uint16)",hf_wkssvc_wkssvc_NetrGetJoinableOus2_ous);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinableOus2_ous___(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrGetJoinableOus2_ous____, NDR_POINTER_REF, "Pointer to Ous (uint16)",hf_wkssvc_wkssvc_NetrGetJoinableOus2_ous);

	return offset;
}

static int
wkssvc_dissect_element_NetrGetJoinableOus2_ous____(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrGetJoinableOus2_ous, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

/* IDL: WERROR wkssvc_NetrGetJoinableOus2( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_name, */
/* IDL: [ref] [in] [charset(UTF16)] uint16 *domain_name, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *Account, */
/* IDL: [unique(1)] [in] wkssvc_PasswordBuffer *EncryptedPassword, */
/* IDL: [out] [in] [ref] uint32 *num_ous, */
/* IDL: [out] [ref] [charset(UTF16)] [size_is(*num_ous)] uint16 ***ous */
/* IDL: ); */

static int
wkssvc_dissect_NetrGetJoinableOus2_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="NetrGetJoinableOus2";
	offset = wkssvc_dissect_element_NetrGetJoinableOus2_num_ous(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = wkssvc_dissect_element_NetrGetJoinableOus2_ous(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetrGetJoinableOus2_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="NetrGetJoinableOus2";
	offset = wkssvc_dissect_element_NetrGetJoinableOus2_server_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrGetJoinableOus2_domain_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrGetJoinableOus2_Account(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrGetJoinableOus2_EncryptedPassword(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrGetJoinableOus2_num_ous(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetrAddAlternateComputerName_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrAddAlternateComputerName_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetrAddAlternateComputerName_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrAddAlternateComputerName_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrAddAlternateComputerName_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrAddAlternateComputerName_NewAlternateMachineName(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrAddAlternateComputerName_NewAlternateMachineName_, NDR_POINTER_UNIQUE, "Pointer to Newalternatemachinename (uint16)",hf_wkssvc_wkssvc_NetrAddAlternateComputerName_NewAlternateMachineName);

	return offset;
}

static int
wkssvc_dissect_element_NetrAddAlternateComputerName_NewAlternateMachineName_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrAddAlternateComputerName_NewAlternateMachineName, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrAddAlternateComputerName_Account(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrAddAlternateComputerName_Account_, NDR_POINTER_UNIQUE, "Pointer to Account (uint16)",hf_wkssvc_wkssvc_NetrAddAlternateComputerName_Account);

	return offset;
}

static int
wkssvc_dissect_element_NetrAddAlternateComputerName_Account_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrAddAlternateComputerName_Account, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrAddAlternateComputerName_EncryptedPassword(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrAddAlternateComputerName_EncryptedPassword_, NDR_POINTER_UNIQUE, "Pointer to Encryptedpassword (wkssvc_PasswordBuffer)",hf_wkssvc_wkssvc_NetrAddAlternateComputerName_EncryptedPassword);

	return offset;
}

static int
wkssvc_dissect_element_NetrAddAlternateComputerName_EncryptedPassword_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_PasswordBuffer(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetrAddAlternateComputerName_EncryptedPassword,0);

	return offset;
}

static int
wkssvc_dissect_element_NetrAddAlternateComputerName_Reserved(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrAddAlternateComputerName_Reserved, 0);

	return offset;
}

/* IDL: WERROR wkssvc_NetrAddAlternateComputerName( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_name, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *NewAlternateMachineName, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *Account, */
/* IDL: [unique(1)] [in] wkssvc_PasswordBuffer *EncryptedPassword, */
/* IDL: [in] uint32 Reserved */
/* IDL: ); */

static int
wkssvc_dissect_NetrAddAlternateComputerName_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="NetrAddAlternateComputerName";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetrAddAlternateComputerName_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="NetrAddAlternateComputerName";
	offset = wkssvc_dissect_element_NetrAddAlternateComputerName_server_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrAddAlternateComputerName_NewAlternateMachineName(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrAddAlternateComputerName_Account(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrAddAlternateComputerName_EncryptedPassword(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrAddAlternateComputerName_Reserved(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetrRemoveAlternateComputerName_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrRemoveAlternateComputerName_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrRemoveAlternateComputerName_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrRemoveAlternateComputerName_AlternateMachineNameToRemove(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrRemoveAlternateComputerName_AlternateMachineNameToRemove_, NDR_POINTER_UNIQUE, "Pointer to Alternatemachinenametoremove (uint16)",hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_AlternateMachineNameToRemove);

	return offset;
}

static int
wkssvc_dissect_element_NetrRemoveAlternateComputerName_AlternateMachineNameToRemove_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_AlternateMachineNameToRemove, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrRemoveAlternateComputerName_Account(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrRemoveAlternateComputerName_Account_, NDR_POINTER_UNIQUE, "Pointer to Account (uint16)",hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_Account);

	return offset;
}

static int
wkssvc_dissect_element_NetrRemoveAlternateComputerName_Account_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_Account, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrRemoveAlternateComputerName_EncryptedPassword(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrRemoveAlternateComputerName_EncryptedPassword_, NDR_POINTER_UNIQUE, "Pointer to Encryptedpassword (wkssvc_PasswordBuffer)",hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_EncryptedPassword);

	return offset;
}

static int
wkssvc_dissect_element_NetrRemoveAlternateComputerName_EncryptedPassword_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_PasswordBuffer(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_EncryptedPassword,0);

	return offset;
}

static int
wkssvc_dissect_element_NetrRemoveAlternateComputerName_Reserved(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_Reserved, 0);

	return offset;
}

/* IDL: WERROR wkssvc_NetrRemoveAlternateComputerName( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_name, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *AlternateMachineNameToRemove, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *Account, */
/* IDL: [unique(1)] [in] wkssvc_PasswordBuffer *EncryptedPassword, */
/* IDL: [in] uint32 Reserved */
/* IDL: ); */

static int
wkssvc_dissect_NetrRemoveAlternateComputerName_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="NetrRemoveAlternateComputerName";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetrRemoveAlternateComputerName_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="NetrRemoveAlternateComputerName";
	offset = wkssvc_dissect_element_NetrRemoveAlternateComputerName_server_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrRemoveAlternateComputerName_AlternateMachineNameToRemove(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrRemoveAlternateComputerName_Account(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrRemoveAlternateComputerName_EncryptedPassword(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrRemoveAlternateComputerName_Reserved(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetrSetPrimaryComputername_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrSetPrimaryComputername_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetrSetPrimaryComputername_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrSetPrimaryComputername_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrSetPrimaryComputername_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrSetPrimaryComputername_primary_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrSetPrimaryComputername_primary_name_, NDR_POINTER_UNIQUE, "Pointer to Primary Name (uint16)",hf_wkssvc_wkssvc_NetrSetPrimaryComputername_primary_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrSetPrimaryComputername_primary_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrSetPrimaryComputername_primary_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrSetPrimaryComputername_Account(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrSetPrimaryComputername_Account_, NDR_POINTER_UNIQUE, "Pointer to Account (uint16)",hf_wkssvc_wkssvc_NetrSetPrimaryComputername_Account);

	return offset;
}

static int
wkssvc_dissect_element_NetrSetPrimaryComputername_Account_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrSetPrimaryComputername_Account, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrSetPrimaryComputername_EncryptedPassword(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrSetPrimaryComputername_EncryptedPassword_, NDR_POINTER_UNIQUE, "Pointer to Encryptedpassword (wkssvc_PasswordBuffer)",hf_wkssvc_wkssvc_NetrSetPrimaryComputername_EncryptedPassword);

	return offset;
}

static int
wkssvc_dissect_element_NetrSetPrimaryComputername_EncryptedPassword_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_PasswordBuffer(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetrSetPrimaryComputername_EncryptedPassword,0);

	return offset;
}

static int
wkssvc_dissect_element_NetrSetPrimaryComputername_Reserved(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrSetPrimaryComputername_Reserved, 0);

	return offset;
}

/* IDL: WERROR wkssvc_NetrSetPrimaryComputername( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_name, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *primary_name, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *Account, */
/* IDL: [unique(1)] [in] wkssvc_PasswordBuffer *EncryptedPassword, */
/* IDL: [in] uint32 Reserved */
/* IDL: ); */

static int
wkssvc_dissect_NetrSetPrimaryComputername_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="NetrSetPrimaryComputername";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetrSetPrimaryComputername_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="NetrSetPrimaryComputername";
	offset = wkssvc_dissect_element_NetrSetPrimaryComputername_server_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrSetPrimaryComputername_primary_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrSetPrimaryComputername_Account(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrSetPrimaryComputername_EncryptedPassword(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrSetPrimaryComputername_Reserved(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetrEnumerateComputerNames_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrEnumerateComputerNames_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetrEnumerateComputerNames_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrEnumerateComputerNames_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrEnumerateComputerNames_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrEnumerateComputerNames_name_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_enum_ComputerNameType(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrEnumerateComputerNames_name_type, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrEnumerateComputerNames_Reserved(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_wkssvc_NetrEnumerateComputerNames_Reserved, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetrEnumerateComputerNames_ctr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrEnumerateComputerNames_ctr_, NDR_POINTER_REF, "Pointer to Ctr (wkssvc_ComputerNamesCtr)",hf_wkssvc_wkssvc_NetrEnumerateComputerNames_ctr);

	return offset;
}

static int
wkssvc_dissect_element_NetrEnumerateComputerNames_ctr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, wkssvc_dissect_element_NetrEnumerateComputerNames_ctr__, NDR_POINTER_REF, "Pointer to Ctr (wkssvc_ComputerNamesCtr)",hf_wkssvc_wkssvc_NetrEnumerateComputerNames_ctr);

	return offset;
}

static int
wkssvc_dissect_element_NetrEnumerateComputerNames_ctr__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_struct_ComputerNamesCtr(tvb,offset,pinfo,tree,di,drep,hf_wkssvc_wkssvc_NetrEnumerateComputerNames_ctr,0);

	return offset;
}

/* IDL: WERROR wkssvc_NetrEnumerateComputerNames( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_name, */
/* IDL: [in] wkssvc_ComputerNameType name_type, */
/* IDL: [in] uint32 Reserved, */
/* IDL: [out] [ref] wkssvc_ComputerNamesCtr **ctr */
/* IDL: ); */

static int
wkssvc_dissect_NetrEnumerateComputerNames_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="NetrEnumerateComputerNames";
	offset = wkssvc_dissect_element_NetrEnumerateComputerNames_ctr(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_wkssvc_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetrEnumerateComputerNames_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="NetrEnumerateComputerNames";
	offset = wkssvc_dissect_element_NetrEnumerateComputerNames_server_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrEnumerateComputerNames_name_type(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = wkssvc_dissect_element_NetrEnumerateComputerNames_Reserved(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}


static dcerpc_sub_dissector wkssvc_dissectors[] = {
	{ 0, "NetWkstaGetInfo",
	   wkssvc_dissect_NetWkstaGetInfo_request, wkssvc_dissect_NetWkstaGetInfo_response},
	{ 1, "NetWkstaSetInfo",
	   wkssvc_dissect_NetWkstaSetInfo_request, wkssvc_dissect_NetWkstaSetInfo_response},
	{ 2, "NetWkstaEnumUsers",
	   wkssvc_dissect_NetWkstaEnumUsers_request, wkssvc_dissect_NetWkstaEnumUsers_response},
	{ 3, "NetrWkstaUserGetInfo",
	   wkssvc_dissect_NetrWkstaUserGetInfo_request, wkssvc_dissect_NetrWkstaUserGetInfo_response},
	{ 4, "NetrWkstaUserSetInfo",
	   wkssvc_dissect_NetrWkstaUserSetInfo_request, wkssvc_dissect_NetrWkstaUserSetInfo_response},
	{ 5, "NetWkstaTransportEnum",
	   wkssvc_dissect_NetWkstaTransportEnum_request, wkssvc_dissect_NetWkstaTransportEnum_response},
	{ 6, "NetrWkstaTransportAdd",
	   wkssvc_dissect_NetrWkstaTransportAdd_request, wkssvc_dissect_NetrWkstaTransportAdd_response},
	{ 7, "NetrWkstaTransportDel",
	   wkssvc_dissect_NetrWkstaTransportDel_request, wkssvc_dissect_NetrWkstaTransportDel_response},
	{ 8, "NetrUseAdd",
	   wkssvc_dissect_NetrUseAdd_request, wkssvc_dissect_NetrUseAdd_response},
	{ 9, "NetrUseGetInfo",
	   wkssvc_dissect_NetrUseGetInfo_request, wkssvc_dissect_NetrUseGetInfo_response},
	{ 10, "NetrUseDel",
	   wkssvc_dissect_NetrUseDel_request, wkssvc_dissect_NetrUseDel_response},
	{ 11, "NetrUseEnum",
	   wkssvc_dissect_NetrUseEnum_request, wkssvc_dissect_NetrUseEnum_response},
	{ 12, "NetrMessageBufferSend",
	   wkssvc_dissect_NetrMessageBufferSend_request, wkssvc_dissect_NetrMessageBufferSend_response},
	{ 13, "NetrWorkstationStatisticsGet",
	   wkssvc_dissect_NetrWorkstationStatisticsGet_request, wkssvc_dissect_NetrWorkstationStatisticsGet_response},
	{ 14, "NetrLogonDomainNameAdd",
	   wkssvc_dissect_NetrLogonDomainNameAdd_request, wkssvc_dissect_NetrLogonDomainNameAdd_response},
	{ 15, "NetrLogonDomainNameDel",
	   wkssvc_dissect_NetrLogonDomainNameDel_request, wkssvc_dissect_NetrLogonDomainNameDel_response},
	{ 16, "NetrJoinDomain",
	   wkssvc_dissect_NetrJoinDomain_request, wkssvc_dissect_NetrJoinDomain_response},
	{ 17, "NetrUnjoinDomain",
	   wkssvc_dissect_NetrUnjoinDomain_request, wkssvc_dissect_NetrUnjoinDomain_response},
	{ 18, "NetrRenameMachineInDomain",
	   wkssvc_dissect_NetrRenameMachineInDomain_request, wkssvc_dissect_NetrRenameMachineInDomain_response},
	{ 19, "NetrValidateName",
	   wkssvc_dissect_NetrValidateName_request, wkssvc_dissect_NetrValidateName_response},
	{ 20, "NetrGetJoinInformation",
	   wkssvc_dissect_NetrGetJoinInformation_request, wkssvc_dissect_NetrGetJoinInformation_response},
	{ 21, "NetrGetJoinableOus",
	   wkssvc_dissect_NetrGetJoinableOus_request, wkssvc_dissect_NetrGetJoinableOus_response},
	{ 22, "NetrJoinDomain2",
	   wkssvc_dissect_NetrJoinDomain2_request, wkssvc_dissect_NetrJoinDomain2_response},
	{ 23, "NetrUnjoinDomain2",
	   wkssvc_dissect_NetrUnjoinDomain2_request, wkssvc_dissect_NetrUnjoinDomain2_response},
	{ 24, "NetrRenameMachineInDomain2",
	   wkssvc_dissect_NetrRenameMachineInDomain2_request, wkssvc_dissect_NetrRenameMachineInDomain2_response},
	{ 25, "NetrValidateName2",
	   wkssvc_dissect_NetrValidateName2_request, wkssvc_dissect_NetrValidateName2_response},
	{ 26, "NetrGetJoinableOus2",
	   wkssvc_dissect_NetrGetJoinableOus2_request, wkssvc_dissect_NetrGetJoinableOus2_response},
	{ 27, "NetrAddAlternateComputerName",
	   wkssvc_dissect_NetrAddAlternateComputerName_request, wkssvc_dissect_NetrAddAlternateComputerName_response},
	{ 28, "NetrRemoveAlternateComputerName",
	   wkssvc_dissect_NetrRemoveAlternateComputerName_request, wkssvc_dissect_NetrRemoveAlternateComputerName_response},
	{ 29, "NetrSetPrimaryComputername",
	   wkssvc_dissect_NetrSetPrimaryComputername_request, wkssvc_dissect_NetrSetPrimaryComputername_response},
	{ 30, "NetrEnumerateComputerNames",
	   wkssvc_dissect_NetrEnumerateComputerNames_request, wkssvc_dissect_NetrEnumerateComputerNames_response},
	{ 0, NULL, NULL, NULL }
};

void proto_register_dcerpc_wkssvc(void)
{
	static hf_register_info hf[] = {
	{ &hf_wkssvc_wkssvc_NetrUseInfo2_use_count, 
	  { "Use Count", "wkssvc.wkssvc_NetrUseInfo2.use_count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaTransportInfo0_quality_of_service, 
	  { "Quality Of Service", "wkssvc.wkssvc_NetWkstaTransportInfo0.quality_of_service", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1045_pipe_maximum, 
	  { "Pipe Maximum", "wkssvc.wkssvc_NetWkstaInfo1045.pipe_maximum", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseInfo2_password, 
	  { "Password", "wkssvc.wkssvc_NetrUseInfo2.password", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrJoinDomain2_join_flags, 
	  { "Join Flags", "wkssvc.wkssvc_NetrJoinDomain2.join_flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseEnumCtr_ctr1, 
	  { "Ctr1", "wkssvc.wkssvc_NetrUseEnumCtr.ctr1", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWkstaUserSetInfo_level, 
	  { "Level", "wkssvc.wkssvc_NetrWkstaUserSetInfo.level", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseEnum_entries_read, 
	  { "Entries Read", "wkssvc.wkssvc_NetrUseEnum.entries_read", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrSetPrimaryComputername_EncryptedPassword, 
	  { "Encryptedpassword", "wkssvc.wkssvc_NetrSetPrimaryComputername.EncryptedPassword", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWkstaUserSetInfo_parm_err, 
	  { "Parm Err", "wkssvc.wkssvc_NetrWkstaUserSetInfo.parm_err", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseEnum_info, 
	  { "Info", "wkssvc.wkssvc_NetrUseEnum.info", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrSetPrimaryComputername_Account, 
	  { "Account", "wkssvc.wkssvc_NetrSetPrimaryComputername.Account", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown14, 
	  { "Unknown14", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown14", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaEnumUsersCtr_user0, 
	  { "User0", "wkssvc.wkssvc_NetWkstaEnumUsersCtr.user0", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrGetJoinableOus_domain_name, 
	  { "Domain Name", "wkssvc.wkssvc_NetrGetJoinableOus.domain_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseInfo2_user_name, 
	  { "User Name", "wkssvc.wkssvc_NetrUseInfo2.user_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo101_version_major, 
	  { "Version Major", "wkssvc.wkssvc_NetWkstaInfo101.version_major", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWkstaUserInfo1_other_domains, 
	  { "Other Domains", "wkssvc.wkssvc_NetrWkstaUserInfo1.other_domains", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrGetJoinableOus_Account, 
	  { "Account", "wkssvc.wkssvc_NetrGetJoinableOus.Account", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaTransportCtr_ctr0, 
	  { "Ctr0", "wkssvc.wkssvc_NetWkstaTransportCtr.ctr0", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_dgram_event_reset_freq, 
	  { "Dgram Event Reset Freq", "wkssvc.wkssvc_NetWkstaInfo502.dgram_event_reset_freq", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo102_lan_root, 
	  { "Lan Root", "wkssvc.wkssvc_NetWkstaInfo102.lan_root", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWkstaUserInfo1_user_name, 
	  { "User Name", "wkssvc.wkssvc_NetrWkstaUserInfo1.user_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info502, 
	  { "Info502", "wkssvc.wkssvc_NetWkstaInfo.info502", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown32, 
	  { "Unknown32", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown32", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown29, 
	  { "Unknown29", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown29", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1055_use_raw_write, 
	  { "Use Raw Write", "wkssvc.wkssvc_NetWkstaInfo1055.use_raw_write", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1051, 
	  { "Info1051", "wkssvc.wkssvc_NetWkstaInfo.info1051", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrValidateName2_name, 
	  { "Name", "wkssvc.wkssvc_NetrValidateName2.name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_dormant_file_limit, 
	  { "Dormant File Limit", "wkssvc.wkssvc_NetWkstaInfo502.dormant_file_limit", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_maximum_collection_count, 
	  { "Maximum Collection Count", "wkssvc.wkssvc_NetWkstaInfo502.maximum_collection_count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrMessageBufferSend_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetrMessageBufferSend.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_use_write_raw_data, 
	  { "Use Write Raw Data", "wkssvc.wkssvc_NetWkstaInfo502.use_write_raw_data", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrEnumerateComputerNames_Reserved, 
	  { "Reserved", "wkssvc.wkssvc_NetrEnumerateComputerNames.Reserved", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_size_char_buf, 
	  { "Size Char Buf", "wkssvc.wkssvc_NetWkstaInfo502.size_char_buf", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaTransportCtr0_array, 
	  { "Array", "wkssvc.wkssvc_NetWkstaTransportCtr0.array", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrEnumerateComputerNames_name_type, 
	  { "Name Type", "wkssvc.wkssvc_NetrEnumerateComputerNames.name_type", FT_UINT16, BASE_DEC, VALS(wkssvc_wkssvc_ComputerNameType_vals), 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseAdd_parm_err, 
	  { "Parm Err", "wkssvc.wkssvc_NetrUseAdd.parm_err", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown9, 
	  { "Unknown9", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown9", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrGetJoinableOus2_num_ous, 
	  { "Num Ous", "wkssvc.wkssvc_NetrGetJoinableOus2.num_ous", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrRenameMachineInDomain_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetrRenameMachineInDomain.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown38, 
	  { "Unknown38", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown38", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWkstaUserInfo1101_other_domains, 
	  { "Other Domains", "wkssvc.wkssvc_NetrWkstaUserInfo1101.other_domains", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaGetInfo_level, 
	  { "Level", "wkssvc.wkssvc_NetWkstaGetInfo.level", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseInfo1_ref_count, 
	  { "Ref Count", "wkssvc.wkssvc_NetrUseInfo1.ref_count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown4, 
	  { "Unknown4", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown4", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrJoinDomain2_domain_name, 
	  { "Domain Name", "wkssvc.wkssvc_NetrJoinDomain2.domain_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseEnumCtr_ctr2, 
	  { "Ctr2", "wkssvc.wkssvc_NetrUseEnumCtr.ctr2", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown3, 
	  { "Unknown3", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown3", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrJoinDomain_join_flags, 
	  { "Join Flags", "wkssvc.wkssvc_NetrJoinDomain.join_flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseDel_use_name, 
	  { "Use Name", "wkssvc.wkssvc_NetrUseDel.use_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_buf_files_deny_write, 
	  { "Buf Files Deny Write", "wkssvc.wkssvc_NetWkstaInfo502.buf_files_deny_write", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseGetInfo_use_name, 
	  { "Use Name", "wkssvc.wkssvc_NetrUseGetInfo.use_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1060, 
	  { "Info1060", "wkssvc.wkssvc_NetWkstaInfo.info1060", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatisticsGet_unknown4, 
	  { "Unknown4", "wkssvc.wkssvc_NetrWorkstationStatisticsGet.unknown4", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1057, 
	  { "Info1057", "wkssvc.wkssvc_NetWkstaInfo.info1057", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaTransportInfo_level, 
	  { "Level", "wkssvc.wkssvc_NetWkstaTransportInfo.level", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaTransportInfo0_name, 
	  { "Name", "wkssvc.wkssvc_NetWkstaTransportInfo0.name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseEnumCtr1_array, 
	  { "Array", "wkssvc.wkssvc_NetrUseEnumCtr1.array", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown20, 
	  { "Unknown20", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown20", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseEnum_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetrUseEnum.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_lsa_String_name_size, 
	  { "Name Size", "wkssvc.lsa_String.name_size", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaEnumUsersCtr1_entries_read, 
	  { "Entries Read", "wkssvc.wkssvc_NetWkstaEnumUsersCtr1.entries_read", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown37, 
	  { "Unknown37", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown37", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1058, 
	  { "Info1058", "wkssvc.wkssvc_NetWkstaInfo.info1058", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_lsa_String_name_len, 
	  { "Name Len", "wkssvc.lsa_String.name_len", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseGetInfo_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetrUseGetInfo.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_ACCOUNT_DELETE, 
	  { "Wkssvc Join Flags Account Delete", "wkssvc.wkssvc_joinflags.WKSSVC_JOIN_FLAGS_ACCOUNT_DELETE", FT_BOOLEAN, 32, TFS(&wkssvc_joinflags_WKSSVC_JOIN_FLAGS_ACCOUNT_DELETE_tfs), ( 0x00000004 ), NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1043_lock_maximum, 
	  { "Lock Maximum", "wkssvc.wkssvc_NetWkstaInfo1043.lock_maximum", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown24, 
	  { "Unknown24", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown24", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo102_domain_name, 
	  { "Domain Name", "wkssvc.wkssvc_NetWkstaInfo102.domain_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseDel_force_cond, 
	  { "Force Cond", "wkssvc.wkssvc_NetrUseDel.force_cond", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaEnumUsers_resume_handle, 
	  { "Resume Handle", "wkssvc.wkssvc_NetWkstaEnumUsers.resume_handle", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseEnumCtr0_count, 
	  { "Count", "wkssvc.wkssvc_NetrUseEnumCtr0.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1053_utilize_nt_caching, 
	  { "Utilize Nt Caching", "wkssvc.wkssvc_NetWkstaInfo1053.utilize_nt_caching", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_num_srv_announce_buffers, 
	  { "Num Srv Announce Buffers", "wkssvc.wkssvc_NetWkstaInfo502.num_srv_announce_buffers", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo100_platform_id, 
	  { "Platform Id", "wkssvc.wkssvc_NetWkstaInfo100.platform_id", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrSetPrimaryComputername_primary_name, 
	  { "Primary Name", "wkssvc.wkssvc_NetrSetPrimaryComputername.primary_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown36, 
	  { "Unknown36", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown36", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseGetInfoCtr_info0, 
	  { "Info0", "wkssvc.wkssvc_NetrUseGetInfoCtr.info0", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseGetInfo_ctr, 
	  { "Ctr", "wkssvc.wkssvc_NetrUseGetInfo.ctr", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseInfo3_unknown2, 
	  { "Unknown2", "wkssvc.wkssvc_NetrUseInfo3.unknown2", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWkstaUserInfo_info1, 
	  { "Info1", "wkssvc.wkssvc_NetrWkstaUserInfo.info1", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1048_use_opportunistic_locking, 
	  { "Use Opportunistic Locking", "wkssvc.wkssvc_NetWkstaInfo1048.use_opportunistic_locking", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown27, 
	  { "Unknown27", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown27", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaTransportInfo0_vc_count, 
	  { "Vc Count", "wkssvc.wkssvc_NetWkstaTransportInfo0.vc_count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_EncryptedPassword, 
	  { "Encryptedpassword", "wkssvc.wkssvc_NetrRemoveAlternateComputerName.EncryptedPassword", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrAddAlternateComputerName_Account, 
	  { "Account", "wkssvc.wkssvc_NetrAddAlternateComputerName.Account", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWkstaUserGetInfo_info, 
	  { "Info", "wkssvc.wkssvc_NetrWkstaUserGetInfo.info", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaEnumUsers_entries_read, 
	  { "Entries Read", "wkssvc.wkssvc_NetWkstaEnumUsers.entries_read", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaEnumUsers_prefmaxlen, 
	  { "Prefmaxlen", "wkssvc.wkssvc_NetWkstaEnumUsers.prefmaxlen", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWkstaUserInfo1_logon_domain, 
	  { "Logon Domain", "wkssvc.wkssvc_NetrWkstaUserInfo1.logon_domain", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown16, 
	  { "Unknown16", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown16", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_log_election_packets, 
	  { "Log Election Packets", "wkssvc.wkssvc_NetWkstaInfo502.log_election_packets", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_use_raw_read, 
	  { "Use Raw Read", "wkssvc.wkssvc_NetWkstaInfo502.use_raw_read", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrGetJoinableOus_unknown, 
	  { "Unknown", "wkssvc.wkssvc_NetrGetJoinableOus.unknown", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrSetPrimaryComputername_Reserved, 
	  { "Reserved", "wkssvc.wkssvc_NetrSetPrimaryComputername.Reserved", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1027_errorlog_sz, 
	  { "Errorlog Sz", "wkssvc.wkssvc_NetWkstaInfo1027.errorlog_sz", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1052, 
	  { "Info1052", "wkssvc.wkssvc_NetWkstaInfo.info1052", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1012_maximum_collection_count, 
	  { "Maximum Collection Count", "wkssvc.wkssvc_NetWkstaInfo1012.maximum_collection_count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrJoinDomain2_admin_account, 
	  { "Admin Account", "wkssvc.wkssvc_NetrJoinDomain2.admin_account", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseEnumCtr_ctr0, 
	  { "Ctr0", "wkssvc.wkssvc_NetrUseEnumCtr.ctr0", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1050_use_close_behind, 
	  { "Use Close Behind", "wkssvc.wkssvc_NetWkstaInfo1050.use_close_behind", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_use_unlock_behind, 
	  { "Use Unlock Behind", "wkssvc.wkssvc_NetWkstaInfo502.use_unlock_behind", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaEnumUsersCtr_user1, 
	  { "User1", "wkssvc.wkssvc_NetWkstaEnumUsersCtr.user1", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo102_version_minor, 
	  { "Version Minor", "wkssvc.wkssvc_NetWkstaInfo102.version_minor", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_ComputerNamesCtr_count, 
	  { "Count", "wkssvc.wkssvc_ComputerNamesCtr.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1048, 
	  { "Info1048", "wkssvc.wkssvc_NetWkstaInfo.info1048", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1018_session_timeout, 
	  { "Session Timeout", "wkssvc.wkssvc_NetWkstaInfo1018.session_timeout", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_keep_connection, 
	  { "Keep Connection", "wkssvc.wkssvc_NetWkstaInfo502.keep_connection", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown31, 
	  { "Unknown31", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown31", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_max_commands, 
	  { "Max Commands", "wkssvc.wkssvc_NetWkstaInfo502.max_commands", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_lock_quota, 
	  { "Lock Quota", "wkssvc.wkssvc_NetWkstaInfo502.lock_quota", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown40, 
	  { "Unknown40", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown40", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1033_max_threads, 
	  { "Max Threads", "wkssvc.wkssvc_NetWkstaInfo1033.max_threads", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseAdd_level, 
	  { "Level", "wkssvc.wkssvc_NetrUseAdd.level", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_renameflags_WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE, 
	  { "Wkssvc Join Flags Account Create", "wkssvc.wkssvc_renameflags.WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE", FT_BOOLEAN, 32, TFS(&wkssvc_renameflags_WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE_tfs), ( 0x00000002 ), NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown25, 
	  { "Unknown25", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown25", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseDel_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetrUseDel.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWkstaUserInfo1_logon_server, 
	  { "Logon Server", "wkssvc.wkssvc_NetrWkstaUserInfo1.logon_server", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_PasswordBuffer_data, 
	  { "Data", "wkssvc.wkssvc_PasswordBuffer.data", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseInfo3_unknown1, 
	  { "Unknown1", "wkssvc.wkssvc_NetrUseInfo3.unknown1", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_cache_file_timeout, 
	  { "Cache File Timeout", "wkssvc.wkssvc_NetWkstaInfo502.cache_file_timeout", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_num_mailslot_buffers, 
	  { "Num Mailslot Buffers", "wkssvc.wkssvc_NetWkstaInfo502.num_mailslot_buffers", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1055, 
	  { "Info1055", "wkssvc.wkssvc_NetWkstaInfo.info1055", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrRenameMachineInDomain_password, 
	  { "Password", "wkssvc.wkssvc_NetrRenameMachineInDomain.password", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown13, 
	  { "Unknown13", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown13", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_utilize_nt_caching, 
	  { "Utilize Nt Caching", "wkssvc.wkssvc_NetWkstaInfo502.utilize_nt_caching", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1061_use_512_byte_max_transfer, 
	  { "Use 512 Byte Max Transfer", "wkssvc.wkssvc_NetWkstaInfo1061.use_512_byte_max_transfer", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatisticsGet_info, 
	  { "Info", "wkssvc.wkssvc_NetrWorkstationStatisticsGet.info", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaSetInfo_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetWkstaSetInfo.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrJoinDomain2_encrypted_password, 
	  { "Encrypted Password", "wkssvc.wkssvc_NetrJoinDomain2.encrypted_password", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseEnum_prefmaxlen, 
	  { "Prefmaxlen", "wkssvc.wkssvc_NetrUseEnum.prefmaxlen", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown2, 
	  { "Unknown2", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown2", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatisticsGet_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetrWorkstationStatisticsGet.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWkstaTransportDel_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetrWkstaTransportDel.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_DEFER_SPN, 
	  { "Wkssvc Join Flags Defer Spn", "wkssvc.wkssvc_joinflags.WKSSVC_JOIN_FLAGS_DEFER_SPN", FT_BOOLEAN, 32, TFS(&wkssvc_joinflags_WKSSVC_JOIN_FLAGS_DEFER_SPN_tfs), ( 0x00000100 ), NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1010_char_wait, 
	  { "Char Wait", "wkssvc.wkssvc_NetWkstaInfo1010.char_wait", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrRenameMachineInDomain_RenameOptions, 
	  { "Renameoptions", "wkssvc.wkssvc_NetrRenameMachineInDomain.RenameOptions", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaEnumUsers_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetWkstaEnumUsers.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrRenameMachineInDomain_Account, 
	  { "Account", "wkssvc.wkssvc_NetrRenameMachineInDomain.Account", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown23, 
	  { "Unknown23", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown23", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseEnumInfo_ctr, 
	  { "Ctr", "wkssvc.wkssvc_NetrUseEnumInfo.ctr", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaEnumUsersInfo_ctr, 
	  { "Ctr", "wkssvc.wkssvc_NetWkstaEnumUsersInfo.ctr", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaEnumUsersCtr0_user0, 
	  { "User0", "wkssvc.wkssvc_NetWkstaEnumUsersCtr0.user0", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_lsa_String_name, 
	  { "Name", "wkssvc.lsa_String.name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_buf_read_only_files, 
	  { "Buf Read Only Files", "wkssvc.wkssvc_NetWkstaInfo502.buf_read_only_files", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUnjoinDomain_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetrUnjoinDomain.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo101_lan_root, 
	  { "Lan Root", "wkssvc.wkssvc_NetWkstaInfo101.lan_root", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_JOIN_TYPE, 
	  { "Wkssvc Join Flags Join Type", "wkssvc.wkssvc_joinflags.WKSSVC_JOIN_FLAGS_JOIN_TYPE", FT_BOOLEAN, 32, TFS(&wkssvc_joinflags_WKSSVC_JOIN_FLAGS_JOIN_TYPE_tfs), ( 0x00000001 ), NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_buf_named_pipes, 
	  { "Buf Named Pipes", "wkssvc.wkssvc_NetWkstaInfo502.buf_named_pipes", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseInfo2_ref_count, 
	  { "Ref Count", "wkssvc.wkssvc_NetrUseInfo2.ref_count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1044_pipe_increment, 
	  { "Pipe Increment", "wkssvc.wkssvc_NetWkstaInfo1044.pipe_increment", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_DOMAIN_JOIN_IF_JOINED, 
	  { "Wkssvc Join Flags Domain Join If Joined", "wkssvc.wkssvc_joinflags.WKSSVC_JOIN_FLAGS_DOMAIN_JOIN_IF_JOINED", FT_BOOLEAN, 32, TFS(&wkssvc_joinflags_WKSSVC_JOIN_FLAGS_DOMAIN_JOIN_IF_JOINED_tfs), ( 0x00000020 ), NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_AlternateMachineNameToRemove, 
	  { "Alternatemachinenametoremove", "wkssvc.wkssvc_NetrRemoveAlternateComputerName.AlternateMachineNameToRemove", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseEnumCtr2_array, 
	  { "Array", "wkssvc.wkssvc_NetrUseEnumCtr2.array", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaGetInfo_info, 
	  { "Info", "wkssvc.wkssvc_NetWkstaGetInfo.info", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_max_illegal_dgram_events, 
	  { "Max Illegal Dgram Events", "wkssvc.wkssvc_NetWkstaInfo502.max_illegal_dgram_events", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1047, 
	  { "Info1047", "wkssvc.wkssvc_NetWkstaInfo.info1047", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrValidateName_Password, 
	  { "Password", "wkssvc.wkssvc_NetrValidateName.Password", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1028_print_buf_time, 
	  { "Print Buf Time", "wkssvc.wkssvc_NetWkstaInfo1028.print_buf_time", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseGetInfoCtr_info3, 
	  { "Info3", "wkssvc.wkssvc_NetrUseGetInfoCtr.info3", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrGetJoinableOus2_Account, 
	  { "Account", "wkssvc.wkssvc_NetrGetJoinableOus2.Account", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_RenameOptions, 
	  { "Renameoptions", "wkssvc.wkssvc_NetrRenameMachineInDomain2.RenameOptions", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWkstaUserInfo_info1101, 
	  { "Info1101", "wkssvc.wkssvc_NetrWkstaUserInfo.info1101", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrJoinDomain2_account_name, 
	  { "Account Name", "wkssvc.wkssvc_NetrJoinDomain2.account_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown17, 
	  { "Unknown17", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown17", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1013, 
	  { "Info1013", "wkssvc.wkssvc_NetWkstaInfo.info1013", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrValidateName2_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetrValidateName2.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown34, 
	  { "Unknown34", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown34", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1018, 
	  { "Info1018", "wkssvc.wkssvc_NetWkstaInfo.info1018", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaEnumUsersCtr0_entries_read, 
	  { "Entries Read", "wkssvc.wkssvc_NetWkstaEnumUsersCtr0.entries_read", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1057_use_encryption, 
	  { "Use Encryption", "wkssvc.wkssvc_NetWkstaInfo1057.use_encryption", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseInfo1_status, 
	  { "Status", "wkssvc.wkssvc_NetrUseInfo1.status", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaTransportInfo0_wan_link, 
	  { "Wan Link", "wkssvc.wkssvc_NetWkstaTransportInfo0.wan_link", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown35, 
	  { "Unknown35", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown35", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown7, 
	  { "Unknown7", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown7", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaSetInfo_parm_error, 
	  { "Parm Error", "wkssvc.wkssvc_NetWkstaSetInfo.parm_error", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseInfo0_remote, 
	  { "Remote", "wkssvc.wkssvc_NetrUseInfo0.remote", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWkstaUserInfo_info0, 
	  { "Info0", "wkssvc.wkssvc_NetrWkstaUserInfo.info0", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1060_force_core_create_mode, 
	  { "Force Core Create Mode", "wkssvc.wkssvc_NetWkstaInfo1060.force_core_create_mode", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWkstaUserInfo0_user_name, 
	  { "User Name", "wkssvc.wkssvc_NetrWkstaUserInfo0.user_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info101, 
	  { "Info101", "wkssvc.wkssvc_NetWkstaInfo.info101", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaTransportInfo0_address, 
	  { "Address", "wkssvc.wkssvc_NetWkstaTransportInfo0.address", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown39, 
	  { "Unknown39", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown39", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseEnumCtr2_count, 
	  { "Count", "wkssvc.wkssvc_NetrUseEnumCtr2.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrGetJoinInformation_name_buffer, 
	  { "Name Buffer", "wkssvc.wkssvc_NetrGetJoinInformation.name_buffer", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrRenameMachineInDomain_NewMachineName, 
	  { "Newmachinename", "wkssvc.wkssvc_NetrRenameMachineInDomain.NewMachineName", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_lock_maximum, 
	  { "Lock Maximum", "wkssvc.wkssvc_NetWkstaInfo502.lock_maximum", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUnjoinDomain_Account, 
	  { "Account", "wkssvc.wkssvc_NetrUnjoinDomain.Account", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWkstaUserGetInfo_level, 
	  { "Level", "wkssvc.wkssvc_NetrWkstaUserGetInfo.level", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1049, 
	  { "Info1049", "wkssvc.wkssvc_NetWkstaInfo.info1049", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrGetJoinableOus_num_ous, 
	  { "Num Ous", "wkssvc.wkssvc_NetrGetJoinableOus.num_ous", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseInfo2_asg_type, 
	  { "Asg Type", "wkssvc.wkssvc_NetrUseInfo2.asg_type", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseInfo1_password, 
	  { "Password", "wkssvc.wkssvc_NetrUseInfo1.password", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrJoinDomain_unknown, 
	  { "Unknown", "wkssvc.wkssvc_NetrJoinDomain.unknown", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseInfo1_local, 
	  { "Local", "wkssvc.wkssvc_NetrUseInfo1.local", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1054_use_raw_read, 
	  { "Use Raw Read", "wkssvc.wkssvc_NetWkstaInfo1054.use_raw_read", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetrRenameMachineInDomain2.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1023_size_char_buf, 
	  { "Size Char Buf", "wkssvc.wkssvc_NetWkstaInfo1023.size_char_buf", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo100_domain_name, 
	  { "Domain Name", "wkssvc.wkssvc_NetWkstaInfo100.domain_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaTransportEnum_max_buffer, 
	  { "Max Buffer", "wkssvc.wkssvc_NetWkstaTransportEnum.max_buffer", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_JOIN_DC_ACCOUNT, 
	  { "Wkssvc Join Flags Join Dc Account", "wkssvc.wkssvc_joinflags.WKSSVC_JOIN_FLAGS_JOIN_DC_ACCOUNT", FT_BOOLEAN, 32, TFS(&wkssvc_joinflags_WKSSVC_JOIN_FLAGS_JOIN_DC_ACCOUNT_tfs), ( 0x00000200 ), NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1042, 
	  { "Info1042", "wkssvc.wkssvc_NetWkstaInfo.info1042", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWkstaUserSetInfo_unknown, 
	  { "Unknown", "wkssvc.wkssvc_NetrWkstaUserSetInfo.unknown", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1045, 
	  { "Info1045", "wkssvc.wkssvc_NetWkstaInfo.info1045", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1011, 
	  { "Info1011", "wkssvc.wkssvc_NetWkstaInfo.info1011", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1049_use_unlock_behind, 
	  { "Use Unlock Behind", "wkssvc.wkssvc_NetWkstaInfo1049.use_unlock_behind", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1062_read_ahead_throughput, 
	  { "Read Ahead Throughput", "wkssvc.wkssvc_NetWkstaInfo1062.read_ahead_throughput", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1056_use_write_raw_data, 
	  { "Use Write Raw Data", "wkssvc.wkssvc_NetWkstaInfo1056.use_write_raw_data", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWkstaTransportAdd_info0, 
	  { "Info0", "wkssvc.wkssvc_NetrWkstaTransportAdd.info0", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrValidateName_name, 
	  { "Name", "wkssvc.wkssvc_NetrValidateName.name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown18, 
	  { "Unknown18", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown18", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrMessageBufferSend_message_size, 
	  { "Message Size", "wkssvc.wkssvc_NetrMessageBufferSend.message_size", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_JOIN_UNSECURE, 
	  { "Wkssvc Join Flags Join Unsecure", "wkssvc.wkssvc_joinflags.WKSSVC_JOIN_FLAGS_JOIN_UNSECURE", FT_BOOLEAN, 32, TFS(&wkssvc_joinflags_WKSSVC_JOIN_FLAGS_JOIN_UNSECURE_tfs), ( 0x00000040 ), NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_ComputerNamesCtr_computer_name, 
	  { "Computer Name", "wkssvc.wkssvc_ComputerNamesCtr.computer_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrValidateName2_name_type, 
	  { "Name Type", "wkssvc.wkssvc_NetrValidateName2.name_type", FT_UINT16, BASE_DEC, VALS(wkssvc_wkssvc_NetValidateNameType_vals), 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrValidateName2_Account, 
	  { "Account", "wkssvc.wkssvc_NetrValidateName2.Account", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrGetJoinableOus_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetrGetJoinableOus.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaTransportEnum_total_entries, 
	  { "Total Entries", "wkssvc.wkssvc_NetWkstaTransportEnum.total_entries", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_WIN9X_UPGRADE, 
	  { "Wkssvc Join Flags Win9x Upgrade", "wkssvc.wkssvc_joinflags.WKSSVC_JOIN_FLAGS_WIN9X_UPGRADE", FT_BOOLEAN, 32, TFS(&wkssvc_joinflags_WKSSVC_JOIN_FLAGS_WIN9X_UPGRADE_tfs), ( 0x00000010 ), NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrValidateName2_EncryptedPassword, 
	  { "Encryptedpassword", "wkssvc.wkssvc_NetrValidateName2.EncryptedPassword", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWkstaTransportDel_unknown3, 
	  { "Unknown3", "wkssvc.wkssvc_NetrWkstaTransportDel.unknown3", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1062, 
	  { "Info1062", "wkssvc.wkssvc_NetWkstaInfo.info1062", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWkstaUserGetInfo_unknown, 
	  { "Unknown", "wkssvc.wkssvc_NetrWkstaUserGetInfo.unknown", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrAddAlternateComputerName_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetrAddAlternateComputerName.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrJoinDomain2_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetrJoinDomain2.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info102, 
	  { "Info102", "wkssvc.wkssvc_NetWkstaInfo.info102", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrJoinDomain_Account, 
	  { "Account", "wkssvc.wkssvc_NetrJoinDomain.Account", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1046_dormant_file_limit, 
	  { "Dormant File Limit", "wkssvc.wkssvc_NetWkstaInfo1046.dormant_file_limit", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWkstaTransportAdd_parm_err, 
	  { "Parm Err", "wkssvc.wkssvc_NetrWkstaTransportAdd.parm_err", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo102_version_major, 
	  { "Version Major", "wkssvc.wkssvc_NetWkstaInfo102.version_major", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_platform_id, 
	  { "Platform Id", "wkssvc.platform_id", FT_UINT32, BASE_DEC, VALS(srvsvc_srvsvc_PlatformId_vals), 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown22, 
	  { "Unknown22", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown22", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseInfo1_use_count, 
	  { "Use Count", "wkssvc.wkssvc_NetrUseInfo1.use_count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUnjoinDomain2_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetrUnjoinDomain2.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_use_512_byte_max_transfer, 
	  { "Use 512 Byte Max Transfer", "wkssvc.wkssvc_NetWkstaInfo502.use_512_byte_max_transfer", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaTransportEnum_info, 
	  { "Info", "wkssvc.wkssvc_NetWkstaTransportEnum.info", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1033, 
	  { "Info1033", "wkssvc.wkssvc_NetWkstaInfo.info1033", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1046, 
	  { "Info1046", "wkssvc.wkssvc_NetWkstaInfo.info1046", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaSetInfo_info, 
	  { "Info", "wkssvc.wkssvc_NetWkstaSetInfo.info", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrMessageBufferSend_message_sender_name, 
	  { "Message Sender Name", "wkssvc.wkssvc_NetrMessageBufferSend.message_sender_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseInfo1_remote, 
	  { "Remote", "wkssvc.wkssvc_NetrUseInfo1.remote", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseInfo2_domain_name, 
	  { "Domain Name", "wkssvc.wkssvc_NetrUseInfo2.domain_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseEnumCtr1_count, 
	  { "Count", "wkssvc.wkssvc_NetrUseEnumCtr1.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1047_cache_file_timeout, 
	  { "Cache File Timeout", "wkssvc.wkssvc_NetWkstaInfo1047.cache_file_timeout", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseGetInfoCtr_info2, 
	  { "Info2", "wkssvc.wkssvc_NetrUseGetInfoCtr.info2", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown30, 
	  { "Unknown30", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown30", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1028, 
	  { "Info1028", "wkssvc.wkssvc_NetWkstaInfo.info1028", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info100, 
	  { "Info100", "wkssvc.wkssvc_NetWkstaInfo.info100", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrLogonDomainNameDel_domain_name, 
	  { "Domain Name", "wkssvc.wkssvc_NetrLogonDomainNameDel.domain_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1013_keep_connection, 
	  { "Keep Connection", "wkssvc.wkssvc_NetWkstaInfo1013.keep_connection", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrEnumerateComputerNames_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetrEnumerateComputerNames.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWkstaUserSetInfo_info, 
	  { "Info", "wkssvc.wkssvc_NetrWkstaUserSetInfo.info", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrMessageBufferSend_message_name, 
	  { "Message Name", "wkssvc.wkssvc_NetrMessageBufferSend.message_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_session_timeout, 
	  { "Session Timeout", "wkssvc.wkssvc_NetWkstaInfo502.session_timeout", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseEnumCtr0_array, 
	  { "Array", "wkssvc.wkssvc_NetrUseEnumCtr0.array", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown6, 
	  { "Unknown6", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown6", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaTransportInfo_ctr, 
	  { "Ctr", "wkssvc.wkssvc_NetWkstaTransportInfo.ctr", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_collection_time, 
	  { "Collection Time", "wkssvc.wkssvc_NetWkstaInfo502.collection_time", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1054, 
	  { "Info1054", "wkssvc.wkssvc_NetWkstaInfo.info1054", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown10, 
	  { "Unknown10", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown10", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1032_wrk_heuristics, 
	  { "Wrk Heuristics", "wkssvc.wkssvc_NetWkstaInfo1032.wrk_heuristics", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo101_version_minor, 
	  { "Version Minor", "wkssvc.wkssvc_NetWkstaInfo101.version_minor", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_MACHINE_PWD_PASSED, 
	  { "Wkssvc Join Flags Machine Pwd Passed", "wkssvc.wkssvc_joinflags.WKSSVC_JOIN_FLAGS_MACHINE_PWD_PASSED", FT_BOOLEAN, 32, TFS(&wkssvc_joinflags_WKSSVC_JOIN_FLAGS_MACHINE_PWD_PASSED_tfs), ( 0x00000080 ), NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWkstaTransportAdd_level, 
	  { "Level", "wkssvc.wkssvc_NetrWkstaTransportAdd.level", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown33, 
	  { "Unknown33", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown33", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrEnumerateComputerNames_ctr, 
	  { "Ctr", "wkssvc.wkssvc_NetrEnumerateComputerNames.ctr", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaTransportEnum_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetWkstaTransportEnum.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_max_threads, 
	  { "Max Threads", "wkssvc.wkssvc_NetWkstaInfo502.max_threads", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1042_lock_increment, 
	  { "Lock Increment", "wkssvc.wkssvc_NetWkstaInfo1042.lock_increment", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseGetInfo_level, 
	  { "Level", "wkssvc.wkssvc_NetrUseGetInfo.level", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1050, 
	  { "Info1050", "wkssvc.wkssvc_NetWkstaInfo.info1050", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_lock_increment, 
	  { "Lock Increment", "wkssvc.wkssvc_NetWkstaInfo502.lock_increment", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseInfo2_local, 
	  { "Local", "wkssvc.wkssvc_NetrUseInfo2.local", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrValidateName_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetrValidateName.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1041, 
	  { "Info1041", "wkssvc.wkssvc_NetWkstaInfo.info1041", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseInfo2_status, 
	  { "Status", "wkssvc.wkssvc_NetrUseInfo2.status", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown12, 
	  { "Unknown12", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown12", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrJoinDomain_account_ou, 
	  { "Account Ou", "wkssvc.wkssvc_NetrJoinDomain.account_ou", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatisticsGet_unknown3, 
	  { "Unknown3", "wkssvc.wkssvc_NetrWorkstationStatisticsGet.unknown3", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown19, 
	  { "Unknown19", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown19", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrAddAlternateComputerName_EncryptedPassword, 
	  { "Encryptedpassword", "wkssvc.wkssvc_NetrAddAlternateComputerName.EncryptedPassword", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1058_buf_files_deny_write, 
	  { "Buf Files Deny Write", "wkssvc.wkssvc_NetWkstaInfo1058.buf_files_deny_write", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUnjoinDomain2_account, 
	  { "Account", "wkssvc.wkssvc_NetrUnjoinDomain2.account", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatisticsGet_unknown2, 
	  { "Unknown2", "wkssvc.wkssvc_NetrWorkstationStatisticsGet.unknown2", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1043, 
	  { "Info1043", "wkssvc.wkssvc_NetWkstaInfo.info1043", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown21, 
	  { "Unknown21", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown21", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo102_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetWkstaInfo102.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_use_encryption, 
	  { "Use Encryption", "wkssvc.wkssvc_NetWkstaInfo502.use_encryption", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1059, 
	  { "Info1059", "wkssvc.wkssvc_NetWkstaInfo.info1059", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrValidateName_name_type, 
	  { "Name Type", "wkssvc.wkssvc_NetrValidateName.name_type", FT_UINT16, BASE_DEC, VALS(wkssvc_wkssvc_NetValidateNameType_vals), 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrMessageBufferSend_message_buffer, 
	  { "Message Buffer", "wkssvc.wkssvc_NetrMessageBufferSend.message_buffer", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaTransportCtr0_count, 
	  { "Count", "wkssvc.wkssvc_NetWkstaTransportCtr0.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseEnumInfo_level, 
	  { "Level", "wkssvc.wkssvc_NetrUseEnumInfo.level", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1041_lock_quota, 
	  { "Lock Quota", "wkssvc.wkssvc_NetWkstaInfo1041.lock_quota", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseAdd_ctr, 
	  { "Ctr", "wkssvc.wkssvc_NetrUseAdd.ctr", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseEnum_resume_handle, 
	  { "Resume Handle", "wkssvc.wkssvc_NetrUseEnum.resume_handle", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo100_version_major, 
	  { "Version Major", "wkssvc.wkssvc_NetWkstaInfo100.version_major", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_Reserved, 
	  { "Reserved", "wkssvc.wkssvc_NetrRemoveAlternateComputerName.Reserved", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseAdd_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetrUseAdd.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown11, 
	  { "Unknown11", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown11", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1012, 
	  { "Info1012", "wkssvc.wkssvc_NetWkstaInfo.info1012", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUnjoinDomain_password, 
	  { "Password", "wkssvc.wkssvc_NetrUnjoinDomain.password", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_werror, 
	  { "Windows Error", "wkssvc.werror", FT_UINT32, BASE_HEX, VALS(WERR_errors), 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrGetJoinableOus2_domain_name, 
	  { "Domain Name", "wkssvc.wkssvc_NetrGetJoinableOus2.domain_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_pipe_increment, 
	  { "Pipe Increment", "wkssvc.wkssvc_NetWkstaInfo502.pipe_increment", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1044, 
	  { "Info1044", "wkssvc.wkssvc_NetWkstaInfo.info1044", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrGetJoinableOus2_EncryptedPassword, 
	  { "Encryptedpassword", "wkssvc.wkssvc_NetrGetJoinableOus2.EncryptedPassword", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1010, 
	  { "Info1010", "wkssvc.wkssvc_NetWkstaInfo.info1010", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1051_buf_named_pipes, 
	  { "Buf Named Pipes", "wkssvc.wkssvc_NetWkstaInfo1051.buf_named_pipes", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_read_ahead_throughput, 
	  { "Read Ahead Throughput", "wkssvc.wkssvc_NetWkstaInfo502.read_ahead_throughput", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrGetJoinableOus_ous, 
	  { "Ous", "wkssvc.wkssvc_NetrGetJoinableOus.ous", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown5, 
	  { "Unknown5", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown5", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_NewMachineName, 
	  { "Newmachinename", "wkssvc.wkssvc_NetrRenameMachineInDomain2.NewMachineName", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWkstaTransportDel_transport_name, 
	  { "Transport Name", "wkssvc.wkssvc_NetrWkstaTransportDel.transport_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseInfo0_local, 
	  { "Local", "wkssvc.wkssvc_NetrUseInfo0.local", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_use_raw_write, 
	  { "Use Raw Write", "wkssvc.wkssvc_NetWkstaInfo502.use_raw_write", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrGetJoinableOus2_ous, 
	  { "Ous", "wkssvc.wkssvc_NetrGetJoinableOus2.ous", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo101_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetWkstaInfo101.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrGetJoinableOus2_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetrGetJoinableOus2.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1059_buf_read_only_files, 
	  { "Buf Read Only Files", "wkssvc.wkssvc_NetWkstaInfo1059.buf_read_only_files", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo100_version_minor, 
	  { "Version Minor", "wkssvc.wkssvc_NetWkstaInfo100.version_minor", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE, 
	  { "Wkssvc Join Flags Account Create", "wkssvc.wkssvc_joinflags.WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE", FT_BOOLEAN, 32, TFS(&wkssvc_joinflags_WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE_tfs), ( 0x00000002 ), NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_use_close_behind, 
	  { "Use Close Behind", "wkssvc.wkssvc_NetWkstaInfo502.use_close_behind", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_opnum, 
	  { "Operation", "wkssvc.opnum", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_force_core_create_mode, 
	  { "Force Core Create Mode", "wkssvc.wkssvc_NetWkstaInfo502.force_core_create_mode", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1011_collection_time, 
	  { "Collection Time", "wkssvc.wkssvc_NetWkstaInfo1011.collection_time", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrGetJoinInformation_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetrGetJoinInformation.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo101_domain_name, 
	  { "Domain Name", "wkssvc.wkssvc_NetWkstaInfo101.domain_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1061, 
	  { "Info1061", "wkssvc.wkssvc_NetWkstaInfo.info1061", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseGetInfoCtr_info1, 
	  { "Info1", "wkssvc.wkssvc_NetrUseGetInfoCtr.info1", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaEnumUsersInfo_level, 
	  { "Level", "wkssvc.wkssvc_NetWkstaEnumUsersInfo.level", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrSetPrimaryComputername_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetrSetPrimaryComputername.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUnjoinDomain_unjoin_flags, 
	  { "Unjoin Flags", "wkssvc.wkssvc_NetrUnjoinDomain.unjoin_flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaTransportEnum_resume_handle, 
	  { "Resume Handle", "wkssvc.wkssvc_NetWkstaTransportEnum.resume_handle", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrJoinDomain_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetrJoinDomain.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo102_platform_id, 
	  { "Platform Id", "wkssvc.wkssvc_NetWkstaInfo102.platform_id", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown8, 
	  { "Unknown8", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown8", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrAddAlternateComputerName_Reserved, 
	  { "Reserved", "wkssvc.wkssvc_NetrAddAlternateComputerName.Reserved", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_JOIN_WITH_NEW_NAME, 
	  { "Wkssvc Join Flags Join With New Name", "wkssvc.wkssvc_joinflags.WKSSVC_JOIN_FLAGS_JOIN_WITH_NEW_NAME", FT_BOOLEAN, 32, TFS(&wkssvc_joinflags_WKSSVC_JOIN_FLAGS_JOIN_WITH_NEW_NAME_tfs), ( 0x00000400 ), NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWkstaTransportAdd_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetrWkstaTransportAdd.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetrRemoveAlternateComputerName.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo101_platform_id, 
	  { "Platform Id", "wkssvc.wkssvc_NetWkstaInfo101.platform_id", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_use_opportunistic_locking, 
	  { "Use Opportunistic Locking", "wkssvc.wkssvc_NetWkstaInfo502.use_opportunistic_locking", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo100_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetWkstaInfo100.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown28, 
	  { "Unknown28", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown28", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaEnumUsersCtr1_user1, 
	  { "User1", "wkssvc.wkssvc_NetWkstaEnumUsersCtr1.user1", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaGetInfo_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetWkstaGetInfo.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1023, 
	  { "Info1023", "wkssvc.wkssvc_NetWkstaInfo.info1023", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown15, 
	  { "Unknown15", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown15", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_use_lock_read_unlock, 
	  { "Use Lock Read Unlock", "wkssvc.wkssvc_NetWkstaInfo502.use_lock_read_unlock", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseInfo1_asg_type, 
	  { "Asg Type", "wkssvc.wkssvc_NetrUseInfo1.asg_type", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUnjoinDomain2_unjoin_flags, 
	  { "Unjoin Flags", "wkssvc.wkssvc_NetrUnjoinDomain2.unjoin_flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown1, 
	  { "Unknown1", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown1", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrLogonDomainNameAdd_domain_name, 
	  { "Domain Name", "wkssvc.wkssvc_NetrLogonDomainNameAdd.domain_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrWorkstationStatistics_unknown26, 
	  { "Unknown26", "wkssvc.wkssvc_NetrWorkstationStatistics.unknown26", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_Account, 
	  { "Account", "wkssvc.wkssvc_NetrRenameMachineInDomain2.Account", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaEnumUsers_info, 
	  { "Info", "wkssvc.wkssvc_NetWkstaEnumUsers.info", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrGetJoinInformation_name_type, 
	  { "Name Type", "wkssvc.wkssvc_NetrGetJoinInformation.name_type", FT_UINT16, BASE_DEC, VALS(wkssvc_wkssvc_NetJoinStatus_vals), 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrAddAlternateComputerName_NewAlternateMachineName, 
	  { "Newalternatemachinename", "wkssvc.wkssvc_NetrAddAlternateComputerName.NewAlternateMachineName", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUnjoinDomain2_encrypted_password, 
	  { "Encrypted Password", "wkssvc.wkssvc_NetrUnjoinDomain2.encrypted_password", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_char_wait, 
	  { "Char Wait", "wkssvc.wkssvc_NetWkstaInfo502.char_wait", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_pipe_maximum, 
	  { "Pipe Maximum", "wkssvc.wkssvc_NetWkstaInfo502.pipe_maximum", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1027, 
	  { "Info1027", "wkssvc.wkssvc_NetWkstaInfo.info1027", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1052_use_lock_read_unlock, 
	  { "Use Lock Read Unlock", "wkssvc.wkssvc_NetWkstaInfo1052.use_lock_read_unlock", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1056, 
	  { "Info1056", "wkssvc.wkssvc_NetWkstaInfo.info1056", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrValidateName_Account, 
	  { "Account", "wkssvc.wkssvc_NetrValidateName.Account", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1032, 
	  { "Info1032", "wkssvc.wkssvc_NetWkstaInfo.info1032", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_Account, 
	  { "Account", "wkssvc.wkssvc_NetrRemoveAlternateComputerName.Account", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1053, 
	  { "Info1053", "wkssvc.wkssvc_NetWkstaInfo.info1053", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_EncryptedPassword, 
	  { "Encryptedpassword", "wkssvc.wkssvc_NetrRenameMachineInDomain2.EncryptedPassword", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaSetInfo_level, 
	  { "Level", "wkssvc.wkssvc_NetWkstaSetInfo.level", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrJoinDomain_domain_name, 
	  { "Domain Name", "wkssvc.wkssvc_NetrJoinDomain.domain_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo102_logged_on_users, 
	  { "Logged On Users", "wkssvc.wkssvc_NetWkstaInfo102.logged_on_users", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUseInfo2_remote, 
	  { "Remote", "wkssvc.wkssvc_NetrUseInfo2.remote", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	};


	static gint *ett[] = {
		&ett_dcerpc_wkssvc,
		&ett_wkssvc_lsa_String,
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
		&ett_wkssvc_wkssvc_NetWkstaInfo1028,
		&ett_wkssvc_wkssvc_NetWkstaInfo1032,
		&ett_wkssvc_wkssvc_NetWkstaInfo1033,
		&ett_wkssvc_wkssvc_NetWkstaInfo1041,
		&ett_wkssvc_wkssvc_NetWkstaInfo1042,
		&ett_wkssvc_wkssvc_NetWkstaInfo1043,
		&ett_wkssvc_wkssvc_NetWkstaInfo1044,
		&ett_wkssvc_wkssvc_NetWkstaInfo1045,
		&ett_wkssvc_wkssvc_NetWkstaInfo1046,
		&ett_wkssvc_wkssvc_NetWkstaInfo1047,
		&ett_wkssvc_wkssvc_NetWkstaInfo1048,
		&ett_wkssvc_wkssvc_NetWkstaInfo1049,
		&ett_wkssvc_wkssvc_NetWkstaInfo1050,
		&ett_wkssvc_wkssvc_NetWkstaInfo1051,
		&ett_wkssvc_wkssvc_NetWkstaInfo1052,
		&ett_wkssvc_wkssvc_NetWkstaInfo1053,
		&ett_wkssvc_wkssvc_NetWkstaInfo1054,
		&ett_wkssvc_wkssvc_NetWkstaInfo1055,
		&ett_wkssvc_wkssvc_NetWkstaInfo1056,
		&ett_wkssvc_wkssvc_NetWkstaInfo1057,
		&ett_wkssvc_wkssvc_NetWkstaInfo1058,
		&ett_wkssvc_wkssvc_NetWkstaInfo1059,
		&ett_wkssvc_wkssvc_NetWkstaInfo1060,
		&ett_wkssvc_wkssvc_NetWkstaInfo1061,
		&ett_wkssvc_wkssvc_NetWkstaInfo1062,
		&ett_wkssvc_wkssvc_NetWkstaInfo,
		&ett_wkssvc_wkssvc_NetrWkstaUserInfo0,
		&ett_wkssvc_wkssvc_NetWkstaEnumUsersCtr0,
		&ett_wkssvc_wkssvc_NetrWkstaUserInfo1,
		&ett_wkssvc_wkssvc_NetWkstaEnumUsersCtr1,
		&ett_wkssvc_wkssvc_NetWkstaEnumUsersCtr,
		&ett_wkssvc_wkssvc_NetWkstaEnumUsersInfo,
		&ett_wkssvc_wkssvc_NetrWkstaUserInfo1101,
		&ett_wkssvc_wkssvc_NetrWkstaUserInfo,
		&ett_wkssvc_wkssvc_NetWkstaTransportInfo0,
		&ett_wkssvc_wkssvc_NetWkstaTransportCtr0,
		&ett_wkssvc_wkssvc_NetWkstaTransportCtr,
		&ett_wkssvc_wkssvc_NetWkstaTransportInfo,
		&ett_wkssvc_wkssvc_NetrUseInfo3,
		&ett_wkssvc_wkssvc_NetrUseInfo2,
		&ett_wkssvc_wkssvc_NetrUseInfo1,
		&ett_wkssvc_wkssvc_NetrUseInfo0,
		&ett_wkssvc_wkssvc_NetrUseGetInfoCtr,
		&ett_wkssvc_wkssvc_NetrUseEnumCtr2,
		&ett_wkssvc_wkssvc_NetrUseEnumCtr1,
		&ett_wkssvc_wkssvc_NetrUseEnumCtr0,
		&ett_wkssvc_wkssvc_NetrUseEnumCtr,
		&ett_wkssvc_wkssvc_NetrUseEnumInfo,
		&ett_wkssvc_wkssvc_NetrWorkstationStatistics,
		&ett_wkssvc_wkssvc_renameflags,
		&ett_wkssvc_wkssvc_PasswordBuffer,
		&ett_wkssvc_wkssvc_joinflags,
		&ett_wkssvc_wkssvc_ComputerNamesCtr,
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
