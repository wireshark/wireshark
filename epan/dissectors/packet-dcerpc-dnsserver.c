/* DO NOT EDIT
	This filter was automatically generated
	from dnsserver.idl and dnsserver.cnf.

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
#include "packet-dcerpc-dnsserver.h"

/* Ett declarations */
static gint ett_dcerpc_dnsserver = -1;
static gint ett_dnsserver_DNS_RPC_VERSION = -1;
static gint ett_dnsserver_DNS_LOG_LEVELS = -1;
static gint ett_dnsserver_DNS_RPC_PROTOCOLS = -1;
static gint ett_dnsserver_DNS_SELECT_FLAGS = -1;
static gint ett_dnsserver_DNS_RPC_NODE_FLAGS = -1;
static gint ett_dnsserver_DNS_RPC_NAME = -1;
static gint ett_dnsserver_DNS_RPC_RECORD_NODE_NAME = -1;
static gint ett_dnsserver_DNS_RPC_RECORD_UNION = -1;
static gint ett_dnsserver_DNS_RPC_RECORD = -1;
static gint ett_dnsserver_DNS_RPC_NODE = -1;
static gint ett_dnsserver_IP4_ARRAY = -1;
static gint ett_dnsserver_DNS_RPC_SERVER_INFO_DOTNET = -1;
static gint ett_dnsserver_DNSSRV_RPC_UNION = -1;
static gint ett_dnsserver_DNS_RECORD_BUFFER = -1;


/* Header field declarations */
static gint hf_dnsserver_DnssrvEnumRecords2_start_child = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_LocalNetPriority = -1;
static gint hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_AGING_ON = -1;
static gint hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_WRITE_THROUGH = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_reserved0 = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DefaultNoRefreshInterval = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_LogFilter = -1;
static gint hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_ANSWERS = -1;
static gint hf_dnsserver_DNS_SELECT_FLAGS_DNS_RPC_VIEW_ONLY_CHILDREN = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_BootMethod = -1;
static gint hf_dnsserver_DNS_SELECT_FLAGS_DNS_RPC_VIEW_AUTHORITY_DATA = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_extension1 = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_ListenAddrs = -1;
static gint hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_QUESTIONS = -1;
static gint hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_NODE_COMPLETE = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_Forwarders = -1;
static gint hf_dnsserver_DnssrvQuery2_server_name = -1;
static gint hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_NODE_STICKY = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_WriteAuthorityNs = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_AutoCacheUpdate = -1;
static gint hf_dnsserver_status = -1;
static gint hf_dnsserver_DNS_RPC_RECORD_DataLength = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_AdminConfigured = -1;
static gint hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_RECV = -1;
static gint hf_dnsserver_DnssrvEnumRecords2_buffer_length = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_extension3 = -1;
static gint hf_dnsserver_DNS_RPC_PROTOCOLS_DNS_RPC_USE_LPC = -1;
static gint hf_dnsserver_DNS_RPC_NAME_name = -1;
static gint hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_RECORD_CREATE_PTR = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_RpcProtocol = -1;
static gint hf_dnsserver_DNS_RPC_NODE_Childcount = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_RpcStructureVersion = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DefaultAgingState = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DsDsaVersion = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_extension0 = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_RoundRobin = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_BindSecondaries = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_extension5 = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_AutoReverseZones = -1;
static gint hf_dnsserver_DnssrvQuery2_data = -1;
static gint hf_dnsserver_DNSSRV_RPC_UNION_dword = -1;
static gint hf_dnsserver_DNS_RPC_VERSION_OSMajorVersion = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DsDomainVersion = -1;
static gint hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_ZONE_DELEGATION = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_RecursionTimeout = -1;
static gint hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_UPDATE = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_LooseWildcarding = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DsContainer = -1;
static gint hf_dnsserver_DnssrvQuery2_client_version = -1;
static gint hf_dnsserver_DNS_SELECT_FLAGS_DNS_RPC_VIEW_ADDITIONAL_DATA = -1;
static gint hf_dnsserver_DNS_RPC_NODE_records = -1;
static gint hf_dnsserver_DNS_RPC_RECORD_NODE_NAME_Name = -1;
static gint hf_dnsserver_DNS_RPC_RECORD_TimeStamp = -1;
static gint hf_dnsserver_DNS_RPC_RECORD_TtlSeconds = -1;
static gint hf_dnsserver_DNS_RPC_VERSION_OSMinorVersion = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_NameCheckFlag = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DomainName = -1;
static gint hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_AUTH_ZONE_ROOT = -1;
static gint hf_dnsserver_DnssrvEnumRecords2_filter_stop = -1;
static gint hf_dnsserver_DnssrvEnumRecords2_setting_flags = -1;
static gint hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_SEND = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DomainDirectoryPartition = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_NoRecursion = -1;
static gint hf_dnsserver_DnssrvEnumRecords2_client_version = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_ServerAddrs = -1;
static gint hf_dnsserver_DnssrvEnumRecords2_select_flag = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_LogFilePath = -1;
static gint hf_dnsserver_DNS_RPC_PROTOCOLS_DNS_RPC_USE_NAMED_PIPE = -1;
static gint hf_dnsserver_DNS_RPC_NODE_NodeName = -1;
static gint hf_dnsserver_DNS_SELECT_FLAGS_DNS_RPC_VIEW_NO_CHILDREN = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_extension4 = -1;
static gint hf_dnsserver_IP4_ARRAY_AddrCount = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_ForestName = -1;
static gint hf_dnsserver_DnssrvEnumRecords2_record_type = -1;
static gint hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_NOTIFY = -1;
static gint hf_dnsserver_DNS_RPC_RECORD_Flags = -1;
static gint hf_dnsserver_DnssrvEnumRecords2_server_name = -1;
static gint hf_dnsserver_DnssrvEnumRecords2_record_buffer = -1;
static gint hf_dnsserver_DnssrvEnumRecords2_node_name = -1;
static gint hf_dnsserver_DNS_RECORD_BUFFER_rpc_node = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_LastScavengeTime = -1;
static gint hf_dnsserver_DNS_RPC_NODE_Length = -1;
static gint hf_dnsserver_DnssrvEnumRecords2_filter_start = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_ForestDirectoryPartition = -1;
static gint hf_dnsserver_DnssrvEnumRecords2_zone = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_reserve_array = -1;
static gint hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_RECORD_TTL_CHANGE = -1;
static gint hf_dnsserver_DNS_SELECT_FLAGS_DNS_RPC_VIEW_CACHE_DATA = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_ForwardTimeout = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_reserve_array2 = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_extension2 = -1;
static gint hf_dnsserver_DNS_RPC_RECORD_UNION_NodeName = -1;
static gint hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_FULL_PACKETS = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_RecursionRetry = -1;
static gint hf_dnsserver_DnssrvQuery2_zone = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DefaultRefreshInterval = -1;
static gint hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_ZONE_ROOT = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_StrictFileParsing = -1;
static gint hf_dnsserver_DNS_SELECT_FLAGS_DNS_RPC_VIEW_ROOT_HINT_DATA = -1;
static gint hf_dnsserver_DNS_SELECT_FLAGS_DNS_RPC_VIEW_GLUE_DATA = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DsForestVersion = -1;
static gint hf_dnsserver_DNSSRV_RPC_UNION_ServerInfoDotnet = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_LogFileMaxSize = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_MaxCacheTtl = -1;
static gint hf_dnsserver_DNS_RPC_RECORD_record = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_ScavengingInterval = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_RecurseAfterForwarding = -1;
static gint hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_SUPPRESS_NOTIFY = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_Version = -1;
static gint hf_dnsserver_DnssrvQuery2_setting_flags = -1;
static gint hf_dnsserver_DNS_RPC_RECORD_reserved = -1;
static gint hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_CACHE_DATA = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_ServerName = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_AddressAnswerLimit = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_AllowUpdate = -1;
static gint hf_dnsserver_DNS_RPC_PROTOCOLS_DNS_RPC_USE_TCPIP = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_SecureResponses = -1;
static gint hf_dnsserver_IP4_ARRAY_AddrArray = -1;
static gint hf_dnsserver_DNS_RPC_VERSION_ServicePackVersion = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DebugLevel = -1;
static gint hf_dnsserver_DNS_RPC_RECORD_Type = -1;
static gint hf_dnsserver_DNSSRV_RPC_UNION_null = -1;
static gint hf_dnsserver_DNS_RPC_NAME_Name = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_LogLevel = -1;
static gint hf_dnsserver_DNS_RPC_NODE_RecordCount = -1;
static gint hf_dnsserver_DNS_RPC_NODE_Flags = -1;
static gint hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_QUERY = -1;
static gint hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_UDP = -1;
static gint hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_TCP = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DsPollingInterval = -1;
static gint hf_dnsserver_opnum = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DsAvailable = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_ForwardDelegations = -1;
static gint hf_dnsserver_DNS_RPC_RECORD_Serial = -1;
static gint hf_dnsserver_DnssrvQuery2_operation = -1;
static gint hf_dnsserver_DnssrvQuery2_type_id = -1;
static gint hf_dnsserver_DNS_RPC_NAME_NameLength = -1;
static gint hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_OPEN_ACL = -1;
static gint hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_RECOR_DEFAULT_TTL = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_EventLogLevel = -1;
static gint hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_LocalNetPriorityNetmask = -1;

static gint proto_dcerpc_dnsserver = -1;
/* Version information */


static e_uuid_t uuid_dcerpc_dnsserver = {
	0x50abc2a4, 0x574d, 0x40b3,
	{ 0x9d, 0x66, 0xee, 0x4f, 0xd5, 0xfb, 0xa0, 0x76 }
};
static guint16 ver_dcerpc_dnsserver = 5;

const value_string dnsserver_DNS_RPC_CLIENT_VERSION_vals[] = {
	{ DNS_CLIENT_VERSION_W2K, "DNS_CLIENT_VERSION_W2K" },
	{ DNS_CLIENT_VERSION_DOTNET, "DNS_CLIENT_VERSION_DOTNET" },
	{ DNS_CLIENT_VERSION_LONGHORN, "DNS_CLIENT_VERSION_LONGHORN" },
{ 0, NULL }
};
static int dnsserver_dissect_element_DNS_RPC_VERSION_OSMajorVersion(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_VERSION_OSMinorVersion(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_VERSION_ServicePackVersion(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
const value_string dnsserver_DNS_RPC_BOOT_METHOD_vals[] = {
	{ DNS_RPC_BOOT_METHOD_FILE, "DNS_RPC_BOOT_METHOD_FILE" },
	{ DNS_RPC_BOOT_METHOD_REGISTRY, "DNS_RPC_BOOT_METHOD_REGISTRY" },
	{ DNS_RPC_BOOT_METHOD_DIRECTORY, "DNS_RPC_BOOT_METHOD_DIRECTORY" },
{ 0, NULL }
};
static const true_false_string DNS_LOG_LEVELS_DNS_LOG_LEVEL_QUERY_tfs = {
   "DNS_LOG_LEVEL_QUERY is SET",
   "DNS_LOG_LEVEL_QUERY is NOT SET",
};
static const true_false_string DNS_LOG_LEVELS_DNS_LOG_LEVEL_NOTIFY_tfs = {
   "DNS_LOG_LEVEL_NOTIFY is SET",
   "DNS_LOG_LEVEL_NOTIFY is NOT SET",
};
static const true_false_string DNS_LOG_LEVELS_DNS_LOG_LEVEL_UPDATE_tfs = {
   "DNS_LOG_LEVEL_UPDATE is SET",
   "DNS_LOG_LEVEL_UPDATE is NOT SET",
};
static const true_false_string DNS_LOG_LEVELS_DNS_LOG_LEVEL_QUESTIONS_tfs = {
   "DNS_LOG_LEVEL_QUESTIONS is SET",
   "DNS_LOG_LEVEL_QUESTIONS is NOT SET",
};
static const true_false_string DNS_LOG_LEVELS_DNS_LOG_LEVEL_ANSWERS_tfs = {
   "DNS_LOG_LEVEL_ANSWERS is SET",
   "DNS_LOG_LEVEL_ANSWERS is NOT SET",
};
static const true_false_string DNS_LOG_LEVELS_DNS_LOG_LEVEL_SEND_tfs = {
   "DNS_LOG_LEVEL_SEND is SET",
   "DNS_LOG_LEVEL_SEND is NOT SET",
};
static const true_false_string DNS_LOG_LEVELS_DNS_LOG_LEVEL_RECV_tfs = {
   "DNS_LOG_LEVEL_RECV is SET",
   "DNS_LOG_LEVEL_RECV is NOT SET",
};
static const true_false_string DNS_LOG_LEVELS_DNS_LOG_LEVEL_UDP_tfs = {
   "DNS_LOG_LEVEL_UDP is SET",
   "DNS_LOG_LEVEL_UDP is NOT SET",
};
static const true_false_string DNS_LOG_LEVELS_DNS_LOG_LEVEL_TCP_tfs = {
   "DNS_LOG_LEVEL_TCP is SET",
   "DNS_LOG_LEVEL_TCP is NOT SET",
};
static const true_false_string DNS_LOG_LEVELS_DNS_LOG_LEVEL_FULL_PACKETS_tfs = {
   "DNS_LOG_LEVEL_FULL_PACKETS is SET",
   "DNS_LOG_LEVEL_FULL_PACKETS is NOT SET",
};
static const true_false_string DNS_LOG_LEVELS_DNS_LOG_LEVEL_WRITE_THROUGH_tfs = {
   "DNS_LOG_LEVEL_WRITE_THROUGH is SET",
   "DNS_LOG_LEVEL_WRITE_THROUGH is NOT SET",
};
static const true_false_string DNS_RPC_PROTOCOLS_DNS_RPC_USE_TCPIP_tfs = {
   "DNS_RPC_USE_TCPIP is SET",
   "DNS_RPC_USE_TCPIP is NOT SET",
};
static const true_false_string DNS_RPC_PROTOCOLS_DNS_RPC_USE_NAMED_PIPE_tfs = {
   "DNS_RPC_USE_NAMED_PIPE is SET",
   "DNS_RPC_USE_NAMED_PIPE is NOT SET",
};
static const true_false_string DNS_RPC_PROTOCOLS_DNS_RPC_USE_LPC_tfs = {
   "DNS_RPC_USE_LPC is SET",
   "DNS_RPC_USE_LPC is NOT SET",
};
const value_string dnsserver_DNS_NAME_CHECK_FLAGS_vals[] = {
	{ DNS_ALLOW_RFC_NAMES_ONLY, "DNS_ALLOW_RFC_NAMES_ONLY" },
	{ DNS_ALLOW_NONRFC_NAMES, "DNS_ALLOW_NONRFC_NAMES" },
	{ DNS_ALLOW_MULTIBYTE_NAMES, "DNS_ALLOW_MULTIBYTE_NAMES" },
	{ DNS_ALLOW_ALL_NAMES, "DNS_ALLOW_ALL_NAMES" },
{ 0, NULL }
};
const value_string dnsserver_DNS_RECORD_TYPE_vals[] = {
	{ DNS_TYPE_ZERO, "DNS_TYPE_ZERO" },
	{ DNS_TYPE_A, "DNS_TYPE_A" },
	{ DNS_TYPE_NS, "DNS_TYPE_NS" },
	{ DNS_TYPE_MD, "DNS_TYPE_MD" },
	{ DNS_TYPE_MF, "DNS_TYPE_MF" },
	{ DNS_TYPE_CNAME, "DNS_TYPE_CNAME" },
	{ DNS_TYPE_SOA, "DNS_TYPE_SOA" },
	{ DNS_TYPE_MB, "DNS_TYPE_MB" },
	{ DNS_TYPE_MG, "DNS_TYPE_MG" },
	{ DNS_TYPE_MR, "DNS_TYPE_MR" },
	{ DNS_TYPE_NULL, "DNS_TYPE_NULL" },
	{ DNS_TYPE_WKS, "DNS_TYPE_WKS" },
	{ DNS_TYPE_PTR, "DNS_TYPE_PTR" },
	{ DNS_TYPE_HINFO, "DNS_TYPE_HINFO" },
	{ DNS_TYPE_MINFO, "DNS_TYPE_MINFO" },
	{ DNS_TYPE_MX, "DNS_TYPE_MX" },
	{ DNS_TYPE_TXT, "DNS_TYPE_TXT" },
	{ DNS_TYPE_RP, "DNS_TYPE_RP" },
	{ DNS_TYPE_AFSDB, "DNS_TYPE_AFSDB" },
	{ DNS_TYPE_X25, "DNS_TYPE_X25" },
	{ DNS_TYPE_ISDN, "DNS_TYPE_ISDN" },
	{ DNS_TYPE_RT, "DNS_TYPE_RT" },
	{ DNS_TYPE_NSAP, "DNS_TYPE_NSAP" },
	{ DNS_TYPE_NSAPPTR, "DNS_TYPE_NSAPPTR" },
	{ DNS_TYPE_SIG, "DNS_TYPE_SIG" },
	{ DNS_TYPE_KEY, "DNS_TYPE_KEY" },
	{ DNS_TYPE_PX, "DNS_TYPE_PX" },
	{ DNS_TYPE_GPOS, "DNS_TYPE_GPOS" },
	{ DNS_TYPE_AAAA, "DNS_TYPE_AAAA" },
	{ DNS_TYPE_LOC, "DNS_TYPE_LOC" },
	{ DNS_TYPE_NXT, "DNS_TYPE_NXT" },
	{ DNS_TYPE_SRV, "DNS_TYPE_SRV" },
	{ DNS_TYPE_ATMA, "DNS_TYPE_ATMA" },
	{ DNS_TYPE_NAPTR, "DNS_TYPE_NAPTR" },
	{ DNS_TYPE_DNAME, "DNS_TYPE_DNAME" },
	{ DNS_TYPE_ALL, "DNS_TYPE_ALL" },
	{ DNS_TYPE_WINS, "DNS_TYPE_WINS" },
	{ DNS_TYPE_WINSR, "DNS_TYPE_WINSR" },
{ 0, NULL }
};
static const true_false_string DNS_SELECT_FLAGS_DNS_RPC_VIEW_AUTHORITY_DATA_tfs = {
   "DNS_RPC_VIEW_AUTHORITY_DATA is SET",
   "DNS_RPC_VIEW_AUTHORITY_DATA is NOT SET",
};
static const true_false_string DNS_SELECT_FLAGS_DNS_RPC_VIEW_CACHE_DATA_tfs = {
   "DNS_RPC_VIEW_CACHE_DATA is SET",
   "DNS_RPC_VIEW_CACHE_DATA is NOT SET",
};
static const true_false_string DNS_SELECT_FLAGS_DNS_RPC_VIEW_GLUE_DATA_tfs = {
   "DNS_RPC_VIEW_GLUE_DATA is SET",
   "DNS_RPC_VIEW_GLUE_DATA is NOT SET",
};
static const true_false_string DNS_SELECT_FLAGS_DNS_RPC_VIEW_ROOT_HINT_DATA_tfs = {
   "DNS_RPC_VIEW_ROOT_HINT_DATA is SET",
   "DNS_RPC_VIEW_ROOT_HINT_DATA is NOT SET",
};
static const true_false_string DNS_SELECT_FLAGS_DNS_RPC_VIEW_ADDITIONAL_DATA_tfs = {
   "DNS_RPC_VIEW_ADDITIONAL_DATA is SET",
   "DNS_RPC_VIEW_ADDITIONAL_DATA is NOT SET",
};
static const true_false_string DNS_SELECT_FLAGS_DNS_RPC_VIEW_NO_CHILDREN_tfs = {
   "DNS_RPC_VIEW_NO_CHILDREN is SET",
   "DNS_RPC_VIEW_NO_CHILDREN is NOT SET",
};
static const true_false_string DNS_SELECT_FLAGS_DNS_RPC_VIEW_ONLY_CHILDREN_tfs = {
   "DNS_RPC_VIEW_ONLY_CHILDREN is SET",
   "DNS_RPC_VIEW_ONLY_CHILDREN is NOT SET",
};
static const true_false_string DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_CACHE_DATA_tfs = {
   "DNS_RPC_FLAG_CACHE_DATA is SET",
   "DNS_RPC_FLAG_CACHE_DATA is NOT SET",
};
static const true_false_string DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_ZONE_ROOT_tfs = {
   "DNS_RPC_FLAG_ZONE_ROOT is SET",
   "DNS_RPC_FLAG_ZONE_ROOT is NOT SET",
};
static const true_false_string DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_AUTH_ZONE_ROOT_tfs = {
   "DNS_RPC_FLAG_AUTH_ZONE_ROOT is SET",
   "DNS_RPC_FLAG_AUTH_ZONE_ROOT is NOT SET",
};
static const true_false_string DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_ZONE_DELEGATION_tfs = {
   "DNS_RPC_FLAG_ZONE_DELEGATION is SET",
   "DNS_RPC_FLAG_ZONE_DELEGATION is NOT SET",
};
static const true_false_string DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_RECOR_DEFAULT_TTL_tfs = {
   "DNS_RPC_FLAG_RECOR_DEFAULT_TTL is SET",
   "DNS_RPC_FLAG_RECOR_DEFAULT_TTL is NOT SET",
};
static const true_false_string DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_RECORD_TTL_CHANGE_tfs = {
   "DNS_RPC_FLAG_RECORD_TTL_CHANGE is SET",
   "DNS_RPC_FLAG_RECORD_TTL_CHANGE is NOT SET",
};
static const true_false_string DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_RECORD_CREATE_PTR_tfs = {
   "DNS_RPC_FLAG_RECORD_CREATE_PTR is SET",
   "DNS_RPC_FLAG_RECORD_CREATE_PTR is NOT SET",
};
static const true_false_string DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_NODE_STICKY_tfs = {
   "DNS_RPC_FLAG_NODE_STICKY is SET",
   "DNS_RPC_FLAG_NODE_STICKY is NOT SET",
};
static const true_false_string DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_NODE_COMPLETE_tfs = {
   "DNS_RPC_FLAG_NODE_COMPLETE is SET",
   "DNS_RPC_FLAG_NODE_COMPLETE is NOT SET",
};
static const true_false_string DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_OPEN_ACL_tfs = {
   "DNS_RPC_FLAG_OPEN_ACL is SET",
   "DNS_RPC_FLAG_OPEN_ACL is NOT SET",
};
static const true_false_string DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_AGING_ON_tfs = {
   "DNS_RPC_FLAG_AGING_ON is SET",
   "DNS_RPC_FLAG_AGING_ON is NOT SET",
};
static const true_false_string DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_SUPPRESS_NOTIFY_tfs = {
   "DNS_RPC_FLAG_SUPPRESS_NOTIFY is SET",
   "DNS_RPC_FLAG_SUPPRESS_NOTIFY is NOT SET",
};
static int dnsserver_dissect_element_DNS_RPC_NAME_NameLength(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_NAME_Name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_NAME_Name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_RECORD_NODE_NAME_Name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_RECORD_UNION_NodeName(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_RECORD_DataLength(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_RECORD_Type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_RECORD_Flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_RECORD_Serial(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_RECORD_TtlSeconds(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_RECORD_TimeStamp(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_RECORD_reserved(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_RECORD_record(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_NODE_Length(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_NODE_RecordCount(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_NODE_Flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_NODE_Childcount(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_NODE_NodeName(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_NODE_records(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_NODE_records_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_IP4_ARRAY_AddrCount(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_IP4_ARRAY_AddrArray(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_IP4_ARRAY_AddrArray_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_RpcStructureVersion(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_reserved0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_Version(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_BootMethod(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_AdminConfigured(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_AllowUpdate(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DsAvailable(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ServerName(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ServerName_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DsContainer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DsContainer_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ServerAddrs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ServerAddrs_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ListenAddrs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ListenAddrs_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_Forwarders(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_Forwarders_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_LogFilter(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_LogFilter_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_LogFilePath(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_LogFilePath_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DomainName(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DomainName_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ForestName(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ForestName_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DomainDirectoryPartition(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DomainDirectoryPartition_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ForestDirectoryPartition(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ForestDirectoryPartition_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension1_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension2_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension3(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension3_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension4(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension4_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension5(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension5_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_LogLevel(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DebugLevel(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ForwardTimeout(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_RpcProtocol(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_NameCheckFlag(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_AddressAnswerLimit(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_RecursionRetry(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_RecursionTimeout(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_MaxCacheTtl(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DsPollingInterval(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_LocalNetPriorityNetmask(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ScavengingInterval(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DefaultRefreshInterval(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DefaultNoRefreshInterval(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_LastScavengeTime(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_EventLogLevel(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_LogFileMaxSize(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DsForestVersion(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DsDomainVersion(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DsDsaVersion(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_reserve_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_reserve_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_AutoReverseZones(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_AutoCacheUpdate(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_RecurseAfterForwarding(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ForwardDelegations(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_NoRecursion(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_SecureResponses(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_RoundRobin(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_LocalNetPriority(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_BindSecondaries(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_WriteAuthorityNs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_StrictFileParsing(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_LooseWildcarding(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DefaultAgingState(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_reserve_array2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_reserve_array2_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
const value_string dnsserver_DnssrvRpcTypeId_vals[] = {
	{ DNSSRV_TYPEID_NULL, "DNSSRV_TYPEID_NULL" },
	{ DNSSRV_TYPEID_DWORD, "DNSSRV_TYPEID_DWORD" },
	{ DNSSRV_TYPEID_LPSTR, "DNSSRV_TYPEID_LPSTR" },
	{ DNSSRV_TYPEID_LPWSTR, "DNSSRV_TYPEID_LPWSTR" },
	{ DNSSRV_TYPEID_IPARRAY, "DNSSRV_TYPEID_IPARRAY" },
	{ DNSSRV_TYPEID_BUFFER, "DNSSRV_TYPEID_BUFFER" },
	{ DNSSRV_TYPEID_SERVER_INFO_W2K, "DNSSRV_TYPEID_SERVER_INFO_W2K" },
	{ DNSSRV_TYPEID_STATS, "DNSSRV_TYPEID_STATS" },
	{ DNSSRV_TYPEID_FORWARDERS_W2K, "DNSSRV_TYPEID_FORWARDERS_W2K" },
	{ DNSSRV_TYPEID_ZONE_W2K, "DNSSRV_TYPEID_ZONE_W2K" },
	{ DNSSRV_TYPEID_ZONE_INFO_W2K, "DNSSRV_TYPEID_ZONE_INFO_W2K" },
	{ DNSSRV_TYPEID_ZONE_SECONDARIES_W2K, "DNSSRV_TYPEID_ZONE_SECONDARIES_W2K" },
	{ DNSSRV_TYPEID_ZONE_DATABASE_W2K, "DNSSRV_TYPEID_ZONE_DATABASE_W2K" },
	{ DNSSRV_TYPEID_ZONE_TYPE_RESET_W2K, "DNSSRV_TYPEID_ZONE_TYPE_RESET_W2K" },
	{ DNSSRV_TYPEID_ZONE_CREATE_W2K, "DNSSRV_TYPEID_ZONE_CREATE_W2K" },
	{ DNSSRV_TYPEID_NAME_AND_PARAM, "DNSSRV_TYPEID_NAME_AND_PARAM" },
	{ DNSSRV_TYPEID_ZONE_LIST_W2K, "DNSSRV_TYPEID_ZONE_LIST_W2K" },
	{ DNSSRV_TYPEID_ZONE_RENAME, "DNSSRV_TYPEID_ZONE_RENAME" },
	{ DNSSRV_TYPEID_ZONE_EXPORT, "DNSSRV_TYPEID_ZONE_EXPORT" },
	{ DNSSRV_TYPEID_SERVER_INFO_DOTNET, "DNSSRV_TYPEID_SERVER_INFO_DOTNET" },
	{ DNSSRV_TYPEID_FORWARDERS_DOTNET, "DNSSRV_TYPEID_FORWARDERS_DOTNET" },
	{ DNSSRV_TYPEID_ZONE, "DNSSRV_TYPEID_ZONE" },
	{ DNSSRV_TYPEID_ZONE_INFO_DOTNET, "DNSSRV_TYPEID_ZONE_INFO_DOTNET" },
	{ DNSSRV_TYPEID_ZONE_SECONDARIES_DOTNET, "DNSSRV_TYPEID_ZONE_SECONDARIES_DOTNET" },
	{ DNSSRV_TYPEID_ZONE_DATABASE, "DNSSRV_TYPEID_ZONE_DATABASE" },
	{ DNSSRV_TYPEID_ZONE_TYPE_RESET_DOTNET, "DNSSRV_TYPEID_ZONE_TYPE_RESET_DOTNET" },
	{ DNSSRV_TYPEID_ZONE_CREATE_DOTNET, "DNSSRV_TYPEID_ZONE_CREATE_DOTNET" },
	{ DNSSRV_TYPEID_ZONE_LIST, "DNSSRV_TYPEID_ZONE_LIST" },
	{ DNSSRV_TYPEID_DP_ENUM, "DNSSRV_TYPEID_DP_ENUM" },
	{ DNSSRV_TYPEID_DP_INFO, "DNSSRV_TYPEID_DP_INFO" },
	{ DNSSRV_TYPEID_DP_LIST, "DNSSRV_TYPEID_DP_LIST" },
	{ DNSSRV_TYPEID_ENLIST_DP, "DNSSRV_TYPEID_ENLIST_DP" },
	{ DNSSRV_TYPEID_ZONE_CHANGE_DP, "DNSSRV_TYPEID_ZONE_CHANGE_DP" },
	{ DNSSRV_TYPEID_ENUM_ZONES_FILTER, "DNSSRV_TYPEID_ENUM_ZONES_FILTER" },
	{ DNSSRV_TYPEID_ADDARRAY, "DNSSRV_TYPEID_ADDARRAY" },
	{ DNSSRV_TYPEID_SERVER_INFO, "DNSSRV_TYPEID_SERVER_INFO" },
	{ DNSSRV_TYPEID_ZONE_INFO, "DNSSRV_TYPEID_ZONE_INFO" },
	{ DNSSRV_TYPEID_FORWARDERS, "DNSSRV_TYPEID_FORWARDERS" },
	{ DNSSRV_TYPEID_ZONE_SECONDARIES, "DNSSRV_TYPEID_ZONE_SECONDARIES" },
	{ DNSSRV_TYPEID_ZONE_TYPE_RESET, "DNSSRV_TYPEID_ZONE_TYPE_RESET" },
	{ DNSSRV_TYPEID_ZONE_CREATE, "DNSSRV_TYPEID_ZONE_CREATE" },
	{ DNSSRV_TYPEID_IP_VALIDATE, "DNSSRV_TYPEID_IP_VALIDATE" },
	{ DNSSRV_TYPEID_AUTOCONFIGURE, "DNSSRV_TYPEID_AUTOCONFIGURE" },
	{ DNSSRV_TYPEID_UTF8_STRING_LIST, "DNSSRV_TYPEID_UTF8_STRING_LIST" },
	{ DNSSRV_TYPEID_UNICODE_STRING_LIST, "DNSSRV_TYPEID_UNICODE_STRING_LIST" },
{ 0, NULL }
};
static int dnsserver_dissect_element_DNSSRV_RPC_UNION_null(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNSSRV_RPC_UNION_null_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNSSRV_RPC_UNION_dword(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNSSRV_RPC_UNION_ServerInfoDotnet(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNSSRV_RPC_UNION_ServerInfoDotnet_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DNS_RECORD_BUFFER_rpc_node(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvQuery2_client_version(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvQuery2_setting_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvQuery2_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvQuery2_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvQuery2_zone(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvQuery2_zone_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvQuery2_operation(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvQuery2_operation_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvQuery2_type_id(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvQuery2_type_id_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvQuery2_data(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvQuery2_data_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvEnumRecords2_client_version(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvEnumRecords2_setting_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvEnumRecords2_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvEnumRecords2_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvEnumRecords2_zone(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvEnumRecords2_zone_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvEnumRecords2_node_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvEnumRecords2_node_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvEnumRecords2_start_child(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvEnumRecords2_start_child_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvEnumRecords2_record_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvEnumRecords2_select_flag(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvEnumRecords2_filter_start(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvEnumRecords2_filter_start_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvEnumRecords2_filter_stop(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvEnumRecords2_filter_stop_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvEnumRecords2_buffer_length(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvEnumRecords2_buffer_length_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvEnumRecords2_record_buffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvEnumRecords2_record_buffer_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int dnsserver_dissect_element_DnssrvEnumRecords2_record_buffer__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
	#include "packet-smb-common.h"
int
dnsserver_dissect_struct_DNS_RPC_NAME(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;
	dcerpc_info *di = NULL;
	guint8 len;
	const char *dn;
	int dn_len = 0;
	guint16 bc;
	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}
	old_offset = offset;
	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_dnsserver_DNS_RPC_NAME);
	}
	offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_NAME_NameLength, &len);
	bc = tvb_length_remaining(tvb, offset);
	dn = get_unicode_or_ascii_string(tvb, &offset,
			TRUE, &dn_len, TRUE, TRUE, &bc);
	if (dn) {
		proto_tree_add_string(tree, hf_dnsserver_DNS_RPC_NAME_name, tvb,
			offset, dn_len,dn);
		offset += dn_len;
	}
	proto_item_set_len(item, offset-old_offset);
	return offset;
}
static guint16 node_record_count;
static int
dnsserver_dissect_element_DNS_RPC_NODE_RecordCount(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	dcerpc_info *di = NULL;
	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_NODE_RecordCount, &node_record_count);
	return offset;
}
static int
dnsserver_dissect_element_DNS_RPC_NODE_records(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	dcerpc_info *di = NULL;
	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}
	while(node_record_count--){
		offset = dnsserver_dissect_element_DNS_RPC_NODE_records_(tvb, offset, pinfo, tree, drep);
	}
	return offset;
}


/* IDL: enum { */
/* IDL: 	DNS_CLIENT_VERSION_W2K=0x00000000, */
/* IDL: 	DNS_CLIENT_VERSION_DOTNET=0x00000006, */
/* IDL: 	DNS_CLIENT_VERSION_LONGHORN=0x00000007, */
/* IDL: } */

int
dnsserver_dissect_enum_DNS_RPC_CLIENT_VERSION(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_)
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
/* IDL: 	uint8 OSMajorVersion; */
/* IDL: 	uint8 OSMinorVersion; */
/* IDL: 	uint16 ServicePackVersion; */
/* IDL: } */

static int
dnsserver_dissect_element_DNS_RPC_VERSION_OSMajorVersion(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_VERSION_OSMajorVersion, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_VERSION_OSMinorVersion(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_VERSION_OSMinorVersion, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_VERSION_ServicePackVersion(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_VERSION_ServicePackVersion, 0);

	return offset;
}

int
dnsserver_dissect_struct_DNS_RPC_VERSION(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_2_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_dnsserver_DNS_RPC_VERSION);
	}

	offset = dnsserver_dissect_element_DNS_RPC_VERSION_OSMajorVersion(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_VERSION_OSMinorVersion(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_VERSION_ServicePackVersion(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: enum { */
/* IDL: 	DNS_RPC_BOOT_METHOD_FILE=0x01, */
/* IDL: 	DNS_RPC_BOOT_METHOD_REGISTRY=0x02, */
/* IDL: 	DNS_RPC_BOOT_METHOD_DIRECTORY=0x03, */
/* IDL: } */

int
dnsserver_dissect_enum_DNS_RPC_BOOT_METHOD(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_)
{
	guint8 parameter=0;
	if(param){
		parameter=(guint8)*param;
	}
	offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep, hf_index, &parameter);
	if(param){
		*param=(guint32)parameter;
	}
	return offset;
}


/* IDL: bitmap { */
/* IDL: 	DNS_LOG_LEVEL_QUERY =  0x00000001 , */
/* IDL: 	DNS_LOG_LEVEL_NOTIFY =  0x00000010 , */
/* IDL: 	DNS_LOG_LEVEL_UPDATE =  0x00000020 , */
/* IDL: 	DNS_LOG_LEVEL_QUESTIONS =  0x00000100 , */
/* IDL: 	DNS_LOG_LEVEL_ANSWERS =  0x00000200 , */
/* IDL: 	DNS_LOG_LEVEL_SEND =  0x00001000 , */
/* IDL: 	DNS_LOG_LEVEL_RECV =  0x00002000 , */
/* IDL: 	DNS_LOG_LEVEL_UDP =  0x00004000 , */
/* IDL: 	DNS_LOG_LEVEL_TCP =  0x00008000 , */
/* IDL: 	DNS_LOG_LEVEL_FULL_PACKETS =  0x01000000 , */
/* IDL: 	DNS_LOG_LEVEL_WRITE_THROUGH =  0x80000000 , */
/* IDL: } */

int
dnsserver_dissect_bitmap_DNS_LOG_LEVELS(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	guint32 flags;
	ALIGN_TO_4_BYTES;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, 4, TRUE);
		tree = proto_item_add_subtree(item,ett_dnsserver_DNS_LOG_LEVELS);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, drep, -1, &flags);
	proto_item_append_text(item, ": ");

	if (!flags)
		proto_item_append_text(item, "(No values set)");

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_QUERY, tvb, offset-4, 4, flags);
	if (flags&( 0x00000001 )){
		proto_item_append_text(item, "DNS_LOG_LEVEL_QUERY");
		if (flags & (~( 0x00000001 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000001 ));

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_NOTIFY, tvb, offset-4, 4, flags);
	if (flags&( 0x00000010 )){
		proto_item_append_text(item, "DNS_LOG_LEVEL_NOTIFY");
		if (flags & (~( 0x00000010 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000010 ));

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_UPDATE, tvb, offset-4, 4, flags);
	if (flags&( 0x00000020 )){
		proto_item_append_text(item, "DNS_LOG_LEVEL_UPDATE");
		if (flags & (~( 0x00000020 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000020 ));

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_QUESTIONS, tvb, offset-4, 4, flags);
	if (flags&( 0x00000100 )){
		proto_item_append_text(item, "DNS_LOG_LEVEL_QUESTIONS");
		if (flags & (~( 0x00000100 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000100 ));

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_ANSWERS, tvb, offset-4, 4, flags);
	if (flags&( 0x00000200 )){
		proto_item_append_text(item, "DNS_LOG_LEVEL_ANSWERS");
		if (flags & (~( 0x00000200 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000200 ));

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_SEND, tvb, offset-4, 4, flags);
	if (flags&( 0x00001000 )){
		proto_item_append_text(item, "DNS_LOG_LEVEL_SEND");
		if (flags & (~( 0x00001000 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00001000 ));

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_RECV, tvb, offset-4, 4, flags);
	if (flags&( 0x00002000 )){
		proto_item_append_text(item, "DNS_LOG_LEVEL_RECV");
		if (flags & (~( 0x00002000 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00002000 ));

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_UDP, tvb, offset-4, 4, flags);
	if (flags&( 0x00004000 )){
		proto_item_append_text(item, "DNS_LOG_LEVEL_UDP");
		if (flags & (~( 0x00004000 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00004000 ));

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_TCP, tvb, offset-4, 4, flags);
	if (flags&( 0x00008000 )){
		proto_item_append_text(item, "DNS_LOG_LEVEL_TCP");
		if (flags & (~( 0x00008000 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00008000 ));

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_FULL_PACKETS, tvb, offset-4, 4, flags);
	if (flags&( 0x01000000 )){
		proto_item_append_text(item, "DNS_LOG_LEVEL_FULL_PACKETS");
		if (flags & (~( 0x01000000 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x01000000 ));

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_WRITE_THROUGH, tvb, offset-4, 4, flags);
	if (flags&( 0x80000000 )){
		proto_item_append_text(item, "DNS_LOG_LEVEL_WRITE_THROUGH");
		if (flags & (~( 0x80000000 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x80000000 ));

	if (flags) {
		proto_item_append_text(item, "Unknown bitmap value 0x%x", flags);
	}

	return offset;
}


/* IDL: bitmap { */
/* IDL: 	DNS_RPC_USE_TCPIP =  0x00000001 , */
/* IDL: 	DNS_RPC_USE_NAMED_PIPE =  0x00000002 , */
/* IDL: 	DNS_RPC_USE_LPC =  0x00000004 , */
/* IDL: } */

int
dnsserver_dissect_bitmap_DNS_RPC_PROTOCOLS(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	guint32 flags;
	ALIGN_TO_4_BYTES;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, 4, TRUE);
		tree = proto_item_add_subtree(item,ett_dnsserver_DNS_RPC_PROTOCOLS);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, drep, -1, &flags);
	proto_item_append_text(item, ": ");

	if (!flags)
		proto_item_append_text(item, "(No values set)");

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_RPC_PROTOCOLS_DNS_RPC_USE_TCPIP, tvb, offset-4, 4, flags);
	if (flags&( 0x00000001 )){
		proto_item_append_text(item, "DNS_RPC_USE_TCPIP");
		if (flags & (~( 0x00000001 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000001 ));

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_RPC_PROTOCOLS_DNS_RPC_USE_NAMED_PIPE, tvb, offset-4, 4, flags);
	if (flags&( 0x00000002 )){
		proto_item_append_text(item, "DNS_RPC_USE_NAMED_PIPE");
		if (flags & (~( 0x00000002 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000002 ));

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_RPC_PROTOCOLS_DNS_RPC_USE_LPC, tvb, offset-4, 4, flags);
	if (flags&( 0x00000004 )){
		proto_item_append_text(item, "DNS_RPC_USE_LPC");
		if (flags & (~( 0x00000004 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000004 ));

	if (flags) {
		proto_item_append_text(item, "Unknown bitmap value 0x%x", flags);
	}

	return offset;
}


/* IDL: enum { */
/* IDL: 	DNS_ALLOW_RFC_NAMES_ONLY=0x00000000, */
/* IDL: 	DNS_ALLOW_NONRFC_NAMES=0x00000001, */
/* IDL: 	DNS_ALLOW_MULTIBYTE_NAMES=0x00000002, */
/* IDL: 	DNS_ALLOW_ALL_NAMES=0x00000003, */
/* IDL: } */

int
dnsserver_dissect_enum_DNS_NAME_CHECK_FLAGS(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_)
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


/* IDL: enum { */
/* IDL: 	DNS_TYPE_ZERO=0x0000, */
/* IDL: 	DNS_TYPE_A=0x0001, */
/* IDL: 	DNS_TYPE_NS=0x0002, */
/* IDL: 	DNS_TYPE_MD=0x0003, */
/* IDL: 	DNS_TYPE_MF=0x0004, */
/* IDL: 	DNS_TYPE_CNAME=0x0005, */
/* IDL: 	DNS_TYPE_SOA=0x0006, */
/* IDL: 	DNS_TYPE_MB=0x0007, */
/* IDL: 	DNS_TYPE_MG=0x0008, */
/* IDL: 	DNS_TYPE_MR=0x0009, */
/* IDL: 	DNS_TYPE_NULL=0x000a, */
/* IDL: 	DNS_TYPE_WKS=0x000b, */
/* IDL: 	DNS_TYPE_PTR=0x000c, */
/* IDL: 	DNS_TYPE_HINFO=0x000d, */
/* IDL: 	DNS_TYPE_MINFO=0x000e, */
/* IDL: 	DNS_TYPE_MX=0x000f, */
/* IDL: 	DNS_TYPE_TXT=0x0010, */
/* IDL: 	DNS_TYPE_RP=0x0011, */
/* IDL: 	DNS_TYPE_AFSDB=0x0012, */
/* IDL: 	DNS_TYPE_X25=0x0013, */
/* IDL: 	DNS_TYPE_ISDN=0x0014, */
/* IDL: 	DNS_TYPE_RT=0x0015, */
/* IDL: 	DNS_TYPE_NSAP=0x0016, */
/* IDL: 	DNS_TYPE_NSAPPTR=0x0017, */
/* IDL: 	DNS_TYPE_SIG=0x0018, */
/* IDL: 	DNS_TYPE_KEY=0x0019, */
/* IDL: 	DNS_TYPE_PX=0x001a, */
/* IDL: 	DNS_TYPE_GPOS=0x001b, */
/* IDL: 	DNS_TYPE_AAAA=0x001c, */
/* IDL: 	DNS_TYPE_LOC=0x001d, */
/* IDL: 	DNS_TYPE_NXT=0x001e, */
/* IDL: 	DNS_TYPE_SRV=0x0021, */
/* IDL: 	DNS_TYPE_ATMA=0x0022, */
/* IDL: 	DNS_TYPE_NAPTR=0x0023, */
/* IDL: 	DNS_TYPE_DNAME=0x0024, */
/* IDL: 	DNS_TYPE_ALL=0x00ff, */
/* IDL: 	DNS_TYPE_WINS=0xff01, */
/* IDL: 	DNS_TYPE_WINSR=0xff02, */
/* IDL: } */

int
dnsserver_dissect_enum_DNS_RECORD_TYPE(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_)
{
	guint16 parameter=0;
	if(param){
		parameter=(guint16)*param;
	}
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_index, &parameter);
	if(param){
		*param=(guint32)parameter;
	}
	return offset;
}


/* IDL: bitmap { */
/* IDL: 	DNS_RPC_VIEW_AUTHORITY_DATA =  0x00000001 , */
/* IDL: 	DNS_RPC_VIEW_CACHE_DATA =  0x00000002 , */
/* IDL: 	DNS_RPC_VIEW_GLUE_DATA =  0x00000004 , */
/* IDL: 	DNS_RPC_VIEW_ROOT_HINT_DATA =  0x00000008 , */
/* IDL: 	DNS_RPC_VIEW_ADDITIONAL_DATA =  0x00000010 , */
/* IDL: 	DNS_RPC_VIEW_NO_CHILDREN =  0x00010000 , */
/* IDL: 	DNS_RPC_VIEW_ONLY_CHILDREN =  0x00020000 , */
/* IDL: } */

int
dnsserver_dissect_bitmap_DNS_SELECT_FLAGS(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	guint32 flags;
	ALIGN_TO_4_BYTES;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, 4, TRUE);
		tree = proto_item_add_subtree(item,ett_dnsserver_DNS_SELECT_FLAGS);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, drep, -1, &flags);
	proto_item_append_text(item, ": ");

	if (!flags)
		proto_item_append_text(item, "(No values set)");

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_SELECT_FLAGS_DNS_RPC_VIEW_AUTHORITY_DATA, tvb, offset-4, 4, flags);
	if (flags&( 0x00000001 )){
		proto_item_append_text(item, "DNS_RPC_VIEW_AUTHORITY_DATA");
		if (flags & (~( 0x00000001 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000001 ));

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_SELECT_FLAGS_DNS_RPC_VIEW_CACHE_DATA, tvb, offset-4, 4, flags);
	if (flags&( 0x00000002 )){
		proto_item_append_text(item, "DNS_RPC_VIEW_CACHE_DATA");
		if (flags & (~( 0x00000002 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000002 ));

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_SELECT_FLAGS_DNS_RPC_VIEW_GLUE_DATA, tvb, offset-4, 4, flags);
	if (flags&( 0x00000004 )){
		proto_item_append_text(item, "DNS_RPC_VIEW_GLUE_DATA");
		if (flags & (~( 0x00000004 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000004 ));

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_SELECT_FLAGS_DNS_RPC_VIEW_ROOT_HINT_DATA, tvb, offset-4, 4, flags);
	if (flags&( 0x00000008 )){
		proto_item_append_text(item, "DNS_RPC_VIEW_ROOT_HINT_DATA");
		if (flags & (~( 0x00000008 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000008 ));

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_SELECT_FLAGS_DNS_RPC_VIEW_ADDITIONAL_DATA, tvb, offset-4, 4, flags);
	if (flags&( 0x00000010 )){
		proto_item_append_text(item, "DNS_RPC_VIEW_ADDITIONAL_DATA");
		if (flags & (~( 0x00000010 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000010 ));

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_SELECT_FLAGS_DNS_RPC_VIEW_NO_CHILDREN, tvb, offset-4, 4, flags);
	if (flags&( 0x00010000 )){
		proto_item_append_text(item, "DNS_RPC_VIEW_NO_CHILDREN");
		if (flags & (~( 0x00010000 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00010000 ));

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_SELECT_FLAGS_DNS_RPC_VIEW_ONLY_CHILDREN, tvb, offset-4, 4, flags);
	if (flags&( 0x00020000 )){
		proto_item_append_text(item, "DNS_RPC_VIEW_ONLY_CHILDREN");
		if (flags & (~( 0x00020000 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00020000 ));

	if (flags) {
		proto_item_append_text(item, "Unknown bitmap value 0x%x", flags);
	}

	return offset;
}


/* IDL: bitmap { */
/* IDL: 	DNS_RPC_FLAG_CACHE_DATA =  0x80000000 , */
/* IDL: 	DNS_RPC_FLAG_ZONE_ROOT =  0x40000000 , */
/* IDL: 	DNS_RPC_FLAG_AUTH_ZONE_ROOT =  0x20000000 , */
/* IDL: 	DNS_RPC_FLAG_ZONE_DELEGATION =  0x10000000 , */
/* IDL: 	DNS_RPC_FLAG_RECOR_DEFAULT_TTL =  0x08000000 , */
/* IDL: 	DNS_RPC_FLAG_RECORD_TTL_CHANGE =  0x04000000 , */
/* IDL: 	DNS_RPC_FLAG_RECORD_CREATE_PTR =  0x02000000 , */
/* IDL: 	DNS_RPC_FLAG_NODE_STICKY =  0x01000000 , */
/* IDL: 	DNS_RPC_FLAG_NODE_COMPLETE =  0x00800000 , */
/* IDL: 	DNS_RPC_FLAG_OPEN_ACL =  0x00040000 , */
/* IDL: 	DNS_RPC_FLAG_AGING_ON =  0x00020000 , */
/* IDL: 	DNS_RPC_FLAG_SUPPRESS_NOTIFY =  0x00010000 , */
/* IDL: } */

int
dnsserver_dissect_bitmap_DNS_RPC_NODE_FLAGS(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	guint32 flags;
	ALIGN_TO_4_BYTES;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, 4, TRUE);
		tree = proto_item_add_subtree(item,ett_dnsserver_DNS_RPC_NODE_FLAGS);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, drep, -1, &flags);
	proto_item_append_text(item, ": ");

	if (!flags)
		proto_item_append_text(item, "(No values set)");

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_CACHE_DATA, tvb, offset-4, 4, flags);
	if (flags&( 0x80000000 )){
		proto_item_append_text(item, "DNS_RPC_FLAG_CACHE_DATA");
		if (flags & (~( 0x80000000 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x80000000 ));

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_ZONE_ROOT, tvb, offset-4, 4, flags);
	if (flags&( 0x40000000 )){
		proto_item_append_text(item, "DNS_RPC_FLAG_ZONE_ROOT");
		if (flags & (~( 0x40000000 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x40000000 ));

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_AUTH_ZONE_ROOT, tvb, offset-4, 4, flags);
	if (flags&( 0x20000000 )){
		proto_item_append_text(item, "DNS_RPC_FLAG_AUTH_ZONE_ROOT");
		if (flags & (~( 0x20000000 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x20000000 ));

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_ZONE_DELEGATION, tvb, offset-4, 4, flags);
	if (flags&( 0x10000000 )){
		proto_item_append_text(item, "DNS_RPC_FLAG_ZONE_DELEGATION");
		if (flags & (~( 0x10000000 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x10000000 ));

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_RECOR_DEFAULT_TTL, tvb, offset-4, 4, flags);
	if (flags&( 0x08000000 )){
		proto_item_append_text(item, "DNS_RPC_FLAG_RECOR_DEFAULT_TTL");
		if (flags & (~( 0x08000000 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x08000000 ));

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_RECORD_TTL_CHANGE, tvb, offset-4, 4, flags);
	if (flags&( 0x04000000 )){
		proto_item_append_text(item, "DNS_RPC_FLAG_RECORD_TTL_CHANGE");
		if (flags & (~( 0x04000000 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x04000000 ));

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_RECORD_CREATE_PTR, tvb, offset-4, 4, flags);
	if (flags&( 0x02000000 )){
		proto_item_append_text(item, "DNS_RPC_FLAG_RECORD_CREATE_PTR");
		if (flags & (~( 0x02000000 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x02000000 ));

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_NODE_STICKY, tvb, offset-4, 4, flags);
	if (flags&( 0x01000000 )){
		proto_item_append_text(item, "DNS_RPC_FLAG_NODE_STICKY");
		if (flags & (~( 0x01000000 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x01000000 ));

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_NODE_COMPLETE, tvb, offset-4, 4, flags);
	if (flags&( 0x00800000 )){
		proto_item_append_text(item, "DNS_RPC_FLAG_NODE_COMPLETE");
		if (flags & (~( 0x00800000 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00800000 ));

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_OPEN_ACL, tvb, offset-4, 4, flags);
	if (flags&( 0x00040000 )){
		proto_item_append_text(item, "DNS_RPC_FLAG_OPEN_ACL");
		if (flags & (~( 0x00040000 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00040000 ));

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_AGING_ON, tvb, offset-4, 4, flags);
	if (flags&( 0x00020000 )){
		proto_item_append_text(item, "DNS_RPC_FLAG_AGING_ON");
		if (flags & (~( 0x00020000 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00020000 ));

	proto_tree_add_boolean(tree, hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_SUPPRESS_NOTIFY, tvb, offset-4, 4, flags);
	if (flags&( 0x00010000 )){
		proto_item_append_text(item, "DNS_RPC_FLAG_SUPPRESS_NOTIFY");
		if (flags & (~( 0x00010000 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00010000 ));

	if (flags) {
		proto_item_append_text(item, "Unknown bitmap value 0x%x", flags);
	}

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint8 NameLength; */
/* IDL: 	uint8 Name[NameLength]; */
/* IDL: } */

static int
dnsserver_dissect_element_DNS_RPC_NAME_NameLength(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_NAME_NameLength, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_NAME_Name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_NAME_Name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_NAME_Name, 0);

	return offset;
}


/* IDL: struct { */
/* IDL: 	DNS_RPC_NAME Name; */
/* IDL: } */

static int
dnsserver_dissect_element_DNS_RPC_RECORD_NODE_NAME_Name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dnsserver_dissect_struct_DNS_RPC_NAME(tvb,offset,pinfo,tree,drep,hf_dnsserver_DNS_RPC_RECORD_NODE_NAME_Name,0);

	return offset;
}

int
dnsserver_dissect_struct_DNS_RPC_RECORD_NODE_NAME(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;


	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_dnsserver_DNS_RPC_RECORD_NODE_NAME);
	}

	offset = dnsserver_dissect_element_DNS_RPC_RECORD_NODE_NAME_Name(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: union { */
/* IDL: [case(2)] [case(2)] DNS_RPC_RECORD_NODE_NAME NodeName; */
/* IDL: } */

static int
dnsserver_dissect_element_DNS_RPC_RECORD_UNION_NodeName(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dnsserver_dissect_struct_DNS_RPC_RECORD_NODE_NAME(tvb,offset,pinfo,tree,drep,hf_dnsserver_DNS_RPC_RECORD_UNION_NodeName,0);

	return offset;
}

static int
dnsserver_dissect_DNS_RPC_RECORD_UNION(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;
	guint32 level;

	old_offset = offset;
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1, "DNS_RPC_RECORD_UNION");
		tree = proto_item_add_subtree(item, ett_dnsserver_DNS_RPC_RECORD_UNION);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_index, &level);
	switch(level) {
		case 2:
			offset = dnsserver_dissect_element_DNS_RPC_RECORD_UNION_NodeName(tvb, offset, pinfo, tree, drep);
		break;
	}
	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: struct { */
/* IDL: 	uint16 DataLength; */
/* IDL: 	DNS_RECORD_TYPE Type; */
/* IDL: 	uint32 Flags; */
/* IDL: 	uint32 Serial; */
/* IDL: 	uint32 TtlSeconds; */
/* IDL: 	uint32 TimeStamp; */
/* IDL: 	uint32 reserved; */
/* IDL: 	[switch_is(Type)] DNS_RPC_RECORD_UNION record; */
/* IDL: } */

static int
dnsserver_dissect_element_DNS_RPC_RECORD_DataLength(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_RECORD_DataLength, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_RECORD_Type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dnsserver_dissect_enum_DNS_RECORD_TYPE(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_RECORD_Type, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_RECORD_Flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_RECORD_Flags, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_RECORD_Serial(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_RECORD_Serial, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_RECORD_TtlSeconds(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_RECORD_TtlSeconds, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_RECORD_TimeStamp(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_RECORD_TimeStamp, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_RECORD_reserved(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_RECORD_reserved, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_RECORD_record(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dnsserver_dissect_DNS_RPC_RECORD_UNION(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_RECORD_record, 0);

	return offset;
}

int
dnsserver_dissect_struct_DNS_RPC_RECORD(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_dnsserver_DNS_RPC_RECORD);
	}

	offset = dnsserver_dissect_element_DNS_RPC_RECORD_DataLength(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_RECORD_Type(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_RECORD_Flags(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_RECORD_Serial(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_RECORD_TtlSeconds(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_RECORD_TimeStamp(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_RECORD_reserved(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_RECORD_record(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint16 Length; */
/* IDL: 	uint16 RecordCount; */
/* IDL: 	DNS_RPC_NODE_FLAGS Flags; */
/* IDL: 	uint32 Childcount; */
/* IDL: 	DNS_RPC_NAME NodeName; */
/* IDL: 	DNS_RPC_RECORD records[RecordCount]; */
/* IDL: } */

static int
dnsserver_dissect_element_DNS_RPC_NODE_Length(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_NODE_Length, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_NODE_Flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dnsserver_dissect_bitmap_DNS_RPC_NODE_FLAGS(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_NODE_Flags, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_NODE_Childcount(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_NODE_Childcount, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_NODE_NodeName(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dnsserver_dissect_struct_DNS_RPC_NAME(tvb,offset,pinfo,tree,drep,hf_dnsserver_DNS_RPC_NODE_NodeName,0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_NODE_records_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dnsserver_dissect_struct_DNS_RPC_RECORD(tvb,offset,pinfo,tree,drep,hf_dnsserver_DNS_RPC_NODE_records,0);

	return offset;
}

int
dnsserver_dissect_struct_DNS_RPC_NODE(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_dnsserver_DNS_RPC_NODE);
	}

	offset = dnsserver_dissect_element_DNS_RPC_NODE_Length(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_NODE_RecordCount(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_NODE_Flags(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_NODE_Childcount(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_NODE_NodeName(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_NODE_records(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 AddrCount; */
/* IDL: 	[size_is(AddrCount)] uint32 AddrArray[*]; */
/* IDL: } */

static int
dnsserver_dissect_element_IP4_ARRAY_AddrCount(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_IP4_ARRAY_AddrCount, 0);

	return offset;
}

static int
dnsserver_dissect_element_IP4_ARRAY_AddrArray(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_IP4_ARRAY_AddrArray_);

	return offset;
}

static int
dnsserver_dissect_element_IP4_ARRAY_AddrArray_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_IP4_ARRAY_AddrArray, 0);

	return offset;
}

int
dnsserver_dissect_struct_IP4_ARRAY(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_dnsserver_IP4_ARRAY);
	}

	offset = dnsserver_dissect_element_IP4_ARRAY_AddrCount(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_IP4_ARRAY_AddrArray(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 RpcStructureVersion; */
/* IDL: 	uint32 reserved0; */
/* IDL: 	DNS_RPC_VERSION Version; */
/* IDL: 	DNS_RPC_BOOT_METHOD BootMethod; */
/* IDL: 	uint8 AdminConfigured; */
/* IDL: 	uint8 AllowUpdate; */
/* IDL: 	uint8 DsAvailable; */
/* IDL: 	[unique(1)] uint8 *ServerName; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *DsContainer; */
/* IDL: 	[unique(1)] IP4_ARRAY *ServerAddrs; */
/* IDL: 	[unique(1)] IP4_ARRAY *ListenAddrs; */
/* IDL: 	[unique(1)] IP4_ARRAY *Forwarders; */
/* IDL: 	[unique(1)] IP4_ARRAY *LogFilter; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *LogFilePath; */
/* IDL: 	[unique(1)] uint8 *DomainName; */
/* IDL: 	[unique(1)] uint8 *ForestName; */
/* IDL: 	[unique(1)] uint8 *DomainDirectoryPartition; */
/* IDL: 	[unique(1)] uint8 *ForestDirectoryPartition; */
/* IDL: 	[unique(1)] uint8 *extension0; */
/* IDL: 	[unique(1)] uint8 *extension1; */
/* IDL: 	[unique(1)] uint8 *extension2; */
/* IDL: 	[unique(1)] uint8 *extension3; */
/* IDL: 	[unique(1)] uint8 *extension4; */
/* IDL: 	[unique(1)] uint8 *extension5; */
/* IDL: 	DNS_LOG_LEVELS LogLevel; */
/* IDL: 	uint32 DebugLevel; */
/* IDL: 	uint32 ForwardTimeout; */
/* IDL: 	DNS_RPC_PROTOCOLS RpcProtocol; */
/* IDL: 	DNS_NAME_CHECK_FLAGS NameCheckFlag; */
/* IDL: 	uint32 AddressAnswerLimit; */
/* IDL: 	uint32 RecursionRetry; */
/* IDL: 	uint32 RecursionTimeout; */
/* IDL: 	uint32 MaxCacheTtl; */
/* IDL: 	uint32 DsPollingInterval; */
/* IDL: 	uint32 LocalNetPriorityNetmask; */
/* IDL: 	uint32 ScavengingInterval; */
/* IDL: 	uint32 DefaultRefreshInterval; */
/* IDL: 	uint32 DefaultNoRefreshInterval; */
/* IDL: 	uint32 LastScavengeTime; */
/* IDL: 	uint32 EventLogLevel; */
/* IDL: 	uint32 LogFileMaxSize; */
/* IDL: 	uint32 DsForestVersion; */
/* IDL: 	uint32 DsDomainVersion; */
/* IDL: 	uint32 DsDsaVersion; */
/* IDL: 	uint32 reserve_array[4]; */
/* IDL: 	uint8 AutoReverseZones; */
/* IDL: 	uint8 AutoCacheUpdate; */
/* IDL: 	uint8 RecurseAfterForwarding; */
/* IDL: 	uint8 ForwardDelegations; */
/* IDL: 	uint8 NoRecursion; */
/* IDL: 	uint8 SecureResponses; */
/* IDL: 	uint8 RoundRobin; */
/* IDL: 	uint8 LocalNetPriority; */
/* IDL: 	uint8 BindSecondaries; */
/* IDL: 	uint8 WriteAuthorityNs; */
/* IDL: 	uint8 StrictFileParsing; */
/* IDL: 	uint8 LooseWildcarding; */
/* IDL: 	uint8 DefaultAgingState; */
/* IDL: 	uint8 reserve_array2[15]; */
/* IDL: } */

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_RpcStructureVersion(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_RpcStructureVersion, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_reserved0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_reserved0, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_Version(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dnsserver_dissect_struct_DNS_RPC_VERSION(tvb,offset,pinfo,tree,drep,hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_Version,0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_BootMethod(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dnsserver_dissect_enum_DNS_RPC_BOOT_METHOD(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_BootMethod, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_AdminConfigured(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_AdminConfigured, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_AllowUpdate(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_AllowUpdate, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DsAvailable(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DsAvailable, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ServerName(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ServerName_, NDR_POINTER_UNIQUE, "Pointer to Servername (uint8)",hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_ServerName);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ServerName_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint8), hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_ServerName, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DsContainer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DsContainer_, NDR_POINTER_UNIQUE, "Pointer to Dscontainer (uint16)",hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DsContainer);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DsContainer_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DsContainer, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ServerAddrs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ServerAddrs_, NDR_POINTER_UNIQUE, "Pointer to Serveraddrs (IP4_ARRAY)",hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_ServerAddrs);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ServerAddrs_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dnsserver_dissect_struct_IP4_ARRAY(tvb,offset,pinfo,tree,drep,hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_ServerAddrs,0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ListenAddrs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ListenAddrs_, NDR_POINTER_UNIQUE, "Pointer to Listenaddrs (IP4_ARRAY)",hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_ListenAddrs);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ListenAddrs_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dnsserver_dissect_struct_IP4_ARRAY(tvb,offset,pinfo,tree,drep,hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_ListenAddrs,0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_Forwarders(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_Forwarders_, NDR_POINTER_UNIQUE, "Pointer to Forwarders (IP4_ARRAY)",hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_Forwarders);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_Forwarders_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dnsserver_dissect_struct_IP4_ARRAY(tvb,offset,pinfo,tree,drep,hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_Forwarders,0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_LogFilter(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_LogFilter_, NDR_POINTER_UNIQUE, "Pointer to Logfilter (IP4_ARRAY)",hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_LogFilter);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_LogFilter_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dnsserver_dissect_struct_IP4_ARRAY(tvb,offset,pinfo,tree,drep,hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_LogFilter,0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_LogFilePath(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_LogFilePath_, NDR_POINTER_UNIQUE, "Pointer to Logfilepath (uint16)",hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_LogFilePath);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_LogFilePath_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_LogFilePath, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DomainName(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DomainName_, NDR_POINTER_UNIQUE, "Pointer to Domainname (uint8)",hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DomainName);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DomainName_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint8), hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DomainName, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ForestName(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ForestName_, NDR_POINTER_UNIQUE, "Pointer to Forestname (uint8)",hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_ForestName);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ForestName_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint8), hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_ForestName, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DomainDirectoryPartition(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DomainDirectoryPartition_, NDR_POINTER_UNIQUE, "Pointer to Domaindirectorypartition (uint8)",hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DomainDirectoryPartition);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DomainDirectoryPartition_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint8), hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DomainDirectoryPartition, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ForestDirectoryPartition(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ForestDirectoryPartition_, NDR_POINTER_UNIQUE, "Pointer to Forestdirectorypartition (uint8)",hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_ForestDirectoryPartition);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ForestDirectoryPartition_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint8), hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_ForestDirectoryPartition, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension0_, NDR_POINTER_UNIQUE, "Pointer to Extension0 (uint8)",hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_extension0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint8), hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_extension0, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension1_, NDR_POINTER_UNIQUE, "Pointer to Extension1 (uint8)",hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_extension1);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension1_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint8), hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_extension1, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension2_, NDR_POINTER_UNIQUE, "Pointer to Extension2 (uint8)",hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_extension2);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension2_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint8), hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_extension2, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension3(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension3_, NDR_POINTER_UNIQUE, "Pointer to Extension3 (uint8)",hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_extension3);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension3_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint8), hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_extension3, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension4(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension4_, NDR_POINTER_UNIQUE, "Pointer to Extension4 (uint8)",hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_extension4);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension4_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint8), hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_extension4, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension5(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension5_, NDR_POINTER_UNIQUE, "Pointer to Extension5 (uint8)",hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_extension5);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension5_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint8), hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_extension5, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_LogLevel(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dnsserver_dissect_bitmap_DNS_LOG_LEVELS(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_LogLevel, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DebugLevel(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DebugLevel, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ForwardTimeout(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_ForwardTimeout, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_RpcProtocol(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dnsserver_dissect_bitmap_DNS_RPC_PROTOCOLS(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_RpcProtocol, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_NameCheckFlag(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dnsserver_dissect_enum_DNS_NAME_CHECK_FLAGS(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_NameCheckFlag, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_AddressAnswerLimit(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_AddressAnswerLimit, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_RecursionRetry(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_RecursionRetry, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_RecursionTimeout(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_RecursionTimeout, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_MaxCacheTtl(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_MaxCacheTtl, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DsPollingInterval(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DsPollingInterval, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_LocalNetPriorityNetmask(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_LocalNetPriorityNetmask, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ScavengingInterval(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_ScavengingInterval, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DefaultRefreshInterval(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DefaultRefreshInterval, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DefaultNoRefreshInterval(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DefaultNoRefreshInterval, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_LastScavengeTime(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_LastScavengeTime, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_EventLogLevel(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_EventLogLevel, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_LogFileMaxSize(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_LogFileMaxSize, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DsForestVersion(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DsForestVersion, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DsDomainVersion(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DsDomainVersion, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DsDsaVersion(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DsDsaVersion, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_reserve_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	int i;
	for (i = 0; i < 4; i++)
		offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_reserve_array_(tvb, offset, pinfo, tree, drep);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_reserve_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_reserve_array, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_AutoReverseZones(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_AutoReverseZones, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_AutoCacheUpdate(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_AutoCacheUpdate, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_RecurseAfterForwarding(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_RecurseAfterForwarding, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ForwardDelegations(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_ForwardDelegations, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_NoRecursion(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_NoRecursion, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_SecureResponses(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_SecureResponses, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_RoundRobin(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_RoundRobin, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_LocalNetPriority(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_LocalNetPriority, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_BindSecondaries(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_BindSecondaries, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_WriteAuthorityNs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_WriteAuthorityNs, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_StrictFileParsing(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_StrictFileParsing, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_LooseWildcarding(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_LooseWildcarding, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DefaultAgingState(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DefaultAgingState, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_reserve_array2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	int i;
	for (i = 0; i < 15; i++)
		offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_reserve_array2_(tvb, offset, pinfo, tree, drep);

	return offset;
}

static int
dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_reserve_array2_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_reserve_array2, 0);

	return offset;
}

int
dnsserver_dissect_struct_DNS_RPC_SERVER_INFO_DOTNET(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_dnsserver_DNS_RPC_SERVER_INFO_DOTNET);
	}

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_RpcStructureVersion(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_reserved0(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_Version(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_BootMethod(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_AdminConfigured(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_AllowUpdate(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DsAvailable(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ServerName(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DsContainer(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ServerAddrs(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ListenAddrs(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_Forwarders(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_LogFilter(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_LogFilePath(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DomainName(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ForestName(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DomainDirectoryPartition(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ForestDirectoryPartition(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension0(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension1(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension2(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension3(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension4(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_extension5(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_LogLevel(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DebugLevel(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ForwardTimeout(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_RpcProtocol(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_NameCheckFlag(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_AddressAnswerLimit(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_RecursionRetry(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_RecursionTimeout(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_MaxCacheTtl(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DsPollingInterval(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_LocalNetPriorityNetmask(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ScavengingInterval(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DefaultRefreshInterval(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DefaultNoRefreshInterval(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_LastScavengeTime(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_EventLogLevel(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_LogFileMaxSize(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DsForestVersion(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DsDomainVersion(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DsDsaVersion(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_reserve_array(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_AutoReverseZones(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_AutoCacheUpdate(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_RecurseAfterForwarding(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_ForwardDelegations(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_NoRecursion(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_SecureResponses(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_RoundRobin(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_LocalNetPriority(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_BindSecondaries(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_WriteAuthorityNs(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_StrictFileParsing(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_LooseWildcarding(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_DefaultAgingState(tvb, offset, pinfo, tree, drep);

	offset = dnsserver_dissect_element_DNS_RPC_SERVER_INFO_DOTNET_reserve_array2(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: enum { */
/* IDL: 	DNSSRV_TYPEID_NULL=0, */
/* IDL: 	DNSSRV_TYPEID_DWORD=1, */
/* IDL: 	DNSSRV_TYPEID_LPSTR=2, */
/* IDL: 	DNSSRV_TYPEID_LPWSTR=3, */
/* IDL: 	DNSSRV_TYPEID_IPARRAY=4, */
/* IDL: 	DNSSRV_TYPEID_BUFFER=5, */
/* IDL: 	DNSSRV_TYPEID_SERVER_INFO_W2K=6, */
/* IDL: 	DNSSRV_TYPEID_STATS=7, */
/* IDL: 	DNSSRV_TYPEID_FORWARDERS_W2K=8, */
/* IDL: 	DNSSRV_TYPEID_ZONE_W2K=9, */
/* IDL: 	DNSSRV_TYPEID_ZONE_INFO_W2K=10, */
/* IDL: 	DNSSRV_TYPEID_ZONE_SECONDARIES_W2K=11, */
/* IDL: 	DNSSRV_TYPEID_ZONE_DATABASE_W2K=12, */
/* IDL: 	DNSSRV_TYPEID_ZONE_TYPE_RESET_W2K=13, */
/* IDL: 	DNSSRV_TYPEID_ZONE_CREATE_W2K=14, */
/* IDL: 	DNSSRV_TYPEID_NAME_AND_PARAM=15, */
/* IDL: 	DNSSRV_TYPEID_ZONE_LIST_W2K=16, */
/* IDL: 	DNSSRV_TYPEID_ZONE_RENAME=17, */
/* IDL: 	DNSSRV_TYPEID_ZONE_EXPORT=18, */
/* IDL: 	DNSSRV_TYPEID_SERVER_INFO_DOTNET=19, */
/* IDL: 	DNSSRV_TYPEID_FORWARDERS_DOTNET=20, */
/* IDL: 	DNSSRV_TYPEID_ZONE=21, */
/* IDL: 	DNSSRV_TYPEID_ZONE_INFO_DOTNET=22, */
/* IDL: 	DNSSRV_TYPEID_ZONE_SECONDARIES_DOTNET=23, */
/* IDL: 	DNSSRV_TYPEID_ZONE_DATABASE=24, */
/* IDL: 	DNSSRV_TYPEID_ZONE_TYPE_RESET_DOTNET=25, */
/* IDL: 	DNSSRV_TYPEID_ZONE_CREATE_DOTNET=26, */
/* IDL: 	DNSSRV_TYPEID_ZONE_LIST=27, */
/* IDL: 	DNSSRV_TYPEID_DP_ENUM=28, */
/* IDL: 	DNSSRV_TYPEID_DP_INFO=29, */
/* IDL: 	DNSSRV_TYPEID_DP_LIST=30, */
/* IDL: 	DNSSRV_TYPEID_ENLIST_DP=31, */
/* IDL: 	DNSSRV_TYPEID_ZONE_CHANGE_DP=32, */
/* IDL: 	DNSSRV_TYPEID_ENUM_ZONES_FILTER=33, */
/* IDL: 	DNSSRV_TYPEID_ADDARRAY=34, */
/* IDL: 	DNSSRV_TYPEID_SERVER_INFO=35, */
/* IDL: 	DNSSRV_TYPEID_ZONE_INFO=36, */
/* IDL: 	DNSSRV_TYPEID_FORWARDERS=37, */
/* IDL: 	DNSSRV_TYPEID_ZONE_SECONDARIES=38, */
/* IDL: 	DNSSRV_TYPEID_ZONE_TYPE_RESET=39, */
/* IDL: 	DNSSRV_TYPEID_ZONE_CREATE=40, */
/* IDL: 	DNSSRV_TYPEID_IP_VALIDATE=41, */
/* IDL: 	DNSSRV_TYPEID_AUTOCONFIGURE=42, */
/* IDL: 	DNSSRV_TYPEID_UTF8_STRING_LIST=43, */
/* IDL: 	DNSSRV_TYPEID_UNICODE_STRING_LIST=44, */
/* IDL: } */

int
dnsserver_dissect_enum_DnssrvRpcTypeId(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_)
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


/* IDL: union { */
/* IDL: [case(DNSSRV_TYPEID_NULL)] [unique(1)] [case(DNSSRV_TYPEID_NULL)] uint8 *null; */
/* IDL: [case(DNSSRV_TYPEID_DWORD)] [case(DNSSRV_TYPEID_DWORD)] uint32 dword; */
/* IDL: [case(DNSSRV_TYPEID_SERVER_INFO_DOTNET)] [unique(1)] [case(DNSSRV_TYPEID_SERVER_INFO_DOTNET)] DNS_RPC_SERVER_INFO_DOTNET *ServerInfoDotnet; */
/* IDL: } */

static int
dnsserver_dissect_element_DNSSRV_RPC_UNION_null(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_DNSSRV_RPC_UNION_null_, NDR_POINTER_UNIQUE, "Pointer to Null (uint8)",hf_dnsserver_DNSSRV_RPC_UNION_null);

	return offset;
}

static int
dnsserver_dissect_element_DNSSRV_RPC_UNION_null_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNSSRV_RPC_UNION_null, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNSSRV_RPC_UNION_dword(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_DNSSRV_RPC_UNION_dword, 0);

	return offset;
}

static int
dnsserver_dissect_element_DNSSRV_RPC_UNION_ServerInfoDotnet(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_DNSSRV_RPC_UNION_ServerInfoDotnet_, NDR_POINTER_UNIQUE, "Pointer to Serverinfodotnet (DNS_RPC_SERVER_INFO_DOTNET)",hf_dnsserver_DNSSRV_RPC_UNION_ServerInfoDotnet);

	return offset;
}

static int
dnsserver_dissect_element_DNSSRV_RPC_UNION_ServerInfoDotnet_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dnsserver_dissect_struct_DNS_RPC_SERVER_INFO_DOTNET(tvb,offset,pinfo,tree,drep,hf_dnsserver_DNSSRV_RPC_UNION_ServerInfoDotnet,0);

	return offset;
}

static int
dnsserver_dissect_DNSSRV_RPC_UNION(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;
	guint32 level;

	old_offset = offset;
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1, "DNSSRV_RPC_UNION");
		tree = proto_item_add_subtree(item, ett_dnsserver_DNSSRV_RPC_UNION);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_index, &level);
	ALIGN_TO_4_BYTES;

	switch(level) {
		case DNSSRV_TYPEID_NULL:
			offset = dnsserver_dissect_element_DNSSRV_RPC_UNION_null(tvb, offset, pinfo, tree, drep);
		break;

		case DNSSRV_TYPEID_DWORD:
			offset = dnsserver_dissect_element_DNSSRV_RPC_UNION_dword(tvb, offset, pinfo, tree, drep);
		break;

		case DNSSRV_TYPEID_SERVER_INFO_DOTNET:
			offset = dnsserver_dissect_element_DNSSRV_RPC_UNION_ServerInfoDotnet(tvb, offset, pinfo, tree, drep);
		break;
	}
	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: struct { */
/* IDL: 	DNS_RPC_NODE rpc_node; */
/* IDL: } */

static int
dnsserver_dissect_element_DNS_RECORD_BUFFER_rpc_node(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dnsserver_dissect_struct_DNS_RPC_NODE(tvb,offset,pinfo,tree,drep,hf_dnsserver_DNS_RECORD_BUFFER_rpc_node,0);

	return offset;
}

int
dnsserver_dissect_struct_DNS_RECORD_BUFFER(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_dnsserver_DNS_RECORD_BUFFER);
	}

	offset = dnsserver_dissect_element_DNS_RECORD_BUFFER_rpc_node(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: NTSTATUS DnssrvOperation( */
/* IDL:  */
/* IDL: ); */

static int
dnsserver_dissect_DnssrvOperation_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="DnssrvOperation";
	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, hf_dnsserver_status, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
dnsserver_dissect_DnssrvOperation_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="DnssrvOperation";
	return offset;
}

/* IDL: NTSTATUS DnssrvQuery( */
/* IDL:  */
/* IDL: ); */

static int
dnsserver_dissect_DnssrvQuery_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="DnssrvQuery";
	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, hf_dnsserver_status, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
dnsserver_dissect_DnssrvQuery_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="DnssrvQuery";
	return offset;
}

/* IDL: NTSTATUS DnssrvComplexOperation( */
/* IDL:  */
/* IDL: ); */

static int
dnsserver_dissect_DnssrvComplexOperation_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="DnssrvComplexOperation";
	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, hf_dnsserver_status, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
dnsserver_dissect_DnssrvComplexOperation_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="DnssrvComplexOperation";
	return offset;
}

/* IDL: NTSTATUS DnssrvEnumRecords( */
/* IDL:  */
/* IDL: ); */

static int
dnsserver_dissect_DnssrvEnumRecords_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="DnssrvEnumRecords";
	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, hf_dnsserver_status, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
dnsserver_dissect_DnssrvEnumRecords_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="DnssrvEnumRecords";
	return offset;
}

/* IDL: NTSTATUS DnssrvUpdateRecord( */
/* IDL:  */
/* IDL: ); */

static int
dnsserver_dissect_DnssrvUpdateRecord_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="DnssrvUpdateRecord";
	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, hf_dnsserver_status, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
dnsserver_dissect_DnssrvUpdateRecord_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="DnssrvUpdateRecord";
	return offset;
}

/* IDL: NTSTATUS DnssrvOperation2( */
/* IDL:  */
/* IDL: ); */

static int
dnsserver_dissect_DnssrvOperation2_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="DnssrvOperation2";
	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, hf_dnsserver_status, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
dnsserver_dissect_DnssrvOperation2_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="DnssrvOperation2";
	return offset;
}

static int
dnsserver_dissect_element_DnssrvQuery2_client_version(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dnsserver_dissect_enum_DNS_RPC_CLIENT_VERSION(tvb, offset, pinfo, tree, drep, hf_dnsserver_DnssrvQuery2_client_version, 0);

	return offset;
}

static int
dnsserver_dissect_element_DnssrvQuery2_setting_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_DnssrvQuery2_setting_flags, 0);

	return offset;
}

static int
dnsserver_dissect_element_DnssrvQuery2_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_DnssrvQuery2_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_dnsserver_DnssrvQuery2_server_name);

	return offset;
}

static int
dnsserver_dissect_element_DnssrvQuery2_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_dnsserver_DnssrvQuery2_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
dnsserver_dissect_element_DnssrvQuery2_zone(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_DnssrvQuery2_zone_, NDR_POINTER_UNIQUE, "Pointer to Zone (uint8)",hf_dnsserver_DnssrvQuery2_zone);

	return offset;
}

static int
dnsserver_dissect_element_DnssrvQuery2_zone_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint8), hf_dnsserver_DnssrvQuery2_zone, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
dnsserver_dissect_element_DnssrvQuery2_operation(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_DnssrvQuery2_operation_, NDR_POINTER_UNIQUE, "Pointer to Operation (uint8)",hf_dnsserver_DnssrvQuery2_operation);

	return offset;
}

static int
dnsserver_dissect_element_DnssrvQuery2_operation_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint8), hf_dnsserver_DnssrvQuery2_operation, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
dnsserver_dissect_element_DnssrvQuery2_type_id(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_DnssrvQuery2_type_id_, NDR_POINTER_REF, "Pointer to Type Id (DnssrvRpcTypeId)",hf_dnsserver_DnssrvQuery2_type_id);

	return offset;
}

static int
dnsserver_dissect_element_DnssrvQuery2_type_id_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dnsserver_dissect_enum_DnssrvRpcTypeId(tvb, offset, pinfo, tree, drep, hf_dnsserver_DnssrvQuery2_type_id, 0);

	return offset;
}

static int
dnsserver_dissect_element_DnssrvQuery2_data(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_DnssrvQuery2_data_, NDR_POINTER_REF, "Pointer to Data (DNSSRV_RPC_UNION)",hf_dnsserver_DnssrvQuery2_data);

	return offset;
}

static int
dnsserver_dissect_element_DnssrvQuery2_data_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dnsserver_dissect_DNSSRV_RPC_UNION(tvb, offset, pinfo, tree, drep, hf_dnsserver_DnssrvQuery2_data, 0);

	return offset;
}

/* IDL: NTSTATUS DnssrvQuery2( */
/* IDL: [in] DNS_RPC_CLIENT_VERSION client_version, */
/* IDL: [in] uint32 setting_flags, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_name, */
/* IDL: [unique(1)] [in] uint8 *zone, */
/* IDL: [unique(1)] [in] uint8 *operation, */
/* IDL: [out] [ref] DnssrvRpcTypeId *type_id, */
/* IDL: [out] [ref] [switch_is(*type_id)] DNSSRV_RPC_UNION *data */
/* IDL: ); */

static int
dnsserver_dissect_DnssrvQuery2_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="DnssrvQuery2";
	offset = dnsserver_dissect_element_DnssrvQuery2_type_id(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dnsserver_dissect_element_DnssrvQuery2_data(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, hf_dnsserver_status, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
dnsserver_dissect_DnssrvQuery2_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="DnssrvQuery2";
	offset = dnsserver_dissect_element_DnssrvQuery2_client_version(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = dnsserver_dissect_element_DnssrvQuery2_setting_flags(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = dnsserver_dissect_element_DnssrvQuery2_server_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = dnsserver_dissect_element_DnssrvQuery2_zone(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = dnsserver_dissect_element_DnssrvQuery2_operation(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

/* IDL: NTSTATUS DnssrvComplexOperation2( */
/* IDL:  */
/* IDL: ); */

static int
dnsserver_dissect_DnssrvComplexOperation2_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="DnssrvComplexOperation2";
	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, hf_dnsserver_status, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
dnsserver_dissect_DnssrvComplexOperation2_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="DnssrvComplexOperation2";
	return offset;
}

static int
dnsserver_dissect_element_DnssrvEnumRecords2_client_version(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dnsserver_dissect_enum_DNS_RPC_CLIENT_VERSION(tvb, offset, pinfo, tree, drep, hf_dnsserver_DnssrvEnumRecords2_client_version, 0);

	return offset;
}

static int
dnsserver_dissect_element_DnssrvEnumRecords2_setting_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_DnssrvEnumRecords2_setting_flags, 0);

	return offset;
}

static int
dnsserver_dissect_element_DnssrvEnumRecords2_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_DnssrvEnumRecords2_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_dnsserver_DnssrvEnumRecords2_server_name);

	return offset;
}

static int
dnsserver_dissect_element_DnssrvEnumRecords2_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_dnsserver_DnssrvEnumRecords2_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
dnsserver_dissect_element_DnssrvEnumRecords2_zone(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_DnssrvEnumRecords2_zone_, NDR_POINTER_UNIQUE, "Pointer to Zone (uint8)",hf_dnsserver_DnssrvEnumRecords2_zone);

	return offset;
}

static int
dnsserver_dissect_element_DnssrvEnumRecords2_zone_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint8), hf_dnsserver_DnssrvEnumRecords2_zone, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
dnsserver_dissect_element_DnssrvEnumRecords2_node_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_DnssrvEnumRecords2_node_name_, NDR_POINTER_UNIQUE, "Pointer to Node Name (uint8)",hf_dnsserver_DnssrvEnumRecords2_node_name);

	return offset;
}

static int
dnsserver_dissect_element_DnssrvEnumRecords2_node_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint8), hf_dnsserver_DnssrvEnumRecords2_node_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
dnsserver_dissect_element_DnssrvEnumRecords2_start_child(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_DnssrvEnumRecords2_start_child_, NDR_POINTER_UNIQUE, "Pointer to Start Child (uint8)",hf_dnsserver_DnssrvEnumRecords2_start_child);

	return offset;
}

static int
dnsserver_dissect_element_DnssrvEnumRecords2_start_child_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint8), hf_dnsserver_DnssrvEnumRecords2_start_child, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
dnsserver_dissect_element_DnssrvEnumRecords2_record_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dnsserver_dissect_enum_DNS_RECORD_TYPE(tvb, offset, pinfo, tree, drep, hf_dnsserver_DnssrvEnumRecords2_record_type, 0);

	return offset;
}

static int
dnsserver_dissect_element_DnssrvEnumRecords2_select_flag(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dnsserver_dissect_bitmap_DNS_SELECT_FLAGS(tvb, offset, pinfo, tree, drep, hf_dnsserver_DnssrvEnumRecords2_select_flag, 0);

	return offset;
}

static int
dnsserver_dissect_element_DnssrvEnumRecords2_filter_start(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_DnssrvEnumRecords2_filter_start_, NDR_POINTER_UNIQUE, "Pointer to Filter Start (uint8)",hf_dnsserver_DnssrvEnumRecords2_filter_start);

	return offset;
}

static int
dnsserver_dissect_element_DnssrvEnumRecords2_filter_start_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint8), hf_dnsserver_DnssrvEnumRecords2_filter_start, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
dnsserver_dissect_element_DnssrvEnumRecords2_filter_stop(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_DnssrvEnumRecords2_filter_stop_, NDR_POINTER_UNIQUE, "Pointer to Filter Stop (uint8)",hf_dnsserver_DnssrvEnumRecords2_filter_stop);

	return offset;
}

static int
dnsserver_dissect_element_DnssrvEnumRecords2_filter_stop_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint8), hf_dnsserver_DnssrvEnumRecords2_filter_stop, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
dnsserver_dissect_element_DnssrvEnumRecords2_buffer_length(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_DnssrvEnumRecords2_buffer_length_, NDR_POINTER_REF, "Pointer to Buffer Length (uint32)",hf_dnsserver_DnssrvEnumRecords2_buffer_length);

	return offset;
}

static int
dnsserver_dissect_element_DnssrvEnumRecords2_buffer_length_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_DnssrvEnumRecords2_buffer_length, 0);

	return offset;
}

static int
dnsserver_dissect_element_DnssrvEnumRecords2_record_buffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, dnsserver_dissect_element_DnssrvEnumRecords2_record_buffer_, NDR_POINTER_UNIQUE, "Pointer to Record Buffer (DNS_RPC_NODE)",hf_dnsserver_DnssrvEnumRecords2_record_buffer);

	return offset;
}

static int
dnsserver_dissect_element_DnssrvEnumRecords2_record_buffer_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 size;
	int start_offset = offset;
	tvbuff_t *subtvb;
	dcerpc_info *di = pinfo->private_data;
	if(di->conformant_run)return offset;
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_dnsserver_DnssrvEnumRecords2_record_buffer, &size);
	proto_tree_add_text(tree, tvb, start_offset, offset, "Subcontext size: %d", size);
	subtvb = tvb_new_subset(tvb, offset, size, -1);
	dnsserver_dissect_element_DnssrvEnumRecords2_record_buffer__(subtvb, 0, pinfo, tree, drep);
	offset = start_offset + size + 4;

	return offset;
}

static int
dnsserver_dissect_element_DnssrvEnumRecords2_record_buffer__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dnsserver_dissect_struct_DNS_RPC_NODE(tvb,offset,pinfo,tree,drep,hf_dnsserver_DnssrvEnumRecords2_record_buffer,0);

	return offset;
}

/* IDL: NTSTATUS DnssrvEnumRecords2( */
/* IDL: [in] DNS_RPC_CLIENT_VERSION client_version, */
/* IDL: [in] uint32 setting_flags, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_name, */
/* IDL: [unique(1)] [in] uint8 *zone, */
/* IDL: [unique(1)] [in] uint8 *node_name, */
/* IDL: [unique(1)] [in] uint8 *start_child, */
/* IDL: [in] DNS_RECORD_TYPE record_type, */
/* IDL: [in] DNS_SELECT_FLAGS select_flag, */
/* IDL: [unique(1)] [in] uint8 *filter_start, */
/* IDL: [unique(1)] [in] uint8 *filter_stop, */
/* IDL: [out] [ref] uint32 *buffer_length, */
/* IDL: [unique(1)] [out] [subcontext(4)] DNS_RPC_NODE *record_buffer */
/* IDL: ); */

static int
dnsserver_dissect_DnssrvEnumRecords2_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="DnssrvEnumRecords2";
	offset = dnsserver_dissect_element_DnssrvEnumRecords2_buffer_length(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dnsserver_dissect_element_DnssrvEnumRecords2_record_buffer(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, hf_dnsserver_status, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
dnsserver_dissect_DnssrvEnumRecords2_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="DnssrvEnumRecords2";
	offset = dnsserver_dissect_element_DnssrvEnumRecords2_client_version(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = dnsserver_dissect_element_DnssrvEnumRecords2_setting_flags(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = dnsserver_dissect_element_DnssrvEnumRecords2_server_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = dnsserver_dissect_element_DnssrvEnumRecords2_zone(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = dnsserver_dissect_element_DnssrvEnumRecords2_node_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = dnsserver_dissect_element_DnssrvEnumRecords2_start_child(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = dnsserver_dissect_element_DnssrvEnumRecords2_record_type(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = dnsserver_dissect_element_DnssrvEnumRecords2_select_flag(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = dnsserver_dissect_element_DnssrvEnumRecords2_filter_start(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = dnsserver_dissect_element_DnssrvEnumRecords2_filter_stop(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

/* IDL: NTSTATUS DnssrvUpdateRecord2( */
/* IDL:  */
/* IDL: ); */

static int
dnsserver_dissect_DnssrvUpdateRecord2_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="DnssrvUpdateRecord2";
	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, hf_dnsserver_status, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
dnsserver_dissect_DnssrvUpdateRecord2_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="DnssrvUpdateRecord2";
	return offset;
}


static dcerpc_sub_dissector dnsserver_dissectors[] = {
	{ 0, "DnssrvOperation",
	   dnsserver_dissect_DnssrvOperation_request, dnsserver_dissect_DnssrvOperation_response},
	{ 1, "DnssrvQuery",
	   dnsserver_dissect_DnssrvQuery_request, dnsserver_dissect_DnssrvQuery_response},
	{ 2, "DnssrvComplexOperation",
	   dnsserver_dissect_DnssrvComplexOperation_request, dnsserver_dissect_DnssrvComplexOperation_response},
	{ 3, "DnssrvEnumRecords",
	   dnsserver_dissect_DnssrvEnumRecords_request, dnsserver_dissect_DnssrvEnumRecords_response},
	{ 4, "DnssrvUpdateRecord",
	   dnsserver_dissect_DnssrvUpdateRecord_request, dnsserver_dissect_DnssrvUpdateRecord_response},
	{ 5, "DnssrvOperation2",
	   dnsserver_dissect_DnssrvOperation2_request, dnsserver_dissect_DnssrvOperation2_response},
	{ 6, "DnssrvQuery2",
	   dnsserver_dissect_DnssrvQuery2_request, dnsserver_dissect_DnssrvQuery2_response},
	{ 7, "DnssrvComplexOperation2",
	   dnsserver_dissect_DnssrvComplexOperation2_request, dnsserver_dissect_DnssrvComplexOperation2_response},
	{ 8, "DnssrvEnumRecords2",
	   dnsserver_dissect_DnssrvEnumRecords2_request, dnsserver_dissect_DnssrvEnumRecords2_response},
	{ 9, "DnssrvUpdateRecord2",
	   dnsserver_dissect_DnssrvUpdateRecord2_request, dnsserver_dissect_DnssrvUpdateRecord2_response},
	{ 0, NULL, NULL, NULL }
};

void proto_register_dcerpc_dnsserver(void)
{
	static hf_register_info hf[] = {
	{ &hf_dnsserver_DnssrvEnumRecords2_start_child,
	  { "Start Child", "dnsserver.DnssrvEnumRecords2.start_child", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_LocalNetPriority,
	  { "Localnetpriority", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.LocalNetPriority", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_AGING_ON,
	  { "Dns Rpc Flag Aging On", "dnsserver.DNS_RPC_NODE_FLAGS.DNS_RPC_FLAG_AGING_ON", FT_BOOLEAN, 32, TFS(&DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_AGING_ON_tfs), ( 0x00020000 ), NULL, HFILL }},
	{ &hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_WRITE_THROUGH,
	  { "Dns Log Level Write Through", "dnsserver.DNS_LOG_LEVELS.DNS_LOG_LEVEL_WRITE_THROUGH", FT_BOOLEAN, 32, TFS(&DNS_LOG_LEVELS_DNS_LOG_LEVEL_WRITE_THROUGH_tfs), ( 0x80000000 ), NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_reserved0,
	  { "Reserved0", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.reserved0", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DefaultNoRefreshInterval,
	  { "Defaultnorefreshinterval", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.DefaultNoRefreshInterval", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_LogFilter,
	  { "Logfilter", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.LogFilter", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_ANSWERS,
	  { "Dns Log Level Answers", "dnsserver.DNS_LOG_LEVELS.DNS_LOG_LEVEL_ANSWERS", FT_BOOLEAN, 32, TFS(&DNS_LOG_LEVELS_DNS_LOG_LEVEL_ANSWERS_tfs), ( 0x00000200 ), NULL, HFILL }},
	{ &hf_dnsserver_DNS_SELECT_FLAGS_DNS_RPC_VIEW_ONLY_CHILDREN,
	  { "Dns Rpc View Only Children", "dnsserver.DNS_SELECT_FLAGS.DNS_RPC_VIEW_ONLY_CHILDREN", FT_BOOLEAN, 32, TFS(&DNS_SELECT_FLAGS_DNS_RPC_VIEW_ONLY_CHILDREN_tfs), ( 0x00020000 ), NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_BootMethod,
	  { "Bootmethod", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.BootMethod", FT_UINT8, BASE_DEC, VALS(dnsserver_DNS_RPC_BOOT_METHOD_vals), 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_SELECT_FLAGS_DNS_RPC_VIEW_AUTHORITY_DATA,
	  { "Dns Rpc View Authority Data", "dnsserver.DNS_SELECT_FLAGS.DNS_RPC_VIEW_AUTHORITY_DATA", FT_BOOLEAN, 32, TFS(&DNS_SELECT_FLAGS_DNS_RPC_VIEW_AUTHORITY_DATA_tfs), ( 0x00000001 ), NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_extension1,
	  { "Extension1", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.extension1", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_ListenAddrs,
	  { "Listenaddrs", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.ListenAddrs", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_QUESTIONS,
	  { "Dns Log Level Questions", "dnsserver.DNS_LOG_LEVELS.DNS_LOG_LEVEL_QUESTIONS", FT_BOOLEAN, 32, TFS(&DNS_LOG_LEVELS_DNS_LOG_LEVEL_QUESTIONS_tfs), ( 0x00000100 ), NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_NODE_COMPLETE,
	  { "Dns Rpc Flag Node Complete", "dnsserver.DNS_RPC_NODE_FLAGS.DNS_RPC_FLAG_NODE_COMPLETE", FT_BOOLEAN, 32, TFS(&DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_NODE_COMPLETE_tfs), ( 0x00800000 ), NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_Forwarders,
	  { "Forwarders", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.Forwarders", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DnssrvQuery2_server_name,
	  { "Server Name", "dnsserver.DnssrvQuery2.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_NODE_STICKY,
	  { "Dns Rpc Flag Node Sticky", "dnsserver.DNS_RPC_NODE_FLAGS.DNS_RPC_FLAG_NODE_STICKY", FT_BOOLEAN, 32, TFS(&DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_NODE_STICKY_tfs), ( 0x01000000 ), NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_WriteAuthorityNs,
	  { "Writeauthorityns", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.WriteAuthorityNs", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_AutoCacheUpdate,
	  { "Autocacheupdate", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.AutoCacheUpdate", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_status,
	  { "NT Error", "dnsserver.status", FT_UINT32, BASE_HEX, VALS(NT_errors), 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_RECORD_DataLength,
	  { "Datalength", "dnsserver.DNS_RPC_RECORD.DataLength", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_AdminConfigured,
	  { "Adminconfigured", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.AdminConfigured", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_RECV,
	  { "Dns Log Level Recv", "dnsserver.DNS_LOG_LEVELS.DNS_LOG_LEVEL_RECV", FT_BOOLEAN, 32, TFS(&DNS_LOG_LEVELS_DNS_LOG_LEVEL_RECV_tfs), ( 0x00002000 ), NULL, HFILL }},
	{ &hf_dnsserver_DnssrvEnumRecords2_buffer_length,
	  { "Buffer Length", "dnsserver.DnssrvEnumRecords2.buffer_length", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_extension3,
	  { "Extension3", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.extension3", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_PROTOCOLS_DNS_RPC_USE_LPC,
	  { "Dns Rpc Use Lpc", "dnsserver.DNS_RPC_PROTOCOLS.DNS_RPC_USE_LPC", FT_BOOLEAN, 32, TFS(&DNS_RPC_PROTOCOLS_DNS_RPC_USE_LPC_tfs), ( 0x00000004 ), NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_NAME_name,
	  { "Name", "dnsserver.DNS_RPC_NAME.name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_RECORD_CREATE_PTR,
	  { "Dns Rpc Flag Record Create Ptr", "dnsserver.DNS_RPC_NODE_FLAGS.DNS_RPC_FLAG_RECORD_CREATE_PTR", FT_BOOLEAN, 32, TFS(&DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_RECORD_CREATE_PTR_tfs), ( 0x02000000 ), NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_RpcProtocol,
	  { "Rpcprotocol", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.RpcProtocol", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_NODE_Childcount,
	  { "Childcount", "dnsserver.DNS_RPC_NODE.Childcount", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_RpcStructureVersion,
	  { "Rpcstructureversion", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.RpcStructureVersion", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DefaultAgingState,
	  { "Defaultagingstate", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.DefaultAgingState", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DsDsaVersion,
	  { "Dsdsaversion", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.DsDsaVersion", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_extension0,
	  { "Extension0", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.extension0", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_RoundRobin,
	  { "Roundrobin", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.RoundRobin", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_BindSecondaries,
	  { "Bindsecondaries", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.BindSecondaries", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_extension5,
	  { "Extension5", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.extension5", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_AutoReverseZones,
	  { "Autoreversezones", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.AutoReverseZones", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DnssrvQuery2_data,
	  { "Data", "dnsserver.DnssrvQuery2.data", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNSSRV_RPC_UNION_dword,
	  { "Dword", "dnsserver.DNSSRV_RPC_UNION.dword", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_VERSION_OSMajorVersion,
	  { "Osmajorversion", "dnsserver.DNS_RPC_VERSION.OSMajorVersion", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DsDomainVersion,
	  { "Dsdomainversion", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.DsDomainVersion", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_ZONE_DELEGATION,
	  { "Dns Rpc Flag Zone Delegation", "dnsserver.DNS_RPC_NODE_FLAGS.DNS_RPC_FLAG_ZONE_DELEGATION", FT_BOOLEAN, 32, TFS(&DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_ZONE_DELEGATION_tfs), ( 0x10000000 ), NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_RecursionTimeout,
	  { "Recursiontimeout", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.RecursionTimeout", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_UPDATE,
	  { "Dns Log Level Update", "dnsserver.DNS_LOG_LEVELS.DNS_LOG_LEVEL_UPDATE", FT_BOOLEAN, 32, TFS(&DNS_LOG_LEVELS_DNS_LOG_LEVEL_UPDATE_tfs), ( 0x00000020 ), NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_LooseWildcarding,
	  { "Loosewildcarding", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.LooseWildcarding", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DsContainer,
	  { "Dscontainer", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.DsContainer", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DnssrvQuery2_client_version,
	  { "Client Version", "dnsserver.DnssrvQuery2.client_version", FT_UINT32, BASE_DEC, VALS(dnsserver_DNS_RPC_CLIENT_VERSION_vals), 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_SELECT_FLAGS_DNS_RPC_VIEW_ADDITIONAL_DATA,
	  { "Dns Rpc View Additional Data", "dnsserver.DNS_SELECT_FLAGS.DNS_RPC_VIEW_ADDITIONAL_DATA", FT_BOOLEAN, 32, TFS(&DNS_SELECT_FLAGS_DNS_RPC_VIEW_ADDITIONAL_DATA_tfs), ( 0x00000010 ), NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_NODE_records,
	  { "Records", "dnsserver.DNS_RPC_NODE.records", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_RECORD_NODE_NAME_Name,
	  { "Name", "dnsserver.DNS_RPC_RECORD_NODE_NAME.Name", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_RECORD_TimeStamp,
	  { "Timestamp", "dnsserver.DNS_RPC_RECORD.TimeStamp", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_RECORD_TtlSeconds,
	  { "Ttlseconds", "dnsserver.DNS_RPC_RECORD.TtlSeconds", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_VERSION_OSMinorVersion,
	  { "Osminorversion", "dnsserver.DNS_RPC_VERSION.OSMinorVersion", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_NameCheckFlag,
	  { "Namecheckflag", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.NameCheckFlag", FT_UINT32, BASE_DEC, VALS(dnsserver_DNS_NAME_CHECK_FLAGS_vals), 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DomainName,
	  { "Domainname", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.DomainName", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_AUTH_ZONE_ROOT,
	  { "Dns Rpc Flag Auth Zone Root", "dnsserver.DNS_RPC_NODE_FLAGS.DNS_RPC_FLAG_AUTH_ZONE_ROOT", FT_BOOLEAN, 32, TFS(&DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_AUTH_ZONE_ROOT_tfs), ( 0x20000000 ), NULL, HFILL }},
	{ &hf_dnsserver_DnssrvEnumRecords2_filter_stop,
	  { "Filter Stop", "dnsserver.DnssrvEnumRecords2.filter_stop", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DnssrvEnumRecords2_setting_flags,
	  { "Setting Flags", "dnsserver.DnssrvEnumRecords2.setting_flags", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_SEND,
	  { "Dns Log Level Send", "dnsserver.DNS_LOG_LEVELS.DNS_LOG_LEVEL_SEND", FT_BOOLEAN, 32, TFS(&DNS_LOG_LEVELS_DNS_LOG_LEVEL_SEND_tfs), ( 0x00001000 ), NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DomainDirectoryPartition,
	  { "Domaindirectorypartition", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.DomainDirectoryPartition", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_NoRecursion,
	  { "Norecursion", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.NoRecursion", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DnssrvEnumRecords2_client_version,
	  { "Client Version", "dnsserver.DnssrvEnumRecords2.client_version", FT_UINT32, BASE_DEC, VALS(dnsserver_DNS_RPC_CLIENT_VERSION_vals), 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_ServerAddrs,
	  { "Serveraddrs", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.ServerAddrs", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DnssrvEnumRecords2_select_flag,
	  { "Select Flag", "dnsserver.DnssrvEnumRecords2.select_flag", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_LogFilePath,
	  { "Logfilepath", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.LogFilePath", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_PROTOCOLS_DNS_RPC_USE_NAMED_PIPE,
	  { "Dns Rpc Use Named Pipe", "dnsserver.DNS_RPC_PROTOCOLS.DNS_RPC_USE_NAMED_PIPE", FT_BOOLEAN, 32, TFS(&DNS_RPC_PROTOCOLS_DNS_RPC_USE_NAMED_PIPE_tfs), ( 0x00000002 ), NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_NODE_NodeName,
	  { "Nodename", "dnsserver.DNS_RPC_NODE.NodeName", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_SELECT_FLAGS_DNS_RPC_VIEW_NO_CHILDREN,
	  { "Dns Rpc View No Children", "dnsserver.DNS_SELECT_FLAGS.DNS_RPC_VIEW_NO_CHILDREN", FT_BOOLEAN, 32, TFS(&DNS_SELECT_FLAGS_DNS_RPC_VIEW_NO_CHILDREN_tfs), ( 0x00010000 ), NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_extension4,
	  { "Extension4", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.extension4", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_IP4_ARRAY_AddrCount,
	  { "Addrcount", "dnsserver.IP4_ARRAY.AddrCount", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_ForestName,
	  { "Forestname", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.ForestName", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DnssrvEnumRecords2_record_type,
	  { "Record Type", "dnsserver.DnssrvEnumRecords2.record_type", FT_UINT16, BASE_DEC, VALS(dnsserver_DNS_RECORD_TYPE_vals), 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_NOTIFY,
	  { "Dns Log Level Notify", "dnsserver.DNS_LOG_LEVELS.DNS_LOG_LEVEL_NOTIFY", FT_BOOLEAN, 32, TFS(&DNS_LOG_LEVELS_DNS_LOG_LEVEL_NOTIFY_tfs), ( 0x00000010 ), NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_RECORD_Flags,
	  { "Flags", "dnsserver.DNS_RPC_RECORD.Flags", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DnssrvEnumRecords2_server_name,
	  { "Server Name", "dnsserver.DnssrvEnumRecords2.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DnssrvEnumRecords2_record_buffer,
	  { "Record Buffer", "dnsserver.DnssrvEnumRecords2.record_buffer", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DnssrvEnumRecords2_node_name,
	  { "Node Name", "dnsserver.DnssrvEnumRecords2.node_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RECORD_BUFFER_rpc_node,
	  { "Rpc Node", "dnsserver.DNS_RECORD_BUFFER.rpc_node", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_LastScavengeTime,
	  { "Lastscavengetime", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.LastScavengeTime", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_NODE_Length,
	  { "Length", "dnsserver.DNS_RPC_NODE.Length", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DnssrvEnumRecords2_filter_start,
	  { "Filter Start", "dnsserver.DnssrvEnumRecords2.filter_start", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_ForestDirectoryPartition,
	  { "Forestdirectorypartition", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.ForestDirectoryPartition", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DnssrvEnumRecords2_zone,
	  { "Zone", "dnsserver.DnssrvEnumRecords2.zone", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_reserve_array,
	  { "Reserve Array", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.reserve_array", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_RECORD_TTL_CHANGE,
	  { "Dns Rpc Flag Record Ttl Change", "dnsserver.DNS_RPC_NODE_FLAGS.DNS_RPC_FLAG_RECORD_TTL_CHANGE", FT_BOOLEAN, 32, TFS(&DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_RECORD_TTL_CHANGE_tfs), ( 0x04000000 ), NULL, HFILL }},
	{ &hf_dnsserver_DNS_SELECT_FLAGS_DNS_RPC_VIEW_CACHE_DATA,
	  { "Dns Rpc View Cache Data", "dnsserver.DNS_SELECT_FLAGS.DNS_RPC_VIEW_CACHE_DATA", FT_BOOLEAN, 32, TFS(&DNS_SELECT_FLAGS_DNS_RPC_VIEW_CACHE_DATA_tfs), ( 0x00000002 ), NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_ForwardTimeout,
	  { "Forwardtimeout", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.ForwardTimeout", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_reserve_array2,
	  { "Reserve Array2", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.reserve_array2", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_extension2,
	  { "Extension2", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.extension2", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_RECORD_UNION_NodeName,
	  { "Nodename", "dnsserver.DNS_RPC_RECORD_UNION.NodeName", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_FULL_PACKETS,
	  { "Dns Log Level Full Packets", "dnsserver.DNS_LOG_LEVELS.DNS_LOG_LEVEL_FULL_PACKETS", FT_BOOLEAN, 32, TFS(&DNS_LOG_LEVELS_DNS_LOG_LEVEL_FULL_PACKETS_tfs), ( 0x01000000 ), NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_RecursionRetry,
	  { "Recursionretry", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.RecursionRetry", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DnssrvQuery2_zone,
	  { "Zone", "dnsserver.DnssrvQuery2.zone", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DefaultRefreshInterval,
	  { "Defaultrefreshinterval", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.DefaultRefreshInterval", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_ZONE_ROOT,
	  { "Dns Rpc Flag Zone Root", "dnsserver.DNS_RPC_NODE_FLAGS.DNS_RPC_FLAG_ZONE_ROOT", FT_BOOLEAN, 32, TFS(&DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_ZONE_ROOT_tfs), ( 0x40000000 ), NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_StrictFileParsing,
	  { "Strictfileparsing", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.StrictFileParsing", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_SELECT_FLAGS_DNS_RPC_VIEW_ROOT_HINT_DATA,
	  { "Dns Rpc View Root Hint Data", "dnsserver.DNS_SELECT_FLAGS.DNS_RPC_VIEW_ROOT_HINT_DATA", FT_BOOLEAN, 32, TFS(&DNS_SELECT_FLAGS_DNS_RPC_VIEW_ROOT_HINT_DATA_tfs), ( 0x00000008 ), NULL, HFILL }},
	{ &hf_dnsserver_DNS_SELECT_FLAGS_DNS_RPC_VIEW_GLUE_DATA,
	  { "Dns Rpc View Glue Data", "dnsserver.DNS_SELECT_FLAGS.DNS_RPC_VIEW_GLUE_DATA", FT_BOOLEAN, 32, TFS(&DNS_SELECT_FLAGS_DNS_RPC_VIEW_GLUE_DATA_tfs), ( 0x00000004 ), NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DsForestVersion,
	  { "Dsforestversion", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.DsForestVersion", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNSSRV_RPC_UNION_ServerInfoDotnet,
	  { "Serverinfodotnet", "dnsserver.DNSSRV_RPC_UNION.ServerInfoDotnet", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_LogFileMaxSize,
	  { "Logfilemaxsize", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.LogFileMaxSize", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_MaxCacheTtl,
	  { "Maxcachettl", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.MaxCacheTtl", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_RECORD_record,
	  { "Record", "dnsserver.DNS_RPC_RECORD.record", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_ScavengingInterval,
	  { "Scavenginginterval", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.ScavengingInterval", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_RecurseAfterForwarding,
	  { "Recurseafterforwarding", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.RecurseAfterForwarding", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_SUPPRESS_NOTIFY,
	  { "Dns Rpc Flag Suppress Notify", "dnsserver.DNS_RPC_NODE_FLAGS.DNS_RPC_FLAG_SUPPRESS_NOTIFY", FT_BOOLEAN, 32, TFS(&DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_SUPPRESS_NOTIFY_tfs), ( 0x00010000 ), NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_Version,
	  { "Version", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.Version", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DnssrvQuery2_setting_flags,
	  { "Setting Flags", "dnsserver.DnssrvQuery2.setting_flags", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_RECORD_reserved,
	  { "Reserved", "dnsserver.DNS_RPC_RECORD.reserved", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_CACHE_DATA,
	  { "Dns Rpc Flag Cache Data", "dnsserver.DNS_RPC_NODE_FLAGS.DNS_RPC_FLAG_CACHE_DATA", FT_BOOLEAN, 32, TFS(&DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_CACHE_DATA_tfs), ( 0x80000000 ), NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_ServerName,
	  { "Servername", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.ServerName", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_AddressAnswerLimit,
	  { "Addressanswerlimit", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.AddressAnswerLimit", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_AllowUpdate,
	  { "Allowupdate", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.AllowUpdate", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_PROTOCOLS_DNS_RPC_USE_TCPIP,
	  { "Dns Rpc Use Tcpip", "dnsserver.DNS_RPC_PROTOCOLS.DNS_RPC_USE_TCPIP", FT_BOOLEAN, 32, TFS(&DNS_RPC_PROTOCOLS_DNS_RPC_USE_TCPIP_tfs), ( 0x00000001 ), NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_SecureResponses,
	  { "Secureresponses", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.SecureResponses", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_IP4_ARRAY_AddrArray,
	  { "Addrarray", "dnsserver.IP4_ARRAY.AddrArray", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_VERSION_ServicePackVersion,
	  { "Servicepackversion", "dnsserver.DNS_RPC_VERSION.ServicePackVersion", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DebugLevel,
	  { "Debuglevel", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.DebugLevel", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_RECORD_Type,
	  { "Type", "dnsserver.DNS_RPC_RECORD.Type", FT_UINT16, BASE_DEC, VALS(dnsserver_DNS_RECORD_TYPE_vals), 0, NULL, HFILL }},
	{ &hf_dnsserver_DNSSRV_RPC_UNION_null,
	  { "Null", "dnsserver.DNSSRV_RPC_UNION.null", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_NAME_Name,
	  { "Name", "dnsserver.DNS_RPC_NAME.Name", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_LogLevel,
	  { "Loglevel", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.LogLevel", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_NODE_RecordCount,
	  { "Recordcount", "dnsserver.DNS_RPC_NODE.RecordCount", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_NODE_Flags,
	  { "Flags", "dnsserver.DNS_RPC_NODE.Flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_QUERY,
	  { "Dns Log Level Query", "dnsserver.DNS_LOG_LEVELS.DNS_LOG_LEVEL_QUERY", FT_BOOLEAN, 32, TFS(&DNS_LOG_LEVELS_DNS_LOG_LEVEL_QUERY_tfs), ( 0x00000001 ), NULL, HFILL }},
	{ &hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_UDP,
	  { "Dns Log Level Udp", "dnsserver.DNS_LOG_LEVELS.DNS_LOG_LEVEL_UDP", FT_BOOLEAN, 32, TFS(&DNS_LOG_LEVELS_DNS_LOG_LEVEL_UDP_tfs), ( 0x00004000 ), NULL, HFILL }},
	{ &hf_dnsserver_DNS_LOG_LEVELS_DNS_LOG_LEVEL_TCP,
	  { "Dns Log Level Tcp", "dnsserver.DNS_LOG_LEVELS.DNS_LOG_LEVEL_TCP", FT_BOOLEAN, 32, TFS(&DNS_LOG_LEVELS_DNS_LOG_LEVEL_TCP_tfs), ( 0x00008000 ), NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DsPollingInterval,
	  { "Dspollinginterval", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.DsPollingInterval", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_opnum,
	  { "Operation", "dnsserver.opnum", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_DsAvailable,
	  { "Dsavailable", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.DsAvailable", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_ForwardDelegations,
	  { "Forwarddelegations", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.ForwardDelegations", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_RECORD_Serial,
	  { "Serial", "dnsserver.DNS_RPC_RECORD.Serial", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DnssrvQuery2_operation,
	  { "Operation", "dnsserver.DnssrvQuery2.operation", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DnssrvQuery2_type_id,
	  { "Type Id", "dnsserver.DnssrvQuery2.type_id", FT_UINT32, BASE_DEC, VALS(dnsserver_DnssrvRpcTypeId_vals), 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_NAME_NameLength,
	  { "Namelength", "dnsserver.DNS_RPC_NAME.NameLength", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_OPEN_ACL,
	  { "Dns Rpc Flag Open Acl", "dnsserver.DNS_RPC_NODE_FLAGS.DNS_RPC_FLAG_OPEN_ACL", FT_BOOLEAN, 32, TFS(&DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_OPEN_ACL_tfs), ( 0x00040000 ), NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_RECOR_DEFAULT_TTL,
	  { "Dns Rpc Flag Recor Default Ttl", "dnsserver.DNS_RPC_NODE_FLAGS.DNS_RPC_FLAG_RECOR_DEFAULT_TTL", FT_BOOLEAN, 32, TFS(&DNS_RPC_NODE_FLAGS_DNS_RPC_FLAG_RECOR_DEFAULT_TTL_tfs), ( 0x08000000 ), NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_EventLogLevel,
	  { "Eventloglevel", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.EventLogLevel", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_dnsserver_DNS_RPC_SERVER_INFO_DOTNET_LocalNetPriorityNetmask,
	  { "Localnetprioritynetmask", "dnsserver.DNS_RPC_SERVER_INFO_DOTNET.LocalNetPriorityNetmask", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	};


	static gint *ett[] = {
		&ett_dcerpc_dnsserver,
		&ett_dnsserver_DNS_RPC_VERSION,
		&ett_dnsserver_DNS_LOG_LEVELS,
		&ett_dnsserver_DNS_RPC_PROTOCOLS,
		&ett_dnsserver_DNS_SELECT_FLAGS,
		&ett_dnsserver_DNS_RPC_NODE_FLAGS,
		&ett_dnsserver_DNS_RPC_NAME,
		&ett_dnsserver_DNS_RPC_RECORD_NODE_NAME,
		&ett_dnsserver_DNS_RPC_RECORD_UNION,
		&ett_dnsserver_DNS_RPC_RECORD,
		&ett_dnsserver_DNS_RPC_NODE,
		&ett_dnsserver_IP4_ARRAY,
		&ett_dnsserver_DNS_RPC_SERVER_INFO_DOTNET,
		&ett_dnsserver_DNSSRV_RPC_UNION,
		&ett_dnsserver_DNS_RECORD_BUFFER,
	};

	proto_dcerpc_dnsserver = proto_register_protocol("DNS Server", "DNSSERVER", "dnsserver");
	proto_register_field_array(proto_dcerpc_dnsserver, hf, array_length (hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_dcerpc_dnsserver(void)
{
	dcerpc_init_uuid(proto_dcerpc_dnsserver, ett_dcerpc_dnsserver,
		&uuid_dcerpc_dnsserver, ver_dcerpc_dnsserver,
		dnsserver_dissectors, hf_dnsserver_opnum);
}
