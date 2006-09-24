/* DO NOT EDIT
	This filter was automatically generated
	from dfs.idl and dfs.cnf.
	
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
#include "packet-dcerpc-dfs.h"

/* Ett declarations */
static gint ett_dcerpc_netdfs = -1;
static gint ett_netdfs_dfs_Info0 = -1;
static gint ett_netdfs_dfs_Info1 = -1;
static gint ett_netdfs_dfs_VolumeState = -1;
static gint ett_netdfs_dfs_Info2 = -1;
static gint ett_netdfs_dfs_StorageState = -1;
static gint ett_netdfs_dfs_StorageInfo = -1;
static gint ett_netdfs_dfs_Info3 = -1;
static gint ett_netdfs_dfs_Info4 = -1;
static gint ett_netdfs_dfs_PropertyFlags = -1;
static gint ett_netdfs_dfs_Info5 = -1;
static gint ett_netdfs_dfs_Target_Priority = -1;
static gint ett_netdfs_dfs_StorageInfo2 = -1;
static gint ett_netdfs_dfs_Info6 = -1;
static gint ett_netdfs_dfs_Info7 = -1;
static gint ett_netdfs_dfs_Info100 = -1;
static gint ett_netdfs_dfs_Info101 = -1;
static gint ett_netdfs_dfs_Info102 = -1;
static gint ett_netdfs_dfs_Info103 = -1;
static gint ett_netdfs_dfs_Info104 = -1;
static gint ett_netdfs_dfs_Info105 = -1;
static gint ett_netdfs_dfs_Info106 = -1;
static gint ett_netdfs_dfs_Info200 = -1;
static gint ett_netdfs_dfs_Info300 = -1;
static gint ett_netdfs_dfs_Info = -1;
static gint ett_netdfs_dfs_EnumArray1 = -1;
static gint ett_netdfs_dfs_EnumArray2 = -1;
static gint ett_netdfs_dfs_EnumArray3 = -1;
static gint ett_netdfs_dfs_EnumArray4 = -1;
static gint ett_netdfs_dfs_EnumArray200 = -1;
static gint ett_netdfs_dfs_EnumArray300 = -1;
static gint ett_netdfs_dfs_EnumInfo = -1;
static gint ett_netdfs_dfs_EnumStruct = -1;
static gint ett_netdfs_dfs_UnknownStruct = -1;


/* Header field declarations */
static gint hf_netdfs_dfs_EnumEx_level = -1;
static gint hf_netdfs_dfs_Info5_pktsize = -1;
static gint hf_netdfs_dfs_StorageState_DFS_STORAGE_STATE_ONLINE = -1;
static gint hf_netdfs_dfs_EnumEx_bufsize = -1;
static gint hf_netdfs_dfs_Info4_comment = -1;
static gint hf_netdfs_dfs_AddFtRoot_dns_servername = -1;
static gint hf_netdfs_dfs_PropertyFlags_DFS_PROPERTY_FLAG_SITE_COSTING = -1;
static gint hf_netdfs_dfs_PropertyFlags_DFS_PROPERTY_FLAG_ROOT_SCALABILITY = -1;
static gint hf_netdfs_dfs_VolumeState_DFS_VOLUME_STATE_OFFLINE = -1;
static gint hf_netdfs_dfs_Info5_guid = -1;
static gint hf_netdfs_dfs_Target_Priority_target_priority_rank = -1;
static gint hf_netdfs_dfs_AddStdRootForced_servername = -1;
static gint hf_netdfs_dfs_EnumInfo_info200 = -1;
static gint hf_netdfs_dfs_PropertyFlags_DFS_PROPERTY_FLAG_TARGET_FAILBACK = -1;
static gint hf_netdfs_dfs_Target_Priority_reserved = -1;
static gint hf_netdfs_dfs_Enum_bufsize = -1;
static gint hf_netdfs_dfs_AddStdRootForced_rootshare = -1;
static gint hf_netdfs_dfs_RemoveFtRoot_servername = -1;
static gint hf_netdfs_dfs_AddFtRoot_unknown1 = -1;
static gint hf_netdfs_dfs_EnumArray4_s = -1;
static gint hf_netdfs_dfs_AddFtRoot_unknown2 = -1;
static gint hf_netdfs_dfs_Info6_comment = -1;
static gint hf_netdfs_dfs_Info6_entry_path = -1;
static gint hf_netdfs_dfs_Info1_path = -1;
static gint hf_netdfs_dfs_EnumStruct_level = -1;
static gint hf_netdfs_dfs_GetInfo_sharename = -1;
static gint hf_netdfs_dfs_Info105_comment = -1;
static gint hf_netdfs_dfs_AddStdRoot_rootshare = -1;
static gint hf_netdfs_dfs_SetInfo_level = -1;
static gint hf_netdfs_dfs_Info6_flags = -1;
static gint hf_netdfs_dfs_Info4_state = -1;
static gint hf_netdfs_dfs_Info4_guid = -1;
static gint hf_netdfs_dfs_Info105_property_flags = -1;
static gint hf_netdfs_dfs_Enum_total = -1;
static gint hf_netdfs_dfs_EnumStruct_e = -1;
static gint hf_netdfs_dfs_EnumArray4_count = -1;
static gint hf_netdfs_dfs_StorageInfo2_info = -1;
static gint hf_netdfs_dfs_Info105_state = -1;
static gint hf_netdfs_dfs_FlushFtTable_servername = -1;
static gint hf_netdfs_dfs_Info4_stores = -1;
static gint hf_netdfs_dfs_Info4_num_stores = -1;
static gint hf_netdfs_dfs_GetInfo_dfs_entry_path = -1;
static gint hf_netdfs_dfs_EnumArray1_count = -1;
static gint hf_netdfs_dfs_StorageInfo_state = -1;
static gint hf_netdfs_dfs_FlushFtTable_rootshare = -1;
static gint hf_netdfs_dfs_AddStdRoot_servername = -1;
static gint hf_netdfs_dfs_EnumArray200_s = -1;
static gint hf_netdfs_dfs_AddFtRoot_servername = -1;
static gint hf_netdfs_dfs_Info6_stores = -1;
static gint hf_netdfs_dfs_GetInfo_servername = -1;
static gint hf_netdfs_dfs_StorageInfo2_target_priority = -1;
static gint hf_netdfs_dfs_EnumArray2_s = -1;
static gint hf_netdfs_dfs_RemoveFtRoot_flags = -1;
static gint hf_netdfs_dfs_EnumArray200_count = -1;
static gint hf_netdfs_dfs_EnumEx_info = -1;
static gint hf_netdfs_dfs_Info104_priority = -1;
static gint hf_netdfs_dfs_Info4_timeout = -1;
static gint hf_netdfs_dfs_AddFtRoot_comment = -1;
static gint hf_netdfs_dfs_PropertyFlags_DFS_PROPERTY_FLAG_CLUSTER_ENABLED = -1;
static gint hf_netdfs_dfs_Enum_info = -1;
static gint hf_netdfs_dfs_AddStdRoot_comment = -1;
static gint hf_netdfs_dfs_GetInfo_info = -1;
static gint hf_netdfs_dfs_Add_share = -1;
static gint hf_netdfs_dfs_Info100_comment = -1;
static gint hf_netdfs_dfs_EnumInfo_info300 = -1;
static gint hf_netdfs_dfs_Info6_state = -1;
static gint hf_netdfs_dfs_VolumeState_DFS_VOLUME_STATE_AD_BLOB = -1;
static gint hf_netdfs_dfs_Add_comment = -1;
static gint hf_netdfs_dfs_Info6_timeout = -1;
static gint hf_netdfs_dfs_RemoveFtRoot_rootshare = -1;
static gint hf_netdfs_dfs_Info105_timeout = -1;
static gint hf_netdfs_dfs_Info3_comment = -1;
static gint hf_netdfs_dfs_Info3_state = -1;
static gint hf_netdfs_dfs_Info5_flags = -1;
static gint hf_netdfs_dfs_Info7_generation_guid = -1;
static gint hf_netdfs_dfs_RemoveFtRoot_unknown = -1;
static gint hf_netdfs_dfs_EnumEx_total = -1;
static gint hf_netdfs_dfs_GetInfo_level = -1;
static gint hf_netdfs_dfs_Info5_num_stores = -1;
static gint hf_netdfs_dfs_Info6_pktsize = -1;
static gint hf_netdfs_dfs_EnumArray300_s = -1;
static gint hf_netdfs_dfs_Add_server = -1;
static gint hf_netdfs_dfs_Info5_comment = -1;
static gint hf_netdfs_werror = -1;
static gint hf_netdfs_dfs_EnumArray3_count = -1;
static gint hf_netdfs_dfs_VolumeState_DFS_VOLUME_STATE_INCONSISTENT = -1;
static gint hf_netdfs_dfs_AddFtRoot_rootshare = -1;
static gint hf_netdfs_dfs_Add_flags = -1;
static gint hf_netdfs_dfs_RemoveStdRoot_servername = -1;
static gint hf_netdfs_dfs_RemoveFtRoot_dfsname = -1;
static gint hf_netdfs_dfs_AddFtRoot_dfs_config_dn = -1;
static gint hf_netdfs_dfs_AddFtRoot_dfsname = -1;
static gint hf_netdfs_dfs_Remove_sharename = -1;
static gint hf_netdfs_dfs_Info101_state = -1;
static gint hf_netdfs_dfs_Info103_flags = -1;
static gint hf_netdfs_dfs_Info200_dom_root = -1;
static gint hf_netdfs_dfs_StorageState_DFS_STORAGE_STATE_OFFLINE = -1;
static gint hf_netdfs_dfs_VolumeState_DFS_VOLUME_STATE_ONLINE = -1;
static gint hf_netdfs_dfs_Info_info0 = -1;
static gint hf_netdfs_dfs_SetInfo_servername = -1;
static gint hf_netdfs_dfs_Info_info1 = -1;
static gint hf_netdfs_dfs_Info2_num_stores = -1;
static gint hf_netdfs_dfs_Info_info2 = -1;
static gint hf_netdfs_dfs_RemoveFtRoot_dns_servername = -1;
static gint hf_netdfs_dfs_Info_info3 = -1;
static gint hf_netdfs_dfs_Info_info4 = -1;
static gint hf_netdfs_dfs_Info_info5 = -1;
static gint hf_netdfs_dfs_StorageState_DFS_STORAGE_STATE_ACTIVE = -1;
static gint hf_netdfs_dfs_Info_info6 = -1;
static gint hf_netdfs_dfs_Enum_level = -1;
static gint hf_netdfs_dfs_Info_info7 = -1;
static gint hf_netdfs_dfs_Info300_flavor = -1;
static gint hf_netdfs_dfs_AddStdRootForced_store = -1;
static gint hf_netdfs_dfs_Info5_path = -1;
static gint hf_netdfs_dfs_GetManagerVersion_version = -1;
static gint hf_netdfs_dfs_Info3_stores = -1;
static gint hf_netdfs_dfs_VolumeState_DFS_VOLUME_STATE_STANDALONE = -1;
static gint hf_netdfs_dfs_EnumArray3_s = -1;
static gint hf_netdfs_dfs_Info106_priority = -1;
static gint hf_netdfs_dfs_UnknownStruct_unknown1 = -1;
static gint hf_netdfs_dfs_UnknownStruct_unknown2 = -1;
static gint hf_netdfs_dfs_VolumeState_DFS_VOLUME_STATE_OK = -1;
static gint hf_netdfs_dfs_StorageInfo_server = -1;
static gint hf_netdfs_dfs_SetInfo_dfs_entry_path = -1;
static gint hf_netdfs_dfs_RemoveStdRoot_flags = -1;
static gint hf_netdfs_dfs_AddFtRoot_flags = -1;
static gint hf_netdfs_dfs_ManagerInitialize_flags = -1;
static gint hf_netdfs_dfs_Info4_path = -1;
static gint hf_netdfs_dfs_Info5_state = -1;
static gint hf_netdfs_dfs_StorageInfo_share = -1;
static gint hf_netdfs_dfs_AddStdRoot_flags = -1;
static gint hf_netdfs_dfs_Info6_num_stores = -1;
static gint hf_netdfs_dfs_Target_Priority_target_priority_class = -1;
static gint hf_netdfs_opnum = -1;
static gint hf_netdfs_dfs_PropertyFlags_DFS_PROPERTY_FLAG_INSITE_REFERRALS = -1;
static gint hf_netdfs_dfs_Info2_state = -1;
static gint hf_netdfs_dfs_Info106_state = -1;
static gint hf_netdfs_dfs_Info_info100 = -1;
static gint hf_netdfs_dfs_AddStdRootForced_comment = -1;
static gint hf_netdfs_dfs_Info_info101 = -1;
static gint hf_netdfs_dfs_Add_path = -1;
static gint hf_netdfs_dfs_Info102_timeout = -1;
static gint hf_netdfs_dfs_Info_info102 = -1;
static gint hf_netdfs_dfs_Info_info103 = -1;
static gint hf_netdfs_dfs_Info_info104 = -1;
static gint hf_netdfs_dfs_Info3_path = -1;
static gint hf_netdfs_dfs_Info_info105 = -1;
static gint hf_netdfs_dfs_Info_info106 = -1;
static gint hf_netdfs_dfs_SetInfo_sharename = -1;
static gint hf_netdfs_dfs_ManagerInitialize_servername = -1;
static gint hf_netdfs_dfs_EnumInfo_info1 = -1;
static gint hf_netdfs_dfs_Info300_dom_root = -1;
static gint hf_netdfs_dfs_EnumArray2_count = -1;
static gint hf_netdfs_dfs_EnumArray300_count = -1;
static gint hf_netdfs_dfs_EnumInfo_info2 = -1;
static gint hf_netdfs_dfs_Remove_dfs_entry_path = -1;
static gint hf_netdfs_dfs_EnumInfo_info3 = -1;
static gint hf_netdfs_dfs_EnumEx_dfs_name = -1;
static gint hf_netdfs_dfs_RemoveStdRoot_rootshare = -1;
static gint hf_netdfs_dfs_EnumInfo_info4 = -1;
static gint hf_netdfs_dfs_Info5_timeout = -1;
static gint hf_netdfs_dfs_EnumArray1_s = -1;
static gint hf_netdfs_dfs_Remove_servername = -1;
static gint hf_netdfs_dfs_Info3_num_stores = -1;
static gint hf_netdfs_dfs_Info105_property_flag_mask = -1;
static gint hf_netdfs_dfs_Info2_comment = -1;
static gint hf_netdfs_dfs_Info6_guid = -1;
static gint hf_netdfs_dfs_Info2_path = -1;
static gint hf_netdfs_dfs_SetInfo_info = -1;

static gint proto_dcerpc_netdfs = -1;
/* Version information */


static e_uuid_t uuid_dcerpc_netdfs = {
	0x4fc742e0, 0x4a10, 0x11cf,
	{ 0x82, 0x73, 0x00, 0xaa, 0x00, 0x4a, 0xe6, 0x73 }
};
static guint16 ver_dcerpc_netdfs = 3;

const value_string netdfs_dfs_ManagerVersion_vals[] = {
	{ DFS_MANAGER_VERSION_NT4, "DFS_MANAGER_VERSION_NT4" },
	{ DFS_MANAGER_VERSION_W2K, "DFS_MANAGER_VERSION_W2K" },
	{ DFS_MANAGER_VERSION_W2K3, "DFS_MANAGER_VERSION_W2K3" },
{ 0, NULL }
};
static int netdfs_dissect_element_dfs_Info1_path(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info1_path_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static const true_false_string dfs_VolumeState_DFS_VOLUME_STATE_OK_tfs = {
   "DFS_VOLUME_STATE_OK is SET",
   "DFS_VOLUME_STATE_OK is NOT SET",
};
static const true_false_string dfs_VolumeState_DFS_VOLUME_STATE_INCONSISTENT_tfs = {
   "DFS_VOLUME_STATE_INCONSISTENT is SET",
   "DFS_VOLUME_STATE_INCONSISTENT is NOT SET",
};
static const true_false_string dfs_VolumeState_DFS_VOLUME_STATE_OFFLINE_tfs = {
   "DFS_VOLUME_STATE_OFFLINE is SET",
   "DFS_VOLUME_STATE_OFFLINE is NOT SET",
};
static const true_false_string dfs_VolumeState_DFS_VOLUME_STATE_ONLINE_tfs = {
   "DFS_VOLUME_STATE_ONLINE is SET",
   "DFS_VOLUME_STATE_ONLINE is NOT SET",
};
static const true_false_string dfs_VolumeState_DFS_VOLUME_STATE_STANDALONE_tfs = {
   "DFS_VOLUME_STATE_STANDALONE is SET",
   "DFS_VOLUME_STATE_STANDALONE is NOT SET",
};
static const true_false_string dfs_VolumeState_DFS_VOLUME_STATE_AD_BLOB_tfs = {
   "DFS_VOLUME_STATE_AD_BLOB is SET",
   "DFS_VOLUME_STATE_AD_BLOB is NOT SET",
};
static int netdfs_dissect_element_dfs_Info2_path(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info2_path_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info2_comment(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info2_comment_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info2_state(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info2_num_stores(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static const true_false_string dfs_StorageState_DFS_STORAGE_STATE_OFFLINE_tfs = {
   "DFS_STORAGE_STATE_OFFLINE is SET",
   "DFS_STORAGE_STATE_OFFLINE is NOT SET",
};
static const true_false_string dfs_StorageState_DFS_STORAGE_STATE_ONLINE_tfs = {
   "DFS_STORAGE_STATE_ONLINE is SET",
   "DFS_STORAGE_STATE_ONLINE is NOT SET",
};
static const true_false_string dfs_StorageState_DFS_STORAGE_STATE_ACTIVE_tfs = {
   "DFS_STORAGE_STATE_ACTIVE is SET",
   "DFS_STORAGE_STATE_ACTIVE is NOT SET",
};
static int netdfs_dissect_element_dfs_StorageInfo_state(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_StorageInfo_server(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_StorageInfo_server_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_StorageInfo_share(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_StorageInfo_share_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info3_path(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info3_path_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info3_comment(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info3_comment_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info3_state(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info3_num_stores(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info3_stores(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info3_stores_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info3_stores__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info4_path(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info4_path_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info4_comment(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info4_comment_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info4_state(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info4_timeout(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info4_guid(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info4_num_stores(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info4_stores(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info4_stores_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info4_stores__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static const true_false_string dfs_PropertyFlags_DFS_PROPERTY_FLAG_INSITE_REFERRALS_tfs = {
   "DFS_PROPERTY_FLAG_INSITE_REFERRALS is SET",
   "DFS_PROPERTY_FLAG_INSITE_REFERRALS is NOT SET",
};
static const true_false_string dfs_PropertyFlags_DFS_PROPERTY_FLAG_ROOT_SCALABILITY_tfs = {
   "DFS_PROPERTY_FLAG_ROOT_SCALABILITY is SET",
   "DFS_PROPERTY_FLAG_ROOT_SCALABILITY is NOT SET",
};
static const true_false_string dfs_PropertyFlags_DFS_PROPERTY_FLAG_SITE_COSTING_tfs = {
   "DFS_PROPERTY_FLAG_SITE_COSTING is SET",
   "DFS_PROPERTY_FLAG_SITE_COSTING is NOT SET",
};
static const true_false_string dfs_PropertyFlags_DFS_PROPERTY_FLAG_TARGET_FAILBACK_tfs = {
   "DFS_PROPERTY_FLAG_TARGET_FAILBACK is SET",
   "DFS_PROPERTY_FLAG_TARGET_FAILBACK is NOT SET",
};
static const true_false_string dfs_PropertyFlags_DFS_PROPERTY_FLAG_CLUSTER_ENABLED_tfs = {
   "DFS_PROPERTY_FLAG_CLUSTER_ENABLED is SET",
   "DFS_PROPERTY_FLAG_CLUSTER_ENABLED is NOT SET",
};
static int netdfs_dissect_element_dfs_Info5_path(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info5_path_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info5_comment(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info5_comment_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info5_state(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info5_timeout(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info5_guid(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info5_flags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info5_pktsize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info5_num_stores(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
const value_string netdfs_dfs_Target_PriorityClass_vals[] = {
	{ DFS_INVALID_PRIORITY_CLASS, "DFS_INVALID_PRIORITY_CLASS" },
	{ DFS_SITE_COST_NORMAL_PRIORITY_CLASS, "DFS_SITE_COST_NORMAL_PRIORITY_CLASS" },
	{ DFS_GLOBAL_HIGH_PRIORITY_CLASS, "DFS_GLOBAL_HIGH_PRIORITY_CLASS" },
	{ DFS_SITE_COST_HIGH_PRIORITY_CLASS, "DFS_SITE_COST_HIGH_PRIORITY_CLASS" },
	{ DFS_SITE_COST_LOW_PRIORITY_CLASS, "DFS_SITE_COST_LOW_PRIORITY_CLASS" },
	{ DFS_GLOBAL_LOW_PRIORITY_CLASS, "DFS_GLOBAL_LOW_PRIORITY_CLASS" },
{ 0, NULL }
};
static int netdfs_dissect_element_dfs_Target_Priority_target_priority_class(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Target_Priority_target_priority_rank(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Target_Priority_reserved(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_StorageInfo2_info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_StorageInfo2_target_priority(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info6_entry_path(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info6_entry_path_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info6_comment(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info6_comment_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info6_state(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info6_timeout(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info6_guid(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info6_flags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info6_pktsize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info6_num_stores(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info6_stores(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info6_stores_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info6_stores__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info7_generation_guid(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info100_comment(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info100_comment_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info101_state(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info102_timeout(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info103_flags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info104_priority(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info105_comment(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info105_comment_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info105_state(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info105_timeout(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info105_property_flag_mask(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info105_property_flags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info106_state(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info106_priority(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info200_dom_root(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info200_dom_root_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
const value_string netdfs_dfs_VolumeFlavor_vals[] = {
	{ DFS_VOLUME_FLAVOR_STANDALONE, "DFS_VOLUME_FLAVOR_STANDALONE" },
	{ DFS_VOLUME_FLAVOR_AD_BLOB, "DFS_VOLUME_FLAVOR_AD_BLOB" },
{ 0, NULL }
};
static int netdfs_dissect_element_dfs_Info300_flavor(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info300_dom_root(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info300_dom_root_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info0(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info0_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info1_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info2_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info3(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info3_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info4(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info4_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info5(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info5_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info6(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info6_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info7(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info7_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info100(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info100_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info101(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info101_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info102(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info102_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info103(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info103_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info104(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info104_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info105(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info105_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info106(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info106_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumArray1_count(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumArray1_s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumArray1_s_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumArray1_s__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumArray2_count(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumArray2_s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumArray2_s_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumArray2_s__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumArray3_count(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumArray3_s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumArray3_s_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumArray3_s__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumArray4_count(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumArray4_s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumArray4_s_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumArray4_s__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumArray200_count(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumArray200_s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumArray200_s_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumArray200_s__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumArray300_count(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumArray300_s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumArray300_s_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumArray300_s__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumInfo_info1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumInfo_info1_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumInfo_info2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumInfo_info2_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumInfo_info3(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumInfo_info3_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumInfo_info4(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumInfo_info4_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumInfo_info200(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumInfo_info200_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumInfo_info300(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumInfo_info300_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumStruct_level(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumStruct_e(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_UnknownStruct_unknown1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_UnknownStruct_unknown2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_UnknownStruct_unknown2_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_GetManagerVersion_version(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_GetManagerVersion_version_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Add_path(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Add_path_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Add_server(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Add_server_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Add_share(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Add_share_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Add_comment(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Add_comment_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Add_flags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Remove_dfs_entry_path(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Remove_dfs_entry_path_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Remove_servername(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Remove_servername_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Remove_sharename(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Remove_sharename_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_SetInfo_dfs_entry_path(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_SetInfo_servername(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_SetInfo_servername_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_SetInfo_sharename(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_SetInfo_sharename_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_SetInfo_level(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_SetInfo_info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_SetInfo_info_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_GetInfo_dfs_entry_path(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_GetInfo_servername(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_GetInfo_servername_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_GetInfo_sharename(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_GetInfo_sharename_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_GetInfo_level(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_GetInfo_info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_GetInfo_info_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Enum_level(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Enum_bufsize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Enum_info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Enum_info_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Enum_total(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Enum_total_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_AddFtRoot_servername(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_AddFtRoot_dns_servername(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_AddFtRoot_dfsname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_AddFtRoot_rootshare(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_AddFtRoot_comment(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_AddFtRoot_dfs_config_dn(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_AddFtRoot_unknown1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_AddFtRoot_flags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_AddFtRoot_unknown2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_AddFtRoot_unknown2_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_AddFtRoot_unknown2__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_RemoveFtRoot_servername(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_RemoveFtRoot_dns_servername(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_RemoveFtRoot_dfsname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_RemoveFtRoot_rootshare(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_RemoveFtRoot_flags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_RemoveFtRoot_unknown(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_RemoveFtRoot_unknown_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_RemoveFtRoot_unknown__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_AddStdRoot_servername(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_AddStdRoot_rootshare(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_AddStdRoot_comment(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_AddStdRoot_flags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_RemoveStdRoot_servername(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_RemoveStdRoot_rootshare(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_RemoveStdRoot_flags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_ManagerInitialize_servername(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_ManagerInitialize_servername_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_ManagerInitialize_flags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_AddStdRootForced_servername(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_AddStdRootForced_rootshare(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_AddStdRootForced_comment(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_AddStdRootForced_store(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_FlushFtTable_servername(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_FlushFtTable_rootshare(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumEx_dfs_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumEx_level(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumEx_bufsize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumEx_info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumEx_info_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumEx_total(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumEx_total_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);

/* IDL: typedef enum { */
/* IDL: 	DFS_MANAGER_VERSION_NT4=1, */
/* IDL: 	DFS_MANAGER_VERSION_W2K=2, */
/* IDL: 	DFS_MANAGER_VERSION_W2K3=4, */
/* IDL: } dfs_ManagerVersion; */

int
netdfs_dissect_enum_dfs_ManagerVersion(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_index, NULL);
	return offset;
}

/* IDL: typedef struct { */
/* IDL: } dfs_Info0; */

int
netdfs_dissect_struct_dfs_Info0(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;


	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_netdfs_dfs_Info0);
	}
	

	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *path; */
/* IDL: } dfs_Info1; */

static int
netdfs_dissect_element_dfs_Info1_path(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info1_path_, NDR_POINTER_UNIQUE, "Pointer to Path (uint16)",hf_netdfs_dfs_Info1_path);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info1_path_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_Info1_path, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

int
netdfs_dissect_struct_dfs_Info1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_netdfs_dfs_Info1);
	}
	
	offset = netdfs_dissect_element_dfs_Info1_path(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef bitmap { */
/* IDL: 	DFS_VOLUME_STATE_OK =  0x1 , */
/* IDL: 	DFS_VOLUME_STATE_INCONSISTENT =  0x2 , */
/* IDL: 	DFS_VOLUME_STATE_OFFLINE =  0x4 , */
/* IDL: 	DFS_VOLUME_STATE_ONLINE =  0x8 , */
/* IDL: 	DFS_VOLUME_STATE_STANDALONE =  DFS_VOLUME_FLAVOR_STANDALONE , */
/* IDL: 	DFS_VOLUME_STATE_AD_BLOB =  DFS_VOLUME_FLAVOR_AD_BLOB , */
/* IDL: } dfs_VolumeState; */

int
netdfs_dissect_bitmap_dfs_VolumeState(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	guint32 flags;
	ALIGN_TO_4_BYTES;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, 4, TRUE);
		tree = proto_item_add_subtree(item,ett_netdfs_dfs_VolumeState);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, drep, -1, &flags);
	proto_item_append_text(item, ": ");

	if (!flags)
		proto_item_append_text(item, "(No values set)");

	proto_tree_add_boolean(tree, hf_netdfs_dfs_VolumeState_DFS_VOLUME_STATE_OK, tvb, offset-4, 4, flags);
	if (flags&( 0x1 )){
		proto_item_append_text(item, "DFS_VOLUME_STATE_OK");
		if (flags & (~( 0x1 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x1 ));

	proto_tree_add_boolean(tree, hf_netdfs_dfs_VolumeState_DFS_VOLUME_STATE_INCONSISTENT, tvb, offset-4, 4, flags);
	if (flags&( 0x2 )){
		proto_item_append_text(item, "DFS_VOLUME_STATE_INCONSISTENT");
		if (flags & (~( 0x2 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x2 ));

	proto_tree_add_boolean(tree, hf_netdfs_dfs_VolumeState_DFS_VOLUME_STATE_OFFLINE, tvb, offset-4, 4, flags);
	if (flags&( 0x4 )){
		proto_item_append_text(item, "DFS_VOLUME_STATE_OFFLINE");
		if (flags & (~( 0x4 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x4 ));

	proto_tree_add_boolean(tree, hf_netdfs_dfs_VolumeState_DFS_VOLUME_STATE_ONLINE, tvb, offset-4, 4, flags);
	if (flags&( 0x8 )){
		proto_item_append_text(item, "DFS_VOLUME_STATE_ONLINE");
		if (flags & (~( 0x8 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x8 ));

	proto_tree_add_boolean(tree, hf_netdfs_dfs_VolumeState_DFS_VOLUME_STATE_STANDALONE, tvb, offset-4, 4, flags);
	if (flags&( DFS_VOLUME_FLAVOR_STANDALONE )){
		proto_item_append_text(item, "DFS_VOLUME_STATE_STANDALONE");
		if (flags & (~( DFS_VOLUME_FLAVOR_STANDALONE )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( DFS_VOLUME_FLAVOR_STANDALONE ));

	proto_tree_add_boolean(tree, hf_netdfs_dfs_VolumeState_DFS_VOLUME_STATE_AD_BLOB, tvb, offset-4, 4, flags);
	if (flags&( DFS_VOLUME_FLAVOR_AD_BLOB )){
		proto_item_append_text(item, "DFS_VOLUME_STATE_AD_BLOB");
		if (flags & (~( DFS_VOLUME_FLAVOR_AD_BLOB )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( DFS_VOLUME_FLAVOR_AD_BLOB ));

	if (flags) {
		proto_item_append_text(item, "Unknown bitmap value 0x%x", flags);
	}

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *path; */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *comment; */
/* IDL: 	dfs_VolumeState state; */
/* IDL: 	uint32 num_stores; */
/* IDL: } dfs_Info2; */

static int
netdfs_dissect_element_dfs_Info2_path(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info2_path_, NDR_POINTER_UNIQUE, "Pointer to Path (uint16)",hf_netdfs_dfs_Info2_path);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info2_path_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_Info2_path, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info2_comment(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info2_comment_, NDR_POINTER_UNIQUE, "Pointer to Comment (uint16)",hf_netdfs_dfs_Info2_comment);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info2_comment_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_Info2_comment, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info2_state(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_bitmap_dfs_VolumeState(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info2_state, 0);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info2_num_stores(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info2_num_stores,NULL);

	return offset;
}

int
netdfs_dissect_struct_dfs_Info2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_netdfs_dfs_Info2);
	}
	
	offset = netdfs_dissect_element_dfs_Info2_path(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info2_comment(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info2_state(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info2_num_stores(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef bitmap { */
/* IDL: 	DFS_STORAGE_STATE_OFFLINE =  1 , */
/* IDL: 	DFS_STORAGE_STATE_ONLINE =  2 , */
/* IDL: 	DFS_STORAGE_STATE_ACTIVE =  4 , */
/* IDL: } dfs_StorageState; */

int
netdfs_dissect_bitmap_dfs_StorageState(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	guint32 flags;
	ALIGN_TO_4_BYTES;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, 4, TRUE);
		tree = proto_item_add_subtree(item,ett_netdfs_dfs_StorageState);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, drep, -1, &flags);
	proto_item_append_text(item, ": ");

	if (!flags)
		proto_item_append_text(item, "(No values set)");

	proto_tree_add_boolean(tree, hf_netdfs_dfs_StorageState_DFS_STORAGE_STATE_OFFLINE, tvb, offset-4, 4, flags);
	if (flags&( 1 )){
		proto_item_append_text(item, "DFS_STORAGE_STATE_OFFLINE");
		if (flags & (~( 1 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 1 ));

	proto_tree_add_boolean(tree, hf_netdfs_dfs_StorageState_DFS_STORAGE_STATE_ONLINE, tvb, offset-4, 4, flags);
	if (flags&( 2 )){
		proto_item_append_text(item, "DFS_STORAGE_STATE_ONLINE");
		if (flags & (~( 2 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 2 ));

	proto_tree_add_boolean(tree, hf_netdfs_dfs_StorageState_DFS_STORAGE_STATE_ACTIVE, tvb, offset-4, 4, flags);
	if (flags&( 4 )){
		proto_item_append_text(item, "DFS_STORAGE_STATE_ACTIVE");
		if (flags & (~( 4 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 4 ));

	if (flags) {
		proto_item_append_text(item, "Unknown bitmap value 0x%x", flags);
	}

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	dfs_StorageState state; */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *server; */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *share; */
/* IDL: } dfs_StorageInfo; */

static int
netdfs_dissect_element_dfs_StorageInfo_state(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_bitmap_dfs_StorageState(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_StorageInfo_state, 0);

	return offset;
}

static int
netdfs_dissect_element_dfs_StorageInfo_server(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_StorageInfo_server_, NDR_POINTER_UNIQUE, "Pointer to Server (uint16)",hf_netdfs_dfs_StorageInfo_server);

	return offset;
}

static int
netdfs_dissect_element_dfs_StorageInfo_server_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_StorageInfo_server, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_StorageInfo_share(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_StorageInfo_share_, NDR_POINTER_UNIQUE, "Pointer to Share (uint16)",hf_netdfs_dfs_StorageInfo_share);

	return offset;
}

static int
netdfs_dissect_element_dfs_StorageInfo_share_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_StorageInfo_share, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

int
netdfs_dissect_struct_dfs_StorageInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_netdfs_dfs_StorageInfo);
	}
	
	offset = netdfs_dissect_element_dfs_StorageInfo_state(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_StorageInfo_server(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_StorageInfo_share(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *path; */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *comment; */
/* IDL: 	dfs_VolumeState state; */
/* IDL: 	uint32 num_stores; */
/* IDL: 	[size_is(num_stores)] [unique(1)] dfs_StorageInfo *stores; */
/* IDL: } dfs_Info3; */

static int
netdfs_dissect_element_dfs_Info3_path(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info3_path_, NDR_POINTER_UNIQUE, "Pointer to Path (uint16)",hf_netdfs_dfs_Info3_path);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info3_path_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_Info3_path, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info3_comment(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info3_comment_, NDR_POINTER_UNIQUE, "Pointer to Comment (uint16)",hf_netdfs_dfs_Info3_comment);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info3_comment_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_Info3_comment, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info3_state(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_bitmap_dfs_VolumeState(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info3_state, 0);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info3_num_stores(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info3_num_stores,NULL);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info3_stores(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info3_stores_, NDR_POINTER_UNIQUE, "Pointer to Stores (dfs_StorageInfo)",hf_netdfs_dfs_Info3_stores);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info3_stores_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info3_stores__);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info3_stores__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_StorageInfo(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_Info3_stores,0);

	return offset;
}

int
netdfs_dissect_struct_dfs_Info3(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_netdfs_dfs_Info3);
	}
	
	offset = netdfs_dissect_element_dfs_Info3_path(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info3_comment(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info3_state(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info3_num_stores(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info3_stores(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *path; */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *comment; */
/* IDL: 	dfs_VolumeState state; */
/* IDL: 	uint32 timeout; */
/* IDL: 	GUID guid; */
/* IDL: 	uint32 num_stores; */
/* IDL: 	[size_is(num_stores)] [unique(1)] dfs_StorageInfo *stores; */
/* IDL: } dfs_Info4; */

static int
netdfs_dissect_element_dfs_Info4_path(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info4_path_, NDR_POINTER_UNIQUE, "Pointer to Path (uint16)",hf_netdfs_dfs_Info4_path);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info4_path_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_Info4_path, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info4_comment(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info4_comment_, NDR_POINTER_UNIQUE, "Pointer to Comment (uint16)",hf_netdfs_dfs_Info4_comment);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info4_comment_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_Info4_comment, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info4_state(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_bitmap_dfs_VolumeState(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info4_state, 0);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info4_timeout(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info4_timeout,NULL);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info4_guid(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uuid_t(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info4_guid, NULL);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info4_num_stores(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info4_num_stores,NULL);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info4_stores(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info4_stores_, NDR_POINTER_UNIQUE, "Pointer to Stores (dfs_StorageInfo)",hf_netdfs_dfs_Info4_stores);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info4_stores_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info4_stores__);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info4_stores__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_StorageInfo(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_Info4_stores,0);

	return offset;
}

int
netdfs_dissect_struct_dfs_Info4(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_netdfs_dfs_Info4);
	}
	
	offset = netdfs_dissect_element_dfs_Info4_path(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info4_comment(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info4_state(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info4_timeout(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info4_guid(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info4_num_stores(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info4_stores(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef bitmap { */
/* IDL: 	DFS_PROPERTY_FLAG_INSITE_REFERRALS =  0x01 , */
/* IDL: 	DFS_PROPERTY_FLAG_ROOT_SCALABILITY =  0x02 , */
/* IDL: 	DFS_PROPERTY_FLAG_SITE_COSTING =  0x04 , */
/* IDL: 	DFS_PROPERTY_FLAG_TARGET_FAILBACK =  0x08 , */
/* IDL: 	DFS_PROPERTY_FLAG_CLUSTER_ENABLED =  0x10 , */
/* IDL: } dfs_PropertyFlags; */

int
netdfs_dissect_bitmap_dfs_PropertyFlags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	guint32 flags;
	ALIGN_TO_4_BYTES;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, 4, TRUE);
		tree = proto_item_add_subtree(item,ett_netdfs_dfs_PropertyFlags);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, drep, -1, &flags);
	proto_item_append_text(item, ": ");

	if (!flags)
		proto_item_append_text(item, "(No values set)");

	proto_tree_add_boolean(tree, hf_netdfs_dfs_PropertyFlags_DFS_PROPERTY_FLAG_INSITE_REFERRALS, tvb, offset-4, 4, flags);
	if (flags&( 0x01 )){
		proto_item_append_text(item, "DFS_PROPERTY_FLAG_INSITE_REFERRALS");
		if (flags & (~( 0x01 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x01 ));

	proto_tree_add_boolean(tree, hf_netdfs_dfs_PropertyFlags_DFS_PROPERTY_FLAG_ROOT_SCALABILITY, tvb, offset-4, 4, flags);
	if (flags&( 0x02 )){
		proto_item_append_text(item, "DFS_PROPERTY_FLAG_ROOT_SCALABILITY");
		if (flags & (~( 0x02 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x02 ));

	proto_tree_add_boolean(tree, hf_netdfs_dfs_PropertyFlags_DFS_PROPERTY_FLAG_SITE_COSTING, tvb, offset-4, 4, flags);
	if (flags&( 0x04 )){
		proto_item_append_text(item, "DFS_PROPERTY_FLAG_SITE_COSTING");
		if (flags & (~( 0x04 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x04 ));

	proto_tree_add_boolean(tree, hf_netdfs_dfs_PropertyFlags_DFS_PROPERTY_FLAG_TARGET_FAILBACK, tvb, offset-4, 4, flags);
	if (flags&( 0x08 )){
		proto_item_append_text(item, "DFS_PROPERTY_FLAG_TARGET_FAILBACK");
		if (flags & (~( 0x08 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x08 ));

	proto_tree_add_boolean(tree, hf_netdfs_dfs_PropertyFlags_DFS_PROPERTY_FLAG_CLUSTER_ENABLED, tvb, offset-4, 4, flags);
	if (flags&( 0x10 )){
		proto_item_append_text(item, "DFS_PROPERTY_FLAG_CLUSTER_ENABLED");
		if (flags & (~( 0x10 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x10 ));

	if (flags) {
		proto_item_append_text(item, "Unknown bitmap value 0x%x", flags);
	}

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *path; */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *comment; */
/* IDL: 	dfs_VolumeState state; */
/* IDL: 	uint32 timeout; */
/* IDL: 	GUID guid; */
/* IDL: 	dfs_PropertyFlags flags; */
/* IDL: 	uint32 pktsize; */
/* IDL: 	uint32 num_stores; */
/* IDL: } dfs_Info5; */

static int
netdfs_dissect_element_dfs_Info5_path(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info5_path_, NDR_POINTER_UNIQUE, "Pointer to Path (uint16)",hf_netdfs_dfs_Info5_path);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info5_path_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_Info5_path, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info5_comment(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info5_comment_, NDR_POINTER_UNIQUE, "Pointer to Comment (uint16)",hf_netdfs_dfs_Info5_comment);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info5_comment_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_Info5_comment, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info5_state(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_bitmap_dfs_VolumeState(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info5_state, 0);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info5_timeout(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info5_timeout,NULL);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info5_guid(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uuid_t(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info5_guid, NULL);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info5_flags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_bitmap_dfs_PropertyFlags(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info5_flags, 0);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info5_pktsize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info5_pktsize,NULL);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info5_num_stores(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info5_num_stores,NULL);

	return offset;
}

int
netdfs_dissect_struct_dfs_Info5(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_netdfs_dfs_Info5);
	}
	
	offset = netdfs_dissect_element_dfs_Info5_path(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info5_comment(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info5_state(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info5_timeout(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info5_guid(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info5_flags(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info5_pktsize(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info5_num_stores(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef enum { */
/* IDL: 	DFS_INVALID_PRIORITY_CLASS=-1, */
/* IDL: 	DFS_SITE_COST_NORMAL_PRIORITY_CLASS=0, */
/* IDL: 	DFS_GLOBAL_HIGH_PRIORITY_CLASS=1, */
/* IDL: 	DFS_SITE_COST_HIGH_PRIORITY_CLASS=2, */
/* IDL: 	DFS_SITE_COST_LOW_PRIORITY_CLASS=3, */
/* IDL: 	DFS_GLOBAL_LOW_PRIORITY_CLASS=4, */
/* IDL: } dfs_Target_PriorityClass; */

int
netdfs_dissect_enum_dfs_Target_PriorityClass(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_index, NULL);
	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	dfs_Target_PriorityClass target_priority_class; */
/* IDL: 	uint16 target_priority_rank; */
/* IDL: 	uint16 reserved; */
/* IDL: } dfs_Target_Priority; */

static int
netdfs_dissect_element_dfs_Target_Priority_target_priority_class(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_enum_dfs_Target_PriorityClass(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Target_Priority_target_priority_class, 0);

	return offset;
}

static int
netdfs_dissect_element_dfs_Target_Priority_target_priority_rank(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Target_Priority_target_priority_rank,NULL);

	return offset;
}

static int
netdfs_dissect_element_dfs_Target_Priority_reserved(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Target_Priority_reserved,NULL);

	return offset;
}

int
netdfs_dissect_struct_dfs_Target_Priority(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_netdfs_dfs_Target_Priority);
	}
	
	offset = netdfs_dissect_element_dfs_Target_Priority_target_priority_class(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Target_Priority_target_priority_rank(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Target_Priority_reserved(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	dfs_StorageInfo info; */
/* IDL: 	dfs_Target_Priority target_priority; */
/* IDL: } dfs_StorageInfo2; */

static int
netdfs_dissect_element_dfs_StorageInfo2_info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_StorageInfo(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_StorageInfo2_info,0);

	return offset;
}

static int
netdfs_dissect_element_dfs_StorageInfo2_target_priority(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_Target_Priority(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_StorageInfo2_target_priority,0);

	return offset;
}

int
netdfs_dissect_struct_dfs_StorageInfo2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_netdfs_dfs_StorageInfo2);
	}
	
	offset = netdfs_dissect_element_dfs_StorageInfo2_info(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_StorageInfo2_target_priority(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *entry_path; */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *comment; */
/* IDL: 	dfs_VolumeState state; */
/* IDL: 	uint32 timeout; */
/* IDL: 	GUID guid; */
/* IDL: 	dfs_PropertyFlags flags; */
/* IDL: 	uint32 pktsize; */
/* IDL: 	uint16 num_stores; */
/* IDL: 	[size_is(num_stores)] [unique(1)] dfs_StorageInfo2 *stores; */
/* IDL: } dfs_Info6; */

static int
netdfs_dissect_element_dfs_Info6_entry_path(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info6_entry_path_, NDR_POINTER_UNIQUE, "Pointer to Entry Path (uint16)",hf_netdfs_dfs_Info6_entry_path);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info6_entry_path_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_Info6_entry_path, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info6_comment(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info6_comment_, NDR_POINTER_UNIQUE, "Pointer to Comment (uint16)",hf_netdfs_dfs_Info6_comment);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info6_comment_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_Info6_comment, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info6_state(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_bitmap_dfs_VolumeState(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info6_state, 0);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info6_timeout(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info6_timeout,NULL);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info6_guid(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uuid_t(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info6_guid, NULL);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info6_flags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_bitmap_dfs_PropertyFlags(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info6_flags, 0);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info6_pktsize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info6_pktsize,NULL);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info6_num_stores(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info6_num_stores,NULL);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info6_stores(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info6_stores_, NDR_POINTER_UNIQUE, "Pointer to Stores (dfs_StorageInfo2)",hf_netdfs_dfs_Info6_stores);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info6_stores_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info6_stores__);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info6_stores__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_StorageInfo2(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_Info6_stores,0);

	return offset;
}

int
netdfs_dissect_struct_dfs_Info6(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_netdfs_dfs_Info6);
	}
	
	offset = netdfs_dissect_element_dfs_Info6_entry_path(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info6_comment(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info6_state(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info6_timeout(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info6_guid(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info6_flags(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info6_pktsize(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info6_num_stores(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info6_stores(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	GUID generation_guid; */
/* IDL: } dfs_Info7; */

static int
netdfs_dissect_element_dfs_Info7_generation_guid(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uuid_t(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info7_generation_guid, NULL);

	return offset;
}

int
netdfs_dissect_struct_dfs_Info7(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_netdfs_dfs_Info7);
	}
	
	offset = netdfs_dissect_element_dfs_Info7_generation_guid(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *comment; */
/* IDL: } dfs_Info100; */

static int
netdfs_dissect_element_dfs_Info100_comment(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info100_comment_, NDR_POINTER_UNIQUE, "Pointer to Comment (uint16)",hf_netdfs_dfs_Info100_comment);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info100_comment_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_Info100_comment, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

int
netdfs_dissect_struct_dfs_Info100(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_netdfs_dfs_Info100);
	}
	
	offset = netdfs_dissect_element_dfs_Info100_comment(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	dfs_StorageState state; */
/* IDL: } dfs_Info101; */

static int
netdfs_dissect_element_dfs_Info101_state(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_bitmap_dfs_StorageState(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info101_state, 0);

	return offset;
}

int
netdfs_dissect_struct_dfs_Info101(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_netdfs_dfs_Info101);
	}
	
	offset = netdfs_dissect_element_dfs_Info101_state(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	uint32 timeout; */
/* IDL: } dfs_Info102; */

static int
netdfs_dissect_element_dfs_Info102_timeout(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info102_timeout,NULL);

	return offset;
}

int
netdfs_dissect_struct_dfs_Info102(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_netdfs_dfs_Info102);
	}
	
	offset = netdfs_dissect_element_dfs_Info102_timeout(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	dfs_PropertyFlags flags; */
/* IDL: } dfs_Info103; */

static int
netdfs_dissect_element_dfs_Info103_flags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_bitmap_dfs_PropertyFlags(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info103_flags, 0);

	return offset;
}

int
netdfs_dissect_struct_dfs_Info103(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_netdfs_dfs_Info103);
	}
	
	offset = netdfs_dissect_element_dfs_Info103_flags(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	dfs_Target_Priority priority; */
/* IDL: } dfs_Info104; */

static int
netdfs_dissect_element_dfs_Info104_priority(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_Target_Priority(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_Info104_priority,0);

	return offset;
}

int
netdfs_dissect_struct_dfs_Info104(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_netdfs_dfs_Info104);
	}
	
	offset = netdfs_dissect_element_dfs_Info104_priority(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *comment; */
/* IDL: 	dfs_VolumeState state; */
/* IDL: 	uint32 timeout; */
/* IDL: 	uint32 property_flag_mask; */
/* IDL: 	uint32 property_flags; */
/* IDL: } dfs_Info105; */

static int
netdfs_dissect_element_dfs_Info105_comment(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info105_comment_, NDR_POINTER_UNIQUE, "Pointer to Comment (uint16)",hf_netdfs_dfs_Info105_comment);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info105_comment_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_Info105_comment, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info105_state(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_bitmap_dfs_VolumeState(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info105_state, 0);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info105_timeout(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info105_timeout,NULL);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info105_property_flag_mask(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info105_property_flag_mask,NULL);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info105_property_flags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info105_property_flags,NULL);

	return offset;
}

int
netdfs_dissect_struct_dfs_Info105(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_netdfs_dfs_Info105);
	}
	
	offset = netdfs_dissect_element_dfs_Info105_comment(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info105_state(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info105_timeout(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info105_property_flag_mask(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info105_property_flags(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	dfs_StorageState state; */
/* IDL: 	dfs_Target_Priority priority; */
/* IDL: } dfs_Info106; */

static int
netdfs_dissect_element_dfs_Info106_state(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_bitmap_dfs_StorageState(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info106_state, 0);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info106_priority(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_Target_Priority(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_Info106_priority,0);

	return offset;
}

int
netdfs_dissect_struct_dfs_Info106(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_netdfs_dfs_Info106);
	}
	
	offset = netdfs_dissect_element_dfs_Info106_state(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info106_priority(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *dom_root; */
/* IDL: } dfs_Info200; */

static int
netdfs_dissect_element_dfs_Info200_dom_root(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info200_dom_root_, NDR_POINTER_UNIQUE, "Pointer to Dom Root (uint16)",hf_netdfs_dfs_Info200_dom_root);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info200_dom_root_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_Info200_dom_root, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

int
netdfs_dissect_struct_dfs_Info200(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_netdfs_dfs_Info200);
	}
	
	offset = netdfs_dissect_element_dfs_Info200_dom_root(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef enum { */
/* IDL: 	DFS_VOLUME_FLAVOR_STANDALONE=0x100, */
/* IDL: 	DFS_VOLUME_FLAVOR_AD_BLOB=0x200, */
/* IDL: } dfs_VolumeFlavor; */

int
netdfs_dissect_enum_dfs_VolumeFlavor(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_index, NULL);
	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	dfs_VolumeFlavor flavor; */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *dom_root; */
/* IDL: } dfs_Info300; */

static int
netdfs_dissect_element_dfs_Info300_flavor(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_enum_dfs_VolumeFlavor(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info300_flavor, 0);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info300_dom_root(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info300_dom_root_, NDR_POINTER_UNIQUE, "Pointer to Dom Root (uint16)",hf_netdfs_dfs_Info300_dom_root);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info300_dom_root_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_Info300_dom_root, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

int
netdfs_dissect_struct_dfs_Info300(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_netdfs_dfs_Info300);
	}
	
	offset = netdfs_dissect_element_dfs_Info300_flavor(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_Info300_dom_root(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef union { */
/* IDL: [case(0)] [unique(1)] [case(0)] dfs_Info0 *info0; */
/* IDL: [case(1)] [unique(1)] [case(1)] dfs_Info1 *info1; */
/* IDL: [case(2)] [unique(1)] [case(2)] dfs_Info2 *info2; */
/* IDL: [case(3)] [unique(1)] [case(3)] dfs_Info3 *info3; */
/* IDL: [case(4)] [unique(1)] [case(4)] dfs_Info4 *info4; */
/* IDL: [case(5)] [unique(1)] [case(5)] dfs_Info5 *info5; */
/* IDL: [case(6)] [unique(1)] [case(6)] dfs_Info6 *info6; */
/* IDL: [case(7)] [unique(1)] [case(7)] dfs_Info7 *info7; */
/* IDL: [case(100)] [unique(1)] [case(100)] dfs_Info100 *info100; */
/* IDL: [case(101)] [unique(1)] [case(101)] dfs_Info101 *info101; */
/* IDL: [case(102)] [unique(1)] [case(102)] dfs_Info102 *info102; */
/* IDL: [case(103)] [unique(1)] [case(103)] dfs_Info103 *info103; */
/* IDL: [case(104)] [unique(1)] [case(104)] dfs_Info104 *info104; */
/* IDL: [case(105)] [unique(1)] [case(105)] dfs_Info105 *info105; */
/* IDL: [case(106)] [unique(1)] [case(106)] dfs_Info106 *info106; */
/* IDL: } dfs_Info; */

static int
netdfs_dissect_element_dfs_Info_info0(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info_info0_, NDR_POINTER_UNIQUE, "Pointer to Info0 (dfs_Info0)",hf_netdfs_dfs_Info_info0);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info_info0_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_Info0(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_Info_info0,0);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info_info1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info_info1_, NDR_POINTER_UNIQUE, "Pointer to Info1 (dfs_Info1)",hf_netdfs_dfs_Info_info1);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info_info1_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_Info1(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_Info_info1,0);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info_info2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info_info2_, NDR_POINTER_UNIQUE, "Pointer to Info2 (dfs_Info2)",hf_netdfs_dfs_Info_info2);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info_info2_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_Info2(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_Info_info2,0);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info_info3(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info_info3_, NDR_POINTER_UNIQUE, "Pointer to Info3 (dfs_Info3)",hf_netdfs_dfs_Info_info3);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info_info3_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_Info3(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_Info_info3,0);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info_info4(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info_info4_, NDR_POINTER_UNIQUE, "Pointer to Info4 (dfs_Info4)",hf_netdfs_dfs_Info_info4);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info_info4_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_Info4(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_Info_info4,0);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info_info5(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info_info5_, NDR_POINTER_UNIQUE, "Pointer to Info5 (dfs_Info5)",hf_netdfs_dfs_Info_info5);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info_info5_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_Info5(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_Info_info5,0);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info_info6(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info_info6_, NDR_POINTER_UNIQUE, "Pointer to Info6 (dfs_Info6)",hf_netdfs_dfs_Info_info6);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info_info6_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_Info6(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_Info_info6,0);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info_info7(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info_info7_, NDR_POINTER_UNIQUE, "Pointer to Info7 (dfs_Info7)",hf_netdfs_dfs_Info_info7);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info_info7_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_Info7(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_Info_info7,0);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info_info100(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info_info100_, NDR_POINTER_UNIQUE, "Pointer to Info100 (dfs_Info100)",hf_netdfs_dfs_Info_info100);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info_info100_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_Info100(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_Info_info100,0);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info_info101(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info_info101_, NDR_POINTER_UNIQUE, "Pointer to Info101 (dfs_Info101)",hf_netdfs_dfs_Info_info101);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info_info101_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_Info101(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_Info_info101,0);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info_info102(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info_info102_, NDR_POINTER_UNIQUE, "Pointer to Info102 (dfs_Info102)",hf_netdfs_dfs_Info_info102);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info_info102_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_Info102(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_Info_info102,0);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info_info103(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info_info103_, NDR_POINTER_UNIQUE, "Pointer to Info103 (dfs_Info103)",hf_netdfs_dfs_Info_info103);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info_info103_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_Info103(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_Info_info103,0);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info_info104(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info_info104_, NDR_POINTER_UNIQUE, "Pointer to Info104 (dfs_Info104)",hf_netdfs_dfs_Info_info104);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info_info104_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_Info104(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_Info_info104,0);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info_info105(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info_info105_, NDR_POINTER_UNIQUE, "Pointer to Info105 (dfs_Info105)",hf_netdfs_dfs_Info_info105);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info_info105_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_Info105(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_Info_info105,0);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info_info106(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Info_info106_, NDR_POINTER_UNIQUE, "Pointer to Info106 (dfs_Info106)",hf_netdfs_dfs_Info_info106);

	return offset;
}

static int
netdfs_dissect_element_dfs_Info_info106_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_Info106(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_Info_info106,0);

	return offset;
}

static int
netdfs_dissect_dfs_Info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;
	guint32 level;

	ALIGN_TO_4_BYTES;

	old_offset = offset;
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1, "dfs_Info");
		tree = proto_item_add_subtree(item, ett_netdfs_dfs_Info);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_index, &level);
	switch(level) {
		case 0:
			offset = netdfs_dissect_element_dfs_Info_info0(tvb, offset, pinfo, tree, drep);
		break;

		case 1:
			offset = netdfs_dissect_element_dfs_Info_info1(tvb, offset, pinfo, tree, drep);
		break;

		case 2:
			offset = netdfs_dissect_element_dfs_Info_info2(tvb, offset, pinfo, tree, drep);
		break;

		case 3:
			offset = netdfs_dissect_element_dfs_Info_info3(tvb, offset, pinfo, tree, drep);
		break;

		case 4:
			offset = netdfs_dissect_element_dfs_Info_info4(tvb, offset, pinfo, tree, drep);
		break;

		case 5:
			offset = netdfs_dissect_element_dfs_Info_info5(tvb, offset, pinfo, tree, drep);
		break;

		case 6:
			offset = netdfs_dissect_element_dfs_Info_info6(tvb, offset, pinfo, tree, drep);
		break;

		case 7:
			offset = netdfs_dissect_element_dfs_Info_info7(tvb, offset, pinfo, tree, drep);
		break;

		case 100:
			offset = netdfs_dissect_element_dfs_Info_info100(tvb, offset, pinfo, tree, drep);
		break;

		case 101:
			offset = netdfs_dissect_element_dfs_Info_info101(tvb, offset, pinfo, tree, drep);
		break;

		case 102:
			offset = netdfs_dissect_element_dfs_Info_info102(tvb, offset, pinfo, tree, drep);
		break;

		case 103:
			offset = netdfs_dissect_element_dfs_Info_info103(tvb, offset, pinfo, tree, drep);
		break;

		case 104:
			offset = netdfs_dissect_element_dfs_Info_info104(tvb, offset, pinfo, tree, drep);
		break;

		case 105:
			offset = netdfs_dissect_element_dfs_Info_info105(tvb, offset, pinfo, tree, drep);
		break;

		case 106:
			offset = netdfs_dissect_element_dfs_Info_info106(tvb, offset, pinfo, tree, drep);
		break;
	}
	proto_item_set_len(item, offset-old_offset);

	return offset;
}
/* IDL: typedef struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[size_is(count)] [unique(1)] dfs_Info1 *s; */
/* IDL: } dfs_EnumArray1; */

static int
netdfs_dissect_element_dfs_EnumArray1_count(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_EnumArray1_count,NULL);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumArray1_s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_EnumArray1_s_, NDR_POINTER_UNIQUE, "Pointer to S (dfs_Info1)",hf_netdfs_dfs_EnumArray1_s);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumArray1_s_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_EnumArray1_s__);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumArray1_s__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_Info1(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_EnumArray1_s,0);

	return offset;
}

int
netdfs_dissect_struct_dfs_EnumArray1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_netdfs_dfs_EnumArray1);
	}
	
	offset = netdfs_dissect_element_dfs_EnumArray1_count(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_EnumArray1_s(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[size_is(count)] [unique(1)] dfs_Info2 *s; */
/* IDL: } dfs_EnumArray2; */

static int
netdfs_dissect_element_dfs_EnumArray2_count(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_EnumArray2_count,NULL);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumArray2_s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_EnumArray2_s_, NDR_POINTER_UNIQUE, "Pointer to S (dfs_Info2)",hf_netdfs_dfs_EnumArray2_s);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumArray2_s_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_EnumArray2_s__);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumArray2_s__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_Info2(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_EnumArray2_s,0);

	return offset;
}

int
netdfs_dissect_struct_dfs_EnumArray2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_netdfs_dfs_EnumArray2);
	}
	
	offset = netdfs_dissect_element_dfs_EnumArray2_count(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_EnumArray2_s(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[size_is(count)] [unique(1)] dfs_Info3 *s; */
/* IDL: } dfs_EnumArray3; */

static int
netdfs_dissect_element_dfs_EnumArray3_count(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_EnumArray3_count,NULL);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumArray3_s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_EnumArray3_s_, NDR_POINTER_UNIQUE, "Pointer to S (dfs_Info3)",hf_netdfs_dfs_EnumArray3_s);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumArray3_s_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_EnumArray3_s__);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumArray3_s__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_Info3(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_EnumArray3_s,0);

	return offset;
}

int
netdfs_dissect_struct_dfs_EnumArray3(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_netdfs_dfs_EnumArray3);
	}
	
	offset = netdfs_dissect_element_dfs_EnumArray3_count(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_EnumArray3_s(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[size_is(count)] [unique(1)] dfs_Info4 *s; */
/* IDL: } dfs_EnumArray4; */

static int
netdfs_dissect_element_dfs_EnumArray4_count(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_EnumArray4_count,NULL);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumArray4_s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_EnumArray4_s_, NDR_POINTER_UNIQUE, "Pointer to S (dfs_Info4)",hf_netdfs_dfs_EnumArray4_s);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumArray4_s_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_EnumArray4_s__);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumArray4_s__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_Info4(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_EnumArray4_s,0);

	return offset;
}

int
netdfs_dissect_struct_dfs_EnumArray4(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_netdfs_dfs_EnumArray4);
	}
	
	offset = netdfs_dissect_element_dfs_EnumArray4_count(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_EnumArray4_s(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[size_is(count)] [unique(1)] dfs_Info200 *s; */
/* IDL: } dfs_EnumArray200; */

static int
netdfs_dissect_element_dfs_EnumArray200_count(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_EnumArray200_count,NULL);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumArray200_s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_EnumArray200_s_, NDR_POINTER_UNIQUE, "Pointer to S (dfs_Info200)",hf_netdfs_dfs_EnumArray200_s);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumArray200_s_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_EnumArray200_s__);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumArray200_s__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_Info200(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_EnumArray200_s,0);

	return offset;
}

int
netdfs_dissect_struct_dfs_EnumArray200(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_netdfs_dfs_EnumArray200);
	}
	
	offset = netdfs_dissect_element_dfs_EnumArray200_count(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_EnumArray200_s(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[size_is(count)] [unique(1)] dfs_Info300 *s; */
/* IDL: } dfs_EnumArray300; */

static int
netdfs_dissect_element_dfs_EnumArray300_count(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_EnumArray300_count,NULL);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumArray300_s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_EnumArray300_s_, NDR_POINTER_UNIQUE, "Pointer to S (dfs_Info300)",hf_netdfs_dfs_EnumArray300_s);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumArray300_s_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_EnumArray300_s__);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumArray300_s__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_Info300(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_EnumArray300_s,0);

	return offset;
}

int
netdfs_dissect_struct_dfs_EnumArray300(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_netdfs_dfs_EnumArray300);
	}
	
	offset = netdfs_dissect_element_dfs_EnumArray300_count(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_EnumArray300_s(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef union { */
/* IDL: [case(1)] [unique(1)] [case(1)] dfs_EnumArray1 *info1; */
/* IDL: [case(2)] [unique(1)] [case(2)] dfs_EnumArray2 *info2; */
/* IDL: [case(3)] [unique(1)] [case(3)] dfs_EnumArray3 *info3; */
/* IDL: [case(4)] [unique(1)] [case(4)] dfs_EnumArray4 *info4; */
/* IDL: [case(200)] [unique(1)] [case(200)] dfs_EnumArray200 *info200; */
/* IDL: [case(300)] [unique(1)] [case(300)] dfs_EnumArray300 *info300; */
/* IDL: } dfs_EnumInfo; */

static int
netdfs_dissect_element_dfs_EnumInfo_info1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_EnumInfo_info1_, NDR_POINTER_UNIQUE, "Pointer to Info1 (dfs_EnumArray1)",hf_netdfs_dfs_EnumInfo_info1);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumInfo_info1_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_EnumArray1(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_EnumInfo_info1,0);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumInfo_info2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_EnumInfo_info2_, NDR_POINTER_UNIQUE, "Pointer to Info2 (dfs_EnumArray2)",hf_netdfs_dfs_EnumInfo_info2);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumInfo_info2_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_EnumArray2(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_EnumInfo_info2,0);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumInfo_info3(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_EnumInfo_info3_, NDR_POINTER_UNIQUE, "Pointer to Info3 (dfs_EnumArray3)",hf_netdfs_dfs_EnumInfo_info3);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumInfo_info3_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_EnumArray3(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_EnumInfo_info3,0);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumInfo_info4(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_EnumInfo_info4_, NDR_POINTER_UNIQUE, "Pointer to Info4 (dfs_EnumArray4)",hf_netdfs_dfs_EnumInfo_info4);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumInfo_info4_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_EnumArray4(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_EnumInfo_info4,0);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumInfo_info200(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_EnumInfo_info200_, NDR_POINTER_UNIQUE, "Pointer to Info200 (dfs_EnumArray200)",hf_netdfs_dfs_EnumInfo_info200);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumInfo_info200_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_EnumArray200(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_EnumInfo_info200,0);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumInfo_info300(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_EnumInfo_info300_, NDR_POINTER_UNIQUE, "Pointer to Info300 (dfs_EnumArray300)",hf_netdfs_dfs_EnumInfo_info300);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumInfo_info300_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_EnumArray300(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_EnumInfo_info300,0);

	return offset;
}

static int
netdfs_dissect_dfs_EnumInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;
	guint32 level;

	ALIGN_TO_4_BYTES;

	old_offset = offset;
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1, "dfs_EnumInfo");
		tree = proto_item_add_subtree(item, ett_netdfs_dfs_EnumInfo);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_index, &level);
	switch(level) {
		case 1:
			offset = netdfs_dissect_element_dfs_EnumInfo_info1(tvb, offset, pinfo, tree, drep);
		break;

		case 2:
			offset = netdfs_dissect_element_dfs_EnumInfo_info2(tvb, offset, pinfo, tree, drep);
		break;

		case 3:
			offset = netdfs_dissect_element_dfs_EnumInfo_info3(tvb, offset, pinfo, tree, drep);
		break;

		case 4:
			offset = netdfs_dissect_element_dfs_EnumInfo_info4(tvb, offset, pinfo, tree, drep);
		break;

		case 200:
			offset = netdfs_dissect_element_dfs_EnumInfo_info200(tvb, offset, pinfo, tree, drep);
		break;

		case 300:
			offset = netdfs_dissect_element_dfs_EnumInfo_info300(tvb, offset, pinfo, tree, drep);
		break;
	}
	proto_item_set_len(item, offset-old_offset);

	return offset;
}
/* IDL: typedef struct { */
/* IDL: 	uint32 level; */
/* IDL: 	[switch_is(level)] dfs_EnumInfo e; */
/* IDL: } dfs_EnumStruct; */

static int
netdfs_dissect_element_dfs_EnumStruct_level(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_EnumStruct_level,NULL);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumStruct_e(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_dfs_EnumInfo(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_EnumStruct_e, 0);

	return offset;
}

int
netdfs_dissect_struct_dfs_EnumStruct(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_netdfs_dfs_EnumStruct);
	}
	
	offset = netdfs_dissect_element_dfs_EnumStruct_level(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_EnumStruct_e(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	uint32 unknown1; */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *unknown2; */
/* IDL: } dfs_UnknownStruct; */

static int
netdfs_dissect_element_dfs_UnknownStruct_unknown1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_UnknownStruct_unknown1,NULL);

	return offset;
}

static int
netdfs_dissect_element_dfs_UnknownStruct_unknown2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_UnknownStruct_unknown2_, NDR_POINTER_UNIQUE, "Pointer to Unknown2 (uint16)",hf_netdfs_dfs_UnknownStruct_unknown2);

	return offset;
}

static int
netdfs_dissect_element_dfs_UnknownStruct_unknown2_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_UnknownStruct_unknown2, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

int
netdfs_dissect_struct_dfs_UnknownStruct(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_netdfs_dfs_UnknownStruct);
	}
	
	offset = netdfs_dissect_element_dfs_UnknownStruct_unknown1(tvb, offset, pinfo, tree, drep);

	offset = netdfs_dissect_element_dfs_UnknownStruct_unknown2(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

static int
netdfs_dissect_element_dfs_GetManagerVersion_version(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_GetManagerVersion_version_, NDR_POINTER_REF, "Pointer to Version (dfs_ManagerVersion)",hf_netdfs_dfs_GetManagerVersion_version);

	return offset;
}

static int
netdfs_dissect_element_dfs_GetManagerVersion_version_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_enum_dfs_ManagerVersion(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_GetManagerVersion_version, 0);

	return offset;
}

/* IDL: void dfs_GetManagerVersion( */
/* IDL: [out] [ref] dfs_ManagerVersion *version */
/* IDL: ); */

static int
netdfs_dissect_dfs_GetManagerVersion_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = netdfs_dissect_element_dfs_GetManagerVersion_version(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	return offset;
}

static int
netdfs_dissect_dfs_GetManagerVersion_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

static int
netdfs_dissect_element_dfs_Add_path(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Add_path_, NDR_POINTER_REF, "Pointer to Path (uint16)",hf_netdfs_dfs_Add_path);

	return offset;
}

static int
netdfs_dissect_element_dfs_Add_path_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_Add_path, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_Add_server(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Add_server_, NDR_POINTER_REF, "Pointer to Server (uint16)",hf_netdfs_dfs_Add_server);

	return offset;
}

static int
netdfs_dissect_element_dfs_Add_server_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_Add_server, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_Add_share(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Add_share_, NDR_POINTER_UNIQUE, "Pointer to Share (uint16)",hf_netdfs_dfs_Add_share);

	return offset;
}

static int
netdfs_dissect_element_dfs_Add_share_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_Add_share, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_Add_comment(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Add_comment_, NDR_POINTER_UNIQUE, "Pointer to Comment (uint16)",hf_netdfs_dfs_Add_comment);

	return offset;
}

static int
netdfs_dissect_element_dfs_Add_comment_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_Add_comment, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_Add_flags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Add_flags,NULL);

	return offset;
}

/* IDL: WERROR dfs_Add( */
/* IDL: [charset(UTF16)] [in] [ref] uint16 *path, */
/* IDL: [charset(UTF16)] [in] [ref] uint16 *server, */
/* IDL: [charset(UTF16)] [unique(1)] [in] uint16 *share, */
/* IDL: [charset(UTF16)] [unique(1)] [in] uint16 *comment, */
/* IDL: [in] uint32 flags */
/* IDL: ); */

static int
netdfs_dissect_dfs_Add_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_Add_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = netdfs_dissect_element_dfs_Add_path(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_Add_server(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_Add_share(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_Add_comment(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_Add_flags(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
netdfs_dissect_element_dfs_Remove_dfs_entry_path(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Remove_dfs_entry_path_, NDR_POINTER_REF, "Pointer to Dfs Entry Path (uint16)",hf_netdfs_dfs_Remove_dfs_entry_path);

	return offset;
}

static int
netdfs_dissect_element_dfs_Remove_dfs_entry_path_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_Remove_dfs_entry_path, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_Remove_servername(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Remove_servername_, NDR_POINTER_UNIQUE, "Pointer to Servername (uint16)",hf_netdfs_dfs_Remove_servername);

	return offset;
}

static int
netdfs_dissect_element_dfs_Remove_servername_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_Remove_servername, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_Remove_sharename(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Remove_sharename_, NDR_POINTER_UNIQUE, "Pointer to Sharename (uint16)",hf_netdfs_dfs_Remove_sharename);

	return offset;
}

static int
netdfs_dissect_element_dfs_Remove_sharename_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_Remove_sharename, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

/* IDL: WERROR dfs_Remove( */
/* IDL: [charset(UTF16)] [in] [ref] uint16 *dfs_entry_path, */
/* IDL: [charset(UTF16)] [unique(1)] [in] uint16 *servername, */
/* IDL: [charset(UTF16)] [unique(1)] [in] uint16 *sharename */
/* IDL: ); */

static int
netdfs_dissect_dfs_Remove_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_Remove_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = netdfs_dissect_element_dfs_Remove_dfs_entry_path(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_Remove_servername(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_Remove_sharename(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
netdfs_dissect_element_dfs_SetInfo_dfs_entry_path(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_SetInfo_dfs_entry_path, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_SetInfo_servername(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_SetInfo_servername_, NDR_POINTER_UNIQUE, "Pointer to Servername (uint16)",hf_netdfs_dfs_SetInfo_servername);

	return offset;
}

static int
netdfs_dissect_element_dfs_SetInfo_servername_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_SetInfo_servername, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_SetInfo_sharename(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_SetInfo_sharename_, NDR_POINTER_UNIQUE, "Pointer to Sharename (uint16)",hf_netdfs_dfs_SetInfo_sharename);

	return offset;
}

static int
netdfs_dissect_element_dfs_SetInfo_sharename_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_SetInfo_sharename, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_SetInfo_level(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_SetInfo_level,NULL);

	return offset;
}

static int
netdfs_dissect_element_dfs_SetInfo_info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_SetInfo_info_, NDR_POINTER_REF, "Pointer to Info (dfs_Info)",hf_netdfs_dfs_SetInfo_info);

	return offset;
}

static int
netdfs_dissect_element_dfs_SetInfo_info_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_dfs_Info(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_SetInfo_info, 0);

	return offset;
}

/* IDL: WERROR dfs_SetInfo( */
/* IDL: [charset(UTF16)] [in] uint16 dfs_entry_path[*], */
/* IDL: [charset(UTF16)] [unique(1)] [in] uint16 *servername, */
/* IDL: [charset(UTF16)] [unique(1)] [in] uint16 *sharename, */
/* IDL: [in] uint32 level, */
/* IDL: [switch_is(level)] [in] [ref] dfs_Info *info */
/* IDL: ); */

static int
netdfs_dissect_dfs_SetInfo_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_SetInfo_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = netdfs_dissect_element_dfs_SetInfo_dfs_entry_path(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_SetInfo_servername(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_SetInfo_sharename(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_SetInfo_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_SetInfo_info(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
netdfs_dissect_element_dfs_GetInfo_dfs_entry_path(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_GetInfo_dfs_entry_path, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_GetInfo_servername(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_GetInfo_servername_, NDR_POINTER_UNIQUE, "Pointer to Servername (uint16)",hf_netdfs_dfs_GetInfo_servername);

	return offset;
}

static int
netdfs_dissect_element_dfs_GetInfo_servername_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_GetInfo_servername, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_GetInfo_sharename(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_GetInfo_sharename_, NDR_POINTER_UNIQUE, "Pointer to Sharename (uint16)",hf_netdfs_dfs_GetInfo_sharename);

	return offset;
}

static int
netdfs_dissect_element_dfs_GetInfo_sharename_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_GetInfo_sharename, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_GetInfo_level(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_GetInfo_level,NULL);

	return offset;
}

static int
netdfs_dissect_element_dfs_GetInfo_info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_GetInfo_info_, NDR_POINTER_REF, "Pointer to Info (dfs_Info)",hf_netdfs_dfs_GetInfo_info);

	return offset;
}

static int
netdfs_dissect_element_dfs_GetInfo_info_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_dfs_Info(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_GetInfo_info, 0);

	return offset;
}

/* IDL: WERROR dfs_GetInfo( */
/* IDL: [charset(UTF16)] [in] uint16 dfs_entry_path[*], */
/* IDL: [charset(UTF16)] [unique(1)] [in] uint16 *servername, */
/* IDL: [charset(UTF16)] [unique(1)] [in] uint16 *sharename, */
/* IDL: [in] uint32 level, */
/* IDL: [switch_is(level)] [out] [ref] dfs_Info *info */
/* IDL: ); */

static int
netdfs_dissect_dfs_GetInfo_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = netdfs_dissect_element_dfs_GetInfo_info(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_GetInfo_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = netdfs_dissect_element_dfs_GetInfo_dfs_entry_path(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_GetInfo_servername(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_GetInfo_sharename(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_GetInfo_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
netdfs_dissect_element_dfs_Enum_level(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Enum_level,NULL);

	return offset;
}

static int
netdfs_dissect_element_dfs_Enum_bufsize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Enum_bufsize,NULL);

	return offset;
}

static int
netdfs_dissect_element_dfs_Enum_info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Enum_info_, NDR_POINTER_UNIQUE, "Pointer to Info (dfs_EnumStruct)",hf_netdfs_dfs_Enum_info);

	return offset;
}

static int
netdfs_dissect_element_dfs_Enum_info_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_EnumStruct(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_Enum_info,0);

	return offset;
}

static int
netdfs_dissect_element_dfs_Enum_total(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Enum_total_, NDR_POINTER_UNIQUE, "Pointer to Total (uint32)",hf_netdfs_dfs_Enum_total);

	return offset;
}

static int
netdfs_dissect_element_dfs_Enum_total_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Enum_total,NULL);

	return offset;
}

/* IDL: WERROR dfs_Enum( */
/* IDL: [in] uint32 level, */
/* IDL: [in] uint32 bufsize, */
/* IDL: [out] [in] [unique(1)] dfs_EnumStruct *info, */
/* IDL: [out] [in] [unique(1)] uint32 *total */
/* IDL: ); */

static int
netdfs_dissect_dfs_Enum_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = netdfs_dissect_element_dfs_Enum_info(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = netdfs_dissect_element_dfs_Enum_total(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_Enum_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = netdfs_dissect_element_dfs_Enum_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_Enum_bufsize(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_Enum_info(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_Enum_total(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

/* IDL: WERROR dfs_Rename( */
/* IDL:  */
/* IDL: ); */

static int
netdfs_dissect_dfs_Rename_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_Rename_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR dfs_Move( */
/* IDL:  */
/* IDL: ); */

static int
netdfs_dissect_dfs_Move_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_Move_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR dfs_ManagerGetConfigInfo( */
/* IDL:  */
/* IDL: ); */

static int
netdfs_dissect_dfs_ManagerGetConfigInfo_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_ManagerGetConfigInfo_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR dfs_ManagerSendSiteInfo( */
/* IDL:  */
/* IDL: ); */

static int
netdfs_dissect_dfs_ManagerSendSiteInfo_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_ManagerSendSiteInfo_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

static int
netdfs_dissect_element_dfs_AddFtRoot_servername(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_AddFtRoot_servername, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_AddFtRoot_dns_servername(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_AddFtRoot_dns_servername, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_AddFtRoot_dfsname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_AddFtRoot_dfsname, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_AddFtRoot_rootshare(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_AddFtRoot_rootshare, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_AddFtRoot_comment(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_AddFtRoot_comment, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_AddFtRoot_dfs_config_dn(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_AddFtRoot_dfs_config_dn, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_AddFtRoot_unknown1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_AddFtRoot_unknown1,NULL);

	return offset;
}

static int
netdfs_dissect_element_dfs_AddFtRoot_flags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_AddFtRoot_flags,NULL);

	return offset;
}

static int
netdfs_dissect_element_dfs_AddFtRoot_unknown2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_AddFtRoot_unknown2_, NDR_POINTER_UNIQUE, "Pointer to Unknown2 (dfs_UnknownStruct)",hf_netdfs_dfs_AddFtRoot_unknown2);

	return offset;
}

static int
netdfs_dissect_element_dfs_AddFtRoot_unknown2_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_AddFtRoot_unknown2__, NDR_POINTER_UNIQUE, "Pointer to Unknown2 (dfs_UnknownStruct)",hf_netdfs_dfs_AddFtRoot_unknown2);

	return offset;
}

static int
netdfs_dissect_element_dfs_AddFtRoot_unknown2__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_UnknownStruct(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_AddFtRoot_unknown2,0);

	return offset;
}

/* IDL: WERROR dfs_AddFtRoot( */
/* IDL: [charset(UTF16)] [in] uint16 servername[*], */
/* IDL: [charset(UTF16)] [in] uint16 dns_servername[*], */
/* IDL: [charset(UTF16)] [in] uint16 dfsname[*], */
/* IDL: [charset(UTF16)] [in] uint16 rootshare[*], */
/* IDL: [charset(UTF16)] [in] uint16 comment[*], */
/* IDL: [charset(UTF16)] [in] uint16 dfs_config_dn[*], */
/* IDL: [in] uint8 unknown1, */
/* IDL: [in] uint32 flags, */
/* IDL: [out] [in] [unique(1)] dfs_UnknownStruct **unknown2 */
/* IDL: ); */

static int
netdfs_dissect_dfs_AddFtRoot_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = netdfs_dissect_element_dfs_AddFtRoot_unknown2(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_AddFtRoot_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = netdfs_dissect_element_dfs_AddFtRoot_servername(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_AddFtRoot_dns_servername(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_AddFtRoot_dfsname(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_AddFtRoot_rootshare(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_AddFtRoot_comment(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_AddFtRoot_dfs_config_dn(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_AddFtRoot_unknown1(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_AddFtRoot_flags(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_AddFtRoot_unknown2(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
netdfs_dissect_element_dfs_RemoveFtRoot_servername(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_RemoveFtRoot_servername, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_RemoveFtRoot_dns_servername(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_RemoveFtRoot_dns_servername, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_RemoveFtRoot_dfsname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_RemoveFtRoot_dfsname, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_RemoveFtRoot_rootshare(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_RemoveFtRoot_rootshare, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_RemoveFtRoot_flags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_RemoveFtRoot_flags,NULL);

	return offset;
}

static int
netdfs_dissect_element_dfs_RemoveFtRoot_unknown(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_RemoveFtRoot_unknown_, NDR_POINTER_UNIQUE, "Pointer to Unknown (dfs_UnknownStruct)",hf_netdfs_dfs_RemoveFtRoot_unknown);

	return offset;
}

static int
netdfs_dissect_element_dfs_RemoveFtRoot_unknown_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_RemoveFtRoot_unknown__, NDR_POINTER_UNIQUE, "Pointer to Unknown (dfs_UnknownStruct)",hf_netdfs_dfs_RemoveFtRoot_unknown);

	return offset;
}

static int
netdfs_dissect_element_dfs_RemoveFtRoot_unknown__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_UnknownStruct(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_RemoveFtRoot_unknown,0);

	return offset;
}

/* IDL: WERROR dfs_RemoveFtRoot( */
/* IDL: [charset(UTF16)] [in] uint16 servername[*], */
/* IDL: [charset(UTF16)] [in] uint16 dns_servername[*], */
/* IDL: [charset(UTF16)] [in] uint16 dfsname[*], */
/* IDL: [charset(UTF16)] [in] uint16 rootshare[*], */
/* IDL: [in] uint32 flags, */
/* IDL: [out] [in] [unique(1)] dfs_UnknownStruct **unknown */
/* IDL: ); */

static int
netdfs_dissect_dfs_RemoveFtRoot_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = netdfs_dissect_element_dfs_RemoveFtRoot_unknown(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_RemoveFtRoot_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = netdfs_dissect_element_dfs_RemoveFtRoot_servername(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_RemoveFtRoot_dns_servername(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_RemoveFtRoot_dfsname(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_RemoveFtRoot_rootshare(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_RemoveFtRoot_flags(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_RemoveFtRoot_unknown(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
netdfs_dissect_element_dfs_AddStdRoot_servername(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_AddStdRoot_servername, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_AddStdRoot_rootshare(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_AddStdRoot_rootshare, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_AddStdRoot_comment(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_AddStdRoot_comment, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_AddStdRoot_flags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_AddStdRoot_flags,NULL);

	return offset;
}

/* IDL: WERROR dfs_AddStdRoot( */
/* IDL: [charset(UTF16)] [in] uint16 servername[*], */
/* IDL: [charset(UTF16)] [in] uint16 rootshare[*], */
/* IDL: [charset(UTF16)] [in] uint16 comment[*], */
/* IDL: [in] uint32 flags */
/* IDL: ); */

static int
netdfs_dissect_dfs_AddStdRoot_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_AddStdRoot_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = netdfs_dissect_element_dfs_AddStdRoot_servername(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_AddStdRoot_rootshare(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_AddStdRoot_comment(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_AddStdRoot_flags(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
netdfs_dissect_element_dfs_RemoveStdRoot_servername(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_RemoveStdRoot_servername, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_RemoveStdRoot_rootshare(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_RemoveStdRoot_rootshare, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_RemoveStdRoot_flags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_RemoveStdRoot_flags,NULL);

	return offset;
}

/* IDL: WERROR dfs_RemoveStdRoot( */
/* IDL: [charset(UTF16)] [in] uint16 servername[*], */
/* IDL: [charset(UTF16)] [in] uint16 rootshare[*], */
/* IDL: [in] uint32 flags */
/* IDL: ); */

static int
netdfs_dissect_dfs_RemoveStdRoot_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_RemoveStdRoot_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = netdfs_dissect_element_dfs_RemoveStdRoot_servername(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_RemoveStdRoot_rootshare(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_RemoveStdRoot_flags(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
netdfs_dissect_element_dfs_ManagerInitialize_servername(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_ManagerInitialize_servername_, NDR_POINTER_REF, "Pointer to Servername (uint16)",hf_netdfs_dfs_ManagerInitialize_servername);

	return offset;
}

static int
netdfs_dissect_element_dfs_ManagerInitialize_servername_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_ManagerInitialize_servername, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_ManagerInitialize_flags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_ManagerInitialize_flags,NULL);

	return offset;
}

/* IDL: WERROR dfs_ManagerInitialize( */
/* IDL: [charset(UTF16)] [in] [ref] uint16 *servername, */
/* IDL: [in] uint32 flags */
/* IDL: ); */

static int
netdfs_dissect_dfs_ManagerInitialize_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_ManagerInitialize_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = netdfs_dissect_element_dfs_ManagerInitialize_servername(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_ManagerInitialize_flags(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
netdfs_dissect_element_dfs_AddStdRootForced_servername(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_AddStdRootForced_servername, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_AddStdRootForced_rootshare(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_AddStdRootForced_rootshare, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_AddStdRootForced_comment(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_AddStdRootForced_comment, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_AddStdRootForced_store(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_AddStdRootForced_store, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

/* IDL: WERROR dfs_AddStdRootForced( */
/* IDL: [charset(UTF16)] [in] uint16 servername[*], */
/* IDL: [charset(UTF16)] [in] uint16 rootshare[*], */
/* IDL: [charset(UTF16)] [in] uint16 comment[*], */
/* IDL: [charset(UTF16)] [in] uint16 store[*] */
/* IDL: ); */

static int
netdfs_dissect_dfs_AddStdRootForced_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_AddStdRootForced_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = netdfs_dissect_element_dfs_AddStdRootForced_servername(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_AddStdRootForced_rootshare(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_AddStdRootForced_comment(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_AddStdRootForced_store(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

/* IDL: WERROR dfs_GetDcAddress( */
/* IDL:  */
/* IDL: ); */

static int
netdfs_dissect_dfs_GetDcAddress_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_GetDcAddress_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR dfs_SetDcAddress( */
/* IDL:  */
/* IDL: ); */

static int
netdfs_dissect_dfs_SetDcAddress_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_SetDcAddress_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

static int
netdfs_dissect_element_dfs_FlushFtTable_servername(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_FlushFtTable_servername, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_FlushFtTable_rootshare(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_FlushFtTable_rootshare, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

/* IDL: WERROR dfs_FlushFtTable( */
/* IDL: [charset(UTF16)] [in] uint16 servername[*], */
/* IDL: [charset(UTF16)] [in] uint16 rootshare[*] */
/* IDL: ); */

static int
netdfs_dissect_dfs_FlushFtTable_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_FlushFtTable_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = netdfs_dissect_element_dfs_FlushFtTable_servername(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_FlushFtTable_rootshare(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

/* IDL: WERROR dfs_Add2( */
/* IDL:  */
/* IDL: ); */

static int
netdfs_dissect_dfs_Add2_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_Add2_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR dfs_Remove2( */
/* IDL:  */
/* IDL: ); */

static int
netdfs_dissect_dfs_Remove2_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_Remove2_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

static int
netdfs_dissect_element_dfs_EnumEx_dfs_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_EnumEx_dfs_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumEx_level(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_EnumEx_level,NULL);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumEx_bufsize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_EnumEx_bufsize,NULL);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumEx_info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_EnumEx_info_, NDR_POINTER_UNIQUE, "Pointer to Info (dfs_EnumStruct)",hf_netdfs_dfs_EnumEx_info);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumEx_info_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = netdfs_dissect_struct_dfs_EnumStruct(tvb,offset,pinfo,tree,drep,hf_netdfs_dfs_EnumEx_info,0);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumEx_total(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_EnumEx_total_, NDR_POINTER_UNIQUE, "Pointer to Total (uint32)",hf_netdfs_dfs_EnumEx_total);

	return offset;
}

static int
netdfs_dissect_element_dfs_EnumEx_total_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_EnumEx_total,NULL);

	return offset;
}

/* IDL: WERROR dfs_EnumEx( */
/* IDL: [charset(UTF16)] [in] uint16 dfs_name[*], */
/* IDL: [in] uint32 level, */
/* IDL: [in] uint32 bufsize, */
/* IDL: [out] [in] [unique(1)] dfs_EnumStruct *info, */
/* IDL: [out] [in] [unique(1)] uint32 *total */
/* IDL: ); */

static int
netdfs_dissect_dfs_EnumEx_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = netdfs_dissect_element_dfs_EnumEx_info(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = netdfs_dissect_element_dfs_EnumEx_total(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_EnumEx_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = netdfs_dissect_element_dfs_EnumEx_dfs_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_EnumEx_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_EnumEx_bufsize(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_EnumEx_info(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_EnumEx_total(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

/* IDL: WERROR dfs_SetInfo2( */
/* IDL:  */
/* IDL: ); */

static int
netdfs_dissect_dfs_SetInfo2_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_SetInfo2_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}


static dcerpc_sub_dissector netdfs_dissectors[] = {
	{ 0, "dfs_GetManagerVersion",
	   netdfs_dissect_dfs_GetManagerVersion_request, netdfs_dissect_dfs_GetManagerVersion_response},
	{ 1, "dfs_Add",
	   netdfs_dissect_dfs_Add_request, netdfs_dissect_dfs_Add_response},
	{ 2, "dfs_Remove",
	   netdfs_dissect_dfs_Remove_request, netdfs_dissect_dfs_Remove_response},
	{ 3, "dfs_SetInfo",
	   netdfs_dissect_dfs_SetInfo_request, netdfs_dissect_dfs_SetInfo_response},
	{ 4, "dfs_GetInfo",
	   netdfs_dissect_dfs_GetInfo_request, netdfs_dissect_dfs_GetInfo_response},
	{ 5, "dfs_Enum",
	   netdfs_dissect_dfs_Enum_request, netdfs_dissect_dfs_Enum_response},
	{ 6, "dfs_Rename",
	   netdfs_dissect_dfs_Rename_request, netdfs_dissect_dfs_Rename_response},
	{ 7, "dfs_Move",
	   netdfs_dissect_dfs_Move_request, netdfs_dissect_dfs_Move_response},
	{ 8, "dfs_ManagerGetConfigInfo",
	   netdfs_dissect_dfs_ManagerGetConfigInfo_request, netdfs_dissect_dfs_ManagerGetConfigInfo_response},
	{ 9, "dfs_ManagerSendSiteInfo",
	   netdfs_dissect_dfs_ManagerSendSiteInfo_request, netdfs_dissect_dfs_ManagerSendSiteInfo_response},
	{ 10, "dfs_AddFtRoot",
	   netdfs_dissect_dfs_AddFtRoot_request, netdfs_dissect_dfs_AddFtRoot_response},
	{ 11, "dfs_RemoveFtRoot",
	   netdfs_dissect_dfs_RemoveFtRoot_request, netdfs_dissect_dfs_RemoveFtRoot_response},
	{ 12, "dfs_AddStdRoot",
	   netdfs_dissect_dfs_AddStdRoot_request, netdfs_dissect_dfs_AddStdRoot_response},
	{ 13, "dfs_RemoveStdRoot",
	   netdfs_dissect_dfs_RemoveStdRoot_request, netdfs_dissect_dfs_RemoveStdRoot_response},
	{ 14, "dfs_ManagerInitialize",
	   netdfs_dissect_dfs_ManagerInitialize_request, netdfs_dissect_dfs_ManagerInitialize_response},
	{ 15, "dfs_AddStdRootForced",
	   netdfs_dissect_dfs_AddStdRootForced_request, netdfs_dissect_dfs_AddStdRootForced_response},
	{ 16, "dfs_GetDcAddress",
	   netdfs_dissect_dfs_GetDcAddress_request, netdfs_dissect_dfs_GetDcAddress_response},
	{ 17, "dfs_SetDcAddress",
	   netdfs_dissect_dfs_SetDcAddress_request, netdfs_dissect_dfs_SetDcAddress_response},
	{ 18, "dfs_FlushFtTable",
	   netdfs_dissect_dfs_FlushFtTable_request, netdfs_dissect_dfs_FlushFtTable_response},
	{ 19, "dfs_Add2",
	   netdfs_dissect_dfs_Add2_request, netdfs_dissect_dfs_Add2_response},
	{ 20, "dfs_Remove2",
	   netdfs_dissect_dfs_Remove2_request, netdfs_dissect_dfs_Remove2_response},
	{ 21, "dfs_EnumEx",
	   netdfs_dissect_dfs_EnumEx_request, netdfs_dissect_dfs_EnumEx_response},
	{ 22, "dfs_SetInfo2",
	   netdfs_dissect_dfs_SetInfo2_request, netdfs_dissect_dfs_SetInfo2_response},
	{ 0, NULL, NULL, NULL }
};

void proto_register_dcerpc_netdfs(void)
{
	static hf_register_info hf[] = {
	{ &hf_netdfs_dfs_EnumEx_level, 
	  { "Level", "netdfs.dfs_EnumEx.level", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info5_pktsize, 
	  { "Pktsize", "netdfs.dfs_Info5.pktsize", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_StorageState_DFS_STORAGE_STATE_ONLINE, 
	  { "Dfs Storage State Online", "netdfs.dfs_StorageState.DFS_STORAGE_STATE_ONLINE", FT_BOOLEAN, 32, TFS(&dfs_StorageState_DFS_STORAGE_STATE_ONLINE_tfs), ( 2 ), "", HFILL }},
	{ &hf_netdfs_dfs_EnumEx_bufsize, 
	  { "Bufsize", "netdfs.dfs_EnumEx.bufsize", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info4_comment, 
	  { "Comment", "netdfs.dfs_Info4.comment", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_AddFtRoot_dns_servername, 
	  { "Dns Servername", "netdfs.dfs_AddFtRoot.dns_servername", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_PropertyFlags_DFS_PROPERTY_FLAG_SITE_COSTING, 
	  { "Dfs Property Flag Site Costing", "netdfs.dfs_PropertyFlags.DFS_PROPERTY_FLAG_SITE_COSTING", FT_BOOLEAN, 32, TFS(&dfs_PropertyFlags_DFS_PROPERTY_FLAG_SITE_COSTING_tfs), ( 0x04 ), "", HFILL }},
	{ &hf_netdfs_dfs_PropertyFlags_DFS_PROPERTY_FLAG_ROOT_SCALABILITY, 
	  { "Dfs Property Flag Root Scalability", "netdfs.dfs_PropertyFlags.DFS_PROPERTY_FLAG_ROOT_SCALABILITY", FT_BOOLEAN, 32, TFS(&dfs_PropertyFlags_DFS_PROPERTY_FLAG_ROOT_SCALABILITY_tfs), ( 0x02 ), "", HFILL }},
	{ &hf_netdfs_dfs_VolumeState_DFS_VOLUME_STATE_OFFLINE, 
	  { "Dfs Volume State Offline", "netdfs.dfs_VolumeState.DFS_VOLUME_STATE_OFFLINE", FT_BOOLEAN, 32, TFS(&dfs_VolumeState_DFS_VOLUME_STATE_OFFLINE_tfs), ( 0x4 ), "", HFILL }},
	{ &hf_netdfs_dfs_Info5_guid, 
	  { "Guid", "netdfs.dfs_Info5.guid", FT_GUID, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Target_Priority_target_priority_rank, 
	  { "Target Priority Rank", "netdfs.dfs_Target_Priority.target_priority_rank", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_AddStdRootForced_servername, 
	  { "Servername", "netdfs.dfs_AddStdRootForced.servername", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumInfo_info200, 
	  { "Info200", "netdfs.dfs_EnumInfo.info200", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_PropertyFlags_DFS_PROPERTY_FLAG_TARGET_FAILBACK, 
	  { "Dfs Property Flag Target Failback", "netdfs.dfs_PropertyFlags.DFS_PROPERTY_FLAG_TARGET_FAILBACK", FT_BOOLEAN, 32, TFS(&dfs_PropertyFlags_DFS_PROPERTY_FLAG_TARGET_FAILBACK_tfs), ( 0x08 ), "", HFILL }},
	{ &hf_netdfs_dfs_Target_Priority_reserved, 
	  { "Reserved", "netdfs.dfs_Target_Priority.reserved", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Enum_bufsize, 
	  { "Bufsize", "netdfs.dfs_Enum.bufsize", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_AddStdRootForced_rootshare, 
	  { "Rootshare", "netdfs.dfs_AddStdRootForced.rootshare", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_RemoveFtRoot_servername, 
	  { "Servername", "netdfs.dfs_RemoveFtRoot.servername", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_AddFtRoot_unknown1, 
	  { "Unknown1", "netdfs.dfs_AddFtRoot.unknown1", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumArray4_s, 
	  { "S", "netdfs.dfs_EnumArray4.s", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_AddFtRoot_unknown2, 
	  { "Unknown2", "netdfs.dfs_AddFtRoot.unknown2", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info6_comment, 
	  { "Comment", "netdfs.dfs_Info6.comment", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info6_entry_path, 
	  { "Entry Path", "netdfs.dfs_Info6.entry_path", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info1_path, 
	  { "Path", "netdfs.dfs_Info1.path", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumStruct_level, 
	  { "Level", "netdfs.dfs_EnumStruct.level", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_GetInfo_sharename, 
	  { "Sharename", "netdfs.dfs_GetInfo.sharename", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info105_comment, 
	  { "Comment", "netdfs.dfs_Info105.comment", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_AddStdRoot_rootshare, 
	  { "Rootshare", "netdfs.dfs_AddStdRoot.rootshare", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_SetInfo_level, 
	  { "Level", "netdfs.dfs_SetInfo.level", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info6_flags, 
	  { "Flags", "netdfs.dfs_Info6.flags", FT_UINT32, BASE_HEX, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info4_state, 
	  { "State", "netdfs.dfs_Info4.state", FT_UINT32, BASE_HEX, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info4_guid, 
	  { "Guid", "netdfs.dfs_Info4.guid", FT_GUID, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info105_property_flags, 
	  { "Property Flags", "netdfs.dfs_Info105.property_flags", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Enum_total, 
	  { "Total", "netdfs.dfs_Enum.total", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumStruct_e, 
	  { "E", "netdfs.dfs_EnumStruct.e", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumArray4_count, 
	  { "Count", "netdfs.dfs_EnumArray4.count", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_StorageInfo2_info, 
	  { "Info", "netdfs.dfs_StorageInfo2.info", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info105_state, 
	  { "State", "netdfs.dfs_Info105.state", FT_UINT32, BASE_HEX, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_FlushFtTable_servername, 
	  { "Servername", "netdfs.dfs_FlushFtTable.servername", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info4_stores, 
	  { "Stores", "netdfs.dfs_Info4.stores", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info4_num_stores, 
	  { "Num Stores", "netdfs.dfs_Info4.num_stores", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_GetInfo_dfs_entry_path, 
	  { "Dfs Entry Path", "netdfs.dfs_GetInfo.dfs_entry_path", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumArray1_count, 
	  { "Count", "netdfs.dfs_EnumArray1.count", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_StorageInfo_state, 
	  { "State", "netdfs.dfs_StorageInfo.state", FT_UINT32, BASE_HEX, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_FlushFtTable_rootshare, 
	  { "Rootshare", "netdfs.dfs_FlushFtTable.rootshare", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_AddStdRoot_servername, 
	  { "Servername", "netdfs.dfs_AddStdRoot.servername", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumArray200_s, 
	  { "S", "netdfs.dfs_EnumArray200.s", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_AddFtRoot_servername, 
	  { "Servername", "netdfs.dfs_AddFtRoot.servername", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info6_stores, 
	  { "Stores", "netdfs.dfs_Info6.stores", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_GetInfo_servername, 
	  { "Servername", "netdfs.dfs_GetInfo.servername", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_StorageInfo2_target_priority, 
	  { "Target Priority", "netdfs.dfs_StorageInfo2.target_priority", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumArray2_s, 
	  { "S", "netdfs.dfs_EnumArray2.s", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_RemoveFtRoot_flags, 
	  { "Flags", "netdfs.dfs_RemoveFtRoot.flags", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumArray200_count, 
	  { "Count", "netdfs.dfs_EnumArray200.count", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumEx_info, 
	  { "Info", "netdfs.dfs_EnumEx.info", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info104_priority, 
	  { "Priority", "netdfs.dfs_Info104.priority", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info4_timeout, 
	  { "Timeout", "netdfs.dfs_Info4.timeout", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_AddFtRoot_comment, 
	  { "Comment", "netdfs.dfs_AddFtRoot.comment", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_PropertyFlags_DFS_PROPERTY_FLAG_CLUSTER_ENABLED, 
	  { "Dfs Property Flag Cluster Enabled", "netdfs.dfs_PropertyFlags.DFS_PROPERTY_FLAG_CLUSTER_ENABLED", FT_BOOLEAN, 32, TFS(&dfs_PropertyFlags_DFS_PROPERTY_FLAG_CLUSTER_ENABLED_tfs), ( 0x10 ), "", HFILL }},
	{ &hf_netdfs_dfs_Enum_info, 
	  { "Info", "netdfs.dfs_Enum.info", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_AddStdRoot_comment, 
	  { "Comment", "netdfs.dfs_AddStdRoot.comment", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_GetInfo_info, 
	  { "Info", "netdfs.dfs_GetInfo.info", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Add_share, 
	  { "Share", "netdfs.dfs_Add.share", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info100_comment, 
	  { "Comment", "netdfs.dfs_Info100.comment", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumInfo_info300, 
	  { "Info300", "netdfs.dfs_EnumInfo.info300", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info6_state, 
	  { "State", "netdfs.dfs_Info6.state", FT_UINT32, BASE_HEX, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_VolumeState_DFS_VOLUME_STATE_AD_BLOB, 
	  { "Dfs Volume State Ad Blob", "netdfs.dfs_VolumeState.DFS_VOLUME_STATE_AD_BLOB", FT_BOOLEAN, 32, TFS(&dfs_VolumeState_DFS_VOLUME_STATE_AD_BLOB_tfs), ( DFS_VOLUME_FLAVOR_AD_BLOB ), "", HFILL }},
	{ &hf_netdfs_dfs_Add_comment, 
	  { "Comment", "netdfs.dfs_Add.comment", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info6_timeout, 
	  { "Timeout", "netdfs.dfs_Info6.timeout", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_RemoveFtRoot_rootshare, 
	  { "Rootshare", "netdfs.dfs_RemoveFtRoot.rootshare", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info105_timeout, 
	  { "Timeout", "netdfs.dfs_Info105.timeout", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info3_comment, 
	  { "Comment", "netdfs.dfs_Info3.comment", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info3_state, 
	  { "State", "netdfs.dfs_Info3.state", FT_UINT32, BASE_HEX, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info5_flags, 
	  { "Flags", "netdfs.dfs_Info5.flags", FT_UINT32, BASE_HEX, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info7_generation_guid, 
	  { "Generation Guid", "netdfs.dfs_Info7.generation_guid", FT_GUID, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_RemoveFtRoot_unknown, 
	  { "Unknown", "netdfs.dfs_RemoveFtRoot.unknown", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumEx_total, 
	  { "Total", "netdfs.dfs_EnumEx.total", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_GetInfo_level, 
	  { "Level", "netdfs.dfs_GetInfo.level", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info5_num_stores, 
	  { "Num Stores", "netdfs.dfs_Info5.num_stores", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info6_pktsize, 
	  { "Pktsize", "netdfs.dfs_Info6.pktsize", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumArray300_s, 
	  { "S", "netdfs.dfs_EnumArray300.s", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Add_server, 
	  { "Server", "netdfs.dfs_Add.server", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info5_comment, 
	  { "Comment", "netdfs.dfs_Info5.comment", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_werror, 
	  { "Windows Error", "netdfs.werror", FT_UINT32, BASE_HEX, VALS(WERR_errors), 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumArray3_count, 
	  { "Count", "netdfs.dfs_EnumArray3.count", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_VolumeState_DFS_VOLUME_STATE_INCONSISTENT, 
	  { "Dfs Volume State Inconsistent", "netdfs.dfs_VolumeState.DFS_VOLUME_STATE_INCONSISTENT", FT_BOOLEAN, 32, TFS(&dfs_VolumeState_DFS_VOLUME_STATE_INCONSISTENT_tfs), ( 0x2 ), "", HFILL }},
	{ &hf_netdfs_dfs_AddFtRoot_rootshare, 
	  { "Rootshare", "netdfs.dfs_AddFtRoot.rootshare", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Add_flags, 
	  { "Flags", "netdfs.dfs_Add.flags", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_RemoveStdRoot_servername, 
	  { "Servername", "netdfs.dfs_RemoveStdRoot.servername", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_RemoveFtRoot_dfsname, 
	  { "Dfsname", "netdfs.dfs_RemoveFtRoot.dfsname", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_AddFtRoot_dfs_config_dn, 
	  { "Dfs Config Dn", "netdfs.dfs_AddFtRoot.dfs_config_dn", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_AddFtRoot_dfsname, 
	  { "Dfsname", "netdfs.dfs_AddFtRoot.dfsname", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Remove_sharename, 
	  { "Sharename", "netdfs.dfs_Remove.sharename", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info101_state, 
	  { "State", "netdfs.dfs_Info101.state", FT_UINT32, BASE_HEX, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info103_flags, 
	  { "Flags", "netdfs.dfs_Info103.flags", FT_UINT32, BASE_HEX, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info200_dom_root, 
	  { "Dom Root", "netdfs.dfs_Info200.dom_root", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_StorageState_DFS_STORAGE_STATE_OFFLINE, 
	  { "Dfs Storage State Offline", "netdfs.dfs_StorageState.DFS_STORAGE_STATE_OFFLINE", FT_BOOLEAN, 32, TFS(&dfs_StorageState_DFS_STORAGE_STATE_OFFLINE_tfs), ( 1 ), "", HFILL }},
	{ &hf_netdfs_dfs_VolumeState_DFS_VOLUME_STATE_ONLINE, 
	  { "Dfs Volume State Online", "netdfs.dfs_VolumeState.DFS_VOLUME_STATE_ONLINE", FT_BOOLEAN, 32, TFS(&dfs_VolumeState_DFS_VOLUME_STATE_ONLINE_tfs), ( 0x8 ), "", HFILL }},
	{ &hf_netdfs_dfs_Info_info0, 
	  { "Info0", "netdfs.dfs_Info.info0", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_SetInfo_servername, 
	  { "Servername", "netdfs.dfs_SetInfo.servername", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info_info1, 
	  { "Info1", "netdfs.dfs_Info.info1", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info2_num_stores, 
	  { "Num Stores", "netdfs.dfs_Info2.num_stores", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info_info2, 
	  { "Info2", "netdfs.dfs_Info.info2", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_RemoveFtRoot_dns_servername, 
	  { "Dns Servername", "netdfs.dfs_RemoveFtRoot.dns_servername", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info_info3, 
	  { "Info3", "netdfs.dfs_Info.info3", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info_info4, 
	  { "Info4", "netdfs.dfs_Info.info4", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info_info5, 
	  { "Info5", "netdfs.dfs_Info.info5", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_StorageState_DFS_STORAGE_STATE_ACTIVE, 
	  { "Dfs Storage State Active", "netdfs.dfs_StorageState.DFS_STORAGE_STATE_ACTIVE", FT_BOOLEAN, 32, TFS(&dfs_StorageState_DFS_STORAGE_STATE_ACTIVE_tfs), ( 4 ), "", HFILL }},
	{ &hf_netdfs_dfs_Info_info6, 
	  { "Info6", "netdfs.dfs_Info.info6", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Enum_level, 
	  { "Level", "netdfs.dfs_Enum.level", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info_info7, 
	  { "Info7", "netdfs.dfs_Info.info7", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info300_flavor, 
	  { "Flavor", "netdfs.dfs_Info300.flavor", FT_UINT16, BASE_DEC, VALS(netdfs_dfs_VolumeFlavor_vals), 0, "", HFILL }},
	{ &hf_netdfs_dfs_AddStdRootForced_store, 
	  { "Store", "netdfs.dfs_AddStdRootForced.store", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info5_path, 
	  { "Path", "netdfs.dfs_Info5.path", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_GetManagerVersion_version, 
	  { "Version", "netdfs.dfs_GetManagerVersion.version", FT_UINT32, BASE_DEC, VALS(netdfs_dfs_ManagerVersion_vals), 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info3_stores, 
	  { "Stores", "netdfs.dfs_Info3.stores", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_VolumeState_DFS_VOLUME_STATE_STANDALONE, 
	  { "Dfs Volume State Standalone", "netdfs.dfs_VolumeState.DFS_VOLUME_STATE_STANDALONE", FT_BOOLEAN, 32, TFS(&dfs_VolumeState_DFS_VOLUME_STATE_STANDALONE_tfs), ( DFS_VOLUME_FLAVOR_STANDALONE ), "", HFILL }},
	{ &hf_netdfs_dfs_EnumArray3_s, 
	  { "S", "netdfs.dfs_EnumArray3.s", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info106_priority, 
	  { "Priority", "netdfs.dfs_Info106.priority", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_UnknownStruct_unknown1, 
	  { "Unknown1", "netdfs.dfs_UnknownStruct.unknown1", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_UnknownStruct_unknown2, 
	  { "Unknown2", "netdfs.dfs_UnknownStruct.unknown2", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_VolumeState_DFS_VOLUME_STATE_OK, 
	  { "Dfs Volume State Ok", "netdfs.dfs_VolumeState.DFS_VOLUME_STATE_OK", FT_BOOLEAN, 32, TFS(&dfs_VolumeState_DFS_VOLUME_STATE_OK_tfs), ( 0x1 ), "", HFILL }},
	{ &hf_netdfs_dfs_StorageInfo_server, 
	  { "Server", "netdfs.dfs_StorageInfo.server", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_SetInfo_dfs_entry_path, 
	  { "Dfs Entry Path", "netdfs.dfs_SetInfo.dfs_entry_path", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_RemoveStdRoot_flags, 
	  { "Flags", "netdfs.dfs_RemoveStdRoot.flags", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_AddFtRoot_flags, 
	  { "Flags", "netdfs.dfs_AddFtRoot.flags", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_ManagerInitialize_flags, 
	  { "Flags", "netdfs.dfs_ManagerInitialize.flags", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info4_path, 
	  { "Path", "netdfs.dfs_Info4.path", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info5_state, 
	  { "State", "netdfs.dfs_Info5.state", FT_UINT32, BASE_HEX, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_StorageInfo_share, 
	  { "Share", "netdfs.dfs_StorageInfo.share", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_AddStdRoot_flags, 
	  { "Flags", "netdfs.dfs_AddStdRoot.flags", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info6_num_stores, 
	  { "Num Stores", "netdfs.dfs_Info6.num_stores", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Target_Priority_target_priority_class, 
	  { "Target Priority Class", "netdfs.dfs_Target_Priority.target_priority_class", FT_UINT32, BASE_DEC, VALS(netdfs_dfs_Target_PriorityClass_vals), 0, "", HFILL }},
	{ &hf_netdfs_opnum, 
	  { "Operation", "netdfs.opnum", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_PropertyFlags_DFS_PROPERTY_FLAG_INSITE_REFERRALS, 
	  { "Dfs Property Flag Insite Referrals", "netdfs.dfs_PropertyFlags.DFS_PROPERTY_FLAG_INSITE_REFERRALS", FT_BOOLEAN, 32, TFS(&dfs_PropertyFlags_DFS_PROPERTY_FLAG_INSITE_REFERRALS_tfs), ( 0x01 ), "", HFILL }},
	{ &hf_netdfs_dfs_Info2_state, 
	  { "State", "netdfs.dfs_Info2.state", FT_UINT32, BASE_HEX, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info106_state, 
	  { "State", "netdfs.dfs_Info106.state", FT_UINT32, BASE_HEX, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info_info100, 
	  { "Info100", "netdfs.dfs_Info.info100", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_AddStdRootForced_comment, 
	  { "Comment", "netdfs.dfs_AddStdRootForced.comment", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info_info101, 
	  { "Info101", "netdfs.dfs_Info.info101", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Add_path, 
	  { "Path", "netdfs.dfs_Add.path", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info102_timeout, 
	  { "Timeout", "netdfs.dfs_Info102.timeout", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info_info102, 
	  { "Info102", "netdfs.dfs_Info.info102", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info_info103, 
	  { "Info103", "netdfs.dfs_Info.info103", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info_info104, 
	  { "Info104", "netdfs.dfs_Info.info104", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info3_path, 
	  { "Path", "netdfs.dfs_Info3.path", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info_info105, 
	  { "Info105", "netdfs.dfs_Info.info105", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info_info106, 
	  { "Info106", "netdfs.dfs_Info.info106", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_SetInfo_sharename, 
	  { "Sharename", "netdfs.dfs_SetInfo.sharename", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_ManagerInitialize_servername, 
	  { "Servername", "netdfs.dfs_ManagerInitialize.servername", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumInfo_info1, 
	  { "Info1", "netdfs.dfs_EnumInfo.info1", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info300_dom_root, 
	  { "Dom Root", "netdfs.dfs_Info300.dom_root", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumArray2_count, 
	  { "Count", "netdfs.dfs_EnumArray2.count", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumArray300_count, 
	  { "Count", "netdfs.dfs_EnumArray300.count", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumInfo_info2, 
	  { "Info2", "netdfs.dfs_EnumInfo.info2", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Remove_dfs_entry_path, 
	  { "Dfs Entry Path", "netdfs.dfs_Remove.dfs_entry_path", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumInfo_info3, 
	  { "Info3", "netdfs.dfs_EnumInfo.info3", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumEx_dfs_name, 
	  { "Dfs Name", "netdfs.dfs_EnumEx.dfs_name", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_RemoveStdRoot_rootshare, 
	  { "Rootshare", "netdfs.dfs_RemoveStdRoot.rootshare", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumInfo_info4, 
	  { "Info4", "netdfs.dfs_EnumInfo.info4", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info5_timeout, 
	  { "Timeout", "netdfs.dfs_Info5.timeout", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumArray1_s, 
	  { "S", "netdfs.dfs_EnumArray1.s", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Remove_servername, 
	  { "Servername", "netdfs.dfs_Remove.servername", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info3_num_stores, 
	  { "Num Stores", "netdfs.dfs_Info3.num_stores", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info105_property_flag_mask, 
	  { "Property Flag Mask", "netdfs.dfs_Info105.property_flag_mask", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info2_comment, 
	  { "Comment", "netdfs.dfs_Info2.comment", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info6_guid, 
	  { "Guid", "netdfs.dfs_Info6.guid", FT_GUID, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info2_path, 
	  { "Path", "netdfs.dfs_Info2.path", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_SetInfo_info, 
	  { "Info", "netdfs.dfs_SetInfo.info", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	};


	static gint *ett[] = {
		&ett_dcerpc_netdfs,
		&ett_netdfs_dfs_Info0,
		&ett_netdfs_dfs_Info1,
		&ett_netdfs_dfs_VolumeState,
		&ett_netdfs_dfs_Info2,
		&ett_netdfs_dfs_StorageState,
		&ett_netdfs_dfs_StorageInfo,
		&ett_netdfs_dfs_Info3,
		&ett_netdfs_dfs_Info4,
		&ett_netdfs_dfs_PropertyFlags,
		&ett_netdfs_dfs_Info5,
		&ett_netdfs_dfs_Target_Priority,
		&ett_netdfs_dfs_StorageInfo2,
		&ett_netdfs_dfs_Info6,
		&ett_netdfs_dfs_Info7,
		&ett_netdfs_dfs_Info100,
		&ett_netdfs_dfs_Info101,
		&ett_netdfs_dfs_Info102,
		&ett_netdfs_dfs_Info103,
		&ett_netdfs_dfs_Info104,
		&ett_netdfs_dfs_Info105,
		&ett_netdfs_dfs_Info106,
		&ett_netdfs_dfs_Info200,
		&ett_netdfs_dfs_Info300,
		&ett_netdfs_dfs_Info,
		&ett_netdfs_dfs_EnumArray1,
		&ett_netdfs_dfs_EnumArray2,
		&ett_netdfs_dfs_EnumArray3,
		&ett_netdfs_dfs_EnumArray4,
		&ett_netdfs_dfs_EnumArray200,
		&ett_netdfs_dfs_EnumArray300,
		&ett_netdfs_dfs_EnumInfo,
		&ett_netdfs_dfs_EnumStruct,
		&ett_netdfs_dfs_UnknownStruct,
	};

	proto_dcerpc_netdfs = proto_register_protocol("Settings for Microsoft Distributed File System", "NETDFS", "netdfs");
	proto_register_field_array(proto_dcerpc_netdfs, hf, array_length (hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_dcerpc_netdfs(void)
{
	dcerpc_init_uuid(proto_dcerpc_netdfs, ett_dcerpc_netdfs,
		&uuid_dcerpc_netdfs, ver_dcerpc_netdfs,
		netdfs_dissectors, hf_netdfs_opnum);
}
