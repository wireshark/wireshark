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
static gint ett_netdfs_dfs_Info2 = -1;
static gint ett_netdfs_dfs_StorageInfo = -1;
static gint ett_netdfs_dfs_Info3 = -1;
static gint ett_netdfs_dfs_Info4 = -1;
static gint ett_netdfs_dfs_Info100 = -1;
static gint ett_netdfs_dfs_Info101 = -1;
static gint ett_netdfs_dfs_Info102 = -1;
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


/* Header field declarations */
static gint hf_netdfs_dfs_EnumEx_level = -1;
static gint hf_netdfs_dfs_EnumEx_total = -1;
static gint hf_netdfs_dfs_EnumEx_bufsize = -1;
static gint hf_netdfs_dfs_Info4_comment = -1;
static gint hf_netdfs_dfs_Remove_server = -1;
static gint hf_netdfs_dfs_GetInfo_level = -1;
static gint hf_netdfs_dfs_Add_server = -1;
static gint hf_netdfs_dfs_EnumArray300_s = -1;
static gint hf_netdfs_werror = -1;
static gint hf_netdfs_dfs_EnumInfo_info200 = -1;
static gint hf_netdfs_dfs_EnumArray3_count = -1;
static gint hf_netdfs_dfs_EnumEx_name = -1;
static gint hf_netdfs_dfs_Enum_bufsize = -1;
static gint hf_netdfs_dfs_Add_flags = -1;
static gint hf_netdfs_dfs_EnumArray4_s = -1;
static gint hf_netdfs_dfs_Info1_path = -1;
static gint hf_netdfs_dfs_GetInfo_path = -1;
static gint hf_netdfs_dfs_EnumStruct_level = -1;
static gint hf_netdfs_dfs_Info101_state = -1;
static gint hf_netdfs_dfs_Info200_dom_root = -1;
static gint hf_netdfs_dfs_Info_info0 = -1;
static gint hf_netdfs_dfs_Info_info1 = -1;
static gint hf_netdfs_dfs_Info2_num_stores = -1;
static gint hf_netdfs_dfs_Info4_state = -1;
static gint hf_netdfs_dfs_Info_info2 = -1;
static gint hf_netdfs_dfs_Info_info3 = -1;
static gint hf_netdfs_dfs_Info_info4 = -1;
static gint hf_netdfs_dfs_Info4_guid = -1;
static gint hf_netdfs_dfs_Enum_level = -1;
static gint hf_netdfs_dfs_Enum_total = -1;
static gint hf_netdfs_dfs_Remove_path = -1;
static gint hf_netdfs_dfs_GetManagerVersion_version = -1;
static gint hf_netdfs_dfs_Info3_stores = -1;
static gint hf_netdfs_dfs_EnumArray3_s = -1;
static gint hf_netdfs_dfs_EnumStruct_e = -1;
static gint hf_netdfs_dfs_EnumArray4_count = -1;
static gint hf_netdfs_dfs_Info300_flags = -1;
static gint hf_netdfs_dfs_Info4_stores = -1;
static gint hf_netdfs_dfs_Info4_num_stores = -1;
static gint hf_netdfs_dfs_StorageInfo_state = -1;
static gint hf_netdfs_dfs_EnumArray1_count = -1;
static gint hf_netdfs_dfs_StorageInfo_server = -1;
static gint hf_netdfs_dfs_Remove_share = -1;
static gint hf_netdfs_dfs_EnumArray200_s = -1;
static gint hf_netdfs_dfs_Info4_path = -1;
static gint hf_netdfs_dfs_GetInfo_share = -1;
static gint hf_netdfs_dfs_StorageInfo_share = -1;
static gint hf_netdfs_dfs_EnumArray2_s = -1;
static gint hf_netdfs_opnum = -1;
static gint hf_netdfs_dfs_Info2_state = -1;
static gint hf_netdfs_dfs_Info_info100 = -1;
static gint hf_netdfs_dfs_Info_info101 = -1;
static gint hf_netdfs_dfs_EnumArray200_count = -1;
static gint hf_netdfs_dfs_Add_path = -1;
static gint hf_netdfs_dfs_Info102_timeout = -1;
static gint hf_netdfs_dfs_Info_info102 = -1;
static gint hf_netdfs_dfs_EnumEx_info = -1;
static gint hf_netdfs_dfs_Info3_path = -1;
static gint hf_netdfs_dfs_Info4_timeout = -1;
static gint hf_netdfs_dfs_Enum_info = -1;
static gint hf_netdfs_dfs_EnumInfo_info1 = -1;
static gint hf_netdfs_dfs_Info300_dom_root = -1;
static gint hf_netdfs_dfs_EnumArray2_count = -1;
static gint hf_netdfs_dfs_EnumArray300_count = -1;
static gint hf_netdfs_dfs_EnumInfo_info2 = -1;
static gint hf_netdfs_dfs_EnumInfo_info3 = -1;
static gint hf_netdfs_dfs_EnumInfo_info4 = -1;
static gint hf_netdfs_dfs_GetInfo_server = -1;
static gint hf_netdfs_dfs_EnumArray1_s = -1;
static gint hf_netdfs_dfs_GetInfo_info = -1;
static gint hf_netdfs_dfs_Info100_comment = -1;
static gint hf_netdfs_dfs_Add_share = -1;
static gint hf_netdfs_dfs_Info3_num_stores = -1;
static gint hf_netdfs_dfs_Info2_comment = -1;
static gint hf_netdfs_dfs_EnumInfo_info300 = -1;
static gint hf_netdfs_dfs_Add_comment = -1;
static gint hf_netdfs_dfs_Info3_comment = -1;
static gint hf_netdfs_dfs_Info2_path = -1;
static gint hf_netdfs_dfs_Info3_state = -1;

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
static int netdfs_dissect_element_dfs_Info2_path(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info2_path_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info2_comment(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info2_comment_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info2_state(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info2_num_stores(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
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
static int netdfs_dissect_element_dfs_Info100_comment(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info100_comment_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info101_state(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info102_timeout(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info200_dom_root(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info200_dom_root_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info300_flags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
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
static int netdfs_dissect_element_dfs_Info_info100(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info100_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info101(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info101_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info102(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Info_info102_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
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
static int netdfs_dissect_element_dfs_Remove_path(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Remove_path_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Remove_server(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Remove_server_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Remove_share(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Remove_share_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_GetInfo_path(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_GetInfo_server(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_GetInfo_server_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_GetInfo_share(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_GetInfo_share_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_GetInfo_level(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_GetInfo_info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_GetInfo_info_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Enum_level(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Enum_bufsize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Enum_info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Enum_info_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Enum_total(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_Enum_total_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumEx_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumEx_level(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumEx_bufsize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumEx_info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumEx_info_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumEx_total(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int netdfs_dissect_element_dfs_EnumEx_total_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);

/* IDL: typedef enum { */
/* IDL: 	DFS_MANAGER_VERSION_NT4=0, */
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

/* IDL: typedef struct { */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *path; */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *comment; */
/* IDL: 	uint32 state; */
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
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info2_state,NULL);

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

/* IDL: typedef struct { */
/* IDL: 	uint32 state; */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *server; */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *share; */
/* IDL: } dfs_StorageInfo; */

static int
netdfs_dissect_element_dfs_StorageInfo_state(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_StorageInfo_state,NULL);

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
/* IDL: 	uint32 state; */
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
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info3_state,NULL);

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
/* IDL: 	uint32 state; */
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
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info4_state,NULL);

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
/* IDL: 	uint32 state; */
/* IDL: } dfs_Info101; */

static int
netdfs_dissect_element_dfs_Info101_state(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info101_state,NULL);

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

/* IDL: typedef struct { */
/* IDL: 	uint32 flags; */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *dom_root; */
/* IDL: } dfs_Info300; */

static int
netdfs_dissect_element_dfs_Info300_flags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_dfs_Info300_flags,NULL);

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
	
	offset = netdfs_dissect_element_dfs_Info300_flags(tvb, offset, pinfo, tree, drep);

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
/* IDL: [case(100)] [unique(1)] [case(100)] dfs_Info100 *info100; */
/* IDL: [case(101)] [unique(1)] [case(101)] dfs_Info101 *info101; */
/* IDL: [case(102)] [unique(1)] [case(102)] dfs_Info102 *info102; */
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

		case 100:
			offset = netdfs_dissect_element_dfs_Info_info100(tvb, offset, pinfo, tree, drep);
		break;

		case 101:
			offset = netdfs_dissect_element_dfs_Info_info101(tvb, offset, pinfo, tree, drep);
		break;

		case 102:
			offset = netdfs_dissect_element_dfs_Info_info102(tvb, offset, pinfo, tree, drep);
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
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

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
netdfs_dissect_element_dfs_Remove_path(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Remove_path_, NDR_POINTER_REF, "Pointer to Path (uint16)",hf_netdfs_dfs_Remove_path);

	return offset;
}

static int
netdfs_dissect_element_dfs_Remove_path_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_Remove_path, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_Remove_server(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Remove_server_, NDR_POINTER_UNIQUE, "Pointer to Server (uint16)",hf_netdfs_dfs_Remove_server);

	return offset;
}

static int
netdfs_dissect_element_dfs_Remove_server_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_Remove_server, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_Remove_share(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_Remove_share_, NDR_POINTER_UNIQUE, "Pointer to Share (uint16)",hf_netdfs_dfs_Remove_share);

	return offset;
}

static int
netdfs_dissect_element_dfs_Remove_share_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_Remove_share, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

/* IDL: WERROR dfs_Remove( */
/* IDL: [charset(UTF16)] [in] [ref] uint16 *path, */
/* IDL: [charset(UTF16)] [unique(1)] [in] uint16 *server, */
/* IDL: [charset(UTF16)] [unique(1)] [in] uint16 *share */
/* IDL: ); */

static int
netdfs_dissect_dfs_Remove_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_Remove_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = netdfs_dissect_element_dfs_Remove_path(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_Remove_server(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_Remove_share(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

/* IDL: WERROR dfs_SetInfo( */
/* IDL:  */
/* IDL: ); */

static int
netdfs_dissect_dfs_SetInfo_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_SetInfo_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

static int
netdfs_dissect_element_dfs_GetInfo_path(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_GetInfo_path, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_GetInfo_server(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_GetInfo_server_, NDR_POINTER_UNIQUE, "Pointer to Server (uint16)",hf_netdfs_dfs_GetInfo_server);

	return offset;
}

static int
netdfs_dissect_element_dfs_GetInfo_server_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_GetInfo_server, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
netdfs_dissect_element_dfs_GetInfo_share(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, netdfs_dissect_element_dfs_GetInfo_share_, NDR_POINTER_UNIQUE, "Pointer to Share (uint16)",hf_netdfs_dfs_GetInfo_share);

	return offset;
}

static int
netdfs_dissect_element_dfs_GetInfo_share_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_GetInfo_share, FALSE, &data);
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
/* IDL: [charset(UTF16)] [in] uint16 path[*], */
/* IDL: [charset(UTF16)] [unique(1)] [in] uint16 *server, */
/* IDL: [charset(UTF16)] [unique(1)] [in] uint16 *share, */
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
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_GetInfo_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = netdfs_dissect_element_dfs_GetInfo_path(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_GetInfo_server(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = netdfs_dissect_element_dfs_GetInfo_share(tvb, offset, pinfo, tree, drep);
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
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

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
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

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
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

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
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

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
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_ManagerSendSiteInfo_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR dfs_AddFtRoot( */
/* IDL:  */
/* IDL: ); */

static int
netdfs_dissect_dfs_AddFtRoot_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_AddFtRoot_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR dfs_RemoveFtRoot( */
/* IDL:  */
/* IDL: ); */

static int
netdfs_dissect_dfs_RemoveFtRoot_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_RemoveFtRoot_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR dfs_AddStdRoot( */
/* IDL:  */
/* IDL: ); */

static int
netdfs_dissect_dfs_AddStdRoot_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_AddStdRoot_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR dfs_RemoveStdRoot( */
/* IDL:  */
/* IDL: ); */

static int
netdfs_dissect_dfs_RemoveStdRoot_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_RemoveStdRoot_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR dfs_ManagerInitialize( */
/* IDL:  */
/* IDL: ); */

static int
netdfs_dissect_dfs_ManagerInitialize_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_ManagerInitialize_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR dfs_AddStdRootForced( */
/* IDL:  */
/* IDL: ); */

static int
netdfs_dissect_dfs_AddStdRootForced_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_AddStdRootForced_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
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
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

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
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_SetDcAddress_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR dfs_FlushFtTable( */
/* IDL:  */
/* IDL: ); */

static int
netdfs_dissect_dfs_FlushFtTable_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netdfs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_FlushFtTable_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
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
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

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
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_Remove2_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

static int
netdfs_dissect_element_dfs_EnumEx_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_netdfs_dfs_EnumEx_name, FALSE, &data);
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
/* IDL: [charset(UTF16)] [in] uint16 name[*], */
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
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
netdfs_dissect_dfs_EnumEx_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = netdfs_dissect_element_dfs_EnumEx_name(tvb, offset, pinfo, tree, drep);
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
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

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
	{ &hf_netdfs_dfs_EnumEx_total, 
	  { "Total", "netdfs.dfs_EnumEx.total", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumEx_bufsize, 
	  { "Bufsize", "netdfs.dfs_EnumEx.bufsize", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info4_comment, 
	  { "Comment", "netdfs.dfs_Info4.comment", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Remove_server, 
	  { "Server", "netdfs.dfs_Remove.server", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_GetInfo_level, 
	  { "Level", "netdfs.dfs_GetInfo.level", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Add_server, 
	  { "Server", "netdfs.dfs_Add.server", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumArray300_s, 
	  { "S", "netdfs.dfs_EnumArray300.s", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_werror, 
	  { "Windows Error", "netdfs.werror", FT_UINT32, BASE_HEX, VALS(DOS_errors), 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumInfo_info200, 
	  { "Info200", "netdfs.dfs_EnumInfo.info200", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumArray3_count, 
	  { "Count", "netdfs.dfs_EnumArray3.count", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumEx_name, 
	  { "Name", "netdfs.dfs_EnumEx.name", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Enum_bufsize, 
	  { "Bufsize", "netdfs.dfs_Enum.bufsize", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Add_flags, 
	  { "Flags", "netdfs.dfs_Add.flags", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumArray4_s, 
	  { "S", "netdfs.dfs_EnumArray4.s", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info1_path, 
	  { "Path", "netdfs.dfs_Info1.path", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_GetInfo_path, 
	  { "Path", "netdfs.dfs_GetInfo.path", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumStruct_level, 
	  { "Level", "netdfs.dfs_EnumStruct.level", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info101_state, 
	  { "State", "netdfs.dfs_Info101.state", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info200_dom_root, 
	  { "Dom Root", "netdfs.dfs_Info200.dom_root", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info_info0, 
	  { "Info0", "netdfs.dfs_Info.info0", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info_info1, 
	  { "Info1", "netdfs.dfs_Info.info1", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info2_num_stores, 
	  { "Num Stores", "netdfs.dfs_Info2.num_stores", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info4_state, 
	  { "State", "netdfs.dfs_Info4.state", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info_info2, 
	  { "Info2", "netdfs.dfs_Info.info2", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info_info3, 
	  { "Info3", "netdfs.dfs_Info.info3", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info_info4, 
	  { "Info4", "netdfs.dfs_Info.info4", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info4_guid, 
	  { "Guid", "netdfs.dfs_Info4.guid", FT_GUID, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Enum_level, 
	  { "Level", "netdfs.dfs_Enum.level", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Enum_total, 
	  { "Total", "netdfs.dfs_Enum.total", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Remove_path, 
	  { "Path", "netdfs.dfs_Remove.path", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_GetManagerVersion_version, 
	  { "Version", "netdfs.dfs_GetManagerVersion.version", FT_UINT32, BASE_DEC, VALS(netdfs_dfs_ManagerVersion_vals), 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info3_stores, 
	  { "Stores", "netdfs.dfs_Info3.stores", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumArray3_s, 
	  { "S", "netdfs.dfs_EnumArray3.s", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumStruct_e, 
	  { "E", "netdfs.dfs_EnumStruct.e", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumArray4_count, 
	  { "Count", "netdfs.dfs_EnumArray4.count", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info300_flags, 
	  { "Flags", "netdfs.dfs_Info300.flags", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info4_stores, 
	  { "Stores", "netdfs.dfs_Info4.stores", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info4_num_stores, 
	  { "Num Stores", "netdfs.dfs_Info4.num_stores", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_StorageInfo_state, 
	  { "State", "netdfs.dfs_StorageInfo.state", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumArray1_count, 
	  { "Count", "netdfs.dfs_EnumArray1.count", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_StorageInfo_server, 
	  { "Server", "netdfs.dfs_StorageInfo.server", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Remove_share, 
	  { "Share", "netdfs.dfs_Remove.share", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumArray200_s, 
	  { "S", "netdfs.dfs_EnumArray200.s", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info4_path, 
	  { "Path", "netdfs.dfs_Info4.path", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_GetInfo_share, 
	  { "Share", "netdfs.dfs_GetInfo.share", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_StorageInfo_share, 
	  { "Share", "netdfs.dfs_StorageInfo.share", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumArray2_s, 
	  { "S", "netdfs.dfs_EnumArray2.s", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_opnum, 
	  { "Operation", "netdfs.opnum", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info2_state, 
	  { "State", "netdfs.dfs_Info2.state", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info_info100, 
	  { "Info100", "netdfs.dfs_Info.info100", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info_info101, 
	  { "Info101", "netdfs.dfs_Info.info101", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumArray200_count, 
	  { "Count", "netdfs.dfs_EnumArray200.count", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Add_path, 
	  { "Path", "netdfs.dfs_Add.path", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info102_timeout, 
	  { "Timeout", "netdfs.dfs_Info102.timeout", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info_info102, 
	  { "Info102", "netdfs.dfs_Info.info102", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumEx_info, 
	  { "Info", "netdfs.dfs_EnumEx.info", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info3_path, 
	  { "Path", "netdfs.dfs_Info3.path", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info4_timeout, 
	  { "Timeout", "netdfs.dfs_Info4.timeout", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Enum_info, 
	  { "Info", "netdfs.dfs_Enum.info", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
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
	{ &hf_netdfs_dfs_EnumInfo_info3, 
	  { "Info3", "netdfs.dfs_EnumInfo.info3", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumInfo_info4, 
	  { "Info4", "netdfs.dfs_EnumInfo.info4", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_GetInfo_server, 
	  { "Server", "netdfs.dfs_GetInfo.server", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumArray1_s, 
	  { "S", "netdfs.dfs_EnumArray1.s", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_GetInfo_info, 
	  { "Info", "netdfs.dfs_GetInfo.info", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info100_comment, 
	  { "Comment", "netdfs.dfs_Info100.comment", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Add_share, 
	  { "Share", "netdfs.dfs_Add.share", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info3_num_stores, 
	  { "Num Stores", "netdfs.dfs_Info3.num_stores", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info2_comment, 
	  { "Comment", "netdfs.dfs_Info2.comment", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_EnumInfo_info300, 
	  { "Info300", "netdfs.dfs_EnumInfo.info300", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Add_comment, 
	  { "Comment", "netdfs.dfs_Add.comment", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info3_comment, 
	  { "Comment", "netdfs.dfs_Info3.comment", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info2_path, 
	  { "Path", "netdfs.dfs_Info2.path", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_netdfs_dfs_Info3_state, 
	  { "State", "netdfs.dfs_Info3.state", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	};


	static gint *ett[] = {
		&ett_dcerpc_netdfs,
		&ett_netdfs_dfs_Info0,
		&ett_netdfs_dfs_Info1,
		&ett_netdfs_dfs_Info2,
		&ett_netdfs_dfs_StorageInfo,
		&ett_netdfs_dfs_Info3,
		&ett_netdfs_dfs_Info4,
		&ett_netdfs_dfs_Info100,
		&ett_netdfs_dfs_Info101,
		&ett_netdfs_dfs_Info102,
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
