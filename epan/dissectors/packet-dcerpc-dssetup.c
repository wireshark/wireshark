/* DO NOT EDIT
	This filter was automatically generated
	from dssetup.idl and dssetup.cnf.
	
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
#include "packet-dcerpc-dssetup.h"

/* Ett declarations */
static gint ett_dcerpc_dssetup = -1;
static gint ett_dssetup_dssetup_DsRoleFlags = -1;
static gint ett_dssetup_dssetup_DsRolePrimaryDomInfoBasic = -1;
static gint ett_dssetup_dssetup_DsRoleUpgradeStatus = -1;
static gint ett_dssetup_dssetup_DsRoleOpStatus = -1;
static gint ett_dssetup_dssetup_DsRoleInfo = -1;


/* Header field declarations */
static gint hf_dssetup_dssetup_DsRoleGetPrimaryDomainInformation_level = -1;
static gint hf_dssetup_opnum = -1;
static gint hf_dssetup_dssetup_DsRolePrimaryDomInfoBasic_flags = -1;
static gint hf_dssetup_dssetup_DsRoleUpgradeStatus_previous_role = -1;
static gint hf_dssetup_dssetup_DsRoleInfo_opstatus = -1;
static gint hf_dssetup_dssetup_DsRolePrimaryDomInfoBasic_domain_guid = -1;
static gint hf_dssetup_dssetup_DsRoleOpStatus_status = -1;
static gint hf_dssetup_dssetup_DsRoleInfo_upgrade = -1;
static gint hf_dssetup_dssetup_DsRoleGetPrimaryDomainInformation_info = -1;
static gint hf_dssetup_dssetup_DsRoleFlags_DS_ROLE_UPGRADE_IN_PROGRESS = -1;
static gint hf_dssetup_dssetup_DsRoleFlags_DS_ROLE_PRIMARY_DOMAIN_GUID_PRESENT = -1;
static gint hf_dssetup_dssetup_DsRoleInfo_basic = -1;
static gint hf_dssetup_dssetup_DsRolePrimaryDomInfoBasic_role = -1;
static gint hf_dssetup_dssetup_DsRoleFlags_DS_ROLE_PRIMARY_DS_RUNNING = -1;
static gint hf_dssetup_dssetup_DsRolePrimaryDomInfoBasic_dns_domain = -1;
static gint hf_dssetup_dssetup_DsRoleUpgradeStatus_upgrading = -1;
static gint hf_dssetup_dssetup_DsRolePrimaryDomInfoBasic_domain = -1;
static gint hf_dssetup_werror = -1;
static gint hf_dssetup_dssetup_DsRoleFlags_DS_ROLE_PRIMARY_DS_MIXED_MODE = -1;
static gint hf_dssetup_dssetup_DsRolePrimaryDomInfoBasic_forest = -1;

static gint proto_dcerpc_dssetup = -1;
/* Version information */


static e_uuid_t uuid_dcerpc_dssetup = {
	0x3919286a, 0xb10c, 0x11d0,
	{ 0x9b, 0xa8, 0x00, 0xc0, 0x4f, 0xd9, 0x2e, 0xf5 }
};
static guint16 ver_dcerpc_dssetup = 0;

const value_string dssetup_dssetup_DsRole_vals[] = {
	{ DS_ROLE_STANDALONE_WORKSTATION, "DS_ROLE_STANDALONE_WORKSTATION" },
	{ DS_ROLE_MEMBER_WORKSTATION, "DS_ROLE_MEMBER_WORKSTATION" },
	{ DS_ROLE_STANDALONE_SERVER, "DS_ROLE_STANDALONE_SERVER" },
	{ DS_ROLE_MEMBER_SERVER, "DS_ROLE_MEMBER_SERVER" },
	{ DS_ROLE_BACKUP_DC, "DS_ROLE_BACKUP_DC" },
	{ DS_ROLE_PRIMARY_DC, "DS_ROLE_PRIMARY_DC" },
{ 0, NULL }
};
static const true_false_string dssetup_DsRoleFlags_DS_ROLE_PRIMARY_DS_RUNNING_tfs = {
   "DS_ROLE_PRIMARY_DS_RUNNING is SET",
   "DS_ROLE_PRIMARY_DS_RUNNING is NOT SET",
};
static const true_false_string dssetup_DsRoleFlags_DS_ROLE_PRIMARY_DS_MIXED_MODE_tfs = {
   "DS_ROLE_PRIMARY_DS_MIXED_MODE is SET",
   "DS_ROLE_PRIMARY_DS_MIXED_MODE is NOT SET",
};
static const true_false_string dssetup_DsRoleFlags_DS_ROLE_UPGRADE_IN_PROGRESS_tfs = {
   "DS_ROLE_UPGRADE_IN_PROGRESS is SET",
   "DS_ROLE_UPGRADE_IN_PROGRESS is NOT SET",
};
static const true_false_string dssetup_DsRoleFlags_DS_ROLE_PRIMARY_DOMAIN_GUID_PRESENT_tfs = {
   "DS_ROLE_PRIMARY_DOMAIN_GUID_PRESENT is SET",
   "DS_ROLE_PRIMARY_DOMAIN_GUID_PRESENT is NOT SET",
};
static int dssetup_dissect_element_DsRolePrimaryDomInfoBasic_role(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int dssetup_dissect_element_DsRolePrimaryDomInfoBasic_flags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int dssetup_dissect_element_DsRolePrimaryDomInfoBasic_domain(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int dssetup_dissect_element_DsRolePrimaryDomInfoBasic_domain_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int dssetup_dissect_element_DsRolePrimaryDomInfoBasic_dns_domain(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int dssetup_dissect_element_DsRolePrimaryDomInfoBasic_dns_domain_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int dssetup_dissect_element_DsRolePrimaryDomInfoBasic_forest(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int dssetup_dissect_element_DsRolePrimaryDomInfoBasic_forest_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int dssetup_dissect_element_DsRolePrimaryDomInfoBasic_domain_guid(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
const value_string dssetup_dssetup_DsUpgrade_vals[] = {
	{ DS_ROLE_NOT_UPGRADING, "DS_ROLE_NOT_UPGRADING" },
	{ DS_ROLE_UPGRADING, "DS_ROLE_UPGRADING" },
{ 0, NULL }
};
const value_string dssetup_dssetup_DsPrevious_vals[] = {
	{ DS_ROLE_PREVIOUS_UNKNOWN, "DS_ROLE_PREVIOUS_UNKNOWN" },
	{ DS_ROLE_PREVIOUS_PRIMARY, "DS_ROLE_PREVIOUS_PRIMARY" },
	{ DS_ROLE_PREVIOUS_BACKUP, "DS_ROLE_PREVIOUS_BACKUP" },
{ 0, NULL }
};
static int dssetup_dissect_element_DsRoleUpgradeStatus_upgrading(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int dssetup_dissect_element_DsRoleUpgradeStatus_previous_role(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
const value_string dssetup_dssetup_DsRoleOp_vals[] = {
	{ DS_ROLE_OP_IDLE, "DS_ROLE_OP_IDLE" },
	{ DS_ROLE_OP_ACTIVE, "DS_ROLE_OP_ACTIVE" },
	{ DS_ROLE_OP_NEEDS_REBOOT, "DS_ROLE_OP_NEEDS_REBOOT" },
{ 0, NULL }
};
static int dssetup_dissect_element_DsRoleOpStatus_status(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
const value_string dssetup_dssetup_DsRoleInfoLevel_vals[] = {
	{ DS_ROLE_BASIC_INFORMATION, "DS_ROLE_BASIC_INFORMATION" },
	{ DS_ROLE_UPGRADE_STATUS, "DS_ROLE_UPGRADE_STATUS" },
	{ DS_ROLE_OP_STATUS, "DS_ROLE_OP_STATUS" },
{ 0, NULL }
};
static int dssetup_dissect_element_DsRoleInfo_basic(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int dssetup_dissect_element_DsRoleInfo_upgrade(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int dssetup_dissect_element_DsRoleInfo_opstatus(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int dssetup_dissect_element_DsRoleGetPrimaryDomainInformation_level(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int dssetup_dissect_element_DsRoleGetPrimaryDomainInformation_info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int dssetup_dissect_element_DsRoleGetPrimaryDomainInformation_info_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);

/* IDL: typedef enum { */
/* IDL: 	DS_ROLE_STANDALONE_WORKSTATION=0, */
/* IDL: 	DS_ROLE_MEMBER_WORKSTATION=1, */
/* IDL: 	DS_ROLE_STANDALONE_SERVER=2, */
/* IDL: 	DS_ROLE_MEMBER_SERVER=3, */
/* IDL: 	DS_ROLE_BACKUP_DC=4, */
/* IDL: 	DS_ROLE_PRIMARY_DC=5, */
/* IDL: } dssetup_DsRole; */

int
dssetup_dissect_enum_DsRole(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_index, NULL);
	return offset;
}

/* IDL: typedef bitmap { */
/* IDL: 	DS_ROLE_PRIMARY_DS_RUNNING =  0x00000001 , */
/* IDL: 	DS_ROLE_PRIMARY_DS_MIXED_MODE =  0x00000002 , */
/* IDL: 	DS_ROLE_UPGRADE_IN_PROGRESS =  0x00000004 , */
/* IDL: 	DS_ROLE_PRIMARY_DOMAIN_GUID_PRESENT =  0x01000000 , */
/* IDL: } dssetup_DsRoleFlags; */

int
dssetup_dissect_bitmap_DsRoleFlags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	guint32 flags;
	ALIGN_TO_4_BYTES;

	if(parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, 4, TRUE);
		tree = proto_item_add_subtree(item,ett_dssetup_dssetup_DsRoleFlags);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, drep, -1, &flags);
	proto_item_append_text(item, ": ");

	if (!flags)
		proto_item_append_text(item, "(No values set)");

	proto_tree_add_boolean(tree, hf_dssetup_dssetup_DsRoleFlags_DS_ROLE_PRIMARY_DS_RUNNING, tvb, offset-4, 4, flags);
	if (flags&( 0x00000001 )){
		proto_item_append_text(item, "DS_ROLE_PRIMARY_DS_RUNNING");
		if (flags & (~( 0x00000001 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000001 ));

	proto_tree_add_boolean(tree, hf_dssetup_dssetup_DsRoleFlags_DS_ROLE_PRIMARY_DS_MIXED_MODE, tvb, offset-4, 4, flags);
	if (flags&( 0x00000002 )){
		proto_item_append_text(item, "DS_ROLE_PRIMARY_DS_MIXED_MODE");
		if (flags & (~( 0x00000002 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000002 ));

	proto_tree_add_boolean(tree, hf_dssetup_dssetup_DsRoleFlags_DS_ROLE_UPGRADE_IN_PROGRESS, tvb, offset-4, 4, flags);
	if (flags&( 0x00000004 )){
		proto_item_append_text(item, "DS_ROLE_UPGRADE_IN_PROGRESS");
		if (flags & (~( 0x00000004 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000004 ));

	proto_tree_add_boolean(tree, hf_dssetup_dssetup_DsRoleFlags_DS_ROLE_PRIMARY_DOMAIN_GUID_PRESENT, tvb, offset-4, 4, flags);
	if (flags&( 0x01000000 )){
		proto_item_append_text(item, "DS_ROLE_PRIMARY_DOMAIN_GUID_PRESENT");
		if (flags & (~( 0x01000000 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x01000000 ));

	if(flags){
		proto_item_append_text(item, "Unknown bitmap value 0x%x", flags);
	}

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	dssetup_DsRole role; */
/* IDL: 	dssetup_DsRoleFlags flags; */
/* IDL: 	[unique(1)] uint16 *domain; */
/* IDL: 	[unique(1)] uint16 *dns_domain; */
/* IDL: 	[unique(1)] uint16 *forest; */
/* IDL: 	GUID domain_guid; */
/* IDL: } dssetup_DsRolePrimaryDomInfoBasic; */

static int
dssetup_dissect_element_DsRolePrimaryDomInfoBasic_role(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dssetup_dissect_enum_DsRole(tvb, offset, pinfo, tree, drep, hf_dssetup_dssetup_DsRolePrimaryDomInfoBasic_role, 0);

	return offset;
}

static int
dssetup_dissect_element_DsRolePrimaryDomInfoBasic_flags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dssetup_dissect_bitmap_DsRoleFlags(tvb, offset, pinfo, tree, drep, hf_dssetup_dssetup_DsRolePrimaryDomInfoBasic_flags, 0);

	return offset;
}

static int
dssetup_dissect_element_DsRolePrimaryDomInfoBasic_domain(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, dssetup_dissect_element_DsRolePrimaryDomInfoBasic_domain_, NDR_POINTER_UNIQUE, "Pointer to Domain (uint16)",hf_dssetup_dssetup_DsRolePrimaryDomInfoBasic_domain);

	return offset;
}

static int
dssetup_dissect_element_DsRolePrimaryDomInfoBasic_domain_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_dssetup_dssetup_DsRolePrimaryDomInfoBasic_domain, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
dssetup_dissect_element_DsRolePrimaryDomInfoBasic_dns_domain(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, dssetup_dissect_element_DsRolePrimaryDomInfoBasic_dns_domain_, NDR_POINTER_UNIQUE, "Pointer to Dns Domain (uint16)",hf_dssetup_dssetup_DsRolePrimaryDomInfoBasic_dns_domain);

	return offset;
}

static int
dssetup_dissect_element_DsRolePrimaryDomInfoBasic_dns_domain_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_dssetup_dssetup_DsRolePrimaryDomInfoBasic_dns_domain, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
dssetup_dissect_element_DsRolePrimaryDomInfoBasic_forest(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, dssetup_dissect_element_DsRolePrimaryDomInfoBasic_forest_, NDR_POINTER_UNIQUE, "Pointer to Forest (uint16)",hf_dssetup_dssetup_DsRolePrimaryDomInfoBasic_forest);

	return offset;
}

static int
dssetup_dissect_element_DsRolePrimaryDomInfoBasic_forest_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_dssetup_dssetup_DsRolePrimaryDomInfoBasic_forest, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
dssetup_dissect_element_DsRolePrimaryDomInfoBasic_domain_guid(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uuid_t(tvb, offset, pinfo, tree, drep, hf_dssetup_dssetup_DsRolePrimaryDomInfoBasic_domain_guid, NULL);

	return offset;
}

int
dssetup_dissect_struct_DsRolePrimaryDomInfoBasic(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_dssetup_dssetup_DsRolePrimaryDomInfoBasic);
	}
	
	offset = dssetup_dissect_element_DsRolePrimaryDomInfoBasic_role(tvb, offset, pinfo, tree, drep);

	offset = dssetup_dissect_element_DsRolePrimaryDomInfoBasic_flags(tvb, offset, pinfo, tree, drep);

	offset = dssetup_dissect_element_DsRolePrimaryDomInfoBasic_domain(tvb, offset, pinfo, tree, drep);

	offset = dssetup_dissect_element_DsRolePrimaryDomInfoBasic_dns_domain(tvb, offset, pinfo, tree, drep);

	offset = dssetup_dissect_element_DsRolePrimaryDomInfoBasic_forest(tvb, offset, pinfo, tree, drep);

	offset = dssetup_dissect_element_DsRolePrimaryDomInfoBasic_domain_guid(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef enum { */
/* IDL: 	DS_ROLE_NOT_UPGRADING=0, */
/* IDL: 	DS_ROLE_UPGRADING=1, */
/* IDL: } dssetup_DsUpgrade; */

int
dssetup_dissect_enum_DsUpgrade(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_index, NULL);
	return offset;
}

/* IDL: typedef enum { */
/* IDL: 	DS_ROLE_PREVIOUS_UNKNOWN=0, */
/* IDL: 	DS_ROLE_PREVIOUS_PRIMARY=1, */
/* IDL: 	DS_ROLE_PREVIOUS_BACKUP=2, */
/* IDL: } dssetup_DsPrevious; */

int
dssetup_dissect_enum_DsPrevious(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_index, NULL);
	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	dssetup_DsUpgrade upgrading; */
/* IDL: 	dssetup_DsPrevious previous_role; */
/* IDL: } dssetup_DsRoleUpgradeStatus; */

static int
dssetup_dissect_element_DsRoleUpgradeStatus_upgrading(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dssetup_dissect_enum_DsUpgrade(tvb, offset, pinfo, tree, drep, hf_dssetup_dssetup_DsRoleUpgradeStatus_upgrading, 0);

	return offset;
}

static int
dssetup_dissect_element_DsRoleUpgradeStatus_previous_role(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dssetup_dissect_enum_DsPrevious(tvb, offset, pinfo, tree, drep, hf_dssetup_dssetup_DsRoleUpgradeStatus_previous_role, 0);

	return offset;
}

int
dssetup_dissect_struct_DsRoleUpgradeStatus(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_dssetup_dssetup_DsRoleUpgradeStatus);
	}
	
	offset = dssetup_dissect_element_DsRoleUpgradeStatus_upgrading(tvb, offset, pinfo, tree, drep);

	offset = dssetup_dissect_element_DsRoleUpgradeStatus_previous_role(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef enum { */
/* IDL: 	DS_ROLE_OP_IDLE=0, */
/* IDL: 	DS_ROLE_OP_ACTIVE=1, */
/* IDL: 	DS_ROLE_OP_NEEDS_REBOOT=2, */
/* IDL: } dssetup_DsRoleOp; */

int
dssetup_dissect_enum_DsRoleOp(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_index, NULL);
	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	dssetup_DsRoleOp status; */
/* IDL: } dssetup_DsRoleOpStatus; */

static int
dssetup_dissect_element_DsRoleOpStatus_status(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dssetup_dissect_enum_DsRoleOp(tvb, offset, pinfo, tree, drep, hf_dssetup_dssetup_DsRoleOpStatus_status, 0);

	return offset;
}

int
dssetup_dissect_struct_DsRoleOpStatus(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_2_BYTES;

	old_offset = offset;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_dssetup_dssetup_DsRoleOpStatus);
	}
	
	offset = dssetup_dissect_element_DsRoleOpStatus_status(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef enum { */
/* IDL: 	DS_ROLE_BASIC_INFORMATION=1, */
/* IDL: 	DS_ROLE_UPGRADE_STATUS=2, */
/* IDL: 	DS_ROLE_OP_STATUS=3, */
/* IDL: } dssetup_DsRoleInfoLevel; */

int
dssetup_dissect_enum_DsRoleInfoLevel(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_index, NULL);
	return offset;
}

/* IDL: typedef [switch_type(dssetup_DsRoleInfoLevel)] union { */
/* IDL: [case(DS_ROLE_BASIC_INFORMATION)] [case(DS_ROLE_BASIC_INFORMATION)] dssetup_DsRolePrimaryDomInfoBasic basic; */
/* IDL: [case(DS_ROLE_UPGRADE_STATUS)] [case(DS_ROLE_UPGRADE_STATUS)] dssetup_DsRoleUpgradeStatus upgrade; */
/* IDL: [case(DS_ROLE_OP_STATUS)] [case(DS_ROLE_OP_STATUS)] dssetup_DsRoleOpStatus opstatus; */
/* IDL: } dssetup_DsRoleInfo; */

static int
dssetup_dissect_element_DsRoleInfo_basic(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dssetup_dissect_struct_DsRolePrimaryDomInfoBasic(tvb,offset,pinfo,tree,drep,hf_dssetup_dssetup_DsRoleInfo_basic,0);

	return offset;
}

static int
dssetup_dissect_element_DsRoleInfo_upgrade(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dssetup_dissect_struct_DsRoleUpgradeStatus(tvb,offset,pinfo,tree,drep,hf_dssetup_dssetup_DsRoleInfo_upgrade,0);

	return offset;
}

static int
dssetup_dissect_element_DsRoleInfo_opstatus(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dssetup_dissect_struct_DsRoleOpStatus(tvb,offset,pinfo,tree,drep,hf_dssetup_dssetup_DsRoleInfo_opstatus,0);

	return offset;
}

static int
dssetup_dissect_DsRoleInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;
	guint16 level;

	ALIGN_TO_4_BYTES;

	old_offset = offset;
	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1, "dssetup_DsRoleInfo");
		tree = proto_item_add_subtree(item, ett_dssetup_dssetup_DsRoleInfo);
	}

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_index, &level);
	switch(level) {
		case DS_ROLE_BASIC_INFORMATION:
			offset = dssetup_dissect_element_DsRoleInfo_basic(tvb, offset, pinfo, tree, drep);
		break;

		case DS_ROLE_UPGRADE_STATUS:
			offset = dssetup_dissect_element_DsRoleInfo_upgrade(tvb, offset, pinfo, tree, drep);
		break;

		case DS_ROLE_OP_STATUS:
			offset = dssetup_dissect_element_DsRoleInfo_opstatus(tvb, offset, pinfo, tree, drep);
		break;
	}
	proto_item_set_len(item, offset-old_offset);

	return offset;
}
static int
dssetup_dissect_element_DsRoleGetPrimaryDomainInformation_level(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dssetup_dissect_enum_DsRoleInfoLevel(tvb, offset, pinfo, tree, drep, hf_dssetup_dssetup_DsRoleGetPrimaryDomainInformation_level, 0);

	return offset;
}

static int
dssetup_dissect_element_DsRoleGetPrimaryDomainInformation_info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, dssetup_dissect_element_DsRoleGetPrimaryDomainInformation_info_, NDR_POINTER_UNIQUE, "Pointer to Info (dssetup_DsRoleInfo)",hf_dssetup_dssetup_DsRoleGetPrimaryDomainInformation_info);

	return offset;
}

static int
dssetup_dissect_element_DsRoleGetPrimaryDomainInformation_info_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dssetup_dissect_DsRoleInfo(tvb, offset, pinfo, tree, drep, hf_dssetup_dssetup_DsRoleGetPrimaryDomainInformation_info, 0);

	return offset;
}

/* IDL: WERROR dssetup_DsRoleGetPrimaryDomainInformation( */
/* IDL: [in] dssetup_DsRoleInfoLevel level, */
/* IDL: [unique(1)] [out] [switch_is(level)] dssetup_DsRoleInfo *info */
/* IDL: ); */

static int
dssetup_dissect_DsRoleGetPrimaryDomainInformation_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dssetup_dissect_element_DsRoleGetPrimaryDomainInformation_info(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_dssetup_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
dssetup_dissect_DsRoleGetPrimaryDomainInformation_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dssetup_dissect_element_DsRoleGetPrimaryDomainInformation_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

/* IDL: WERROR dssetup_DsRoleDnsNameToFlatName( */
/* IDL:  */
/* IDL: ); */

static int
dssetup_dissect_DsRoleDnsNameToFlatName_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_dssetup_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
dssetup_dissect_DsRoleDnsNameToFlatName_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR dssetup_DsRoleDcAsDc( */
/* IDL:  */
/* IDL: ); */

static int
dssetup_dissect_DsRoleDcAsDc_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_dssetup_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
dssetup_dissect_DsRoleDcAsDc_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR dssetup_DsRoleDcAsReplica( */
/* IDL:  */
/* IDL: ); */

static int
dssetup_dissect_DsRoleDcAsReplica_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_dssetup_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
dssetup_dissect_DsRoleDcAsReplica_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR dssetup_DsRoleDemoteDc( */
/* IDL:  */
/* IDL: ); */

static int
dssetup_dissect_DsRoleDemoteDc_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_dssetup_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
dssetup_dissect_DsRoleDemoteDc_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR dssetup_DsRoleGetDcOperationProgress( */
/* IDL:  */
/* IDL: ); */

static int
dssetup_dissect_DsRoleGetDcOperationProgress_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_dssetup_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
dssetup_dissect_DsRoleGetDcOperationProgress_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR dssetup_DsRoleGetDcOperationResults( */
/* IDL:  */
/* IDL: ); */

static int
dssetup_dissect_DsRoleGetDcOperationResults_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_dssetup_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
dssetup_dissect_DsRoleGetDcOperationResults_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR dssetup_DsRoleCancel( */
/* IDL:  */
/* IDL: ); */

static int
dssetup_dissect_DsRoleCancel_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_dssetup_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
dssetup_dissect_DsRoleCancel_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR dssetup_DsRoleServerSaveStateForUpgrade( */
/* IDL:  */
/* IDL: ); */

static int
dssetup_dissect_DsRoleServerSaveStateForUpgrade_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_dssetup_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
dssetup_dissect_DsRoleServerSaveStateForUpgrade_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR dssetup_DsRoleUpgradeDownlevelServer( */
/* IDL:  */
/* IDL: ); */

static int
dssetup_dissect_DsRoleUpgradeDownlevelServer_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_dssetup_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
dssetup_dissect_DsRoleUpgradeDownlevelServer_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR dssetup_DsRoleAbortDownlevelServerUpgrade( */
/* IDL:  */
/* IDL: ); */

static int
dssetup_dissect_DsRoleAbortDownlevelServerUpgrade_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_dssetup_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
dssetup_dissect_DsRoleAbortDownlevelServerUpgrade_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}


static dcerpc_sub_dissector dssetup_dissectors[] = {
	{ 0, "DsRoleGetPrimaryDomainInformation",
	   dssetup_dissect_DsRoleGetPrimaryDomainInformation_request, dssetup_dissect_DsRoleGetPrimaryDomainInformation_response},
	{ 1, "DsRoleDnsNameToFlatName",
	   dssetup_dissect_DsRoleDnsNameToFlatName_request, dssetup_dissect_DsRoleDnsNameToFlatName_response},
	{ 2, "DsRoleDcAsDc",
	   dssetup_dissect_DsRoleDcAsDc_request, dssetup_dissect_DsRoleDcAsDc_response},
	{ 3, "DsRoleDcAsReplica",
	   dssetup_dissect_DsRoleDcAsReplica_request, dssetup_dissect_DsRoleDcAsReplica_response},
	{ 4, "DsRoleDemoteDc",
	   dssetup_dissect_DsRoleDemoteDc_request, dssetup_dissect_DsRoleDemoteDc_response},
	{ 5, "DsRoleGetDcOperationProgress",
	   dssetup_dissect_DsRoleGetDcOperationProgress_request, dssetup_dissect_DsRoleGetDcOperationProgress_response},
	{ 6, "DsRoleGetDcOperationResults",
	   dssetup_dissect_DsRoleGetDcOperationResults_request, dssetup_dissect_DsRoleGetDcOperationResults_response},
	{ 7, "DsRoleCancel",
	   dssetup_dissect_DsRoleCancel_request, dssetup_dissect_DsRoleCancel_response},
	{ 8, "DsRoleServerSaveStateForUpgrade",
	   dssetup_dissect_DsRoleServerSaveStateForUpgrade_request, dssetup_dissect_DsRoleServerSaveStateForUpgrade_response},
	{ 9, "DsRoleUpgradeDownlevelServer",
	   dssetup_dissect_DsRoleUpgradeDownlevelServer_request, dssetup_dissect_DsRoleUpgradeDownlevelServer_response},
	{ 10, "DsRoleAbortDownlevelServerUpgrade",
	   dssetup_dissect_DsRoleAbortDownlevelServerUpgrade_request, dssetup_dissect_DsRoleAbortDownlevelServerUpgrade_response},
	{ 0, NULL, NULL, NULL }
};

void proto_register_dcerpc_dssetup(void)
{
	static hf_register_info hf[] = {
	{ &hf_dssetup_dssetup_DsRoleGetPrimaryDomainInformation_level, 
	  { "Level", "dssetup.dssetup_DsRoleGetPrimaryDomainInformation.level", FT_UINT16, BASE_DEC, VALS(dssetup_dssetup_DsRoleInfoLevel_vals), 0, "", HFILL }},
	{ &hf_dssetup_opnum, 
	  { "Operation", "dssetup.opnum", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_dssetup_dssetup_DsRolePrimaryDomInfoBasic_flags, 
	  { "Flags", "dssetup.dssetup_DsRolePrimaryDomInfoBasic.flags", FT_UINT32, BASE_HEX, NULL, 0, "", HFILL }},
	{ &hf_dssetup_dssetup_DsRoleUpgradeStatus_previous_role, 
	  { "Previous Role", "dssetup.dssetup_DsRoleUpgradeStatus.previous_role", FT_UINT16, BASE_DEC, VALS(dssetup_dssetup_DsPrevious_vals), 0, "", HFILL }},
	{ &hf_dssetup_dssetup_DsRoleInfo_opstatus, 
	  { "Opstatus", "dssetup.dssetup_DsRoleInfo.opstatus", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_dssetup_dssetup_DsRolePrimaryDomInfoBasic_domain_guid, 
	  { "Domain Guid", "dssetup.dssetup_DsRolePrimaryDomInfoBasic.domain_guid", FT_GUID, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_dssetup_dssetup_DsRoleOpStatus_status, 
	  { "Status", "dssetup.dssetup_DsRoleOpStatus.status", FT_UINT16, BASE_DEC, VALS(dssetup_dssetup_DsRoleOp_vals), 0, "", HFILL }},
	{ &hf_dssetup_dssetup_DsRoleInfo_upgrade, 
	  { "Upgrade", "dssetup.dssetup_DsRoleInfo.upgrade", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_dssetup_dssetup_DsRoleGetPrimaryDomainInformation_info, 
	  { "Info", "dssetup.dssetup_DsRoleGetPrimaryDomainInformation.info", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_dssetup_dssetup_DsRoleFlags_DS_ROLE_UPGRADE_IN_PROGRESS, 
	  { "Ds Role Upgrade In Progress", "dssetup.dssetup_DsRoleFlags.DS_ROLE_UPGRADE_IN_PROGRESS", FT_BOOLEAN, 32, TFS(&dssetup_DsRoleFlags_DS_ROLE_UPGRADE_IN_PROGRESS_tfs), ( 0x00000004 ), "", HFILL }},
	{ &hf_dssetup_dssetup_DsRoleFlags_DS_ROLE_PRIMARY_DOMAIN_GUID_PRESENT, 
	  { "Ds Role Primary Domain Guid Present", "dssetup.dssetup_DsRoleFlags.DS_ROLE_PRIMARY_DOMAIN_GUID_PRESENT", FT_BOOLEAN, 32, TFS(&dssetup_DsRoleFlags_DS_ROLE_PRIMARY_DOMAIN_GUID_PRESENT_tfs), ( 0x01000000 ), "", HFILL }},
	{ &hf_dssetup_dssetup_DsRoleInfo_basic, 
	  { "Basic", "dssetup.dssetup_DsRoleInfo.basic", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_dssetup_dssetup_DsRolePrimaryDomInfoBasic_role, 
	  { "Role", "dssetup.dssetup_DsRolePrimaryDomInfoBasic.role", FT_UINT16, BASE_DEC, VALS(dssetup_dssetup_DsRole_vals), 0, "", HFILL }},
	{ &hf_dssetup_dssetup_DsRoleFlags_DS_ROLE_PRIMARY_DS_RUNNING, 
	  { "Ds Role Primary Ds Running", "dssetup.dssetup_DsRoleFlags.DS_ROLE_PRIMARY_DS_RUNNING", FT_BOOLEAN, 32, TFS(&dssetup_DsRoleFlags_DS_ROLE_PRIMARY_DS_RUNNING_tfs), ( 0x00000001 ), "", HFILL }},
	{ &hf_dssetup_dssetup_DsRolePrimaryDomInfoBasic_dns_domain, 
	  { "Dns Domain", "dssetup.dssetup_DsRolePrimaryDomInfoBasic.dns_domain", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_dssetup_dssetup_DsRoleUpgradeStatus_upgrading, 
	  { "Upgrading", "dssetup.dssetup_DsRoleUpgradeStatus.upgrading", FT_UINT32, BASE_DEC, VALS(dssetup_dssetup_DsUpgrade_vals), 0, "", HFILL }},
	{ &hf_dssetup_dssetup_DsRolePrimaryDomInfoBasic_domain, 
	  { "Domain", "dssetup.dssetup_DsRolePrimaryDomInfoBasic.domain", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_dssetup_werror, 
	  { "Windows Error", "dssetup.werror", FT_UINT32, BASE_HEX, VALS(DOS_errors), 0, "", HFILL }},
	{ &hf_dssetup_dssetup_DsRoleFlags_DS_ROLE_PRIMARY_DS_MIXED_MODE, 
	  { "Ds Role Primary Ds Mixed Mode", "dssetup.dssetup_DsRoleFlags.DS_ROLE_PRIMARY_DS_MIXED_MODE", FT_BOOLEAN, 32, TFS(&dssetup_DsRoleFlags_DS_ROLE_PRIMARY_DS_MIXED_MODE_tfs), ( 0x00000002 ), "", HFILL }},
	{ &hf_dssetup_dssetup_DsRolePrimaryDomInfoBasic_forest, 
	  { "Forest", "dssetup.dssetup_DsRolePrimaryDomInfoBasic.forest", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	};


	static gint *ett[] = {
		&ett_dcerpc_dssetup,
		&ett_dssetup_dssetup_DsRoleFlags,
		&ett_dssetup_dssetup_DsRolePrimaryDomInfoBasic,
		&ett_dssetup_dssetup_DsRoleUpgradeStatus,
		&ett_dssetup_dssetup_DsRoleOpStatus,
		&ett_dssetup_dssetup_DsRoleInfo,
	};

	proto_dcerpc_dssetup = proto_register_protocol("Active Directory Setup", "DSSETUP", "dssetup");
	proto_register_field_array(proto_dcerpc_dssetup, hf, array_length (hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_dcerpc_dssetup(void)
{
	dcerpc_init_uuid(proto_dcerpc_dssetup, ett_dcerpc_dssetup,
		&uuid_dcerpc_dssetup, ver_dcerpc_dssetup,
		dssetup_dissectors, hf_dssetup_opnum);
}
