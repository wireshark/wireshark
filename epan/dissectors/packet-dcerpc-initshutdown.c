/* DO NOT EDIT
	This filter was automatically generated
	from initshutdown.idl and initshutdown.cnf.

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
#include "packet-dcerpc-initshutdown.h"

void proto_register_dcerpc_initshutdown(void);
void proto_reg_handoff_dcerpc_initshutdown(void);

/* Ett declarations */
static gint ett_dcerpc_initshutdown = -1;
static gint ett_initshutdown_initshutdown_ReasonFlags = -1;


/* Header field declarations */
static gint hf_initshutdown_initshutdown_InitEx_do_reboot = -1;
static gint hf_initshutdown_opnum = -1;
static gint hf_initshutdown_initshutdown_Init_hostname = -1;
static gint hf_initshutdown_initshutdown_InitEx_reason = -1;
static gint hf_initshutdown_initshutdown_InitEx_force_apps = -1;
static gint hf_initshutdown_initshutdown_ReasonFlags_SHTDN_REASON_FLAG_PLANNED = -1;
static gint hf_initshutdown_initshutdown_ReasonFlags_SHTDN_REASON_FLAG_USER_DEFINED = -1;
static gint hf_initshutdown_initshutdown_InitEx_timeout = -1;
static gint hf_initshutdown_initshutdown_Init_timeout = -1;
static gint hf_initshutdown_initshutdown_Init_force_apps = -1;
static gint hf_initshutdown_initshutdown_InitEx_hostname = -1;
static gint hf_initshutdown_initshutdown_Init_do_reboot = -1;
static gint hf_initshutdown_initshutdown_Init_message = -1;
static gint hf_initshutdown_werror = -1;
static gint hf_initshutdown_initshutdown_InitEx_message = -1;
static gint hf_initshutdown_initshutdown_Abort_server = -1;

static gint proto_dcerpc_initshutdown = -1;
/* Version information */


static e_uuid_t uuid_dcerpc_initshutdown = {
	0x894de0c0, 0x0d55, 0x11d3,
	{ 0xa3, 0x22, 0x00, 0xc0, 0x4f, 0xa3, 0x21, 0xa1 }
};
static guint16 ver_dcerpc_initshutdown = 1;

const value_string initshutdown_initshutdown_ReasonMajor_vals[] = {
	{ SHTDN_REASON_MAJOR_OTHER, "SHTDN_REASON_MAJOR_OTHER" },
	{ SHTDN_REASON_MAJOR_HARDWARE, "SHTDN_REASON_MAJOR_HARDWARE" },
	{ SHTDN_REASON_MAJOR_OPERATINGSYSTEM, "SHTDN_REASON_MAJOR_OPERATINGSYSTEM" },
	{ SHTDN_REASON_MAJOR_SOFTWARE, "SHTDN_REASON_MAJOR_SOFTWARE" },
	{ SHTDN_REASON_MAJOR_APPLICATION, "SHTDN_REASON_MAJOR_APPLICATION" },
	{ SHTDN_REASON_MAJOR_SYSTEM, "SHTDN_REASON_MAJOR_SYSTEM" },
	{ SHTDN_REASON_MAJOR_POWER, "SHTDN_REASON_MAJOR_POWER" },
	{ SHTDN_REASON_MAJOR_LEGACY_API, "SHTDN_REASON_MAJOR_LEGACY_API" },
{ 0, NULL }
};
const value_string initshutdown_initshutdown_ReasonMinor_vals[] = {
	{ SHTDN_REASON_MINOR_OTHER, "SHTDN_REASON_MINOR_OTHER" },
	{ SHTDN_REASON_MINOR_MAINTENANCE, "SHTDN_REASON_MINOR_MAINTENANCE" },
	{ SHTDN_REASON_MINOR_INSTALLATION, "SHTDN_REASON_MINOR_INSTALLATION" },
	{ SHTDN_REASON_MINOR_UPGRADE, "SHTDN_REASON_MINOR_UPGRADE" },
	{ SHTDN_REASON_MINOR_RECONFIG, "SHTDN_REASON_MINOR_RECONFIG" },
	{ SHTDN_REASON_MINOR_HUNG, "SHTDN_REASON_MINOR_HUNG" },
	{ SHTDN_REASON_MINOR_UNSTABLE, "SHTDN_REASON_MINOR_UNSTABLE" },
	{ SHTDN_REASON_MINOR_DISK, "SHTDN_REASON_MINOR_DISK" },
	{ SHTDN_REASON_MINOR_PROCESSOR, "SHTDN_REASON_MINOR_PROCESSOR" },
	{ SHTDN_REASON_MINOR_NETWORKCARD, "SHTDN_REASON_MINOR_NETWORKCARD" },
	{ SHTDN_REASON_MINOR_POWER_SUPPLY, "SHTDN_REASON_MINOR_POWER_SUPPLY" },
	{ SHTDN_REASON_MINOR_CORDUNPLUGGED, "SHTDN_REASON_MINOR_CORDUNPLUGGED" },
	{ SHTDN_REASON_MINOR_ENVIRONMENT, "SHTDN_REASON_MINOR_ENVIRONMENT" },
	{ SHTDN_REASON_MINOR_HARDWARE_DRIVER, "SHTDN_REASON_MINOR_HARDWARE_DRIVER" },
	{ SHTDN_REASON_MINOR_OTHERDRIVER, "SHTDN_REASON_MINOR_OTHERDRIVER" },
	{ SHTDN_REASON_MINOR_BLUESCREEN, "SHTDN_REASON_MINOR_BLUESCREEN" },
	{ SHTDN_REASON_MINOR_SERVICEPACK, "SHTDN_REASON_MINOR_SERVICEPACK" },
	{ SHTDN_REASON_MINOR_HOTFIX, "SHTDN_REASON_MINOR_HOTFIX" },
	{ SHTDN_REASON_MINOR_SECURITYFIX, "SHTDN_REASON_MINOR_SECURITYFIX" },
	{ SHTDN_REASON_MINOR_SECURITY, "SHTDN_REASON_MINOR_SECURITY" },
	{ SHTDN_REASON_MINOR_NETWORK_CONNECTIVITY, "SHTDN_REASON_MINOR_NETWORK_CONNECTIVITY" },
	{ SHTDN_REASON_MINOR_WMI, "SHTDN_REASON_MINOR_WMI" },
	{ SHTDN_REASON_MINOR_SERVICEPACK_UNINSTALL, "SHTDN_REASON_MINOR_SERVICEPACK_UNINSTALL" },
	{ SHTDN_REASON_MINOR_HOTFIX_UNINSTALL, "SHTDN_REASON_MINOR_HOTFIX_UNINSTALL" },
	{ SHTDN_REASON_MINOR_SECURITYFIX_UNINSTALL, "SHTDN_REASON_MINOR_SECURITYFIX_UNINSTALL" },
	{ SHTDN_REASON_MINOR_MMC, "SHTDN_REASON_MINOR_MMC" },
	{ SHTDN_REASON_MINOR_TERMSRV, "SHTDN_REASON_MINOR_TERMSRV" },
{ 0, NULL }
};
static const true_false_string initshutdown_ReasonFlags_SHTDN_REASON_FLAG_USER_DEFINED_tfs = {
   "SHTDN_REASON_FLAG_USER_DEFINED is SET",
   "SHTDN_REASON_FLAG_USER_DEFINED is NOT SET",
};
static const true_false_string initshutdown_ReasonFlags_SHTDN_REASON_FLAG_PLANNED_tfs = {
   "SHTDN_REASON_FLAG_PLANNED is SET",
   "SHTDN_REASON_FLAG_PLANNED is NOT SET",
};
static int initshutdown_dissect_element_Init_hostname(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int initshutdown_dissect_element_Init_hostname_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int initshutdown_dissect_element_Init_message(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int initshutdown_dissect_element_Init_message_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int initshutdown_dissect_element_Init_timeout(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int initshutdown_dissect_element_Init_force_apps(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int initshutdown_dissect_element_Init_do_reboot(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int initshutdown_dissect_element_Abort_server(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int initshutdown_dissect_element_Abort_server_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int initshutdown_dissect_element_InitEx_hostname(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int initshutdown_dissect_element_InitEx_hostname_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int initshutdown_dissect_element_InitEx_message(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int initshutdown_dissect_element_InitEx_message_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int initshutdown_dissect_element_InitEx_timeout(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int initshutdown_dissect_element_InitEx_force_apps(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int initshutdown_dissect_element_InitEx_do_reboot(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int initshutdown_dissect_element_InitEx_reason(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);


/* IDL: enum { */
/* IDL: 	SHTDN_REASON_MAJOR_OTHER=0x00000000, */
/* IDL: 	SHTDN_REASON_MAJOR_HARDWARE=0x00010000, */
/* IDL: 	SHTDN_REASON_MAJOR_OPERATINGSYSTEM=0x00020000, */
/* IDL: 	SHTDN_REASON_MAJOR_SOFTWARE=0x00030000, */
/* IDL: 	SHTDN_REASON_MAJOR_APPLICATION=0x00040000, */
/* IDL: 	SHTDN_REASON_MAJOR_SYSTEM=0x00050000, */
/* IDL: 	SHTDN_REASON_MAJOR_POWER=0x00060000, */
/* IDL: 	SHTDN_REASON_MAJOR_LEGACY_API=0x00070000, */
/* IDL: } */

int
initshutdown_dissect_enum_ReasonMajor(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_)
{
	guint32 parameter=0;
	if(param){
		parameter=(guint32)*param;
	}
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_index, &parameter);
	if(param){
		*param=(guint32)parameter;
	}
	return offset;
}


/* IDL: enum { */
/* IDL: 	SHTDN_REASON_MINOR_OTHER=0x00000000, */
/* IDL: 	SHTDN_REASON_MINOR_MAINTENANCE=0x00000001, */
/* IDL: 	SHTDN_REASON_MINOR_INSTALLATION=0x00000002, */
/* IDL: 	SHTDN_REASON_MINOR_UPGRADE=0x00000003, */
/* IDL: 	SHTDN_REASON_MINOR_RECONFIG=0x00000004, */
/* IDL: 	SHTDN_REASON_MINOR_HUNG=0x00000005, */
/* IDL: 	SHTDN_REASON_MINOR_UNSTABLE=0x00000006, */
/* IDL: 	SHTDN_REASON_MINOR_DISK=0x00000007, */
/* IDL: 	SHTDN_REASON_MINOR_PROCESSOR=0x00000008, */
/* IDL: 	SHTDN_REASON_MINOR_NETWORKCARD=0x00000009, */
/* IDL: 	SHTDN_REASON_MINOR_POWER_SUPPLY=0x0000000a, */
/* IDL: 	SHTDN_REASON_MINOR_CORDUNPLUGGED=0x0000000b, */
/* IDL: 	SHTDN_REASON_MINOR_ENVIRONMENT=0x0000000c, */
/* IDL: 	SHTDN_REASON_MINOR_HARDWARE_DRIVER=0x0000000d, */
/* IDL: 	SHTDN_REASON_MINOR_OTHERDRIVER=0x0000000e, */
/* IDL: 	SHTDN_REASON_MINOR_BLUESCREEN=0x0000000f, */
/* IDL: 	SHTDN_REASON_MINOR_SERVICEPACK=0x00000010, */
/* IDL: 	SHTDN_REASON_MINOR_HOTFIX=0x00000011, */
/* IDL: 	SHTDN_REASON_MINOR_SECURITYFIX=0x00000012, */
/* IDL: 	SHTDN_REASON_MINOR_SECURITY=0x00000013, */
/* IDL: 	SHTDN_REASON_MINOR_NETWORK_CONNECTIVITY=0x00000014, */
/* IDL: 	SHTDN_REASON_MINOR_WMI=0x00000015, */
/* IDL: 	SHTDN_REASON_MINOR_SERVICEPACK_UNINSTALL=0x00000016, */
/* IDL: 	SHTDN_REASON_MINOR_HOTFIX_UNINSTALL=0x00000017, */
/* IDL: 	SHTDN_REASON_MINOR_SECURITYFIX_UNINSTALL=0x00000018, */
/* IDL: 	SHTDN_REASON_MINOR_MMC=0x00000019, */
/* IDL: 	SHTDN_REASON_MINOR_TERMSRV=0x00000020, */
/* IDL: } */

int
initshutdown_dissect_enum_ReasonMinor(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_)
{
	guint32 parameter=0;
	if(param){
		parameter=(guint32)*param;
	}
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_index, &parameter);
	if(param){
		*param=(guint32)parameter;
	}
	return offset;
}


/* IDL: bitmap { */
/* IDL: 	SHTDN_REASON_FLAG_USER_DEFINED =  0x40000000 , */
/* IDL: 	SHTDN_REASON_FLAG_PLANNED =  0x80000000 , */
/* IDL: } */

int
initshutdown_dissect_bitmap_ReasonFlags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	guint32 flags;
	ALIGN_TO_4_BYTES;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, 4, DREP_ENC_INTEGER(drep));
		tree = proto_item_add_subtree(item,ett_initshutdown_initshutdown_ReasonFlags);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, di, drep, -1, &flags);
	proto_item_append_text(item, ": ");

	if (!flags)
		proto_item_append_text(item, "(No values set)");

	proto_tree_add_boolean(tree, hf_initshutdown_initshutdown_ReasonFlags_SHTDN_REASON_FLAG_USER_DEFINED, tvb, offset-4, 4, flags);
	if (flags&( 0x40000000 )){
		proto_item_append_text(item, "SHTDN_REASON_FLAG_USER_DEFINED");
		if (flags & (~( 0x40000000 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x40000000 ));

	proto_tree_add_boolean(tree, hf_initshutdown_initshutdown_ReasonFlags_SHTDN_REASON_FLAG_PLANNED, tvb, offset-4, 4, flags);
	if (flags&( 0x80000000 )){
		proto_item_append_text(item, "SHTDN_REASON_FLAG_PLANNED");
		if (flags & (~( 0x80000000 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x80000000 ));

	if (flags) {
		proto_item_append_text(item, "Unknown bitmap value 0x%x", flags);
	}

	return offset;
}

static int
initshutdown_dissect_element_Init_hostname(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, initshutdown_dissect_element_Init_hostname_, NDR_POINTER_UNIQUE, "Pointer to Hostname (uint16)",hf_initshutdown_initshutdown_Init_hostname);

	return offset;
}

static int
initshutdown_dissect_element_Init_hostname_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, di, drep, hf_initshutdown_initshutdown_Init_hostname, 0);

	return offset;
}

static int
initshutdown_dissect_element_Init_message(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, initshutdown_dissect_element_Init_message_, NDR_POINTER_UNIQUE, "Pointer to Message (lsa_StringLarge)",hf_initshutdown_initshutdown_Init_message);

	return offset;
}

static int
initshutdown_dissect_element_Init_message_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset=lsarpc_dissect_struct_lsa_StringLarge(tvb, offset, pinfo, tree, di, drep, hf_initshutdown_initshutdown_Init_message, 0);

	return offset;
}

static int
initshutdown_dissect_element_Init_timeout(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_initshutdown_initshutdown_Init_timeout, 0);

	return offset;
}

static int
initshutdown_dissect_element_Init_force_apps(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, di, drep, hf_initshutdown_initshutdown_Init_force_apps, 0);

	return offset;
}

static int
initshutdown_dissect_element_Init_do_reboot(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, di, drep, hf_initshutdown_initshutdown_Init_do_reboot, 0);

	return offset;
}

/* IDL: WERROR initshutdown_Init( */
/* IDL: [unique(1)] [in] uint16 *hostname, */
/* IDL: [unique(1)] [in] lsa_StringLarge *message, */
/* IDL: [in] uint32 timeout, */
/* IDL: [in] uint8 force_apps, */
/* IDL: [in] uint8 do_reboot */
/* IDL: ); */

static int
initshutdown_dissect_Init_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="Init";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_initshutdown_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
initshutdown_dissect_Init_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="Init";
	offset = initshutdown_dissect_element_Init_hostname(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = initshutdown_dissect_element_Init_message(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = initshutdown_dissect_element_Init_timeout(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = initshutdown_dissect_element_Init_force_apps(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = initshutdown_dissect_element_Init_do_reboot(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
initshutdown_dissect_element_Abort_server(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, initshutdown_dissect_element_Abort_server_, NDR_POINTER_UNIQUE, "Pointer to Server (uint16)",hf_initshutdown_initshutdown_Abort_server);

	return offset;
}

static int
initshutdown_dissect_element_Abort_server_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, di, drep, hf_initshutdown_initshutdown_Abort_server, 0);

	return offset;
}

/* IDL: WERROR initshutdown_Abort( */
/* IDL: [unique(1)] [in] uint16 *server */
/* IDL: ); */

static int
initshutdown_dissect_Abort_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="Abort";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_initshutdown_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
initshutdown_dissect_Abort_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="Abort";
	offset = initshutdown_dissect_element_Abort_server(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
initshutdown_dissect_element_InitEx_hostname(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, initshutdown_dissect_element_InitEx_hostname_, NDR_POINTER_UNIQUE, "Pointer to Hostname (uint16)",hf_initshutdown_initshutdown_InitEx_hostname);

	return offset;
}

static int
initshutdown_dissect_element_InitEx_hostname_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, di, drep, hf_initshutdown_initshutdown_InitEx_hostname, 0);

	return offset;
}

static int
initshutdown_dissect_element_InitEx_message(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, initshutdown_dissect_element_InitEx_message_, NDR_POINTER_UNIQUE, "Pointer to Message (lsa_StringLarge)",hf_initshutdown_initshutdown_InitEx_message);

	return offset;
}

static int
initshutdown_dissect_element_InitEx_message_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset=lsarpc_dissect_struct_lsa_StringLarge(tvb, offset, pinfo, tree, di, drep, hf_initshutdown_initshutdown_InitEx_message, 0);

	return offset;
}

static int
initshutdown_dissect_element_InitEx_timeout(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_initshutdown_initshutdown_InitEx_timeout, 0);

	return offset;
}

static int
initshutdown_dissect_element_InitEx_force_apps(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, di, drep, hf_initshutdown_initshutdown_InitEx_force_apps, 0);

	return offset;
}

static int
initshutdown_dissect_element_InitEx_do_reboot(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, di, drep, hf_initshutdown_initshutdown_InitEx_do_reboot, 0);

	return offset;
}

static int
initshutdown_dissect_element_InitEx_reason(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_initshutdown_initshutdown_InitEx_reason, 0);

	return offset;
}

/* IDL: WERROR initshutdown_InitEx( */
/* IDL: [unique(1)] [in] uint16 *hostname, */
/* IDL: [unique(1)] [in] lsa_StringLarge *message, */
/* IDL: [in] uint32 timeout, */
/* IDL: [in] uint8 force_apps, */
/* IDL: [in] uint8 do_reboot, */
/* IDL: [in] uint32 reason */
/* IDL: ); */

static int
initshutdown_dissect_InitEx_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="InitEx";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_initshutdown_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
initshutdown_dissect_InitEx_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="InitEx";
	offset = initshutdown_dissect_element_InitEx_hostname(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = initshutdown_dissect_element_InitEx_message(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = initshutdown_dissect_element_InitEx_timeout(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = initshutdown_dissect_element_InitEx_force_apps(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = initshutdown_dissect_element_InitEx_do_reboot(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = initshutdown_dissect_element_InitEx_reason(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}


static dcerpc_sub_dissector initshutdown_dissectors[] = {
	{ 0, "Init",
	   initshutdown_dissect_Init_request, initshutdown_dissect_Init_response},
	{ 1, "Abort",
	   initshutdown_dissect_Abort_request, initshutdown_dissect_Abort_response},
	{ 2, "InitEx",
	   initshutdown_dissect_InitEx_request, initshutdown_dissect_InitEx_response},
	{ 0, NULL, NULL, NULL }
};

void proto_register_dcerpc_initshutdown(void)
{
	static hf_register_info hf[] = {
	{ &hf_initshutdown_initshutdown_InitEx_do_reboot,
	  { "Do Reboot", "initshutdown.initshutdown_InitEx.do_reboot", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_initshutdown_opnum,
	  { "Operation", "initshutdown.opnum", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_initshutdown_initshutdown_Init_hostname,
	  { "Hostname", "initshutdown.initshutdown_Init.hostname", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_initshutdown_initshutdown_InitEx_reason,
	  { "Reason", "initshutdown.initshutdown_InitEx.reason", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_initshutdown_initshutdown_InitEx_force_apps,
	  { "Force Apps", "initshutdown.initshutdown_InitEx.force_apps", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_initshutdown_initshutdown_ReasonFlags_SHTDN_REASON_FLAG_PLANNED,
	  { "Shtdn Reason Flag Planned", "initshutdown.initshutdown_ReasonFlags.SHTDN_REASON_FLAG_PLANNED", FT_BOOLEAN, 32, TFS(&initshutdown_ReasonFlags_SHTDN_REASON_FLAG_PLANNED_tfs), ( 0x80000000 ), NULL, HFILL }},
	{ &hf_initshutdown_initshutdown_ReasonFlags_SHTDN_REASON_FLAG_USER_DEFINED,
	  { "Shtdn Reason Flag User Defined", "initshutdown.initshutdown_ReasonFlags.SHTDN_REASON_FLAG_USER_DEFINED", FT_BOOLEAN, 32, TFS(&initshutdown_ReasonFlags_SHTDN_REASON_FLAG_USER_DEFINED_tfs), ( 0x40000000 ), NULL, HFILL }},
	{ &hf_initshutdown_initshutdown_InitEx_timeout,
	  { "Timeout", "initshutdown.initshutdown_InitEx.timeout", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_initshutdown_initshutdown_Init_timeout,
	  { "Timeout", "initshutdown.initshutdown_Init.timeout", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_initshutdown_initshutdown_Init_force_apps,
	  { "Force Apps", "initshutdown.initshutdown_Init.force_apps", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_initshutdown_initshutdown_InitEx_hostname,
	  { "Hostname", "initshutdown.initshutdown_InitEx.hostname", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_initshutdown_initshutdown_Init_do_reboot,
	  { "Do Reboot", "initshutdown.initshutdown_Init.do_reboot", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_initshutdown_initshutdown_Init_message,
	  { "Message", "initshutdown.initshutdown_Init.message", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_initshutdown_werror,
	  { "Windows Error", "initshutdown.werror", FT_UINT32, BASE_HEX, VALS(WERR_errors), 0, NULL, HFILL }},
	{ &hf_initshutdown_initshutdown_InitEx_message,
	  { "Message", "initshutdown.initshutdown_InitEx.message", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_initshutdown_initshutdown_Abort_server,
	  { "Server", "initshutdown.initshutdown_Abort.server", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	};


	static gint *ett[] = {
		&ett_dcerpc_initshutdown,
		&ett_initshutdown_initshutdown_ReasonFlags,
	};

	proto_dcerpc_initshutdown = proto_register_protocol("Init shutdown service", "INITSHUTDOWN", "initshutdown");
	proto_register_field_array(proto_dcerpc_initshutdown, hf, array_length (hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_dcerpc_initshutdown(void)
{
	dcerpc_init_uuid(proto_dcerpc_initshutdown, ett_dcerpc_initshutdown,
		&uuid_dcerpc_initshutdown, ver_dcerpc_initshutdown,
		initshutdown_dissectors, hf_initshutdown_opnum);
}
