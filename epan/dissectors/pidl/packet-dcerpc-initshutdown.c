/* DO NOT EDIT
	This filter was automatically generated
	from initshutdown.idl and initshutdown.cnf.
	
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
#include "packet-dcerpc-initshutdown.h"

/* Ett declarations */
static gint ett_dcerpc_initshutdown = -1;
static gint ett_initshutdown_initshutdown_String_sub = -1;
static gint ett_initshutdown_initshutdown_String = -1;


/* Header field declarations */
static gint hf_initshutdown_initshutdown_String_name_len = -1;
static gint hf_initshutdown_opnum = -1;
static gint hf_initshutdown_initshutdown_Init_hostname = -1;
static gint hf_initshutdown_initshutdown_String_sub_name = -1;
static gint hf_initshutdown_initshutdown_String_sub_name_size = -1;
static gint hf_initshutdown_initshutdown_InitEx_reason = -1;
static gint hf_initshutdown_initshutdown_InitEx_force_apps = -1;
static gint hf_initshutdown_initshutdown_InitEx_timeout = -1;
static gint hf_initshutdown_initshutdown_Init_timeout = -1;
static gint hf_initshutdown_initshutdown_String_name_size = -1;
static gint hf_initshutdown_initshutdown_Init_force_apps = -1;
static gint hf_initshutdown_initshutdown_InitEx_hostname = -1;
static gint hf_initshutdown_initshutdown_Init_reboot = -1;
static gint hf_initshutdown_initshutdown_InitEx_reboot = -1;
static gint hf_initshutdown_initshutdown_Init_message = -1;
static gint hf_initshutdown_werror = -1;
static gint hf_initshutdown_initshutdown_InitEx_message = -1;
static gint hf_initshutdown_initshutdown_Abort_server = -1;
static gint hf_initshutdown_initshutdown_String_name = -1;

static gint proto_dcerpc_initshutdown = -1;
/* Version information */


static e_uuid_t uuid_dcerpc_initshutdown = {
	0x894de0c0, 0x0d55, 0x11d3,
	{ 0xa3, 0x22, 0x00, 0xc0, 0x4f, 0xa3, 0x21, 0xa1 }
};
static guint16 ver_dcerpc_initshutdown = 1;

static int initshutdown_dissect_element_String_sub_name_size(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int initshutdown_dissect_element_String_sub_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int initshutdown_dissect_element_String_name_len(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int initshutdown_dissect_element_String_name_size(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int initshutdown_dissect_element_String_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int initshutdown_dissect_element_String_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int initshutdown_dissect_element_Init_hostname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int initshutdown_dissect_element_Init_hostname_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int initshutdown_dissect_element_Init_message(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int initshutdown_dissect_element_Init_message_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int initshutdown_dissect_element_Init_timeout(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int initshutdown_dissect_element_Init_force_apps(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int initshutdown_dissect_element_Init_reboot(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int initshutdown_dissect_element_Abort_server(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int initshutdown_dissect_element_Abort_server_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int initshutdown_dissect_element_InitEx_hostname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int initshutdown_dissect_element_InitEx_hostname_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int initshutdown_dissect_element_InitEx_message(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int initshutdown_dissect_element_InitEx_message_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int initshutdown_dissect_element_InitEx_timeout(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int initshutdown_dissect_element_InitEx_force_apps(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int initshutdown_dissect_element_InitEx_reboot(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int initshutdown_dissect_element_InitEx_reason(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);

/* IDL: typedef struct { */
/* IDL: 	[value(strlen_m_term(name))] uint32 name_size; */
/* IDL: 	[flag(LIBNDR_FLAG_STR_LEN4|LIBNDR_FLAG_STR_NOTERM)] string name; */
/* IDL: } initshutdown_String_sub; */

static int
initshutdown_dissect_element_String_sub_name_size(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_initshutdown_initshutdown_String_sub_name_size,NULL);

	return offset;
}

static int
initshutdown_dissect_element_String_sub_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

	return offset;
}

int
initshutdown_dissect_struct_String_sub(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_initshutdown_initshutdown_String_sub);
	}
	
	offset = initshutdown_dissect_element_String_sub_name_size(tvb, offset, pinfo, tree, drep);

	offset = initshutdown_dissect_element_String_sub_name(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	[value(strlen_m(r->name->name)*2)] uint16 name_len; */
/* IDL: 	[value(strlen_m_term(r->name->name)*2)] uint16 name_size; */
/* IDL: 	[unique(1)] initshutdown_String_sub *name; */
/* IDL: } initshutdown_String; */

static int
initshutdown_dissect_element_String_name_len(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_initshutdown_initshutdown_String_name_len,NULL);

	return offset;
}

static int
initshutdown_dissect_element_String_name_size(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_initshutdown_initshutdown_String_name_size,NULL);

	return offset;
}

static int
initshutdown_dissect_element_String_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, initshutdown_dissect_element_String_name_, NDR_POINTER_UNIQUE, "Pointer to Name (initshutdown_String_sub)",hf_initshutdown_initshutdown_String_name);

	return offset;
}

static int
initshutdown_dissect_element_String_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = initshutdown_dissect_struct_String_sub(tvb,offset,pinfo,tree,drep,hf_initshutdown_initshutdown_String_name,0);

	return offset;
}

int
initshutdown_dissect_struct_String(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_initshutdown_initshutdown_String);
	}
	
	offset = initshutdown_dissect_element_String_name_len(tvb, offset, pinfo, tree, drep);

	offset = initshutdown_dissect_element_String_name_size(tvb, offset, pinfo, tree, drep);

	offset = initshutdown_dissect_element_String_name(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

static int
initshutdown_dissect_element_Init_hostname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, initshutdown_dissect_element_Init_hostname_, NDR_POINTER_UNIQUE, "Pointer to Hostname (uint16)",hf_initshutdown_initshutdown_Init_hostname);

	return offset;
}

static int
initshutdown_dissect_element_Init_hostname_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_initshutdown_initshutdown_Init_hostname,NULL);

	return offset;
}

static int
initshutdown_dissect_element_Init_message(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, initshutdown_dissect_element_Init_message_, NDR_POINTER_UNIQUE, "Pointer to Message (initshutdown_String)",hf_initshutdown_initshutdown_Init_message);

	return offset;
}

static int
initshutdown_dissect_element_Init_message_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = initshutdown_dissect_struct_String(tvb,offset,pinfo,tree,drep,hf_initshutdown_initshutdown_Init_message,0);

	return offset;
}

static int
initshutdown_dissect_element_Init_timeout(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_initshutdown_initshutdown_Init_timeout,NULL);

	return offset;
}

static int
initshutdown_dissect_element_Init_force_apps(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep, hf_initshutdown_initshutdown_Init_force_apps,NULL);

	return offset;
}

static int
initshutdown_dissect_element_Init_reboot(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep, hf_initshutdown_initshutdown_Init_reboot,NULL);

	return offset;
}

/* IDL: WERROR initshutdown_Init( */
/* IDL: [unique(1)] [in] uint16 *hostname, */
/* IDL: [unique(1)] [in] initshutdown_String *message, */
/* IDL: [in] uint32 timeout, */
/* IDL: [in] uint8 force_apps, */
/* IDL: [in] uint8 reboot */
/* IDL: ); */

static int
initshutdown_dissect_Init_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_initshutdown_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
initshutdown_dissect_Init_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = initshutdown_dissect_element_Init_hostname(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = initshutdown_dissect_element_Init_message(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = initshutdown_dissect_element_Init_timeout(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = initshutdown_dissect_element_Init_force_apps(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = initshutdown_dissect_element_Init_reboot(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
initshutdown_dissect_element_Abort_server(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, initshutdown_dissect_element_Abort_server_, NDR_POINTER_UNIQUE, "Pointer to Server (uint16)",hf_initshutdown_initshutdown_Abort_server);

	return offset;
}

static int
initshutdown_dissect_element_Abort_server_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_initshutdown_initshutdown_Abort_server,NULL);

	return offset;
}

/* IDL: WERROR initshutdown_Abort( */
/* IDL: [unique(1)] [in] uint16 *server */
/* IDL: ); */

static int
initshutdown_dissect_Abort_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_initshutdown_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
initshutdown_dissect_Abort_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = initshutdown_dissect_element_Abort_server(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
initshutdown_dissect_element_InitEx_hostname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, initshutdown_dissect_element_InitEx_hostname_, NDR_POINTER_UNIQUE, "Pointer to Hostname (uint16)",hf_initshutdown_initshutdown_InitEx_hostname);

	return offset;
}

static int
initshutdown_dissect_element_InitEx_hostname_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_initshutdown_initshutdown_InitEx_hostname,NULL);

	return offset;
}

static int
initshutdown_dissect_element_InitEx_message(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, initshutdown_dissect_element_InitEx_message_, NDR_POINTER_UNIQUE, "Pointer to Message (initshutdown_String)",hf_initshutdown_initshutdown_InitEx_message);

	return offset;
}

static int
initshutdown_dissect_element_InitEx_message_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = initshutdown_dissect_struct_String(tvb,offset,pinfo,tree,drep,hf_initshutdown_initshutdown_InitEx_message,0);

	return offset;
}

static int
initshutdown_dissect_element_InitEx_timeout(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_initshutdown_initshutdown_InitEx_timeout,NULL);

	return offset;
}

static int
initshutdown_dissect_element_InitEx_force_apps(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep, hf_initshutdown_initshutdown_InitEx_force_apps,NULL);

	return offset;
}

static int
initshutdown_dissect_element_InitEx_reboot(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep, hf_initshutdown_initshutdown_InitEx_reboot,NULL);

	return offset;
}

static int
initshutdown_dissect_element_InitEx_reason(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_initshutdown_initshutdown_InitEx_reason,NULL);

	return offset;
}

/* IDL: WERROR initshutdown_InitEx( */
/* IDL: [unique(1)] [in] uint16 *hostname, */
/* IDL: [unique(1)] [in] initshutdown_String *message, */
/* IDL: [in] uint32 timeout, */
/* IDL: [in] uint8 force_apps, */
/* IDL: [in] uint8 reboot, */
/* IDL: [in] uint32 reason */
/* IDL: ); */

static int
initshutdown_dissect_InitEx_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_initshutdown_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
initshutdown_dissect_InitEx_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = initshutdown_dissect_element_InitEx_hostname(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = initshutdown_dissect_element_InitEx_message(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = initshutdown_dissect_element_InitEx_timeout(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = initshutdown_dissect_element_InitEx_force_apps(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = initshutdown_dissect_element_InitEx_reboot(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = initshutdown_dissect_element_InitEx_reason(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
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
	{ &hf_initshutdown_initshutdown_String_name_len, 
	  { "Name Len", "initshutdown.initshutdown_String.name_len", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_initshutdown_opnum, 
	  { "Operation", "initshutdown.opnum", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_initshutdown_initshutdown_Init_hostname, 
	  { "Hostname", "initshutdown.initshutdown_Init.hostname", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_initshutdown_initshutdown_String_sub_name, 
	  { "Name", "initshutdown.initshutdown_String_sub.name", FT_NONE, BASE_HEX, NULL, 0, "", HFILL }},
	{ &hf_initshutdown_initshutdown_String_sub_name_size, 
	  { "Name Size", "initshutdown.initshutdown_String_sub.name_size", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_initshutdown_initshutdown_InitEx_reason, 
	  { "Reason", "initshutdown.initshutdown_InitEx.reason", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_initshutdown_initshutdown_InitEx_force_apps, 
	  { "Force Apps", "initshutdown.initshutdown_InitEx.force_apps", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_initshutdown_initshutdown_InitEx_timeout, 
	  { "Timeout", "initshutdown.initshutdown_InitEx.timeout", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_initshutdown_initshutdown_Init_timeout, 
	  { "Timeout", "initshutdown.initshutdown_Init.timeout", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_initshutdown_initshutdown_String_name_size, 
	  { "Name Size", "initshutdown.initshutdown_String.name_size", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_initshutdown_initshutdown_Init_force_apps, 
	  { "Force Apps", "initshutdown.initshutdown_Init.force_apps", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_initshutdown_initshutdown_InitEx_hostname, 
	  { "Hostname", "initshutdown.initshutdown_InitEx.hostname", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_initshutdown_initshutdown_Init_reboot, 
	  { "Reboot", "initshutdown.initshutdown_Init.reboot", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_initshutdown_initshutdown_InitEx_reboot, 
	  { "Reboot", "initshutdown.initshutdown_InitEx.reboot", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_initshutdown_initshutdown_Init_message, 
	  { "Message", "initshutdown.initshutdown_Init.message", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_initshutdown_werror, 
	  { "Windows Error", "initshutdown.werror", FT_UINT32, BASE_HEX, VALS(DOS_errors), 0, "", HFILL }},
	{ &hf_initshutdown_initshutdown_InitEx_message, 
	  { "Message", "initshutdown.initshutdown_InitEx.message", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_initshutdown_initshutdown_Abort_server, 
	  { "Server", "initshutdown.initshutdown_Abort.server", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_initshutdown_initshutdown_String_name, 
	  { "Name", "initshutdown.initshutdown_String.name", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	};


	static gint *ett[] = {
		&ett_dcerpc_initshutdown,
		&ett_initshutdown_initshutdown_String_sub,
		&ett_initshutdown_initshutdown_String,
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
