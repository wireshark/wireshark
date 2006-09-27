/* DO NOT EDIT
	This filter was automatically generated
	from wzcsvc.idl and wzcsvc.cnf.
	
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
#include "packet-dcerpc-wzcsvc.h"

/* Ett declarations */
static gint ett_dcerpc_wzcsvc = -1;


/* Header field declarations */
static gint hf_wzcsvc_opnum = -1;

static gint proto_dcerpc_wzcsvc = -1;
/* Version information */


static e_uuid_t uuid_dcerpc_wzcsvc = {
	0x378e52b0, 0xc0a9, 0x11cf,
	{ 0x82, 0x2d, 0x00, 0xaa, 0x00, 0x51, 0xe4, 0x0f }
};
static guint16 ver_dcerpc_wzcsvc = 1;


/* IDL: void wzcsvc_EnumInterfaces( */
/* IDL:  */
/* IDL: ); */

static int
wzcsvc_dissect_EnumInterfaces_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	return offset;
}

static int
wzcsvc_dissect_EnumInterfaces_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: void wzcsvc_QueryInterface( */
/* IDL:  */
/* IDL: ); */

static int
wzcsvc_dissect_QueryInterface_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	return offset;
}

static int
wzcsvc_dissect_QueryInterface_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: void wzcsvc_SetInterface( */
/* IDL:  */
/* IDL: ); */

static int
wzcsvc_dissect_SetInterface_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	return offset;
}

static int
wzcsvc_dissect_SetInterface_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: void wzcsvc_RefreshInterface( */
/* IDL:  */
/* IDL: ); */

static int
wzcsvc_dissect_RefreshInterface_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	return offset;
}

static int
wzcsvc_dissect_RefreshInterface_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: void wzcsvc_QueryContext( */
/* IDL:  */
/* IDL: ); */

static int
wzcsvc_dissect_QueryContext_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	return offset;
}

static int
wzcsvc_dissect_QueryContext_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: void wzcsvc_SetContext( */
/* IDL:  */
/* IDL: ); */

static int
wzcsvc_dissect_SetContext_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	return offset;
}

static int
wzcsvc_dissect_SetContext_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: void wzcsvc_EapolUIResponse( */
/* IDL:  */
/* IDL: ); */

static int
wzcsvc_dissect_EapolUIResponse_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	return offset;
}

static int
wzcsvc_dissect_EapolUIResponse_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: void wzcsvc_EapolGetCustomAuthData( */
/* IDL:  */
/* IDL: ); */

static int
wzcsvc_dissect_EapolGetCustomAuthData_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	return offset;
}

static int
wzcsvc_dissect_EapolGetCustomAuthData_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: void wzcsvc_EapolSetCustomAuthData( */
/* IDL:  */
/* IDL: ); */

static int
wzcsvc_dissect_EapolSetCustomAuthData_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	return offset;
}

static int
wzcsvc_dissect_EapolSetCustomAuthData_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: void wzcsvc_EapolGetInterfaceParams( */
/* IDL:  */
/* IDL: ); */

static int
wzcsvc_dissect_EapolGetInterfaceParams_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	return offset;
}

static int
wzcsvc_dissect_EapolGetInterfaceParams_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: void wzcsvc_EapolSetInterfaceParams( */
/* IDL:  */
/* IDL: ); */

static int
wzcsvc_dissect_EapolSetInterfaceParams_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	return offset;
}

static int
wzcsvc_dissect_EapolSetInterfaceParams_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: void wzcsvc_EapolReAuthenticateInterface( */
/* IDL:  */
/* IDL: ); */

static int
wzcsvc_dissect_EapolReAuthenticateInterface_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	return offset;
}

static int
wzcsvc_dissect_EapolReAuthenticateInterface_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: void wzcsvc_EapolQueryInterfaceState( */
/* IDL:  */
/* IDL: ); */

static int
wzcsvc_dissect_EapolQueryInterfaceState_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	return offset;
}

static int
wzcsvc_dissect_EapolQueryInterfaceState_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: void wzcsvc_OpenWZCDbLogSession( */
/* IDL:  */
/* IDL: ); */

static int
wzcsvc_dissect_OpenWZCDbLogSession_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	return offset;
}

static int
wzcsvc_dissect_OpenWZCDbLogSession_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: void wzcsvc_CloseWZCDbLogSession( */
/* IDL:  */
/* IDL: ); */

static int
wzcsvc_dissect_CloseWZCDbLogSession_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	return offset;
}

static int
wzcsvc_dissect_CloseWZCDbLogSession_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: void wzcsvc_EnumWZCDbLogRecords( */
/* IDL:  */
/* IDL: ); */

static int
wzcsvc_dissect_EnumWZCDbLogRecords_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	return offset;
}

static int
wzcsvc_dissect_EnumWZCDbLogRecords_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: void wzcsvc_FlushWZCdbLog( */
/* IDL:  */
/* IDL: ); */

static int
wzcsvc_dissect_FlushWZCdbLog_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	return offset;
}

static int
wzcsvc_dissect_FlushWZCdbLog_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: void wzcsvc_GetWZCDbLogRecord( */
/* IDL:  */
/* IDL: ); */

static int
wzcsvc_dissect_GetWZCDbLogRecord_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	return offset;
}

static int
wzcsvc_dissect_GetWZCDbLogRecord_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}


static dcerpc_sub_dissector wzcsvc_dissectors[] = {
	{ 0, "EnumInterfaces",
	   wzcsvc_dissect_EnumInterfaces_request, wzcsvc_dissect_EnumInterfaces_response},
	{ 1, "QueryInterface",
	   wzcsvc_dissect_QueryInterface_request, wzcsvc_dissect_QueryInterface_response},
	{ 2, "SetInterface",
	   wzcsvc_dissect_SetInterface_request, wzcsvc_dissect_SetInterface_response},
	{ 3, "RefreshInterface",
	   wzcsvc_dissect_RefreshInterface_request, wzcsvc_dissect_RefreshInterface_response},
	{ 4, "QueryContext",
	   wzcsvc_dissect_QueryContext_request, wzcsvc_dissect_QueryContext_response},
	{ 5, "SetContext",
	   wzcsvc_dissect_SetContext_request, wzcsvc_dissect_SetContext_response},
	{ 6, "EapolUIResponse",
	   wzcsvc_dissect_EapolUIResponse_request, wzcsvc_dissect_EapolUIResponse_response},
	{ 7, "EapolGetCustomAuthData",
	   wzcsvc_dissect_EapolGetCustomAuthData_request, wzcsvc_dissect_EapolGetCustomAuthData_response},
	{ 8, "EapolSetCustomAuthData",
	   wzcsvc_dissect_EapolSetCustomAuthData_request, wzcsvc_dissect_EapolSetCustomAuthData_response},
	{ 9, "EapolGetInterfaceParams",
	   wzcsvc_dissect_EapolGetInterfaceParams_request, wzcsvc_dissect_EapolGetInterfaceParams_response},
	{ 10, "EapolSetInterfaceParams",
	   wzcsvc_dissect_EapolSetInterfaceParams_request, wzcsvc_dissect_EapolSetInterfaceParams_response},
	{ 11, "EapolReAuthenticateInterface",
	   wzcsvc_dissect_EapolReAuthenticateInterface_request, wzcsvc_dissect_EapolReAuthenticateInterface_response},
	{ 12, "EapolQueryInterfaceState",
	   wzcsvc_dissect_EapolQueryInterfaceState_request, wzcsvc_dissect_EapolQueryInterfaceState_response},
	{ 13, "OpenWZCDbLogSession",
	   wzcsvc_dissect_OpenWZCDbLogSession_request, wzcsvc_dissect_OpenWZCDbLogSession_response},
	{ 14, "CloseWZCDbLogSession",
	   wzcsvc_dissect_CloseWZCDbLogSession_request, wzcsvc_dissect_CloseWZCDbLogSession_response},
	{ 15, "EnumWZCDbLogRecords",
	   wzcsvc_dissect_EnumWZCDbLogRecords_request, wzcsvc_dissect_EnumWZCDbLogRecords_response},
	{ 16, "FlushWZCdbLog",
	   wzcsvc_dissect_FlushWZCdbLog_request, wzcsvc_dissect_FlushWZCdbLog_response},
	{ 17, "GetWZCDbLogRecord",
	   wzcsvc_dissect_GetWZCDbLogRecord_request, wzcsvc_dissect_GetWZCDbLogRecord_response},
	{ 0, NULL, NULL, NULL }
};

void proto_register_dcerpc_wzcsvc(void)
{
	static hf_register_info hf[] = {
	{ &hf_wzcsvc_opnum, 
	  { "Operation", "wzcsvc.opnum", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
	};


	static gint *ett[] = {
		&ett_dcerpc_wzcsvc,
	};

	proto_dcerpc_wzcsvc = proto_register_protocol("Wireless Configuration Service", "WZCSVC", "wzcsvc");
	proto_register_field_array(proto_dcerpc_wzcsvc, hf, array_length (hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_dcerpc_wzcsvc(void)
{
	dcerpc_init_uuid(proto_dcerpc_wzcsvc, ett_dcerpc_wzcsvc,
		&uuid_dcerpc_wzcsvc, ver_dcerpc_wzcsvc,
		wzcsvc_dissectors, hf_wzcsvc_opnum);
}
