/* packet-dcerpc-svcctl.c
 * Routines for SMB \PIPE\svcctl packet disassembly
 * Copyright 2003, Tim Potter <tpot@samba.org>
 * Copyright 2003, Ronnie Sahlberg,  added function dissectors
 *
 * $Id: packet-dcerpc-svcctl.c,v 1.4 2003/04/27 04:38:10 sahlberg Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-svcctl.h"
#include "packet-dcerpc-nt.h"
#include "smb.h"
#include "packet-smb-common.h"

static int proto_dcerpc_svcctl = -1;
static int hf_svcctl_opnum = -1;
static int hf_svcctl_machinename = -1;
static int hf_svcctl_database = -1;
static int hf_svcctl_access_mask = -1;
static int hf_svcctl_scm_rights_connect = -1;
static int hf_svcctl_scm_rights_create_service = -1;
static int hf_svcctl_scm_rights_enumerate_service = -1;
static int hf_svcctl_scm_rights_lock = -1;
static int hf_svcctl_scm_rights_query_lock_status = -1;
static int hf_svcctl_scm_rights_modify_boot_config = -1;
static int hf_svcctl_hnd = -1;
static int hf_svcctl_lock = -1;
static int hf_svcctl_rc = -1;
static int hf_svcctl_size = -1;
static int hf_svcctl_required_size = -1;
static int hf_svcctl_is_locked = -1;
static int hf_svcctl_lock_duration = -1;
static int hf_svcctl_lock_owner = -1;

static gint ett_dcerpc_svcctl = -1;

static e_uuid_t uuid_dcerpc_svcctl = {
        0x367abb81, 0x9844, 0x35f1,
        { 0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03 }
};

static guint16 ver_dcerpc_svcctl = 2;




static void
svcctl_scm_specific_rights(tvbuff_t *tvb, gint offset, proto_tree *tree,
		    guint32 access)
{
	proto_tree_add_boolean(tree, hf_svcctl_scm_rights_modify_boot_config, tvb, offset, 4, access);
	proto_tree_add_boolean(tree, hf_svcctl_scm_rights_query_lock_status, tvb, offset, 4, access);
	proto_tree_add_boolean(tree, hf_svcctl_scm_rights_lock, tvb, offset, 4, access);
	proto_tree_add_boolean(tree, hf_svcctl_scm_rights_enumerate_service, tvb, offset, 4, access);
	proto_tree_add_boolean(tree, hf_svcctl_scm_rights_create_service, tvb, offset, 4, access);
	proto_tree_add_boolean(tree, hf_svcctl_scm_rights_connect, tvb, offset, 4, access);
}

/*
 * IDL long OpenSCManager(
 * IDL      [in] [string] [unique] char *MachineName,
 * IDL      [in] [string] [unique] char *DatabaseName,
 * IDL      [in] long access_mask,
 * IDL      [out] SC_HANDLE handle,
 * IDL );
 */
static int
svcctl_dissect_OpenSCManager_rqst(tvbuff_t *tvb, int offset, 
				  packet_info *pinfo, proto_tree *tree,
				  char *drep)
{
	/* MachineName */
	offset = dissect_ndr_pointer_cb(
		tvb, offset, pinfo, tree, drep,
		dissect_ndr_char_cvstring, NDR_POINTER_UNIQUE,
		"MachineName", hf_svcctl_machinename, cb_str_postprocess,
		GINT_TO_POINTER(CB_STR_COL_INFO | CB_STR_SAVE | 1));

	/* DatabaseName */
	offset = dissect_ndr_pointer_cb(
		tvb, offset, pinfo, tree, drep,
		dissect_ndr_char_cvstring, NDR_POINTER_UNIQUE,
		"Database", hf_svcctl_database, cb_str_postprocess,
		GINT_TO_POINTER(CB_STR_COL_INFO | 1));

	/* access mask */
	offset = dissect_nt_access_mask(
		tvb, offset, pinfo, tree, drep, hf_svcctl_access_mask,
		svcctl_scm_specific_rights, "SVCCTL");

	return offset;
}

static int
svcctl_dissect_OpenSCManager_reply(tvbuff_t *tvb, int offset, 
				  packet_info *pinfo, proto_tree *tree,
				  char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	e_ctx_hnd policy_hnd;
	guint32 status;
	int start_offset = offset;

	/* We need the value of the policy handle and status before we
	   can retrieve the policy handle name.  Then we can insert
	   the policy handle with the name in the proto tree. */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, NULL, drep, hf_svcctl_hnd, &policy_hnd,
		TRUE, FALSE);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, NULL, drep, hf_svcctl_rc, &status);

	if (status == 0) {

		/* Associate the returned svcctl with a name */

		if (dcv->private_data) {
			char *pol_name;

			pol_name = g_strdup_printf(
				"OpenSCManager(%s)", 
				(char *)dcv->private_data);

			dcerpc_smb_store_pol_name(&policy_hnd, pol_name);

			g_free(pol_name);
			g_free(dcv->private_data);
			dcv->private_data = NULL;
		}
	}

	/* Parse packet */

	offset = start_offset;

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep, hf_svcctl_hnd, &policy_hnd,
		TRUE, FALSE);

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, drep, hf_svcctl_rc, &status);

	return offset;
}



/*
 * IDL BOOL CloseServiceHandle(
 * IDL      [in][out] SC_HANDLE handle
 * IDL );
 */
static int
svcctl_dissect_CloseServiceHandle_rqst(tvbuff_t *tvb, int offset, 
				  packet_info *pinfo, proto_tree *tree,
				  char *drep)
{
	e_ctx_hnd policy_hnd;
	char *pol_name;

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep, hf_svcctl_hnd, &policy_hnd,
		FALSE, TRUE);

	dcerpc_smb_fetch_pol(&policy_hnd, &pol_name, NULL, NULL);

	if (check_col(pinfo->cinfo, COL_INFO) && pol_name)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
				pol_name);

	return offset;
}

static int
svcctl_dissect_CloseServiceHandle_reply(tvbuff_t *tvb, int offset, 
				  packet_info *pinfo, proto_tree *tree,
				  char *drep)
{
	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep, hf_svcctl_hnd, NULL,
		FALSE, TRUE);

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, drep, hf_svcctl_rc, NULL);

	return offset;
}



/*
 * IDL long LockServiceDatabase(
 * IDL      [in] SC_HANDLE dbhandle,
 * IDL      [out] SC_HANDLE lock,
 * IDL );
 */
static int
svcctl_dissect_LockServiceDatabase_rqst(tvbuff_t *tvb, int offset, 
				  packet_info *pinfo, proto_tree *tree,
				  char *drep)
{
	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep, hf_svcctl_hnd, NULL,
		FALSE, TRUE);

	return offset;
}
static int
svcctl_dissect_LockServiceDatabase_reply(tvbuff_t *tvb, int offset, 
				  packet_info *pinfo, proto_tree *tree,
				  char *drep)
{
	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep, hf_svcctl_lock, NULL,
		TRUE, FALSE);

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, drep, hf_svcctl_rc, NULL);

	return offset;
}



/*
 * IDL long UnlockServiceDatabase(
 * IDL      [in][out] SC_HANDLE lock,
 * IDL );
 */
static int
svcctl_dissect_UnlockServiceDatabase_rqst(tvbuff_t *tvb, int offset, 
				  packet_info *pinfo, proto_tree *tree,
				  char *drep)
{
	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep, hf_svcctl_lock, NULL,
		FALSE, TRUE);

	return offset;
}
static int
svcctl_dissect_UnlockServiceDatabase_reply(tvbuff_t *tvb, int offset, 
				  packet_info *pinfo, proto_tree *tree,
				  char *drep)
{
	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep, hf_svcctl_lock, NULL,
		TRUE, FALSE);

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, drep, hf_svcctl_rc, NULL);

	return offset;
}


/*
 * IDL typedef struct {
 * IDL     long is_locked,
 * IDL     [unique][string] char *lock_owner,
 * IDL     long lock_duration,
 * IDL };
 */ 
static int
svcctl_dissect_QUERY_SERVICE_LOCK_STATUS(tvbuff_t *tvb, int offset, 
				  packet_info *pinfo, proto_tree *tree,
				  char *drep)
{
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_svcctl_is_locked, NULL);

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, tree, drep,
		dissect_ndr_char_cvstring, NDR_POINTER_UNIQUE,
		"Owner", hf_svcctl_lock_owner);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_svcctl_lock_duration, NULL);

	return offset;
}

/*
 * IDL long QueryServiceLockStatus(
 * IDL      [in] SC_HANDLE db_handle,
 * IDL      [in] long buf_size,
 * IDL      [out][ref] QUERY_SERVICE_LOCK_STATUS *status,
 * IDL      [out][ref] long *required_buf_size
 * IDL );
 */
static int
svcctl_dissect_QueryServiceLockStatus_rqst(tvbuff_t *tvb, int offset, 
				  packet_info *pinfo, proto_tree *tree,
				  char *drep)
{
	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep, hf_svcctl_hnd, NULL,
		FALSE, TRUE);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_svcctl_size, NULL);

	return offset;
}
static int
svcctl_dissect_QueryServiceLockStatus_reply(tvbuff_t *tvb, int offset, 
				  packet_info *pinfo, proto_tree *tree,
				  char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		svcctl_dissect_QUERY_SERVICE_LOCK_STATUS, NDR_POINTER_REF,
		"LOCK_STATUS", -1);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_svcctl_required_size, NULL);

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, drep, hf_svcctl_rc, NULL);

	return offset;
}



static dcerpc_sub_dissector dcerpc_svcctl_dissectors[] = {
	{ SVC_CLOSE_SERVICE_HANDLE, "CloseServiceHandle", 
		svcctl_dissect_CloseServiceHandle_rqst, 
		svcctl_dissect_CloseServiceHandle_reply  },
	{ SVC_STOP_SERVICE, "Stop", NULL, NULL },
	{ SVC_DELETE, "Delete", NULL, NULL },
	{ SVC_LOCK_SERVICE_DATABASE, "LockServiceDatabase",
		svcctl_dissect_LockServiceDatabase_rqst, 
		svcctl_dissect_LockServiceDatabase_reply  },
	{ SVC_GET_SVC_SEC, "Get security", NULL, NULL },
	{ SVC_UNLOCK_SERVICE_DATABASE, "UnlockServiceDatabase",
		svcctl_dissect_UnlockServiceDatabase_rqst, 
		svcctl_dissect_UnlockServiceDatabase_reply  },
	{ SVC_CHANGE_SVC_CONFIG, "Change config", NULL, NULL },
	{ SVC_ENUM_SVCS_STATUS, "Enum status", NULL, NULL },
	{ SVC_OPEN_SC_MAN, "Open SC Manager", NULL, NULL },
	{ SVC_OPEN_SERVICE, "Open service", NULL, NULL },
	{ SVC_QUERY_SVC_CONFIG, "Query config", NULL, NULL },
	{ SVC_START_SERVICE, "Start", NULL, NULL },
	{ SVC_QUERY_DISP_NAME, "Query display name", NULL, NULL },
	{ SVC_OPEN_SC_MANAGER, "OpenSCManager",
		svcctl_dissect_OpenSCManager_rqst,
		svcctl_dissect_OpenSCManager_reply },
	{ SVC_OPEN_SERVICE_A, "Open Service A", NULL, NULL },
	{ SVC_QUERY_SERVICE_LOCK_STATUS, "QueryServiceLockStatus",
		svcctl_dissect_QueryServiceLockStatus_rqst,
		svcctl_dissect_QueryServiceLockStatus_reply },
	{0, NULL, NULL, NULL}
};

static const value_string svcctl_opnum_vals[] = {
	{ SVC_CLOSE_SERVICE_HANDLE, "CloseService_handle" },
	{ SVC_STOP_SERVICE, "Stop" },
	{ SVC_DELETE, "Delete" },
	{ SVC_LOCK_SERVICE_DATABASE, "LockServiceDatabase" },
	{ SVC_GET_SVC_SEC, "Get security" },
	{ SVC_UNLOCK_SERVICE_DATABASE, "UnockServiceDatabase" },
	{ SVC_CHANGE_SVC_CONFIG, "Change config" },
	{ SVC_ENUM_SVCS_STATUS, "Enum status" },
	{ SVC_OPEN_SC_MAN, "Open SC Manager" },
	{ SVC_OPEN_SERVICE, "Open service" },
	{ SVC_QUERY_SVC_CONFIG, "Query config" },
	{ SVC_START_SERVICE, "Start" },
	{ SVC_QUERY_DISP_NAME, "Query display name" },
	{ SVC_OPEN_SC_MANAGER, "OpenSCManager" },
	{ SVC_OPEN_SERVICE_A, "Open Service A" },
	{ SVC_QUERY_SERVICE_LOCK_STATUS, "QueryServiceLockStatus" },
	{ 0, NULL }
};

void
proto_register_dcerpc_svcctl(void)
{
        static hf_register_info hf[] = {
	  { &hf_svcctl_opnum,
	    { "Operation", "svcctl.opnum", FT_UINT16, BASE_DEC,
	      VALS(svcctl_opnum_vals), 0x0, "Operation", HFILL }},
	  { &hf_svcctl_machinename,
	    { "MachineName", "svcctl.machinename", FT_STRING, BASE_NONE,
	      NULL, 0x0, "Name of the host we want to open the database on", HFILL }},
	  { &hf_svcctl_database,
	    { "Database", "svcctl.database", FT_STRING, BASE_NONE,
	      NULL, 0x0, "Name of the database to open", HFILL }},
	  { &hf_svcctl_access_mask,
	    { "Access Mask", "svcctl.access_mask", FT_UINT32, BASE_HEX,
	      NULL, 0x0, "SVCCTL Access Mask", HFILL }},
	  { &hf_svcctl_scm_rights_connect,
	    { "Connect", "svcctl.scm_rights_connect", FT_BOOLEAN, 32,
	      TFS(&flags_set_truth), 0x00000001, "SVCCTL Rights to connect to SCM", HFILL }},
	  { &hf_svcctl_scm_rights_create_service,
	    { "Create Service", "svcctl.scm_rights_create_service", FT_BOOLEAN, 32,
	      TFS(&flags_set_truth), 0x00000002, "SVCCTL Rights to create services", HFILL }},
	  { &hf_svcctl_scm_rights_enumerate_service,
	    { "Enumerate Service", "svcctl.scm_rights_enumerate_service", FT_BOOLEAN, 32,
	      TFS(&flags_set_truth), 0x00000004, "SVCCTL Rights to enumerate services", HFILL }},
	  { &hf_svcctl_scm_rights_lock,
	    { "Lock", "svcctl.scm_rights_lock", FT_BOOLEAN, 32,
	      TFS(&flags_set_truth), 0x00000008, "SVCCTL Rights to lock database", HFILL }},
	  { &hf_svcctl_scm_rights_query_lock_status,
	    { "Query Lock Status", "svcctl.scm_rights_query_lock_status", FT_BOOLEAN, 32,
	      TFS(&flags_set_truth), 0x00000010, "SVCCTL Rights to query database lock status", HFILL }},
	  { &hf_svcctl_scm_rights_modify_boot_config,
	    { "Modify Boot Config", "svcctl.scm_rights_modify_boot_config", FT_BOOLEAN, 32,
	      TFS(&flags_set_truth), 0x00000020, "SVCCTL Rights to modify boot config", HFILL }},
	  { &hf_svcctl_hnd,
	    { "Context Handle", "svcctl.hnd", FT_BYTES, BASE_NONE,
	      NULL, 0x0, "SVCCTL Context handle", HFILL }},
	  { &hf_svcctl_lock,
	    { "Lock", "svcctl.lock", FT_BYTES, BASE_NONE,
	      NULL, 0x0, "SVCCTL Database Lock", HFILL }},
	  { &hf_svcctl_rc,
	    { "Return code", "svcctl.rc", FT_UINT32, BASE_HEX,
	      VALS(DOS_errors), 0x0, "SVCCTL return code", HFILL }},
	  { &hf_svcctl_size,
	    { "Size", "svcctl.size", FT_UINT32, BASE_DEC,
	      NULL, 0x0, "SVCCTL size of buffer", HFILL }},
	  { &hf_svcctl_required_size,
	    { "Required Size", "svcctl.required_size", FT_UINT32, BASE_DEC,
	      NULL, 0x0, "SVCCTL required size of buffer for data to fit", HFILL }},
	  { &hf_svcctl_is_locked,
	    { "IsLocked", "svcctl.is_locked", FT_UINT32, BASE_DEC,
	      NULL, 0x0, "SVCCTL whether the database is locked or not", HFILL }},
	  { &hf_svcctl_lock_duration,
	    { "Duration", "svcctl.lock_duration", FT_UINT32, BASE_DEC,
	      NULL, 0x0, "SVCCTL number of seconds the database has been locked", HFILL }},
	  { &hf_svcctl_lock_owner,
	    { "Owner", "svcctl.lock_owner", FT_STRING, BASE_NONE,
	      NULL, 0x0, "SVCCTL the user that holds the database lock", HFILL }},
	};

        static gint *ett[] = {
                &ett_dcerpc_svcctl,
        };

        proto_dcerpc_svcctl = proto_register_protocol(
                "Microsoft Service Control", "SVCCTL", "svcctl");

	proto_register_field_array(proto_dcerpc_svcctl, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dcerpc_svcctl(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_svcctl, ett_dcerpc_svcctl,
                         &uuid_dcerpc_svcctl, ver_dcerpc_svcctl,
                         dcerpc_svcctl_dissectors, hf_svcctl_opnum);
}
