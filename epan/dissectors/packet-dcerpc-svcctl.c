/* packet-dcerpc-svcctl.c
 * Routines for SMB \PIPE\svcctl packet disassembly
 * Copyright 2003, Tim Potter <tpot@samba.org>
 * Copyright 2003, Ronnie Sahlberg,  added function dissectors
 * Copyright 2010, Brett Kuskie <fullaxx@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/wmem/wmem.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-svcctl.h"
#include "packet-dcerpc-nt.h"
#include "packet-windows-common.h"

void proto_register_dcerpc_svcctl(void);
void proto_reg_handoff_dcerpc_svcctl(void);

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
static int hf_svcctl_service_type = -1;
static int hf_svcctl_service_type_kernel_driver = -1;
static int hf_svcctl_service_type_fs_driver = -1;
static int hf_svcctl_service_type_win32_own_process = -1;
static int hf_svcctl_service_type_win32_share_process = -1;
static int hf_svcctl_service_type_interactive_process = -1;
static int hf_svcctl_service_state = -1;
static int hf_svcctl_buffer = -1;
/* static int hf_svcctl_bytes_needed = -1; */
/* static int hf_svcctl_services_returned = -1; */
static int hf_svcctl_resume = -1;
static int hf_svcctl_service_name = -1;
static int hf_svcctl_display_name = -1;
static int hf_svcctl_service_start_type = -1;
static int hf_svcctl_service_error_control = -1;
static int hf_svcctl_binarypathname = -1;
static int hf_svcctl_loadordergroup = -1;
static int hf_svcctl_tagid = -1;
static int hf_svcctl_dependencies = -1;
static int hf_svcctl_depend_size = -1;
static int hf_svcctl_service_start_name = -1;
static int hf_svcctl_password = -1;
static int hf_svcctl_password_size = -1;

static gint ett_dcerpc_svcctl = -1;
static gint ett_dcerpc_svcctl_service_type_bits = -1;

static e_uuid_t uuid_dcerpc_svcctl = {
        0x367abb81, 0x9844, 0x35f1,
        { 0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03 }
};

static guint16 ver_dcerpc_svcctl = 2;

#define SVCCTL_SERVICE_TYPE_KERNEL_DRIVER	0x01
#define SVCCTL_SERVICE_TYPE_FILE_SYSTEM_DRIVER	0x02
#define SVCCTL_SERVICE_TYPE_WIN32_OWN_PROCESS	0x10
#define SVCCTL_SERVICE_TYPE_WIN32_SHARE_PROCESS	0x20
#define SVCCTL_SERVICE_TYPE_INTERACTIVE_PROCESS	0x100
#define SVCCTL_SERVICE_TYPE_NO_CHANGE		0xffffffff
static const true_false_string tfs_svcctl_service_type_kernel_driver = {
	"Is a kernel driver service",
	"Is not a kernel driver service"
};
static const true_false_string tfs_svcctl_service_type_fs_driver = {
	"Is a file system driver service",
	"Is not a file system driver service"
};
static const true_false_string tfs_svcctl_service_type_win32_own_process = {
	"Service runs its own processes",
	"Service does not run its own process"
};
static const true_false_string tfs_svcctl_service_type_win32_share_process = {
	"Service shares its process",
	"Service does not share its process"
};
static const true_false_string tfs_svcctl_service_type_interactive_process = {
	"Service can interact with the desktop",
	"Service cannot interact with the desktop"
};

static int
svcctl_dissect_dwServiceType_flags(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep, int opnum)
{
	guint32 value, len=4;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	(void) dissect_dcerpc_uint32 (tvb, offset, pinfo, NULL, drep, 0, &value);
	if(parent_tree) {
		item = proto_tree_add_uint(parent_tree, hf_svcctl_service_type, tvb, offset, len, value);
		tree = proto_item_add_subtree(item, ett_dcerpc_svcctl_service_type_bits);
	}

	switch(opnum) {
	case SVC_CREATE_SERVICE_W:
		proto_tree_add_boolean(tree, hf_svcctl_service_type_interactive_process,
			tvb, offset, len, value & SVCCTL_SERVICE_TYPE_INTERACTIVE_PROCESS);
		proto_tree_add_boolean(tree, hf_svcctl_service_type_win32_share_process,
			tvb, offset, len, value & SVCCTL_SERVICE_TYPE_WIN32_SHARE_PROCESS);
		proto_tree_add_boolean(tree, hf_svcctl_service_type_win32_own_process,
			tvb, offset, len, value & SVCCTL_SERVICE_TYPE_WIN32_OWN_PROCESS);
		proto_tree_add_boolean(tree, hf_svcctl_service_type_fs_driver,
			tvb, offset, len, value & SVCCTL_SERVICE_TYPE_FILE_SYSTEM_DRIVER);
		proto_tree_add_boolean(tree, hf_svcctl_service_type_kernel_driver,
			tvb, offset, len, value & SVCCTL_SERVICE_TYPE_KERNEL_DRIVER);
		break;
	case SVC_ENUM_SERVICES_STATUS_W:
		proto_tree_add_boolean(tree, hf_svcctl_service_type_win32_share_process,
			tvb, offset, len, value & SVCCTL_SERVICE_TYPE_WIN32_SHARE_PROCESS);
		proto_tree_add_boolean(tree, hf_svcctl_service_type_win32_own_process,
			tvb, offset, len, value & SVCCTL_SERVICE_TYPE_WIN32_OWN_PROCESS);
		proto_tree_add_boolean(tree, hf_svcctl_service_type_fs_driver,
			tvb, offset, len, value & SVCCTL_SERVICE_TYPE_FILE_SYSTEM_DRIVER);
		proto_tree_add_boolean(tree, hf_svcctl_service_type_kernel_driver,
			tvb, offset, len, value & SVCCTL_SERVICE_TYPE_KERNEL_DRIVER);
		break;
	case SVC_QUERY_SERVICE_CONFIG_W:
		proto_tree_add_boolean(tree, hf_svcctl_service_type_win32_share_process,
			tvb, offset, len, value & SVCCTL_SERVICE_TYPE_WIN32_SHARE_PROCESS);
		proto_tree_add_boolean(tree, hf_svcctl_service_type_win32_own_process,
			tvb, offset, len, value & SVCCTL_SERVICE_TYPE_WIN32_OWN_PROCESS);
		proto_tree_add_boolean(tree, hf_svcctl_service_type_fs_driver,
			tvb, offset, len, value & SVCCTL_SERVICE_TYPE_FILE_SYSTEM_DRIVER);
		proto_tree_add_boolean(tree, hf_svcctl_service_type_kernel_driver,
			tvb, offset, len, value & SVCCTL_SERVICE_TYPE_KERNEL_DRIVER);
		break;
	}

	offset += len;
	return offset;
}

#define SVCCTL_SERVICE_ACTIVE       0x01
#define SVCCTL_SERVICE_INACTIVE     0x02
#define SVCCTL_SERVICE_STATE_ALL    0x03
static const value_string svcctl_service_status_vals[] = {
	{ SVCCTL_SERVICE_ACTIVE,    "SERVICE_ACTIVE" },
	{ SVCCTL_SERVICE_INACTIVE,  "SERVICE_INACTIVE" },
	{ SVCCTL_SERVICE_STATE_ALL, "SERVICE_STATE_ALL" },
	{ 0, NULL }
};

#define SVCCTL_SERVICE_BOOT_START	0x00
#define SVCCTL_SERVICE_SYSTEM_START	0x01
#define SVCCTL_SERVICE_AUTO_START	0x02
#define SVCCTL_SERVICE_DEMAND_START	0x03
#define SVCCTL_SERVICE_DISABLED		0x04
static const value_string svcctl_service_start_type_vals[] = {
	{ SVCCTL_SERVICE_BOOT_START,	"SERVICE_BOOT_START" },
	{ SVCCTL_SERVICE_SYSTEM_START,	"SERVICE_SYSTEM_START" },
	{ SVCCTL_SERVICE_AUTO_START,	"SERVICE_AUTO_START" },
	{ SVCCTL_SERVICE_DEMAND_START,	"SERVICE_DEMAND_START" },
	{ SVCCTL_SERVICE_DISABLED,	"SERVICE_DISABLED" },
	{ 0, NULL }
};

#define SVCCTL_SERVICE_ERROR_IGNORE	0x00
#define SVCCTL_SERVICE_ERROR_NORMAL	0x01
#define SVCCTL_SERVICE_ERROR_SEVERE	0x02
#define SVCCTL_SERVICE_ERROR_CRITICAL	0x03
static const value_string svcctl_service_error_control_vals[] = {
	{ SVCCTL_SERVICE_ERROR_IGNORE,	 "SERVICE_ERROR_IGNORE" },
	{ SVCCTL_SERVICE_ERROR_NORMAL,	 "SERVICE_ERROR_NORMAL" },
	{ SVCCTL_SERVICE_ERROR_SEVERE,	 "SERVICE_ERROR_SEVERE" },
	{ SVCCTL_SERVICE_ERROR_CRITICAL, "SERVICE_ERROR_CRITICAL" },
	{ 0, NULL }
};

static int
svcctl_dissect_pointer_long(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             dcerpc_info *di, guint8 *drep)
{
    offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                                     di->hf_index, NULL);
	return offset;
}

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

struct access_mask_info svcctl_scm_access_mask_info = {
	"SVCCTL",
	svcctl_scm_specific_rights,
	NULL,			/* Generic mapping table */
	NULL			/* Standard mapping table */
};

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
				  dcerpc_info *di, guint8 *drep)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	const char *mn, *dn;

	/* MachineName */
	dcv->private_data=NULL;
	offset = dissect_ndr_pointer_cb(
		tvb, offset, pinfo, tree, di, drep,
		dissect_ndr_char_cvstring, NDR_POINTER_UNIQUE,
		"MachineName", hf_svcctl_machinename, cb_str_postprocess,
		GINT_TO_POINTER(CB_STR_COL_INFO | CB_STR_SAVE | 1));
	mn=(const char *)dcv->private_data;
	if(!mn)
		mn="";

	/* DatabaseName */
	dcv->private_data=NULL;
	offset = dissect_ndr_pointer_cb(
		tvb, offset, pinfo, tree, di, drep,
		dissect_ndr_char_cvstring, NDR_POINTER_UNIQUE,
		"Database", hf_svcctl_database, cb_str_postprocess,
		GINT_TO_POINTER(CB_STR_COL_INFO | 1));
	dn=(const char *)dcv->private_data;
	if(!dn)
		dn="";

	/* OpenSCManager() stores the server\database  in se_data */
	if(!pinfo->fd->flags.visited){
		if(!dcv->se_data){
			dcv->se_data=wmem_strdup_printf(wmem_file_scope(), "%s\\%s",mn,dn);
		}
	}

	/* access mask */
	offset = dissect_nt_access_mask(
		tvb, offset, pinfo, tree, di, drep, hf_svcctl_access_mask,
		&svcctl_scm_access_mask_info, NULL);

	return offset;
}

static int
svcctl_dissect_OpenSCManager_reply(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  dcerpc_info *di, guint8 *drep)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	e_ctx_hnd policy_hnd;
	proto_item *hnd_item;
	guint32 status;

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_svcctl_hnd, &policy_hnd,
		&hnd_item, TRUE, FALSE);

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_svcctl_rc, &status);

	if( status == 0 ){
		const char *pol_name;

		if (dcv->se_data){
			pol_name = wmem_strdup_printf(wmem_packet_scope(),
				"OpenSCManagerW(%s)", (char *)dcv->se_data);
		} else {
			pol_name = "Unknown OpenSCManagerW() handle";
		}
		if(!pinfo->fd->flags.visited){
			dcerpc_store_polhnd_name(&policy_hnd, pinfo, pol_name);
		}

		if(hnd_item)
			proto_item_append_text(hnd_item, ": %s", pol_name);
	}

	return offset;
}

static int
svcctl_dissect_OpenSCManagerW_rqst(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  dcerpc_info *di, guint8 *drep)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	const char *mn, *dn;

	/* MachineName */
	dcv->private_data=NULL;
	offset = dissect_ndr_pointer_cb(
		tvb, offset, pinfo, tree, di, drep,
		dissect_ndr_wchar_cvstring, NDR_POINTER_UNIQUE,
		"MachineName", hf_svcctl_machinename, cb_wstr_postprocess,
		GINT_TO_POINTER(CB_STR_COL_INFO | CB_STR_SAVE | 1));
	mn=(const char *)dcv->private_data;
	if(!mn)
		mn="";

	/* DatabaseName */
	dcv->private_data=NULL;
	offset = dissect_ndr_pointer_cb(
		tvb, offset, pinfo, tree, di, drep,
		dissect_ndr_wchar_cvstring, NDR_POINTER_UNIQUE,
		"Database", hf_svcctl_database, cb_wstr_postprocess,
		GINT_TO_POINTER(CB_STR_COL_INFO | 1));
	dn=(const char *)dcv->private_data;
	if(!dn)
		dn="";

	/* OpenSCManager() stores the server\database  in se_data */
	if(!pinfo->fd->flags.visited){
		if(!dcv->se_data){
			dcv->se_data=wmem_strdup_printf(wmem_file_scope(), "%s\\%s",mn,dn);
		}
	}

	/* access mask */
	offset = dissect_nt_access_mask(
		tvb, offset, pinfo, tree, di, drep, hf_svcctl_access_mask,
		&svcctl_scm_access_mask_info, NULL);

	return offset;
}

static int
svcctl_dissect_OpenSCManagerW_reply(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  dcerpc_info *di, guint8 *drep)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	e_ctx_hnd policy_hnd;
	proto_item *hnd_item;
	guint32 status;

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_svcctl_hnd, &policy_hnd,
		&hnd_item, TRUE, FALSE);

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_svcctl_rc, &status);

	if( status == 0 ){
		const char *pol_name;

		if (dcv->se_data){
			pol_name = wmem_strdup_printf(wmem_packet_scope(),
				"OpenSCManagerW(%s)", (char *)dcv->se_data);
		} else {
			pol_name = "Unknown OpenSCManagerW() handle";
		}
		if(!pinfo->fd->flags.visited){
			dcerpc_store_polhnd_name(&policy_hnd, pinfo, pol_name);
		}

		if(hnd_item)
			proto_item_append_text(hnd_item, ": %s", pol_name);
	}

	return offset;
}

static int
svcctl_dissect_CreateServiceW_rqst(tvbuff_t *tvb, int offset,
		packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	/* policy handle */
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, di, drep,
		hf_svcctl_hnd, NULL, NULL, FALSE, FALSE);

	/* service name */
	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep,
		sizeof(guint16), hf_svcctl_service_name, TRUE, NULL);

	/* display name */
	offset = dissect_ndr_pointer_cb(
		tvb, offset, pinfo, tree, di, drep,
		dissect_ndr_wchar_cvstring, NDR_POINTER_UNIQUE,
		"Display Name", hf_svcctl_display_name, cb_wstr_postprocess,
		GINT_TO_POINTER(1));

	/* access mask */
	offset = dissect_nt_access_mask(
		tvb, offset, pinfo, tree, di, drep, hf_svcctl_access_mask,
		&svcctl_scm_access_mask_info, NULL);

	/* service type */
	offset = svcctl_dissect_dwServiceType_flags(tvb, offset, pinfo, tree, drep, SVC_CREATE_SERVICE_W);

	/* service start type */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
		hf_svcctl_service_start_type, NULL);

	/* service error control */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
		hf_svcctl_service_error_control, NULL);

	/* binary path name */
	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep,
		sizeof(guint16), hf_svcctl_binarypathname, TRUE, NULL);

	/* load order group */
	offset = dissect_ndr_pointer_cb(
		tvb, offset, pinfo, tree, di, drep,
		dissect_ndr_wchar_cvstring, NDR_POINTER_UNIQUE,
		"Load Order Group", hf_svcctl_loadordergroup, cb_wstr_postprocess,
		GINT_TO_POINTER(1));

	/* tag id */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
		hf_svcctl_tagid, NULL);

	/* dependencies */
	offset = dissect_ndr_pointer_cb(
		tvb, offset, pinfo, tree, di, drep,
		dissect_ndr_wchar_cvstring, NDR_POINTER_UNIQUE,
		"Dependencies", hf_svcctl_dependencies, cb_wstr_postprocess,
		GINT_TO_POINTER(1));

	/* depend size */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
		hf_svcctl_depend_size, NULL);

	/* service start name */
	offset = dissect_ndr_pointer_cb(
		tvb, offset, pinfo, tree, di, drep,
		dissect_ndr_wchar_cvstring, NDR_POINTER_UNIQUE,
		"Service Start Name", hf_svcctl_service_start_name, cb_wstr_postprocess,
		GINT_TO_POINTER(1));

	/* password */
	offset = dissect_ndr_pointer_cb(
		tvb, offset, pinfo, tree, di, drep,
		dissect_ndr_wchar_cvstring, NDR_POINTER_UNIQUE,
		"Password", hf_svcctl_password, cb_wstr_postprocess,
		GINT_TO_POINTER(1));

	/* password size */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
		hf_svcctl_password_size, NULL);

	return offset;
}

static int
svcctl_dissect_CreateServiceW_reply(tvbuff_t *tvb, int offset,
		packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	/* tag id */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
		hf_svcctl_tagid, NULL);

	/* policy handle */
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, di, drep,
		hf_svcctl_hnd, NULL, NULL, FALSE, FALSE);

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_svcctl_rc, NULL);

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
				  dcerpc_info *di, guint8 *drep)
{
	e_ctx_hnd policy_hnd;
	char *pol_name;

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_svcctl_hnd, &policy_hnd,
		NULL, FALSE, TRUE);

	dcerpc_fetch_polhnd_data(&policy_hnd, &pol_name, NULL, NULL, NULL,
			     pinfo->fd->num);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
				pol_name);

	return offset;
}

static int
svcctl_dissect_CloseServiceHandle_reply(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  dcerpc_info *di, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_svcctl_hnd, NULL,
		NULL, FALSE, TRUE);

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_svcctl_rc, NULL);

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
				  dcerpc_info *di, guint8 *drep)
{
	/* XXX - why is the "is a close" argument TRUE? */
	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_svcctl_hnd, NULL,
		NULL, FALSE, TRUE);

	return offset;
}
static int
svcctl_dissect_LockServiceDatabase_reply(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  dcerpc_info *di, guint8 *drep)
{
	/* XXX - why is the "is an open" argument TRUE? */
	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_svcctl_lock, NULL,
		NULL, TRUE, FALSE);

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_svcctl_rc, NULL);

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
				  dcerpc_info *di, guint8 *drep)
{
	/* XXX - why is the "is a close" argument TRUE? */
	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_svcctl_lock, NULL,
		NULL, FALSE, TRUE);

	return offset;
}
static int
svcctl_dissect_UnlockServiceDatabase_reply(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  dcerpc_info *di, guint8 *drep)
{
	/* XXX - why is the "is an open" argument TRUE? */
	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_svcctl_lock, NULL,
		NULL, TRUE, FALSE);

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_svcctl_rc, NULL);

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
				  dcerpc_info *di, guint8 *drep)
{
        offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
                                     hf_svcctl_is_locked, NULL);

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, tree, di, drep,
		dissect_ndr_char_cvstring, NDR_POINTER_UNIQUE,
		"Owner", hf_svcctl_lock_owner);

        offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
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
				  dcerpc_info *di, guint8 *drep)
{
	/* XXX - why is the "is a close" argument TRUE? */
	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_svcctl_hnd, NULL,
		NULL, FALSE, TRUE);

        offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
                                     hf_svcctl_size, NULL);

	return offset;
}
static int
svcctl_dissect_QueryServiceLockStatus_reply(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  dcerpc_info *di, guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, di, drep,
		svcctl_dissect_QUERY_SERVICE_LOCK_STATUS, NDR_POINTER_REF,
		"LOCK_STATUS", -1);

        offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
                                     hf_svcctl_required_size, NULL);

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_svcctl_rc, NULL);

	return offset;
}

/*
 * IDL long EnumServicesStatus(
 * IDL      [in] SC_HANDLE db_handle,
 * IDL      [in] long type,
 * IDL      [in] long status,
 * IDL      [in] long buf_size,
 * IDL      [in][unique] long *resume_handle,
 * IDL );
 */

static int
svcctl_dissect_EnumServicesStatus_rqst(tvbuff_t *tvb, int offset,
		packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	/* policy handle */
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, di, drep,
			hf_svcctl_hnd, NULL, NULL, FALSE, FALSE);

	/* service type */
	offset = svcctl_dissect_dwServiceType_flags(tvb, offset, pinfo, tree, drep, SVC_ENUM_SERVICES_STATUS_W);

	/* service state */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
			hf_svcctl_service_state, NULL);

	/* size */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
			hf_svcctl_size, NULL);

	/* resume handle */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, di, drep,
			svcctl_dissect_pointer_long, NDR_POINTER_UNIQUE,
			"Resume Handle", hf_svcctl_resume);

	return offset;
}

static int
svcctl_dissect_OpenServiceW_rqst(tvbuff_t *tvb, int offset,
		packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	/* policy handle */
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, di, drep,
		hf_svcctl_hnd, NULL, NULL, FALSE, FALSE);

	/* service name */
	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep,
		sizeof(guint16), hf_svcctl_service_name, TRUE, NULL);

	/* access mask */
	offset = dissect_nt_access_mask(
		tvb, offset, pinfo, tree, di, drep, hf_svcctl_access_mask,
		&svcctl_scm_access_mask_info, NULL);

	return offset;
}

static int
svcctl_dissect_OpenServiceW_reply(tvbuff_t *tvb, int offset,
		packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	/* policy handle */
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, di, drep,
		hf_svcctl_hnd, NULL, NULL, FALSE, FALSE);

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_svcctl_rc, NULL);

	return offset;
}

static int
svcctl_dissect_QueryServiceConfigW_rqst(tvbuff_t *tvb, int offset,
		packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	/* policy handle */
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, di, drep,
		hf_svcctl_hnd, NULL, NULL, FALSE, FALSE);

	/* cbBufSize */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
		hf_svcctl_buffer, NULL);

	return offset;
}

static dcerpc_sub_dissector dcerpc_svcctl_dissectors[] = {
	{ SVC_CLOSE_SERVICE_HANDLE, "CloseServiceHandle",
		svcctl_dissect_CloseServiceHandle_rqst,
		svcctl_dissect_CloseServiceHandle_reply  },
	{ SVC_CONTROL_SERVICE, "ControlService", NULL, NULL },
	{ SVC_DELETE_SERVICE, "DeleteService", NULL, NULL },
	{ SVC_LOCK_SERVICE_DATABASE, "LockServiceDatabase",
		svcctl_dissect_LockServiceDatabase_rqst,
		svcctl_dissect_LockServiceDatabase_reply  },
	{ SVC_QUERY_SERVICE_OBJECT_SECURITY, "QueryServiceObjectSecurity",
	  NULL, NULL },
	{ SVC_SET_SERVICE_OBJECT_SECURITY, "SetServiceObjectSecurity",
	  NULL, NULL },
 	{ SVC_QUERY_SERVICE_STATUS, "QueryServiceStatus",
	  NULL, NULL },
	{ SVC_SET_SERVICE_STATUS, "SetServiceStatus",
	  NULL, NULL },
	{ SVC_UNLOCK_SERVICE_DATABASE, "UnlockServiceDatabase",
		svcctl_dissect_UnlockServiceDatabase_rqst,
		svcctl_dissect_UnlockServiceDatabase_reply  },
	{ SVC_NOTIFY_BOOT_CONFIG_STATUS, "NotifyBootConfigStatus",
	  NULL, NULL },
	{ SVC_SC_SET_SERVICE_BITS_W, "ScSetServiceBitsW",
	  NULL, NULL },
	{ SVC_CHANGE_SERVICE_CONFIG_W, "ChangeServiceConfigW",
	  NULL, NULL },
	{ SVC_CREATE_SERVICE_W, "CreateServiceW",
	  svcctl_dissect_CreateServiceW_rqst,
	  svcctl_dissect_CreateServiceW_reply },
	{ SVC_ENUM_DEPENDENT_SERVICES_W, "EnumDependentServicesW",
	  NULL, NULL },
	{ SVC_ENUM_SERVICES_STATUS_W, "EnumServicesStatusW",
	  svcctl_dissect_EnumServicesStatus_rqst, NULL },
	{ SVC_OPEN_SC_MANAGER_W, "OpenSCManagerW",
		svcctl_dissect_OpenSCManagerW_rqst,
		svcctl_dissect_OpenSCManagerW_reply },
	{ SVC_OPEN_SERVICE_W, "OpenServiceW",
		svcctl_dissect_OpenServiceW_rqst,
		svcctl_dissect_OpenServiceW_reply },
	{ SVC_QUERY_SERVICE_CONFIG_W, "QueryServiceConfigW",
		svcctl_dissect_QueryServiceConfigW_rqst, NULL },
	{ SVC_QUERY_SERVICE_LOCK_STATUS_W, "QueryServiceLockStatusW",
	  NULL, NULL },
	{ SVC_START_SERVICE_W, "StartServiceW", NULL, NULL },
	{ SVC_GET_SERVICE_DISPLAY_NAME_W, "GetServiceDisplayNameW",
	  NULL, NULL },
	{ SVC_GET_SERVICE_KEY_NAME_W, "GetServiceKeyNameW", NULL, NULL },
	{ SVC_SC_SET_SERVICE_BITS_A, "ScSetServiceBitsA", NULL, NULL },
	{ SVC_CHANGE_SERVICE_CONFIG_A, "ChangeServiceConfigA", NULL, NULL },
	{ SVC_CREATE_SERVICE_A, "CreateServiceA", NULL, NULL },
	{ SVC_ENUM_DEPENDENT_SERVICES_A, "EnumDependentServicesA",
	  NULL, NULL },
	{ SVC_ENUM_SERVICES_STATUS_A, "EnumServicesStatusA",
		svcctl_dissect_EnumServicesStatus_rqst,
		NULL },
	{ SVC_OPEN_SC_MANAGER_A, "OpenSCManagerA",
		svcctl_dissect_OpenSCManager_rqst,
		svcctl_dissect_OpenSCManager_reply },
	{ SVC_OPEN_SERVICE_A, "OpenServiceA", NULL, NULL },
	{ SVC_QUERY_SERVICE_CONFIG_A, "QueryServiceConfigA", NULL, NULL },
	{ SVC_QUERY_SERVICE_LOCK_STATUS_A, "QueryServiceLockStatusA",
		svcctl_dissect_QueryServiceLockStatus_rqst,
		svcctl_dissect_QueryServiceLockStatus_reply },
	{ SVC_START_SERVICE_A, "StartServiceA", NULL, NULL },
	{ SVC_GET_SERVICE_DISPLAY_NAME_A, "GetServiceDisplayNameA",
	  NULL, NULL },
	{ SVC_GET_SERVICE_KEY_NAME_A, "GetServiceKeyNameA", NULL, NULL },
	{ SVC_SC_GET_CURRENT_GROUPE_STATE_W, "ScGetCurrentGroupStateW",
	  NULL, NULL },
	{ SVC_ENUM_SERVICE_GROUP_W, "EnumServiceGroupW",
	  NULL, NULL },
	{ SVC_CHANGE_SERVICE_CONFIG2_A, "ChangeServiceConfig2A",
	  NULL, NULL },
	{ SVC_CHANGE_SERVICE_CONFIG2_W, "ChangeServiceConfig2W",
	  NULL, NULL },
	{ SVC_QUERY_SERVICE_CONFIG2_A, "QueryServiceConfig2A",
	  NULL, NULL },
	{ SVC_QUERY_SERVICE_CONFIG2_W, "QueryServiceConfig2W",
	  NULL, NULL },
	{ SVC_QUERY_SERVICE_STATUS_EX, "QueryServiceStatusEx",
	  NULL, NULL },
	{ SVC_ENUM_SERVICES_STATUS_EX_A, "EnumServicesStatusExA",
	  NULL, NULL },
	{ SVC_ENUM_SERVICES_STATUS_EX_W, "EnumServicesStatusExW",
	  NULL, NULL },
	{ SVC_SC_SEND_TS_MESSAGE, "ScSendTSMessage",
	  NULL, NULL },
	{0, NULL, NULL, NULL}
};

void
proto_register_dcerpc_svcctl(void)
{
        static hf_register_info hf[] = {
	  { &hf_svcctl_opnum,
	    { "Operation", "svcctl.opnum", FT_UINT16, BASE_DEC,
	      NULL, 0x0, NULL, HFILL }},
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
	      TFS(&tfs_set_notset), 0x00000001, "SVCCTL Rights to connect to SCM", HFILL }},
	  { &hf_svcctl_scm_rights_create_service,
	    { "Create Service", "svcctl.scm_rights_create_service", FT_BOOLEAN, 32,
	      TFS(&tfs_set_notset), 0x00000002, "SVCCTL Rights to create services", HFILL }},
	  { &hf_svcctl_scm_rights_enumerate_service,
	    { "Enumerate Service", "svcctl.scm_rights_enumerate_service", FT_BOOLEAN, 32,
	      TFS(&tfs_set_notset), 0x00000004, "SVCCTL Rights to enumerate services", HFILL }},
	  { &hf_svcctl_scm_rights_lock,
	    { "Lock", "svcctl.scm_rights_lock", FT_BOOLEAN, 32,
	      TFS(&tfs_set_notset), 0x00000008, "SVCCTL Rights to lock database", HFILL }},
	  { &hf_svcctl_scm_rights_query_lock_status,
	    { "Query Lock Status", "svcctl.scm_rights_query_lock_status", FT_BOOLEAN, 32,
	      TFS(&tfs_set_notset), 0x00000010, "SVCCTL Rights to query database lock status", HFILL }},
	  { &hf_svcctl_scm_rights_modify_boot_config,
	    { "Modify Boot Config", "svcctl.scm_rights_modify_boot_config", FT_BOOLEAN, 32,
	      TFS(&tfs_set_notset), 0x00000020, "SVCCTL Rights to modify boot config", HFILL }},
	  { &hf_svcctl_hnd,
	    { "Context Handle", "svcctl.hnd", FT_BYTES, BASE_NONE,
	      NULL, 0x0, "SVCCTL Context handle", HFILL }},
	  { &hf_svcctl_lock,
	    { "Lock", "svcctl.lock", FT_BYTES, BASE_NONE,
	      NULL, 0x0, "SVCCTL Database Lock", HFILL }},
	  { &hf_svcctl_rc,
	    { "Return code", "svcctl.rc", FT_UINT32, BASE_HEX | BASE_EXT_STRING,
	      &DOS_errors_ext, 0x0, "SVCCTL return code", HFILL }},
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
	  { &hf_svcctl_service_type,
	    { "Service Type", "svcctl.service_type", FT_UINT32, BASE_HEX,
	      NULL, 0x0, "SVCCTL type of service", HFILL }},
	  { &hf_svcctl_service_type_kernel_driver,
	    { "Kernel Driver Service", "svcctl.service_type.kernel", FT_BOOLEAN, 32,
	      TFS(&tfs_svcctl_service_type_kernel_driver), SVCCTL_SERVICE_TYPE_KERNEL_DRIVER, "Request includes kernel driver services?", HFILL }},
	  { &hf_svcctl_service_type_fs_driver,
	    { "File System Driver Service", "svcctl.service_type.fs", FT_BOOLEAN, 32,
	      TFS(&tfs_svcctl_service_type_fs_driver), SVCCTL_SERVICE_TYPE_FILE_SYSTEM_DRIVER, "Request includes file system driver services?", HFILL }},
	  { &hf_svcctl_service_type_win32_own_process,
	    { "Self Process Service", "svcctl.service_type.win32_own", FT_BOOLEAN, 32,
	      TFS(&tfs_svcctl_service_type_win32_own_process), SVCCTL_SERVICE_TYPE_WIN32_OWN_PROCESS, "Request includes services that run their own process?", HFILL }},
	  { &hf_svcctl_service_type_win32_share_process,
	    { "Shared Process Service", "svcctl.service_type.win32_shared", FT_BOOLEAN, 32,
	      TFS(&tfs_svcctl_service_type_win32_share_process), SVCCTL_SERVICE_TYPE_WIN32_SHARE_PROCESS, "Request includes services that share their process?", HFILL }},
	  { &hf_svcctl_service_type_interactive_process,
	    { "Interactive Process Service", "svcctl.service_type.interactive", FT_BOOLEAN, 32,
	      TFS(&tfs_svcctl_service_type_interactive_process), SVCCTL_SERVICE_TYPE_INTERACTIVE_PROCESS, "Request includes services that can interact with the desktop?", HFILL }},
	  { &hf_svcctl_service_state,
	    { "Service State", "svcctl.service_state", FT_UINT32, BASE_DEC,
	      VALS(svcctl_service_status_vals), 0x0, "SVCCTL service state", HFILL }},
	  { &hf_svcctl_buffer,
	    { "Buffer", "svcctl.buffer", FT_UINT32, BASE_DEC,
	      NULL, 0x0, "SVCCTL buffer", HFILL }},
#if 0
	  { &hf_svcctl_bytes_needed,
	    { "Bytes Needed", "svcctl.bytes_needed", FT_UINT32, BASE_DEC,
	      NULL, 0x0, "SVCCTL bytes needed", HFILL }},
	  { &hf_svcctl_services_returned,
	    { "Services Returned", "svcctl.services_returned", FT_UINT32, BASE_DEC,
	      NULL, 0x0, "SVCCTL services returned", HFILL }},
#endif
	  { &hf_svcctl_service_name,
	    { "Service Name", "svcctl.servicename", FT_STRING, BASE_NONE,
	      NULL, 0x0, "SVCCTL name of service", HFILL }},
	  { &hf_svcctl_display_name,
	    { "Display Name", "svcctl.displayname", FT_STRING, BASE_NONE,
	      NULL, 0x0, "SVCCTL display name", HFILL }},
	  { &hf_svcctl_service_start_type,
	    { "Service Start Type", "svcctl.service_start_type", FT_UINT32, BASE_DEC,
	      VALS(svcctl_service_start_type_vals), 0x0, "SVCCTL service start type", HFILL }},
	  { &hf_svcctl_service_error_control,
	    { "Service Error Control", "svcctl.service_error_control", FT_UINT32, BASE_DEC,
	      VALS(svcctl_service_error_control_vals), 0x0, "SVCCTL service error control", HFILL }},
	  { &hf_svcctl_binarypathname,
	    { "Binary Path Name", "svcctl.binarypathname", FT_STRING, BASE_NONE,
	      NULL, 0x0, "SVCCTL binary path name", HFILL }},
	  { &hf_svcctl_loadordergroup,
	    { "Load Order Group", "svcctl.loadordergroup", FT_STRING, BASE_NONE,
	      NULL, 0x0, "SVCCTL load order group", HFILL }},
	  { &hf_svcctl_tagid,
	    { "Tag Id", "svcctl.tagid", FT_UINT32, BASE_DEC,
	      NULL, 0x0, "SVCCTL tag id", HFILL }},
	  { &hf_svcctl_dependencies,
	    { "Dependencies", "svcctl.dependencies", FT_STRING, BASE_NONE,
	      NULL, 0x0, "SVCCTL dependencies", HFILL }},
	  { &hf_svcctl_depend_size,
	    { "Depend Size", "svcctl.depend_size", FT_UINT32, BASE_DEC,
	      NULL, 0x0, "SVCCTL depend size", HFILL }},
	  { &hf_svcctl_service_start_name,
	    { "Service Start Name", "svcctl.service_start_name", FT_STRING, BASE_NONE,
	      NULL, 0x0, "SVCCTL service start name", HFILL }},
	  { &hf_svcctl_password,
	    { "Password", "svcctl.password", FT_STRING, BASE_NONE,
	      NULL, 0x0, "SVCCTL password", HFILL }},
	  { &hf_svcctl_password_size,
	    { "Password Size", "svcctl.password_size", FT_UINT32, BASE_DEC,
	      NULL, 0x0, "SVCCTL password size", HFILL }},
	  { &hf_svcctl_resume,
	    { "Resume Handle", "svcctl.resume", FT_UINT32, BASE_DEC,
	      NULL, 0x0, "SVCCTL resume handle", HFILL }},
	};

        static gint *ett[] = {
                &ett_dcerpc_svcctl,
                &ett_dcerpc_svcctl_service_type_bits,
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
