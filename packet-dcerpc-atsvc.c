/* packet-dcerpc-atsvc.c
 * Routines for SMB \pipe\atsvc packet disassembly
 * Copyright 2003 Jean-Baptiste Marchand <jbm@hsc.fr>
 *
 * $Id: packet-dcerpc-atsvc.c,v 1.1 2003/05/28 22:43:57 sharpe Exp $
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
#include "packet-dcerpc-nt.h"
#include "packet-dcerpc-atsvc.h"
#include "smb.h"


static int proto_dcerpc_atsvc = -1;

static int hf_atsvc_server = -1;
static int hf_atsvc_opnum = -1;
static int hf_atsvc_rc = -1;
static int hf_atsvc_job_id = -1;
static int hf_atsvc_job_time = -1;
static int hf_atsvc_job_days_of_month = -1;
static int hf_atsvc_job_days_of_week = -1;
static int hf_atsvc_job_flags = -1;
static int hf_atsvc_min_job_id = -1;
static int hf_atsvc_max_job_id = -1;
static int hf_atsvc_job_flags_noninteractive = -1;
static int hf_atsvc_job_flags_add_current_date = -1;
static int hf_atsvc_job_flags_runs_today = -1;
static int hf_atsvc_job_flags_exec_error = -1;
static int hf_atsvc_job_flags_run_periodically = -1;

static gint ett_dcerpc_atsvc = -1;
static gint ett_dcerpc_atsvc_job = -1;
static gint ett_dcerpc_atsvc_job_flags = -1;


/* 
IDL [ uuid(1ff70682-0a51-30e8-076d-740be8cee98b),
IDL  version(1.0),
IDL  implicit_handle(handle_t rpc_binding)
IDL ] interface atsvc
*/


static e_uuid_t uuid_dcerpc_atsvc = {
	0x1ff70682, 0x0a51, 0x30e8,
	{ 0x07, 0x6d, 0x74, 0x0b, 0xe8, 0xce, 0xe9, 0x8b }
};

static guint16 ver_dcerpc_atsvc = 1; 


/*
 IDL typedef struct {
 IDL   long JobTime;
 IDL   long DaysOfMonth;
 IDL   char DaysOfWeek;
 IDL   char Flags;
 IDL   [unique] [string] wchar_t *Command;
 IDL } AT_INFO;
 */

static int
dissect_atsvc_AT_INFO(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	proto_item *item = NULL;
	proto_tree *subtree = NULL;
	proto_tree *flags_tree = NULL;
	guint32 job_time;
	guint8 job_flags;
	guint8 job_hour, job_min, job_sec;
	guint16 job_msec;


	if (tree) {
		item = proto_tree_add_text(tree, tvb, offset, -1, "Job");
		subtree = proto_item_add_subtree(item, ett_dcerpc_atsvc_job);
	}

	if (subtree) {

		offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, drep,
				0, &job_time);

		job_hour = job_time / 3600000;
		job_min = (job_time - job_hour * 3600000) / 60000;
		job_sec = (job_time - (job_hour * 3600000) - (job_min * 60000)) / 1000;
		job_msec = (job_time - (job_hour * 3600000) - (job_min * 60000) - (job_sec * 1000));

		proto_tree_add_uint_format(subtree, hf_atsvc_job_time, tvb, offset - 4,
				4, job_time, "Time: %02d:%02d:%02d:%03d", job_hour, job_min, job_sec, job_msec);

		offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, drep,
				hf_atsvc_job_days_of_month, NULL);

		offset = dissect_ndr_uint8(tvb, offset, pinfo, subtree, drep,
				hf_atsvc_job_days_of_week, NULL);

		offset = dissect_ndr_uint8(tvb, offset, pinfo, NULL, drep,
					0, &job_flags);

		item = proto_tree_add_text(subtree, tvb, offset-1, 1, "Flags: 0x%02x", job_flags);
		flags_tree = proto_item_add_subtree(item, ett_dcerpc_atsvc_job_flags);

		if (flags_tree) {

#define JOB_RUN_PERIODICALLY 0x01
#define JOB_EXEC_ERROR 0x02
#define JOB_RUNS_TODAY 0x04
#define JOB_ADD_CURRENT_DATE 0x08
#define JOB_NONINTERACTIVE 0x10


			if (job_flags & JOB_RUN_PERIODICALLY) {
				proto_tree_add_boolean(flags_tree, hf_atsvc_job_flags_run_periodically,
						tvb, offset-1, 1, job_flags);
			}

			if (job_flags & JOB_EXEC_ERROR) {
				proto_tree_add_boolean(flags_tree, hf_atsvc_job_flags_exec_error,
						tvb, offset-1, 1, job_flags);
			}

			if (job_flags & JOB_RUNS_TODAY) {
				proto_tree_add_boolean(flags_tree, hf_atsvc_job_flags_runs_today,
						tvb, offset-1, 1, job_flags);
			}

			if (job_flags & JOB_ADD_CURRENT_DATE) {
				proto_tree_add_boolean(flags_tree, hf_atsvc_job_flags_add_current_date,
						tvb, offset-1, 1, job_flags);
			}

			if (job_flags & JOB_NONINTERACTIVE) {
				proto_tree_add_boolean(flags_tree, hf_atsvc_job_flags_noninteractive,
						tvb, offset-1, 1, job_flags);
			}
				

		offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, subtree, drep,
				NDR_POINTER_UNIQUE, "Command", hf_atsvc_server, 0);
		}
	}

	return offset;
}


/*
 IDL long NetrJobAdd(
 IDL       [in] [unique] [string] wchar_t *Servername,
 IDL       [in] [ref] AT_INFO *element_22,
 IDL      [out] [ref] long *JobId
 IDL );
 */

static int
atsvc_dissect_add_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_atsvc_server, 0);

	offset = dissect_atsvc_AT_INFO(tvb, offset, pinfo, tree, drep);

	return offset;
}

static int
atsvc_dissect_add_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_atsvc_job_id, NULL);
	
	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, 
			hf_atsvc_rc, NULL);

	return offset;
}


/*
 IDL long NetrJobDel(
 IDL       [in] [unique] [string] wchar_t *Servername,
 IDL       [in] long MinJobId,
 IDL       [in] long MaxJobId,
 IDL );
 */

static int
atsvc_dissect_del_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_atsvc_server, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_atsvc_min_job_id, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_atsvc_max_job_id, NULL);

	return offset;
}

static int
atsvc_dissect_del_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, 
			hf_atsvc_rc, NULL);
	return offset;
}


/*
 IDL typedef struct {
 IDL   long JobId;
 IDL   long JobTime;
 IDL   long DaysOfMonth;
 IDL   char DaysOfWeek;
 IDL   char Flags;
 IDL   [unique] [string] wchar_t *Command;
 IDL } AT_ENUM;
 */

static int
dissect_atsvc_AT_ENUM(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_atsvc_job_id, NULL);

	offset = dissect_atsvc_AT_INFO(tvb, offset, pinfo, tree, drep);

	return offset;
}

/*
 IDL typedef struct {
 IDL   long element_27;
 IDL   [size_is(element_27)] [unique] AT_ENUM *element_28;
 IDL } TYPE_2;
 */


/*
 IDL long NetrJobEnum(
 IDL       [in] [unique] [string] wchar_t *Servername,
 IDL   [in,out] [ref] TYPE_2 *PointerToBuffer,
 IDL       [in] long PreferredMaximumLength,
 IDL      [out] [ref] long *element_38,
 IDL   [in,out] [unique] long *element_39
 IDL );
 */

static int
atsvc_dissect_enum_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_atsvc_server, 0);

	return offset;
}

static int
atsvc_dissect_enum_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	return offset;
}


/*
 IDL long NetrJobGetInfo(
 IDL       [in] [unique] [string] wchar_t *ServerName,
 IDL       [in] long JobId,
 IDL      [out] [ref] AT_INFO **PointerToBuffer
 IDL );
 */

static int
atsvc_dissect_getinfo_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_atsvc_server, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_atsvc_job_id, NULL);

	return offset;
}

static int
atsvc_dissect_getinfo_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_atsvc_AT_INFO, NDR_POINTER_UNIQUE,
			"Job info", -1);
	return offset;
}

static dcerpc_sub_dissector dcerpc_atsvc_dissectors[] = {
	{ ATSVC_JOB_ADD, "NetrJobAdd", atsvc_dissect_add_rqst, atsvc_dissect_add_reply },
	{ ATSVC_JOB_DEL, "NetrJobDel", atsvc_dissect_del_rqst, atsvc_dissect_del_reply },
	{ ATSVC_JOB_ENUM, "NetrJobEnum", atsvc_dissect_enum_rqst, NULL },
	{ ATSVC_JOB_GETINFO, "NetrJobGetInfo", atsvc_dissect_getinfo_rqst, atsvc_dissect_getinfo_reply },
        { 0, NULL, NULL,  NULL }
};


static const value_string atsvc_opnum_vals[] = {
	{ ATSVC_JOB_ADD, "NetrJobAdd" },
	{ ATSVC_JOB_DEL, "NetrJobDel" },
	{ ATSVC_JOB_ENUM, "NetrJobEnum" },
	{ ATSVC_JOB_GETINFO, "NetrJobGetInfo" },
	{ 0, NULL }
};


static const value_string atsvc_job_day_of_week[] = {
	{ 0x00, "Today" },
	{ 0x01, "Monday" },
	{ 0x02, "Tuesday" },
	{ 0x04, "Wednesday" },
	{ 0x08, "Thursday" },
	{ 0x10, "Friday" },
	{ 0x20, "Saturday" },
	{ 0x40, "Sunday" },
	{ 0, NULL }
};

static const true_false_string tfs_job_flags_type = {
	"Job runs periodically",
	"Job runs once"
};

static const true_false_string tfs_job_flags_exec_error = {
	"Last job execution was successful",
	"Last job execution failed"
};

static const true_false_string tfs_job_flags_runs_today = {
	"Job is scheduled to execute today",
	"Job is NOT scheduled to execute today"
};

static const true_false_string tfs_job_flags_add_current_date = {
	"Job relative to current date",
	"Job NOT relative to current date"
};

static const true_false_string tfs_job_flags_noninteractive = {
	"Job is NOT interactive", 
	"Job is interactive"
};

void
proto_register_dcerpc_atsvc(void)
{

        static hf_register_info hf[] = {

	  	{ &hf_atsvc_server,
		    { "Server", "atsvc.server", FT_STRING, BASE_NONE,
		      NULL, 0x0, "Server Name", HFILL}},

		{ &hf_atsvc_opnum, 
		  { "Operation", "atsvc.opnum", FT_UINT16, BASE_DEC,
		   VALS(atsvc_opnum_vals), 0x0, "Operation", HFILL }},	

		{&hf_atsvc_rc,
		  { "Return code", "atsvc.rc", FT_UINT32, BASE_HEX,
		    VALS(NT_errors), 0x0, "Eventlog return status code", HFILL }}, 

	  	{ &hf_atsvc_job_id,
		    { "Job ID", "atsvc.job_id", FT_UINT32,
		      BASE_DEC, NULL, 0x0, "Job ID", HFILL}},

	  	{ &hf_atsvc_job_time,
		    { "Job time", "atsvc.job_time", FT_UINT32,
		      BASE_DEC, NULL, 0x0, "Job time", HFILL}},

	  	{ &hf_atsvc_job_days_of_month,
		    { "Job day of the month", "atsvc.job_day_of_month", FT_UINT32,
		      BASE_DEC, NULL, 0x0, "Job day of the month", HFILL}},

	  	{ &hf_atsvc_job_days_of_week,
		    { "Job day of the week", "atsvc.job_day_of_week", FT_UINT8,
		      BASE_DEC, VALS(atsvc_job_day_of_week), 0x0, "Job day of the week", HFILL}},

	  	{ &hf_atsvc_job_flags,
		    { "Job flags", "atsvc.job_flags", FT_UINT8,
		      BASE_DEC, NULL, 0x0, "Job flags", HFILL}},

	  	{ &hf_atsvc_min_job_id,
		    { "Min job ID", "atsvc.min_id", FT_UINT32,
		      BASE_DEC, NULL, 0x0, "Min job ID", HFILL}},

	  	{ &hf_atsvc_max_job_id,
		    { "Max job ID", "atsvc.max_id", FT_UINT32,
		      BASE_DEC, NULL, 0x0, "Max job ID", HFILL}},

		{ &hf_atsvc_job_flags_run_periodically,
		    { "Job type", "atsvc.jobs.flags.type", FT_BOOLEAN, 8,
	 		TFS(&tfs_job_flags_type), JOB_RUN_PERIODICALLY, "Job type", HFILL }},

		{ &hf_atsvc_job_flags_exec_error,
		    { "Last job execution error", "atsvc.jobs.flags.exec_error", FT_BOOLEAN, 8,
	 		TFS(&tfs_job_flags_exec_error), JOB_EXEC_ERROR, "Last job execution failed?", HFILL }},

		{ &hf_atsvc_job_flags_runs_today,
		    { "Job scheduled to execute today", "atsvc.jobs.flags.runs_today", FT_BOOLEAN, 8,
	 		TFS(&tfs_job_flags_runs_today), JOB_RUNS_TODAY, "Job runs today?", HFILL }},

		{ &hf_atsvc_job_flags_add_current_date,
		    { "Job relative to current date?", "atsvc.jobs.flags.add_current_date", FT_BOOLEAN, 8,
	 		TFS(&tfs_job_flags_add_current_date), JOB_ADD_CURRENT_DATE, "Job relative to current date?", HFILL }},

		{ &hf_atsvc_job_flags_noninteractive,
		    { "Job interactive status", "atsvc.jobs.flags.noninteractive", FT_BOOLEAN, 8,
	 		TFS(&tfs_job_flags_noninteractive), JOB_NONINTERACTIVE, "Job interactive status", HFILL }},

	};


        static gint *ett[] = {
                &ett_dcerpc_atsvc,
		&ett_dcerpc_atsvc_job,
		&ett_dcerpc_atsvc_job_flags
        };


	proto_dcerpc_atsvc = proto_register_protocol(
		"Microsoft Task Scheduler Service", "ATSVC", "atsvc");

	proto_register_field_array(proto_dcerpc_atsvc, hf, array_length(hf));

        proto_register_subtree_array(ett, array_length(ett));

}


void
proto_reg_handoff_dcerpc_atsvc(void)
{

	/* register protocol as dcerpc */

	dcerpc_init_uuid(
		proto_dcerpc_atsvc, ett_dcerpc_atsvc, &uuid_dcerpc_atsvc,
		ver_dcerpc_atsvc, dcerpc_atsvc_dissectors, hf_atsvc_opnum);

}


