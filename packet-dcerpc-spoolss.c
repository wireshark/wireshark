/* packet-dcerpc-spoolss.c
 * Routines for SMB \PIPE\spoolss packet disassembly
 * Copyright 2001-2002, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-dcerpc-spoolss.c,v 1.55 2002/11/08 19:25:42 sharpe Exp $
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
#include <string.h>

#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"
#include "packet-dcerpc-spoolss.h"
#include "packet-dcerpc-reg.h"
#include "smb.h"
#include "packet-smb-common.h"

/* Global objects */

static int hf_spoolss_opnum = -1;

static const value_string spoolss_opnum_vals[] = {
        { SPOOLSS_ENUMPRINTERS, "EnumPrinters" },
	{ SPOOLSS_OPENPRINTER, "OpenPrinter" },
        { SPOOLSS_SETJOB, "SetJob" },
        { SPOOLSS_GETJOB, "GetJob" },
        { SPOOLSS_ENUMJOBS, "EnumJobs" },
        { SPOOLSS_ADDPRINTER, "AddPrinter" },
        { SPOOLSS_DELETEPRINTER, "DeletePrinter" },
        { SPOOLSS_SETPRINTER, "SetPrinter" },
        { SPOOLSS_GETPRINTER, "GetPrinter" },
        { SPOOLSS_ADDPRINTERDRIVER, "AddPrinterDriver" },
        { SPOOLSS_ENUMPRINTERDRIVERS, "EnumPrinterDrivers" },
	{ SPOOLSS_GETPRINTERDRIVER, "GetPrinterDriver" },
        { SPOOLSS_GETPRINTERDRIVERDIRECTORY, "GetPrinterDriverDirectory" },
        { SPOOLSS_DELETEPRINTERDRIVER, "DeletePrinterDriver" },
        { SPOOLSS_ADDPRINTPROCESSOR, "AddPrintProcessor" },
        { SPOOLSS_ENUMPRINTPROCESSORS, "EnumPrintProcessor" },
	{ SPOOLSS_GETPRINTPROCESSORDIRECTORY, "GetPrintProcessorDirectory" },
        { SPOOLSS_STARTDOCPRINTER, "StartDocPrinter" },
        { SPOOLSS_STARTPAGEPRINTER, "StartPagePrinter" },
        { SPOOLSS_WRITEPRINTER, "WritePrinter" },
        { SPOOLSS_ENDPAGEPRINTER, "EndPagePrinter" },
        { SPOOLSS_ABORTPRINTER, "AbortPrinter" },
	{ SPOOLSS_READPRINTER, "ReadPrinter" },
        { SPOOLSS_ENDDOCPRINTER, "EndDocPrinter" },
        { SPOOLSS_ADDJOB, "AddJob" },
        { SPOOLSS_SCHEDULEJOB, "ScheduleJob" },
        { SPOOLSS_GETPRINTERDATA, "GetPrinterData" },
        { SPOOLSS_SETPRINTERDATA, "SetPrinterData" },
	{ SPOOLSS_WAITFORPRINTERCHANGE, "WaitForPrinterChange" },
        { SPOOLSS_CLOSEPRINTER, "ClosePrinter" },
        { SPOOLSS_ADDFORM, "AddForm" },
        { SPOOLSS_DELETEFORM, "DeleteForm" },
        { SPOOLSS_GETFORM, "GetForm" },
        { SPOOLSS_SETFORM, "SetForm" },
        { SPOOLSS_ENUMFORMS, "EnumForms" },
        { SPOOLSS_ENUMPORTS, "EnumPorts" },
        { SPOOLSS_ENUMMONITORS, "EnumMonitors" },
	{ SPOOLSS_ADDPORT, "AddPort" },
	{ SPOOLSS_CONFIGUREPORT, "ConfigurePort" },
	{ SPOOLSS_DELETEPORT, "DeletePort" },
	{ SPOOLSS_CREATEPRINTERIC, "CreatePrinterIC" },
	{ SPOOLSS_PLAYGDISCRIPTONPRINTERIC, "PlayDiscriptOnPrinterIC" },
	{ SPOOLSS_DELETEPRINTERIC, "DeletePrinterIC" },
	{ SPOOLSS_ADDPRINTERCONNECTION, "AddPrinterConnection" },
	{ SPOOLSS_DELETEPRINTERCONNECTION, "DeletePrinterConnection" },
	{ SPOOLSS_PRINTERMESSAGEBOX, "PrinterMessageBox" },
	{ SPOOLSS_ADDMONITOR, "AddMonitor" },
	{ SPOOLSS_DELETEMONITOR, "DeleteMonitor" },
	{ SPOOLSS_DELETEPRINTPROCESSOR, "DeletePrintProcessor" },
	{ SPOOLSS_ADDPRINTPROVIDER, "AddPrintProvider" },
	{ SPOOLSS_DELETEPRINTPROVIDER, "DeletePrintProvider" },
        { SPOOLSS_ENUMPRINTPROCDATATYPES, "EnumPrintProcDataTypes" },
	{ SPOOLSS_RESETPRINTER, "ResetPrinter" },
        { SPOOLSS_GETPRINTERDRIVER2, "GetPrinterDriver2" },
	{ SPOOLSS_FINDFIRSTPRINTERCHANGENOTIFICATION, "FindNextPrinterChangeNotification" },
	{ SPOOLSS_FINDNEXTPRINTERCHANGENOTIFICATION, "FindNextPrinterChangeNotification" },
        { SPOOLSS_FCPN, "FCPN" },
	{ SPOOLSS_ROUTERFINDFIRSTPRINTERNOTIFICATIONOLD, "RouterFindFirstPrinterNotificationOld" },
        { SPOOLSS_REPLYOPENPRINTER, "ReplyOpenPrinter" },
	{ SPOOLSS_ROUTERREPLYPRINTER, "RouterReplyPrinter" },
        { SPOOLSS_REPLYCLOSEPRINTER, "ReplyClosePrinter" },
	{ SPOOLSS_ADDPORTEX, "AddPortEx" },
	{ SPOOLSS_REMOTEFINDFIRSTPRINTERCHANGENOTIFICATION, "RemoteFindFirstPrinterChangeNotification" },
	{ SPOOLSS_SPOOLERINIT, "SpoolerInit" },
	{ SPOOLSS_RESETPRINTEREX, "ResetPrinterEx" },
        { SPOOLSS_RFFPCNEX, "RFFPCNEX" },
        { SPOOLSS_RRPCN, "RRPCN" },
        { SPOOLSS_RFNPCNEX, "RFNPCNEX" },
        { SPOOLSS_OPENPRINTEREX, "OpenPrinterEx" },
        { SPOOLSS_ADDPRINTEREX, "AddPrinterEx" },
        { SPOOLSS_ENUMPRINTERDATA, "EnumPrinterData" },
        { SPOOLSS_DELETEPRINTERDATA, "DeletePrinterData" },
        { SPOOLSS_GETPRINTERDATAEX, "GetPrinterDataEx" },
        { SPOOLSS_SETPRINTERDATAEX, "SetPrinterDataEx" },
	{ SPOOLSS_ENUMPRINTERDATAEX, "EnumPrinterDataEx" },
	{ SPOOLSS_ENUMPRINTERKEY, "EnumPrinterKey" },
	{ SPOOLSS_DELETEPRINTERDATAEX, "DeletePrinterDataEx" },
	{ SPOOLSS_DELETEPRINTERDRIVEREX, "DeletePrinterDriverEx" },
	{ SPOOLSS_ADDPRINTERDRIVEREX, "AddPrinterDriverEx" },
	{ 0, NULL }
};

static int hf_spoolss_hnd = -1;
static int hf_spoolss_rc = -1;
static int hf_spoolss_offered = -1;
static int hf_spoolss_needed = -1;
static int hf_spoolss_returned = -1;
static int hf_spoolss_buffer_size = -1;
static int hf_spoolss_buffer_data = -1;
static int hf_spoolss_relstr_offset = -1;
static int hf_spoolss_printername = -1;
static int hf_spoolss_servername = -1;
static int hf_spoolss_drivername = -1;
static int hf_spoolss_architecture = -1;
static int hf_spoolss_username = -1;
static int hf_spoolss_documentname = -1;
static int hf_spoolss_outputfile = -1;
static int hf_spoolss_datatype = -1;
static int hf_spoolss_textstatus = -1;
static int hf_spoolss_level = -1;
static int hf_access_required = -1;

/* Print job */

static int hf_spoolss_jobid = -1;
static int hf_spoolss_jobpriority = -1;
static int hf_spoolss_jobposition = -1;
static int hf_spoolss_jobtotalpages = -1;
static int hf_spoolss_jobpagesprinted = -1;
static int hf_spoolss_enumjobs_firstjob = -1;
static int hf_spoolss_enumjobs_numjobs = -1;

/* SYSTEM_TIME */

static int hf_spoolss_time_year = -1;
static int hf_spoolss_time_month = -1;
static int hf_spoolss_time_dow = -1;
static int hf_spoolss_time_day = -1;
static int hf_spoolss_time_hour = -1;
static int hf_spoolss_time_minute = -1;
static int hf_spoolss_time_second = -1;
static int hf_spoolss_time_msec = -1;

/* Printer data */

static int hf_spoolss_printerdata_value = -1;
static int hf_spoolss_printerdata_type = -1;

/* enumprinterdata */

static int hf_spoolss_enumprinterdata_index = -1;
static int hf_spoolss_enumprinterdata_value_offered = -1;
static int hf_spoolss_enumprinterdata_data_offered = -1;
static int hf_spoolss_enumprinterdata_value_needed = -1;
static int hf_spoolss_enumprinterdata_data_needed = -1;

/* SetJob */

static int hf_spoolss_setjob_cmd = -1;

/* WritePrinter */

static int hf_spoolss_writeprinter_numwritten = -1;

/* GetPrinterDriver2 */

static int hf_spoolss_clientmajorversion = -1;
static int hf_spoolss_clientminorversion = -1;
static int hf_spoolss_servermajorversion = -1;
static int hf_spoolss_serverminorversion = -1;
static int hf_spoolss_driverpath = -1;
static int hf_spoolss_datafile = -1;
static int hf_spoolss_configfile = -1;
static int hf_spoolss_helpfile = -1;
static int hf_spoolss_monitorname = -1;
static int hf_spoolss_defaultdatatype = -1;
static int hf_spoolss_driverinfo_cversion = -1;
static int hf_spoolss_dependentfiles = -1;
static int hf_spoolss_printer_status = -1;

/* rffpcnex */

static int hf_spoolss_rffpcnex_flags = -1;
static int hf_spoolss_rffpcnex_options = -1;
static int hf_spoolss_printerlocal = -1;
static int hf_spoolss_notify_options_version = -1;
static int hf_spoolss_notify_options_flags = -1;
static int hf_spoolss_notify_options_flags_refresh = -1;
static int hf_spoolss_notify_options_count = -1;
static int hf_spoolss_notify_option_type = -1;
static int hf_spoolss_notify_option_reserved1 = -1;
static int hf_spoolss_notify_option_reserved2 = -1;
static int hf_spoolss_notify_option_reserved3 = -1;
static int hf_spoolss_notify_option_count = -1;
static int hf_spoolss_notify_option_data_count = -1;
static int hf_spoolss_notify_info_count = -1;
static int hf_spoolss_notify_info_version = -1;
static int hf_spoolss_notify_info_flags = -1;
static int hf_spoolss_notify_info_data_type = -1;
static int hf_spoolss_notify_info_data_count = -1;
static int hf_spoolss_notify_info_data_id = -1;
static int hf_spoolss_notify_info_data_value1 = -1;
static int hf_spoolss_notify_info_data_value2 = -1;
static int hf_spoolss_notify_info_data_bufsize = -1;
static int hf_spoolss_notify_info_data_buffer = -1;
static int hf_spoolss_notify_info_data_buffer_len = -1;
static int hf_spoolss_notify_info_data_buffer_data = -1;

static int hf_spoolss_notify_field = -1;

static int hf_spoolss_rrpcn_changelow = -1;
static int hf_spoolss_rrpcn_changehigh = -1;
static int hf_spoolss_rrpcn_unk0 = -1;
static int hf_spoolss_rrpcn_unk1 = -1;

static int hf_spoolss_replyopenprinter_unk0 = -1;
static int hf_spoolss_replyopenprinter_unk1 = -1;

static const value_string printer_status_vals[] =
{
	{ PRINTER_STATUS_OK, "OK" },
	{ PRINTER_STATUS_PAUSED, "Paused" },
	{ PRINTER_STATUS_ERROR, "Error" },
	{ PRINTER_STATUS_PENDING_DELETION, "Pending deletion" },
	{ PRINTER_STATUS_PAPER_JAM, "Paper jam" },
	{ PRINTER_STATUS_PAPER_OUT, "Paper out" },
	{ PRINTER_STATUS_MANUAL_FEED, "Manual feed" },
	{ PRINTER_STATUS_PAPER_PROBLEM, "Paper problem" },
	{ PRINTER_STATUS_OFFLINE, "Offline" },
	{ PRINTER_STATUS_IO_ACTIVE, "IO active" },
	{ PRINTER_STATUS_BUSY, "Busy" },
	{ PRINTER_STATUS_PRINTING, "Printing" },
	{ PRINTER_STATUS_OUTPUT_BIN_FULL, "Output bin full" },
	{ PRINTER_STATUS_NOT_AVAILABLE, "Not available" },
	{ PRINTER_STATUS_WAITING, "Waiting" },
	{ PRINTER_STATUS_PROCESSING, "Processing" },
	{ PRINTER_STATUS_INITIALIZING, "Initialising" },
	{ PRINTER_STATUS_WARMING_UP, "Warming up" },
	{ PRINTER_STATUS_TONER_LOW, "Toner low" },
	{ PRINTER_STATUS_NO_TONER, "No toner" },
	{ PRINTER_STATUS_PAGE_PUNT, "Page punt" },
	{ PRINTER_STATUS_USER_INTERVENTION, "User intervention" },
	{ PRINTER_STATUS_OUT_OF_MEMORY, "Out of memory" },
	{ PRINTER_STATUS_DOOR_OPEN, "Door open" },
	{ PRINTER_STATUS_SERVER_UNKNOWN, "Server unknown" },
	{ PRINTER_STATUS_POWER_SAVE, "Power save" },
	{ 0, NULL }
};

/* Printer attributes */

static int hf_spoolss_printer_attributes = -1;
static int hf_spoolss_printer_attributes_queued = -1;
static int hf_spoolss_printer_attributes_direct = -1;
static int hf_spoolss_printer_attributes_default = -1;
static int hf_spoolss_printer_attributes_shared = -1;
static int hf_spoolss_printer_attributes_network = -1;
static int hf_spoolss_printer_attributes_hidden = -1;
static int hf_spoolss_printer_attributes_local = -1;
static int hf_spoolss_printer_attributes_enable_devq = -1;
static int hf_spoolss_printer_attributes_keep_printed_jobs = -1;
static int hf_spoolss_printer_attributes_do_complete_first = -1;
static int hf_spoolss_printer_attributes_work_offline = -1;
static int hf_spoolss_printer_attributes_enable_bidi = -1;
static int hf_spoolss_printer_attributes_raw_only = -1;
static int hf_spoolss_printer_attributes_published = -1;

static const true_false_string tfs_printer_attributes_queued = {
	"Printer starts printing after last page spooled",
	"Printer starts printing while spooling"
};

static const true_false_string tfs_printer_attributes_direct = {
	"Jobs sent directly to printer",
	"Jobs are spooled to printer before printing"
};

static const true_false_string tfs_printer_attributes_default = {
	"Printer is the default printer",
	"Printer is not the default printer"
};

static const true_false_string tfs_printer_attributes_shared = {
	"Printer is shared",
	"Printer is not shared"
};

static const true_false_string tfs_printer_attributes_network = {
	"Printer is a network printer connection",
	"Printer is not a network printer connection"
};

static const true_false_string tfs_printer_attributes_hidden = {
	"Reserved",
	"Reserved"
};

static const true_false_string tfs_printer_attributes_local = {
	"Printer is a local printer",
	"Printer is not a local printer"
};

static const true_false_string tfs_printer_attributes_enable_devq = {
	"Call DevQueryPrint",
	"Do not call DevQueryPrint"
};

static const true_false_string tfs_printer_attributes_keep_printed_jobs = {
	"Jobs are kept after they are printed",
	"Jobs are deleted after printing"
};

static const true_false_string tfs_printer_attributes_do_complete_first = {
	"Jobs that have completed spooling are scheduled before still spooling jobs",
	"Jobs are scheduled in the order they start spooling"
};

static const true_false_string tfs_printer_attributes_work_offline = {
	"The printer is currently connected",
	"The printer is currently not connected"
};

static const true_false_string tfs_printer_attributes_enable_bidi = {
	"Bidirectional communications are supported",
	"Bidirectional communications are not supported"
};

static const true_false_string tfs_printer_attributes_raw_only = {
	"Only raw data type print jobs can be spooled",
	"All data type print jobs can be spooled"
};

static const true_false_string tfs_printer_attributes_published = {
	"Printer is published in the directory",
	"Printer is not published in the directory"
};

static int hf_spoolss_job_status = -1;
static int hf_spoolss_job_status_paused = -1;
static int hf_spoolss_job_status_error = -1;
static int hf_spoolss_job_status_deleting = -1;
static int hf_spoolss_job_status_spooling = -1;
static int hf_spoolss_job_status_printing = -1;
static int hf_spoolss_job_status_offline = -1;
static int hf_spoolss_job_status_paperout = -1;
static int hf_spoolss_job_status_printed = -1;
static int hf_spoolss_job_status_deleted = -1;
static int hf_spoolss_job_status_blocked = -1;
static int hf_spoolss_job_status_user_intervention = -1;

static const true_false_string tfs_job_status_paused = {
	"Job is paused",
	"Job is not paused"
};

static const true_false_string tfs_job_status_error = {
	"Job has an error",
	"Job is OK"
};

static const true_false_string tfs_job_status_deleting = {
	"Job is being deleted",
	"Job is not being deleted"
};

static const true_false_string tfs_job_status_spooling = {
	"Job is being spooled",
	"Job is not being spooled"
};

static const true_false_string tfs_job_status_printing = {
	"Job is being printed",
	"Job is not being printed"
};

static const true_false_string tfs_job_status_offline = {
	"Job is offline",
	"Job is not offline"
};

static const true_false_string tfs_job_status_paperout = {
	"Job is out of paper",
	"Job is not out of paper"
};

static const true_false_string tfs_job_status_printed = {
	"Job has completed printing",
	"Job has not completed printing"
};

static const true_false_string tfs_job_status_deleted = {
	"Job has been deleted",
	"Job has not been deleted"
};

static const true_false_string tfs_job_status_blocked = {
	"Job has been blocked",
	"Job has not been blocked"
};

static const true_false_string tfs_job_status_user_intervention = {
	"User intervention required",
	"User intervention not required"
};

/* Setprinter RPC */

static int hf_spoolss_setprinter_cmd = -1;

static const value_string setprinter_cmd_vals[] = {
	{ SPOOLSS_PRINTER_CONTROL_UNPAUSE, "Unpause" },
	{ SPOOLSS_PRINTER_CONTROL_PAUSE, "Pause" },
	{ SPOOLSS_PRINTER_CONTROL_RESUME, "Resume" },
	{ SPOOLSS_PRINTER_CONTROL_PURGE, "Purge" },
	{ SPOOLSS_PRINTER_CONTROL_SET_STATUS, "Set status" },
	{ 0, NULL }
};

/* RouterReplyPrinter RPC */

static int hf_spoolss_routerreplyprinter_condition = -1;
static int hf_spoolss_routerreplyprinter_unknown1 = -1;
static int hf_spoolss_routerreplyprinter_changeid = -1;

/* Forms */

static int hf_spoolss_form_level = -1;
static int hf_spoolss_form_name = -1;
static int hf_spoolss_form_flags = -1;
static int hf_spoolss_form_unknown = -1;
static int hf_spoolss_form_width = -1;
static int hf_spoolss_form_height = -1;
static int hf_spoolss_form_left_margin = -1;
static int hf_spoolss_form_top_margin = -1;
static int hf_spoolss_form_horiz_len = -1;
static int hf_spoolss_form_vert_len = -1;

/* AddForm RPC */

static int hf_spoolss_addform_level = -1;

/* GetForm RPC */

static int hf_spoolss_getform_level = -1;

/* SetForm RPC */

static int hf_spoolss_setform_level = -1;

/* EnumForms RPC */

static int hf_spoolss_enumforms_num = -1;

/* Printerdata */

static int hf_spoolss_printerdata_size = -1;
static int hf_spoolss_printerdata_data = -1;

/*
 * Dissect SPOOLSS specific access rights
 */

static int hf_server_access_admin = -1;
static int hf_server_access_enum = -1;
static int hf_printer_access_admin = -1;
static int hf_printer_access_use = -1;
static int hf_job_access_admin = -1;

/* EnumPrinterKey */
static int hf_spoolss_keybuffer_size = -1;
static int hf_spoolss_keybuffer_data = -1;

static void
spoolss_specific_rights(tvbuff_t *tvb, gint offset, proto_tree *tree,
			guint32 access)
{
	proto_tree_add_boolean(
		tree, hf_job_access_admin,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_printer_access_use,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_printer_access_admin,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_server_access_enum,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_server_access_admin,
		tvb, offset, 4, access);
}

/*
 * Routines to dissect a spoolss BUFFER
 */

typedef struct {
	guint32 size;		/* Size of buffer */
	guint8 *data;		/* Contents of buffer */
	int offset;		/* Offset to start of buffer */
	proto_item *tree;	/* Proto tree buffer located in */
} BUFFER;

static int
dissect_spoolss_buffer_data(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, char *drep)
{
	dcerpc_info *di = pinfo->private_data;
	BUFFER *b = (BUFFER *)di->private_data;
	guint32 size;
	guint8 *data;

	if (di->conformant_run)
		return offset;

	/* Dissect size and data */

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_buffer_size, &size);

	offset = dissect_ndr_uint8s(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_buffer_data, size, &data);

	/* Return buffer info */

	if (b) {
		b->size = size;
		b->data = data;
		b->offset = offset - size;
		b->tree = tree;
	}

	return offset;
}

/* Dissect a spoolss buffer and return buffer data */

static int
dissect_spoolss_buffer(tvbuff_t *tvb, gint offset, packet_info *pinfo,
		       proto_tree *tree, char *drep, BUFFER *b)
{
	dcerpc_info *di = pinfo->private_data;

	if (b)
		memset(b, 0, sizeof(BUFFER));

	di->private_data = b;

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
				     dissect_spoolss_buffer_data,
				     NDR_POINTER_UNIQUE, "Buffer",
				     -1, 0);

	return offset;
}

/*
 * New system for handling pointers and buffers.  We act more like the NDR
 * specification and have a list of deferred pointers which are processed
 * after a structure has been parsed.
 *
 * Each structure has a parse function which takes as an argument a GList.
 * As pointers are processed, they are appended onto this list.  When the
 * structure is complete, the pointers (referents) are processed by calling
 * prs_referents().  In the case of function arguments, the
 * prs_struct_and_referents() function is called as pointers are always
 * processed immediately after the argument.
 */

typedef int prs_fn(tvbuff_t *tvb, int offset, packet_info *pinfo,
		   proto_tree *tree, GList **dp_list, void **data);

/* Deferred referent */

struct deferred_ptr {
	prs_fn *fn;		/* Parse function to call */
	proto_tree *tree;	/* Tree context */
};

/* A structure to hold needed ethereal state to pass to GList foreach
   iterator. */

struct deferred_ptr_state {
	tvbuff_t *tvb;
	int *poffset;
	packet_info *pinfo;
	GList **dp_list;
	void **ptr_data;
};

static void defer_ptr(GList **list, prs_fn *fn, proto_tree *tree)
{
	struct deferred_ptr *dr;

	dr = g_malloc(sizeof(struct deferred_ptr));

	dr->fn = fn;
	dr->tree = tree;

	*list = g_list_append(*list, dr);
}

/* Parse a pointer */

static int prs_ptr(tvbuff_t *tvb, int offset, packet_info *pinfo,
		   proto_tree *tree, guint32 *data, char *name)
{
	guint32 ptr;

	offset = prs_uint32(tvb, offset, pinfo, tree, &ptr, NULL);

	if (tree && name)
		proto_tree_add_text(tree, tvb, offset - 4, 4,
				    "%s pointer: 0x%08x", name, ptr);

	if (data)
		*data = ptr;

	return offset;
}

/* Iterator function for prs_referents */

static void dr_iterator(gpointer data, gpointer user_data)
{
	struct deferred_ptr *dp = (struct deferred_ptr *)data;
	struct deferred_ptr_state *s = (struct deferred_ptr_state *)user_data;

	/* Parse pointer */

	*s->poffset = dp->fn(s->tvb, *s->poffset, s->pinfo, dp->tree,
			     s->dp_list, s->ptr_data);

	if (s->ptr_data)
		s->ptr_data++;		/* Ready for next parse fn */
}

/* Call the parse function for each element in the deferred pointers list.
   If there are any additional pointers in these structures they are pushed
   onto parent_dp_list. */

static int prs_referents(tvbuff_t *tvb, int offset, packet_info *pinfo,
		  proto_tree *tree _U_, GList **dp_list, GList **list,
		  void ***ptr_data)
{
	struct deferred_ptr_state s;
	int new_offset = offset;

	/* Create a list of void pointers to store return data */

	if (ptr_data) {
		int len = g_list_length(*dp_list) * sizeof(void *);

		if (len > 0) {
			*ptr_data = malloc(len);
			memset(*ptr_data, 0, len);
		} else
			*ptr_data = NULL;
	}

	/* Set up iterator data */

	s.tvb = tvb;
	s.poffset = &new_offset;
	s.pinfo = pinfo;
	s.dp_list = dp_list;
	s.ptr_data = ptr_data ? *ptr_data : NULL;

	g_list_foreach(*list, dr_iterator, &s);

	*list = NULL;		/* XXX: free list */

	return new_offset;
}

/* Parse a structure then clean up any deferred referants it creates. */

static int prs_struct_and_referents(tvbuff_t *tvb, int offset,
				    packet_info *pinfo, proto_tree *tree,
				    prs_fn *fn, void **data, void ***ptr_data)
{
	GList *dp_list = NULL;

	offset = fn(tvb, offset, pinfo, tree, &dp_list, data);

	offset = prs_referents(tvb, offset, pinfo, tree, &dp_list,
			       &dp_list, ptr_data);

	return offset;
}

/*
 * SpoolssClosePrinter
 */

static int SpoolssClosePrinter_q(tvbuff_t *tvb, int offset,
				 packet_info *pinfo, proto_tree *tree,
				 char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	e_ctx_hnd policy_hnd;
	char *pol_name;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);
	/* Parse packet */

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_spoolss_hnd, &policy_hnd,
				       FALSE, TRUE);

	dcerpc_smb_fetch_pol(&policy_hnd, &pol_name, NULL, NULL);

	if (check_col(pinfo->cinfo, COL_INFO) && pol_name)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
				pol_name);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssClosePrinter_r(tvbuff_t *tvb, int offset,
				 packet_info *pinfo, proto_tree *tree,
				 char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_spoolss_hnd, NULL,
				       FALSE, FALSE);


	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/* Parse a UNISTR2 structure */

static gint ett_UNISTR2 = -1;

static int prs_UNISTR2_dp(tvbuff_t *tvb, int offset, packet_info *pinfo,
			  proto_tree *tree, GList **dp_list _U_, void **data)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 length, the_offset, max_len;
	int old_offset = offset;
	int data16_offset;
	char *text;

	offset = prs_uint32(tvb, offset, pinfo, tree, &length, NULL);
	offset = prs_uint32(tvb, offset, pinfo, tree, &the_offset, NULL);
	offset = prs_uint32(tvb, offset, pinfo, tree, &max_len, NULL);

	offset = prs_uint16s(tvb, offset, pinfo, tree, max_len, &data16_offset,
			     NULL);

	text = fake_unicode(tvb, data16_offset, max_len);

	item = proto_tree_add_text(tree, tvb, old_offset, offset - old_offset,
				   "UNISTR2: %s", text);

	subtree = proto_item_add_subtree(item, ett_UNISTR2);

	if (data)
		*data = text;
	else
		g_free(text);

	proto_tree_add_text(subtree, tvb, old_offset, 4, "Length: %u", length);

	old_offset += 4;

	proto_tree_add_text(subtree, tvb, old_offset, 4, "Offset: %u",
			    the_offset);

	old_offset += 4;

	proto_tree_add_text(subtree, tvb, old_offset, 4, "Max length: %u",
			    max_len);

	old_offset += 4;

	proto_tree_add_text(subtree, tvb, old_offset, max_len * 2, "Data");

	return offset;
}

/* Dissect some printer data.  The get/set/enum printerdata routines all
   store value/data in a uint8 array.  We could use the ndr routines for
   this but that would result in one item for each byte in the printer
   data. */

static gint ett_printerdata_data = -1;
static gint ett_printerdata_value = -1;

static int dissect_printerdata_data(tvbuff_t *tvb, int offset,
				    packet_info *pinfo, proto_tree *tree,
				    char *drep _U_)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 size;

	item = proto_tree_add_text(tree, tvb, offset, 0, "Printer data");
	subtree = proto_item_add_subtree(item, ett_printerdata_data);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, drep,
		hf_spoolss_printerdata_size, &size);

	offset = dissect_ndr_uint8s(
		tvb, offset, pinfo, subtree, drep,
		hf_spoolss_printerdata_data, size, NULL);

	proto_item_set_len(item, size + 4);

	return offset;
}

/*
 * SpoolssGetPrinterData
 */

static int SpoolssGetPrinterData_q(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	char *value_name = NULL;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep, hf_spoolss_hnd, NULL,
		FALSE, FALSE);

 	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
 					  prs_UNISTR2_dp, (void **)&value_name,
 					  NULL);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", value_name);

	g_free(value_name);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_offered, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssGetPrinterData_r(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_printerdata_type, NULL);

	offset = dissect_printerdata_data(tvb, offset, pinfo, tree, drep);

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Needed");

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * SpoolssGetPrinterDataEx
 */

static int SpoolssGetPrinterDataEx_q(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	char *key_name, *value_name;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep, hf_spoolss_hnd, NULL,
		FALSE, FALSE);

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_UNISTR2_dp, (void **)&key_name,
					  NULL);

	/*
	 * Register a cleanup function in case on of our tvbuff accesses
	 * throws an exception. We need to clean up key_name.
	 */
	CLEANUP_PUSH(g_free, key_name);

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_UNISTR2_dp, (void **)&value_name,
					  NULL);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s/%s",
				key_name, value_name);

	/*
	 * We're done with key_name, so we can call the cleanup handler to
	 * free it, and then pop the cleanup handler.
	 */
	CLEANUP_CALL_AND_POP;

	/*
	 * We're also done with value_name.
	 */
	g_free(value_name);

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Size");

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssGetPrinterDataEx_r(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 size;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_printerdata_type, NULL);

	offset = prs_uint32(tvb, offset, pinfo, tree, &size, "Size");

	offset = prs_uint8s(tvb, offset, pinfo, tree, size, NULL, "Data");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Needed");

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * SpoolssSetPrinterData
 */

static int SpoolssSetPrinterData_q(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	char *value_name = NULL;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep, hf_spoolss_hnd, NULL,
		FALSE, FALSE);

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_UNISTR2_dp, (void **)&value_name,
					  NULL);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", value_name);

	g_free(value_name);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_printerdata_type, NULL);

	offset = dissect_printerdata_data(tvb, offset, pinfo, tree, drep);

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Offered");

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssSetPrinterData_r(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * SpoolssSetPrinterDataEx
 */

static int SpoolssSetPrinterDataEx_q(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	char *key_name, *value_name;
	guint32 max_len;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep, hf_spoolss_hnd, NULL,
		FALSE, FALSE);

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_UNISTR2_dp, (void **)&key_name,
					  NULL);

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_UNISTR2_dp, (void **)&value_name,
					  NULL);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s/%s",
				key_name, value_name);

	g_free(key_name);
	g_free(value_name);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_printerdata_type, NULL);

	offset = prs_uint32(tvb, offset, pinfo, tree, &max_len, "Max length");

	offset = prs_uint8s(tvb, offset, pinfo, tree, max_len, NULL,
			    "Data");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Real length");

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssSetPrinterDataEx_r(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/* Yet another way to represent a unicode string - sheesh. This function
   dissects a NULL terminate unicode string at the current offset and
   returns the (char *) equivalent.  This really should return UTF8 or
   something but we use fake_unicode() instead. */

static int
dissect_spoolss_uint16uni(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			  proto_tree *tree, char *drep _U_, char **data)
{
	gint len, remaining;
	char *text;

	if (offset % 2)
		offset += 2 - (offset % 2);

	/* Get remaining data in buffer as a string */

	remaining = tvb_length_remaining(tvb, offset) / 2;
	text = fake_unicode(tvb, offset, remaining);
	len = strlen(text);

	proto_tree_add_text(tree, tvb, offset, len * 2, "%s: %s",
			    "UINT16UNI", tvb_bytes_to_str(tvb, offset, len * 2));

	if (data)
		*data = text;
	else
		g_free(text);

	return offset + (len + 1) * 2;
}

static int prs_uint16uni(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			 proto_tree *tree, void **data, char *name)
{
	gint len = 0, remaining;
	char *text;

	offset = prs_align(offset, 2);

	/* Get remaining data in buffer as a string */

	remaining = tvb_length_remaining(tvb, offset)/2;
	text = fake_unicode(tvb, offset, remaining);
	len = strlen(text);

	if (name)
		proto_tree_add_text(tree, tvb, offset, (len + 1) * 2,
				    "%s: %s", name ? name : "UINT16UNI",
				    text);

	if (data)
		*data = text;
	else
		g_free(text);

	return offset + (len + 1) * 2;
}

/*
 * DEVMODE
 */

static gint ett_DEVMODE = -1;

static int prs_DEVMODE(tvbuff_t *tvb, int offset, packet_info *pinfo,
		       proto_tree *tree, GList **dp_list _U_, void **data _U_)
{
	proto_item *item;
	proto_tree *subtree;
	guint16 extra;

	item = proto_tree_add_text(tree, tvb, offset, 0, "DEVMODE");

	subtree = proto_item_add_subtree(item, ett_DEVMODE);

 	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Size");

	/* The device name is stored in a 32-wchar buffer */

	prs_uint16uni(tvb, offset, pinfo, subtree, NULL, "Devicename");
	offset += 64;

	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Spec version");
	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Driver version");
	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Size");
	offset = prs_uint16(tvb, offset, pinfo, subtree, &extra, "Driver extra");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Fields");

	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Orientation");
	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Paper size");
	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Paper length");
	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Paper width");
	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Scale");
	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Copies");
	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Default source");
	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Print quality");
	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Color");
	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Duplex");
	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Y resolution");
	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "TT option");
	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Collate");

	prs_uint16uni(tvb, offset, pinfo, subtree, NULL, "Form name");
	offset += 64;

	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Log pixels");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Bits per pel");
	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Pels width");
	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Pels height");
	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Display flags");
	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Display frequency");
	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "ICM method");
	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "ICM intent");
	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Media type");
	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Dither type");
	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Reserved");
	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Reserved");
	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Panning width");
	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Panning height");

	if (extra != 0)
		offset = prs_uint8s(tvb, offset, pinfo, subtree, extra, NULL,
				    "Private");

	return offset;
}

/*
 * Relative string given by offset into the current buffer.  Note that
 * the offset for subsequent relstrs are against the structure start, not
 * the point where the offset is parsed from.
 */

static gint ett_RELSTR = -1;

static int
dissect_spoolss_relstr(tvbuff_t *tvb, int offset, packet_info *pinfo,
		       proto_tree *tree, char *drep, int hf_index,
		       int struct_start, char **data)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 relstr_offset, relstr_start, relstr_end, relstr_len;
	char *text;

	item = proto_tree_add_string(tree, hf_index, tvb, offset, 4, "");

	subtree = proto_item_add_subtree(item, ett_RELSTR);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, drep,
				    hf_spoolss_relstr_offset,
				    &relstr_offset);

	/* A relative offset of zero is a NULL string */

	relstr_start = relstr_offset + struct_start;

	if (relstr_offset)
		relstr_end = dissect_spoolss_uint16uni(
			tvb, relstr_start, pinfo, subtree, drep, &text);
	else {
		text = g_strdup("NULL");
		relstr_end = offset;
	}

	relstr_len = relstr_end - relstr_start;

	proto_item_append_text(item, text);

	if (data)
		*data = text;
	else
		g_free(text);

	return offset;
}

/* An array of relative strings.  This is currently just a copy of the
   dissect_spoolss_relstr() function as I can't find an example driver that
   has more than one dependent file. */

static gint ett_RELSTR_ARRAY = -1;

static int
dissect_spoolss_relstrarray(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, char *drep, int hf_index,
			    int struct_start, char **data)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 relstr_offset, relstr_start, relstr_end, relstr_len;
	char *text;

	item = proto_tree_add_string(tree, hf_index, tvb, offset, 4, "");

	subtree = proto_item_add_subtree(item, ett_RELSTR_ARRAY);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, drep,
				    hf_spoolss_relstr_offset,
				    &relstr_offset);

	/* A relative offset of zero is a NULL string */

	relstr_start = relstr_offset + struct_start;

	if (relstr_offset)
		relstr_end = dissect_spoolss_uint16uni(
			tvb, relstr_start, pinfo, subtree, drep, &text);
	else {
		text = g_strdup("NULL");
		relstr_end = offset;
	}

	relstr_len = relstr_end - relstr_start;

	proto_item_append_text(item, text);

	if (data)
		*data = text;
	else
		g_free(text);

	return offset;
}

static int prs_relstr(tvbuff_t *tvb, int offset, packet_info *pinfo,
		      proto_tree *tree, GList **dp_list _U_, int struct_start,
		      void **data, char *name)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 relstr_offset, relstr_start, relstr_end;
	char *text = strdup("NULL");

	offset = prs_uint32(tvb, offset, pinfo, tree, &relstr_offset, NULL);

	/* A relative offset of zero is a NULL string */

	relstr_start = relstr_offset + struct_start;

	if (relstr_offset)
		relstr_end = prs_uint16uni(tvb, relstr_start, pinfo, tree,
					   (void **)&text, NULL);
	else
		relstr_end = offset;

	item = proto_tree_add_text(tree, tvb, relstr_start,
				   relstr_end - relstr_start, "%s: %s",
				   name ? name : "RELSTR", text);

	subtree = proto_item_add_subtree(item, ett_RELSTR);

	if (data)
		*data = text;
	else
		g_free(text);

	proto_tree_add_text(subtree, tvb, offset - 4, 4,
			    "Relative offset: %d", relstr_offset);

	proto_tree_add_text(subtree, tvb, relstr_start,
			    relstr_end - relstr_start, "Data");

	return offset;
}

/*
 * PRINTER_INFO_0
 */

static gint ett_PRINTER_INFO_0 = -1;

static int prs_PRINTER_INFO_0(tvbuff_t *tvb, int offset, packet_info *pinfo,
			      proto_tree *tree, GList **dp_list,
			      void **data _U_)
{
	int struct_start = offset;

	offset = prs_relstr(tvb, offset, pinfo, tree, dp_list, struct_start,
			    NULL, "Printer name");
	offset = prs_relstr(tvb, offset, pinfo, tree, dp_list, struct_start,
			    NULL, "Server name");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "CJobs");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Total jobs");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Total bytes");

	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Year");
	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Month");
	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Day of week");
	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Day");
	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Hour");
	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Minute");
	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Second");
	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Milliseconds");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Global counter");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Total pages");

	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Major version");
	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Build version");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Session counter");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Printer errors");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Change id");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Status");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "C_setprinter");

	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Unknown");

	return offset;
}

/*
 * PRINTER_INFO_1
 */

static gint ett_PRINTER_INFO_1 = -1;

static int prs_PRINTER_INFO_1(tvbuff_t *tvb, int offset, packet_info *pinfo,
			      proto_tree *tree, GList **dp_list,
			      void **data _U_)
{
	int struct_start = offset;

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Flags");

	offset = prs_relstr(tvb, offset, pinfo, tree, dp_list, struct_start,
			    NULL, "Description");

	offset = prs_relstr(tvb, offset, pinfo, tree, dp_list, struct_start,
			    NULL, "Name");

	offset = prs_relstr(tvb, offset, pinfo, tree, dp_list, struct_start,
			    NULL, "Comment");

	return offset;
}

/* Job status */

static gint ett_job_status = -1;

static int
dissect_job_status(tvbuff_t *tvb, int offset, packet_info *pinfo,
		   proto_tree *tree, char *drep)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, drep,
				    hf_spoolss_job_status, &status);

	item = proto_tree_add_text(tree, tvb, offset - 4, 4,
				   "Status: 0x%08x", status);

	subtree = proto_item_add_subtree(item, ett_job_status);

	proto_tree_add_boolean(
		subtree, hf_spoolss_job_status_user_intervention,
		tvb, offset - 4, 4, status);

	proto_tree_add_boolean(
		subtree, hf_spoolss_job_status_blocked,
		tvb, offset - 4, 4, status);

	proto_tree_add_boolean(
		subtree, hf_spoolss_job_status_deleted,
		tvb, offset - 4, 4, status);

	proto_tree_add_boolean(
		subtree, hf_spoolss_job_status_printed,
		tvb, offset - 4, 4, status);

	proto_tree_add_boolean(
		subtree, hf_spoolss_job_status_paperout,
		tvb, offset - 4, 4, status);

	proto_tree_add_boolean(
		subtree, hf_spoolss_job_status_offline,
		tvb, offset - 4, 4, status);

	proto_tree_add_boolean(
		subtree, hf_spoolss_job_status_printing,
		tvb, offset - 4, 4, status);

	proto_tree_add_boolean(
		subtree, hf_spoolss_job_status_spooling,
		tvb, offset - 4, 4, status);

	proto_tree_add_boolean(
		subtree, hf_spoolss_job_status_deleting,
		tvb, offset - 4, 4, status);

	proto_tree_add_boolean(
		subtree, hf_spoolss_job_status_error,
		tvb, offset - 4, 4, status);

	proto_tree_add_boolean(
		subtree, hf_spoolss_job_status_paused,
		tvb, offset - 4, 4, status);

	return offset;
}

/* Printer attributes */

static gint ett_printer_attributes = -1;

static int
dissect_printer_attributes(tvbuff_t *tvb, int offset, packet_info *pinfo,
			   proto_tree *tree, char *drep)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 attributes;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, drep,
				    hf_spoolss_printer_attributes,
				    &attributes);

	item = proto_tree_add_text(tree, tvb, offset - 4, 4,
				   "Attributes: 0x%08x", attributes);

	subtree = proto_item_add_subtree(item, ett_printer_attributes);

	proto_tree_add_boolean(
		subtree, hf_spoolss_printer_attributes_published,
		tvb, offset - 4, 4, attributes);

	proto_tree_add_boolean(
		subtree, hf_spoolss_printer_attributes_raw_only,
		tvb, offset - 4, 4, attributes);

	proto_tree_add_boolean(
		subtree, hf_spoolss_printer_attributes_enable_bidi,
		tvb, offset - 4, 4, attributes);

	proto_tree_add_boolean(
		subtree, hf_spoolss_printer_attributes_work_offline,
		tvb, offset - 4, 4, attributes);

	proto_tree_add_boolean(
		subtree, hf_spoolss_printer_attributes_do_complete_first,
		tvb, offset - 4, 4, attributes);

	proto_tree_add_boolean(
		subtree, hf_spoolss_printer_attributes_keep_printed_jobs,
		tvb, offset - 4, 4, attributes);

	proto_tree_add_boolean(
		subtree, hf_spoolss_printer_attributes_enable_devq,
		tvb, offset - 4, 4, attributes);

	proto_tree_add_boolean(
		subtree, hf_spoolss_printer_attributes_local,
		tvb, offset - 4, 4, attributes);

	proto_tree_add_boolean(
		subtree, hf_spoolss_printer_attributes_hidden,
		tvb, offset - 4, 4, attributes);

	proto_tree_add_boolean(
		subtree, hf_spoolss_printer_attributes_network,
		tvb, offset - 4, 4, attributes);

	proto_tree_add_boolean(
		subtree, hf_spoolss_printer_attributes_shared,
		tvb, offset - 4, 4, attributes);

	proto_tree_add_boolean(
		subtree, hf_spoolss_printer_attributes_default,
		tvb, offset - 4, 4, attributes);

	proto_tree_add_boolean(
		subtree, hf_spoolss_printer_attributes_direct,
		tvb, offset - 4, 4, attributes);

	proto_tree_add_boolean(
		subtree, hf_spoolss_printer_attributes_queued,
		tvb, offset - 4, 4, attributes);

	return offset;
}

/*
 * PRINTER_INFO_2
 */

static gint ett_PRINTER_INFO_2 = -1;

static int prs_PRINTER_INFO_2(tvbuff_t *tvb, int offset, packet_info *pinfo,
			      proto_tree *tree, int len, GList **dp_list,
			      void **data _U_)
{
	int struct_start = offset;
	guint32 rel_offset;

	offset = prs_relstr(tvb, offset, pinfo, tree, dp_list, struct_start,
			    NULL, "Server name");

	offset = prs_relstr(tvb, offset, pinfo, tree, dp_list, struct_start,
			    NULL, "Printer name");

	offset = prs_relstr(tvb, offset, pinfo, tree, dp_list, struct_start,
			    NULL, "Share name");

	offset = prs_relstr(tvb, offset, pinfo, tree, dp_list, struct_start,
                           NULL, "Port name");

	offset = prs_relstr(tvb, offset, pinfo, tree, dp_list, struct_start,
			    NULL, "Driver name");

	offset = prs_relstr(tvb, offset, pinfo, tree, dp_list, struct_start,
			    NULL, "Comment");

	offset = prs_relstr(tvb, offset, pinfo, tree, dp_list, struct_start,
			    NULL, "Location");

	/* This is a relative devicemode */

	offset = prs_uint32(tvb, offset, pinfo, tree, &rel_offset, NULL);

	prs_DEVMODE(tvb, struct_start + rel_offset - 4, pinfo, tree,
		    dp_list, NULL);

	offset = prs_relstr(tvb, offset, pinfo, tree, dp_list, struct_start,
			    NULL, "Separator file");

	offset = prs_relstr(tvb, offset, pinfo, tree, dp_list, struct_start,
			    NULL, "Print processor");

	offset = prs_relstr(tvb, offset, pinfo, tree, dp_list, struct_start,
			    NULL, "Datatype");

	offset = prs_relstr(tvb, offset, pinfo, tree, dp_list, struct_start,
			    NULL, "Parameters");

	/* This is a relative security descriptor */

	offset = prs_uint32(tvb, offset, pinfo, tree, &rel_offset, NULL);

	/*
	 * XXX - what *is* the length of this security descriptor?
	 * "prs_PRINTER_INFO_2()" is passed to "defer_ptr()", but
	 * "defer_ptr" takes, as an argument, a function with a
	 * different calling sequence from "prs_PRINTER_INFO_2()",
	 * lacking the "len" argument, so that won't work.
	 */
	dissect_nt_sec_desc(tvb, struct_start + rel_offset, tree, len);

/*	offset = dissect_printer_attributes(tvb, offset, pinfo, tree, drep); */

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Attributes");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Priority");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL,
			    "Default priority");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Start time");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "End time");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Status");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Jobs");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Average PPM");

	return offset;
}

/*
 * PRINTER_INFO_3
 */

static gint ett_PRINTER_INFO_3 = -1;

static int prs_PRINTER_INFO_3(tvbuff_t *tvb, int offset, packet_info *pinfo,
			      proto_tree *tree, int len, GList **dp_list _U_,
			      void **data _U_)
{
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Flags");

	offset = dissect_nt_sec_desc(tvb, offset, tree, len);

	return offset;
}

/*
 * DEVMODE_CTR
 */

static gint ett_DEVMODE_CTR = -1;

static int prs_DEVMODE_CTR(tvbuff_t *tvb, int offset, packet_info *pinfo,
			   proto_tree *tree, GList **dp_list, void **data)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 ptr = 0;

	item = proto_tree_add_text(tree, tvb, offset, 0, "DEVMODE_CTR");

	subtree = proto_item_add_subtree(item, ett_DEVMODE_CTR);

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Size");

	offset = prs_ptr(tvb, offset, pinfo, subtree, &ptr, "Devicemode");

	if (ptr)
		offset = prs_DEVMODE(tvb, offset, pinfo, subtree, dp_list,
				     data);

	return offset;
}

/*
 * PRINTER_DEFAULT structure
 */

static gint ett_PRINTER_DEFAULT = -1;

static int prs_PRINTER_DEFAULT(tvbuff_t *tvb, int offset, packet_info *pinfo,
			       proto_tree *tree, GList **dp_list,
			       void **data _U_)
{
	GList *child_dp_list = NULL;
	proto_item *item;
	proto_tree *subtree;
	guint32 ptr = 0;
	char drep = 0x10;

	item = proto_tree_add_text(tree, tvb, offset, 0, "PRINTER_DEFAULT");

	subtree = proto_item_add_subtree(item, ett_PRINTER_DEFAULT);

	offset = prs_ptr(tvb, offset, pinfo, subtree, &ptr, "Datatype");

	/* Not sure why this isn't a deferred pointer.  I think this may be
	   two structures stuck together. */

	if (ptr)
		offset = prs_UNISTR2_dp(tvb, offset, pinfo, subtree, dp_list,
					NULL);

	offset = prs_DEVMODE_CTR(tvb, offset, pinfo, subtree,
				 &child_dp_list, NULL);

	offset = dissect_nt_access_mask(
		tvb, offset, pinfo, subtree, &drep, hf_access_required,
		spoolss_specific_rights);

	offset = prs_referents(tvb, offset, pinfo, subtree, dp_list,
			       &child_dp_list, NULL);

	return offset;
}

/*
 * USER_LEVEL_1 structure
 */

static gint ett_USER_LEVEL_1 = -1;

static int prs_USER_LEVEL_1(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, GList **dp_list,
			    void **data _U_)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 ptr = 0;

	item = proto_tree_add_text(tree, tvb, offset, 0, "USER_LEVEL_1");

	subtree = proto_item_add_subtree(item, ett_USER_LEVEL_1);

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Size");

	offset = prs_ptr(tvb, offset, pinfo, subtree, &ptr, "Client name");

	if (ptr)
		defer_ptr(dp_list, prs_UNISTR2_dp, subtree);

	offset = prs_ptr(tvb, offset, pinfo, subtree, &ptr, "User name");

	if (ptr)
		defer_ptr(dp_list, prs_UNISTR2_dp, subtree);

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Build");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Major");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Minor");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Processor");

	return offset;
}

/*
 * USER_LEVEL structure
 */

static gint ett_USER_LEVEL = -1;

static int prs_USER_LEVEL(tvbuff_t *tvb, int offset, packet_info *pinfo,
			  proto_tree *tree, GList **parent_dp_list,
			  void **data _U_)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 ptr = 0;
	guint32 level;

	item = proto_tree_add_text(tree, tvb, offset, 0, "USER_LEVEL");

	subtree = proto_item_add_subtree(item, ett_USER_LEVEL);

	offset = prs_uint32(tvb, offset, pinfo, subtree, &level, "Info level");

	offset = prs_ptr(tvb, offset, pinfo, subtree, &ptr, "User level");

	if (ptr) {
		switch (level) {
		case 1:
			defer_ptr(parent_dp_list, prs_USER_LEVEL_1, subtree);
			break;
		default:
			proto_tree_add_text(
				tree, tvb, offset, 0,
				"[GetPrinter level %d not decoded]", level);
			break;
		}
	}

	return offset;
}

/*
 * SpoolssOpenPrinterEx
 */

static int SpoolssOpenPrinterEx_q(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 ptr = 0;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = prs_ptr(tvb, offset, pinfo, tree, &ptr, "Printer name");

	if (ptr) {
		char *printer_name;

		offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
						  prs_UNISTR2_dp,
						  (void **)&printer_name,
						  NULL);

		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
					printer_name);

		/* Store printer name to match with reply packet */

		dcv->private_data = printer_name;
	}

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_PRINTER_DEFAULT, NULL, NULL);

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "User switch");

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_USER_LEVEL, NULL, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssOpenPrinterEx_r(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	e_ctx_hnd policy_hnd;
	guint32 status;
	int start_offset = offset;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* We need the value of the policy handle and status before we
	   can retrieve the policy handle name.  Then we can insert
	   the policy handle with the name in the proto tree. */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, NULL, drep, hf_spoolss_hnd, &policy_hnd,
		TRUE, FALSE);

	offset = dissect_doserror(tvb, offset, pinfo, NULL, drep,
				  hf_spoolss_rc, &status);

	if (status == 0) {

		/* Associate the returned printer handle with a name */

		if (dcv->private_data) {
			dcerpc_smb_store_pol_name(
				&policy_hnd, dcv->private_data);

			g_free(dcv->private_data);
			dcv->private_data = NULL;
		}
	}

	/* Parse packet */

	offset = start_offset;

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep, hf_spoolss_hnd, &policy_hnd,
		TRUE, FALSE);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, &status);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static const value_string printer_notify_option_data_vals[] = {
	{ PRINTER_NOTIFY_SERVER_NAME, "Server name" },
	{ PRINTER_NOTIFY_PRINTER_NAME, "Printer name" },
	{ PRINTER_NOTIFY_SHARE_NAME, "Share name" },
	{ PRINTER_NOTIFY_PORT_NAME, "Port name" },
	{ PRINTER_NOTIFY_DRIVER_NAME, "Driver name" },
	{ PRINTER_NOTIFY_COMMENT, "Comment" },
	{ PRINTER_NOTIFY_LOCATION, "Location" },
	{ PRINTER_NOTIFY_DEVMODE, "Devmode" },
	{ PRINTER_NOTIFY_SEPFILE, "Sepfile" },
	{ PRINTER_NOTIFY_PRINT_PROCESSOR, "Print processor" },
	{ PRINTER_NOTIFY_PARAMETERS, "Parameters" },
	{ PRINTER_NOTIFY_DATATYPE, "Datatype" },
	{ PRINTER_NOTIFY_SECURITY_DESCRIPTOR, "Security descriptor" },
	{ PRINTER_NOTIFY_ATTRIBUTES, "Attributes" },
	{ PRINTER_NOTIFY_PRIORITY, "Priority" },
	{ PRINTER_NOTIFY_DEFAULT_PRIORITY, "Default priority" },
	{ PRINTER_NOTIFY_START_TIME, "Start time" },
	{ PRINTER_NOTIFY_UNTIL_TIME, "Until time" },
	{ PRINTER_NOTIFY_STATUS, "Status" },
	{ PRINTER_NOTIFY_STATUS_STRING, "Status string" },
	{ PRINTER_NOTIFY_CJOBS, "Cjobs" },
	{ PRINTER_NOTIFY_AVERAGE_PPM, "Average PPM" },
	{ PRINTER_NOTIFY_TOTAL_PAGES, "Total pages" },
	{ PRINTER_NOTIFY_PAGES_PRINTED, "Pages printed" },
	{ PRINTER_NOTIFY_TOTAL_BYTES, "Total bytes" },
	{ PRINTER_NOTIFY_BYTES_PRINTED, "Bytes printed" },
	{ 0, NULL}
};

static const value_string job_notify_option_data_vals[] = {
	{ JOB_NOTIFY_PRINTER_NAME, "Printer name" },
	{ JOB_NOTIFY_MACHINE_NAME, "Machine name" },
	{ JOB_NOTIFY_PORT_NAME, "Port name" },
	{ JOB_NOTIFY_USER_NAME, "User name" },
	{ JOB_NOTIFY_NOTIFY_NAME, "Notify name" },
	{ JOB_NOTIFY_DATATYPE, "Data type" },
	{ JOB_NOTIFY_PRINT_PROCESSOR, "Print processor" },
	{ JOB_NOTIFY_PARAMETERS, "Parameters" },
	{ JOB_NOTIFY_DRIVER_NAME, "Driver name" },
	{ JOB_NOTIFY_DEVMODE, "Devmode" },
	{ JOB_NOTIFY_STATUS, "Status" },
	{ JOB_NOTIFY_STATUS_STRING, "Status string" },
	{ JOB_NOTIFY_SECURITY_DESCRIPTOR, "Security descriptor" },
	{ JOB_NOTIFY_DOCUMENT, "Document" },
	{ JOB_NOTIFY_PRIORITY, "Priority" },
	{ JOB_NOTIFY_POSITION, "Position" },
	{ JOB_NOTIFY_SUBMITTED, "Submitted" },
	{ JOB_NOTIFY_START_TIME, "Start time" },
	{ JOB_NOTIFY_UNTIL_TIME, "Until time" },
	{ JOB_NOTIFY_TIME, "Time" },
	{ JOB_NOTIFY_TOTAL_PAGES, "Total pages" },
	{ JOB_NOTIFY_PAGES_PRINTED, "Pages printed" },
	{ JOB_NOTIFY_TOTAL_BYTES, "Total bytes" },
	{ JOB_NOTIFY_BYTES_PRINTED, "Bytes printed" },
	{ 0, NULL}
};

static int
dissect_notify_field(tvbuff_t *tvb, int offset, packet_info *pinfo,
		     proto_tree *tree, char *drep, guint16 type,
		     guint16 *data)
{
	guint16 field;
	char *str;

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, NULL, drep,
		hf_spoolss_notify_field, &field);

	switch(type) {
	case PRINTER_NOTIFY_TYPE:
		str = val_to_str(field, printer_notify_option_data_vals,
				 "Unknown");
		break;
	case JOB_NOTIFY_TYPE:
		str = val_to_str(field, job_notify_option_data_vals,
				 "Unknown");
		break;
	default:
		str = "Unknown notify type";
		break;
	}

	proto_tree_add_text(tree, tvb, offset - 2, 2,
			    "Field: %s (%d)", str, field);

	if (data)
		*data = field;

	return offset;
}

static int
dissect_NOTIFY_OPTION_DATA(tvbuff_t *tvb, int offset, packet_info *pinfo,
			   proto_tree *tree, char *drep)
{
	dcerpc_info *di = pinfo->private_data;
	guint32 count, i;
	guint16 type;

	if (di->conformant_run)
		return offset;

	type = di->levels;

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_spoolss_notify_option_data_count, &count);

	for (i = 0; i < count; i++)
		offset = dissect_notify_field(
			tvb, offset, pinfo, tree, drep, type, NULL);

	return offset;
}

static const value_string printer_notify_types[] =
{
	{ PRINTER_NOTIFY_TYPE, "Printer notify" },
	{ JOB_NOTIFY_TYPE, "Job notify" },
	{ 0, NULL }
};

static gint ett_NOTIFY_OPTION = -1;

static int
dissect_NOTIFY_OPTION(tvbuff_t *tvb, int offset, packet_info *pinfo,
		      proto_tree *tree, char *drep)
{
	proto_item *item;
	proto_tree *subtree;
	guint16 type;

	item = proto_tree_add_text(tree, tvb, offset, 0, "NOTIFY_OPTION");

	subtree = proto_item_add_subtree(item, ett_NOTIFY_OPTION);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, subtree, drep,
				    hf_spoolss_notify_option_type, &type);

	proto_item_append_text(item, ": %s",
			       val_to_str(type, printer_notify_types, "Unknown (%d)"));

	offset = dissect_ndr_uint16(tvb, offset, pinfo, subtree, drep,
				    hf_spoolss_notify_option_reserved1, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, drep,
				    hf_spoolss_notify_option_reserved2, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, drep,
				    hf_spoolss_notify_option_reserved3, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, drep,
				    hf_spoolss_notify_option_count, NULL);

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, subtree, drep,
		dissect_NOTIFY_OPTION_DATA, NDR_POINTER_UNIQUE,
		"NOTIFY_OPTION_DATA", -1, type);

	return offset;
}

static int
dissect_NOTIFY_OPTIONS_ARRAY(tvbuff_t *tvb, int offset,
			     packet_info *pinfo, proto_tree *tree,
			     char *drep)
{
	/* Why is a check for di->conformant_run not required here? */

	offset = dissect_ndr_ucarray(
		tvb, offset, pinfo, tree, drep, dissect_NOTIFY_OPTION);

	return offset;
}

static gint ett_notify_options_flags = -1;

static const true_false_string tfs_notify_options_flags_refresh = {
	"Data for all monitored fields is present",
	"Data for all monitored fields not present"
};

static int
dissect_notify_options_flags(tvbuff_t *tvb, int offset, packet_info *pinfo,
			     proto_tree *tree, char *drep)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 flags;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, drep,
				    hf_spoolss_notify_options_flags,
				    &flags);

	item = proto_tree_add_text(tree, tvb, offset - 4, 4,
				   "Flags: 0x%08x", flags);

	subtree = proto_item_add_subtree(item, ett_notify_options_flags);

	proto_tree_add_boolean(
		subtree, hf_spoolss_notify_options_flags_refresh,
		tvb, offset, 4, flags);

	return offset;
}

static int
dissect_NOTIFY_OPTIONS_ARRAY_CTR(tvbuff_t *tvb, int offset,
				 packet_info *pinfo, proto_tree *tree,
				 char *drep)
{
	dcerpc_info *di = pinfo->private_data;

	if (di->conformant_run)
		return offset;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_notify_options_version, NULL);

	offset = dissect_notify_options_flags(tvb, offset, pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_notify_options_count, NULL);

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, tree, drep,
		dissect_NOTIFY_OPTIONS_ARRAY, NDR_POINTER_UNIQUE,
		"NOTIFY_OPTIONS", -1, 0);

	return offset;
}

/*
 * SpoolssRFFPCNEX
 */

static gint ett_rffpcnex_flags = -1;

static int hf_spoolss_rffpcnex_flags_add_printer = -1;
static int hf_spoolss_rffpcnex_flags_set_printer = -1;
static int hf_spoolss_rffpcnex_flags_delete_printer = -1;
static int hf_spoolss_rffpcnex_flags_failed_printer_connection = -1;

static const true_false_string tfs_rffpcnex_flags_add_printer = {
	"Notify on add printer",
	"Don't notify on add printer"
};

static const true_false_string tfs_rffpcnex_flags_set_printer = {
	"Notify on set printer",
	"Don't notify on set printer"
};

static const true_false_string tfs_rffpcnex_flags_delete_printer = {
	"Notify on delete printer",
	"Don't notify on delete printer"
};

static const true_false_string tfs_rffpcnex_flags_failed_connection_printer = {
	"Notify on failed printer connection",
	"Don't notify on failed printer connection"
};

static int hf_spoolss_rffpcnex_flags_add_job = -1;
static int hf_spoolss_rffpcnex_flags_set_job = -1;
static int hf_spoolss_rffpcnex_flags_delete_job = -1;
static int hf_spoolss_rffpcnex_flags_write_job = -1;

static const true_false_string tfs_rffpcnex_flags_add_job = {
	"Notify on add job",
	"Don't notify on add job"
};

static const true_false_string tfs_rffpcnex_flags_set_job = {
	"Notify on set job",
	"Don't notify on set job"
};

static const true_false_string tfs_rffpcnex_flags_delete_job = {
	"Notify on delete job",
	"Don't notify on delete job"
};

static const true_false_string tfs_rffpcnex_flags_write_job = {
	"Notify on writejob",
	"Don't notify on write job"
};

static int hf_spoolss_rffpcnex_flags_add_form = -1;
static int hf_spoolss_rffpcnex_flags_set_form = -1;
static int hf_spoolss_rffpcnex_flags_delete_form = -1;

static const true_false_string tfs_rffpcnex_flags_add_form = {
	"Notify on add form",
	"Don't notify on add form"
};

static const true_false_string tfs_rffpcnex_flags_set_form = {
	"Notify on set form",
	"Don't notify on set form"
};

static const true_false_string tfs_rffpcnex_flags_delete_form = {
	"Notify on delete form",
	"Don't notify on delete form"
};

static int hf_spoolss_rffpcnex_flags_add_port = -1;
static int hf_spoolss_rffpcnex_flags_configure_port = -1;
static int hf_spoolss_rffpcnex_flags_delete_port = -1;

static const true_false_string tfs_rffpcnex_flags_add_port = {
	"Notify on add port",
	"Don't notify on add port"
};

static const true_false_string tfs_rffpcnex_flags_configure_port = {
	"Notify on configure port",
	"Don't notify on configure port"
};

static const true_false_string tfs_rffpcnex_flags_delete_port = {
	"Notify on delete port",
	"Don't notify on delete port"
};

static int hf_spoolss_rffpcnex_flags_add_print_processor = -1;
static int hf_spoolss_rffpcnex_flags_delete_print_processor = -1;

static const true_false_string tfs_rffpcnex_flags_add_print_processor = {
	"Notify on add driver",
	"Don't notify on add driver"
};

static const true_false_string tfs_rffpcnex_flags_delete_print_processor = {
	"Notify on add driver",
	"Don't notify on add driver"
};

static int hf_spoolss_rffpcnex_flags_add_driver = -1;
static int hf_spoolss_rffpcnex_flags_set_driver = -1;
static int hf_spoolss_rffpcnex_flags_delete_driver = -1;

static const true_false_string tfs_rffpcnex_flags_add_driver = {
	"Notify on add driver",
	"Don't notify on add driver"
};

static const true_false_string tfs_rffpcnex_flags_set_driver = {
	"Notify on set driver",
	"Don't notify on set driver"
};

static const true_false_string tfs_rffpcnex_flags_delete_driver = {
	"Notify on delete driver",
	"Don't notify on delete driver"
};

static int hf_spoolss_rffpcnex_flags_timeout = -1;

static const true_false_string tfs_rffpcnex_flags_timeout = {
	"Notify on timeout",
	"Don't notify on timeout"
};

static int SpoolssRFFPCNEX_q(tvbuff_t *tvb, int offset,
			     packet_info *pinfo, proto_tree *tree,
			     char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 flags;
	proto_item *flags_item;
	proto_tree *flags_subtree;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_spoolss_hnd, NULL, FALSE, FALSE);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, drep,
				    hf_spoolss_rffpcnex_flags, &flags);

	flags_item = proto_tree_add_text(tree, tvb, offset - 4, 4,
					 "Flags: 0x%08x", flags);

	flags_subtree = proto_item_add_subtree(flags_item, ett_rffpcnex_flags);

	proto_tree_add_boolean(
		flags_subtree, hf_spoolss_rffpcnex_flags_timeout, tvb,
		offset - 4, 4, flags);

	proto_tree_add_boolean(
		flags_subtree, hf_spoolss_rffpcnex_flags_delete_driver, tvb,
		offset - 4, 4, flags);

	proto_tree_add_boolean(
		flags_subtree, hf_spoolss_rffpcnex_flags_set_driver, tvb,
		offset - 4, 4, flags);

	proto_tree_add_boolean(
		flags_subtree, hf_spoolss_rffpcnex_flags_add_driver, tvb,
		offset - 4, 4, flags);

	proto_tree_add_boolean(
		flags_subtree,
		hf_spoolss_rffpcnex_flags_delete_print_processor, tvb,
		offset - 4, 4, flags);

	proto_tree_add_boolean(
		flags_subtree, hf_spoolss_rffpcnex_flags_add_print_processor,
		tvb, offset - 4, 4, flags);

	proto_tree_add_boolean(
		flags_subtree, hf_spoolss_rffpcnex_flags_delete_port, tvb,
		offset - 4, 4, flags);

	proto_tree_add_boolean(
		flags_subtree, hf_spoolss_rffpcnex_flags_configure_port, tvb,
		offset - 4, 4, flags);

	proto_tree_add_boolean(
		flags_subtree, hf_spoolss_rffpcnex_flags_add_port, tvb,
		offset - 4, 4, flags);

	proto_tree_add_boolean(
		flags_subtree, hf_spoolss_rffpcnex_flags_delete_form, tvb,
		offset - 4, 4, flags);

	proto_tree_add_boolean(
		flags_subtree, hf_spoolss_rffpcnex_flags_set_form, tvb,
		offset - 4, 4, flags);

	proto_tree_add_boolean(
		flags_subtree, hf_spoolss_rffpcnex_flags_add_form, tvb,
		offset - 4, 4, flags);

	proto_tree_add_boolean(
		flags_subtree, hf_spoolss_rffpcnex_flags_write_job, tvb,
		offset - 4, 4, flags);

	proto_tree_add_boolean(
		flags_subtree, hf_spoolss_rffpcnex_flags_delete_job, tvb,
		offset - 4, 4, flags);

	proto_tree_add_boolean(
		flags_subtree, hf_spoolss_rffpcnex_flags_set_job, tvb,
		offset - 4, 4, flags);

	proto_tree_add_boolean(
		flags_subtree, hf_spoolss_rffpcnex_flags_add_job, tvb,
		offset - 4, 4, flags);

	proto_tree_add_boolean(
		flags_subtree,
		hf_spoolss_rffpcnex_flags_failed_printer_connection, tvb,
		offset - 4, 4, flags);

	proto_tree_add_boolean(
		flags_subtree, hf_spoolss_rffpcnex_flags_delete_printer, tvb,
		offset - 4, 4, flags);

	proto_tree_add_boolean(
		flags_subtree, hf_spoolss_rffpcnex_flags_set_printer, tvb,
		offset - 4, 4, flags);

	proto_tree_add_boolean(
		flags_subtree, hf_spoolss_rffpcnex_flags_add_printer, tvb,
		offset - 4, 4, flags);

	if (flags & SPOOLSS_PRINTER_CHANGE_PRINTER)
		proto_item_append_text(flags_item, ", change printer");

	if (flags & SPOOLSS_PRINTER_CHANGE_JOB)
		proto_item_append_text(flags_item, ", change job");

	if (flags & SPOOLSS_PRINTER_CHANGE_FORM)
		proto_item_append_text(flags_item, ", change form");

	if (flags & SPOOLSS_PRINTER_CHANGE_PORT)
		proto_item_append_text(flags_item, ", change port");

	if (flags & SPOOLSS_PRINTER_CHANGE_PRINTER_DRIVER)
		proto_item_append_text(flags_item, ", change printer driver");

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_rffpcnex_options, NULL);

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"Server", hf_spoolss_servername, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_printerlocal, NULL);

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, tree, drep,
		dissect_NOTIFY_OPTIONS_ARRAY_CTR, NDR_POINTER_UNIQUE,
		"NOTIFY_OPTIONS_CTR", -1, 0);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssRFFPCNEX_r(tvbuff_t *tvb, int offset,
			     packet_info *pinfo, proto_tree *tree,
			     char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * SpoolssReplyOpenPrinter
 */

static int SpoolssReplyOpenPrinter_q(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 printerlocal;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

 	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
 					  prs_UNISTR2_dp, NULL, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_printerlocal, &printerlocal);

	dcv->private_data = (void *)printerlocal;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_printerdata_type, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_replyopenprinter_unk0, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_replyopenprinter_unk1, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssReplyOpenPrinter_r(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	e_ctx_hnd policy_hnd;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_spoolss_hnd, &policy_hnd,
				       TRUE, FALSE);

	dcerpc_smb_store_pol_name(&policy_hnd, "ReplyOpenPrinter handle");

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * BUFFER_DATA
 */

static gint ett_BUFFER_DATA = -1;
static gint ett_BUFFER_DATA_BUFFER = -1;

struct BUFFER_DATA {
	proto_item *item;	/* proto_item holding proto_tree */
	proto_tree *tree;	/* proto_tree holding buffer data */
	tvbuff_t *tvb;
	int offset;		/* Offset where data starts in tvb*/
	int size;		/* Size of buffer data */
};

static int prs_BUFFER_DATA(tvbuff_t *tvb, int offset, packet_info *pinfo,
			   proto_tree *tree, GList **dp_list _U_, void **data)
{
	proto_item *item, *subitem;
	proto_tree *subtree, *subsubtree;
	guint32 size;
	int data8_offset;

	item = proto_tree_add_text(tree, tvb, offset, 0, "BUFFER_DATA");

	subtree = proto_item_add_subtree(item, ett_BUFFER_DATA);

	offset = prs_uint32(tvb, offset, pinfo, subtree, &size, "Size");

	subitem = proto_tree_add_text(subtree, tvb, offset, size, "Data");

	subsubtree = proto_item_add_subtree(subitem, ett_BUFFER_DATA_BUFFER);

	offset = prs_uint8s(tvb, offset, pinfo, subsubtree, size,
			    &data8_offset, NULL);

	/* Return some info which will help the caller "cast" the buffer
	   data and dissect it further. */

	if (data) {
		struct BUFFER_DATA *bd;

		bd = (struct BUFFER_DATA *)malloc(sizeof(struct BUFFER_DATA));

		bd->item = subitem;
		bd->tree = subsubtree;
		bd->tvb = tvb;
		bd->offset = data8_offset;
		bd->size = size;

		*data = bd;
	}

	return offset;
}

/*
 * BUFFER
 */

static gint ett_BUFFER = -1;

static int prs_BUFFER(tvbuff_t *tvb, int offset, packet_info *pinfo,
		      proto_tree *tree, GList **dp_list, void **data _U_)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 ptr = 0;

	item = proto_tree_add_text(tree, tvb, offset, 0, "BUFFER");

	subtree = proto_item_add_subtree(item, ett_BUFFER);

	offset = prs_ptr(tvb, offset, pinfo, subtree, &ptr, "Data");

	if (ptr)
		defer_ptr(dp_list, prs_BUFFER_DATA, subtree);

	return offset;
}

/*
 * SpoolssGetPrinter
 */

static int SpoolssGetPrinter_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			       proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 level;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep, hf_spoolss_hnd, NULL,
		FALSE, FALSE);

	offset = prs_uint32(tvb, offset, pinfo, tree, &level, "Level");

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_BUFFER, NULL, NULL);

	dcv->private_data = (void *)level;

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Offered");

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssGetPrinter_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
				proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	GList *dp_list = NULL;
	void **data_list;
	struct BUFFER_DATA *bd = NULL;
	gint16 level = (guint32)dcv->private_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	/* Parse packet */

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_BUFFER, NULL, &data_list);

	if (data_list)
		bd = (struct BUFFER_DATA *)data_list[0];

	if (bd && bd->tree) {
		proto_item_append_text(bd->item, ", PRINTER_INFO_%d", level);

		switch (level) {
		case 0:
			prs_PRINTER_INFO_0(bd->tvb, bd->offset, pinfo,
					   bd->tree, &dp_list, NULL);
			break;

		case 1:
			prs_PRINTER_INFO_1(bd->tvb, bd->offset, pinfo,
					   bd->tree, &dp_list, NULL);
			break;

		case 2:
			prs_PRINTER_INFO_2(bd->tvb, bd->offset, pinfo,
					   bd->tree, bd->size, &dp_list, NULL);
			break;

		case 3:
			prs_PRINTER_INFO_3(bd->tvb, bd->offset, pinfo,
					   bd->tree, bd->size, &dp_list, NULL);
			break;

		default:
			proto_tree_add_text(bd->tree, tvb, offset, 0,
					    "[Unknown info level %d]", level);
			break;
		}
	}

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Needed");

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * SEC_DESC_BUF
 */

static gint ett_SEC_DESC_BUF = -1;

static int prs_SEC_DESC_BUF(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, GList **dp_list _U_,
			    void **Data _U_)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 len;

	item = proto_tree_add_text(tree, tvb, offset, 0, "SEC_DESC_BUF");

	subtree = proto_item_add_subtree(item, ett_SEC_DESC_BUF);

	offset = prs_uint32(tvb, offset, pinfo, subtree, &len, "Max length");
	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Undocumented");
	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Length");

	dissect_nt_sec_desc(tvb, offset, subtree, len);

	offset += len;

	return offset;
}

/*
 * SPOOL_PRINTER_INFO_LEVEL
 */

static gint ett_SPOOL_PRINTER_INFO_LEVEL = -1;

static int prs_SPOOL_PRINTER_INFO_LEVEL(tvbuff_t *tvb, int offset,
					packet_info *pinfo, proto_tree *tree,
					GList **dp_list, void **data _U_)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 level;

	item = proto_tree_add_text(tree, tvb, offset, 0,
				   "SPOOL_PRINTER_INFO_LEVEL");

	subtree = proto_item_add_subtree(item, ett_SPOOL_PRINTER_INFO_LEVEL);

	offset = prs_uint32(tvb, offset, pinfo, subtree, &level, "Level");

	switch(level) {
	case 3: {
		guint32 ptr;

		offset = prs_ptr(tvb, offset, pinfo, subtree, &ptr,
				 "Devicemode container");

		if (ptr)
			defer_ptr(dp_list, prs_DEVMODE_CTR, subtree);

		offset = prs_ptr(tvb, offset, pinfo, subtree, &ptr,
				 "Security descriptor");

		if (ptr)
			defer_ptr(dp_list, prs_SEC_DESC_BUF, subtree);

		break;
	}
	case 2: {
		guint32 ptr;

		offset = prs_ptr(tvb, offset, pinfo, subtree, &ptr, "Info");

		/* Sigh - dissecting a PRINTER_INFO_2 is currently
		   broken.  Hopefully this will be fixed when these
		   routines are converted to the NDR parsing functions
		   used by all the other DCERPC dissectors. */

#if 0
		if (ptr)
			defer_ptr(dp_list, prs_PRINTER_INFO_2, subtree);
#endif

		break;
	}
	default:
		proto_tree_add_text(subtree, tvb, offset, 0,
				    "[Unknown info level %d]", level);
		break;
	}

	return offset;
}

/*
 * SpoolssSetPrinter
 */

static int SpoolssSetPrinter_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			       proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 level;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep, hf_spoolss_hnd, NULL,
		FALSE, FALSE);

	offset = prs_uint32(tvb, offset, pinfo, tree, &level, "Level");

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_SPOOL_PRINTER_INFO_LEVEL,
					  NULL, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_spoolss_setprinter_cmd, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssSetPrinter_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
				proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * FORM_REL
 */

static const value_string form_type_vals[] =
{
	{ SPOOLSS_FORM_USER, "User" },
	{ SPOOLSS_FORM_BUILTIN, "Builtin" },
	{ SPOOLSS_FORM_PRINTER, "Printer" },
	{ 0, NULL }
};

static gint ett_FORM_REL = -1;

static int dissect_FORM_REL(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, char *drep, int struct_start)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 flags;
	int item_start = offset;

	item = proto_tree_add_text(tree, tvb, offset, 0, "FORM_REL");

	subtree = proto_item_add_subtree(item, ett_FORM_REL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, NULL, drep,
		hf_spoolss_form_flags, &flags);

	proto_tree_add_text(subtree, tvb, offset - 4, 4, "Flags: %s",
			    val_to_str(flags, form_type_vals, "Unknown (%d)"));

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, drep, hf_spoolss_form_name,
		struct_start, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, drep,
		hf_spoolss_form_width, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, drep,
		hf_spoolss_form_height, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, drep,
		hf_spoolss_form_left_margin, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, drep,
		hf_spoolss_form_top_margin, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, drep,
		hf_spoolss_form_horiz_len, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, drep,
		hf_spoolss_form_vert_len, NULL);

	proto_item_set_len(item, offset - item_start);

	return offset;
}

/*
 * SpoolssEnumForms
 */

static int SpoolssEnumForms_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			      proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 level;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep, hf_spoolss_hnd, NULL,
		FALSE, FALSE);

	offset = prs_uint32(tvb, offset, pinfo, tree, &level, "Level");

	dcv->private_data = (void *)level;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_BUFFER, NULL, NULL);

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Offered");

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssEnumForms_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			      proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	BUFFER buffer;
	guint32 level = (guint32)dcv->private_data, i, count;
	int buffer_offset;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_spoolss_buffer(
		tvb, offset, pinfo, tree, drep, &buffer);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_spoolss_needed, NULL);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_spoolss_enumforms_num, &count);

	/* Unfortunately this array isn't in NDR format so we can't
	   use prs_array().  The other weird thing is the
	   struct_start being inside the loop rather than outside.
	   Very strange. */

	buffer_offset = buffer.offset;

	for (i = 0; i < count; i++) {
		int struct_start = buffer.offset;

		buffer_offset = dissect_FORM_REL(
			tvb, buffer_offset, pinfo, buffer.tree, drep,
			struct_start);
	}

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * SpoolssDeletePrinter
 */

static int SpoolssDeletePrinter_q(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep, hf_spoolss_hnd, NULL,
		FALSE, FALSE);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssDeletePrinter_r(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep, hf_spoolss_hnd, NULL,
		FALSE, FALSE);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * AddPrinterEx
 */
#if 0
static int SpoolssAddPrinterEx_q(tvbuff_t *tvb, int offset,
                                 packet_info *pinfo, proto_tree *tree,
                                 char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 ptr;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = prs_ptr(tvb, offset, pinfo, tree, &ptr, "Server name");

	if (ptr) {
		char *printer_name;

		offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
						  prs_UNISTR2_dp,
						  (void *)&printer_name, NULL);

		if (printer_name)
			dcv->private_data = printer_name;
	}

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Level");

	/* TODO: PRINTER INFO LEVEL */

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "User switch");

	/* TODO: USER LEVEL */

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}
#endif
static int SpoolssAddPrinterEx_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
				 proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	e_ctx_hnd policy_hnd;
	guint32 status;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep, hf_spoolss_hnd, &policy_hnd,
		TRUE, FALSE);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, &status);

	if (status == 0) {

		/* Associate the returned printer handle with a name */

		if (dcv->private_data) {

			if (check_col(pinfo->cinfo, COL_INFO))
				col_append_fstr(
					pinfo->cinfo, COL_INFO, ", %s",
					(char *)dcv->private_data);

			dcerpc_smb_store_pol_name(
				&policy_hnd, dcv->private_data);

			g_free(dcv->private_data);
			dcv->private_data = NULL;
		}
	}

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * SpoolssEnumPrinterData
 */

static int SpoolssEnumPrinterData_q(tvbuff_t *tvb, int offset,
				    packet_info *pinfo, proto_tree *tree,
				    char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 ndx;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep, hf_spoolss_hnd, NULL,
		FALSE, FALSE);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_enumprinterdata_index, &ndx);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", index %d", ndx);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_enumprinterdata_value_offered, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_enumprinterdata_data_offered, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssEnumPrinterData_r(tvbuff_t *tvb, int offset,
				    packet_info *pinfo, proto_tree *tree,
				    char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 value_size;
	proto_item *value_item;
	proto_tree *value_subtree;
	int uint16s_offset;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	value_item = proto_tree_add_text(tree, tvb, offset, 0, "Value");

	value_subtree = proto_item_add_subtree(value_item, ett_printerdata_value);

	offset = prs_uint32(tvb, offset, pinfo, value_subtree, &value_size,
			    "Value size");

	offset = prs_uint16s(tvb, offset, pinfo, value_subtree, value_size,
			     &uint16s_offset, NULL);

	if (value_size) {
		char *text = fake_unicode(tvb, uint16s_offset, value_size);

		proto_tree_add_text(value_subtree, tvb, uint16s_offset,
				    value_size * 2, "Value: %s", text);

		proto_item_append_text(value_item, ": %s", text);

		if (text[0] && check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", text);

		g_free(text);
	}

	proto_item_set_len(value_item, value_size * 2 + 4);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_enumprinterdata_value_needed, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_printerdata_type, NULL);

	offset = dissect_printerdata_data(tvb, offset, pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_enumprinterdata_data_needed, NULL);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * SpoolssEnumPrinters
 */

static gint ett_enumprinters_flags = -1;

static int hf_enumprinters_flags_local = -1;
static int hf_enumprinters_flags_name = -1;
static int hf_enumprinters_flags_shared = -1;
static int hf_enumprinters_flags_default = -1;
static int hf_enumprinters_flags_connections = -1;
static int hf_enumprinters_flags_network = -1;
static int hf_enumprinters_flags_remote = -1;

static int SpoolssEnumPrinters_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
				 proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 ptr, level, flags;
	proto_tree *flags_subtree;
	proto_item *flags_item;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = prs_uint32(tvb, offset, pinfo, NULL, &flags, "Flags");

	flags_item = proto_tree_add_text(tree, tvb, offset - 4, 4,
					 "Flags: 0x%08x", flags);

	flags_subtree = proto_item_add_subtree(
		flags_item, ett_enumprinters_flags);

	proto_tree_add_boolean(
		flags_subtree, hf_enumprinters_flags_network, tvb,
		offset - 4, 4, flags);

	proto_tree_add_boolean(
		flags_subtree, hf_enumprinters_flags_shared, tvb,
		offset - 4, 4, flags);

	proto_tree_add_boolean(
		flags_subtree, hf_enumprinters_flags_remote, tvb,
		offset - 4, 4, flags);

	proto_tree_add_boolean(
		flags_subtree, hf_enumprinters_flags_name, tvb,
		offset - 4, 4, flags);

	proto_tree_add_boolean(
		flags_subtree, hf_enumprinters_flags_connections, tvb,
		offset - 4, 4, flags);

	proto_tree_add_boolean(
		flags_subtree, hf_enumprinters_flags_local, tvb,
		offset - 4, 4, flags);

	proto_tree_add_boolean(
		flags_subtree, hf_enumprinters_flags_default, tvb,
		offset - 4, 4, flags);

	offset = prs_ptr(tvb, offset, pinfo, tree, &ptr, "Name");

	if (ptr)
		offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
						  prs_UNISTR2_dp, NULL, NULL);

	offset = prs_uint32(tvb, offset, pinfo, tree, &level, "Level");

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level, %d", level);

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_BUFFER, NULL, NULL);

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Offered");

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssEnumPrinters_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
				 proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_BUFFER, NULL, NULL);

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Needed");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Returned");

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * AddPrinterDriver
 */
#if 0
static int SpoolssAddPrinterDriver_q(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"Server", hf_spoolss_servername, 0);

	offset = dissect_spoolss_DRIVER_INFO_CTR(
		tvb, offset, pinfo, tree, drep);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}
#endif
static int SpoolssAddPrinterDriver_r(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * FORM_1
 */

static gint ett_FORM_1 = -1;

static int dissect_FORM_1(tvbuff_t *tvb, int offset, packet_info *pinfo,
			  proto_tree *tree, char *drep)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 flags;

	item = proto_tree_add_text(tree, tvb, offset, 0, "FORM_1");

	subtree = proto_item_add_subtree(item, ett_FORM_1);

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, subtree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"Name", hf_spoolss_form_name, 0);

	/* Eek - we need to know whether this pointer was NULL or not.
	   Currently there is not any way to do this. */

	if (tvb_length_remaining(tvb, offset) == 0)
		goto done;

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, NULL, drep,
		hf_spoolss_form_flags, &flags);

	proto_tree_add_text(subtree, tvb, offset - 4, 4, "Flags: %s",
			    val_to_str(flags, form_type_vals, "Unknown (%d)"));

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, drep,
		hf_spoolss_form_unknown, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, drep,
		hf_spoolss_form_width, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, drep,
		hf_spoolss_form_height, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, drep,
		hf_spoolss_form_left_margin, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, drep,
		hf_spoolss_form_top_margin, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, drep,
		hf_spoolss_form_horiz_len, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, drep,
		hf_spoolss_form_vert_len, NULL);

 done:
	return offset;
}

/*
 * FORM_CTR
 */

static gint ett_FORM_CTR = -1;

static int dissect_FORM_CTR(tvbuff_t *tvb, int offset,
			    packet_info *pinfo, proto_tree *tree,
			    char *drep)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 level;

	item = proto_tree_add_text(tree, tvb, offset, 0, "FORM_CTR");

	subtree = proto_item_add_subtree(item, ett_FORM_CTR);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, drep,
		hf_spoolss_form_level, &level);

	switch(level) {
	case 1:
		offset = dissect_FORM_1(tvb, offset, pinfo, subtree, drep);
		break;

	default:
		proto_tree_add_text(subtree, tvb, offset, 0,
				    "[Unknown info level %d]", level);
		break;
	}

	return offset;
}

/* Form name - this is actually a unistr2 without the pointer */

static int dissect_form_name(tvbuff_t *tvb, int offset, packet_info *pinfo,
			     proto_tree *tree, char *drep)
{
	extern int hf_nt_str_len;
	extern int hf_nt_str_off;
	extern int hf_nt_str_max_len;
	guint32 len;

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_nt_str_max_len, NULL);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_nt_str_off, NULL);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_nt_str_len, &len);

	offset = dissect_ndr_uint16s(
		tvb, offset, pinfo, tree, drep,
		hf_spoolss_form_name, len, NULL);

	return offset;
}


/*
 * AddForm
 */

static int SpoolssAddForm_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 level;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep, hf_spoolss_hnd, NULL,
		FALSE, FALSE);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_spoolss_addform_level, &level);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	/* Store info level to match with reply packet */

	dcv->private_data = (void *)level;

	offset = dissect_FORM_CTR(tvb, offset, pinfo, tree, drep);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssAddForm_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * DeleteForm
 */

static int SpoolssDeleteForm_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			       proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep, hf_spoolss_hnd, NULL,
		FALSE, FALSE);

	offset = dissect_form_name(
		tvb, offset, pinfo, tree, drep);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssDeleteForm_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * SetForm
 */

static int SpoolssSetForm_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 level;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep, hf_spoolss_hnd, NULL,
		FALSE, FALSE);

	offset = dissect_form_name(
		tvb, offset, pinfo, tree, drep);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_spoolss_setform_level, &level);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	offset = dissect_FORM_CTR(tvb, offset, pinfo, tree, drep);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssSetForm_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * GetForm
 */

static int SpoolssGetForm_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 level;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep, hf_spoolss_hnd, NULL,
		FALSE, FALSE);

	offset = dissect_form_name(
		tvb, offset, pinfo, tree, drep);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_spoolss_getform_level, &level);

	dcv->private_data = (void *)level;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d",
				level);

	offset = dissect_spoolss_buffer(tvb, offset, pinfo, tree, drep, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_spoolss_offered, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssGetForm_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	BUFFER buffer;
	int buffer_offset;
	guint32 level = (guint32)dcv->private_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_spoolss_buffer(
		tvb, offset, pinfo, tree, drep, &buffer);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_spoolss_needed, NULL);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	if (!buffer.size)
		goto done;

	buffer_offset = buffer.offset;

	switch(level) {
	case 1: {
		int struct_start = buffer.offset;

		buffer_offset = dissect_FORM_REL(
			tvb, buffer_offset, pinfo, tree, drep, struct_start);
		break;
	}

	default:
		proto_tree_add_text(
			buffer.tree, tvb, buffer_offset, buffer.size,
			"[Unknown info level %d]", level);
		goto done;
	}

 done:
	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/* A generic reply function that just parses the status code.  Useful for
   unimplemented dissectors so the status code can be inserted into the
   INFO column. */

static int SpoolssGeneric_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	int len = tvb_length(tvb);

	proto_tree_add_text(tree, tvb, offset, 0,
			    "[Unimplemented dissector: SPOOLSS]");

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	offset = dissect_doserror(tvb, len - 4, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	return offset;
}

/*
 * SYSTEM_TIME
 */

static gint ett_SYSTEM_TIME;

static int
dissect_SYSTEM_TIME(tvbuff_t *tvb, int offset, packet_info *pinfo,
		    proto_tree *tree, char *drep)
{
	proto_item *item;
	proto_tree *subtree;
	guint16 year, month, day, hour, minute, second;

	item = proto_tree_add_text(tree, tvb, offset, 16, "SYSTEM_TIME: ");

	subtree = proto_item_add_subtree(item, ett_SYSTEM_TIME);

	offset = dissect_ndr_uint16 (tvb, offset, pinfo, subtree, drep,
				     hf_spoolss_time_year, &year);

	offset = dissect_ndr_uint16 (tvb, offset, pinfo, subtree, drep,
				     hf_spoolss_time_month, &month);

	offset = dissect_ndr_uint16 (tvb, offset, pinfo, subtree, drep,
				     hf_spoolss_time_dow, NULL);

	offset = dissect_ndr_uint16 (tvb, offset, pinfo, subtree, drep,
				     hf_spoolss_time_day, &day);

	offset = dissect_ndr_uint16 (tvb, offset, pinfo, subtree, drep,
				     hf_spoolss_time_hour, &hour);

	offset = dissect_ndr_uint16 (tvb, offset, pinfo, subtree, drep,
				     hf_spoolss_time_minute, &minute);

	offset = dissect_ndr_uint16 (tvb, offset, pinfo, subtree, drep,
				     hf_spoolss_time_second, &second);

	offset = dissect_ndr_uint16 (tvb, offset, pinfo, subtree, drep,
				     hf_spoolss_time_msec, NULL);

	proto_item_append_text(item, "%d/%02d/%02d %02d:%02d:%02d", year,
			       month, day, hour, minute, second);

	return offset;
}

/*
 * JOB_INFO_1
 */

static gint ett_JOB_INFO_1;

static int
dissect_spoolss_JOB_INFO_1(tvbuff_t *tvb, int offset, packet_info *pinfo,
			   proto_tree *tree, char *drep)
{
	proto_item *item;
	proto_tree *subtree;
	int struct_start = offset;
	char *document_name;

	item = proto_tree_add_text(tree, tvb, offset, 0, "JOB_INFO_1");

	subtree = proto_item_add_subtree(item, ett_JOB_INFO_1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, drep,
				    hf_spoolss_jobid, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, drep, hf_spoolss_printername,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, drep, hf_spoolss_servername,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, drep, hf_spoolss_username,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, drep, hf_spoolss_documentname,
		struct_start, &document_name);

	proto_item_append_text(item, ": %s", document_name);
	g_free(document_name);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, drep, hf_spoolss_datatype,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, drep, hf_spoolss_textstatus,
		struct_start, NULL);

	offset = dissect_job_status(tvb, offset, pinfo, subtree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, drep,
				    hf_spoolss_jobpriority, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, drep,
				    hf_spoolss_jobposition, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, drep,
				    hf_spoolss_jobtotalpages, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, drep,
				    hf_spoolss_jobpagesprinted, NULL);

	offset = dissect_SYSTEM_TIME(tvb, offset, pinfo, subtree, drep);

	proto_item_set_len(item, offset - struct_start);

	return offset;
}

/*
 * JOB_INFO_2
 */

static gint ett_JOB_INFO_2;

#if 0

static int prs_JOB_INFO_2(tvbuff_t *tvb, int offset, packet_info *pinfo,
			  proto_tree *tree, GList **dp_list, void **data)
{
	proto_item *item;
	proto_tree *subtree;
	int struct_start = offset;
	guint32 rel_offset;

	item = proto_tree_add_text(tree, tvb, offset, 0, "JOB_INFO_2");

	subtree = proto_item_add_subtree(item, ett_FORM_CTR);

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Job ID");

	offset = prs_relstr(tvb, offset, pinfo, subtree, dp_list, struct_start,
			    NULL, "Printer name");

	offset = prs_relstr(tvb, offset, pinfo, subtree, dp_list, struct_start,
			    NULL, "Machine name");

	offset = prs_relstr(tvb, offset, pinfo, subtree, dp_list, struct_start,
			    NULL, "User name");

	offset = prs_relstr(tvb, offset, pinfo, subtree, dp_list, struct_start,
			    NULL, "Document");

	offset = prs_relstr(tvb, offset, pinfo, subtree, dp_list, struct_start,
			    NULL, "Notify name");

	offset = prs_relstr(tvb, offset, pinfo, subtree, dp_list, struct_start,
			    NULL, "Data type");

	offset = prs_relstr(tvb, offset, pinfo, subtree, dp_list, struct_start,
			    NULL, "Print processor");

	offset = prs_relstr(tvb, offset, pinfo, subtree, dp_list, struct_start,
			    NULL, "Parameters");

	offset = prs_relstr(tvb, offset, pinfo, subtree, dp_list, struct_start,
			    NULL, "Driver name");

	offset = prs_uint32(tvb, offset, pinfo, tree, &rel_offset, NULL);

	prs_DEVMODE(tvb, struct_start + rel_offset - 4, pinfo, tree,
		    dp_list, NULL);

	/* XXX security descriptor */

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Security descriptor");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Status");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Priority");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Position");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Start time");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Until time");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Total pages");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Size");

	offset = prs_struct_and_referents(tvb, offset, pinfo, subtree,
					  prs_SYSTEM_TIME, NULL, NULL);

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Time elapsed");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Pages printed");

	return offset;
}

#endif

/*
 * EnumJobs
 */

static int SpoolssEnumJobs_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			     proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 level;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %d", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_spoolss_hnd, NULL,
				       FALSE, FALSE);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_enumjobs_firstjob, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_enumjobs_numjobs, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_level, &level);

	dcv->private_data = (void *)level;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	offset = dissect_spoolss_buffer(tvb, offset, pinfo, tree, drep, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_spoolss_offered, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssEnumJobs_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			     proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	gint16 level = (guint32)dcv->private_data;
	BUFFER buffer;
	guint32 num_jobs, i;
	int buffer_offset;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %d", dcv->req_frame);

	/* Parse packet */

	offset = dissect_spoolss_buffer(tvb, offset, pinfo, tree, drep,
					&buffer);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_spoolss_needed, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_enumjobs_numjobs, &num_jobs);

	buffer_offset = buffer.offset;

	for (i = 0; i < num_jobs; i++) {
		switch(level) {
		case 1:
			buffer_offset = dissect_spoolss_JOB_INFO_1(
				tvb, buffer_offset, pinfo, buffer.tree, drep);
			break;
		case 2:
		default:
			proto_tree_add_text(
				buffer.tree, tvb, buffer_offset, buffer.size,
				"[Unknown info level %d]", level);
			goto done;
		}

	}

done:
	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * SetJob
 */

/* Set job command values */

#define JOB_CONTROL_PAUSE              1
#define JOB_CONTROL_RESUME             2
#define JOB_CONTROL_CANCEL             3
#define JOB_CONTROL_RESTART            4
#define JOB_CONTROL_DELETE             5

static const value_string setjob_commands[] = {
	{ JOB_CONTROL_PAUSE, "Pause" },
	{ JOB_CONTROL_RESUME, "Resume" },
	{ JOB_CONTROL_CANCEL, "Cancel" },
	{ JOB_CONTROL_RESTART, "Restart" },
	{ JOB_CONTROL_DELETE, "Delete" },
	{ 0, NULL }
};

static int SpoolssSetJob_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			   proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 jobid, cmd;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_spoolss_hnd, NULL,
				       FALSE, FALSE);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_jobid, &jobid);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_level, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_setjob_cmd, &cmd);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(
			pinfo->cinfo, COL_INFO, ", %s jobid %d",
			val_to_str(cmd, setjob_commands, "Unknown (%d)"),
			jobid);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssSetJob_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			   proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * GetJob
 */

static int SpoolssGetJob_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			   proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 level, jobid;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_spoolss_hnd, NULL,
				       FALSE, FALSE);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_jobid, &jobid);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_level, &level);

	dcv->private_data = (void *)level;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d, jobid %d",
				level, jobid);

	offset = dissect_spoolss_buffer(tvb, offset, pinfo, tree, drep, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_spoolss_offered, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssGetJob_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	gint32 level = (guint32)dcv->private_data;
	BUFFER buffer;
	int buffer_offset;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_spoolss_buffer(tvb, offset, pinfo, tree, drep,
					&buffer);

	if (!buffer.size)
		goto done;

	buffer_offset = buffer.offset;

	switch(level) {
	case 1:
		buffer_offset = dissect_spoolss_JOB_INFO_1(
			tvb, buffer_offset, pinfo, buffer.tree, drep);
		break;
	case 2:
	default:
		proto_tree_add_text(
			buffer.tree, tvb, buffer_offset, buffer.size,
			"[Unknown info level %d]", level);
		goto done;
	}

done:
	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_spoolss_needed, NULL);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * StartPagePrinter
 */

static int SpoolssStartPagePrinter_q(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	e_ctx_hnd policy_hnd;
	char *pol_name;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_spoolss_hnd, &policy_hnd,
				       FALSE, FALSE);

	dcerpc_smb_fetch_pol(&policy_hnd, &pol_name, NULL, NULL);

	if (check_col(pinfo->cinfo, COL_INFO) && pol_name)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
				pol_name);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssStartPagePrinter_r(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * EndPagePrinter
 */

static int SpoolssEndPagePrinter_q(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	e_ctx_hnd policy_hnd;
	char *pol_name;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_spoolss_hnd, &policy_hnd,
				       FALSE, FALSE);

	dcerpc_smb_fetch_pol(&policy_hnd, &pol_name, NULL, NULL);

	if (check_col(pinfo->cinfo, COL_INFO) && pol_name)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
				pol_name);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssEndPagePrinter_r(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * DOC_INFO_1
 */

static gint ett_DOC_INFO_1 = -1;

static int
dissect_spoolss_doc_info_1(tvbuff_t *tvb, int offset, packet_info *pinfo,
			   proto_tree *tree, char *drep)
{
	proto_item *item;
	proto_tree *subtree;

	item = proto_tree_add_text(tree, tvb, offset, 0, "DOC_INFO_1");

	subtree = proto_item_add_subtree(item, ett_DOC_INFO_1);

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, subtree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"Document name", hf_spoolss_documentname, 0);

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, subtree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"Output file", hf_spoolss_outputfile, 0);

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, subtree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"Data type", hf_spoolss_datatype, 0);

	return offset;
}

static int
dissect_spoolss_doc_info_data(tvbuff_t *tvb, int offset, packet_info *pinfo,
			      proto_tree *tree, char *drep)
{
	dcerpc_info *di = pinfo->private_data;

	if (di->conformant_run)
		return offset;

	switch(di->levels) {
	case 1:
		offset = dissect_spoolss_doc_info_1(
			tvb, offset, pinfo, tree, drep);
		break;
	default:
		proto_tree_add_text(tree, tvb, offset, 0,
				    "[Unknown info level %d]", di->levels);
		break;
	}

	return offset;
}

/*
 * DOC_INFO
 */

static gint ett_DOC_INFO = -1;

static int
dissect_spoolss_doc_info(tvbuff_t *tvb, int offset, packet_info *pinfo,
			 proto_tree *tree, char *drep)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 level;

	item = proto_tree_add_text(tree, tvb, offset, 0, "DOC_INFO");

	subtree = proto_item_add_subtree(item, ett_DOC_INFO);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, drep,
				    hf_spoolss_level, &level);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, subtree, drep,
				     dissect_spoolss_doc_info_data,
				     NDR_POINTER_UNIQUE, "Document info",
				     -1, level);
	return offset;
}

/*
 * DOC_INFO_CTR
 */

static gint ett_DOC_INFO_CTR = -1;

static int
dissect_spoolss_doc_info_ctr(tvbuff_t *tvb, int offset, packet_info *pinfo,
			     proto_tree *tree, char *drep)
{
	proto_item *item;
	proto_tree *subtree;

	item = proto_tree_add_text(tree, tvb, offset, 0, "DOC_INFO_CTR");

	subtree = proto_item_add_subtree(item, ett_DOC_INFO_CTR);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, drep,
				    hf_spoolss_level, NULL);

	offset = dissect_spoolss_doc_info(
		tvb, offset, pinfo, subtree, drep);

	return offset;
}

/*
 * StartDocPrinter
 */

static int SpoolssStartDocPrinter_q(tvbuff_t *tvb, int offset,
				    packet_info *pinfo, proto_tree *tree,
				    char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	e_ctx_hnd policy_hnd;
	char *pol_name;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_spoolss_hnd, &policy_hnd,
				       FALSE, FALSE);

	dcerpc_smb_fetch_pol(&policy_hnd, &pol_name, NULL, NULL);

	if (check_col(pinfo->cinfo, COL_INFO) && pol_name)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
				pol_name);

	offset = dissect_spoolss_doc_info_ctr(tvb, offset, pinfo, tree, drep);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssStartDocPrinter_r(tvbuff_t *tvb, int offset,
				    packet_info *pinfo, proto_tree *tree,
				    char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_jobid, NULL);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * EndDocPrinter
 */

static int SpoolssEndDocPrinter_q(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	e_ctx_hnd policy_hnd;
	char *pol_name;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_spoolss_hnd, &policy_hnd,
				       FALSE, FALSE);

	dcerpc_smb_fetch_pol(&policy_hnd, &pol_name, NULL, NULL);

	if (check_col(pinfo->cinfo, COL_INFO) && pol_name)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
				pol_name);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssEndDocPrinter_r(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * WritePrinter
 */

static gint ett_writeprinter_buffer = -1;

static int SpoolssWritePrinter_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
				 proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	e_ctx_hnd policy_hnd;
	char *pol_name;
	guint32 size;
	proto_item *item;
	proto_tree *subtree;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_spoolss_hnd, &policy_hnd,
				       FALSE, FALSE);

	dcerpc_smb_fetch_pol(&policy_hnd, &pol_name, NULL, NULL);

	if (check_col(pinfo->cinfo, COL_INFO) && pol_name)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
				pol_name);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_buffer_size, &size);

	item = proto_tree_add_text(tree, tvb, offset, 0, "Buffer");

	subtree = proto_item_add_subtree(item, ett_writeprinter_buffer);

	offset = dissect_ndr_uint8s(tvb, offset, pinfo, subtree, drep,
				    hf_spoolss_buffer_data, size, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, drep,
				    hf_spoolss_buffer_size, NULL);

	proto_item_set_len(item, size + 4);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssWritePrinter_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
				 proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_writeprinter_numwritten, NULL);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * DeletePrinterData
 */

static int SpoolssDeletePrinterData_q(tvbuff_t *tvb, int offset,
				      packet_info *pinfo, proto_tree *tree,
				      char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	char *value_name;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep, hf_spoolss_hnd, NULL,
		FALSE, FALSE);

 	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
 					  prs_UNISTR2_dp, (void **)&value_name,
 					  NULL);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", value_name);

	g_free(value_name);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssDeletePrinterData_r(tvbuff_t *tvb, int offset,
				      packet_info *pinfo, proto_tree *tree,
				      char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}


/*
 * DRIVER_INFO_1
 */

static gint ett_DRIVER_INFO_1 = -1;

static int dissect_DRIVER_INFO_1(tvbuff_t *tvb, int offset,
				 packet_info *pinfo, proto_tree *tree,
				 char *drep)
{
	proto_item *item;
	proto_tree *subtree;
	int struct_start = offset;

	item = proto_tree_add_text(tree, tvb, offset, 0, "DRIVER_INFO_1");

	subtree = proto_item_add_subtree(item, ett_DRIVER_INFO_1);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, drep, hf_spoolss_drivername,
		struct_start, NULL);

	return offset;
}

/*
 * DRIVER_INFO_3
 */

static const value_string driverinfo_cversion_vals[] =
{
	{ 0, "Windows 95/98/Me" },
	{ 2, "Windows NT 4.0" },
	{ 3, "Windows 2000/XP" },
	{ 0, NULL }
};

static gint ett_DRIVER_INFO_3 = -1;

static int dissect_DRIVER_INFO_3(tvbuff_t *tvb, int offset,
				 packet_info *pinfo, proto_tree *tree,
				 char *drep)
{
	proto_item *item;
	proto_tree *subtree;
	int struct_start = offset;

	item = proto_tree_add_text(tree, tvb, offset, 0, "DRIVER_INFO_3");

	subtree = proto_item_add_subtree(item, ett_DRIVER_INFO_3);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, drep,
				    hf_spoolss_driverinfo_cversion, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, drep, hf_spoolss_drivername,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, drep, hf_spoolss_architecture,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, drep, hf_spoolss_driverpath,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, drep, hf_spoolss_datafile,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, drep, hf_spoolss_configfile,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, drep, hf_spoolss_helpfile,
		struct_start, NULL);

	offset = dissect_spoolss_relstrarray(
		tvb, offset, pinfo, subtree, drep, hf_spoolss_dependentfiles,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, drep, hf_spoolss_monitorname,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, drep, hf_spoolss_defaultdatatype,
		struct_start, NULL);

	return offset;
}

/*
 * EnumPrinterDrivers
 */

static int SpoolssEnumPrinterDrivers_q(tvbuff_t *tvb, int offset,
				       packet_info *pinfo, proto_tree *tree,
				       char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 level;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"Name", hf_spoolss_servername, 0);

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"Environment", hf_spoolss_servername, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_level, &level);

	dcv->private_data = (void *)level;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	offset = dissect_spoolss_buffer(tvb, offset, pinfo, tree, drep, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_spoolss_offered, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssEnumPrinterDrivers_r(tvbuff_t *tvb, int offset,
				       packet_info *pinfo, proto_tree *tree,
				       char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 level = (guint32)dcv->private_data, num_drivers, i;
	int buffer_offset;
	BUFFER buffer;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_spoolss_buffer(tvb, offset, pinfo, tree, drep,
					&buffer);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_spoolss_needed, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_spoolss_returned, &num_drivers);

	buffer_offset = buffer.offset;

	for (i = 0; i < num_drivers; i++) {
		switch(level) {
		case 1:
			buffer_offset = dissect_DRIVER_INFO_1(
				tvb, buffer_offset, pinfo, buffer.tree, drep);
			break;
		case 3:
			buffer_offset = dissect_DRIVER_INFO_3(
				tvb, buffer_offset, pinfo, buffer.tree, drep);
			break;
		default:
			proto_tree_add_text(
				buffer.tree, tvb, buffer_offset, buffer.size,
				"[Unknown info level %d]", level);
			goto done;
		}
	}

done:
	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * GetPrinterDriver2
 */

static int SpoolssGetPrinterDriver2_q(tvbuff_t *tvb, int offset,
				      packet_info *pinfo, proto_tree *tree,
				      char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	e_ctx_hnd policy_hnd;
	char *pol_name;
	guint32 level;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep, hf_spoolss_hnd, &policy_hnd,
		FALSE, FALSE);

	dcerpc_smb_fetch_pol(&policy_hnd, &pol_name, NULL, NULL);

	if (check_col(pinfo->cinfo, COL_INFO) && pol_name)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
				pol_name);

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"Architecture", hf_spoolss_architecture, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_level, &level);

	dcv->private_data = (void *)level;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	offset = dissect_spoolss_buffer(tvb, offset, pinfo, tree, drep, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_spoolss_offered, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_clientmajorversion, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_clientminorversion, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssGetPrinterDriver2_r(tvbuff_t *tvb, int offset,
				      packet_info *pinfo, proto_tree *tree,
				      char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 level = (guint32)dcv->private_data;
	BUFFER buffer;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_spoolss_buffer(tvb, offset, pinfo, tree, drep,
					&buffer);

	switch(level) {
	case 1:
		dissect_DRIVER_INFO_1(
			tvb, buffer.offset, pinfo, buffer.tree, drep);
		break;
	case 3:
		dissect_DRIVER_INFO_3(
			tvb, buffer.offset, pinfo, buffer.tree, drep);
		break;
	default:
		proto_tree_add_text(
			buffer.tree, tvb, buffer.offset, buffer.size,
			"[Unknown info level %d]", level);
		break;
	}

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_spoolss_needed, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_servermajorversion, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_serverminorversion, NULL);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int
dissect_notify_info_data_buffer(tvbuff_t *tvb, int offset, packet_info *pinfo,
				proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	guint32 len = di->levels;

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_spoolss_notify_info_data_buffer_len, NULL);

	offset = dissect_ndr_uint16s(
		tvb, offset, pinfo, tree, drep,
		hf_spoolss_notify_info_data_buffer_data, len, NULL);

	return offset;
}

static int
dissect_NOTIFY_INFO_DATA_printer(tvbuff_t *tvb, int offset, packet_info *pinfo,
				 proto_tree *tree, char *drep, guint16 field)
{
	guint32 value1;

	switch (field) {

		/* String notify data */

	case PRINTER_NOTIFY_SERVER_NAME:
	case PRINTER_NOTIFY_PRINTER_NAME:
	case PRINTER_NOTIFY_SHARE_NAME:
	case PRINTER_NOTIFY_DRIVER_NAME:
	case PRINTER_NOTIFY_COMMENT:
	case PRINTER_NOTIFY_LOCATION:
	case PRINTER_NOTIFY_SEPFILE:
	case PRINTER_NOTIFY_PRINT_PROCESSOR:
	case PRINTER_NOTIFY_PARAMETERS:
	case PRINTER_NOTIFY_DATATYPE:
	case PRINTER_NOTIFY_PORT_NAME:

		offset = dissect_ndr_uint32(
			tvb, offset, pinfo, tree, drep,
			hf_spoolss_notify_info_data_bufsize, &value1);

		offset = dissect_ndr_pointer(
			tvb, offset, pinfo, tree, drep,
			dissect_notify_info_data_buffer,
			NDR_POINTER_UNIQUE, "String",
			hf_spoolss_notify_info_data_buffer, value1 / 2);

		break;

	case PRINTER_NOTIFY_ATTRIBUTES:

		/* Value 1 is the printer attributes */

		offset = dissect_printer_attributes(
			tvb, offset, pinfo, tree, drep);

		offset = dissect_ndr_uint32(
			tvb, offset, pinfo, NULL, drep,
			hf_spoolss_notify_info_data_value2, NULL);

		break;

	case PRINTER_NOTIFY_STATUS:

		/* Value 1 is the printer status */

		offset = dissect_ndr_uint32(
			tvb, offset, pinfo, tree, drep,
			hf_spoolss_printer_status, NULL);

		offset = dissect_ndr_uint32(
			tvb, offset, pinfo, NULL, drep,
			hf_spoolss_notify_info_data_value2, NULL);

		break;

		/* Unknown notify data */

	case PRINTER_NOTIFY_SECURITY_DESCRIPTOR: /* Secdesc */
	case PRINTER_NOTIFY_DEVMODE: /* Device mode */

		offset = dissect_ndr_uint32(
			tvb, offset, pinfo, tree, drep,
			hf_spoolss_notify_info_data_bufsize, &value1);

		offset = dissect_ndr_pointer(
			tvb, offset, pinfo, tree, drep,
			dissect_notify_info_data_buffer,
			NDR_POINTER_UNIQUE, "Buffer",
			hf_spoolss_notify_info_data_buffer, value1 / 2);

		break;

	default:
		offset = dissect_ndr_uint32(
			tvb, offset, pinfo, tree, drep,
			hf_spoolss_notify_info_data_value1, NULL);

		offset = dissect_ndr_uint32(
			tvb, offset, pinfo, tree, drep,
			hf_spoolss_notify_info_data_value2, NULL);

		break;
	}
	return offset;
}

static int
dissect_NOTIFY_INFO_DATA_job(tvbuff_t *tvb, int offset, packet_info *pinfo,
			     proto_tree *tree, char *drep, guint16 field)
{
	guint32 value1;

	switch (field) {

		/* String notify data */

	case JOB_NOTIFY_PRINTER_NAME:
	case JOB_NOTIFY_MACHINE_NAME:
	case JOB_NOTIFY_PORT_NAME:
	case JOB_NOTIFY_USER_NAME:
	case JOB_NOTIFY_NOTIFY_NAME:
	case JOB_NOTIFY_DATATYPE:
	case JOB_NOTIFY_PRINT_PROCESSOR:
	case JOB_NOTIFY_PARAMETERS:
	case JOB_NOTIFY_DRIVER_NAME:
	case JOB_NOTIFY_STATUS_STRING:
	case JOB_NOTIFY_DOCUMENT:

		offset = dissect_ndr_uint32(
			tvb, offset, pinfo, tree, drep,
			hf_spoolss_notify_info_data_bufsize, &value1);

		offset = dissect_ndr_pointer(
			tvb, offset, pinfo, tree, drep,
			dissect_notify_info_data_buffer,
			NDR_POINTER_UNIQUE, "String",
			hf_spoolss_notify_info_data_buffer, value1 / 2);

		break;

	case JOB_NOTIFY_STATUS:

		offset = dissect_job_status(
			tvb, offset, pinfo, tree, drep);

		offset = dissect_ndr_uint32(
			tvb, offset, pinfo, NULL, drep,
			hf_spoolss_notify_info_data_value2, NULL);

		break;

	case JOB_NOTIFY_SUBMITTED:

		/* SYSTEM_TIME */

		offset = dissect_ndr_uint32(
			tvb, offset, pinfo, tree, drep,
			hf_spoolss_notify_info_data_buffer_len, NULL);

		offset = dissect_ndr_pointer(
			tvb, offset, pinfo, tree, drep,
			dissect_SYSTEM_TIME, NDR_POINTER_UNIQUE,
			"SYSTEM_TIME", -1, 0);

		break;

		/* Unknown notify data */

	case JOB_NOTIFY_DEVMODE:

		offset = dissect_ndr_uint32(
			tvb, offset, pinfo, tree, drep,
			hf_spoolss_notify_info_data_bufsize, &value1);

		offset = dissect_ndr_pointer(
			tvb, offset, pinfo, tree, drep,
			dissect_notify_info_data_buffer,
			NDR_POINTER_UNIQUE, "Buffer",
			hf_spoolss_notify_info_data_buffer, value1 / 2);

		break;

	default:
		offset = dissect_ndr_uint32(
			tvb, offset, pinfo, tree, drep,
			hf_spoolss_notify_info_data_value1, NULL);

		offset = dissect_ndr_uint32(
			tvb, offset, pinfo, tree, drep,
			hf_spoolss_notify_info_data_value2, NULL);
	}
	return offset;
}

static gint ett_NOTIFY_INFO_DATA;

static int
dissect_NOTIFY_INFO_DATA(tvbuff_t *tvb, int offset, packet_info *pinfo,
			 proto_tree *tree, char *drep)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 count;
	guint16 type, field;
	char *field_string;

	item = proto_tree_add_text(tree, tvb, offset, 0, "NOTIFY_INFO_DATA");

	subtree = proto_item_add_subtree(item, ett_NOTIFY_INFO_DATA);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, subtree, drep,
		hf_spoolss_notify_info_data_type, &type);

	offset = dissect_notify_field(
		tvb, offset, pinfo, subtree, drep, type, &field);

	switch(type) {
	case PRINTER_NOTIFY_TYPE:
		field_string = val_to_str(
			field, printer_notify_option_data_vals, "Unknown (%d)");
		break;
	case JOB_NOTIFY_TYPE:
		field_string = val_to_str(
			field, job_notify_option_data_vals, "Unknown (%d)");
		break;
	default:
		field_string = "Unknown field";
		break;
	}

	proto_item_append_text(
		item, ": %s, %s",
		val_to_str(type, printer_notify_types, "Unknown (%d)"),
		field_string);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, drep,
		hf_spoolss_notify_info_data_count, &count);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, drep,
		hf_spoolss_notify_info_data_id, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, drep,
		hf_spoolss_notify_info_data_count, NULL);

	/* The value here depends on (type, field) */

	switch (type) {
	case PRINTER_NOTIFY_TYPE:
		offset = dissect_NOTIFY_INFO_DATA_printer(
			tvb, offset, pinfo, subtree, drep,
			field);
		break;
	case JOB_NOTIFY_TYPE:
		offset = dissect_NOTIFY_INFO_DATA_job(
			tvb, offset, pinfo, subtree, drep,
			field);
		break;
	default:
		proto_tree_add_text(
			tree, tvb, offset, 0,
			"[Unknown notify type %d]", type);
		break;
	}

	return offset;
}

static int
dissect_NOTIFY_INFO(tvbuff_t *tvb, int offset, packet_info *pinfo,
		    proto_tree *tree, char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_notify_info_version, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_notify_info_flags, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_notify_info_count, NULL);

	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
				     dissect_NOTIFY_INFO_DATA);

	return offset;
}

/*
 * RFNPCNEX
 */

static int SpoolssRFNPCNEX_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			     proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep, hf_spoolss_hnd, NULL,
		FALSE, FALSE);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_spoolss_rrpcn_changelow, NULL);

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, tree, drep,
		dissect_NOTIFY_OPTIONS_ARRAY_CTR, NDR_POINTER_UNIQUE,
		"NOTIFY_OPTIONS_ARRAY_CTR", -1, 0);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssRFNPCNEX_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			     proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, tree, drep,
		dissect_NOTIFY_INFO, NDR_POINTER_UNIQUE,
		"NOTIFY_INFO", -1, 0);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * RRPCN
 */

static int SpoolssRRPCN_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			  proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep, hf_spoolss_hnd, NULL,
		FALSE, FALSE);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_rrpcn_changelow, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_rrpcn_changehigh, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_rrpcn_unk0, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_rrpcn_unk1, NULL);

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, tree, drep,
		dissect_NOTIFY_INFO, NDR_POINTER_UNIQUE,
		"NOTIFY_INFO", -1, 0);

	/* Notify info */

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssRRPCN_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			  proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_rrpcn_unk0, NULL);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * ReplyClosePrinter
 */

static int SpoolssReplyClosePrinter_q(tvbuff_t *tvb, int offset,
				      packet_info *pinfo, proto_tree *tree,
				      char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_spoolss_hnd, NULL,
				       FALSE, TRUE);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssReplyClosePrinter_r(tvbuff_t *tvb, int offset,
				      packet_info *pinfo, proto_tree *tree,
				      char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_spoolss_hnd, NULL,
				       FALSE, FALSE);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * FCPN
 */

static int SpoolssFCPN_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_spoolss_hnd, NULL,
				       FALSE, FALSE);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssFCPN_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * RouterReplyPrinter
 */

static int SpoolssRouterReplyPrinter_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
				       proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_spoolss_hnd, NULL,
				       FALSE, FALSE);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_spoolss_routerreplyprinter_condition, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_spoolss_routerreplyprinter_unknown1, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_spoolss_routerreplyprinter_changeid, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssRouterReplyPrinter_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
				       proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int
dissect_spoolss_keybuffer(tvbuff_t *tvb, int offset, packet_info *pinfo,
			  proto_tree *tree, char *drep)
{
	dcerpc_info *di = pinfo->private_data;
	guint32 size, key_start;

	if (di->conformant_run)
		return offset;

	/* Dissect size and data */

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_keybuffer_size, &size);

	key_start = offset;
	while (key_start + (size*2) > offset) {
		offset = prs_uint16uni(tvb, offset, pinfo, tree,
				       NULL, "Key");
	}

	return offset;
}


static int SpoolssEnumPrinterKey_q(tvbuff_t *tvb, int offset, 
				   packet_info *pinfo, proto_tree *tree, 
				   char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	char *key_name;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep, hf_spoolss_hnd, NULL,
		FALSE, FALSE);

 	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
 					  prs_UNISTR2_dp, (void **)&key_name,
 					  NULL);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", key_name);

	g_free(key_name);

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Size");

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssEnumPrinterKey_r(tvbuff_t *tvb, int offset, 
				   packet_info *pinfo, proto_tree *tree, 
				   char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_spoolss_keybuffer(tvb, offset, pinfo, tree, drep);

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Needed");

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

#if 0

/* Templates for new subdissectors */

/*
 * FOO
 */

static int SpoolssFoo_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssFoo_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

#endif

/*
 * List of subdissectors for this pipe.
 */

static dcerpc_sub_dissector dcerpc_spoolss_dissectors[] = {
        { SPOOLSS_ENUMPRINTERS, "EnumPrinters",
	  SpoolssEnumPrinters_q, SpoolssEnumPrinters_r },
	{ SPOOLSS_OPENPRINTER, "OpenPrinter",
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_SETJOB, "SetJob",
	  SpoolssSetJob_q, SpoolssSetJob_r },
        { SPOOLSS_GETJOB, "GetJob",
	  SpoolssGetJob_q, SpoolssGetJob_r },
        { SPOOLSS_ENUMJOBS, "EnumJobs",
	  SpoolssEnumJobs_q, SpoolssEnumJobs_r },
        { SPOOLSS_ADDPRINTER, "AddPrinter",
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_DELETEPRINTER, "DeletePrinter",
	  SpoolssDeletePrinter_q, SpoolssDeletePrinter_r },
        { SPOOLSS_SETPRINTER, "SetPrinter",
	  SpoolssSetPrinter_q, SpoolssSetPrinter_r },
        { SPOOLSS_GETPRINTER, "GetPrinter",
	  SpoolssGetPrinter_q, SpoolssGetPrinter_r },
        { SPOOLSS_ADDPRINTERDRIVER, "AddPrinterDriver",
	  NULL, SpoolssAddPrinterDriver_r },
        { SPOOLSS_ENUMPRINTERDRIVERS, "EnumPrinterDrivers",
	  SpoolssEnumPrinterDrivers_q, SpoolssEnumPrinterDrivers_r },
	{ SPOOLSS_GETPRINTERDRIVER, "GetPrinterDriver",
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_GETPRINTERDRIVERDIRECTORY, "GetPrinterDriverDirectory",
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_DELETEPRINTERDRIVER, "DeletePrinterDriver",
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_ADDPRINTPROCESSOR, "AddPrintProcessor",
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_ENUMPRINTPROCESSORS, "EnumPrintProcessor",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_GETPRINTPROCESSORDIRECTORY, "GetPrintProcessorDirectory",
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_STARTDOCPRINTER, "StartDocPrinter",
	  SpoolssStartDocPrinter_q, SpoolssStartDocPrinter_r },
        { SPOOLSS_STARTPAGEPRINTER, "StartPagePrinter",
	  SpoolssStartPagePrinter_q, SpoolssStartPagePrinter_r },
        { SPOOLSS_WRITEPRINTER, "WritePrinter",
	  SpoolssWritePrinter_q, SpoolssWritePrinter_r },
        { SPOOLSS_ENDPAGEPRINTER, "EndPagePrinter",
	  SpoolssEndPagePrinter_q, SpoolssEndPagePrinter_r },
        { SPOOLSS_ABORTPRINTER, "AbortPrinter",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_READPRINTER, "ReadPrinter",
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_ENDDOCPRINTER, "EndDocPrinter",
	  SpoolssEndDocPrinter_q, SpoolssEndDocPrinter_r },
        { SPOOLSS_ADDJOB, "AddJob",
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_SCHEDULEJOB, "ScheduleJob",
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_GETPRINTERDATA, "GetPrinterData",
	  SpoolssGetPrinterData_q, SpoolssGetPrinterData_r },
        { SPOOLSS_SETPRINTERDATA, "SetPrinterData",
	  SpoolssSetPrinterData_q, SpoolssSetPrinterData_r },
	{ SPOOLSS_WAITFORPRINTERCHANGE, "WaitForPrinterChange",
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_CLOSEPRINTER, "ClosePrinter",
	  SpoolssClosePrinter_q, SpoolssClosePrinter_r },
        { SPOOLSS_ADDFORM, "AddForm",
	  SpoolssAddForm_q, SpoolssAddForm_r },
        { SPOOLSS_DELETEFORM, "DeleteForm",
	  SpoolssDeleteForm_q, SpoolssDeleteForm_r },
        { SPOOLSS_GETFORM, "GetForm",
	  SpoolssGetForm_q, SpoolssGetForm_r },
        { SPOOLSS_SETFORM, "SetForm",
	  SpoolssSetForm_q, SpoolssSetForm_r },
        { SPOOLSS_ENUMFORMS, "EnumForms",
	  SpoolssEnumForms_q, SpoolssEnumForms_r },
        { SPOOLSS_ENUMPORTS, "EnumPorts",
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_ENUMMONITORS, "EnumMonitors",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_ADDPORT, "AddPort",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_CONFIGUREPORT, "ConfigurePort",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_DELETEPORT, "DeletePort",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_CREATEPRINTERIC, "CreatePrinterIC",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_PLAYGDISCRIPTONPRINTERIC, "PlayDiscriptOnPrinterIC",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_DELETEPRINTERIC, "DeletePrinterIC",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_ADDPRINTERCONNECTION, "AddPrinterConnection",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_DELETEPRINTERCONNECTION, "DeletePrinterConnection",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_PRINTERMESSAGEBOX, "PrinterMessageBox",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_ADDMONITOR, "AddMonitor",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_DELETEMONITOR, "DeleteMonitor",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_DELETEPRINTPROCESSOR, "DeletePrintProcessor",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_ADDPRINTPROVIDER, "AddPrintProvider",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_DELETEPRINTPROVIDER, "DeletePrintProvider",
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_ENUMPRINTPROCDATATYPES, "EnumPrintProcDataTypes",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_RESETPRINTER, "ResetPrinter",
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_GETPRINTERDRIVER2, "GetPrinterDriver2",
	  SpoolssGetPrinterDriver2_q, SpoolssGetPrinterDriver2_r },
	{ SPOOLSS_FINDFIRSTPRINTERCHANGENOTIFICATION,
	  "FindFirstPrinterChangeNotification",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_FINDNEXTPRINTERCHANGENOTIFICATION,
	  "FindNextPrinterChangeNotification",
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_FCPN, "FCPN",
	  SpoolssFCPN_q, SpoolssFCPN_r },
	{ SPOOLSS_ROUTERFINDFIRSTPRINTERNOTIFICATIONOLD,
	  "RouterFindFirstPrinterNotificationOld",
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_REPLYOPENPRINTER, "ReplyOpenPrinter",
	  SpoolssReplyOpenPrinter_q, SpoolssReplyOpenPrinter_r },
	{ SPOOLSS_ROUTERREPLYPRINTER, "RouterReplyPrinter",
	  SpoolssRouterReplyPrinter_q, SpoolssRouterReplyPrinter_r },
        { SPOOLSS_REPLYCLOSEPRINTER, "ReplyClosePrinter",
	  SpoolssReplyClosePrinter_q, SpoolssReplyClosePrinter_r },
	{ SPOOLSS_ADDPORTEX, "AddPortEx",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_REMOTEFINDFIRSTPRINTERCHANGENOTIFICATION,
	  "RemoteFindFirstPrinterChangeNotification",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_SPOOLERINIT, "SpoolerInit",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_RESETPRINTEREX, "ResetPrinterEx",
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_RFFPCNEX, "RFFPCNEX",
	  SpoolssRFFPCNEX_q, SpoolssRFFPCNEX_r },
        { SPOOLSS_RRPCN, "RRPCN",
	  SpoolssRRPCN_q, SpoolssRRPCN_r },
        { SPOOLSS_RFNPCNEX, "RFNPCNEX",
	  SpoolssRFNPCNEX_q, SpoolssRFNPCNEX_r },
        { SPOOLSS_OPENPRINTEREX, "OpenPrinterEx",
	  SpoolssOpenPrinterEx_q, SpoolssOpenPrinterEx_r },
        { SPOOLSS_ADDPRINTEREX, "AddPrinterEx",
	  NULL, SpoolssAddPrinterEx_r },
        { SPOOLSS_ENUMPRINTERDATA, "EnumPrinterData",
	  SpoolssEnumPrinterData_q, SpoolssEnumPrinterData_r },
        { SPOOLSS_DELETEPRINTERDATA, "DeletePrinterData",
	  SpoolssDeletePrinterData_q, SpoolssDeletePrinterData_r },
        { SPOOLSS_GETPRINTERDATAEX, "GetPrinterDataEx",
	  SpoolssGetPrinterDataEx_q, SpoolssGetPrinterDataEx_r },
        { SPOOLSS_SETPRINTERDATAEX, "SetPrinterDataEx",
	  SpoolssSetPrinterDataEx_q, SpoolssSetPrinterDataEx_r },
	{ SPOOLSS_ENUMPRINTERDATAEX, "EnumPrinterDataEx",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_ENUMPRINTERKEY, "EnumPrinterKey",
	  SpoolssEnumPrinterKey_q, SpoolssEnumPrinterKey_r },
	{ SPOOLSS_DELETEPRINTERDATAEX, "DeletePrinterDataEx",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_DELETEPRINTERDRIVEREX, "DeletePrinterDriverEx",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_ADDPRINTERDRIVEREX, "AddPrinterDriverEx",
	  NULL, SpoolssGeneric_r },

        { 0, NULL, NULL, NULL },
};

/*
 * Dissector initialisation function
 */

/* Protocol registration */

static int proto_dcerpc_spoolss = -1;
static gint ett_dcerpc_spoolss = -1;

void
proto_register_dcerpc_spoolss(void)
{
        static hf_register_info hf[] = {

		/* Opnum */

		{ &hf_spoolss_opnum,
		  { "Operation", "spoolss.opnum", FT_UINT16, BASE_DEC,
		    VALS(spoolss_opnum_vals), 0x0, "Operation", HFILL }},

		{ &hf_spoolss_hnd,
		  { "Context handle", "spoolss.hnd", FT_BYTES, BASE_NONE,
		    NULL, 0x0, "SPOOLSS policy handle", HFILL }},
		{ &hf_spoolss_rc,
		  { "Return code", "spoolss.rc", FT_UINT32, BASE_HEX,
		    VALS(DOS_errors), 0x0, "SPOOLSS return code", HFILL }},
		{ &hf_spoolss_offered,
		  { "Offered", "spoolss.offered", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Size of buffer offered in this request", HFILL }},
		{ &hf_spoolss_needed,
		  { "Needed", "spoolss.needed", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Size of buffer required for request", HFILL }},
		{ &hf_spoolss_returned,
		  { "Returned", "spoolss.returned", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Number of items returned", HFILL }},
		{ &hf_spoolss_relstr_offset,
		  { "Relative string offset", "spoolss.relstr.offset", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Offset of relative string data", HFILL }},
		{ &hf_spoolss_printername,
		  { "Printer name", "spoolss.printername", FT_STRING, BASE_NONE,
		    NULL, 0, "Printer name", HFILL }},
		{ &hf_spoolss_servername,
		  { "Server name", "spoolss.servername", FT_STRING, BASE_NONE,
		    NULL, 0, "Server name", HFILL }},
		{ &hf_spoolss_architecture,
		  { "Architecture name", "spoolss.architecture", FT_STRING, BASE_NONE,
		    NULL, 0, "Architecture name", HFILL }},
		{ &hf_spoolss_drivername,
		  { "Driver name", "spoolss.drivername", FT_STRING, BASE_NONE,
		    NULL, 0, "Driver name", HFILL }},
		{ &hf_spoolss_username,
		  { "User name", "spoolss.username", FT_STRING, BASE_NONE,
		    NULL, 0, "User name", HFILL }},
		{ &hf_spoolss_documentname,
		  { "Document name", "spoolss.document", FT_STRING, BASE_NONE,
		    NULL, 0, "Document name", HFILL }},
		{ &hf_spoolss_outputfile,
		  { "Output file", "spoolss.outputfile", FT_STRING, BASE_NONE,
		    NULL, 0, "Output File", HFILL }},
		{ &hf_spoolss_datatype,
		  { "Datatype", "spoolss.Datatype", FT_STRING, BASE_NONE,
		    NULL, 0, "Datatype", HFILL }},
		{ &hf_spoolss_textstatus,
		  { "Text status", "spoolss.textstatus", FT_STRING, BASE_NONE,
		    NULL, 0, "Text status", HFILL }},
		{ &hf_spoolss_buffer_size,
		  { "Buffer size", "spoolss.buffer.size", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Size of buffer", HFILL }},
		{ &hf_spoolss_buffer_data,
		  { "Buffer data", "spoolss.buffer.data", FT_BYTES, BASE_HEX,
		    NULL, 0x0, "Contents of buffer", HFILL }},
		{ &hf_spoolss_enumjobs_firstjob,
		  { "First job", "spoolss.enumjobs.firstjob", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Index of first job to return", HFILL }},
		{ &hf_spoolss_enumjobs_numjobs,
		  { "Num jobs", "spoolss.enumjobs.numjobs", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Number of jobs to return", HFILL }},
		{ &hf_spoolss_level,
		  { "Info level", "spoolss.enumjobs.level", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Info level", HFILL }},

		/* Print jobs */

		{ &hf_spoolss_jobid,
		  { "Job ID", "spoolss.job.id", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Job identification number", HFILL }},

		{ &hf_spoolss_job_status,
		  { "Job status", "spoolss.job.status", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Job status", HFILL }},

		{ &hf_spoolss_job_status_paused,
		  { "Paused", "spoolss.job.status.paused", FT_BOOLEAN, 32,
		    TFS(&tfs_job_status_paused), JOB_STATUS_PAUSED,
		    "Paused", HFILL }},

		{ &hf_spoolss_job_status_error,
		  { "Error", "spoolss.job.status.error", FT_BOOLEAN, 32,
		    TFS(&tfs_job_status_error), JOB_STATUS_ERROR,
		    "Error", HFILL }},

		{ &hf_spoolss_job_status_deleting,
		  { "Deleting", "spoolss.job.status.deleting", FT_BOOLEAN, 32,
		    TFS(&tfs_job_status_deleting), JOB_STATUS_DELETING,
		    "Deleting", HFILL }},

		{ &hf_spoolss_job_status_spooling,
		  { "Spooling", "spoolss.job.status.spooling", FT_BOOLEAN, 32,
		    TFS(&tfs_job_status_spooling), JOB_STATUS_SPOOLING,
		    "Spooling", HFILL }},

		{ &hf_spoolss_job_status_printing,
		  { "Printing", "spoolss.job.status.printing", FT_BOOLEAN, 32,
		    TFS(&tfs_job_status_printing), JOB_STATUS_PRINTING,
		    "Printing", HFILL }},

		{ &hf_spoolss_job_status_offline,
		  { "Offline", "spoolss.job.status.offline", FT_BOOLEAN, 32,
		    TFS(&tfs_job_status_offline), JOB_STATUS_OFFLINE,
		    "Offline", HFILL }},

		{ &hf_spoolss_job_status_paperout,
		  { "Paperout", "spoolss.job.status.paperout", FT_BOOLEAN, 32,
		    TFS(&tfs_job_status_paperout), JOB_STATUS_PAPEROUT,
		    "Paperout", HFILL }},

		{ &hf_spoolss_job_status_printed,
		  { "Printed", "spoolss.job.status.printed", FT_BOOLEAN, 32,
		    TFS(&tfs_job_status_printed), JOB_STATUS_PRINTED,
		    "Printed", HFILL }},

		{ &hf_spoolss_job_status_deleted,
		  { "Deleted", "spoolss.job.status.deleted", FT_BOOLEAN, 32,
		    TFS(&tfs_job_status_deleted), JOB_STATUS_DELETED,
		    "Deleted", HFILL }},

		{ &hf_spoolss_job_status_blocked,
		  { "Blocked", "spoolss.job.status.blocked", FT_BOOLEAN, 32,
		    TFS(&tfs_job_status_blocked), JOB_STATUS_BLOCKED,
		    "Blocked", HFILL }},

		{ &hf_spoolss_job_status_user_intervention,
		  { "User intervention", "spoolss.job.status.user_intervention", FT_BOOLEAN, 32,
		    TFS(&tfs_job_status_user_intervention), JOB_STATUS_USER_INTERVENTION,
		    "User intervention", HFILL }},

		{ &hf_spoolss_jobpriority,
		  { "Job priority", "spoolss.job.priority", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Job priority", HFILL }},
		{ &hf_spoolss_jobposition,
		  { "Job position", "spoolss.job.position", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Job position", HFILL }},
		{ &hf_spoolss_jobtotalpages,
		  { "Job total pages", "spoolss.job.totalpages", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Job total pages", HFILL }},
		{ &hf_spoolss_jobpagesprinted,
		  { "Job pages printed", "spoolss.job.pagesprinted", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Job identification number", HFILL }},

		/* SYSTEM_TIME */

		{ &hf_spoolss_time_year,
		  { "Year", "spoolss.time.year", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Year", HFILL }},
		{ &hf_spoolss_time_month,
		  { "Month", "spoolss.time.month", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Month", HFILL }},
		{ &hf_spoolss_time_dow,
		  { "Day of week", "spoolss.time.dow", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Day of week", HFILL }},
		{ &hf_spoolss_time_day,
		  { "Day", "spoolss.time.day", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Day", HFILL }},
		{ &hf_spoolss_time_hour,
		  { "Hour", "spoolss.time.hour", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Hour", HFILL }},
		{ &hf_spoolss_time_minute,
		  { "Minute", "spoolss.time.minute", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Minute", HFILL }},
		{ &hf_spoolss_time_second,
		  { "Second", "spoolss.time.second", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Second", HFILL }},
		{ &hf_spoolss_time_msec,
		  { "Millisecond", "spoolss.time.msec", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Millisecond", HFILL }},

		/* Printer data */

		{ &hf_spoolss_printerdata_value,
		  { "Printer data value", "spoolss.printerdata.value", FT_STRING, BASE_NONE,
		    NULL, 0, "Printer data value", HFILL }},

		{ &hf_spoolss_printerdata_type,
		  { "Printer data type", "spoolss.printerdata.type", FT_UINT32, BASE_DEC,
		    VALS(reg_datatypes), 0, "Printer data type", HFILL }},

		/* SetJob RPC */

		{ &hf_spoolss_setjob_cmd,
		  { "Set job command", "spoolss.setjob.cmd", FT_UINT32, BASE_DEC,
		    VALS(setjob_commands), 0x0, "Printer data name", HFILL }},

		/* WritePrinter */

		{ &hf_spoolss_writeprinter_numwritten,
		  { "Num written", "spoolss.writeprinter.numwritten", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Number of bytes written", HFILL }},

		/* EnumPrinterData */

		{ &hf_spoolss_enumprinterdata_index,
		  { "Enum index", "spoolss.enumprinterdata.index", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Index for start of enumeration", HFILL }},

		{ &hf_spoolss_enumprinterdata_value_offered,
		  { "Value size offered", "spoolss.enumprinterdata.value_offered", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Buffer size offered for printerdata value", HFILL }},

		{ &hf_spoolss_enumprinterdata_data_offered,
		  { "Data size offered", "spoolss.enumprinterdata.data_offered", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Buffer size offered for printerdata data", HFILL }},

		{ &hf_spoolss_enumprinterdata_value_needed,
		  { "Value size needed", "spoolss.enumprinterdata.value_needed", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Buffer size needed for printerdata value", HFILL }},

		{ &hf_spoolss_enumprinterdata_data_needed,
		  { "Data size needed", "spoolss.enumprinterdata.data_needed", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Buffer size needed for printerdata data", HFILL }},

		/* GetPrinterDriver2 */

		{ &hf_spoolss_clientmajorversion,
		  { "Client major version", "spoolss.clientmajorversion", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Client printer driver major version", HFILL }},
		{ &hf_spoolss_clientminorversion,
		  { "Client minor version", "spoolss.clientminorversion", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Client printer driver minor version", HFILL }},
		{ &hf_spoolss_servermajorversion,
		  { "Server major version", "spoolss.servermajorversion", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Server printer driver major version", HFILL }},
		{ &hf_spoolss_serverminorversion,
		  { "Server minor version", "spoolss.serverminorversion", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Server printer driver minor version", HFILL }},
		{ &hf_spoolss_driverpath,
		  { "Driver path", "spoolss.driverpath", FT_STRING, BASE_NONE,
		    NULL, 0, "Driver path", HFILL }},
		{ &hf_spoolss_datafile,
		  { "Data file", "spoolss.datafile", FT_STRING, BASE_NONE,
		    NULL, 0, "Data file", HFILL }},
		{ &hf_spoolss_configfile,
		  { "Config file", "spoolss.configfile", FT_STRING, BASE_NONE,
		    NULL, 0, "Printer name", HFILL }},
		{ &hf_spoolss_helpfile,
		  { "Help file", "spoolss.helpfile", FT_STRING, BASE_NONE,
		    NULL, 0, "Help file", HFILL }},
		{ &hf_spoolss_monitorname,
		  { "Monitor name", "spoolss.monitorname", FT_STRING, BASE_NONE,
		    NULL, 0, "Monitor name", HFILL }},
		{ &hf_spoolss_defaultdatatype,
		  { "Default data type", "spoolss.defaultdatatype", FT_STRING, BASE_NONE,
		    NULL, 0, "Default data type", HFILL }},
		{ &hf_spoolss_driverinfo_cversion,
		  { "Driver version", "spoolss.driverversion", FT_UINT32, BASE_DEC,
		    VALS(driverinfo_cversion_vals), 0, "Printer name", HFILL }},
		{ &hf_spoolss_dependentfiles,
		  { "Dependent files", "spoolss.dependentfiles", FT_STRING, BASE_NONE,
		    NULL, 0, "Dependent files", HFILL }},

		/* rffpcnex */

		{ &hf_spoolss_rffpcnex_options,
		  { "Options", "spoolss.rffpcnex.options", FT_UINT32, BASE_DEC,
		    NULL, 0, "RFFPCNEX options", HFILL }},

		{ &hf_spoolss_printerlocal,
		  { "Printer local", "spoolss.printer_local", FT_UINT32, BASE_DEC,
		    NULL, 0, "Printer local", HFILL }},

		{ &hf_spoolss_rffpcnex_flags,
		  { "RFFPCNEX flags", "spoolss.rffpcnex.flags", FT_UINT32, BASE_DEC,
		    NULL, 0, "RFFPCNEX flags", HFILL }},

		{ &hf_spoolss_rffpcnex_flags_add_printer,
		  { "Add printer", "spoolss.rffpcnex.flags.add_printer",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_add_printer),
		    SPOOLSS_PRINTER_CHANGE_ADD_PRINTER, "Add printer", HFILL }},

		{ &hf_spoolss_rffpcnex_flags_set_printer,
		  { "Set printer", "spoolss.rffpcnex.flags.set_printer",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_set_printer),
		    SPOOLSS_PRINTER_CHANGE_SET_PRINTER, "Set printer", HFILL }},

		{ &hf_spoolss_rffpcnex_flags_delete_printer,
		  { "Delete printer", "spoolss.rffpcnex.flags.delete_printer",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_delete_printer),
		    SPOOLSS_PRINTER_CHANGE_DELETE_PRINTER, "Delete printer", HFILL }},

		{ &hf_spoolss_rffpcnex_flags_add_job,
		  { "Add job", "spoolss.rffpcnex.flags.add_job",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_add_job),
		    SPOOLSS_PRINTER_CHANGE_ADD_JOB, "Add job", HFILL }},

		{ &hf_spoolss_rffpcnex_flags_set_job,
		  { "Set job", "spoolss.rffpcnex.flags.set_job",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_set_job),
		    SPOOLSS_PRINTER_CHANGE_SET_JOB, "Set job", HFILL }},

		{ &hf_spoolss_rffpcnex_flags_delete_job,
		  { "Delete job", "spoolss.rffpcnex.flags.delete_job",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_delete_job),
		    SPOOLSS_PRINTER_CHANGE_DELETE_JOB, "Delete job", HFILL }},

		{ &hf_spoolss_rffpcnex_flags_write_job,
		  { "Write job", "spoolss.rffpcnex.flags.write_job",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_write_job),
		    SPOOLSS_PRINTER_CHANGE_WRITE_JOB, "Write job", HFILL }},

		{ &hf_spoolss_rffpcnex_flags_add_form,
		  { "Add form", "spoolss.rffpcnex.flags.add_form",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_add_form),
		    SPOOLSS_PRINTER_CHANGE_ADD_FORM, "Add form", HFILL }},

		{ &hf_spoolss_rffpcnex_flags_set_form,
		  { "Set form", "spoolss.rffpcnex.flags.set_form",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_set_form),
		    SPOOLSS_PRINTER_CHANGE_SET_FORM, "Set form", HFILL }},

		{ &hf_spoolss_rffpcnex_flags_delete_form,
		  { "Delete form", "spoolss.rffpcnex.flags.delete_form",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_delete_form),
		    SPOOLSS_PRINTER_CHANGE_DELETE_FORM, "Delete form", HFILL }},

		{ &hf_spoolss_rffpcnex_flags_add_port,
		  { "Add port", "spoolss.rffpcnex.flags.add_port",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_add_port),
		    SPOOLSS_PRINTER_CHANGE_ADD_PORT, "Add port", HFILL }},

		{ &hf_spoolss_rffpcnex_flags_configure_port,
		  { "Configure port", "spoolss.rffpcnex.flags.configure_port",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_configure_port),
		    SPOOLSS_PRINTER_CHANGE_CONFIGURE_PORT, "Configure port", HFILL }},

		{ &hf_spoolss_rffpcnex_flags_delete_port,
		  { "Delete port", "spoolss.rffpcnex.flags.delete_port",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_delete_port),
		    SPOOLSS_PRINTER_CHANGE_DELETE_PORT, "Delete port", HFILL }},


		{ &hf_spoolss_rffpcnex_flags_add_print_processor,
		  { "Add processor", "spoolss.rffpcnex.flags.add_processor",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_add_print_processor),
		    SPOOLSS_PRINTER_CHANGE_ADD_PRINT_PROCESSOR, "Add processor", HFILL }},

		{ &hf_spoolss_rffpcnex_flags_delete_print_processor,
		  { "Delete processor", "spoolss.rffpcnex.flags.delete_processor",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_delete_print_processor),
		    SPOOLSS_PRINTER_CHANGE_DELETE_PRINT_PROCESSOR, "Delete processor", HFILL }},

		{ &hf_spoolss_rffpcnex_flags_add_driver,
		  { "Add driver", "spoolss.rffpcnex.flags.add_driver",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_add_driver),
		    SPOOLSS_PRINTER_CHANGE_ADD_PRINTER_DRIVER, "Add driver", HFILL }},

		{ &hf_spoolss_rffpcnex_flags_set_driver,
		  { "Set driver", "spoolss.rffpcnex.flags.set_driver",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_set_driver),
		    SPOOLSS_PRINTER_CHANGE_SET_PRINTER_DRIVER, "Set driver", HFILL }},

		{ &hf_spoolss_rffpcnex_flags_delete_driver,
		  { "Delete driver", "spoolss.rffpcnex.flags.delete_driver",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_delete_driver),
		    SPOOLSS_PRINTER_CHANGE_DELETE_PRINTER_DRIVER, "Delete driver", HFILL }},

		{ &hf_spoolss_rffpcnex_flags_timeout,
		  { "Timeout", "spoolss.rffpcnex.flags.timeout",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_timeout),
		    SPOOLSS_PRINTER_CHANGE_TIMEOUT, "Timeout", HFILL }},

		{ &hf_spoolss_rffpcnex_flags_failed_printer_connection,
		  { "Failed printer connection", "spoolss.rffpcnex.flags.failed_connection_printer",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_failed_connection_printer),
		    SPOOLSS_PRINTER_CHANGE_FAILED_CONNECTION_PRINTER, "Failed printer connection", HFILL }},

		{ &hf_spoolss_notify_options_version,
		  { "Version", "spoolss.notify_options.version", FT_UINT32, BASE_DEC,
		    NULL, 0, "Version", HFILL }},

		{ &hf_spoolss_notify_options_flags,
		  { "Flags", "spoolss.notify_options.flags", FT_UINT32, BASE_DEC,
		    NULL, 0, "Flags", HFILL }},

		{ &hf_spoolss_notify_options_count,
		  { "Count", "spoolss.notify_options.count", FT_UINT32, BASE_DEC,
		    NULL, 0, "Count", HFILL }},

		{ &hf_spoolss_notify_option_type,
		  { "Type", "spoolss.notify_option.type", FT_UINT16, BASE_DEC,
		    VALS(printer_notify_types), 0, "Type", HFILL }},
		{ &hf_spoolss_notify_option_reserved1,
		  { "Reserved1", "spoolss.notify_option.reserved1", FT_UINT16, BASE_DEC,
		    NULL, 0, "Reserved1", HFILL }},
		{ &hf_spoolss_notify_option_reserved2,
		  { "Reserved2", "spoolss.notify_option.reserved2", FT_UINT32, BASE_DEC,
		    NULL, 0, "Reserved2", HFILL }},
		{ &hf_spoolss_notify_option_reserved3,
		  { "Reserved3", "spoolss.notify_option.reserved3", FT_UINT32, BASE_DEC,
		    NULL, 0, "Reserved3", HFILL }},
		{ &hf_spoolss_notify_option_count,
		  { "Count", "spoolss.notify_option.count", FT_UINT32, BASE_DEC,
		    NULL, 0, "Count", HFILL }},
		{ &hf_spoolss_notify_option_data_count,
		  { "Count", "spoolss.notify_option_data.count", FT_UINT32, BASE_DEC,
		    NULL, 0, "Count", HFILL }},
		{ &hf_spoolss_notify_options_flags_refresh,
		  { "Refresh", "spoolss.notify_options.flags", FT_BOOLEAN, 32,
		    TFS(&tfs_notify_options_flags_refresh), PRINTER_NOTIFY_OPTIONS_REFRESH,
		    "Refresh", HFILL }},
		{ &hf_spoolss_notify_info_count,
		  { "Count", "spoolss.notify_info.count", FT_UINT32, BASE_DEC,
		    NULL, 0, "Count", HFILL }},
		{ &hf_spoolss_notify_info_version,
		  { "Version", "spoolss.notify_info.version", FT_UINT32, BASE_DEC,
		    NULL, 0, "Version", HFILL }},
		{ &hf_spoolss_notify_info_flags,
		  { "Flags", "spoolss.notify_info.flags", FT_UINT32, BASE_HEX,
		    NULL, 0, "Flags", HFILL }},
		{ &hf_spoolss_notify_info_data_type,
		  { "Type", "spoolss.notify_info_data.type", FT_UINT16, BASE_DEC,
		    VALS(printer_notify_types), 0, "Type", HFILL }},
		{ &hf_spoolss_notify_field,
		  { "Field", "spoolss.notify_field", FT_UINT16, BASE_DEC,
		    NULL, 0, "Field", HFILL }},
		{ &hf_spoolss_notify_info_data_count,
		  { "Count", "spoolss.notify_info_data.count", FT_UINT32, BASE_DEC,
		    NULL, 0, "Count", HFILL }},
		{ &hf_spoolss_notify_info_data_id,
		  { "Job Id", "spoolss.notify_info_data.jobid", FT_UINT32, BASE_DEC,
		    NULL, 0, "Job Id", HFILL }},
		{ &hf_spoolss_notify_info_data_value1,
		  { "Value1", "spoolss.notify_info_data.value1", FT_UINT32, BASE_HEX,
		    NULL, 0, "Value1", HFILL }},
		{ &hf_spoolss_notify_info_data_value2,
		  { "Value2", "spoolss.notify_info_data.value2", FT_UINT32, BASE_HEX,
		    NULL, 0, "Value2", HFILL }},
		{ &hf_spoolss_notify_info_data_bufsize,
		  { "Buffer size", "spoolss.notify_info_data.bufsize", FT_UINT32, BASE_DEC,
		    NULL, 0, "Buffer size", HFILL }},
		{ &hf_spoolss_notify_info_data_buffer,
		  { "Buffer", "spoolss.notify_info_data.buffer", FT_UINT32, BASE_HEX,
		    NULL, 0, "Buffer", HFILL }},
		{ &hf_spoolss_notify_info_data_buffer_len,
		  { "Buffer length", "spoolss.notify_info_data.buffer.len", FT_UINT32, BASE_HEX,
		    NULL, 0, "Buffer length", HFILL }},
		{ &hf_spoolss_notify_info_data_buffer_data,
		  { "Buffer data", "spoolss.notify_info_data.buffer.data", FT_BYTES, BASE_HEX,
		    NULL, 0, "Buffer data", HFILL }},

		{ &hf_spoolss_rrpcn_changelow,
		  { "Change low", "spoolss.rrpcn.changelow", FT_UINT32, BASE_DEC,
		    NULL, 0, "Change low", HFILL }},
		{ &hf_spoolss_rrpcn_changehigh,
		  { "Change high", "spoolss.rrpcn.changehigh", FT_UINT32, BASE_DEC,
		    NULL, 0, "Change high", HFILL }},
		{ &hf_spoolss_rrpcn_unk0,
		  { "Unknown 0", "spoolss.rrpcn.unk0", FT_UINT32, BASE_DEC,
		    NULL, 0, "Unknown 0", HFILL }},
		{ &hf_spoolss_rrpcn_unk1,
		  { "Unknown 1", "spoolss.rrpcn.unk1", FT_UINT32, BASE_DEC,
		    NULL, 0, "Unknown 1", HFILL }},
		{ &hf_spoolss_replyopenprinter_unk0,
		  { "Unknown 0", "spoolss.replyopenprinter.unk0", FT_UINT32, BASE_DEC,
		    NULL, 0, "Unknown 0", HFILL }},
		{ &hf_spoolss_replyopenprinter_unk1,
		  { "Unknown 1", "spoolss.replyopenprinter.unk1", FT_UINT32, BASE_DEC,
		    NULL, 0, "Unknown 1", HFILL }},

		{ &hf_spoolss_printer_status,
		  { "Status", "spoolss.printer_status", FT_UINT32, BASE_DEC,
		   VALS(printer_status_vals), 0, "Status", HFILL }},

		/* Printer attributes */

		{ &hf_spoolss_printer_attributes,
		  { "Attributes", "spoolss.printer_attributes", FT_UINT32,
		    BASE_HEX, NULL, 0, "Attributes", HFILL }},

		{ &hf_spoolss_printer_attributes_queued,
		  { "Queued", "spoolss.printer_attributes.queued", FT_BOOLEAN,
		    32, TFS(&tfs_printer_attributes_queued),
		    PRINTER_ATTRIBUTE_QUEUED, "Queued", HFILL }},

		{ &hf_spoolss_printer_attributes_direct,
		  { "Direct", "spoolss.printer_attributes.direct", FT_BOOLEAN,
		    32, TFS(&tfs_printer_attributes_direct),
		    PRINTER_ATTRIBUTE_DIRECT, "Direct", HFILL }},

		{ &hf_spoolss_printer_attributes_default,
		  { "Default (9x/ME only)", "spoolss.printer_attributes.default",FT_BOOLEAN,
		    32, TFS(&tfs_printer_attributes_default),
		    PRINTER_ATTRIBUTE_DEFAULT, "Default", HFILL }},

		{ &hf_spoolss_printer_attributes_shared,
		  { "Shared", "spoolss.printer_attributes.shared", FT_BOOLEAN,
		    32, TFS(&tfs_printer_attributes_shared),
		    PRINTER_ATTRIBUTE_SHARED, "Shared", HFILL }},

		{ &hf_spoolss_printer_attributes_network,
		  { "Network", "spoolss.printer_attributes.network", FT_BOOLEAN,
		    32, TFS(&tfs_printer_attributes_network),
		    PRINTER_ATTRIBUTE_NETWORK, "Network", HFILL }},

		{ &hf_spoolss_printer_attributes_hidden,
		  { "Hidden", "spoolss.printer_attributes.hidden", FT_BOOLEAN,
		    32, TFS(&tfs_printer_attributes_hidden),
		    PRINTER_ATTRIBUTE_HIDDEN, "Hidden", HFILL }},

		{ &hf_spoolss_printer_attributes_local,
		  { "Local", "spoolss.printer_attributes.local", FT_BOOLEAN,
		    32, TFS(&tfs_printer_attributes_local),
		    PRINTER_ATTRIBUTE_LOCAL, "Local", HFILL }},

		{ &hf_spoolss_printer_attributes_enable_devq,
		  { "Enable devq", "spoolss.printer_attributes.enable_devq", FT_BOOLEAN,
		    32, TFS(&tfs_printer_attributes_enable_devq),
		    PRINTER_ATTRIBUTE_ENABLE_DEVQ, "Enable evq", HFILL }},

		{ &hf_spoolss_printer_attributes_keep_printed_jobs,
		  { "Keep printed jobs", "spoolss.printer_attributes.keep_printed_jobs", FT_BOOLEAN,
		    32, TFS(&tfs_printer_attributes_keep_printed_jobs),
		    PRINTER_ATTRIBUTE_KEEPPRINTEDJOBS, "Keep printed jobs", HFILL }},

		{ &hf_spoolss_printer_attributes_do_complete_first,
		  { "Do complete first", "spoolss.printer_attributes.do_complete_first", FT_BOOLEAN,
		    32, TFS(&tfs_printer_attributes_do_complete_first),
		    PRINTER_ATTRIBUTE_DO_COMPLETE_FIRST, "Do complete first", HFILL }},

		{ &hf_spoolss_printer_attributes_work_offline,
		  { "Work offline (9x/ME only)", "spoolss.printer_attributes.work_offline", FT_BOOLEAN,
		    32, TFS(&tfs_printer_attributes_work_offline),
		    PRINTER_ATTRIBUTE_WORK_OFFLINE, "Work offline", HFILL }},

		{ &hf_spoolss_printer_attributes_enable_bidi,
		  { "Enable bidi (9x/ME only)", "spoolss.printer_attributes.enable_bidi", FT_BOOLEAN,
		    32, TFS(&tfs_printer_attributes_enable_bidi),
		    PRINTER_ATTRIBUTE_ENABLE_BIDI, "Enable bidi", HFILL }},

		{ &hf_spoolss_printer_attributes_raw_only,
		  { "Raw only", "spoolss.printer_attributes.raw_only", FT_BOOLEAN,
		    32, TFS(&tfs_printer_attributes_raw_only),
		    PRINTER_ATTRIBUTE_RAW_ONLY, "Raw only", HFILL }},

		{ &hf_spoolss_printer_attributes_published,
		  { "Published", "spoolss.printer_attributes.published", FT_BOOLEAN,
		    32, TFS(&tfs_printer_attributes_published),
		    PRINTER_ATTRIBUTE_PUBLISHED, "Published", HFILL }},

		/* Setprinter RPC */

		{ &hf_spoolss_setprinter_cmd,
		  { "Command", "spoolss.setprinter_cmd", FT_UINT32, BASE_DEC,
		   VALS(setprinter_cmd_vals), 0, "Command", HFILL }},

		/* RouterReplyPrinter RPC */

		{ &hf_spoolss_routerreplyprinter_condition,
		  { "Condition", "spoolss.routerreplyprinter.condition", FT_UINT32,
		    BASE_DEC, NULL, 0, "Condition", HFILL }},

		{ &hf_spoolss_routerreplyprinter_unknown1,
		  { "Unknown1", "spoolss.routerreplyprinter.unknown1", FT_UINT32,
		    BASE_DEC, NULL, 0, "Unknown1", HFILL }},

		{ &hf_spoolss_routerreplyprinter_changeid,
		  { "Change id", "spoolss.routerreplyprinter.changeid", FT_UINT32,
		    BASE_DEC, NULL, 0, "Change id", HFILL }},

		/* Forms */

		{ &hf_spoolss_form_level,
		  { "Level", "spoolss.form.level", FT_UINT32,
		    BASE_DEC, NULL, 0, "Level", HFILL }},

		{ &hf_spoolss_form_name,
		  { "Name", "spoolss.form.name", FT_STRING, BASE_NONE,
		    NULL, 0, "Name", HFILL }},

		{ &hf_spoolss_form_flags,
		  { "Flags", "spoolss.form.flags", FT_UINT32,
		    BASE_DEC, NULL, 0, "Flags", HFILL }},

		{ &hf_spoolss_form_unknown,
		  { "Unknown", "spoolss.form.unknown", FT_UINT32,
		    BASE_HEX, NULL, 0, "Unknown", HFILL }},

		{ &hf_spoolss_form_width,
		  { "Width", "spoolss.form.width", FT_UINT32,
		    BASE_DEC, NULL, 0, "Width", HFILL }},

		{ &hf_spoolss_form_height,
		  { "Height", "spoolss.form.height", FT_UINT32,
		    BASE_DEC, NULL, 0, "Height", HFILL }},

		{ &hf_spoolss_form_left_margin,
		  { "Left margin", "spoolss.form.left", FT_UINT32,
		    BASE_DEC, NULL, 0, "Left", HFILL }},

		{ &hf_spoolss_form_top_margin,
		  { "Top", "spoolss.form.top", FT_UINT32,
		    BASE_DEC, NULL, 0, "Top", HFILL }},

		{ &hf_spoolss_form_horiz_len,
		  { "Horizontal", "spoolss.form.horiz", FT_UINT32,
		    BASE_DEC, NULL, 0, "Horizontal", HFILL }},

		{ &hf_spoolss_form_vert_len,
		  { "Vertical", "spoolss.form.vert", FT_UINT32,
		    BASE_DEC, NULL, 0, "Vertical", HFILL }},

		/* GetForm RPC */

		{ &hf_spoolss_getform_level,
		  { "Level", "spoolss.getform.level", FT_UINT32,
		    BASE_DEC, NULL, 0, "Level", HFILL }},

		/* SetForm RPC */

		{ &hf_spoolss_setform_level,
		  { "Level", "spoolss.setform.level", FT_UINT32,
		    BASE_DEC, NULL, 0, "Level", HFILL }},

		/* AddForm RPC */

		{ &hf_spoolss_addform_level,
		  { "Level", "spoolss.addform.level", FT_UINT32,
		    BASE_DEC, NULL, 0, "Level", HFILL }},

		/* EnumForms RPC */

		{ &hf_spoolss_enumforms_num,
		  { "Num", "spoolss.enumforms.num", FT_UINT32,
		    BASE_DEC, NULL, 0, "Num", HFILL }},

		/* Printerdata */

		{ &hf_spoolss_printerdata_size,
		  { "Size", "spoolss.printerdata.size", FT_UINT32,
		    BASE_DEC, NULL, 0, "Size", HFILL }},

		{ &hf_spoolss_printerdata_data,
		  { "Data", "spoolss.printerdata.data", FT_BYTES,
		    BASE_HEX, NULL, 0, "Data", HFILL }},

		/* Specific access rights */

		{ &hf_access_required,
		  { "Access required", "spoolss.access_required",
		    FT_UINT32, BASE_HEX, NULL, 0x0, "Access REQUIRED",
		    HFILL }},

		{ &hf_server_access_admin,
		  { "Server admin", "spoolss.access_mask.server_admin",
		    FT_BOOLEAN, 32, TFS(&flags_set_truth),
		    SERVER_ACCESS_ADMINISTER, "Server admin", HFILL }},

		{ &hf_server_access_enum,
		  { "Server enum", "spoolss.access_mask.server_enum",
		    FT_BOOLEAN, 32, TFS(&flags_set_truth),
		    SERVER_ACCESS_ENUMERATE, "Server enum", HFILL }},

		{ &hf_printer_access_admin,
		  { "Printer admin", "spoolss.access_mask.printer_admin",
		    FT_BOOLEAN, 32, TFS(&flags_set_truth),
		    PRINTER_ACCESS_ADMINISTER, "Printer admin", HFILL }},

		{ &hf_printer_access_use,
		  { "Printer use", "spoolss.access_mask.printer_use",
		    FT_BOOLEAN, 32, TFS(&flags_set_truth),
		    PRINTER_ACCESS_USE, "Printer use", HFILL }},

		{ &hf_job_access_admin,
		  { "Job admin", "spoolss.access_mask.job_admin",
		    FT_BOOLEAN, 32, TFS(&flags_set_truth),
		    JOB_ACCESS_ADMINISTER, "Job admin", HFILL }},

		/* Enumprinters */

		{ &hf_enumprinters_flags_local,
		  { "Enum local", "spoolss.enumprinters.flags.enum_local",
		    FT_BOOLEAN, 32, TFS(&flags_set_truth),
		    PRINTER_ENUM_LOCAL, "Enum local", HFILL }},

		{ &hf_enumprinters_flags_name,
		  { "Enum name", "spoolss.enumprinters.flags.enum_name",
		    FT_BOOLEAN, 32, TFS(&flags_set_truth),
		    PRINTER_ENUM_NAME, "Enum name", HFILL }},

		{ &hf_enumprinters_flags_shared,
		  { "Enum shared", "spoolss.enumprinters.flags.enum_shared",
		    FT_BOOLEAN, 32, TFS(&flags_set_truth),
		    PRINTER_ENUM_SHARED, "Enum shared", HFILL }},

		{ &hf_enumprinters_flags_default,
		  { "Enum default", "spoolss.enumprinters.flags.enum_default",
		    FT_BOOLEAN, 32, TFS(&flags_set_truth),
		    PRINTER_ENUM_DEFAULT, "Enum default", HFILL }},

		{ &hf_enumprinters_flags_connections,
		  { "Enum connections", "spoolss.enumprinters.flags.enum_connections",
		    FT_BOOLEAN, 32, TFS(&flags_set_truth),
		    PRINTER_ENUM_CONNECTIONS, "Enum connections", HFILL }},

		{ &hf_enumprinters_flags_network,
		  { "Enum network", "spoolss.enumprinters.flags.enum_network",
		    FT_BOOLEAN, 32, TFS(&flags_set_truth),
		    PRINTER_ENUM_NETWORK, "Enum network", HFILL }},

		{ &hf_enumprinters_flags_remote,
		  { "Enum remote", "spoolss.enumprinters.flags.enum_remote",
		    FT_BOOLEAN, 32, TFS(&flags_set_truth),
		    PRINTER_ENUM_REMOTE, "Enum remote", HFILL }},

		/* EnumPrinterKey */
		{ &hf_spoolss_keybuffer_size,
		  { "Key Buffer size", "spoolss.keybuffer.size", FT_UINT32, 
		    BASE_DEC, NULL, 0x0, "Size of buffer", HFILL }},

		{ &hf_spoolss_keybuffer_data,
		  { "Key Buffer data", "spoolss.keybuffer.data", FT_BYTES, 
		    BASE_HEX, NULL, 0x0, "Contents of buffer", HFILL }},

	};

        static gint *ett[] = {
                &ett_dcerpc_spoolss,
		&ett_PRINTER_DEFAULT,
		&ett_DEVMODE_CTR,
		&ett_DEVMODE,
		&ett_USER_LEVEL,
		&ett_USER_LEVEL_1,
		&ett_BUFFER,
		&ett_BUFFER_DATA,
		&ett_BUFFER_DATA_BUFFER,
		&ett_UNISTR2,
		&ett_SPOOL_PRINTER_INFO_LEVEL,
		&ett_PRINTER_INFO_0,
		&ett_PRINTER_INFO_1,
		&ett_PRINTER_INFO_2,
		&ett_PRINTER_INFO_3,
		&ett_RELSTR,
		&ett_RELSTR_ARRAY,
		&ett_FORM_REL,
		&ett_FORM_CTR,
		&ett_FORM_1,
		&ett_JOB_INFO_1,
		&ett_JOB_INFO_2,
		&ett_SEC_DESC_BUF,
		&ett_SYSTEM_TIME,
		&ett_DOC_INFO_1,
		&ett_DOC_INFO,
		&ett_DOC_INFO_CTR,
		&ett_printerdata_value,
		&ett_printerdata_data,
		&ett_writeprinter_buffer,
		&ett_DRIVER_INFO_1,
		&ett_DRIVER_INFO_3,
		&ett_rffpcnex_flags,
		&ett_notify_options_flags,
		&ett_NOTIFY_INFO_DATA,
		&ett_NOTIFY_OPTION,
		&ett_printer_attributes,
		&ett_job_status,
		&ett_enumprinters_flags,
        };

        proto_dcerpc_spoolss = proto_register_protocol(
                "Microsoft Spool Subsystem", "SPOOLSS", "spoolss");

	proto_register_field_array(proto_dcerpc_spoolss, hf, array_length(hf));

        proto_register_subtree_array(ett, array_length(ett));
}

/* Protocol handoff */

static e_uuid_t uuid_dcerpc_spoolss = {
        0x12345678, 0x1234, 0xabcd,
        { 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab }
};

static guint16 ver_dcerpc_spoolss = 1;

void
proto_reg_handoff_dcerpc_spoolss(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_spoolss, ett_dcerpc_spoolss,
                         &uuid_dcerpc_spoolss, ver_dcerpc_spoolss,
                         dcerpc_spoolss_dissectors, hf_spoolss_opnum);
}
