/* packet-dcerpc-eventlog.c
 * Routines for SMB \pipe\eventlog packet disassembly
 * Copyright 2004 Jean-Baptiste Marchand <jbm@hsc.fr>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"
#include "packet-dcerpc-eventlog.h"
#include "packet-windows-common.h"


static int proto_dcerpc_eventlog = -1;

static int hf_eventlog_opnum = -1;
static int hf_eventlog_name = -1;
static int hf_eventlog_numofrecords = -1;
static int hf_eventlog_oldest_record = -1;
static int hf_eventlog_rc = -1;
static int hf_eventlog_hnd = -1;
static int hf_eventlog_backup_file = -1;
static int hf_eventlog_infolevel = -1;
static int hf_eventlog_bufsize = -1;
static int hf_eventlog_unknown = -1;
static int hf_eventlog_unknown_string = -1;
static int hf_eventlog_flags = -1;
static int hf_eventlog_offset = -1;
static int hf_eventlog_size = -1;

static gint ett_dcerpc_eventlog = -1;


/* 
 IDL [ uuid(82273fdc-e32a-18c3-3f78-827929dc23ea),
 IDL  version(0.0),
 IDL implicit_handle(handle_t rpc_binding)
 IDL ] interface eventlog
*/


static e_uuid_t uuid_dcerpc_eventlog = {
	0x82273fdc, 0xe32a, 0x18c3, 
	{ 0x3f, 0x78, 0x82, 0x79, 0x29, 0xdc, 0x23, 0xea }
};

static guint16 ver_dcerpc_eventlog = 0; 



/* 
 IDL
 IDL long ElfrClearELFW(
 IDL      [in] [context_handle] void *hEventLog,
 IDL      [in] [string] [unique] wchar_t *BackupFileName
 IDL );
 */

static int
eventlog_dissect_clearw_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_eventlog_hnd, NULL, NULL, FALSE, FALSE);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_counted_string_ptr, NDR_POINTER_UNIQUE,
		"Backup filename", hf_eventlog_backup_file);

	return offset;
}

static int
eventlog_dissect_clearw_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, 
			hf_eventlog_rc, NULL);

	return offset;
}


/*
 IDL long ElfrBackupELFW(
 IDL      [in] [context_handle] void *hEventLog,
 IDL      [in] [string] wchar_t *BackupFileName
 IDL );
 */

static int
eventlog_dissect_backupw_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_eventlog_hnd, NULL, NULL, FALSE, FALSE);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_counted_string_ptr, NDR_POINTER_REF,
		"Backup filename", hf_eventlog_backup_file);

	return offset;
}

static int
eventlog_dissect_backupw_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, 
			hf_eventlog_rc, NULL);

	return offset;
}


/*
 IDL long ElfrCloseEL(
 IDL    [in,out] [context_handle] void *hEventLog,
 IDL );
 */

static int
eventlog_dissect_close_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_eventlog_hnd, NULL, NULL, FALSE, TRUE);

	return offset;
}

static int
eventlog_dissect_close_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_eventlog_hnd, NULL, NULL, FALSE, FALSE);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, 
			hf_eventlog_rc, NULL);

	return offset;
}


/*
 IDL
 IDL long ElfrDeregisterEventSource(
 IDL   [in,out] [context_handle] void *hEventLog
 IDL );
 */

static int
eventlog_dissect_deregister_evt_src_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_eventlog_hnd, NULL, NULL, FALSE, FALSE);
	return offset;
}

static int
eventlog_dissect_deregister_evt_src_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_eventlog_hnd, NULL, NULL, FALSE, FALSE);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, 
			hf_eventlog_rc, NULL);

	return offset;
}


/* 
 IDL
 IDL long ElfrNumberOfRecords(
 IDL      [in] [context_handle] void *hEventLog,
 IDL      [out] long NumberOfRecords
 IDL );
 */

static int
eventlog_dissect_getnumofrecords_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_eventlog_hnd, NULL, NULL, FALSE, FALSE);
	return offset;
}

static int
eventlog_dissect_getnumofrecords_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_eventlog_numofrecords, NULL);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, 
			hf_eventlog_rc, NULL);

	return offset;
}

/*
 IDL
 IDL long ElfrOldestRecord(
 IDL      [in] [context_handle] void *hEventLog,
 IDL      [out] long OldestRecord
 IDL );
 */

static int
eventlog_dissect_oldestrecord_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_eventlog_hnd, NULL, NULL, FALSE, FALSE);

	return offset;
}


static int
eventlog_dissect_oldestrecord_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_eventlog_oldest_record, NULL);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, 
			hf_eventlog_rc, NULL);

	return offset;
}


/*
 IDL typedef struct {
 IDL   long element_14;
 IDL   long element_15;
 IDL } TYPE_2;
 */

static int
eventlog_dissect_TYPE_2(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_eventlog_unknown, NULL);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_eventlog_unknown, NULL);

	return offset;
}

/*
 IDL long ElfrChangeNotify (
 IDL      [in] [context_handle] void *element_16,
 IDL      [in] TYPE_2 element_17,
 IDL      [in] long element_18
 IDL );
 */


static int
eventlog_dissect_changenotify_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_eventlog_hnd, NULL, NULL, FALSE, FALSE);

	offset = eventlog_dissect_TYPE_2(tvb, offset, pinfo, tree, drep);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_eventlog_unknown, NULL);

	return offset;
}


static int
eventlog_dissect_changenotify_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, 
			hf_eventlog_rc, NULL);

	return offset;
}


/*
 IDL typedef struct {
 IDL   short unknown0;
 IDL   short unknown1;
 IDL } TYPE_6;
 */

static int
eventlog_dissect_TYPE_6(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
			hf_eventlog_unknown, NULL);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
			hf_eventlog_unknown, NULL);

	return offset;
}


/*
 IDL NTSTATUS ElfrOpenELW(
 IDL      [in] [unique] TYPE_6 *unknown0,
 IDL      [in] UNICODE_STRING eventlog_name,
 IDL      [in] UNICODE_STRING unknown1,
 IDL      [in] long unknown2,
 IDL      [in] long unknown3,
 IDL      [out] [context_handle] void *hEventLog
 IDL );
 */

static int 
eventlog_dissect_openw_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			eventlog_dissect_TYPE_6, NDR_POINTER_UNIQUE,
			"Unknown struct pointer:", hf_eventlog_unknown);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, 
					    drep, hf_eventlog_name, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, 
					    drep, hf_eventlog_unknown_string, 0);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_eventlog_unknown, NULL);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_eventlog_unknown, NULL);

	return offset;
}

static int
eventlog_dissect_openw_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_eventlog_hnd, NULL, NULL, TRUE, FALSE);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, 
			hf_eventlog_rc, NULL);

	return offset;
}

/*
 IDL 
 IDL long ElfrRegisterEventSourceW(
 IDL       [in] [unique] TYPE_6 *unknown0,
 IDL       [in] UNICODE_STRING element_26,
 IDL       [in] UNICODE_STRING element_27,
 IDL       [in] long unknown3,
 IDL       [in] long unknown3,
 IDL      [out] [context_handle] void *hEventLog,
 IDL );
 */

static int 
eventlog_dissect_register_evt_srcw_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			eventlog_dissect_TYPE_6, NDR_POINTER_UNIQUE,
			"Unknown struct pointer:", hf_eventlog_unknown);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, 
					    drep, hf_eventlog_name, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, 
					    drep, hf_eventlog_unknown_string, 0);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_eventlog_unknown, NULL);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_eventlog_unknown, NULL);

	return offset;
}

static int 
eventlog_dissect_register_evt_srcw_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_eventlog_hnd, NULL, NULL, TRUE, FALSE);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, 
			hf_eventlog_rc, NULL);

	return offset;
}

/*
 IDL NTSTATUS ElfrOpenBELW(
 IDL       [in] [unique] TYPE_6 *unknown0,
 IDL       [in] UNICODE_STRING eventlog_name,
 IDL       [in] long unknown2,
 IDL       [in] long unknown3,
 IDL      [out] [context_handle] void *hEventLog
 IDL );
 */

static int 
eventlog_dissect_open_backupw_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			eventlog_dissect_TYPE_6, NDR_POINTER_UNIQUE,
			"Unknown struct pointer:", hf_eventlog_unknown);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, 
					    drep, hf_eventlog_name, 0);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_eventlog_unknown, NULL);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_eventlog_unknown, NULL);

	return offset;
}

static int 
eventlog_dissect_open_backupw_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_eventlog_hnd, NULL, NULL, TRUE, FALSE);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, 
			hf_eventlog_rc, NULL);

	return offset;
}

/*
 IDL long ElfrReadELW(
 IDL      [in] [context_handle] void *hEventLog,
 IDL      [in] long flags,
 IDL      [in] long offset,
 IDL      [in,out] long number_of_bytes, 
 IDL     [out] [size_is(number_of_bytes)] byte *data,
 IDL     [out] long sent_size,
 IDL     [out] long real_size
 IDL   );
 */

static int 
eventlog_dissect_readw_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_eventlog_hnd, NULL, NULL, FALSE, FALSE);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_eventlog_flags, NULL);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_eventlog_offset, NULL);
	
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_eventlog_size, NULL);

	return offset;
}


/* 
 IDL typedef struct {
 IDL   char element_47[6];
 IDL } TYPE_4;
 */

/*
 IDL typedef struct {
 IDL   char element_43;
 IDL   char element_44;
 IDL   TYPE_4 element_45;
 IDL   [size_is(element_44)] byte element_46[*];
 IDL } TYPE_3;
 */

/*
 IDL long ElfrReportEventW(
 IDL       [in] [context_handle] void *hEventLog,
 IDL      [in] long element_49,
 IDL       [in] short element_50,
 IDL       [in] short element_51,
 IDL      [in] long element_52,
 IDL       [in] short element_53,
 IDL       [in] long element_54,
 IDL       [in] UNICODE_STRING element_55,
 IDL       [in] [unique] TYPE_3 *element_56,
 IDL       [in] [size_is(element_53)] [unique] byte *element_57,
 IDL       [in] [size_is(element_54)] [unique] byte *element_58,
 IDL       [in] short element_59,
 IDL   [in,out] [unique] long *element_60,
 IDL   [in,out] [unique] long *element_61
 IDL );
 */

/*
 * IDL typedef struct {
 * IDL   short length;
 * IDL   short size;
 * IDL   [size_is(size] [unique] byte *string;
 * IDL } ASCII_STRING;
 */

/*
 IDL NTSTATUS ElfrClearELFA
 IDL       [in] [context_handle] void *hEventLog,
 IDL       [in] [unique] ASCII_STRING *BackupFileName
 IDL );
 */

/*
 IDL NTSTATUS ElfrBackupELFA(
 IDL       [in] [context_handle] void *hEventLog,
 IDL       [in] ASCII_STRING BackupFileName
 IDL );
 */

/*
 IDL NTSTATUS ElfrOpenELA(
 IDL       [in] [unique] TYPE_6 *unknown0,
 IDL       [in] ASCII_STRING eventlog_name,
 IDL       [in] ASCII_STRING unknown1,
 IDL       [in] long unknown2,
 IDL       [in] long unknown3,
 IDL      [out] [context_handle] void *hEventLog,
 IDL );
 */

/*
 IDL long ElfrRegisterEventSourceA(
 IDL      [in] [unique] char *element_75,
 IDL      [in] ASCII_STRING element_76,
 IDL      [in] ASCII_STRING element_77,
 IDL      [in] long element_78,
 IDL      [in] long element_79,
 IDL     [out] [context_handle] void *hEventLog,
  );
 */


/*
 IDL NTSTATUS ElfrOpenBELA(
 IDL       [in] [unique] char *element_81,
 IDL       [in] ASCII_STRING element_82,
 IDL       [in] long element_83,
 IDL       [in] long element_84,
 IDL      [out] [context_handle] void *hEventLog
  );
 */


/*
 IDL long ElfrReadELA(
 IDL       [in] [context_handle] void *hEventLog,
 IDL       [in] long element_87,
 IDL       [in] long element_88,
 IDL       [in] long element_89,
 IDL      [out] [size_is(element_89)] byte element_90[*],
 IDL      [out] long element_91,
 IDL      [out] long element_92
 IDL );
 */

/*
 IDL long ElfrReportEventA
 IDL      [in] [context_handle] void *hEventLog,
 IDL      [in] long element_94,
 IDL      [in] short element_95,
 IDL      [in] short element_96,
 IDL      [in] long element_97,
 IDL      [in] short element_98,
 IDL      [in] long element_99,
 IDL      [in] ASCII_STRING element_100,
 IDL      [in] [unique] TYPE_3 *element_101,
 IDL      [in] [size_is(element_98)] [unique] byte *element_102,
 IDL      [in] [size_is(element_99)] [unique] byte *element_103,
 IDL      [in] short element_104,
 IDL  [in,out] [unique] long *element_105,
 IDL  [in,out] [unique] long *element_106
 IDL   );
 */


/*
 IDL long ElfrRegisterClusterSvc(
 IDL      [in] [unique] wchar_t *element_107,
 IDL      [out] long element_108,
 IDL      [out] [size_is(*element_108)] [ref] byte **element_109
 IDL );
 */

/*
 IDL long ElfrWriteClusterEvents(
 IDL      [in] [unique] wchar_t *element_110
 IDL );
 */

/*
 IDL long ElfrUnregisterClusterSvc(
 IDL       [in] [unique] wchar_t *element_111,
 IDL       [in] long element_112,
 IDL       [in] [size_is(element_112)] byte element_113[*]
 IDL );
 */




static value_string infoLevels[] = {
  { 0, "EVENTLOG_FULL_INFORMATION" },
  { 0, NULL}
};


/*
 IDL   long ElfrGetLogInformation(
 IDL        [in] [context_handle] void *hEventLog,
 IDL        [in] long dwInfoLevel,
 IDL       [out] [size_is(cbBufSize)] char lpBuffer[*],
 IDL        [in] long cbBufSize,
 IDL       [out] long cbBytesNeeded,
 IDL   );
 */

static int 
eventlog_dissect_getloginfo_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_eventlog_hnd, NULL, NULL, FALSE, FALSE);
	
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_eventlog_infolevel, NULL);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_eventlog_bufsize, NULL);

	return offset;
}


static dcerpc_sub_dissector dcerpc_eventlog_dissectors[] = {
	{ EVENTLOG_CLEAR, "ElfrClearELFW", 
		eventlog_dissect_clearw_rqst, 
		eventlog_dissect_clearw_reply},
	{ EVENTLOG_BACKUP, "ElfrBackupELFW", 
		eventlog_dissect_backupw_rqst,
		eventlog_dissect_backupw_reply },
	{ EVENTLOG_CLOSE, "ElfrCloseEL", 
		eventlog_dissect_close_rqst,	
		eventlog_dissect_close_reply },
	{ EVENTLOG_DEREGISTER_EVT_SRC, "ElfrDeregisterEventSource", 
		eventlog_dissect_deregister_evt_src_rqst,
		eventlog_dissect_deregister_evt_src_reply },
	{ EVENTLOG_NUMOFRECORDS, "ElfrNumberOfRecords",
		eventlog_dissect_getnumofrecords_rqst, 
		eventlog_dissect_getnumofrecords_reply },
	{ EVENTLOG_GET_OLDEST_RECORD, "ElfrOldestRecord", 
		eventlog_dissect_oldestrecord_rqst, 
		eventlog_dissect_oldestrecord_reply },
	{ EVENTLOG_NOTIFY_CHANGE, "ElfrChangeNotify", 
		eventlog_dissect_changenotify_rqst,
		eventlog_dissect_changenotify_reply },
	{ EVENTLOG_OPEN, "ElfrOpenELW", 
		eventlog_dissect_openw_rqst, 
		eventlog_dissect_openw_reply },
	{ EVENTLOG_REGISTER_EVT_SRC, "ElfrRegisterEventSourceW", 
		eventlog_dissect_register_evt_srcw_rqst,
		eventlog_dissect_register_evt_srcw_reply },
	{ EVENTLOG_OPEN_BACKUP, "ElfrOpenBELW", 
		eventlog_dissect_open_backupw_rqst,	
		eventlog_dissect_open_backupw_reply },
	{ EVENTLOG_READ, "ElfrReadELW", 
	 	eventlog_dissect_readw_rqst,	
		NULL },
	{ EVENTLOG_REPORT, "ElfrReportEventW", 
		NULL, NULL },
	{ EVENTLOG_CLEAR_ASCII, "ElfrClearELFA", 
		NULL, NULL },
	{ EVENTLOG_BACKUP_ASCII, "ElfrBackupELFA", 
		NULL, NULL },
	{ EVENTLOG_OPEN_ASCII, "ElfrOpenELA", 
		NULL, NULL },
	{ EVENTLOG_REGISTER_EVT_SRC_ASCII, "ElfrRegisterEventSourceA", 
		NULL, NULL },
	{ EVENTLOG_OPEN_BACKUP_ASCII, "ElfrOpenBELA", 
		NULL, NULL },
	{ EVENTLOG_READ_ASCII, "ElfrReadELA", 
		NULL, NULL },
 	{ EVENTLOG_REPORT_ASCII, "ElfrReportEventA", 
		NULL, NULL },
	{ EVENTLOG_REGISTER_CLUSTER_SVC, "ElfrRegisterClusterSvc", 
		NULL, NULL },
	{ EVENTLOG_DEREGISTER_CLUSTER_SVC, "ElfrDeregisterClusterSvc", 
		NULL, NULL }, 
	{ EVENTLOG_WRITE_CLUSTER_EVENTS, "ElfrWriteClusterEvents", 
		NULL, NULL },
	{ EVENTLOG_GET_INFO, "ElfrGetLogInformation", 
		eventlog_dissect_getloginfo_rqst,
		NULL },
	{ EVENTLOG_FLUSH, "ElfrFlushEL", 
		NULL, NULL },
        { 0, NULL, NULL,  NULL }
};


void
proto_register_dcerpc_eventlog(void)
{

        static hf_register_info hf[] = {

		{ &hf_eventlog_opnum, 
		  { "Operation", "eventlog.opnum", FT_UINT16, BASE_DEC,
		   NULL, 0x0, "Operation", HFILL }},	

	  	{ &hf_eventlog_name,
		    { "Eventlog name", "eventlog.name", FT_STRING, BASE_NONE,
		      NULL, 0x0, "Eventlog name", HFILL}},

		{&hf_eventlog_numofrecords,
		  { "Number of records", "eventlog.records", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Number of records in eventlog", HFILL }},

		{&hf_eventlog_oldest_record,
		  { "Oldest record", "eventlog.oldest_record", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Oldest record available in eventlog", HFILL }},

		{&hf_eventlog_rc,
		  { "Return code", "eventlog.rc", FT_UINT32, BASE_HEX,
		    VALS(NT_errors), 0x0, "Eventlog return status code", HFILL }}, 

	  	{ &hf_eventlog_hnd,
		    { "Context Handle", "eventlog.hnd", FT_BYTES, BASE_NONE,
		      NULL, 0x0, "Eventlog context handle", HFILL }},

	  	{ &hf_eventlog_backup_file,
		    { "Backup filename", "eventlog.backup_file", FT_STRING, BASE_NONE,
		      NULL, 0x0, "Eventlog backup file", HFILL}},

		{&hf_eventlog_infolevel,
		  { "Information level", "eventlog.info_level", FT_UINT32, BASE_DEC,
		    &infoLevels, 0x0, "Eventlog information level", HFILL }},

		{&hf_eventlog_bufsize,
		  { "Buffer size", "eventlog.buf_size", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Eventlog buffer size", HFILL }},

		{&hf_eventlog_unknown,
		  { "Unknown field", "eventlog.unknown", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Unknown field", HFILL }},

	  	{ &hf_eventlog_unknown_string,
		    { "Unknown string", "eventlog.unknown_str", FT_STRING, BASE_NONE,
		      NULL, 0x0, "Unknown string", HFILL}},

		{&hf_eventlog_flags,
		  { "Eventlog flags", "eventlog.flags", FT_UINT32, BASE_HEX,
		    NULL, 0x0, "Eventlog flags", HFILL }},

		{&hf_eventlog_offset,
		  { "Eventlog offset", "eventlog.offset", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Eventlog offset", HFILL }},

		{&hf_eventlog_size,
		  { "Eventlog size", "eventlog.size", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Eventlog size", HFILL }},

	};


        static gint *ett[] = {
                &ett_dcerpc_eventlog,
        };


	proto_dcerpc_eventlog = proto_register_protocol(
		"Microsoft Eventlog Service", "EVENTLOG", "eventlog");

	proto_register_field_array(proto_dcerpc_eventlog, hf, array_length(hf));

        proto_register_subtree_array(ett, array_length(ett));

}


void
proto_reg_handoff_dcerpc_eventlog(void)
{

	/* register protocol as dcerpc */

	dcerpc_init_uuid(
		proto_dcerpc_eventlog, ett_dcerpc_eventlog, &uuid_dcerpc_eventlog,
		ver_dcerpc_eventlog, dcerpc_eventlog_dissectors, hf_eventlog_opnum);

}
