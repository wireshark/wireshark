/* packet-iscsi.c
 * Routines for iSCSI dissection
 * Copyright 2001, Eurologic and Mark Burton <markb@ordern.com>
 *
 * Conforms to the protocol described in: draft-ietf-ips-iscsi-06.txt
 * Optionally, supports the protocol described in: draft-ietf-ips-iscsi-03.txt
 *
 * $Id: packet-iscsi.c,v 1.4 2001/06/02 08:13:04 guy Exp $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include "packet.h"
#include "prefs.h"

static int enable_03_mode = TRUE;
static int enable_bogosity_filter = TRUE;
static int bogus_pdu_data_length_threshold = 1024 * 1024;
static int bogus_pdu_max_digest_padding = 20;

/* Initialize the protocol and registered fields */
static int proto_iscsi = -1;
static int hf_iscsi_Payload = -1;
static int hf_iscsi_Opcode = -1;
static int hf_iscsi_Opcode_03 = -1;
static int hf_iscsi_Flags = -1;
#if 0
static int hf_iscsi_X = -1;
static int hf_iscsi_I = -1;
#endif
static int hf_iscsi_SCSICommand_X03 = -1;
static int hf_iscsi_SCSICommand_F = -1;
static int hf_iscsi_SCSICommand_R = -1;
static int hf_iscsi_SCSICommand_W = -1;
static int hf_iscsi_SCSICommand_Attr = -1;
static int hf_iscsi_SCSICommand_CRN = -1;
static int hf_iscsi_SCSICommand_AddCDB = -1;
static int hf_iscsi_Length03 = -1;
static int hf_iscsi_DataSegmentLength = -1;
static int hf_iscsi_TotalAHSLength = -1;
static int hf_iscsi_LUN = -1;
static int hf_iscsi_InitiatorTaskTag = -1;
static int hf_iscsi_ExpectedDataTransferLength = -1;
static int hf_iscsi_CmdSN = -1;
static int hf_iscsi_ExpStatSN = -1;
static int hf_iscsi_SCSICommand_CDB = -1;
static int hf_iscsi_SCSICommand_CDB0 = -1;
static int hf_iscsi_StatSN = -1;
static int hf_iscsi_ExpCmdSN = -1;
static int hf_iscsi_MaxCmdSN = -1;
static int hf_iscsi_SCSIResponse_o03 = -1;
static int hf_iscsi_SCSIResponse_u03 = -1;
static int hf_iscsi_SCSIResponse_O03 = -1;
static int hf_iscsi_SCSIResponse_U03 = -1;
static int hf_iscsi_SCSIResponse_o = -1;
static int hf_iscsi_SCSIResponse_u = -1;
static int hf_iscsi_SCSIResponse_O = -1;
static int hf_iscsi_SCSIResponse_U = -1;
static int hf_iscsi_SCSIResponse_S = -1;
static int hf_iscsi_CommandStatus03 = -1;
static int hf_iscsi_StatusResponse_is_status = -1;
static int hf_iscsi_StatusResponse_is_response = -1;
static int hf_iscsi_SCSIResponse_SenseLength = -1;
static int hf_iscsi_SCSIResponse_BidiReadResidualCount = -1;
static int hf_iscsi_SCSIResponse_BasicResidualCount = -1;
static int hf_iscsi_SCSIData_F = -1;
static int hf_iscsi_SCSIData_P03 = -1;
static int hf_iscsi_SCSIData_S03 = -1;
static int hf_iscsi_SCSIData_O03 = -1;
static int hf_iscsi_SCSIData_U03 = -1;
static int hf_iscsi_SCSIData_S = -1;
static int hf_iscsi_SCSIData_O = -1;
static int hf_iscsi_SCSIData_U = -1;
static int hf_iscsi_TargetTransferTag = -1;
static int hf_iscsi_DataSN = -1;
static int hf_iscsi_BufferOffset = -1;
static int hf_iscsi_SCSIData_ResidualCount = -1;
static int hf_iscsi_VersionMin = -1;
static int hf_iscsi_VersionMax = -1;
static int hf_iscsi_CID = -1;
static int hf_iscsi_ISID = -1;
static int hf_iscsi_TSID = -1;
static int hf_iscsi_InitStatSN = -1;
static int hf_iscsi_InitCmdSN = -1;
static int hf_iscsi_Login_F = -1;
static int hf_iscsi_Login_Status03 = -1;
static int hf_iscsi_Login_Status = -1;
static int hf_iscsi_KeyValue = -1;
static int hf_iscsi_Text_F = -1;
static int hf_iscsi_NOP_P = -1;
static int hf_iscsi_ExpDataSN = -1;
static int hf_iscsi_R2TExpDataSN = -1;
static int hf_iscsi_SCSITask_ReferencedTaskTag = -1;
static int hf_iscsi_SCSITask_Function = -1;
static int hf_iscsi_SCSITask_Response = -1;
static int hf_iscsi_Logout_Reason03 = -1;
static int hf_iscsi_Logout_Reason = -1;
static int hf_iscsi_Logout_Response = -1;
static int hf_iscsi_DesiredDataLength = -1;
static int hf_iscsi_SCSIEvent = -1;
static int hf_iscsi_iSCSIEvent = -1;
static int hf_iscsi_SCSIEvent03 = -1;
static int hf_iscsi_iSCSIEvent03 = -1;
static int hf_iscsi_Parameter1 = -1;
static int hf_iscsi_Parameter2 = -1;
static int hf_iscsi_Reject_Reason = -1;
static int hf_iscsi_Reject_FirstBadByte = -1;
static int hf_iscsi_Reject_Reason03 = -1;
static int hf_iscsi_SNACK_S = -1;
static int hf_iscsi_AddRuns = -1;
static int hf_iscsi_BegRun = -1;
static int hf_iscsi_RunLength = -1;
static int hf_iscsi_AdditionalRuns = -1;

/* Initialize the subtree pointers */
static gint ett_iscsi_KeyValues = -1;
static gint ett_iscsi_CDB = -1;
static gint ett_iscsi_Flags = -1;

static const value_string iscsi_opcodes[] = {
  {0x00, "NOP Out"},
  {0x40, "NOP Out (Immediate)"},
  {0x80, "NOP Out (Retry)"},

  {0x01, "SCSI Command"},
  {0x41, "SCSI Command (Immediate)"},
  {0x81, "SCSI Command (Retry)"},

  {0x02, "SCSI Task Management Command"},
  {0x42, "SCSI Task Management Command (Immediate)"},
  {0x82, "SCSI Task Management Command (Retry)"},

  {0x03, "Login Command"},
  {0x83, "Login Command (Retry)"},

  {0x04, "Text Command"},
  {0x44, "Text Command (Immediate)"},
  {0x84, "Text Command (Retry)"},

  {0x05, "SCSI Write Data"},

  {0x06, "Logout Command"},
  {0x46, "Logout Command (Immediate)"},

  {0x10, "SNACK Request (Missing Immediate bit)"},
  {0x50, "SNACK Request"},

  {0xc0, "NOP In"},
  {0xc1, "SCSI Command Response"},
  {0xc2, "SCSI Task Management Response"},
  {0xc3, "Login Response"},
  {0xc4, "Text Response"},
  {0xc5, "SCSI Read Data"},
  {0xc6, "Logout Response"},
  {0xd0, "Ready To Transfer"},
  {0xd1, "Asynchronous Message"},
  {0xef, "Reject"},
  {0, NULL},
};

static const value_string iscsi_opcodes_03[] = {
  {0x00, "NOP Out"},
  {0x01, "SCSI Command"},
  {0x02, "SCSI Task Management Command"},
  {0x03, "Login Command"},
  {0x04, "Text Command"},
  {0x05, "SCSI Write Data"},
  {0x06, "Logout Command"},
  {0x80, "NOP In"},
  {0x81, "SCSI Command Response"},
  {0x82, "SCSI Task Management Response"},
  {0x83, "Login Response"},
  {0x84, "Text Response"},
  {0x85, "SCSI Read Data"},
  {0x86, "Logout Response"},
  {0x90, "Ready To Transfer"},
  {0x91, "Asynchronous Event"},
  {0xef, "Reject"},
  {0, NULL},
};

static const true_false_string iscsi_meaning_X = {
    "Retry",
    "Not retry"
};

static const true_false_string iscsi_meaning_I = {
    "Immediate delivery",
    "Queued delivery"
};

static const true_false_string iscsi_meaning_F = {
    "Final PDU in sequence",
    "Not final PDU in sequence"
};

static const true_false_string iscsi_meaning_P = {
    "Poll requested",
    "No poll requested"
};

static const true_false_string iscsi_meaning_S = {
    "Response contains SCSI status",
    "Response does not contain SCSI status"
};

static const true_false_string iscsi_meaning_R = {
    "Data will be read from target",
    "No data will be read from target"
};

static const true_false_string iscsi_meaning_W = {
    "Data will be written to target",
    "No data will be written to target"
};

static const true_false_string iscsi_meaning_o = {
    "Read part of bi-directional command overflowed",
    "No overflow of read part of bi-directional command",
};

static const true_false_string iscsi_meaning_u = {
    "Read part of bi-directional command underflowed",
    "No underflow of read part of bi-directional command",
};

static const true_false_string iscsi_meaning_O = {
    "Residual overflow occurred",
    "No residual overflow occurred",
};

static const true_false_string iscsi_meaning_U = {
    "Residual underflow occurred",
    "No residual underflow occurred",
};

static const true_false_string iscsi_meaning_scsiresponse_S = {
    "Status/Response field contains SCSI status",
    "Status/Response field contains iSCSI response",
};

static const true_false_string iscsi_meaning_SNACK_S = {
    "Status SNACK",
    "Data SNACK",
};

static const value_string iscsi_scsicommand_taskattrs[] = {
    {0, "Untagged"},
    {1, "Simple"},
    {2, "Ordered"},
    {3, "Head of Queue"},
    {4, "ACA"},
    {0, NULL},
};

static const value_string iscsi_scsi_cdb0[] = {
    {0x00, "TEST_UNIT_READY"},
    {0x01, "REZERO_UNIT"},
    {0x03, "REQUEST_SENSE"},
    {0x04, "FORMAT_UNIT"},
    {0x05, "READ_BLOCK_LIMITS"},
    {0x07, "REASSIGN_BLOCKS"},
    {0x08, "READ_6"},
    {0x0a, "WRITE_6"},
    {0x0b, "SEEK_6"},
    {0x0f, "READ_REVERSE"},
    {0x10, "WRITE_FILEMARKS"},
    {0x11, "SPACE"},
    {0x12, "INQUIRY"},
    {0x14, "RECOVER_BUFFERED_DATA"},
    {0x15, "MODE_SELECT"},
    {0x16, "RESERVE"},
    {0x17, "RELEASE"},
    {0x18, "COPY"},
    {0x19, "ERASE"},
    {0x1a, "MODE_SENSE"},
    {0x1b, "START_STOP"},
    {0x1c, "RECEIVE_DIAGNOSTIC"},
    {0x1d, "SEND_DIAGNOSTIC"},
    {0x1e, "ALLOW_MEDIUM_REMOVAL"},
    {0x24, "SET_WINDOW"},
    {0x25, "READ_CAPACITY"},
    {0x28, "READ_10"},
    {0x2a, "WRITE_10"},
    {0x2b, "SEEK_10"},
    {0x2e, "WRITE_VERIFY"},
    {0x2f, "VERIFY"},
    {0x30, "SEARCH_HIGH"},
    {0x31, "SEARCH_EQUAL"},
    {0x32, "SEARCH_LOW"},
    {0x33, "SET_LIMITS"},
    {0x34, "PRE_FETCH"},
    {0x34, "READ_POSITION"},
    {0x35, "SYNCHRONIZE_CACHE"},
    {0x36, "LOCK_UNLOCK_CACHE"},
    {0x37, "READ_DEFECT_DATA"},
    {0x38, "MEDIUM_SCAN"},
    {0x39, "COMPARE"},
    {0x3a, "COPY_VERIFY"},
    {0x3b, "WRITE_BUFFER"},
    {0x3c, "READ_BUFFER"},
    {0x3d, "UPDATE_BLOCK"},
    {0x3e, "READ_LONG"},
    {0x3f, "WRITE_LONG"},
    {0x40, "CHANGE_DEFINITION"},
    {0x41, "WRITE_SAME"},
    {0x43, "READ_TOC"},
    {0x4c, "LOG_SELECT"},
    {0x4d, "LOG_SENSE"},
    {0x55, "MODE_SELECT_10"},
    {0x5a, "MODE_SENSE_10"},
    {0xa5, "MOVE_MEDIUM"},
    {0xa8, "READ_12"},
    {0xaa, "WRITE_12"},
    {0xae, "WRITE_VERIFY_12"},
    {0xb0, "SEARCH_HIGH_12"},
    {0xb1, "SEARCH_EQUAL_12"},
    {0xb2, "SEARCH_LOW_12"},
    {0xb8, "READ_ELEMENT_STATUS"},
    {0xb6, "SEND_VOLUME_TAG"},
    {0xea, "WRITE_LONG_2"},
    {0, NULL},
};

static const value_string iscsi_scsi_statuses[] = {
    {0x00, "Good"},
    {0x01, "Check condition"},
    {0x02, "Condition good"},
    {0x04, "Busy"},
    {0x08, "Intermediate good"},
    {0x0a, "Intermediate c good"},
    {0x0c, "Reservation conflict"},
    {0x11, "Command terminated"},
    {0x14, "Queue full"},
    {0, NULL},
};

static const value_string iscsi_scsi_responses[] = {
    {0x01, "Target failure"},
    {0x02, "Delivery subsystem failure"},
    {0x03, "Unsolicited data rejected"},
    {0x04, "SNACK rejected"},
    {0, NULL},
};

static const value_string iscsi_task_responses[] = {
    {0, "Function complete"},
    {1, "Task not in task set"},
    {2, "LUN does not exist"},
    {255, "Function rejected"},
    {0, NULL},
};

static const value_string iscsi_task_functions[] = {
    {1, "Abort Task"},
    {2, "Abort Task Set"},
    {3, "Clear ACA"},
    {4, "Clear Task Set"},
    {5, "Logical Unit Reset"},
    {6, "Target Warm Reset"},
    {7, "Target Cold Reset"},
    {0, NULL},
};

static const value_string iscsi_login_status03[] = {
    {0, "Accept Login"},
    {1, "Reject Login - unsupported version"},
    {2, "Reject Login - failed authentication"},
    {3, "Reject Login - incompatible parameters"},
    {0, NULL},
};

static const value_string iscsi_login_status[] = {
    {0x0000, "Success - Accept login"},
    {0x0001, "Success - Athenticate"},
    {0x0002, "Success - iSCSI target name required"},
    {0x0101, "Redirection - Target moved temporarily"},
    {0x0102, "Redirection - Target moved permanently"},
    {0x0103, "Redirection - Proxy required"},
    {0x0201, "Initiator error - Athentication failed"},
    {0x0202, "Initiator error - Forbidden target"},
    {0x0203, "Initiator error - Target not found"},
    {0x0204, "Initiator error - Target removed"},
    {0x0205, "Initiator error - Target conflict"},
    {0x0206, "Initiator error - Initiator SID error"},
    {0x0207, "Initiator error - Missing parameter"},
    {0x0300, "Target error - Target error"},
    {0x0301, "Target error - Service unavailable"},
    {0x0302, "Target error - Unsupported version"},
    {0, NULL},
};

static const value_string iscsi_logout_reasons03[] = {
    {0, "Remove connection - session is closing"},
    {1, "Remove connection - for recovery"},
    {2, "Remove connection - at target's request"},
    {0, NULL},
};

static const value_string iscsi_logout_reasons[] = {
    {0, "Session is closing"},
    {1, "Close connections"},
    {2, "Remove connection for recovery"},
    {3, "Remove connection at target's request"},
    {0, NULL},
};

static const value_string iscsi_logout_response[] = {
    {0, "Connection closed successfully"},
    {1, "Cleanup failed"},
    {0, NULL},
};

static const value_string iscsi_scsievents03[] = {
    {1, "Error condition encountered after command completion"},
    {2, "A newly initialised device is available to the initiator"},
    {3, "All task sets are being reset by another initiator"},
    {5, "Some other type of unit attention condition has occurred"},
    {6, "An asynchronous event has occurred"},
    {0, NULL},
};

static const value_string iscsi_iscsievents03[] = {
    {1, "Target is being reset"},
    {2, "Target requests logout"},
    {3, "Target will drop connection"},
    {0, NULL},
};

static const value_string iscsi_reject_reasons03[] = {
    {1, "Format error"},
    {2, "Header digest error"},
    {3, "Payload digest error"},
    {0, NULL},
};

static const value_string iscsi_reject_reasons[] = {
    {1, "Format error"},
    {2, "Header digest error"},
    {3, "Payload digest error"},
    {4, "Data SNACK reject"},
    {5, "Command retry reject"},
    {15, "Full feature phase command before login"},
    {0, NULL},
};

static int iscsi_min(int a, int b) {
    return (a < b)? a : b;
}

static gint addTextKeys(proto_tree *tt, tvbuff_t *tvb, gint offset, guint32 text_len) {
    const gint limit = offset + text_len;
    while(offset < limit) {
	const char *p = tvb_get_ptr(tvb, offset, 1);
	int len = strlen(p) + 1;
	if((offset + len) >= limit)
	    len = limit - offset;
	proto_tree_add_string_format(tt, hf_iscsi_KeyValue, tvb, offset, len, p, "%s", p);
	offset += len;
    }
    return offset;
}

static gint dissectCDB(proto_tree *tt, tvbuff_t *tvb, gint offset, gint cdbLen) {
    guint8 cdb0 = tvb_get_guint8(tvb, offset);
    switch(cdb0) {
    case 0x08:	/* READ_6 */
#if 0
	proto_tree_add_uint(tt, hf_iscsi_SCSICommand_CDB0, tvb, offset, 1, cdb0);
#endif
    default:
	proto_tree_add_bytes(tt, hf_iscsi_SCSICommand_CDB, tvb, offset, cdbLen, tvb_get_ptr(tvb, offset, cdbLen));
    }
    return offset + cdbLen;
}

/* Code to actually dissect the packets */
static gboolean
dissect_iscsi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {

    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    gint offset = 0;
    guint32 data_segment_len;
    guint8 opcode;
    const char *opcode_str;
    guint32 packet_len = tvb_length_remaining(tvb, offset);

    /* quick check to see if the packet is long enough to contain a
     * whole iSCSI header segment */
    if (packet_len < 48) {
	/* no, so give up */
	return FALSE;
    }

    opcode = tvb_get_guint8(tvb, offset + 0);

    if(enable_03_mode) {
	opcode_str = match_strval(opcode, iscsi_opcodes_03);
	data_segment_len = tvb_get_ntohl(tvb, offset + 4);
    }
    else {
	opcode_str = match_strval(opcode, iscsi_opcodes);
	data_segment_len = tvb_get_ntohl(tvb, offset + 4) & 0x00ffffff;
    }

    /* try and distinguish between data and real headers */
    if(opcode_str == NULL ||
       (enable_bogosity_filter &&
	(data_segment_len > bogus_pdu_data_length_threshold ||
	 packet_len > (data_segment_len + 48 + bogus_pdu_max_digest_padding)))) {
	return FALSE;
    }

    /* Make entries in Protocol column and Info column on summary display */
    if (check_col(pinfo->fd, COL_PROTOCOL))
	col_set_str(pinfo->fd, COL_PROTOCOL, "iSCSI");


    if (check_col(pinfo->fd, COL_INFO)) {

	col_add_str(pinfo->fd, COL_INFO, (char *)opcode_str);

	if((opcode & 0xbf) == 0x01) {
	    const char *scsiCommandName = match_strval(tvb_get_guint8(tvb, offset + 32),
						       iscsi_scsi_cdb0);
	    if(scsiCommandName != NULL)
		col_append_fstr(pinfo->fd, COL_INFO, " (%s)", scsiCommandName);
	}
	else if(enable_03_mode && opcode == 0x81) {
	    const char *blurb = match_strval(tvb_get_guint8(tvb, offset + 36), iscsi_scsi_statuses);
	    if(blurb != NULL)
		col_append_fstr(pinfo->fd, COL_INFO, " (%s)", blurb);
	}
	else if(!enable_03_mode && opcode == 0xc1) {
	    const char *blurb = NULL;
	    if(tvb_get_guint8(tvb, offset + 1) & 0x01)
		blurb = match_strval(tvb_get_guint8(tvb, offset + 3), iscsi_scsi_statuses);
	    else
		blurb = match_strval(tvb_get_guint8(tvb, offset + 3), iscsi_scsi_responses);
	    if(blurb != NULL)
		col_append_fstr(pinfo->fd, COL_INFO, " (%s)", blurb);
	}
    }

    /* In the interest of speed, if "tree" is NULL, don't do any
       work not necessary to generate protocol tree items. */
    if (tree) {

	/* create display subtree for the protocol */
	ti = proto_tree_add_protocol_format(tree, proto_iscsi, tvb, offset,
				 packet_len, "iSCSI (%s)", (char *)opcode_str);

	if((enable_03_mode && opcode == 0x00) ||
	   (!enable_03_mode && (opcode == 0x00 ||
				opcode == 0x40 ||
				opcode == 0x80))) {
	    /* NOP Out */
	    if(enable_03_mode) {
		proto_tree_add_uint(ti, hf_iscsi_Opcode_03, tvb, 
				    offset + 0, 1, opcode);
	    }
	    else {
		proto_tree_add_uint(ti, hf_iscsi_Opcode, tvb,
				    offset + 0, 1, opcode);
	    }
	    {
		gint b = tvb_get_guint8(tvb, offset + 1);
		proto_item *tf = proto_tree_add_uint(ti, hf_iscsi_Flags, tvb, offset + 1, 1, b);
		proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_Flags);
		proto_tree_add_boolean(tt, hf_iscsi_NOP_P, tvb, offset + 1, 1, b);
	    }
	    if(enable_03_mode) {
		proto_tree_add_uint(ti, hf_iscsi_Length03, tvb, offset + 4, 4, data_segment_len);
	    }
	    else {
		proto_tree_add_uint(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, data_segment_len);
	    }
	    proto_tree_add_bytes(ti, hf_iscsi_LUN, tvb, offset + 8, 8, tvb_get_ptr(tvb, offset + 8, 8));
	    proto_tree_add_uint(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, tvb_get_ntohl(tvb, offset + 16));
	    proto_tree_add_uint(ti, hf_iscsi_TargetTransferTag, tvb, offset + 20, 4, tvb_get_ntohl(tvb, offset + 20));
	    proto_tree_add_uint(ti, hf_iscsi_CmdSN, tvb, offset + 24, 4, tvb_get_ntohl(tvb, offset + 24));
	    proto_tree_add_uint(ti, hf_iscsi_ExpStatSN, tvb, offset + 28, 4, tvb_get_ntohl(tvb, offset + 28));
	    if(enable_03_mode) {
		proto_tree_add_uint(ti, hf_iscsi_ExpDataSN, tvb, offset + 32, 4, tvb_get_ntohl(tvb, offset + 32));
	    }
	    proto_tree_add_uint(ti, hf_iscsi_BufferOffset, tvb, offset + 40, 4, tvb_get_ntohl(tvb, offset + 40));
	    offset += 48;
	}
	else if((enable_03_mode && opcode == 0x80) ||
		(!enable_03_mode && opcode == 0xc0)) {
	    /* NOP In */
	    if(enable_03_mode) {
		proto_tree_add_uint(ti, hf_iscsi_Opcode_03, tvb, 
				    offset + 0, 1, opcode);
	    }
	    else {
		proto_tree_add_uint(ti, hf_iscsi_Opcode, tvb,
				    offset + 0, 1, opcode);
	    }
	    {
		gint b = tvb_get_guint8(tvb, offset + 1);
		proto_item *tf = proto_tree_add_uint(ti, hf_iscsi_Flags, tvb, offset + 1, 1, b);
		proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_Flags);
		proto_tree_add_boolean(tt, hf_iscsi_NOP_P, tvb, offset + 1, 1, b);
	    }
	    if(enable_03_mode) {
		proto_tree_add_uint(ti, hf_iscsi_Length03, tvb, offset + 4, 4, data_segment_len);
	    }
	    else {
		proto_tree_add_uint(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, data_segment_len);
	    }
	    proto_tree_add_uint(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, tvb_get_ntohl(tvb, offset + 16));
	    proto_tree_add_uint(ti, hf_iscsi_TargetTransferTag, tvb, offset + 20, 4, tvb_get_ntohl(tvb, offset + 20));
	    proto_tree_add_uint(ti, hf_iscsi_StatSN, tvb, offset + 24, 4, tvb_get_ntohl(tvb, offset + 24));
	    proto_tree_add_uint(ti, hf_iscsi_ExpCmdSN, tvb, offset + 28, 4, tvb_get_ntohl(tvb, offset + 28));
	    proto_tree_add_uint(ti, hf_iscsi_MaxCmdSN, tvb, offset + 32, 4, tvb_get_ntohl(tvb, offset + 32));
	    offset += 48;
	}
	else if((enable_03_mode && opcode == 0x01) ||
		(!enable_03_mode && (opcode == 0x01 ||
				     opcode == 0x41 ||
				     opcode == 0x81))) {
	    /* SCSI Command */
	    if(enable_03_mode) {
		proto_tree_add_uint(ti, hf_iscsi_Opcode_03, tvb, 
				    offset + 0, 1, opcode);
		{
		    gint b = tvb_get_guint8(tvb, offset + 1);
		    proto_item *tf = proto_tree_add_uint(ti, hf_iscsi_Flags, tvb, offset + 1, 1, b);
		    proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_Flags);

		    proto_tree_add_boolean(tt, hf_iscsi_SCSICommand_X03, tvb, offset + 1, 1, b);
		    proto_tree_add_boolean(tt, hf_iscsi_SCSICommand_R, tvb, offset + 1, 1, b);
		    proto_tree_add_boolean(tt, hf_iscsi_SCSICommand_W, tvb, offset + 1, 1, b);
		    proto_tree_add_uint(tt, hf_iscsi_SCSICommand_Attr, tvb, offset + 1, 1, b);
		}
		proto_tree_add_uint(ti, hf_iscsi_SCSICommand_AddCDB, tvb, offset + 3, 1, tvb_get_guint8(tvb, offset + 3));
		proto_tree_add_uint(ti, hf_iscsi_Length03, tvb, offset + 4, 4, data_segment_len);
	    }
	    else {
		proto_tree_add_uint(ti, hf_iscsi_Opcode, tvb,
				    offset + 0, 1, opcode);
		{
		    gint b = tvb_get_guint8(tvb, offset + 1);
		    proto_item *tf = proto_tree_add_uint(ti, hf_iscsi_Flags, tvb, offset + 1, 1, b);
		    proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_Flags);

		    proto_tree_add_boolean(tt, hf_iscsi_SCSICommand_F, tvb, offset + 1, 1, b);
		    proto_tree_add_boolean(tt, hf_iscsi_SCSICommand_R, tvb, offset + 1, 1, b);
		    proto_tree_add_boolean(tt, hf_iscsi_SCSICommand_W, tvb, offset + 1, 1, b);
		    proto_tree_add_uint(tt, hf_iscsi_SCSICommand_Attr, tvb, offset + 1, 1, b);
		}
		proto_tree_add_uint(ti, hf_iscsi_SCSICommand_CRN, tvb, offset + 3, 1, tvb_get_guint8(tvb, offset + 3));
		proto_tree_add_uint(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, tvb_get_guint8(tvb, offset + 4));
		proto_tree_add_uint(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, data_segment_len);
	    }
	    proto_tree_add_bytes(ti, hf_iscsi_LUN, tvb, offset + 8, 8, tvb_get_ptr(tvb, offset + 8, 8));
	    proto_tree_add_uint(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, tvb_get_ntohl(tvb, offset + 16));
	    proto_tree_add_uint(ti, hf_iscsi_ExpectedDataTransferLength, tvb, offset + 20, 4, tvb_get_ntohl(tvb, offset + 20));
	    proto_tree_add_uint(ti, hf_iscsi_CmdSN, tvb, offset + 24, 4, tvb_get_ntohl(tvb, offset + 24));
	    proto_tree_add_uint(ti, hf_iscsi_ExpStatSN, tvb, offset + 28, 4, tvb_get_ntohl(tvb, offset + 28));
	    {
		guint8 cdb0 = tvb_get_guint8(tvb, offset + 32);
		proto_item *tf = proto_tree_add_uint(ti, hf_iscsi_SCSICommand_CDB0, tvb, offset + 32, 1, cdb0);
		proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_CDB);
		dissectCDB(tt, tvb, offset + 32, 16 + tvb_get_guint8(tvb, offset + 3) * 4);
	    }
	    offset += 48;
	}
	else if((enable_03_mode && opcode == 0x81) ||
		(!enable_03_mode && opcode == 0xc1)) {
	    /* SCSI Response */
	    if(enable_03_mode) {
		proto_tree_add_uint(ti, hf_iscsi_Opcode_03, tvb, 
				    offset + 0, 1, opcode);
		{
		    gint b = tvb_get_guint8(tvb, offset + 1);
		    proto_item *tf = proto_tree_add_uint(ti, hf_iscsi_Flags, tvb, offset + 1, 1, b);
		    proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_Flags);

		    proto_tree_add_boolean(tt, hf_iscsi_SCSIResponse_o03, tvb, offset + 1, 1, b);
		    proto_tree_add_boolean(tt, hf_iscsi_SCSIResponse_u03, tvb, offset + 1, 1, b);
		    proto_tree_add_boolean(tt, hf_iscsi_SCSIResponse_O03, tvb, offset + 1, 1, b);
		    proto_tree_add_boolean(tt, hf_iscsi_SCSIResponse_U03, tvb, offset + 1, 1, b);
		}
		proto_tree_add_uint(ti, hf_iscsi_Length03, tvb, offset + 4, 4, data_segment_len);
	    }
	    else {
		proto_tree_add_uint(ti, hf_iscsi_Opcode, tvb,
				    offset + 0, 1, opcode);
		{
		    gint b = tvb_get_guint8(tvb, offset + 1);
		    proto_item *tf = proto_tree_add_uint(ti, hf_iscsi_Flags, tvb, offset + 1, 1, b);
		    proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_Flags);

		    proto_tree_add_boolean(tt, hf_iscsi_SCSIResponse_o, tvb, offset + 1, 1, b);
		    proto_tree_add_boolean(tt, hf_iscsi_SCSIResponse_u, tvb, offset + 1, 1, b);
		    proto_tree_add_boolean(tt, hf_iscsi_SCSIResponse_O, tvb, offset + 1, 1, b);
		    proto_tree_add_boolean(tt, hf_iscsi_SCSIResponse_U, tvb, offset + 1, 1, b);
		    proto_tree_add_boolean(tt, hf_iscsi_SCSIResponse_S, tvb, offset + 1, 1, b);
		    if(b & 0x01)
			proto_tree_add_uint(ti, hf_iscsi_StatusResponse_is_status, tvb, offset + 3, 1, tvb_get_guint8(tvb, offset + 3));
		    else
			proto_tree_add_uint(ti, hf_iscsi_StatusResponse_is_response, tvb, offset + 3, 1, tvb_get_guint8(tvb, offset + 3));
		}
		proto_tree_add_uint(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, data_segment_len);
	    }
	    proto_tree_add_uint(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, tvb_get_ntohl(tvb, offset + 16));
	    proto_tree_add_uint(ti, hf_iscsi_SCSIResponse_BasicResidualCount, tvb, offset + 20, 4, tvb_get_ntohl(tvb, offset + 20));
	    proto_tree_add_uint(ti, hf_iscsi_StatSN, tvb, offset + 24, 4, tvb_get_ntohl(tvb, offset + 24));
	    proto_tree_add_uint(ti, hf_iscsi_ExpCmdSN, tvb, offset + 28, 4, tvb_get_ntohl(tvb, offset + 28));
	    proto_tree_add_uint(ti, hf_iscsi_MaxCmdSN, tvb, offset + 32, 4, tvb_get_ntohl(tvb, offset + 32));
	    if(enable_03_mode) {
		proto_tree_add_uint(ti, hf_iscsi_CommandStatus03, tvb, offset + 36, 1, tvb_get_guint8(tvb, offset + 36));
		proto_tree_add_uint(ti, hf_iscsi_SCSIResponse_SenseLength, tvb, offset + 40, 2, tvb_get_ntohs(tvb, offset + 40));
	    }
	    else {
		proto_tree_add_uint(ti, hf_iscsi_ExpDataSN, tvb, offset + 36, 4, tvb_get_ntohl(tvb, offset + 36));
		proto_tree_add_uint(ti, hf_iscsi_R2TExpDataSN, tvb, offset + 40, 4, tvb_get_ntohl(tvb, offset + 40));
	    }
	    proto_tree_add_uint(ti, hf_iscsi_SCSIResponse_BidiReadResidualCount, tvb, offset + 44, 4, tvb_get_ntohl(tvb, offset + 44));
	    offset += 48;
	}
	else if((enable_03_mode && opcode == 0x02) ||
		(!enable_03_mode && (opcode == 0x02 ||
				     opcode == 0x42 ||
				     opcode == 0x82))) {
	    /* SCSI Task Command */
	    if(enable_03_mode) {
		proto_tree_add_uint(ti, hf_iscsi_Opcode_03, tvb, 
				    offset + 0, 1, opcode);
	    }
	    else {
		proto_tree_add_uint(ti, hf_iscsi_Opcode, tvb,
				    offset + 0, 1, opcode);
	    }
	    proto_tree_add_uint(ti, hf_iscsi_SCSITask_Function, tvb, offset + 1, 1, tvb_get_guint8(tvb, offset + 1));
	    if(enable_03_mode) {
		proto_tree_add_uint(ti, hf_iscsi_Length03, tvb, offset + 4, 4, data_segment_len);
	    }
	    proto_tree_add_bytes(ti, hf_iscsi_LUN, tvb, offset + 8, 8, tvb_get_ptr(tvb, offset + 8, 8));
	    proto_tree_add_uint(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, tvb_get_ntohl(tvb, offset + 16));
	    proto_tree_add_uint(ti, hf_iscsi_SCSITask_ReferencedTaskTag, tvb, offset + 20, 4, tvb_get_ntohl(tvb, offset + 20));
	    proto_tree_add_uint(ti, hf_iscsi_CmdSN, tvb, offset + 24, 4, tvb_get_ntohl(tvb, offset + 24));
	    proto_tree_add_uint(ti, hf_iscsi_ExpStatSN, tvb, offset + 28, 4, tvb_get_ntohl(tvb, offset + 28));
	    offset += 48;
	}
	else if((enable_03_mode && opcode == 0x82) ||
		(!enable_03_mode && opcode == 0xc2)) {
	    /* SCSI Task Response */
	    if(enable_03_mode) {
		proto_tree_add_uint(ti, hf_iscsi_Opcode_03, tvb, 
				    offset + 0, 1, opcode);
		proto_tree_add_uint(ti, hf_iscsi_Length03, tvb, offset + 4, 4, data_segment_len);
	    }
	    else {
		proto_tree_add_uint(ti, hf_iscsi_Opcode, tvb,
				    offset + 0, 1, opcode);
	    }
	    proto_tree_add_bytes(ti, hf_iscsi_LUN, tvb, offset + 8, 8, tvb_get_ptr(tvb, offset + 8, 8));
	    proto_tree_add_uint(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, tvb_get_ntohl(tvb, offset + 16));
	    proto_tree_add_uint(ti, hf_iscsi_SCSITask_ReferencedTaskTag, tvb, offset + 20, 4, tvb_get_ntohl(tvb, offset + 20));
	    proto_tree_add_uint(ti, hf_iscsi_StatSN, tvb, offset + 24, 4, tvb_get_ntohl(tvb, offset + 24));
	    proto_tree_add_uint(ti, hf_iscsi_ExpCmdSN, tvb, offset + 28, 4, tvb_get_ntohl(tvb, offset + 28));
	    proto_tree_add_uint(ti, hf_iscsi_MaxCmdSN, tvb, offset + 32, 4, tvb_get_ntohl(tvb, offset + 32));
	    proto_tree_add_uint(ti, hf_iscsi_SCSITask_Response, tvb, offset + 36, 1, tvb_get_guint8(tvb, offset + 36));
	    offset += 48;
	}
	else if((enable_03_mode && opcode == 0x03) ||
		(!enable_03_mode && (opcode == 0x03 ||
				     opcode == 0x83))) {
	    /* Login Command */
	    if(enable_03_mode) {
		proto_tree_add_uint(ti, hf_iscsi_Opcode_03, tvb, 
				    offset + 0, 1, opcode);
	    }
	    else {
		proto_tree_add_uint(ti, hf_iscsi_Opcode, tvb,
				    offset + 0, 1, opcode);
		{
		    gint b = tvb_get_guint8(tvb, offset + 1);
		    proto_item *tf = proto_tree_add_uint(ti, hf_iscsi_Flags, tvb, offset + 1, 1, b);
		    proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_Flags);

		    proto_tree_add_boolean(tt, hf_iscsi_Login_F, tvb, offset + 1, 1, b);
		}
	    }
	    proto_tree_add_uint(ti, hf_iscsi_VersionMax, tvb, offset + 2, 1, tvb_get_guint8(tvb, offset + 2));
	    proto_tree_add_uint(ti, hf_iscsi_VersionMin, tvb, offset + 3, 1, tvb_get_guint8(tvb, offset + 3));
	    if(enable_03_mode) {
		proto_tree_add_uint(ti, hf_iscsi_Length03, tvb, offset + 4, 4, data_segment_len);
	    }
	    else {
		proto_tree_add_uint(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, data_segment_len);
	    }
	    proto_tree_add_uint(ti, hf_iscsi_CID, tvb, offset + 8, 2, tvb_get_ntohs(tvb, offset + 8));
	    proto_tree_add_uint(ti, hf_iscsi_ISID, tvb, offset + 12, 2, tvb_get_ntohs(tvb, offset + 12));
	    proto_tree_add_uint(ti, hf_iscsi_TSID, tvb, offset + 14, 2, tvb_get_ntohs(tvb, offset + 14));
	    proto_tree_add_uint(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, tvb_get_ntohl(tvb, offset + 16));
	    if(enable_03_mode) {
		proto_tree_add_uint(ti, hf_iscsi_InitCmdSN, tvb, offset + 24, 4, tvb_get_ntohl(tvb, offset + 24));
	    }
	    else {
		proto_tree_add_uint(ti, hf_iscsi_CmdSN, tvb, offset + 24, 4, tvb_get_ntohl(tvb, offset + 24));
		proto_tree_add_uint(ti, hf_iscsi_ExpStatSN, tvb, offset + 28, 4, tvb_get_ntohl(tvb, offset + 28));
	    }
	    offset += 48;
	    if(packet_len > 48) {
		int text_len = iscsi_min(data_segment_len, packet_len - 48);
		proto_item *tf = proto_tree_add_text(ti, tvb, 48, text_len, "Key/Value Pairs");
		proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_KeyValues);
		offset = addTextKeys(tt, tvb, 48, text_len);
	    }
	}
	else if((enable_03_mode && opcode == 0x83) ||
		(!enable_03_mode && opcode == 0xc3)) {
	    /* Login Response */
	    if(enable_03_mode) {
		proto_tree_add_uint(ti, hf_iscsi_Opcode_03, tvb, 
				    offset + 0, 1, opcode);
	    }
	    else {
		proto_tree_add_uint(ti, hf_iscsi_Opcode, tvb,
				    offset + 0, 1, opcode);
	    }
	    {
		gint b = tvb_get_guint8(tvb, offset + 1);
		proto_item *tf = proto_tree_add_uint(ti, hf_iscsi_Flags, tvb, offset + 1, 1, b);
		proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_Flags);

		proto_tree_add_boolean(tt, hf_iscsi_Login_F, tvb, offset + 1, 1, b);
	    }
	    proto_tree_add_uint(ti, hf_iscsi_VersionMax, tvb, offset + 2, 1, tvb_get_guint8(tvb, offset + 2));
	    proto_tree_add_uint(ti, hf_iscsi_VersionMin, tvb, offset + 3, 1, tvb_get_guint8(tvb, offset + 3));
	    if(enable_03_mode) {
		proto_tree_add_uint(ti, hf_iscsi_Length03, tvb, offset + 4, 4, data_segment_len);
	    }
	    else {
		proto_tree_add_uint(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, data_segment_len);
	    }
	    proto_tree_add_uint(ti, hf_iscsi_ISID, tvb, offset + 12, 2, tvb_get_ntohs(tvb, offset + 12));
	    proto_tree_add_uint(ti, hf_iscsi_TSID, tvb, offset + 14, 2, tvb_get_ntohs(tvb, offset + 14));
	    proto_tree_add_uint(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, tvb_get_ntohl(tvb, offset + 16));
	    proto_tree_add_uint(ti, hf_iscsi_InitStatSN, tvb, offset + 24, 4, tvb_get_ntohl(tvb, offset + 24));
	    proto_tree_add_uint(ti, hf_iscsi_ExpCmdSN, tvb, offset + 28, 4, tvb_get_ntohl(tvb, offset + 28));
	    proto_tree_add_uint(ti, hf_iscsi_MaxCmdSN, tvb, offset + 32, 4, tvb_get_ntohl(tvb, offset + 32));
	    if(enable_03_mode) {
		proto_tree_add_uint(ti, hf_iscsi_Login_Status03, tvb, offset + 36, 1, tvb_get_guint8(tvb, offset + 36));
	    }
	    else {
		proto_tree_add_uint(ti, hf_iscsi_Login_Status, tvb, offset + 36, 1, tvb_get_ntohs(tvb, offset + 36));
	    }
	    offset += 48;
	    if(packet_len > 48) {
		int text_len = iscsi_min(data_segment_len, packet_len - 48);
		proto_item *tf = proto_tree_add_text(ti, tvb, 48, text_len, "Key/Value Pairs");
		proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_KeyValues);
		offset = addTextKeys(tt, tvb, 48, text_len);
	    }
	}
	else if((enable_03_mode && opcode == 0x04) ||
		(!enable_03_mode && (opcode == 0x04 ||
				     opcode == 0x44 ||
				     opcode == 0x84))) {
	    /* Text Command */
	    if(enable_03_mode) {
		proto_tree_add_uint(ti, hf_iscsi_Opcode_03, tvb, 
				    offset + 0, 1, opcode);
		proto_tree_add_uint(ti, hf_iscsi_Length03, tvb, offset + 4, 4, data_segment_len);
	    }
	    else {
		proto_tree_add_uint(ti, hf_iscsi_Opcode, tvb,
				    offset + 0, 1, opcode);
		{
		    gint b = tvb_get_guint8(tvb, offset + 1);
		    proto_item *tf = proto_tree_add_uint(ti, hf_iscsi_Flags, tvb, offset + 1, 1, b);
		    proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_Flags);

		    proto_tree_add_boolean(tt, hf_iscsi_Text_F, tvb, offset + 1, 1, b);
		}
		proto_tree_add_uint(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, data_segment_len);
	    }
	    proto_tree_add_uint(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, tvb_get_ntohl(tvb, offset + 16));
	    proto_tree_add_uint(ti, hf_iscsi_CmdSN, tvb, offset + 24, 4, tvb_get_ntohl(tvb, offset + 24));
	    proto_tree_add_uint(ti, hf_iscsi_ExpStatSN, tvb, offset + 28, 4, tvb_get_ntohl(tvb, offset + 28));
	    offset += 48;
	    if(packet_len > 48) {
		int text_len = iscsi_min(data_segment_len, packet_len - 48);
		proto_item *tf = proto_tree_add_text(ti, tvb, 48, text_len, "Key/Value Pairs");
		proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_KeyValues);
		offset = addTextKeys(tt, tvb, 48, text_len);
	    }
	}
	else if((enable_03_mode && opcode == 0x84) ||
		(!enable_03_mode && (opcode == 0xc4))) {
	    /* Text Response */
	    if(enable_03_mode) {
		proto_tree_add_uint(ti, hf_iscsi_Opcode_03, tvb, 
				    offset + 0, 1, opcode);
		proto_tree_add_uint(ti, hf_iscsi_Length03, tvb, offset + 4, 4, data_segment_len);
	    }
	    else {
		proto_tree_add_uint(ti, hf_iscsi_Opcode, tvb,
				    offset + 0, 1, opcode);
		{
		    gint b = tvb_get_guint8(tvb, offset + 1);
		    proto_item *tf = proto_tree_add_uint(ti, hf_iscsi_Flags, tvb, offset + 1, 1, b);
		    proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_Flags);

		    proto_tree_add_boolean(tt, hf_iscsi_Text_F, tvb, offset + 1, 1, b);
		}
		proto_tree_add_uint(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, data_segment_len);
	    }
	    proto_tree_add_uint(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, tvb_get_ntohl(tvb, offset + 16));
	    proto_tree_add_uint(ti, hf_iscsi_StatSN, tvb, offset + 24, 4, tvb_get_ntohl(tvb, offset + 24));
	    proto_tree_add_uint(ti, hf_iscsi_ExpCmdSN, tvb, offset + 28, 4, tvb_get_ntohl(tvb, offset + 28));
	    proto_tree_add_uint(ti, hf_iscsi_MaxCmdSN, tvb, offset + 32, 4, tvb_get_ntohl(tvb, offset + 32));
	    offset += 48;
	    if(packet_len > 48) {
		int text_len = iscsi_min(data_segment_len, packet_len - 48);
		proto_item *tf = proto_tree_add_text(ti, tvb, 48, text_len, "Key/Value Pairs");
		proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_KeyValues);
		offset = addTextKeys(tt, tvb, 48, text_len);
	    }
	}
	else if(opcode == 0x05) {
	    /* SCSI Data (write) */
	    if(enable_03_mode) {
		proto_tree_add_uint(ti, hf_iscsi_Opcode_03, tvb, 
				    offset + 0, 1, opcode);
	    }
	    else {
		proto_tree_add_uint(ti, hf_iscsi_Opcode, tvb,
				    offset + 0, 1, opcode);
	    }
	    {
		gint b = tvb_get_guint8(tvb, offset + 1);
		proto_item *tf = proto_tree_add_uint(ti, hf_iscsi_Flags, tvb, offset + 1, 1, b);
		proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_Flags);

		proto_tree_add_boolean(tt, hf_iscsi_SCSIData_F, tvb, offset + 1, 1, b);
	    }
	    if(enable_03_mode) {
		proto_tree_add_uint(ti, hf_iscsi_Length03, tvb, offset + 4, 4, data_segment_len);
	    }
	    else {
		proto_tree_add_uint(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, data_segment_len);
	    }
	    proto_tree_add_bytes(ti, hf_iscsi_LUN, tvb, offset + 8, 8, tvb_get_ptr(tvb, offset + 8, 8));
	    proto_tree_add_uint(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, tvb_get_ntohl(tvb, offset + 16));
	    proto_tree_add_uint(ti, hf_iscsi_TargetTransferTag, tvb, offset + 20, 4, tvb_get_ntohl(tvb, offset + 20));
	    proto_tree_add_uint(ti, hf_iscsi_ExpStatSN, tvb, offset + 28, 4, tvb_get_ntohl(tvb, offset + 28));
	    if(!enable_03_mode)
		proto_tree_add_uint(ti, hf_iscsi_DataSN, tvb, offset + 36, 4, tvb_get_ntohl(tvb, offset + 36));
	    proto_tree_add_uint(ti, hf_iscsi_BufferOffset, tvb, offset + 40, 4, tvb_get_ntohl(tvb, offset + 40));
	    offset += 48;
	}
	else if((enable_03_mode && opcode == 0x85) ||
		(!enable_03_mode && opcode == 0xc5)) {
	    /* SCSI Data (read) */
	    if(enable_03_mode) {
		proto_tree_add_uint(ti, hf_iscsi_Opcode_03, tvb, 
				    offset + 0, 1, opcode);
		{
		    gint b = tvb_get_guint8(tvb, offset + 1);
		    proto_item *tf = proto_tree_add_uint(ti, hf_iscsi_Flags, tvb, offset + 1, 1, b);
		    proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_Flags);

		    proto_tree_add_boolean(tt, hf_iscsi_SCSIData_P03, tvb, offset + 1, 1, b);
		    proto_tree_add_boolean(tt, hf_iscsi_SCSIData_S03, tvb, offset + 1, 1, b);
		    proto_tree_add_boolean(tt, hf_iscsi_SCSIData_O03, tvb, offset + 1, 1, b);
		    proto_tree_add_boolean(tt, hf_iscsi_SCSIData_U03, tvb, offset + 1, 1, b);
		}
		proto_tree_add_uint(ti, hf_iscsi_Length03, tvb, offset + 4, 4, data_segment_len);
	    }
	    else {
		proto_tree_add_uint(ti, hf_iscsi_Opcode, tvb,
				    offset + 0, 1, opcode);
		{
		    gint b = tvb_get_guint8(tvb, offset + 1);
		    proto_item *tf = proto_tree_add_uint(ti, hf_iscsi_Flags, tvb, offset + 1, 1, b);
		    proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_Flags);

		    proto_tree_add_boolean(tt, hf_iscsi_SCSIData_F, tvb, offset + 1, 1, b);
		    proto_tree_add_boolean(tt, hf_iscsi_SCSIData_O, tvb, offset + 1, 1, b);
		    proto_tree_add_boolean(tt, hf_iscsi_SCSIData_U, tvb, offset + 1, 1, b);
		    proto_tree_add_boolean(tt, hf_iscsi_SCSIData_S, tvb, offset + 1, 1, b);
		}
		proto_tree_add_uint(ti, hf_iscsi_StatusResponse_is_status, tvb, offset + 3, 1, tvb_get_guint8(tvb, offset + 3));
		proto_tree_add_uint(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, data_segment_len);
	    }
	    proto_tree_add_uint(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, tvb_get_ntohl(tvb, offset + 16));
	    if(enable_03_mode) {
		proto_tree_add_uint(ti, hf_iscsi_TargetTransferTag, tvb, offset + 20, 4, tvb_get_ntohl(tvb, offset + 20));
	    }
	    proto_tree_add_uint(ti, hf_iscsi_StatSN, tvb, offset + 24, 4, tvb_get_ntohl(tvb, offset + 24));
	    proto_tree_add_uint(ti, hf_iscsi_ExpCmdSN, tvb, offset + 28, 4, tvb_get_ntohl(tvb, offset + 28));
	    proto_tree_add_uint(ti, hf_iscsi_MaxCmdSN, tvb, offset + 32, 4, tvb_get_ntohl(tvb, offset + 32));
	    if(enable_03_mode) {
		proto_tree_add_uint(ti, hf_iscsi_CommandStatus03, tvb, offset + 36, 1, tvb_get_guint8(tvb, offset + 36));
	    }
	    else {
		proto_tree_add_uint(ti, hf_iscsi_DataSN, tvb, offset + 36, 4, tvb_get_ntohl(tvb, offset + 36));
	    }
	    proto_tree_add_uint(ti, hf_iscsi_BufferOffset, tvb, offset + 40, 4, tvb_get_ntohl(tvb, offset + 40));
	    proto_tree_add_uint(ti, hf_iscsi_SCSIData_ResidualCount, tvb, offset + 44, 4, tvb_get_ntohl(tvb, offset + 44));
	    offset += 48;
	}
	else if((enable_03_mode && opcode == 0x06) ||
		(!enable_03_mode && (opcode == 0x06 || opcode == 0x46))) {
	    /* Logout Command */
	    if(enable_03_mode) {
		proto_tree_add_uint(ti, hf_iscsi_Opcode_03, tvb, 
				    offset + 0, 1, opcode);
		proto_tree_add_uint(ti, hf_iscsi_Length03, tvb, offset + 4, 4, data_segment_len);
	    }
	    else {
		proto_tree_add_uint(ti, hf_iscsi_Opcode, tvb,
				    offset + 0, 1, opcode);
		proto_tree_add_uint(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, data_segment_len);
	    }
	    proto_tree_add_uint(ti, hf_iscsi_CID, tvb, offset + 8, 2, tvb_get_ntohs(tvb, offset + 8));
	    if(enable_03_mode)
		proto_tree_add_uint(ti, hf_iscsi_Logout_Reason03, tvb, offset + 11, 1, tvb_get_guint8(tvb, offset + 11));
	    else
		proto_tree_add_uint(ti, hf_iscsi_Logout_Reason, tvb, offset + 11, 1, tvb_get_guint8(tvb, offset + 11));
	    proto_tree_add_uint(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, tvb_get_ntohl(tvb, offset + 16));
	    if(!enable_03_mode) {
		proto_tree_add_uint(ti, hf_iscsi_ExpStatSN, tvb, offset + 28, 4, tvb_get_ntohl(tvb, offset + 28));
	    }
	    offset += 48;
	}
	else if((enable_03_mode && opcode == 0x86) ||
		(!enable_03_mode && opcode == 0xc6)) {
	    /* Logout Response */
	    if(enable_03_mode) {
		proto_tree_add_uint(ti, hf_iscsi_Opcode_03, tvb, 
				    offset + 0, 1, opcode);
		proto_tree_add_uint(ti, hf_iscsi_Length03, tvb, offset + 4, 4, data_segment_len);
	    }
	    else {
		proto_tree_add_uint(ti, hf_iscsi_Opcode, tvb,
				    offset + 0, 1, opcode);
	    }
	    proto_tree_add_uint(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, tvb_get_ntohl(tvb, offset + 16));
	    proto_tree_add_uint(ti, hf_iscsi_ExpCmdSN, tvb, offset + 28, 4, tvb_get_ntohl(tvb, offset + 28));
	    proto_tree_add_uint(ti, hf_iscsi_MaxCmdSN, tvb, offset + 32, 4, tvb_get_ntohl(tvb, offset + 32));
	    proto_tree_add_uint(ti, hf_iscsi_Logout_Response, tvb, offset + 36, 1, tvb_get_guint8(tvb, offset + 36));
	    offset += 48;
	}
	else if((!enable_03_mode && (opcode == 0x10 || opcode == 0x50))) {
	    int S = 0;
	    /* SNACK Request */
	    proto_tree_add_uint(ti, hf_iscsi_Opcode, tvb,
				offset + 0, 1, opcode);
	    {
		gint b = tvb_get_guint8(tvb, offset + 1);
		proto_item *tf = proto_tree_add_uint(ti, hf_iscsi_Flags, tvb, offset + 1, 1, b);
		proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_Flags);

		proto_tree_add_boolean(tt, hf_iscsi_SNACK_S, tvb, offset + 1, 1, b);
		S = b & 0x01;
	    }
	    proto_tree_add_boolean(ti, hf_iscsi_AddRuns, tvb, offset + 3, 1, tvb_get_guint8(tvb, offset + 3));
	    proto_tree_add_uint(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, tvb_get_ntohl(tvb, offset + 16));
	    proto_tree_add_uint(ti, hf_iscsi_BegRun, tvb, offset + 20, 4, tvb_get_ntohl(tvb, offset + 20));
	    proto_tree_add_uint(ti, hf_iscsi_RunLength, tvb, offset + 24, 4, tvb_get_ntohl(tvb, offset + 24));
	    if(S) {
		proto_tree_add_uint(ti, hf_iscsi_ExpStatSN, tvb, offset + 28, 4, tvb_get_ntohl(tvb, offset + 28));
	    }
	    else {
		proto_tree_add_uint(ti, hf_iscsi_ExpDataSN, tvb, offset + 28, 4, tvb_get_ntohl(tvb, offset + 28));
	    }
	    proto_tree_add_bytes(ti, hf_iscsi_AdditionalRuns, tvb, offset + 32, 16, tvb_get_ptr(tvb, offset + 32, 16));
	    offset += 48;
	}
	else if((enable_03_mode && opcode == 0x90) ||
		(!enable_03_mode && opcode == 0xd0)) {
	    /* R2T */
	    if(enable_03_mode) {
		proto_tree_add_uint(ti, hf_iscsi_Opcode_03, tvb, 
				    offset + 0, 1, opcode);
		proto_tree_add_uint(ti, hf_iscsi_Length03, tvb, offset + 4, 4, data_segment_len);
	    }
	    else {
		proto_tree_add_uint(ti, hf_iscsi_Opcode, tvb,
				    offset + 0, 1, opcode);
	    }
	    proto_tree_add_uint(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, tvb_get_ntohl(tvb, offset + 16));
	    proto_tree_add_uint(ti, hf_iscsi_TargetTransferTag, tvb, offset + 20, 4, tvb_get_ntohl(tvb, offset + 20));
	    if(!enable_03_mode) {
		proto_tree_add_uint(ti, hf_iscsi_StatSN, tvb, offset + 24, 4, tvb_get_ntohl(tvb, offset + 24));
	    }
	    proto_tree_add_uint(ti, hf_iscsi_ExpCmdSN, tvb, offset + 28, 4, tvb_get_ntohl(tvb, offset + 28));
	    proto_tree_add_uint(ti, hf_iscsi_MaxCmdSN, tvb, offset + 32, 4, tvb_get_ntohl(tvb, offset + 32));
	    if(enable_03_mode) {
		proto_tree_add_uint(ti, hf_iscsi_DesiredDataLength, tvb, offset + 36, 4, tvb_get_ntohl(tvb, offset + 36));
		proto_tree_add_uint(ti, hf_iscsi_BufferOffset, tvb, offset + 40, 4, tvb_get_ntohl(tvb, offset + 40));
	    }
	    else {
		proto_tree_add_uint(ti, hf_iscsi_DataSN, tvb, offset + 36, 4, tvb_get_ntohl(tvb, offset + 36));
		proto_tree_add_uint(ti, hf_iscsi_BufferOffset, tvb, offset + 40, 4, tvb_get_ntohl(tvb, offset + 40));
		proto_tree_add_uint(ti, hf_iscsi_DesiredDataLength, tvb, offset + 44, 4, tvb_get_ntohl(tvb, offset + 44));
	    }
	    offset += 48;
	}
	else if((enable_03_mode && opcode == 0x91) || 
		(!enable_03_mode && opcode == 0xd1)) {
	    /* Asynchronous Message */
	    if(enable_03_mode) {
		proto_tree_add_uint(ti, hf_iscsi_Opcode_03, tvb, 
				    offset + 0, 1, opcode);
		proto_tree_add_uint(ti, hf_iscsi_Length03, tvb, offset + 4, 4, data_segment_len);
	    }
	    else {
		proto_tree_add_uint(ti, hf_iscsi_Opcode, tvb,
				    offset + 0, 1, opcode);
		proto_tree_add_uint(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, data_segment_len);
	    }
	    proto_tree_add_bytes(ti, hf_iscsi_LUN, tvb, offset + 8, 8, tvb_get_ptr(tvb, offset + 8, 8));
	    proto_tree_add_uint(ti, hf_iscsi_StatSN, tvb, offset + 24, 4, tvb_get_ntohl(tvb, offset + 24));
	    proto_tree_add_uint(ti, hf_iscsi_ExpCmdSN, tvb, offset + 28, 4, tvb_get_ntohl(tvb, offset + 28));
	    proto_tree_add_uint(ti, hf_iscsi_MaxCmdSN, tvb, offset + 32, 4, tvb_get_ntohl(tvb, offset + 32));
	    proto_tree_add_uint(ti, hf_iscsi_SCSIEvent, tvb, offset + 36, 1, tvb_get_guint8(tvb, offset + 36));
	    proto_tree_add_uint(ti, hf_iscsi_iSCSIEvent, tvb, offset + 37, 1, tvb_get_guint8(tvb, offset + 37));
	    proto_tree_add_uint(ti, hf_iscsi_Parameter1, tvb, offset + 38, 2, tvb_get_ntohs(tvb, offset + 38));
	    proto_tree_add_uint(ti, hf_iscsi_Parameter2, tvb, offset + 40, 2, tvb_get_ntohs(tvb, offset + 40));
	    offset += 48;
	}
	else if(opcode == 0xef) {
	    /* Reject */
	    if(enable_03_mode) {
		proto_tree_add_uint(ti, hf_iscsi_Opcode_03, tvb, 
				    offset + 0, 1, opcode);
		proto_tree_add_uint(ti, hf_iscsi_Length03, tvb, offset + 4, 4, data_segment_len);
		proto_tree_add_uint(ti, hf_iscsi_Reject_Reason03, tvb, offset + 36, 1, tvb_get_guint8(tvb, offset + 36));
	    }
	    else {
		proto_tree_add_uint(ti, hf_iscsi_Opcode, tvb,
				    offset + 0, 1, opcode);
		proto_tree_add_uint(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, data_segment_len);
		proto_tree_add_uint(ti, hf_iscsi_Reject_Reason, tvb, offset + 40, 1, tvb_get_guint8(tvb, offset + 40));
		proto_tree_add_uint(ti, hf_iscsi_Reject_FirstBadByte, tvb, offset + 42, 1, tvb_get_ntohs(tvb, offset + 42));
	    }
	    offset += 48;
	}

	if(packet_len > offset)
	    proto_tree_add_bytes(ti, hf_iscsi_Payload, tvb, offset, packet_len - offset, tvb_get_ptr(tvb, offset, packet_len - offset));
    }

    return TRUE;
}

/* Register the protocol with Ethereal */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_iscsi(void)
{                 

	/* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
	{ &hf_iscsi_Payload,
	  { "Payload", "iscsi.payload",
	    FT_BYTES, BASE_HEX, NULL, 0,
	    "Payload (includes any header digest)" }
	},
	{ &hf_iscsi_Opcode,
	  { "Opcode", "iscsi.opcode",
	    FT_UINT8, BASE_HEX, VALS(iscsi_opcodes), 0,          
	    "Opcode" }
	},
	{ &hf_iscsi_Opcode_03,
	  { "Opcode", "iscsi.opcode",
	    FT_UINT8, BASE_HEX, VALS(iscsi_opcodes_03), 0,          
	    "Opcode" }
	},
#if 0
	{ &hf_iscsi_X,
	  { "X", "iscsi.x",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_X), 0x80,          
	    "Command Retry" }
	},
	{ &hf_iscsi_I,
	  { "I", "iscsi.i",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_I), 0x40,          
	    "Immediate delivery" }
	},
#endif
	{ &hf_iscsi_Flags,
	  { "Flags", "iscsi.flags",
	    FT_UINT8, BASE_HEX, NULL, 0,          
	    "Opcode specific flags" }
	},
	{ &hf_iscsi_SCSICommand_X03,
	  { "X", "iscsi.scsicommand.x",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_X), 0x80,          
	    "Command Retry" }
	},
	{ &hf_iscsi_SCSICommand_F,
	  { "F", "iscsi.scsicommand.f",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_F), 0x80,          
	    "PDU completes command" }
	},
	{ &hf_iscsi_SCSICommand_R,
	  { "R", "iscsi.scsicommand.r",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_R), 0x40,          
	    "Command reads from SCSI target" }
	},
	{ &hf_iscsi_SCSICommand_W,
	  { "W", "iscsi.scsicommand.r",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_W), 0x20,          
	    "Command writes to SCSI target" }
	},
	{ &hf_iscsi_SCSICommand_Attr,
	  { "Attr", "iscsi.scsicommand.attr",
	    FT_UINT8, BASE_HEX, VALS(iscsi_scsicommand_taskattrs), 0x07,          
	    "SCSI task attributes" }
	},
	{ &hf_iscsi_SCSICommand_CRN,
	  { "CRN", "iscsi.scsicommand.crn",
	    FT_UINT8, BASE_HEX, NULL, 0,          
	    "SCSI command reference number" }
	},
	{ &hf_iscsi_SCSICommand_AddCDB,
	  { "AddCDB", "iscsi.scsicommand.addcdb",
	    FT_UINT8, BASE_HEX, NULL, 0,
	    "Additional CDB length (in 4 byte units)" }
	},
	{ &hf_iscsi_Length03,
	  { "Length", "iscsi.length",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Data length (bytes)" }
	},
	{ &hf_iscsi_DataSegmentLength,
	  { "DataSegmentLength", "iscsi.datasegmentlength",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Data segment length (bytes)" }
	},
	{ &hf_iscsi_TotalAHSLength,
	  { "TotalAHSLength", "iscsi.totalahslength",
	    FT_UINT8, BASE_HEX, NULL, 0,
	    "Total additional header segment length (4 byte words)" }
	},
	{ &hf_iscsi_LUN,
	  { "LUN", "iscsi.lun",
	    FT_BYTES, BASE_HEX, NULL, 0,
	    "Logical Unit Number" }
	},
	{ &hf_iscsi_InitiatorTaskTag,
	  { "InitiatorTaskTag", "iscsi.initiatortasktag",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Initiator's task tag" }
	},
	{ &hf_iscsi_ExpectedDataTransferLength,
	  { "ExpectedDataTransferLength", "iscsi.scsicommand.expecteddatatransferlength",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Expected length of data transfer" }
	},
	{ &hf_iscsi_CmdSN,
	  { "CmdSN", "iscsi.cmdsn",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Sequence number for this command (0 == immediate)" }
	},
	{ &hf_iscsi_ExpStatSN,
	  { "ExpStatSN", "iscsi.expstatsn",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Next expected status sequence number" }
	},
	{ &hf_iscsi_SCSICommand_CDB,
	  { "CDB", "iscsi.scsicommand.cdb",
	    FT_BYTES, BASE_HEX, NULL, 0,
	    "SCSI CDB" }
	},
	{ &hf_iscsi_SCSICommand_CDB0,
	  { "CDB", "iscsi.scsicommand.cdb0",
	    FT_UINT8, BASE_HEX, VALS(iscsi_scsi_cdb0), 0,
	    "SCSI CDB[0]" }
	},
	{ &hf_iscsi_SCSIResponse_BasicResidualCount,
	  { "BasicResidualCount", "iscsi.scsiresponse.basicresidualcount",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Residual count" }
	},
	{ &hf_iscsi_StatSN,
	  { "StatSN", "iscsi.statsn",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Status sequence number" }
	},
	{ &hf_iscsi_ExpCmdSN,
	  { "ExpCmdSN", "iscsi.expcmdsn",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Next expected command sequence number" }
	},
	{ &hf_iscsi_MaxCmdSN,
	  { "MaxCmdSN", "iscsi.maxcmdsn",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Maximum acceptable command sequence number" }
	},
	{ &hf_iscsi_SCSIResponse_o03,
	  { "o", "iscsi.scsiresponse.o",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_o), 0x08,          
	    "Bi-directional read residual overflow" }
	},
	{ &hf_iscsi_SCSIResponse_u03,
	  { "u", "iscsi.scsiresponse.u",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_u), 0x04,          
	    "Bi-directional read residual underflow" }
	},
	{ &hf_iscsi_SCSIResponse_O03,
	  { "O", "iscsi.scsiresponse.O",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_O), 0x02,          
	    "Residual overflow" }
	},
	{ &hf_iscsi_SCSIResponse_U03,
	  { "U", "iscsi.scsiresponse.U",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_U), 0x01,          
	    "Residual underflow" }
	},
	{ &hf_iscsi_SCSIResponse_o,
	  { "o", "iscsi.scsiresponse.o",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_o), 0x10,          
	    "Bi-directional read residual overflow" }
	},
	{ &hf_iscsi_SCSIResponse_u,
	  { "u", "iscsi.scsiresponse.u",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_u), 0x08,          
	    "Bi-directional read residual underflow" }
	},
	{ &hf_iscsi_SCSIResponse_O,
	  { "O", "iscsi.scsiresponse.O",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_O), 0x04,          
	    "Residual overflow" }
	},
	{ &hf_iscsi_SCSIResponse_U,
	  { "U", "iscsi.scsiresponse.U",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_U), 0x02,          
	    "Residual underflow" }
	},
	{ &hf_iscsi_SCSIResponse_S,
	  { "S", "iscsi.scsiresponse.S",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_scsiresponse_S), 0x01,          
	    "Status/Response" }
	},
	{ &hf_iscsi_CommandStatus03,
	  { "CommandStatus", "iscsi.commandstatus",
	    FT_UINT8, BASE_HEX, VALS(iscsi_scsi_statuses), 0,
	    "SCSI command status value" }
	},
	{ &hf_iscsi_StatusResponse_is_status,
	  { "Status/Response", "iscsi.scsiresponse.statusresponse",
	    FT_UINT8, BASE_HEX, VALS(iscsi_scsi_statuses), 0,
	    "SCSI command status value" }
	},
	{ &hf_iscsi_StatusResponse_is_response,
	  { "Status/Response", "iscsi.scsiresponse.statusresponse",
	    FT_UINT8, BASE_HEX, VALS(iscsi_scsi_responses), 0,
	    "iSCSI response value" }
	},
	{ &hf_iscsi_SCSIResponse_SenseLength,
	  { "SenseLength", "iscsi.scsiresponse.senselength",
	    FT_UINT16, BASE_HEX, NULL, 0,
	    "SCSI sense data length" }
	},
	{ &hf_iscsi_SCSIResponse_BidiReadResidualCount,
	  { "BidiReadResidualCount", "iscsi.scsiresponse.bidireadresidualcount",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Bi-directional read residual count" }
	},
	{ &hf_iscsi_SCSIData_F,
	  { "F", "iscsi.scsidata.f",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_F), 0x80,          
	    "Final PDU" }
	},
	{ &hf_iscsi_SCSIData_P03,
	  { "P", "iscsi.scsidata.p",
	    FT_BOOLEAN, 8,  TFS(&iscsi_meaning_P), 0x80,          
	    "Poll requested" }
	},
	{ &hf_iscsi_SCSIData_S03,
	  { "S", "iscsi.scsidata.s",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_S), 0x04,          
	    "PDU Contains SCSI command status" }
	},
	{ &hf_iscsi_SCSIData_O03,
	  { "O", "iscsi.scsidata.O",
	    FT_BOOLEAN, 8,  TFS(&iscsi_meaning_O), 0x02,          
	    "Residual overflow" }
	},
	{ &hf_iscsi_SCSIData_U03,
	  { "U", "iscsi.scsidata.U",
	    FT_BOOLEAN, 8,  TFS(&iscsi_meaning_U), 0x01,          
	    "Residual underflow" }
	},
	{ &hf_iscsi_SCSIData_S,
	  { "S", "iscsi.scsidata.s",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_S), 0x01,          
	    "PDU Contains SCSI command status" }
	},
	{ &hf_iscsi_SCSIData_U,
	  { "U", "iscsi.scsidata.U",
	    FT_BOOLEAN, 8,  TFS(&iscsi_meaning_U), 0x02,          
	    "Residual underflow" }
	},
	{ &hf_iscsi_SCSIData_O,
	  { "O", "iscsi.scsidata.O",
	    FT_BOOLEAN, 8,  TFS(&iscsi_meaning_O), 0x04,          
	    "Residual overflow" }
	},
	{ &hf_iscsi_TargetTransferTag,
	  { "TargetTransferTag", "iscsi.targettransfertag",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Target transfer tag" }
	},
	{ &hf_iscsi_BufferOffset,
	  { "BufferOffset", "iscsi.bufferOffset",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Buffer offset" }
	},
	{ &hf_iscsi_SCSIData_ResidualCount,
	  { "ResidualCount", "iscsi.scsidata.readresidualcount",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Residual count" }
	},
	{ &hf_iscsi_DataSN,
	  { "DataSN", "iscsi.datasn",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Data sequence number" }
	},
	{ &hf_iscsi_VersionMax,
	  { "VersionMax", "iscsi.versionmax",
	    FT_UINT8, BASE_HEX, NULL, 0,
	    "Maximum supported protocol version" }
	},
	{ &hf_iscsi_VersionMin,
	  { "VersionMin", "iscsi.versionmin",
	    FT_UINT8, BASE_HEX, NULL, 0,
	    "Minimum supported protocol version" }
	},
	{ &hf_iscsi_CID,
	  { "CID", "iscsi.cid",
	    FT_UINT16, BASE_HEX, NULL, 0,
	    "Connection identifier" }
	},
	{ &hf_iscsi_ISID,
	  { "ISID", "iscsi.isid",
	    FT_UINT16, BASE_HEX, NULL, 0,
	    "Initiator part of session identifier" }
	},
	{ &hf_iscsi_TSID,
	  { "TSID", "iscsi.tsid",
	    FT_UINT16, BASE_HEX, NULL, 0,
	    "Target part of session identifier" }
	},
	{ &hf_iscsi_InitStatSN,
	  { "InitStatSN", "iscsi.initstatsn",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Initial status sequence number" }
	},
	{ &hf_iscsi_InitCmdSN,
	  { "InitCmdSN", "iscsi.initcmdsn",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Initial command sequence number" }
	},
	{ &hf_iscsi_Login_F,
	  { "F", "iscsi.login.f",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_F), 0x80,          
	    "Final PDU in login sequence" }
	},
	{ &hf_iscsi_Login_Status03,
	  { "Status", "iscsi.login.status",
	    FT_UINT8, BASE_HEX, VALS(iscsi_login_status03), 0,
	    "Status" }
	},
	{ &hf_iscsi_Login_Status,
	  { "Status", "iscsi.login.status",
	    FT_UINT16, BASE_HEX, VALS(iscsi_login_status), 0,
	    "Status class and detail" }
	},
	{ &hf_iscsi_KeyValue,
	  { "KeyValue", "iscsi.keyvalue",
	    FT_STRING, 0, NULL, 0,
	    "Key/value pair" }
	},
	{ &hf_iscsi_Text_F,
	  { "F", "iscsi.text.f",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_F), 0x80,          
	    "Final PDU in text sequence" }
	},
	{ &hf_iscsi_NOP_P,
	  { "P", "iscsi.nop.p",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_P), 0x80,          
	    "Poll requested" }
	},
	{ &hf_iscsi_ExpDataSN,
	  { "ExpCmdSN", "iscsi.expdatasn",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Next expected data sequence number" }
	},
	{ &hf_iscsi_R2TExpDataSN,
	  { "R2TExpCmdSN", "iscsi.r2texpdatasn",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Next expected R2T data sequence number" }
	},
	{ &hf_iscsi_SCSITask_Response,
	  { "Response", "iscsi.scsitask.response",
	    FT_UINT8, BASE_HEX, VALS(iscsi_task_responses), 0,
	    "Response" }
	},
	{ &hf_iscsi_SCSITask_ReferencedTaskTag,
	  { "InitiatorTaskTag", "iscsi.scsitask.referencedtasktag",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Task's initiator task tag" }
	},
	{ &hf_iscsi_SCSITask_Function,
	  { "Function", "iscsi.scsitask.function",
	    FT_UINT8, BASE_HEX, VALS(iscsi_task_functions), 0x7F,
	    "Requested task function" }
	},
	{ &hf_iscsi_Logout_Reason03,
	  { "Reason", "iscsi.logout.reason",
	    FT_UINT8, BASE_HEX, VALS(iscsi_logout_reasons03), 0,
	    "Reason for logout" }
	},
	{ &hf_iscsi_Logout_Reason,
	  { "Reason", "iscsi.logout.reason",
	    FT_UINT8, BASE_HEX, VALS(iscsi_logout_reasons), 0,
	    "Reason for logout" }
	},
	{ &hf_iscsi_Logout_Response,
	  { "Response", "iscsi.logout.response",
	    FT_UINT8, BASE_HEX, VALS(iscsi_logout_response), 0,
	    "Logout response" }
	},
	{ &hf_iscsi_DesiredDataLength,
	  { "DesiredDataLength", "iscsi.desireddatalength",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Desired data length (bytes)" }
	},
	{ &hf_iscsi_SCSIEvent03,
	  { "SCSIEvent", "iscsi.scsievent",
	    FT_UINT8, BASE_HEX, VALS(iscsi_scsievents03), 0,
	    "SCSI event indicator" }
	},
	{ &hf_iscsi_iSCSIEvent03,
	  { "iSCSIEvent", "iscsi.iscsievent",
	    FT_UINT8, BASE_HEX, VALS(iscsi_iscsievents03), 0,
	    "iSCSI event indicator" }
	},
	{ &hf_iscsi_Parameter1,
	  { "Parameter1", "iscsi.parameter1",
	    FT_UINT16, BASE_HEX, NULL, 0,
	    "Parameter 1" }
	},
	{ &hf_iscsi_Parameter2,
	  { "Parameter2", "iscsi.parameter2",
	    FT_UINT16, BASE_HEX, NULL, 0,
	    "Parameter 2" }
	},
	{ &hf_iscsi_Reject_Reason,
	  { "Reason", "iscsi.reject.reason",
	    FT_UINT8, BASE_HEX, VALS(iscsi_reject_reasons), 0,
	    "Reason for command rejection" }
	},
	{ &hf_iscsi_Reject_FirstBadByte,
	  { "FirstBadByte", "iscsi.reject.firstbadbyte",
	    FT_UINT16, BASE_HEX, NULL, 0,
	    "Offset of first bad byte in PDU when reason is 'format error'" }
	},
	{ &hf_iscsi_Reject_Reason03,
	  { "Reason", "iscsi.reject.reason",
	    FT_UINT8, BASE_HEX, VALS(iscsi_reject_reasons03), 0,
	    "Reason for command rejection" }
	},
	{ &hf_iscsi_SNACK_S,
	  { "S", "iscsi.snack.s",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_SNACK_S), 0x01,          
	    "Status not data SNACK requested" }
	},
	{ &hf_iscsi_AddRuns,
	  { "AddRuns", "iscsi.snack.addruns",
	    FT_UINT8, BASE_HEX, NULL, 0,
	    "Number of additional runs" }
	},
	{ &hf_iscsi_BegRun,
	  { "BegRun", "iscsi.snack.begrun",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "First missed DataSN or StatSN" }
	},
	{ &hf_iscsi_RunLength,
	  { "RunLength", "iscsi.snack.runlength",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Number of additional missing status PDUs in this run" }
	},
	{ &hf_iscsi_AdditionalRuns,
	  { "AdditionalRuns", "iscsi.snack.additionalruns",
	    FT_BYTES, BASE_HEX, NULL, 0,
	    "Additional runs of missing status PDUs" }
	},
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
	&ett_iscsi_KeyValues,
	&ett_iscsi_CDB,
	&ett_iscsi_Flags,
    };

    /* Register the protocol name and description */
    proto_iscsi = proto_register_protocol("iSCSI", "ISCSI", "iscsi");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_iscsi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    {
	module_t *iscsi_module = prefs_register_protocol(proto_iscsi, NULL);

	prefs_register_bool_preference(iscsi_module,
				       "version_03_compatible", 
				       "Enable 03 compatibility mode",
				       "When enabled, assume packets conform to the legacy 03 version of the iSCSI specification",
				       &enable_03_mode);
	prefs_register_bool_preference(iscsi_module,
				       "bogus_pdu_filter", 
				       "Enable bogus pdu filter",
				       "When enabled, packets that appear bogus are ignored",
				       &enable_bogosity_filter);

	prefs_register_uint_preference(iscsi_module,
				       "bogus_pdu_max_data_len", 
				       "Bogus pdu max data length threshold",
				       "Treat packets whose data segment length is greater than this value as bogus",
				       10,
				       &bogus_pdu_data_length_threshold);
	prefs_register_uint_preference(iscsi_module,
				       "bogus_pdu_max_digest_padding", 
				       "Bogus pdu max digest padding",
				       "Treat packets whose apparent total digest size is greater than this value as bogus",
				       10,
				       &bogus_pdu_max_digest_padding);
    }
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_iscsi(void)
{
    heur_dissector_add("tcp", dissect_iscsi, proto_iscsi);
}
