/* TODO for the cases where one just can not autodetect whether header digest
   is used or not we might need a new preference
   HeaderDigest :
       Automatic (default)
       None
       CRC32
*/

/* packet-iscsi.c
 * Routines for iSCSI dissection
 * Copyright 2001, Eurologic and Mark Burton <markb@ordern.com>
 *  2004 Request/Response matching and Service Response Time: ronnie sahlberg
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include "packet-scsi.h"
#include <epan/nstime.h>
#include <epan/emem.h>
#include <epan/range.h>
#include <wsutil/crc32.h>

/* the absolute values of these constants don't matter as long as
 * latter revisions of the protocol are assigned a larger number */
#define ISCSI_PROTOCOL_DRAFT08 1
#define ISCSI_PROTOCOL_DRAFT09 2
#define ISCSI_PROTOCOL_DRAFT11 3
#define ISCSI_PROTOCOL_DRAFT12 4
#define ISCSI_PROTOCOL_DRAFT13 5

static enum_val_t iscsi_protocol_versions[] = {
    { "draft-08", "Draft 08", ISCSI_PROTOCOL_DRAFT08 },
    { "draft-09", "Draft 09", ISCSI_PROTOCOL_DRAFT09 },
    { "draft-11", "Draft 11", ISCSI_PROTOCOL_DRAFT11 },
    { "draft-12", "Draft 12", ISCSI_PROTOCOL_DRAFT12 },
    { "draft-13", "Draft 13", ISCSI_PROTOCOL_DRAFT13 },
    { NULL, NULL, 0 }
};

static const value_string ahs_type_vals[] = {
    {1, "Extended CDB"},
    {2, "Expected Bidirection Read Data Length"},
    {0, NULL}
};

static dissector_handle_t iscsi_handle=NULL;

static gint iscsi_protocol_version = ISCSI_PROTOCOL_DRAFT13;

static gboolean iscsi_desegment = TRUE;

static int demand_good_f_bit = FALSE;
static int enable_bogosity_filter = TRUE;
static guint32 bogus_pdu_data_length_threshold = 256 * 1024;

static int enableDataDigests = FALSE;

static int dataDigestIsCRC32 = TRUE;

static guint dataDigestSize = 4;

#define	TCP_PORT_ISCSI_RANGE	"3260"

static range_t *global_iscsi_port_range;
static guint iscsi_system_port = 860;

/* Initialize the protocol and registered fields */
static int proto_iscsi = -1;
static int hf_iscsi_time = -1;
static int hf_iscsi_request_frame = -1;
static int hf_iscsi_data_in_frame = -1;
static int hf_iscsi_data_out_frame = -1;
static int hf_iscsi_response_frame = -1;
static int hf_iscsi_AHS_length = -1;
static int hf_iscsi_AHS_type = -1;
static int hf_iscsi_AHS_blob = -1;
static int hf_iscsi_AHS_read_data_length = -1;
static int hf_iscsi_AHS_extended_cdb = -1;
static int hf_iscsi_Padding = -1;
static int hf_iscsi_ping_data = -1;
static int hf_iscsi_immediate_data = -1;
static int hf_iscsi_async_event_data = -1;
static int hf_iscsi_vendor_specific_data = -1;
static int hf_iscsi_Opcode = -1;
static int hf_iscsi_Flags = -1;
static int hf_iscsi_HeaderDigest32 = -1;
static int hf_iscsi_DataDigest = -1;
static int hf_iscsi_DataDigest32 = -1;
/* #ifdef DRAFT08 */
static int hf_iscsi_X = -1;
/* #endif */
static int hf_iscsi_I = -1;
static int hf_iscsi_SCSICommand_F = -1;
static int hf_iscsi_SCSICommand_R = -1;
static int hf_iscsi_SCSICommand_W = -1;
static int hf_iscsi_SCSICommand_Attr = -1;
static int hf_iscsi_SCSICommand_CRN = -1;
static int hf_iscsi_DataSegmentLength = -1;
static int hf_iscsi_TotalAHSLength = -1;
static int hf_iscsi_LUN = -1;
static int hf_iscsi_InitiatorTaskTag = -1;
static int hf_iscsi_ExpectedDataTransferLength = -1;
static int hf_iscsi_CmdSN = -1;
static int hf_iscsi_ExpStatSN = -1;
static int hf_iscsi_StatSN = -1;
static int hf_iscsi_ExpCmdSN = -1;
static int hf_iscsi_MaxCmdSN = -1;
static int hf_iscsi_SCSIResponse_o = -1;
static int hf_iscsi_SCSIResponse_u = -1;
static int hf_iscsi_SCSIResponse_O = -1;
static int hf_iscsi_SCSIResponse_U = -1;
static int hf_iscsi_SCSIResponse_BidiReadResidualCount = -1;
static int hf_iscsi_SCSIResponse_ResidualCount = -1;
static int hf_iscsi_SCSIResponse_Response = -1;
static int hf_iscsi_SCSIResponse_Status = -1;
static int hf_iscsi_SenseLength = -1;
static int hf_iscsi_SCSIData_F = -1;
static int hf_iscsi_SCSIData_A = -1;
static int hf_iscsi_SCSIData_S = -1;
static int hf_iscsi_SCSIData_O = -1;
static int hf_iscsi_SCSIData_U = -1;
static int hf_iscsi_TargetTransferTag = -1;
static int hf_iscsi_DataSN = -1;
static int hf_iscsi_BufferOffset = -1;
static int hf_iscsi_SCSIData_ResidualCount = -1;
static int hf_iscsi_VersionMin = -1;
static int hf_iscsi_VersionMax = -1;
static int hf_iscsi_VersionActive = -1;
static int hf_iscsi_CID = -1;
static int hf_iscsi_ISID8 = -1;
static int hf_iscsi_ISID = -1;
/* #if defined(DRAFT09) */
static int hf_iscsi_ISID_Type = -1;
static int hf_iscsi_ISID_NamingAuthority = -1;
static int hf_iscsi_ISID_Qualifier = -1;
/* #elif !defined(DRAFT08) */
static int hf_iscsi_ISID_t = -1;
static int hf_iscsi_ISID_a = -1;
static int hf_iscsi_ISID_b = -1;
static int hf_iscsi_ISID_c = -1;
static int hf_iscsi_ISID_d = -1;
/* #endif */
static int hf_iscsi_TSID = -1;
static int hf_iscsi_TSIH = -1;
/* #ifdef DRAFT09 */
static int hf_iscsi_Login_X = -1;
/* #endif */
static int hf_iscsi_Login_C = -1;
static int hf_iscsi_Login_T = -1;
static int hf_iscsi_Login_CSG = -1;
static int hf_iscsi_Login_NSG = -1;
static int hf_iscsi_Login_Status = -1;
static int hf_iscsi_KeyValue = -1;
static int hf_iscsi_Text_C = -1;
static int hf_iscsi_Text_F = -1;
static int hf_iscsi_ExpDataSN = -1;
static int hf_iscsi_R2TSN = -1;
static int hf_iscsi_TaskManagementFunction_ReferencedTaskTag = -1;
static int hf_iscsi_RefCmdSN = -1;
static int hf_iscsi_TaskManagementFunction_Function = -1;
static int hf_iscsi_TaskManagementFunction_Response = -1;
static int hf_iscsi_Logout_Reason = -1;
static int hf_iscsi_Logout_Response = -1;
static int hf_iscsi_Time2Wait = -1;
static int hf_iscsi_Time2Retain = -1;
static int hf_iscsi_DesiredDataLength = -1;
static int hf_iscsi_AsyncEvent = -1;
static int hf_iscsi_EventVendorCode = -1;
static int hf_iscsi_Parameter1 = -1;
static int hf_iscsi_Parameter2 = -1;
static int hf_iscsi_Parameter3 = -1;
static int hf_iscsi_Reject_Reason = -1;
static int hf_iscsi_snack_type = -1;
static int hf_iscsi_BegRun = -1;
static int hf_iscsi_RunLength = -1;

/* Initialize the subtree pointers */
static gint ett_iscsi = -1;
static gint ett_iscsi_KeyValues = -1;
static gint ett_iscsi_CDB = -1;
static gint ett_iscsi_Flags = -1;
static gint ett_iscsi_RejectHeader = -1;
/* #ifndef DRAFT08 */
static gint ett_iscsi_ISID = -1;
/* #endif */

#define ISCSI_HEADER_DIGEST_AUTO	0
#define ISCSI_HEADER_DIGEST_NONE	1
#define ISCSI_HEADER_DIGEST_CRC32	2
/* this structure contains session wide state for a specific tcp conversation */
typedef struct _iscsi_session_t {
	guint32 header_digest;
	emem_tree_t *itlq;	/* indexed by ITT */
	emem_tree_t *itl;		/* indexed by LUN */
} iscsi_session_t;



/* #ifdef DRAFT08 */
#define X_BIT 0x80
/* #endif */

#define I_BIT 0x40

#define OPCODE_MASK 0x3f

#define TARGET_OPCODE_BIT 0x20

#define ISCSI_OPCODE_NOP_OUT                  0x00
#define ISCSI_OPCODE_SCSI_COMMAND             0x01
#define ISCSI_OPCODE_TASK_MANAGEMENT_FUNCTION 0x02
#define ISCSI_OPCODE_LOGIN_COMMAND            0x03
#define ISCSI_OPCODE_TEXT_COMMAND             0x04
#define ISCSI_OPCODE_SCSI_DATA_OUT            0x05
#define ISCSI_OPCODE_LOGOUT_COMMAND           0x06
#define ISCSI_OPCODE_SNACK_REQUEST            0x10
#define ISCSI_OPCODE_VENDOR_SPECIFIC_I0       0x1c
#define ISCSI_OPCODE_VENDOR_SPECIFIC_I1       0x1d
#define ISCSI_OPCODE_VENDOR_SPECIFIC_I2       0x1e

#define ISCSI_OPCODE_NOP_IN                            0x20
#define ISCSI_OPCODE_SCSI_RESPONSE                     0x21
#define ISCSI_OPCODE_TASK_MANAGEMENT_FUNCTION_RESPONSE 0x22
#define ISCSI_OPCODE_LOGIN_RESPONSE                    0x23
#define ISCSI_OPCODE_TEXT_RESPONSE                     0x24
#define ISCSI_OPCODE_SCSI_DATA_IN                      0x25
#define ISCSI_OPCODE_LOGOUT_RESPONSE                   0x26
#define ISCSI_OPCODE_R2T                               0x31
#define ISCSI_OPCODE_ASYNC_MESSAGE                     0x32
#define ISCSI_OPCODE_REJECT                            0x3f
#define ISCSI_OPCODE_VENDOR_SPECIFIC_T0                0x3c
#define ISCSI_OPCODE_VENDOR_SPECIFIC_T1                0x3d
#define ISCSI_OPCODE_VENDOR_SPECIFIC_T2                0x3e

#define CSG_SHIFT 2
#define CSG_MASK  (0x03 << CSG_SHIFT)
#define NSG_MASK  0x03

#define ISCSI_CSG_SECURITY_NEGOTIATION    (0 << CSG_SHIFT)
#define ISCSI_CSG_OPERATIONAL_NEGOTIATION (1 << CSG_SHIFT)
#define ISCSI_CSG_FULL_FEATURE_PHASE      (3 << CSG_SHIFT)

#define ISCSI_SCSI_DATA_FLAG_S 0x01
#define ISCSI_SCSI_DATA_FLAG_U 0x02
#define ISCSI_SCSI_DATA_FLAG_O 0x04
#define ISCSI_SCSI_DATA_FLAG_A 0x40
#define ISCSI_SCSI_DATA_FLAG_F 0x80

static const value_string iscsi_opcodes[] = {
  { ISCSI_OPCODE_NOP_OUT,                           "NOP Out" },
  { ISCSI_OPCODE_SCSI_COMMAND,                      "SCSI Command" },
  { ISCSI_OPCODE_TASK_MANAGEMENT_FUNCTION,          "Task Management Function" },
  { ISCSI_OPCODE_LOGIN_COMMAND,                     "Login Command" },
  { ISCSI_OPCODE_TEXT_COMMAND,                      "Text Command" },
  { ISCSI_OPCODE_SCSI_DATA_OUT,                     "SCSI Data Out" },
  { ISCSI_OPCODE_LOGOUT_COMMAND,                    "Logout Command" },
  { ISCSI_OPCODE_SNACK_REQUEST,                     "SNACK Request" },
  { ISCSI_OPCODE_VENDOR_SPECIFIC_I0,                "Vendor Specific I0" },
  { ISCSI_OPCODE_VENDOR_SPECIFIC_I1,                "Vendor Specific I1" },
  { ISCSI_OPCODE_VENDOR_SPECIFIC_I2,                "Vendor Specific I2" },

  { ISCSI_OPCODE_NOP_IN,                            "NOP In" },
  { ISCSI_OPCODE_SCSI_RESPONSE,                     "SCSI Response" },
  { ISCSI_OPCODE_TASK_MANAGEMENT_FUNCTION_RESPONSE, "Task Management Function Response" },
  { ISCSI_OPCODE_LOGIN_RESPONSE,                    "Login Response" },
  { ISCSI_OPCODE_TEXT_RESPONSE,                     "Text Response" },
  { ISCSI_OPCODE_SCSI_DATA_IN,                      "SCSI Data In" },
  { ISCSI_OPCODE_LOGOUT_RESPONSE,                   "Logout Response" },
  { ISCSI_OPCODE_R2T,                               "Ready To Transfer" },
  { ISCSI_OPCODE_ASYNC_MESSAGE,                     "Asynchronous Message" },
  { ISCSI_OPCODE_REJECT,                            "Reject"},
  { ISCSI_OPCODE_VENDOR_SPECIFIC_T0,                "Vendor Specific T0" },
  { ISCSI_OPCODE_VENDOR_SPECIFIC_T1,                "Vendor Specific T1" },
  { ISCSI_OPCODE_VENDOR_SPECIFIC_T2,                "Vendor Specific T2" },
  {0, NULL},
};

/* #ifdef DRAFT08 */
static const true_false_string iscsi_meaning_X = {
    "Retry",
    "Not retry"
};
/* #endif */

/* #ifdef DRAFT09 */
static const true_false_string iscsi_meaning_login_X = {
    "Reinstate failed connection",
    "New connection"
};
/* #endif */

static const true_false_string iscsi_meaning_I = {
    "Immediate delivery",
    "Queued delivery"
};

static const true_false_string iscsi_meaning_F = {
    "Final PDU in sequence",
    "Not final PDU in sequence"
};

static const true_false_string iscsi_meaning_A = {
    "Acknowledge requested",
    "Acknowledge not requested"
};

static const true_false_string iscsi_meaning_T = {
    "Transit to next login stage",
    "Stay in current login stage"
};

static const true_false_string iscsi_meaning_C = {
    "Text is incomplete",
    "Text is complete"
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

static const value_string iscsi_scsi_responses[] = {
    { 0, "Command completed at target" },
    { 1, "Response does not contain SCSI status"},
    { 0, NULL }
};

static const value_string iscsi_scsicommand_taskattrs[] = {
    {0, "Untagged"},
    {1, "Simple"},
    {2, "Ordered"},
    {3, "Head of Queue"},
    {4, "ACA"},
    {0, NULL},
};

static const value_string iscsi_task_management_responses[] = {
    {0, "Function complete"},
    {1, "Task not in task set"},
    {2, "LUN does not exist"},
    {3, "Task still allegiant"},
    {4, "Task failover not supported"},
    {5, "Task management function not supported"},
    {6, "Authorisation failed"},
    {255, "Function rejected"},
    {0, NULL},
};

static const value_string iscsi_task_management_functions[] = {
    {1, "Abort Task"},
    {2, "Abort Task Set"},
    {3, "Clear ACA"},
    {4, "Clear Task Set"},
    {5, "Logical Unit Reset"},
    {6, "Target Warm Reset"},
    {7, "Target Cold Reset"},
    {8, "Target Reassign"},
    {0, NULL},
};

static const value_string iscsi_login_status[] = {
    {0x0000, "Success"},
    {0x0101, "Target moved temporarily"},
    {0x0102, "Target moved permanently"},
    {0x0200, "Initiator error (miscellaneous error)"},
    {0x0201, "Authentication failed"},
    {0x0202, "Authorisation failure"},
    {0x0203, "Target not found"},
    {0x0204, "Target removed"},
    {0x0205, "Unsupported version"},
    {0x0206, "Too many connections"},
    {0x0207, "Missing parameter"},
    {0x0208, "Can't include in session"},
    {0x0209, "Session type not supported"},
    {0x020a, "Session does not exist"},
    {0x020b, "Invalid request during login"},
    {0x0300, "Target error (miscellaneous error)"},
    {0x0301, "Service unavailable"},
    {0x0302, "Out of resources"},
    {0, NULL},
};

static const value_string iscsi_login_stage[] = {
    {0, "Security negotiation"},
    {1, "Operational negotiation"},
    {3, "Full feature phase"},
    {0, NULL},
};

/* #ifndef DRAFT08 */
static const value_string iscsi_isid_type[] = {
    {0x00, "IEEE OUI"},
    {0x01, "IANA Enterprise Number"},
    {0x02, "Random"},
    {0, NULL},
};
/* #endif */

static const value_string iscsi_logout_reasons[] = {
    {0, "Close session"},
    {1, "Close connection"},
    {2, "Remove connection for recovery"},
    {0, NULL},
};

static const value_string iscsi_logout_response[] = {
    {0, "Connection closed successfully"},
    {1, "CID not found"},
    {2, "Connection recovery not supported"},
    {3, "Cleanup failed for various reasons"},
    {0, NULL},
};

static const value_string iscsi_asyncevents[] = {
    {0, "A SCSI asynchronous event is reported in the sense data"},
    {1, "Target requests logout"},
    {2, "Target will/has dropped connection"},
    {3, "Target will/has dropped all connections"},
    {4, "Target requests parameter negotiation"},
    {0, NULL},
};

static const value_string iscsi_snack_types[] = {
    {0, "Data/R2T"},
    {1, "Status"},
/* #ifndef DRAFT08 */
    {2, "Data ACK"},
/* #endif */
    {3, "R-Data"},
    {0, NULL}
};

static const value_string iscsi_reject_reasons[] = {
/* #ifdef DRAFT08 */
    {0x01, "Full feature phase command before login"},
/* #endif */
    {0x02, "Data (payload) digest error"},
    {0x03, "Data SNACK reject"},
    {0x04, "Protocol error"},
    {0x05, "Command not supported in this session type"},
    {0x06, "Immediate command reject (too many immediate commands)"},
    {0x07, "Task in progress"},
    {0x08, "Invalid Data Ack"},
    {0x09, "Invalid PDU field"},
    {0x0a, "Long operation reject"},
    {0x0b, "Negotiation reset"},
    {0x0c, "Waiting for logout"},
    {0, NULL},
};

/* structure and functions to keep track of
 * COMMAND/DATA_IN/DATA_OUT/RESPONSE matching
 */
typedef struct _iscsi_conv_data {
    guint32 data_in_frame;
    guint32 data_out_frame;
    itlq_nexus_t itlq;
} iscsi_conv_data_t;

/* TargetAddress describes a iscsi port, possibly using a non-standard port
   so we can use this to set up a conversation dissector to that port.

   TargetAddress is of the form :
   TargetAddress=domainname[:port][,portal-group-tag]

   where domainname is either a dns-name, an ipv4 address is dotted-decimal
   form or a bracketed ipv6 address.
   so treat this as signalling, parse the value and register iscis as a conversation
   dissector for the address/port that TargetAddress points to.
   (it starts to be common to use redirectors to point to non-3260 ports)
*/
static void
iscsi_dissect_TargetAddress(packet_info *pinfo, proto_tree *tree _U_,char *val)
{
	address *addr = NULL;
	int port;
	char *value = ep_strdup(val);
	char *a = NULL, *p = NULL, *pgt = NULL;

	if (value[0] == '[') {
		/* this looks like an ipv6 address */
		p = strchr(value, ']');
		if (p != NULL) {
			a = value+1;
			*p = 0;
			p += 2;	/* skip past "]:" */

			pgt = strchr(p, ',');
			if (pgt != NULL) {
				*pgt++ = 0;
			}

			/* cant handle ipv6 yet */
		}
	} else {
		/* This is either a ipv4 address or a dns name */
		int i0,i1,i2,i3;
		if (sscanf(value, "%d.%d.%d.%d", &i0,&i1,&i2,&i3) == 4) {
			/* looks like a ipv4 address */
			p = strchr(value, ':');
			if (p != NULL) {
				a = value;
				*p++ = 0;

				pgt = strchr(p, ',');
				if (pgt != NULL) {
					*pgt++ = 0;
				}

				addr = ep_alloc(sizeof(address));
				addr->type = AT_IPv4;
				addr->len  = 4;
				addr->data = ep_alloc(4);
				((char *)addr->data)[0] = i0;
				((char *)addr->data)[1] = i1;
				((char *)addr->data)[2] = i2;
				((char *)addr->data)[3] = i3;

				port = atoi(p);
			}

		}
	}


	/* attach a conversation dissector to this address/port tuple */
	if (addr && !pinfo->fd->flags.visited) {
		conversation_t *conv;

		conv = conversation_new(pinfo->fd->num, addr, addr, PT_TCP, port, port, NO_ADDR2|NO_PORT2);
		if (conv == NULL) {
			return;
		}
		conversation_set_dissector(conv, iscsi_handle);
	}

}

static gint
addTextKeys(packet_info *pinfo, proto_tree *tt, tvbuff_t *tvb, gint offset, guint32 text_len) {
    const gint limit = offset + text_len;

    while(offset < limit) {
	char *key = NULL, *value = NULL;
	gint len = tvb_strnlen(tvb, offset, limit - offset);

	if(len == -1) {
	    len = limit - offset;
	} else {
	    len = len + 1;
	}

	key = tvb_get_ephemeral_string(tvb, offset, len);
	if (key == NULL) {
		break;
	}
	value = strchr(key, '=');
	if (value == NULL) {
		break;
	}
	*value++ = 0;

	if (!strcmp(key, "TargetAddress")) {
		iscsi_dissect_TargetAddress(pinfo, tt, value);
	}

	proto_tree_add_item(tt, hf_iscsi_KeyValue, tvb, offset, len, FALSE);
	offset += len;
    }
    return offset;
}

static gint
handleHeaderDigest(iscsi_session_t *iscsi_session, proto_item *ti, tvbuff_t *tvb, guint offset, int headerLen) {
    int available_bytes = tvb_length_remaining(tvb, offset);

    switch(iscsi_session->header_digest){
    case ISCSI_HEADER_DIGEST_CRC32:
	if(available_bytes >= (headerLen + 4)) {
	    guint32 crc = ~crc32c_calculate(tvb_get_ptr(tvb, offset, headerLen), headerLen, CRC32C_PRELOAD);
	    guint32 sent = tvb_get_ntohl(tvb, offset + headerLen);
	    if(crc == sent) {
		proto_tree_add_uint_format(ti, hf_iscsi_HeaderDigest32, tvb, offset + headerLen, 4, sent, "HeaderDigest: 0x%08x (Good CRC32)", sent);
	    } else {
		proto_tree_add_uint_format(ti, hf_iscsi_HeaderDigest32, tvb, offset + headerLen, 4, sent, "HeaderDigest: 0x%08x (Bad CRC32, should be 0x%08x)", sent, crc);
	    }
	}
	return offset + headerLen + 4;
    }
    return offset + headerLen;
}

static gint
handleDataDigest(proto_item *ti, tvbuff_t *tvb, guint offset, int dataLen) {
    int available_bytes = tvb_length_remaining(tvb, offset);
    if(enableDataDigests) {
	if(dataDigestIsCRC32) {
	    if(available_bytes >= (dataLen + 4)) {
		guint32 crc = ~crc32c_calculate(tvb_get_ptr(tvb, offset, dataLen), dataLen, CRC32C_PRELOAD);
		guint32 sent = tvb_get_ntohl(tvb, offset + dataLen);
		if(crc == sent) {
		    proto_tree_add_uint_format(ti, hf_iscsi_DataDigest32, tvb, offset + dataLen, 4, sent, "DataDigest: 0x%08x (Good CRC32)", sent);
		}
		else {
		    proto_tree_add_uint_format(ti, hf_iscsi_DataDigest32, tvb, offset + dataLen, 4, sent, "DataDigest: 0x%08x (Bad CRC32, should be 0x%08x)", sent, crc);
		}
	    }
	    return offset + dataLen + 4;
	}
	if((unsigned)available_bytes >= (dataLen + dataDigestSize)) {
	    proto_tree_add_item(ti, hf_iscsi_DataDigest, tvb, offset + dataLen, dataDigestSize, ENC_NA);
	}
	return offset + dataLen + dataDigestSize;
    }
    return offset + dataLen;
}

static int
handleDataSegment(proto_item *ti, tvbuff_t *tvb, guint offset, guint dataSegmentLen, guint endOffset, int hf_id) {
    if(endOffset > offset) {
	int dataOffset = offset;
	int dataLen = MIN(dataSegmentLen, endOffset - offset);
	if(dataLen > 0) {
	    proto_tree_add_item(ti, hf_id, tvb, offset, dataLen, FALSE);
	    offset += dataLen;
	}
	if(offset < endOffset && (offset & 3) != 0) {
	    int padding = 4 - (offset & 3);
	    proto_tree_add_item(ti, hf_iscsi_Padding, tvb, offset, padding, ENC_NA);
	    offset += padding;
	}
	if(dataSegmentLen > 0 && offset < endOffset)
	    offset = handleDataDigest(ti, tvb, dataOffset, offset - dataOffset);
    }

    return offset;
}

static int
handleDataSegmentAsTextKeys(packet_info *pinfo, proto_item *ti, tvbuff_t *tvb, guint offset, guint dataSegmentLen, guint endOffset, int digestsActive) {
    if(endOffset > offset) {
	int dataOffset = offset;
	int textLen = MIN(dataSegmentLen, endOffset - offset);
	if(textLen > 0) {
	    proto_item *tf = proto_tree_add_text(ti, tvb, offset, textLen, "Key/Value Pairs");
	    proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_KeyValues);
	    offset = addTextKeys(pinfo, tt, tvb, offset, textLen);
	}
	if(offset < endOffset && (offset & 3) != 0) {
	    int padding = 4 - (offset & 3);
	    proto_tree_add_item(ti, hf_iscsi_Padding, tvb, offset, padding, ENC_NA);
	    offset += padding;
	}
	if(digestsActive && dataSegmentLen > 0 && offset < endOffset)
	    offset = handleDataDigest(ti, tvb, dataOffset, offset - dataOffset);
    }
    return offset;
}

/* Code to actually dissect the packets */
static void
dissect_iscsi_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint8 opcode, const char *opcode_str, guint32 data_segment_len, iscsi_session_t *iscsi_session, conversation_t *conversation) {

    guint original_offset = offset;
    proto_tree *ti = NULL;
    guint8 scsi_status = 0;
    gboolean S_bit=FALSE;
    guint cdb_offset = offset + 32; /* offset of CDB from start of PDU */
    guint end_offset = offset + tvb_length_remaining(tvb, offset);
    iscsi_conv_data_t *cdata = NULL;
    int paddedDataSegmentLength = data_segment_len;
    guint16 lun=0xffff;
    guint immediate_data_length=0;
    guint immediate_data_offset=0;
    itl_nexus_t *itl=NULL;
    guint ahs_cdb_length=0;
    guint ahs_cdb_offset=0;
    guint32 data_offset=0;

    if(paddedDataSegmentLength & 3)
	paddedDataSegmentLength += 4 - (paddedDataSegmentLength & 3);

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "iSCSI");

    /* XXX we need a way to handle replayed iscsi itt here */
    cdata=(iscsi_conv_data_t *)se_tree_lookup32(iscsi_session->itlq, tvb_get_ntohl(tvb, offset+16));
    if(!cdata){
        cdata = se_alloc (sizeof(iscsi_conv_data_t));
        cdata->itlq.lun=0xffff;
        cdata->itlq.scsi_opcode=0xffff;
	cdata->itlq.task_flags=0;
	cdata->itlq.data_length=0;
	cdata->itlq.bidir_data_length=0;
        cdata->itlq.fc_time = pinfo->fd->abs_ts;
        cdata->itlq.first_exchange_frame=0;
        cdata->itlq.last_exchange_frame=0;
        cdata->itlq.flags=0;
        cdata->itlq.alloc_len=0;
        cdata->itlq.extra_data=NULL;
        cdata->data_in_frame=0;
        cdata->data_out_frame=0;

        se_tree_insert32(iscsi_session->itlq, tvb_get_ntohl(tvb, offset+16), cdata);
    }

    if (opcode == ISCSI_OPCODE_SCSI_RESPONSE ||
	opcode == ISCSI_OPCODE_SCSI_DATA_IN) {
        scsi_status = tvb_get_guint8 (tvb, offset+3);
    }

    if ((opcode == ISCSI_OPCODE_SCSI_RESPONSE) ||
        (opcode == ISCSI_OPCODE_SCSI_DATA_IN) ||
        (opcode == ISCSI_OPCODE_SCSI_DATA_OUT)) {
        /* first time we see this packet. check if we can find the request */
        switch(opcode){
        case ISCSI_OPCODE_SCSI_RESPONSE:
            cdata->itlq.last_exchange_frame=pinfo->fd->num;
            break;
        case ISCSI_OPCODE_SCSI_DATA_IN:
            /* a bit ugly but we need to check the S bit here */
            if(tvb_get_guint8(tvb, offset+1)&ISCSI_SCSI_DATA_FLAG_S){
                cdata->itlq.last_exchange_frame=pinfo->fd->num;
            }
            cdata->data_in_frame=pinfo->fd->num;
            break;
        case ISCSI_OPCODE_SCSI_DATA_OUT:
            cdata->data_out_frame=pinfo->fd->num;
            break;
        }

    } else if (opcode == ISCSI_OPCODE_SCSI_COMMAND) {
        /*we need the LUN value for some of the commands so we can pass it
          across to the SCSI dissector.
          Not correct but simple  and probably accurate enough :
          If bit 6 of first bit is 0   then just take second byte as the LUN
          If bit 6 of first bit is 1, then take 6 bits from first byte
          and all of second byte and pretend it is the lun value
	  people that care can add host specific dissection of vsa later.

          We need to keep track of this on a per transaction basis since
          for error recoverylevel 0 and when the A bit is clear in a
          Data-In PDU, there will not be a LUN field in teh iscsi layer.
        */
        if(tvb_get_guint8(tvb, offset+8)&0x40){
          /* volume set addressing */
          lun=tvb_get_guint8(tvb,offset+8)&0x3f;
          lun<<=8;
          lun|=tvb_get_guint8(tvb,offset+9);
        } else {
          lun=tvb_get_guint8(tvb,offset+9);
        }

        cdata->itlq.lun=lun;
        cdata->itlq.first_exchange_frame=pinfo->fd->num;

        itl=(itl_nexus_t *)se_tree_lookup32(iscsi_session->itl, lun);
        if(!itl){
            itl=se_alloc(sizeof(itl_nexus_t));
            itl->cmdset=0xff;
            itl->conversation=conversation;
            se_tree_insert32(iscsi_session->itl, lun, itl);
        }

    }

    if(!itl){
        itl=(itl_nexus_t *)se_tree_lookup32(iscsi_session->itl, cdata->itlq.lun);
    }


    if (check_col(pinfo->cinfo, COL_INFO)) {

        if (opcode != ISCSI_OPCODE_SCSI_COMMAND) {

            col_append_str(pinfo->cinfo, COL_INFO, opcode_str);

	    if (opcode == ISCSI_OPCODE_SCSI_RESPONSE ||
		(opcode == ISCSI_OPCODE_SCSI_DATA_IN &&
		 (tvb_get_guint8(tvb, offset + 1) & ISCSI_SCSI_DATA_FLAG_S))) {
		col_append_fstr (pinfo->cinfo, COL_INFO, " (%s)",
				 val_to_str (scsi_status, scsi_status_val, "0x%x"));
	    }
	    else if (opcode == ISCSI_OPCODE_LOGIN_RESPONSE) {
		guint16 login_status = tvb_get_ntohs(tvb, offset+36);
		col_append_fstr (pinfo->cinfo, COL_INFO, " (%s)",
				 val_to_str (login_status, iscsi_login_status, "0x%x"));
	    }
	    else if (opcode == ISCSI_OPCODE_LOGOUT_COMMAND) {
		guint8 logoutReason;
		if(iscsi_protocol_version == ISCSI_PROTOCOL_DRAFT08) {
		    logoutReason = tvb_get_guint8(tvb, offset+11);
		} else if(iscsi_protocol_version >= ISCSI_PROTOCOL_DRAFT13) {
		    logoutReason = tvb_get_guint8(tvb, offset+1) & 0x7f;
		}
		else {
		    logoutReason = tvb_get_guint8(tvb, offset+23);
		}
		col_append_fstr (pinfo->cinfo, COL_INFO, " (%s)",
				 val_to_str (logoutReason, iscsi_logout_reasons, "0x%x"));
	    }
	    else if (opcode == ISCSI_OPCODE_TASK_MANAGEMENT_FUNCTION) {
		guint8 tmf = tvb_get_guint8(tvb, offset + 1);
		col_append_fstr (pinfo->cinfo, COL_INFO, " (%s)",
				 val_to_str (tmf, iscsi_task_management_functions, "0x%x"));
	    }
	    else if (opcode == ISCSI_OPCODE_TASK_MANAGEMENT_FUNCTION_RESPONSE) {
		guint8 resp = tvb_get_guint8(tvb, offset + 2);
		col_append_fstr (pinfo->cinfo, COL_INFO, " (%s)",
				 val_to_str (resp, iscsi_task_management_responses, "0x%x"));
	    }
	    else if (opcode == ISCSI_OPCODE_REJECT) {
		guint8 reason = tvb_get_guint8(tvb, offset + 2);
		col_append_fstr (pinfo->cinfo, COL_INFO, " (%s)",
				 val_to_str (reason, iscsi_reject_reasons, "0x%x"));
	    }
	    else if (opcode == ISCSI_OPCODE_ASYNC_MESSAGE) {
		guint8 asyncEvent = tvb_get_guint8(tvb, offset + 36);
		col_append_fstr (pinfo->cinfo, COL_INFO, " (%s)",
				 val_to_str (asyncEvent, iscsi_asyncevents, "0x%x"));
	    }
	}
    }

    /* In the interest of speed, if "tree" is NULL, don't do any
       work not necessary to generate protocol tree items. */
    if (tree) {
	proto_item *tp;
	/* create display subtree for the protocol */
	tp = proto_tree_add_protocol_format(tree, proto_iscsi, tvb,
					    offset, -1, "iSCSI (%s)",
					    opcode_str);
	ti = proto_item_add_subtree(tp, ett_iscsi);
    }
    proto_tree_add_uint(ti, hf_iscsi_Opcode, tvb,
			    offset + 0, 1, opcode);
    if((opcode & TARGET_OPCODE_BIT) == 0) {
	    /* initiator -> target */
	    gint b = tvb_get_guint8(tvb, offset + 0);
	if(iscsi_protocol_version == ISCSI_PROTOCOL_DRAFT08) {
		if(opcode != ISCSI_OPCODE_SCSI_DATA_OUT &&
		   opcode != ISCSI_OPCODE_LOGOUT_COMMAND &&
		   opcode != ISCSI_OPCODE_SNACK_REQUEST)
		    proto_tree_add_boolean(ti, hf_iscsi_X, tvb, offset + 0, 1, b);
	}
	    if(opcode != ISCSI_OPCODE_SCSI_DATA_OUT &&
	       opcode != ISCSI_OPCODE_LOGIN_COMMAND &&
	       opcode != ISCSI_OPCODE_SNACK_REQUEST)
		proto_tree_add_boolean(ti, hf_iscsi_I, tvb, offset + 0, 1, b);
    }

    if(opcode == ISCSI_OPCODE_NOP_OUT) {
	    /* NOP Out */
	    if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
		proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
	    }
	    proto_tree_add_uint(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, tvb_get_ntoh24(tvb, offset + 5));
	    proto_tree_add_item(ti, hf_iscsi_LUN, tvb, offset + 8, 8, ENC_NA);
	    proto_tree_add_item(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_TargetTransferTag, tvb, offset + 20, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_CmdSN, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_ExpStatSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
	    offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);
	    offset = handleDataSegment(ti, tvb, offset, data_segment_len, end_offset, hf_iscsi_ping_data);
    } else if(opcode == ISCSI_OPCODE_NOP_IN) {
	    /* NOP In */
	    if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
		proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
	    }
	    proto_tree_add_uint(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, tvb_get_ntoh24(tvb, offset + 5));
	    proto_tree_add_item(ti, hf_iscsi_LUN, tvb, offset + 8, 8, ENC_NA);
	    proto_tree_add_item(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_TargetTransferTag, tvb, offset + 20, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_StatSN, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_ExpCmdSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_MaxCmdSN, tvb, offset + 32, 4, ENC_BIG_ENDIAN);
	    offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);
	    offset = handleDataSegment(ti, tvb, offset, data_segment_len, end_offset, hf_iscsi_ping_data);
    } else if(opcode == ISCSI_OPCODE_SCSI_COMMAND) {
	    /* SCSI Command */
	    guint32 ahsLen = tvb_get_guint8(tvb, offset + 4) * 4;
    	    {
		gint b = tvb_get_guint8(tvb, offset + 1);

		proto_item *tf = proto_tree_add_uint(ti, hf_iscsi_Flags, tvb, offset + 1, 1, b);
		proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_Flags);

		proto_tree_add_boolean(tt, hf_iscsi_SCSICommand_F, tvb, offset + 1, 1, b);
		proto_tree_add_boolean(tt, hf_iscsi_SCSICommand_R, tvb, offset + 1, 1, b);
		if(b&0x40){
		    cdata->itlq.task_flags|=SCSI_DATA_READ;
		}
		proto_tree_add_boolean(tt, hf_iscsi_SCSICommand_W, tvb, offset + 1, 1, b);
		if(b&0x20){
		    cdata->itlq.task_flags|=SCSI_DATA_WRITE;
		}
		proto_tree_add_uint(tt, hf_iscsi_SCSICommand_Attr, tvb, offset + 1, 1, b);
	    }
	    if(iscsi_protocol_version < ISCSI_PROTOCOL_DRAFT12) {
		proto_tree_add_item(ti, hf_iscsi_SCSICommand_CRN, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
	    }
	    proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
	    proto_tree_add_uint(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, tvb_get_ntoh24(tvb, offset + 5));
	    proto_tree_add_item(ti, hf_iscsi_LUN, tvb, offset + 8, 8, ENC_NA);
	    proto_tree_add_item(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_ExpectedDataTransferLength, tvb, offset + 20, 4, ENC_BIG_ENDIAN);
	    cdata->itlq.data_length=tvb_get_ntohl(tvb, offset+20);
	    proto_tree_add_item(ti, hf_iscsi_CmdSN, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_ExpStatSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
	    if(ahsLen > 0) {
		guint ahs_offset=offset+48;
		guint16 ahs_length=0;
		guint8 ahs_type=0;

		while(ahs_offset<(offset+48+ahsLen)){

		    ahs_length=tvb_get_ntohs(tvb, ahs_offset);
		    proto_tree_add_item(ti, hf_iscsi_AHS_length, tvb, ahs_offset, 2, ENC_BIG_ENDIAN);
		    ahs_offset+=2;

		    ahs_type=tvb_get_guint8(tvb, ahs_offset);
		    proto_tree_add_item(ti, hf_iscsi_AHS_type, tvb, ahs_offset, 1, ENC_BIG_ENDIAN);
		    ahs_offset++;

		    switch(ahs_type){
		    case 0x01: /* extended CDB */
			/* additional cdb */
			ahs_cdb_offset=ahs_offset+1;
			ahs_cdb_length=ahs_length-1;
			proto_tree_add_item(ti, hf_iscsi_AHS_extended_cdb, tvb, ahs_cdb_offset, ahs_cdb_length, ENC_NA);
			ahs_offset+=ahs_length;
			break;
		    case 0x02: /* bidirectional read data length */
			/* skip reserved byte */
			ahs_offset++;
			/* read data length */
			proto_tree_add_item(ti, hf_iscsi_AHS_read_data_length, tvb, ahs_offset, 4, ENC_BIG_ENDIAN);
			cdata->itlq.bidir_data_length=tvb_get_ntohl(tvb, ahs_offset);
			ahs_offset+=4;
			break;
		    default:
			proto_tree_add_item(ti, hf_iscsi_AHS_blob, tvb, ahs_offset, ahs_length, ENC_NA);
			ahs_offset+=ahs_length;
		    }

		    /* strip off padding bytes */
		    if(ahs_offset&0x0003){
			ahs_offset=(ahs_offset+3)&0xfffc;
		    }

		}

	    }
	    offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48 + ahsLen);

            immediate_data_offset=offset;
	    offset = handleDataSegment(ti, tvb, offset, data_segment_len, end_offset, hf_iscsi_immediate_data);
	    immediate_data_length=offset-immediate_data_offset;
    } else if(opcode == ISCSI_OPCODE_SCSI_RESPONSE) {
	    /* SCSI Response */
	    {
		gint b = tvb_get_guint8(tvb, offset + 1);
		proto_item *tf = proto_tree_add_uint(ti, hf_iscsi_Flags, tvb, offset + 1, 1, b);
		proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_Flags);

		proto_tree_add_boolean(tt, hf_iscsi_SCSIResponse_o, tvb, offset + 1, 1, b);
		proto_tree_add_boolean(tt, hf_iscsi_SCSIResponse_u, tvb, offset + 1, 1, b);
		proto_tree_add_boolean(tt, hf_iscsi_SCSIResponse_O, tvb, offset + 1, 1, b);
		proto_tree_add_boolean(tt, hf_iscsi_SCSIResponse_U, tvb, offset + 1, 1, b);
	    }
	    proto_tree_add_item(ti, hf_iscsi_SCSIResponse_Response, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_SCSIResponse_Status, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
	    if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
		proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
	    }
	    proto_tree_add_uint(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, tvb_get_ntoh24(tvb, offset + 5));
	    proto_tree_add_item(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
	    if(iscsi_protocol_version <= ISCSI_PROTOCOL_DRAFT09) {
		proto_tree_add_item(ti, hf_iscsi_SCSIResponse_ResidualCount, tvb, offset + 20, 4, ENC_BIG_ENDIAN);
	    }
	    proto_tree_add_item(ti, hf_iscsi_StatSN, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_ExpCmdSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_MaxCmdSN, tvb, offset + 32, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_ExpDataSN, tvb, offset + 36, 4, ENC_BIG_ENDIAN);
	    if(iscsi_protocol_version <= ISCSI_PROTOCOL_DRAFT09) {
		proto_tree_add_item(ti, hf_iscsi_SCSIResponse_BidiReadResidualCount, tvb, offset + 44, 4, ENC_BIG_ENDIAN);
	    }
	    else {
		proto_tree_add_item(ti, hf_iscsi_SCSIResponse_BidiReadResidualCount, tvb, offset + 40, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(ti, hf_iscsi_SCSIResponse_ResidualCount, tvb, offset + 44, 4, ENC_BIG_ENDIAN);
	    }
	    offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);
	    /* do not update offset here because the data segment is
	     * dissected below */
	    handleDataDigest(ti, tvb, offset, paddedDataSegmentLength);
    } else if(opcode == ISCSI_OPCODE_TASK_MANAGEMENT_FUNCTION) {
	    /* Task Management Function */
 	    proto_tree_add_item(ti, hf_iscsi_TaskManagementFunction_Function, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
	    if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
		proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
		proto_tree_add_uint(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, tvb_get_ntoh24(tvb, offset + 5));
	    }
	    proto_tree_add_item(ti, hf_iscsi_LUN, tvb, offset + 8, 8, ENC_NA);
	    proto_tree_add_item(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_TaskManagementFunction_ReferencedTaskTag, tvb, offset + 20, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_CmdSN, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_ExpStatSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_RefCmdSN, tvb, offset + 32, 4, ENC_BIG_ENDIAN);
	    offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);
    } else if(opcode == ISCSI_OPCODE_TASK_MANAGEMENT_FUNCTION_RESPONSE) {
	    /* Task Management Function Response */
	    proto_tree_add_item(ti, hf_iscsi_TaskManagementFunction_Response, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
	    if(iscsi_protocol_version <= ISCSI_PROTOCOL_DRAFT09) {
		proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
		proto_tree_add_uint(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, tvb_get_ntoh24(tvb, offset + 5));
	    }
	    proto_tree_add_item(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
	    if(iscsi_protocol_version < ISCSI_PROTOCOL_DRAFT12) {
		proto_tree_add_item(ti, hf_iscsi_TaskManagementFunction_ReferencedTaskTag, tvb, offset + 20, 4, ENC_BIG_ENDIAN);
	    }
	    proto_tree_add_item(ti, hf_iscsi_StatSN, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_ExpCmdSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_MaxCmdSN, tvb, offset + 32, 4, ENC_BIG_ENDIAN);
	    offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);
    } else if(opcode == ISCSI_OPCODE_LOGIN_COMMAND) {
	    /* Login Command */
	    int digestsActive = 0;
	    {
		gint b = tvb_get_guint8(tvb, offset + 1);
		if(iscsi_protocol_version == ISCSI_PROTOCOL_DRAFT08) {
		    if((b & CSG_MASK) >= ISCSI_CSG_OPERATIONAL_NEGOTIATION)
			digestsActive = 1;
		}
#if 0
		proto_item *tf = proto_tree_add_uint(ti, hf_iscsi_Flags, tvb, offset + 1, 1, b);
		proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_Flags);
#endif

		proto_tree_add_boolean(ti, hf_iscsi_Login_T, tvb, offset + 1, 1, b);
		if(iscsi_protocol_version >= ISCSI_PROTOCOL_DRAFT13) {
		    proto_tree_add_boolean(ti, hf_iscsi_Login_C, tvb, offset + 1, 1, b);
		}
		if(iscsi_protocol_version == ISCSI_PROTOCOL_DRAFT08) {
		    proto_tree_add_boolean(ti, hf_iscsi_Login_X, tvb, offset + 1, 1, b);
		}
		proto_tree_add_item(ti, hf_iscsi_Login_CSG, tvb, offset + 1, 1, ENC_BIG_ENDIAN);

		/* NSG is undefined unless T is set */
		if(b&0x80){
			proto_tree_add_item(ti, hf_iscsi_Login_NSG, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
		}
	    }
	    proto_tree_add_item(ti, hf_iscsi_VersionMax, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_VersionMin, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
	    if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
		proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
	    }
	    proto_tree_add_uint(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, tvb_get_ntoh24(tvb, offset + 5));
	    if(iscsi_protocol_version == ISCSI_PROTOCOL_DRAFT08) {
		proto_tree_add_item(ti, hf_iscsi_CID, tvb, offset + 8, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(ti, hf_iscsi_ISID8, tvb, offset + 12, 2, ENC_BIG_ENDIAN);
	    }
	    else {
		proto_item *tf = proto_tree_add_item(ti, hf_iscsi_ISID, tvb, offset + 8, 6, ENC_NA);
		proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_ISID);
		if(iscsi_protocol_version == ISCSI_PROTOCOL_DRAFT09) {
		    proto_tree_add_item(tt, hf_iscsi_ISID_Type, tvb, offset + 8, 1, ENC_BIG_ENDIAN);
		    proto_tree_add_item(tt, hf_iscsi_ISID_NamingAuthority, tvb, offset + 9, 3, ENC_BIG_ENDIAN);
		    proto_tree_add_item(tt, hf_iscsi_ISID_Qualifier, tvb, offset + 12, 2, ENC_BIG_ENDIAN);
		}
		else {
		    proto_tree_add_item(tt, hf_iscsi_ISID_t, tvb, offset + 8, 1, ENC_BIG_ENDIAN);
		    proto_tree_add_item(tt, hf_iscsi_ISID_a, tvb, offset + 8, 1, ENC_BIG_ENDIAN);
		    proto_tree_add_item(tt, hf_iscsi_ISID_b, tvb, offset + 9, 2, ENC_BIG_ENDIAN);
		    proto_tree_add_item(tt, hf_iscsi_ISID_c, tvb, offset + 11, 1, ENC_BIG_ENDIAN);
		    proto_tree_add_item(tt, hf_iscsi_ISID_d, tvb, offset + 12, 2, ENC_BIG_ENDIAN);
		}
	    }
	    if(iscsi_protocol_version < ISCSI_PROTOCOL_DRAFT12) {
		proto_tree_add_item(ti, hf_iscsi_TSID, tvb, offset + 14, 2, ENC_BIG_ENDIAN);
	    }
	    else {
		proto_tree_add_item(ti, hf_iscsi_TSIH, tvb, offset + 14, 2, ENC_BIG_ENDIAN);
	    }
	    proto_tree_add_item(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
	    if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT08) {
		proto_tree_add_item(ti, hf_iscsi_CID, tvb, offset + 20, 2, ENC_BIG_ENDIAN);
	    }
	    proto_tree_add_item(ti, hf_iscsi_CmdSN, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_ExpStatSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
	    if(digestsActive){
		offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);
	    } else {
		offset += 48;
	    }
	    offset = handleDataSegmentAsTextKeys(pinfo, ti, tvb, offset, data_segment_len, end_offset, digestsActive);
    } else if(opcode == ISCSI_OPCODE_LOGIN_RESPONSE) {
	    /* Login Response */
	    int digestsActive = 0;
	    {
		gint b = tvb_get_guint8(tvb, offset + 1);
		if(iscsi_protocol_version == ISCSI_PROTOCOL_DRAFT08) {
		    if((b & CSG_MASK) >= ISCSI_CSG_OPERATIONAL_NEGOTIATION)
			digestsActive = 1;
		}
#if 0
		proto_item *tf = proto_tree_add_uint(ti, hf_iscsi_Flags, tvb, offset + 1, 1, b);
		proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_Flags);
#endif

		proto_tree_add_boolean(ti, hf_iscsi_Login_T, tvb, offset + 1, 1, b);
		if(iscsi_protocol_version >= ISCSI_PROTOCOL_DRAFT13) {
		    proto_tree_add_boolean(ti, hf_iscsi_Login_C, tvb, offset + 1, 1, b);
		}
		proto_tree_add_item(ti, hf_iscsi_Login_CSG, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
		/* NSG is undefined unless T is set */
		if(b&0x80){
			proto_tree_add_item(ti, hf_iscsi_Login_NSG, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
		}
	    }

	    proto_tree_add_item(ti, hf_iscsi_VersionMax, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_VersionActive, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
	    if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
		proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
	    }
	    proto_tree_add_uint(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, tvb_get_ntoh24(tvb, offset + 5));
	    if(iscsi_protocol_version == ISCSI_PROTOCOL_DRAFT08) {
		proto_tree_add_item(ti, hf_iscsi_ISID8, tvb, offset + 12, 2, ENC_BIG_ENDIAN);
	    }
	    else {
		proto_item *tf = proto_tree_add_item(ti, hf_iscsi_ISID, tvb, offset + 8, 6, ENC_NA);
		proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_ISID);
		if(iscsi_protocol_version == ISCSI_PROTOCOL_DRAFT09) {
		    proto_tree_add_item(tt, hf_iscsi_ISID_Type, tvb, offset + 8, 1, ENC_BIG_ENDIAN);
		    proto_tree_add_item(tt, hf_iscsi_ISID_NamingAuthority, tvb, offset + 9, 3, ENC_BIG_ENDIAN);
		    proto_tree_add_item(tt, hf_iscsi_ISID_Qualifier, tvb, offset + 12, 2, ENC_BIG_ENDIAN);
		}
		else {
		    proto_tree_add_item(tt, hf_iscsi_ISID_t, tvb, offset + 8, 1, ENC_BIG_ENDIAN);
		    proto_tree_add_item(tt, hf_iscsi_ISID_a, tvb, offset + 8, 1, ENC_BIG_ENDIAN);
		    proto_tree_add_item(tt, hf_iscsi_ISID_b, tvb, offset + 9, 2, ENC_BIG_ENDIAN);
		    proto_tree_add_item(tt, hf_iscsi_ISID_c, tvb, offset + 11, 1, ENC_BIG_ENDIAN);
		    proto_tree_add_item(tt, hf_iscsi_ISID_d, tvb, offset + 12, 2, ENC_BIG_ENDIAN);
		}
	    }
	    if(iscsi_protocol_version < ISCSI_PROTOCOL_DRAFT12) {
		proto_tree_add_item(ti, hf_iscsi_TSID, tvb, offset + 14, 2, ENC_BIG_ENDIAN);
	    }
	    else {
		proto_tree_add_item(ti, hf_iscsi_TSIH, tvb, offset + 14, 2, ENC_BIG_ENDIAN);
	    }
	    proto_tree_add_item(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_StatSN, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_ExpCmdSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_MaxCmdSN, tvb, offset + 32, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_Login_Status, tvb, offset + 36, 2, ENC_BIG_ENDIAN);
	    if(digestsActive){
		offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);
	    } else {
		offset += 48;
	    }
	    offset = handleDataSegmentAsTextKeys(pinfo, ti, tvb, offset, data_segment_len, end_offset, digestsActive);
    } else if(opcode == ISCSI_OPCODE_TEXT_COMMAND) {
	    /* Text Command */
	    {
		gint b = tvb_get_guint8(tvb, offset + 1);
		proto_item *tf = proto_tree_add_uint(ti, hf_iscsi_Flags, tvb, offset + 1, 1, b);
		proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_Flags);

		proto_tree_add_boolean(tt, hf_iscsi_Text_F, tvb, offset + 1, 1, b);
		if(iscsi_protocol_version >= ISCSI_PROTOCOL_DRAFT13) {
		    proto_tree_add_boolean(tt, hf_iscsi_Text_C, tvb, offset + 1, 1, b);
		}
	    }
	    if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
		proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
	    }
	    proto_tree_add_uint(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, tvb_get_ntoh24(tvb, offset + 5));
	    if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
		proto_tree_add_item(ti, hf_iscsi_LUN, tvb, offset + 8, 8, ENC_NA);
	    }
	    proto_tree_add_item(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_TargetTransferTag, tvb, offset + 20, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_CmdSN, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_ExpStatSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
	    offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);
	    offset = handleDataSegmentAsTextKeys(pinfo, ti, tvb, offset, data_segment_len, end_offset, TRUE);
    } else if(opcode == ISCSI_OPCODE_TEXT_RESPONSE) {
	    /* Text Response */
	    {
		gint b = tvb_get_guint8(tvb, offset + 1);
		proto_item *tf = proto_tree_add_uint(ti, hf_iscsi_Flags, tvb, offset + 1, 1, b);
		proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_Flags);

		proto_tree_add_boolean(tt, hf_iscsi_Text_F, tvb, offset + 1, 1, b);
		if(iscsi_protocol_version >= ISCSI_PROTOCOL_DRAFT13) {
		    proto_tree_add_boolean(tt, hf_iscsi_Text_C, tvb, offset + 1, 1, b);
		}
	    }
	    if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
		proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
	    }
	    proto_tree_add_uint(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, tvb_get_ntoh24(tvb, offset + 5));
	    if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
		proto_tree_add_item(ti, hf_iscsi_LUN, tvb, offset + 8, 8, ENC_NA);
	    }
	    proto_tree_add_item(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_TargetTransferTag, tvb, offset + 20, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_StatSN, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_ExpCmdSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_MaxCmdSN, tvb, offset + 32, 4, ENC_BIG_ENDIAN);
	    offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);
	    offset = handleDataSegmentAsTextKeys(pinfo, ti, tvb, offset, data_segment_len, end_offset, TRUE);
    } else if(opcode == ISCSI_OPCODE_SCSI_DATA_OUT) {
	    /* SCSI Data Out (write) */
	    {
		gint b = tvb_get_guint8(tvb, offset + 1);
		proto_item *tf = proto_tree_add_uint(ti, hf_iscsi_Flags, tvb, offset + 1, 1, b);
		proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_Flags);

		proto_tree_add_boolean(tt, hf_iscsi_SCSIData_F, tvb, offset + 1, 1, b);
	    }
	    if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
		proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
	    }
	    proto_tree_add_uint(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, tvb_get_ntoh24(tvb, offset + 5));
	    proto_tree_add_item(ti, hf_iscsi_LUN, tvb, offset + 8, 8, ENC_NA);
	    proto_tree_add_item(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_TargetTransferTag, tvb, offset + 20, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_ExpStatSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_DataSN, tvb, offset + 36, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_BufferOffset, tvb, offset + 40, 4, ENC_BIG_ENDIAN);
	    data_offset=tvb_get_ntohl(tvb, offset+40);

	    offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);
	    /* do not update offset here because the data segment is
	     * dissected below */
	    handleDataDigest(ti, tvb, offset, paddedDataSegmentLength);
    } else if(opcode == ISCSI_OPCODE_SCSI_DATA_IN) {
	    /* SCSI Data In (read) */
	    {
		gint b = tvb_get_guint8(tvb, offset + 1);
		proto_item *tf = proto_tree_add_uint(ti, hf_iscsi_Flags, tvb, offset + 1, 1, b);
		proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_Flags);

                if(b&ISCSI_SCSI_DATA_FLAG_S){
                   S_bit=TRUE;
                }
		proto_tree_add_boolean(tt, hf_iscsi_SCSIData_F, tvb, offset + 1, 1, b);
		if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT08) {
		    proto_tree_add_boolean(tt, hf_iscsi_SCSIData_A, tvb, offset + 1, 1, b);
		}
		proto_tree_add_boolean(tt, hf_iscsi_SCSIData_O, tvb, offset + 1, 1, b);
		proto_tree_add_boolean(tt, hf_iscsi_SCSIData_U, tvb, offset + 1, 1, b);
		proto_tree_add_boolean(tt, hf_iscsi_SCSIData_S, tvb, offset + 1, 1, b);
	    }
	    if(S_bit){
		proto_tree_add_item(ti, hf_iscsi_SCSIResponse_Status, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
	    }
	    if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
		proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
	    }
	    proto_tree_add_uint(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, tvb_get_ntoh24(tvb, offset + 5));
	    if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
		proto_tree_add_item(ti, hf_iscsi_LUN, tvb, offset + 8, 8, ENC_NA);
	    }
	    proto_tree_add_item(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
	    if(iscsi_protocol_version <= ISCSI_PROTOCOL_DRAFT09) {
		proto_tree_add_item(ti, hf_iscsi_SCSIData_ResidualCount, tvb, offset + 20, 4, ENC_BIG_ENDIAN);
	    }
	    else {
		proto_tree_add_item(ti, hf_iscsi_TargetTransferTag, tvb, offset + 20, 4, ENC_BIG_ENDIAN);
	    }
	    proto_tree_add_item(ti, hf_iscsi_StatSN, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_ExpCmdSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_MaxCmdSN, tvb, offset + 32, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_DataSN, tvb, offset + 36, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_BufferOffset, tvb, offset + 40, 4, ENC_BIG_ENDIAN);
	    data_offset=tvb_get_ntohl(tvb, offset+40);

	    if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
		proto_tree_add_item(ti, hf_iscsi_SCSIData_ResidualCount, tvb, offset + 44, 4, ENC_BIG_ENDIAN);
	    }
	    offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);
	    /* do not update offset here because the data segment is
	     * dissected below */
	    handleDataDigest(ti, tvb, offset, paddedDataSegmentLength);
    } else if(opcode == ISCSI_OPCODE_LOGOUT_COMMAND) {
	    /* Logout Command */
	    if(iscsi_protocol_version >= ISCSI_PROTOCOL_DRAFT13) {
		proto_tree_add_item(ti, hf_iscsi_Logout_Reason, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
	    }
	    if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
		proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
		proto_tree_add_uint(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, tvb_get_ntoh24(tvb, offset + 5));
	    }
	    if(iscsi_protocol_version == ISCSI_PROTOCOL_DRAFT08) {
		proto_tree_add_item(ti, hf_iscsi_CID, tvb, offset + 8, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(ti, hf_iscsi_Logout_Reason, tvb, offset + 11, 1, ENC_BIG_ENDIAN);
	    }
	    proto_tree_add_item(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
	    if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT08) {
		proto_tree_add_item(ti, hf_iscsi_CID, tvb, offset + 20, 2, ENC_BIG_ENDIAN);
		if(iscsi_protocol_version < ISCSI_PROTOCOL_DRAFT13) {
		    proto_tree_add_item(ti, hf_iscsi_Logout_Reason, tvb, offset + 23, 1, ENC_BIG_ENDIAN);
		}
	    }
	    proto_tree_add_item(ti, hf_iscsi_CmdSN, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_ExpStatSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
	    offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);
    } else if(opcode == ISCSI_OPCODE_LOGOUT_RESPONSE) {
	    /* Logout Response */
	    proto_tree_add_item(ti, hf_iscsi_Logout_Response, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
	    if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
		proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
		proto_tree_add_uint(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, tvb_get_ntoh24(tvb, offset + 5));
	    }
	    proto_tree_add_item(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_StatSN, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_ExpCmdSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_MaxCmdSN, tvb, offset + 32, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_Time2Wait, tvb, offset + 40, 2, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_Time2Retain, tvb, offset + 42, 2, ENC_BIG_ENDIAN);
	    offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);
    } else if(opcode == ISCSI_OPCODE_SNACK_REQUEST) {
	    /* SNACK Request */
	    {
#if 0
		gint b = tvb_get_guint8(tvb, offset + 1);
		proto_item *tf = proto_tree_add_uint(ti, hf_iscsi_Flags, tvb, offset + 1, 1, b);
		proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_Flags);
#endif

		proto_tree_add_item(ti, hf_iscsi_snack_type, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
	    }
	    if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
		proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
		proto_tree_add_uint(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, tvb_get_ntoh24(tvb, offset + 5));
		proto_tree_add_item(ti, hf_iscsi_LUN, tvb, offset + 8, 8, ENC_NA);
	    }
	    proto_tree_add_item(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
	    if(iscsi_protocol_version <= ISCSI_PROTOCOL_DRAFT09) {
		proto_tree_add_item(ti, hf_iscsi_BegRun, tvb, offset + 20, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(ti, hf_iscsi_RunLength, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(ti, hf_iscsi_ExpStatSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(ti, hf_iscsi_ExpDataSN, tvb, offset + 36, 4, ENC_BIG_ENDIAN);
	    }
	    else {
		proto_tree_add_item(ti, hf_iscsi_TargetTransferTag, tvb, offset + 20, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(ti, hf_iscsi_ExpStatSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(ti, hf_iscsi_BegRun, tvb, offset + 40, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(ti, hf_iscsi_RunLength, tvb, offset + 44, 4, ENC_BIG_ENDIAN);
	    }
	    offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);
    } else if(opcode == ISCSI_OPCODE_R2T) {
	    /* R2T */
	    if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
		proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
		proto_tree_add_uint(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, tvb_get_ntoh24(tvb, offset + 5));
		proto_tree_add_item(ti, hf_iscsi_LUN, tvb, offset + 8, 8, ENC_NA);
	    }
	    proto_tree_add_item(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_TargetTransferTag, tvb, offset + 20, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_StatSN, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_ExpCmdSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_MaxCmdSN, tvb, offset + 32, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_R2TSN, tvb, offset + 36, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_BufferOffset, tvb, offset + 40, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_DesiredDataLength, tvb, offset + 44, 4, ENC_BIG_ENDIAN);
	    offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);
    } else if(opcode == ISCSI_OPCODE_ASYNC_MESSAGE) {
	    int dsl, snsl;

	    /* Asynchronous Message */
	    if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
		proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
	    }
	    dsl=tvb_get_ntoh24(tvb, offset+5);
	    proto_tree_add_uint(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, tvb_get_ntoh24(tvb, offset + 5));
	    proto_tree_add_item(ti, hf_iscsi_LUN, tvb, offset + 8, 8, ENC_NA);
	    proto_tree_add_item(ti, hf_iscsi_StatSN, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_ExpCmdSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_MaxCmdSN, tvb, offset + 32, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_AsyncEvent, tvb, offset + 36, 1, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_EventVendorCode, tvb, offset + 37, 1, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_Parameter1, tvb, offset + 38, 2, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_Parameter2, tvb, offset + 40, 2, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_Parameter3, tvb, offset + 42, 2, ENC_BIG_ENDIAN);
	    offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);

	    /* If we have a datasegment this contains scsi sense info followed
	     * by iscsi event data. (rfc3720 10.9.4)
	     */
	    if(dsl){
		snsl=tvb_get_ntohs(tvb, offset);
		offset+=2;
		if(snsl){
		    tvbuff_t *data_tvb;
		    int tvb_len, tvb_rlen;

		    tvb_len=tvb_length_remaining(tvb, offset);
		    if(tvb_len>snsl)
			tvb_len=snsl;
		    tvb_rlen=tvb_reported_length_remaining(tvb, offset);
		    if(tvb_rlen>snsl)
			tvb_rlen=snsl;
		    data_tvb=tvb_new_subset(tvb, offset, tvb_len, tvb_rlen);
		    dissect_scsi_snsinfo (data_tvb, pinfo, tree, 0,
					  tvb_len,
					  &cdata->itlq, itl);

		    offset+=snsl;
		}
		if((end_offset-offset)>0){
		    proto_tree_add_item(ti, hf_iscsi_async_event_data, tvb, offset, end_offset-offset, ENC_NA);
		}
	    }
	    offset=end_offset;
    } else if(opcode == ISCSI_OPCODE_REJECT) {
	    proto_item *tf;
	    proto_tree *tt;
	    int next_opcode;
	    const char *next_opcode_str;

	    /* Reject */
	    proto_tree_add_item(ti, hf_iscsi_Reject_Reason, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
	    if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
		proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
	    }
	    proto_tree_add_uint(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, tvb_get_ntoh24(tvb, offset + 5));
	    proto_tree_add_item(ti, hf_iscsi_StatSN, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_ExpCmdSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_MaxCmdSN, tvb, offset + 32, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(ti, hf_iscsi_DataSN, tvb, offset + 36, 4, ENC_BIG_ENDIAN);
	    offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);

	    next_opcode = tvb_get_guint8(tvb, offset) & 0x3f;
	    next_opcode_str = match_strval(next_opcode, iscsi_opcodes);

	    tf = proto_tree_add_text(ti, tvb, offset, -1, "Rejected Header");
	    tt = proto_item_add_subtree(tf, ett_iscsi_RejectHeader);

	    dissect_iscsi_pdu(tvb, pinfo, tt, offset, next_opcode, next_opcode_str, 0, iscsi_session, conversation);
    } else if(opcode == ISCSI_OPCODE_VENDOR_SPECIFIC_I0 ||
		opcode == ISCSI_OPCODE_VENDOR_SPECIFIC_I1 ||
		opcode == ISCSI_OPCODE_VENDOR_SPECIFIC_I2 ||
		opcode == ISCSI_OPCODE_VENDOR_SPECIFIC_T0 ||
		opcode == ISCSI_OPCODE_VENDOR_SPECIFIC_T1 ||
		opcode == ISCSI_OPCODE_VENDOR_SPECIFIC_T2) {
	    /* Vendor specific opcodes */
	    if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
		proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
	    }
	    proto_tree_add_uint(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, tvb_get_ntoh24(tvb, offset + 5));
	    offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);
	    offset = handleDataSegment(ti, tvb, offset, data_segment_len, end_offset, hf_iscsi_vendor_specific_data);
    }



    /* handle request/response matching */
    switch(opcode){
    case ISCSI_OPCODE_SCSI_RESPONSE:
        if (cdata->itlq.first_exchange_frame){
            nstime_t delta_time;
            proto_tree_add_uint(ti, hf_iscsi_request_frame, tvb, 0, 0, cdata->itlq.first_exchange_frame);
            nstime_delta(&delta_time, &pinfo->fd->abs_ts, &cdata->itlq.fc_time);
            proto_tree_add_time(ti, hf_iscsi_time, tvb, 0, 0, &delta_time);
        }
        if (cdata->data_in_frame)
            proto_tree_add_uint(ti, hf_iscsi_data_in_frame, tvb, 0, 0, cdata->data_in_frame);
        if (cdata->data_out_frame)
            proto_tree_add_uint(ti, hf_iscsi_data_out_frame, tvb, 0, 0, cdata->data_out_frame);
        break;
    case ISCSI_OPCODE_SCSI_DATA_IN:
        /* if we have phase collaps then we might have the
           response embedded in the last DataIn segment */
        if(!S_bit){
            if (cdata->itlq.first_exchange_frame)
                proto_tree_add_uint(ti, hf_iscsi_request_frame, tvb, 0, 0, cdata->itlq.first_exchange_frame);
            if (cdata->itlq.last_exchange_frame)
                proto_tree_add_uint(ti, hf_iscsi_response_frame, tvb, 0, 0, cdata->itlq.last_exchange_frame);
        } else {
            if (cdata->itlq.first_exchange_frame){
                 nstime_t delta_time;
                 proto_tree_add_uint(ti, hf_iscsi_request_frame, tvb, 0, 0, cdata->itlq.first_exchange_frame);
		 nstime_delta(&delta_time, &pinfo->fd->abs_ts, &cdata->itlq.fc_time);
                 proto_tree_add_time(ti, hf_iscsi_time, tvb, 0, 0, &delta_time);
            }
        }
        if (cdata->data_out_frame)
            proto_tree_add_uint(ti, hf_iscsi_data_out_frame, tvb, 0, 0, cdata->data_out_frame);
        break;
    case ISCSI_OPCODE_SCSI_DATA_OUT:
        if (cdata->itlq.first_exchange_frame)
            proto_tree_add_uint(ti, hf_iscsi_request_frame, tvb, 0, 0, cdata->itlq.first_exchange_frame);
        if (cdata->data_in_frame)
            proto_tree_add_uint(ti, hf_iscsi_data_in_frame, tvb, 0, 0, cdata->data_in_frame);
        if (cdata->itlq.last_exchange_frame)
            proto_tree_add_uint(ti, hf_iscsi_response_frame, tvb, 0, 0, cdata->itlq.last_exchange_frame);
        break;
    case ISCSI_OPCODE_SCSI_COMMAND:
        if (cdata->data_in_frame)
            proto_tree_add_uint(ti, hf_iscsi_data_in_frame, tvb, 0, 0, cdata->data_in_frame);
        if (cdata->data_out_frame)
            proto_tree_add_uint(ti, hf_iscsi_data_out_frame, tvb, 0, 0, cdata->data_out_frame);
        if (cdata->itlq.last_exchange_frame)
            proto_tree_add_uint(ti, hf_iscsi_response_frame, tvb, 0, 0, cdata->itlq.last_exchange_frame);
        break;
    }



    proto_item_set_len(ti, offset - original_offset);

    if((opcode & ((iscsi_protocol_version == ISCSI_PROTOCOL_DRAFT08)?
		  ~(X_BIT | I_BIT) :
		  ~I_BIT)) == ISCSI_OPCODE_SCSI_COMMAND) {
	tvbuff_t *cdb_tvb, *data_tvb;
	int tvb_len, tvb_rlen;
	guint8 scsi_opcode;

        /* SCSI Command */
	tvb_len=tvb_length_remaining(tvb, cdb_offset);
	tvb_rlen=tvb_reported_length_remaining(tvb, cdb_offset);
	scsi_opcode=tvb_get_guint8(tvb, cdb_offset);
	if(ahs_cdb_length && ahs_cdb_length<1024){
		guint8 *cdb_buf;

		/* We have a variable length CDB where bytes >16 is transported
		 * in the AHS.
		 */
		cdb_buf=g_malloc(16+ahs_cdb_length);
		/* the 16 first bytes of the cdb */
		tvb_memcpy(tvb, cdb_buf, cdb_offset, 16);
		/* the remainder of the cdb from the ahs */
		tvb_memcpy(tvb, cdb_buf+16, ahs_cdb_offset, ahs_cdb_length);

		cdb_tvb = tvb_new_child_real_data(tvb, cdb_buf,
					  ahs_cdb_length+16,
					  ahs_cdb_length+16);
                tvb_set_free_cb(cdb_tvb, g_free);

		add_new_data_source(pinfo, cdb_tvb, "CDB+AHS");
	} else {
		if(tvb_len>16){
		    tvb_len=16;
		}
		if(tvb_rlen>16){
		    tvb_rlen=16;
		}
		cdb_tvb=tvb_new_subset(tvb, cdb_offset, tvb_len, tvb_rlen);
	}
        dissect_scsi_cdb(cdb_tvb, pinfo, tree, SCSI_DEV_UNKNOWN, &cdata->itlq, itl);
	/* we dont want the immediata below to overwrite our CDB info */
	if (check_col(pinfo->cinfo, COL_INFO)) {
	    col_set_fence(pinfo->cinfo, COL_INFO);
	}
	/* where there any ImmediateData ? */
	if(immediate_data_length){
            /* Immediate Data TVB */
	    tvb_len=tvb_length_remaining(tvb, immediate_data_offset);
	    if(tvb_len>(int)immediate_data_length)
	        tvb_len=immediate_data_length;
	    tvb_rlen=tvb_reported_length_remaining(tvb, immediate_data_offset);
    	    if(tvb_rlen>(int)immediate_data_length)
	        tvb_rlen=immediate_data_length;
	    data_tvb=tvb_new_subset(tvb, immediate_data_offset, tvb_len, tvb_rlen);
            dissect_scsi_payload (data_tvb, pinfo, tree,
		  	          TRUE,
			          &cdata->itlq, itl,
				  0);
	}
    }
    else if (opcode == ISCSI_OPCODE_SCSI_RESPONSE) {
        if (scsi_status == 0x2) {
            /* A SCSI response with Check Condition contains sense data */
            /* offset is setup correctly by the iscsi code for response above */
	    if((end_offset - offset) >= 2) {
		int senseLen = tvb_get_ntohs(tvb, offset);
		if(ti != NULL)
		    proto_tree_add_item(ti, hf_iscsi_SenseLength, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		if(senseLen > 0){
		    tvbuff_t *data_tvb;
		    int tvb_len, tvb_rlen;

		    tvb_len=tvb_length_remaining(tvb, offset);
		    if(tvb_len>senseLen)
			tvb_len=senseLen;
		    tvb_rlen=tvb_reported_length_remaining(tvb, offset);
		    if(tvb_rlen>senseLen)
			tvb_rlen=senseLen;
		    data_tvb=tvb_new_subset(tvb, offset, tvb_len, tvb_rlen);
		    dissect_scsi_snsinfo (data_tvb, pinfo, tree, 0,
					  tvb_len,
					  &cdata->itlq, itl);
		}
	    }
        }
        else {
            dissect_scsi_rsp(tvb, pinfo, tree, &cdata->itlq, itl, scsi_status);
        }
    }
    else if ((opcode == ISCSI_OPCODE_SCSI_DATA_IN) ||
             (opcode == ISCSI_OPCODE_SCSI_DATA_OUT)) {
	tvbuff_t *data_tvb;
	int tvb_len, tvb_rlen;

        /* offset is setup correctly by the iscsi code for response above */
	tvb_len=tvb_length_remaining(tvb, offset);
	if(tvb_len>(int)data_segment_len)
	    tvb_len=data_segment_len;
	tvb_rlen=tvb_reported_length_remaining(tvb, offset);
	if(tvb_rlen>(int)data_segment_len)
	    tvb_rlen=data_segment_len;
	data_tvb=tvb_new_subset(tvb, offset, tvb_len, tvb_rlen);
        dissect_scsi_payload (data_tvb, pinfo, tree,
			      (opcode==ISCSI_OPCODE_SCSI_DATA_OUT),
			      &cdata->itlq, itl,
			      data_offset);
    }

    if(S_bit){
        dissect_scsi_rsp(tvb, pinfo, tree, &cdata->itlq, itl, scsi_status);
    }
}

static gboolean
dissect_iscsi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean check_port) {
    /* Set up structures needed to add the protocol subtree and manage it */
    guint iSCSIPdusDissected = 0;
    guint offset = 0;
    guint32 available_bytes = tvb_length(tvb);
    int digestsActive = 1;
    conversation_t *conversation = NULL;
    iscsi_session_t *iscsi_session=NULL;
    guint8 opcode, tmpbyte;

    if (available_bytes < 48) {
	/* heuristic already rejected the packet if size < 48,
	  assume it's an iscsi packet with a segmented header */
        pinfo->desegment_offset = offset;
        pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
        return TRUE;
    }

    opcode = tvb_get_guint8(tvb, offset + 0);
    opcode &= OPCODE_MASK;

    /* heuristics to verify that the packet looks sane.   the heuristics
     * are based on the RFC version of iscsi.
     * (we should retire support for older iscsi versions in wireshark)
     *      -- ronnie s
     */
    /* opcode must be any of the ones from the standard
     * also check the header that it looks "sane"
     * all reserved or undefined bits in iscsi must be set to zero.
     */
    switch(opcode){
    case ISCSI_OPCODE_NOP_IN:
	/* top two bits of byte 0 must be 0 */
	if(tvb_get_guint8(tvb, offset+0)&0xc0){
	    return FALSE;
	}
	/* byte 1 must be 0x80 */
	if(tvb_get_guint8(tvb, offset+1)!=0x80){
	    return FALSE;
	}
	/* bytes 2 and 3 must be 0 */
	if(tvb_get_guint8(tvb, offset+2)||tvb_get_guint8(tvb, offset+3)){
	    return FALSE;
	}
	break;
    case ISCSI_OPCODE_NOP_OUT:
	/* top bit of byte 0 must be 0 */
	if(tvb_get_guint8(tvb, offset+0)&0x80){
	    return FALSE;
	}
	/* byte 1 must be 0x80 */
	if(tvb_get_guint8(tvb, offset+1)!=0x80){
	    return FALSE;
	}
	/* bytes 2 and 3 must be 0 */
	if(tvb_get_guint8(tvb, offset+2)||tvb_get_guint8(tvb, offset+3)){
	    return FALSE;
	}
	/* assume ITT and TTT must always be non NULL (ok they can be NULL
	 * from time to time but it usually means we are in the middle
	 * of a zeroed datablock).
	 */
	if(!tvb_get_letohl(tvb,offset+16) || !tvb_get_letohl(tvb,offset+20)){
	    return FALSE;
	}
	/* all reserved bytes between 32 - 47 must be null */
	if(tvb_get_letohl(tvb,offset+32)
	|| tvb_get_letohl(tvb,offset+36)
	|| tvb_get_letohl(tvb,offset+40)
	|| tvb_get_letohl(tvb,offset+44)){
	    return FALSE;
	}
	break;
    case ISCSI_OPCODE_LOGIN_COMMAND:
	/* top two bits in byte 0 must be 0x40 */
	if((tvb_get_guint8(tvb, offset+0)&0xc0)!=0x40){

	    return FALSE;
	}
	/* both the T and C bits can not be set
	 * and the two reserved bits in byte 1 must be 0
	 */
	tmpbyte=tvb_get_guint8(tvb, offset+1);
	switch(tmpbyte&0xf0){
	case 0x80:
	case 0x40:
	case 0x00:
	    break;
	default:
	    return FALSE;
	}
	/* CSG and NSG must not be 2 */
	if(((tmpbyte & 0x03) == 0x02)
	|| ((tmpbyte & 0x0c) == 0x08)) {
	    return FALSE;
	}
	/* if T bit is set NSG must not be 0 */
	if(tmpbyte&0x80){
	    if(!(tmpbyte&0x03)){
		return FALSE;
	    }
	}
	/* should we test that datasegmentlen is non zero? */
	break;
    case ISCSI_OPCODE_LOGIN_RESPONSE:
	/* top two bits in byte 0 must be 0 */
	if(tvb_get_guint8(tvb, offset+0)&0xc0){

	    return FALSE;
	}
	/* both the T and C bits can not be set
	 * and the two reserved bits in byte 1 must be 0
	 */
	tmpbyte=tvb_get_guint8(tvb, offset+1);
	switch(tmpbyte&0xf0){
	case 0x80:
	case 0x40:
	case 0x00:
	    break;
	default:
	    return FALSE;
	}
	/* CSG and NSG must not be 2 */
	if(((tmpbyte & 0x03) == 0x02)
	|| ((tmpbyte & 0x0c) == 0x08)) {
	    return FALSE;
	}
	/* if T bit is set NSG must not be 0 */
	if(tmpbyte&0x80){
	    if(!(tmpbyte&0x03)){
		return FALSE;
	    }
	}
	/* the 32bit words at offsets 20, 40, 44 must be zero */
	if(tvb_get_letohl(tvb,offset+20)
	|| tvb_get_letohl(tvb,offset+40)
	|| tvb_get_letohl(tvb,offset+44)){
	    return FALSE;
	}
	/* the two bytes at offset 38 must be zero */
	if(tvb_get_letohs(tvb,offset+38)){
	    return FALSE;
	}
	/* should we test that datasegmentlen is non zero unless we just
	 * entered full featured phase?
	 */
	break;
    case ISCSI_OPCODE_TASK_MANAGEMENT_FUNCTION:
	/* top bit in byte 0 must be 0 */
	if(tvb_get_guint8(tvb, offset+0)&0x80){
	    return FALSE;
	}
	/* top bit in byte 1 must be set */
	tmpbyte=tvb_get_guint8(tvb, offset+1);
	if(!(tmpbyte&0x80)){
	    return FALSE;
	}
	/* Function must be known */
	if(!match_strval(tmpbyte&0x7f, iscsi_task_management_functions)){
	    return FALSE;
	}
	/* bytes 2,3 must be null */
	if(tvb_get_letohs(tvb,offset+2)){
	    return FALSE;
	}
	/* ahs and dsl must be null */
	if(tvb_get_letohl(tvb,offset+4)){
	    return FALSE;
	}
	break;
    case ISCSI_OPCODE_TASK_MANAGEMENT_FUNCTION_RESPONSE:
	/* top two bits in byte 0 must be 0 */
	if(tvb_get_guint8(tvb, offset+0)&0xc0){
	    return FALSE;
	}
	/* byte 1 must be 0x80 */
	if(tvb_get_guint8(tvb, offset+1)!=0x80){
	    return FALSE;
	}
	/* response must be 0-6 or 255 */
	tmpbyte=tvb_get_guint8(tvb,offset+2);
	if(tmpbyte>6 && tmpbyte<255){
	    return FALSE;
	}
	/* byte 3 must be 0 */
	if(tvb_get_guint8(tvb,offset+3)){
	    return FALSE;
	}
	/* ahs and dsl  as well as the 32bit words at offsets 8, 12, 20, 36
	 * 40, 44 must all be 0
	 */
	if(tvb_get_letohl(tvb,offset+4)
	|| tvb_get_letohl(tvb,offset+8)
	|| tvb_get_letohl(tvb,offset+12)
	|| tvb_get_letohl(tvb,offset+20)
	|| tvb_get_letohl(tvb,offset+36)
	|| tvb_get_letohl(tvb,offset+40)
	|| tvb_get_letohl(tvb,offset+44)){
	    return FALSE;
	}
	break;
    case ISCSI_OPCODE_LOGOUT_COMMAND:
	/* top bit in byte 0 must be 0 */
	if(tvb_get_guint8(tvb, offset+0)&0x80){
	    return FALSE;
	}
	/* top bit in byte 1 must be set */
	tmpbyte=tvb_get_guint8(tvb, offset+1);
	if(!(tmpbyte&0x80)){
	    return FALSE;
	}
	/* Reason code must be known */
	if(!match_strval(tmpbyte&0x7f, iscsi_logout_reasons)){
	    return FALSE;
	}
	/* bytes 2,3 must be null */
	if(tvb_get_letohs(tvb,offset+2)){
	    return FALSE;
	}
	/* ahs and dsl  as well as the 32bit words at offsets 8, 12, 32, 36
	 * 40, 44 must all be 0
	 */
	if(tvb_get_letohl(tvb,offset+4)
	|| tvb_get_letohl(tvb,offset+8)
	|| tvb_get_letohl(tvb,offset+12)
	|| tvb_get_letohl(tvb,offset+32)
	|| tvb_get_letohl(tvb,offset+36)
	|| tvb_get_letohl(tvb,offset+40)
	|| tvb_get_letohl(tvb,offset+44)){
	    return FALSE;
	}
	break;
    case ISCSI_OPCODE_SNACK_REQUEST:
	/* top two bits in byte 0 must be 0 */
	if(tvb_get_guint8(tvb, offset+0)&0xc0){
	    return FALSE;
	}
	/* top 4 bits in byte 1 must be 0x80 */
	tmpbyte=tvb_get_guint8(tvb, offset+1);
	if((tmpbyte&0xf0)!=0x80){
	    return FALSE;
	}
	/* type must be known */
	if(!match_strval(tmpbyte&0x0f, iscsi_snack_types)){
	    return FALSE;
	}
	/* for status/snack and datack itt must be 0xffffffff
	 * for rdata/snack ttt must not be 0 or 0xffffffff
	 */
	switch(tmpbyte&0x0f){
	case 1:
	case 2:
	    if(tvb_get_letohl(tvb,offset+16)!=0xffffffff){
		return FALSE;
	    }
	    break;
	case 3:
	    if(tvb_get_letohl(tvb,offset+20)==0xffffffff){
		return FALSE;
	    }
	    if(tvb_get_letohl(tvb,offset+20)==0){
		return FALSE;
	    }
	    break;
	}
	/* bytes 2,3 must be null */
	if(tvb_get_letohs(tvb,offset+2)){
	    return FALSE;
	}
	/* the 32bit words at offsets 24, 32, 36
	 * must all be 0
	 */
	if(tvb_get_letohl(tvb,offset+24)
	|| tvb_get_letohl(tvb,offset+32)
	|| tvb_get_letohl(tvb,offset+36)){
	    return FALSE;
	}

	break;
    case ISCSI_OPCODE_R2T:
	/* top two bits in byte 0 must be 0 */
	if(tvb_get_guint8(tvb, offset+0)&0xc0){
	    return FALSE;
	}
	/* byte 1 must be 0x80 */
	if(tvb_get_guint8(tvb, offset+1)!=0x80){
	    return FALSE;
	}
	/* bytes 2,3 must be null */
	if(tvb_get_letohs(tvb,offset+2)){
	    return FALSE;
	}
	/* ahs and dsl must be null */
	if(tvb_get_letohl(tvb,offset+4)){
	    return FALSE;
	}
	/* desired data transfer length must not be null */
	if(!tvb_get_letohl(tvb,offset+44)){
	    return FALSE;
	}
	break;
    case ISCSI_OPCODE_REJECT:
	/* top two bits in byte 0 must be 0 */
	if(tvb_get_guint8(tvb, offset+0)&0xc0){
	    return FALSE;
	}
	/* byte 1 must be 0x80 */
	if(tvb_get_guint8(tvb, offset+1)!=0x80){
	    return FALSE;
	}
	/* reason must be known */
	if(!match_strval(tvb_get_guint8(tvb,offset+2), iscsi_reject_reasons)){
	    return FALSE;
	}
	/* byte 3 must be 0 */
	if(tvb_get_guint8(tvb, offset+3)){
	    return FALSE;
	}
	/* the 32bit words at offsets 8, 12, 20, 40, 44
	 * must all be 0
	 */
	if(tvb_get_letohl(tvb,offset+8)
	|| tvb_get_letohl(tvb,offset+12)
	|| tvb_get_letohl(tvb,offset+20)
	|| tvb_get_letohl(tvb,offset+40)
	|| tvb_get_letohl(tvb,offset+44)){
	    return FALSE;
	}
	/* the 32bit word at 16 must be 0xffffffff */
	if(tvb_get_letohl(tvb,offset+16)!=0xffffffff){
	    return FALSE;
	}
	break;
    case ISCSI_OPCODE_TEXT_COMMAND:
	/* top bit in byte 0 must be 0 */
	if(tvb_get_guint8(tvb, offset+0)&0x80){
	    return FALSE;
	}
	/* one of the F and C bits must be set but not both
	 * low 6 bits in byte 1 must be 0
	 */
	switch(tvb_get_guint8(tvb,offset+1)){
	case 0x80:
	case 0x40:
	    break;
	default:
	    return FALSE;
	}
	/* bytes 2,3 must be null */
	if(tvb_get_letohs(tvb,offset+2)){
	    return FALSE;
	}
	/* the 32bit words at offsets 32, 36, 40, 44
	 * must all be 0
	 */
	if(tvb_get_letohl(tvb,offset+32)
	|| tvb_get_letohl(tvb,offset+36)
	|| tvb_get_letohl(tvb,offset+40)
	|| tvb_get_letohl(tvb,offset+44)){
	    return FALSE;
	}
	break;
    case ISCSI_OPCODE_TEXT_RESPONSE:
	/* top two bits in byte 0 must be 0 */
	if(tvb_get_guint8(tvb, offset+0)&0xc0){
	    return FALSE;
	}
	/* one of the F and C bits must be set but not both
	 * low 6 bits in byte 1 must be 0
	 */
	switch(tvb_get_guint8(tvb,offset+1)){
	case 0x80:
	case 0x40:
	    break;
	default:
	    return FALSE;
	}
	/* bytes 2,3 must be null */
	if(tvb_get_letohs(tvb,offset+2)){
	    return FALSE;
	}
	/* the 32bit words at offsets 36, 40, 44
	 * must all be 0
	 */
	if(tvb_get_letohl(tvb,offset+36)
	|| tvb_get_letohl(tvb,offset+40)
	|| tvb_get_letohl(tvb,offset+44)){
	    return FALSE;
	}
	break;
    case ISCSI_OPCODE_SCSI_COMMAND:
	/* top bit in byte 0 must be 0 */
	if(tvb_get_guint8(tvb, offset+0)&0x80){
	    return FALSE;
	}
	/* reserved bits in byte 1 must be 0 */
	if(tvb_get_guint8(tvb, offset+1)&0x18){
	    return FALSE;
	}
	/* bytes 2,3 must be null */
	if(tvb_get_letohs(tvb,offset+2)){
	    return FALSE;
	}
	/* last 6 bytes of LUN are always 0 */
	if(tvb_get_ntohs(tvb, offset+10) || tvb_get_ntohl(tvb, offset+12)){
	    return FALSE;
	}
	/* expected data transfer length is never >16MByte ? */
	if(tvb_get_guint8(tvb,offset+20)){
	    return FALSE;
	}
	break;
    case ISCSI_OPCODE_SCSI_RESPONSE:
	/* top two bits in byte 0 must be 0 */
	if(tvb_get_guint8(tvb, offset+0)&0xc0){
	    return FALSE;
	}
	/* top bit in byte 1 must be 1 */
	tmpbyte=tvb_get_guint8(tvb,offset+1);
	if(!(tmpbyte&0x80)){
	    return FALSE;
	}
	/* the reserved bits in byte 1 must be 0 */
	if(tmpbyte&0x61){
	    return FALSE;
	}
	/* status must be known */
	if(!match_strval(tvb_get_guint8(tvb,offset+3), scsi_status_val)){
	    return FALSE;
	}
	/* the 32bit words at offsets 8, 12
	 * must all be 0
	 */
	if(tvb_get_letohl(tvb,offset+8)
	|| tvb_get_letohl(tvb,offset+12)){
	    return FALSE;
	}
	break;
    case ISCSI_OPCODE_ASYNC_MESSAGE:
	/* top two bits in byte 0 must be 0 */
	if(tvb_get_guint8(tvb, offset+0)&0xc0){
	    return FALSE;
	}
	/* byte 1 must be 0x80 */
	if(tvb_get_guint8(tvb, offset+1)!=0x80){
	    return FALSE;
	}
	/* bytes 2,3 must be null */
	if(tvb_get_letohs(tvb,offset+2)){
	    return FALSE;
	}
	/* the 32bit words at offsets 20, 44
	 * must all be 0
	 */
	if(tvb_get_letohl(tvb,offset+20)
	|| tvb_get_letohl(tvb,offset+44)){
	    return FALSE;
	}
	/* the 32bit word at 16 must be 0xffffffff */
	if(tvb_get_letohl(tvb,offset+16)!=0xffffffff){
	    return FALSE;
	}
	break;
    case ISCSI_OPCODE_LOGOUT_RESPONSE:
	/* top two bits in byte 0 must be 0 */
	if(tvb_get_guint8(tvb, offset+0)&0xc0){
	    return FALSE;
	}
	/* byte 1 must be 0x80 */
	if(tvb_get_guint8(tvb, offset+1)!=0x80){
	    return FALSE;
	}
	/* response must be known */
	if(!match_strval(tvb_get_guint8(tvb,offset+2), iscsi_logout_response)){
	    return FALSE;
	}
	/* byte 3 must be 0 */
	if(tvb_get_guint8(tvb,offset+3)){
	    return FALSE;
	}
	/* ahs and dsl  as well as the 32bit words at offsets 8, 12, 20, 36
	 * 44 must all be 0
	 */
	if(tvb_get_letohl(tvb,offset+4)
	|| tvb_get_letohl(tvb,offset+8)
	|| tvb_get_letohl(tvb,offset+12)
	|| tvb_get_letohl(tvb,offset+20)
	|| tvb_get_letohl(tvb,offset+36)
	|| tvb_get_letohl(tvb,offset+44)){
	    return FALSE;
	}
	break;
    case ISCSI_OPCODE_SCSI_DATA_OUT:
	/* top two bits in byte 0 must be 0 */
	if(tvb_get_guint8(tvb, offset+0)&0xc0){
	    return FALSE;
	}
	/* low 7 bits in byte 1 must be 0 */
	if(tvb_get_guint8(tvb,offset+1)&0x7f){
	    return FALSE;
	}
	/* bytes 2,3 must be null */
	if(tvb_get_letohs(tvb,offset+2)){
	    return FALSE;
	}
	/* the 32bit words at offsets 24, 32, 44
	 * must all be 0
	 */
	if(tvb_get_letohl(tvb,offset+24)
	|| tvb_get_letohl(tvb,offset+32)
	|| tvb_get_letohl(tvb,offset+44)){
	    return FALSE;
	}
	break;
    case ISCSI_OPCODE_SCSI_DATA_IN:
	/* top two bits in byte 0 must be 0 */
	if(tvb_get_guint8(tvb, offset+0)&0xc0){
	    return FALSE;
	}
	/* reserved bits in byte 1 must be 0 */
	if(tvb_get_guint8(tvb,offset+1)&0x38){
	    return FALSE;
	}
	/* byte 2 must be reserved */
	if(tvb_get_guint8(tvb,offset+2)){
	    return FALSE;
	}
	break;
    case ISCSI_OPCODE_VENDOR_SPECIFIC_I0:
    case ISCSI_OPCODE_VENDOR_SPECIFIC_I1:
    case ISCSI_OPCODE_VENDOR_SPECIFIC_I2:
    case ISCSI_OPCODE_VENDOR_SPECIFIC_T0:
    case ISCSI_OPCODE_VENDOR_SPECIFIC_T1:
    case ISCSI_OPCODE_VENDOR_SPECIFIC_T2:
	break;
    default:
	return FALSE;
    }


    /* process multiple iSCSI PDUs per packet */
    while(available_bytes >= 48 || (iscsi_desegment && available_bytes >= 8)) {
	const char *opcode_str = NULL;
	guint32 data_segment_len;
	guint32 pduLen = 48;
	guint8 secondPduByte = tvb_get_guint8(tvb, offset + 1);
	int badPdu = FALSE;
	guint8 ahsLen=0;

	/* mask out any extra bits in the opcode byte */
	opcode = tvb_get_guint8(tvb, offset + 0);
	opcode &= OPCODE_MASK;

	opcode_str = match_strval(opcode, iscsi_opcodes);
	if(opcode == ISCSI_OPCODE_TASK_MANAGEMENT_FUNCTION ||
	   opcode == ISCSI_OPCODE_TASK_MANAGEMENT_FUNCTION_RESPONSE ||
	   opcode == ISCSI_OPCODE_R2T ||
	   opcode == ISCSI_OPCODE_LOGOUT_COMMAND ||
	   opcode == ISCSI_OPCODE_LOGOUT_RESPONSE ||
	   opcode == ISCSI_OPCODE_SNACK_REQUEST)
	    data_segment_len = 0;
	else
	    data_segment_len = tvb_get_ntohl(tvb, offset + 4) & 0x00ffffff;

	if(opcode_str == NULL) {
	    badPdu = TRUE;
	}


	if(!badPdu && check_port) {
	    badPdu = TRUE;
	    if ((opcode & TARGET_OPCODE_BIT) && value_is_in_range(global_iscsi_port_range, pinfo->srcport)) {
	        badPdu = FALSE;
	    }
	    if (!(opcode & TARGET_OPCODE_BIT) && value_is_in_range(global_iscsi_port_range, pinfo->destport)) {
	        badPdu = FALSE;
	    }
	    if ((opcode & TARGET_OPCODE_BIT) && pinfo->srcport == iscsi_system_port) {
	        badPdu = FALSE;
	    }
	    if (!(opcode & TARGET_OPCODE_BIT) && pinfo->destport == iscsi_system_port) {
	        badPdu = FALSE;
	    }
	}

	if(!badPdu && enable_bogosity_filter) {
	    /* try and distinguish between data and real headers */
	    if(data_segment_len > bogus_pdu_data_length_threshold) {
		badPdu = TRUE;
	    }
	    else if(demand_good_f_bit &&
		    !(secondPduByte & 0x80) &&
		    (opcode == ISCSI_OPCODE_NOP_OUT ||
		     opcode == ISCSI_OPCODE_NOP_IN ||
		     opcode == ISCSI_OPCODE_LOGOUT_COMMAND ||
		     opcode == ISCSI_OPCODE_LOGOUT_RESPONSE ||
		     opcode == ISCSI_OPCODE_SCSI_RESPONSE ||
		     opcode == ISCSI_OPCODE_TASK_MANAGEMENT_FUNCTION_RESPONSE ||
		     opcode == ISCSI_OPCODE_R2T ||
		     opcode == ISCSI_OPCODE_ASYNC_MESSAGE ||
		     opcode == ISCSI_OPCODE_SNACK_REQUEST ||
		     opcode == ISCSI_OPCODE_REJECT)) {
		badPdu = TRUE;
	    } else if(opcode==ISCSI_OPCODE_NOP_OUT) {
		/* TransferTag for NOP-Out should either be -1 or
		   the tag value we want for a response.
		   Assume 0 means we are just inside a big all zero
		   datablock.
		*/
		if(tvb_get_ntohl(tvb, offset+20)==0){
		    badPdu = TRUE;
		}
	    }
	}

	if(badPdu) {
	    return iSCSIPdusDissected > 0;
	}

	if(opcode == ISCSI_OPCODE_LOGIN_COMMAND ||
	    opcode == ISCSI_OPCODE_LOGIN_RESPONSE) {
	    if(iscsi_protocol_version == ISCSI_PROTOCOL_DRAFT08) {
		if((secondPduByte & CSG_MASK) < ISCSI_CSG_OPERATIONAL_NEGOTIATION) {
		    /* digests are not yet turned on */
		    digestsActive = 0;
		}
	    } else {
		digestsActive = 0;
	    }
	}

	if(opcode == ISCSI_OPCODE_SCSI_COMMAND) {
	    /* ahsLen */
	    ahsLen = tvb_get_guint8(tvb, offset + 4);
	    pduLen += ahsLen * 4;
	}

	pduLen += data_segment_len;
	if((pduLen & 3) != 0)
	    pduLen += 4 - (pduLen & 3);


	if(digestsActive && data_segment_len > 0 && enableDataDigests) {
	    if(dataDigestIsCRC32)
		pduLen += 4;
	    else
		pduLen += dataDigestSize;
	}

	/* make sure we have a conversation for this session */
        conversation = find_or_create_conversation(pinfo);

        iscsi_session=conversation_get_proto_data(conversation, proto_iscsi);
        if(!iscsi_session){
            iscsi_session=se_alloc(sizeof(iscsi_session_t));
            iscsi_session->header_digest=ISCSI_HEADER_DIGEST_AUTO;
            iscsi_session->itlq=se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "iSCSI ITLQ");
            iscsi_session->itl=se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "iSCSI ITL");
            conversation_add_proto_data(conversation, proto_iscsi, iscsi_session);

            /* DataOut PDUs are often mistaken by DCERPC heuristics to be
             * that protocol. Now that we know this is iscsi, set a
             * dissector for this conversation to block other heuristic
             * dissectors.
             */
            conversation_set_dissector(conversation, iscsi_handle);
        }
        /* try to autodetect if header digest is used or not */
	if(digestsActive && (available_bytes>=(guint32) (48+4+ahsLen*4)) && (iscsi_session->header_digest==ISCSI_HEADER_DIGEST_AUTO) ){
            guint32 crc;
		/* we have enough data to test if HeaderDigest is enabled */
            crc= ~crc32c_calculate(tvb_get_ptr(tvb, offset, 48+ahsLen*4), 48+ahsLen*4, CRC32C_PRELOAD);
            if(crc==tvb_get_ntohl(tvb,48+ahsLen*4)){
                iscsi_session->header_digest=ISCSI_HEADER_DIGEST_CRC32;
            } else {
                iscsi_session->header_digest=ISCSI_HEADER_DIGEST_NONE;
            }
	}


	/* Add header digest length to pdulen */
	if(digestsActive){
		switch(iscsi_session->header_digest){
		case ISCSI_HEADER_DIGEST_CRC32:
			pduLen += 4;
			break;
		case ISCSI_HEADER_DIGEST_NONE:
			break;
		case ISCSI_HEADER_DIGEST_AUTO:
			/* oops we didnt know what digest is used yet */
			/* here we should use some default */
			break;
		default:
			DISSECTOR_ASSERT_NOT_REACHED();
		}
	}

	/*
	 * Desegmentation check.
	 */
	if(iscsi_desegment && pinfo->can_desegment) {
	    if(pduLen > available_bytes) {
		/*
		 * This frame doesn't have all of the data for
		 * this message, but we can do reassembly on it.
		 *
		 * Tell the TCP dissector where the data for this
		 * message starts in the data it handed us, and
		 * how many more bytes we need, and return.
		 */
		pinfo->desegment_offset = offset;
		pinfo->desegment_len = pduLen - available_bytes;
		return TRUE;
	    }
	}

	/* This is to help TCP keep track of PDU boundaries
	   and allows it to find PDUs that are not aligned to
	   the start of a TCP segments.
	   Since it also allows TCP to know what is in the middle
	   of a large PDU, it reduces the probability of a segment
	   in the middle of a large PDU transfer being misdissected as
	   a PDU.
	*/
	if(!pinfo->fd->flags.visited){
	    if(pduLen>(guint32)tvb_reported_length_remaining(tvb, offset)){
		pinfo->want_pdu_tracking=2;
		pinfo->bytes_until_next_pdu=pduLen-tvb_reported_length_remaining(tvb, offset);
	    }
	}

	if(check_col(pinfo->cinfo, COL_INFO)) {
	    if(iSCSIPdusDissected == 0)
		col_set_str(pinfo->cinfo, COL_INFO, "");
	    else
		col_append_str(pinfo->cinfo, COL_INFO, ", ");
	}

	dissect_iscsi_pdu(tvb, pinfo, tree, offset, opcode, opcode_str, data_segment_len, iscsi_session, conversation);
	if(pduLen > available_bytes)
	    pduLen = available_bytes;
	offset += pduLen;
	available_bytes -= pduLen;
	++iSCSIPdusDissected;
    }

    return iSCSIPdusDissected > 0;
}

/* This is called for those sessions where we have explicitely said
   this to be iSCSI using "Decode As..."
   In this case we will not check the port number for sanity and just
   do as the user said.
   We still check that the PDU header looks sane though.
*/
static int
dissect_iscsi_handle(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    return dissect_iscsi(tvb, pinfo, tree, FALSE);
}

/* This is called through the heuristic handler.
   In this case we also want to check that the port matches the preference
   setting for iSCSI in order to reduce the number of
   false positives.
*/
static gboolean
dissect_iscsi_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    guint32 available_bytes = tvb_length(tvb);

    /* quick check to see if the packet is long enough to contain the
     * minimum amount of information we need */
    if (available_bytes < 48 ){
	/* no, so give up */
	return FALSE;
    }

    return dissect_iscsi(tvb, pinfo, tree, TRUE);
}


/* Register the protocol with Wireshark */

/*
 * this format is require because a script is used to build the C
 * function that calls all the protocol registration.
*/

void
proto_register_iscsi(void)
{
    module_t *iscsi_module;

    /* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
	{ &hf_iscsi_request_frame,
	  { "Request in", "iscsi.request_frame",
	    FT_FRAMENUM, BASE_NONE, NULL, 0,
	    "The request to this transaction is in this frame", HFILL }},

	{ &hf_iscsi_time,
	  { "Time from request", "iscsi.time",
	    FT_RELATIVE_TIME, BASE_NONE, NULL, 0,
	    "Time between the Command and the Response", HFILL }},

	{ &hf_iscsi_data_in_frame,
	  { "Data In in", "iscsi.data_in_frame",
	    FT_FRAMENUM, BASE_NONE, NULL, 0,
	    "The Data In for this transaction is in this frame", HFILL }},

	{ &hf_iscsi_data_out_frame,
	  { "Data Out in", "iscsi.data_out_frame",
	    FT_FRAMENUM, BASE_NONE, NULL, 0,
	    "The Data Out for this transaction is in this frame", HFILL }},

	{ &hf_iscsi_response_frame,
	  { "Response in", "iscsi.response_frame",
	    FT_FRAMENUM, BASE_NONE, NULL, 0,
	    "The response to this transaction is in this frame", HFILL }},
	{ &hf_iscsi_AHS_length,
	  { "AHS Length", "iscsi.ahs.length",
	    FT_UINT16, BASE_DEC, NULL, 0,
	    "Length of Additional header segment", HFILL }
	},
	{ &hf_iscsi_AHS_read_data_length,
	  { "Bidirectional Read Data Length", "iscsi.ahs.bidir.length",
	    FT_UINT32, BASE_DEC, NULL, 0,
	    NULL, HFILL }
	},
	{ &hf_iscsi_AHS_type,
	  { "AHS Type", "iscsi.ahs.type",
	    FT_UINT8, BASE_DEC, VALS(ahs_type_vals), 0,
	    "Type of Additional header segment", HFILL }
	},
	{ &hf_iscsi_AHS_extended_cdb,
	  { "AHS Extended CDB", "iscsi.ahs.extended_cdb",
	    FT_BYTES, BASE_NONE, NULL, 0,
	    NULL, HFILL }
	},
	{ &hf_iscsi_AHS_blob,
	  { "Unknown AHS blob", "iscsi.ahs.unknown_blob",
	    FT_BYTES, BASE_NONE, NULL, 0,
	    NULL, HFILL }
	},
	{ &hf_iscsi_Padding,
	  { "Padding", "iscsi.padding",
	    FT_BYTES, BASE_NONE, NULL, 0,
	    "Padding to 4 byte boundary", HFILL }
	},
	{ &hf_iscsi_ping_data,
	  { "PingData", "iscsi.pingdata",
	    FT_BYTES, BASE_NONE, NULL, 0,
	    "Ping Data", HFILL }
	},
	{ &hf_iscsi_immediate_data,
	  { "ImmediateData", "iscsi.immediatedata",
	    FT_BYTES, BASE_NONE, NULL, 0,
	    "Immediate Data", HFILL }
	},
	{ &hf_iscsi_async_event_data,
	  { "AsyncEventData", "iscsi.asynceventdata",
	    FT_BYTES, BASE_NONE, NULL, 0,
	    "Async Event Data", HFILL }
	},
	{ &hf_iscsi_vendor_specific_data,
	  { "VendorSpecificData", "iscsi.vendorspecificdata",
	    FT_BYTES, BASE_NONE, NULL, 0,
	    "Vendor Specific Data", HFILL }
	},
	{ &hf_iscsi_HeaderDigest32,
	  { "HeaderDigest", "iscsi.headerdigest32",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Header Digest", HFILL }
	},
	{ &hf_iscsi_DataDigest,
	  { "DataDigest", "iscsi.datadigest",
	    FT_BYTES, BASE_NONE, NULL, 0,
	    "Data Digest", HFILL }
	},
	{ &hf_iscsi_DataDigest32,
	  { "DataDigest", "iscsi.datadigest32",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Data Digest", HFILL }
	},
	{ &hf_iscsi_Opcode,
	  { "Opcode", "iscsi.opcode",
	    FT_UINT8, BASE_HEX, VALS(iscsi_opcodes), 0,
	    NULL, HFILL }
	},
/* #ifdef DRAFT08 */
	{ &hf_iscsi_X,
	  { "X", "iscsi.X",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_X), 0x80,
	    "Command Retry", HFILL }
	},
/* #endif */
	{ &hf_iscsi_I,
	  { "I", "iscsi.I",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_I), 0x40,
	    "Immediate delivery", HFILL }
	},
	{ &hf_iscsi_Flags,
	  { "Flags", "iscsi.flags",
	    FT_UINT8, BASE_HEX, NULL, 0,
	    "Opcode specific flags", HFILL }
	},
	{ &hf_iscsi_SCSICommand_F,
	  { "F", "iscsi.scsicommand.F",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_F), 0x80,
	    "PDU completes command", HFILL }
	},
	{ &hf_iscsi_SCSICommand_R,
	  { "R", "iscsi.scsicommand.R",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_R), 0x40,
	    "Command reads from SCSI target", HFILL }
	},
	{ &hf_iscsi_SCSICommand_W,
	  { "W", "iscsi.scsicommand.W",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_W), 0x20,
	    "Command writes to SCSI target", HFILL }
	},
	{ &hf_iscsi_SCSICommand_Attr,
	  { "Attr", "iscsi.scsicommand.attr",
	    FT_UINT8, BASE_HEX, VALS(iscsi_scsicommand_taskattrs), 0x07,
	    "SCSI task attributes", HFILL }
	},
	{ &hf_iscsi_SCSICommand_CRN,
	  { "CRN", "iscsi.scsicommand.crn",
	    FT_UINT8, BASE_HEX, NULL, 0,
	    "SCSI command reference number", HFILL }
	},
	{ &hf_iscsi_DataSegmentLength,
	  { "DataSegmentLength", "iscsi.datasegmentlength",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Data segment length (bytes)", HFILL }
	},
	{ &hf_iscsi_TotalAHSLength,
	  { "TotalAHSLength", "iscsi.totalahslength",
	    FT_UINT8, BASE_HEX, NULL, 0,
	    "Total additional header segment length (4 byte words)", HFILL }
	},
	{ &hf_iscsi_LUN,
	  { "LUN", "iscsi.lun",
	    FT_BYTES, BASE_NONE, NULL, 0,
	    "Logical Unit Number", HFILL }
	},
	{ &hf_iscsi_InitiatorTaskTag,
	  { "InitiatorTaskTag", "iscsi.initiatortasktag",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Initiator's task tag", HFILL }
	},
	{ &hf_iscsi_ExpectedDataTransferLength,
	  { "ExpectedDataTransferLength", "iscsi.scsicommand.expecteddatatransferlength",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Expected length of data transfer", HFILL }
	},
	{ &hf_iscsi_CmdSN,
	  { "CmdSN", "iscsi.cmdsn",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Sequence number for this command", HFILL }
	},
	{ &hf_iscsi_ExpStatSN,
	  { "ExpStatSN", "iscsi.expstatsn",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Next expected status sequence number", HFILL }
	},
	{ &hf_iscsi_SCSIResponse_ResidualCount,
	  { "ResidualCount", "iscsi.scsiresponse.residualcount",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Residual count", HFILL }
	},
	{ &hf_iscsi_StatSN,
	  { "StatSN", "iscsi.statsn",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Status sequence number", HFILL }
	},
	{ &hf_iscsi_ExpCmdSN,
	  { "ExpCmdSN", "iscsi.expcmdsn",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Next expected command sequence number", HFILL }
	},
	{ &hf_iscsi_MaxCmdSN,
	  { "MaxCmdSN", "iscsi.maxcmdsn",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Maximum acceptable command sequence number", HFILL }
	},
	{ &hf_iscsi_SCSIResponse_o,
	  { "o", "iscsi.scsiresponse.o",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_o), 0x10,
	    "Bi-directional read residual overflow", HFILL }
	},
	{ &hf_iscsi_SCSIResponse_u,
	  { "u", "iscsi.scsiresponse.u",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_u), 0x08,
	    "Bi-directional read residual underflow", HFILL }
	},
	{ &hf_iscsi_SCSIResponse_O,
	  { "O", "iscsi.scsiresponse.O",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_O), 0x04,
	    "Residual overflow", HFILL }
	},
	{ &hf_iscsi_SCSIResponse_U,
	  { "U", "iscsi.scsiresponse.U",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_U), 0x02,
	    "Residual underflow", HFILL }
	},
	{ &hf_iscsi_SCSIResponse_Status,
	  { "Status", "iscsi.scsiresponse.status",
	    FT_UINT8, BASE_HEX, VALS(scsi_status_val), 0,
	    "SCSI command status value", HFILL }
	},
	{ &hf_iscsi_SCSIResponse_Response,
	  { "Response", "iscsi.scsiresponse.response",
	    FT_UINT8, BASE_HEX, VALS(iscsi_scsi_responses), 0,
	    "SCSI command response value", HFILL }
	},
	{ &hf_iscsi_SCSIResponse_BidiReadResidualCount,
	  { "BidiReadResidualCount", "iscsi.scsiresponse.bidireadresidualcount",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Bi-directional read residual count", HFILL }
	},
	{ &hf_iscsi_SenseLength,
	  { "SenseLength", "iscsi.scsiresponse.senselength",
	    FT_UINT16, BASE_HEX, NULL, 0,
	    "Sense data length", HFILL }
	},
	{ &hf_iscsi_SCSIData_F,
	  { "F", "iscsi.scsidata.F",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_F), ISCSI_SCSI_DATA_FLAG_F,
	    "Final PDU", HFILL }
	},
	{ &hf_iscsi_SCSIData_A,
	  { "A", "iscsi.scsidata.A",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_A), ISCSI_SCSI_DATA_FLAG_A,
	    "Acknowledge Requested", HFILL }
	},
	{ &hf_iscsi_SCSIData_S,
	  { "S", "iscsi.scsidata.S",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_S), ISCSI_SCSI_DATA_FLAG_S,
	    "PDU Contains SCSI command status", HFILL }
	},
	{ &hf_iscsi_SCSIData_U,
	  { "U", "iscsi.scsidata.U",
	    FT_BOOLEAN, 8,  TFS(&iscsi_meaning_U), ISCSI_SCSI_DATA_FLAG_U,
	    "Residual underflow", HFILL }
	},
	{ &hf_iscsi_SCSIData_O,
	  { "O", "iscsi.scsidata.O",
	    FT_BOOLEAN, 8,  TFS(&iscsi_meaning_O), ISCSI_SCSI_DATA_FLAG_O,
	    "Residual overflow", HFILL }
	},
	{ &hf_iscsi_TargetTransferTag,
	  { "TargetTransferTag", "iscsi.targettransfertag",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Target transfer tag", HFILL }
	},
	{ &hf_iscsi_BufferOffset,
	  { "BufferOffset", "iscsi.bufferOffset",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Buffer offset", HFILL }
	},
	{ &hf_iscsi_SCSIData_ResidualCount,
	  { "ResidualCount", "iscsi.scsidata.readresidualcount",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Residual count", HFILL }
	},
	{ &hf_iscsi_DataSN,
	  { "DataSN", "iscsi.datasn",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Data sequence number", HFILL }
	},
	{ &hf_iscsi_VersionMax,
	  { "VersionMax", "iscsi.versionmax",
	    FT_UINT8, BASE_HEX, NULL, 0,
	    "Maximum supported protocol version", HFILL }
	},
	{ &hf_iscsi_VersionMin,
	  { "VersionMin", "iscsi.versionmin",
	    FT_UINT8, BASE_HEX, NULL, 0,
	    "Minimum supported protocol version", HFILL }
	},
	{ &hf_iscsi_VersionActive,
	  { "VersionActive", "iscsi.versionactive",
	    FT_UINT8, BASE_HEX, NULL, 0,
	    "Negotiated protocol version", HFILL }
	},
	{ &hf_iscsi_CID,
	  { "CID", "iscsi.cid",
	    FT_UINT16, BASE_HEX, NULL, 0,
	    "Connection identifier", HFILL }
	},
/* #ifdef DRAFT08 */
	{ &hf_iscsi_ISID8,
	  { "ISID", "iscsi.isid",
	    FT_UINT16, BASE_HEX, NULL, 0,
	    "Initiator part of session identifier", HFILL }
	},
/* #else */
	{ &hf_iscsi_ISID,
	  { "ISID", "iscsi.isid",
	    FT_BYTES, BASE_NONE, NULL, 0,
	    "Initiator part of session identifier", HFILL }
	},
/* #ifdef DRAFT09 */
	{ &hf_iscsi_ISID_Type,
	  { "ISID_Type", "iscsi.isid.type",
	    FT_UINT8, BASE_HEX, VALS(iscsi_isid_type), 0,
	    "Initiator part of session identifier - type", HFILL }
	},
	{ &hf_iscsi_ISID_NamingAuthority,
	  { "ISID_NamingAuthority", "iscsi.isid.namingauthority",
	    FT_UINT24, BASE_HEX, NULL, 0,
	    "Initiator part of session identifier - naming authority", HFILL }
	},
	{ &hf_iscsi_ISID_Qualifier,
	  { "ISID_Qualifier", "iscsi.isid.qualifier",
	    FT_UINT8, BASE_HEX, NULL, 0,
	    "Initiator part of session identifier - qualifier", HFILL }
	},
/* #else */
	{ &hf_iscsi_ISID_t,
	  { "ISID_t", "iscsi.isid.t",
	    FT_UINT8, BASE_HEX, VALS(iscsi_isid_type), 0xc0,
	    "Initiator part of session identifier - t", HFILL }
	},
	{ &hf_iscsi_ISID_a,
	  { "ISID_a", "iscsi.isid.a",
	    FT_UINT8, BASE_HEX, NULL, 0x3f,
	    "Initiator part of session identifier - a", HFILL }
	},
	{ &hf_iscsi_ISID_b,
	  { "ISID_b", "iscsi.isid.b",
	    FT_UINT16, BASE_HEX, NULL, 0,
	    "Initiator part of session identifier - b", HFILL }
	},
	{ &hf_iscsi_ISID_c,
	  { "ISID_c", "iscsi.isid.c",
	    FT_UINT8, BASE_HEX, NULL, 0,
	    "Initiator part of session identifier - c", HFILL }
	},
	{ &hf_iscsi_ISID_d,
	  { "ISID_d", "iscsi.isid.d",
	    FT_UINT16, BASE_HEX, NULL, 0,
	    "Initiator part of session identifier - d", HFILL }
	},
/* #endif */
/* #endif */
	{ &hf_iscsi_TSID,
	  { "TSID", "iscsi.tsid",
	    FT_UINT16, BASE_HEX, NULL, 0,
	    "Target part of session identifier", HFILL }
	},
	{ &hf_iscsi_TSIH,
	  { "TSIH", "iscsi.tsih",
	    FT_UINT16, BASE_HEX, NULL, 0,
	    "Target session identifying handle", HFILL }
	},
	{ &hf_iscsi_Login_T,
	  { "T", "iscsi.login.T",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_T), 0x80,
	    "Transit to next login stage",  HFILL }
	},
	{ &hf_iscsi_Login_C,
	  { "C", "iscsi.login.C",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_C), 0x40,
	    "Text incomplete",  HFILL }
	},
/* #ifdef DRAFT09 */
	{ &hf_iscsi_Login_X,
	  { "X", "iscsi.login.X",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_login_X), 0x40,
	    "Restart Connection",  HFILL }
	},
/* #endif */
	{ &hf_iscsi_Login_CSG,
	  { "CSG", "iscsi.login.csg",
	    FT_UINT8, BASE_HEX, VALS(iscsi_login_stage), CSG_MASK,
	    "Current stage",  HFILL }
	},
	{ &hf_iscsi_Login_NSG,
	  { "NSG", "iscsi.login.nsg",
	    FT_UINT8, BASE_HEX, VALS(iscsi_login_stage), NSG_MASK,
	    "Next stage",  HFILL }
	},
	{ &hf_iscsi_Login_Status,
	  { "Status", "iscsi.login.status",
	    FT_UINT16, BASE_HEX, VALS(iscsi_login_status), 0,
	    "Status class and detail", HFILL }
	},
	{ &hf_iscsi_KeyValue,
	  { "KeyValue", "iscsi.keyvalue",
	    FT_STRING, BASE_NONE, NULL, 0,
	    "Key/value pair", HFILL }
	},
	{ &hf_iscsi_Text_F,
	  { "F", "iscsi.text.F",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_F), 0x80,
	    "Final PDU in text sequence", HFILL }
	},
	{ &hf_iscsi_Text_C,
	  { "C", "iscsi.text.C",
	    FT_BOOLEAN, 8, TFS(&iscsi_meaning_C), 0x40,
	    "Text incomplete", HFILL }
	},
	{ &hf_iscsi_ExpDataSN,
	  { "ExpDataSN", "iscsi.expdatasn",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Next expected data sequence number", HFILL }
	},
	{ &hf_iscsi_R2TSN,
	  { "R2TSN", "iscsi.r2tsn",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "R2T PDU Number", HFILL }
	},
	{ &hf_iscsi_TaskManagementFunction_Response,
	  { "Response", "iscsi.taskmanfun.response",
	    FT_UINT8, BASE_HEX, VALS(iscsi_task_management_responses), 0,
	    NULL, HFILL }
	},
	{ &hf_iscsi_TaskManagementFunction_ReferencedTaskTag,
	  { "ReferencedTaskTag", "iscsi.taskmanfun.referencedtasktag",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Referenced task tag", HFILL }
	},
	{ &hf_iscsi_RefCmdSN,
	  { "RefCmdSN", "iscsi.refcmdsn",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Command sequence number for command to be aborted", HFILL }
	},
	{ &hf_iscsi_TaskManagementFunction_Function,
	  { "Function", "iscsi.taskmanfun.function",
	    FT_UINT8, BASE_HEX, VALS(iscsi_task_management_functions), 0x7F,
	    "Requested task function", HFILL }
	},
	{ &hf_iscsi_Logout_Reason,
	  { "Reason", "iscsi.logout.reason",
	    FT_UINT8, BASE_HEX, VALS(iscsi_logout_reasons), 0x7F,
	    "Reason for logout", HFILL }
	},
	{ &hf_iscsi_Logout_Response,
	  { "Response", "iscsi.logout.response",
	    FT_UINT8, BASE_HEX, VALS(iscsi_logout_response), 0,
	    "Logout response", HFILL }
	},
	{ &hf_iscsi_Time2Wait,
	  { "Time2Wait", "iscsi.time2wait",
	    FT_UINT16, BASE_HEX, NULL, 0,
	    NULL, HFILL }
	},
	{ &hf_iscsi_Time2Retain,
	  { "Time2Retain", "iscsi.time2retain",
	    FT_UINT16, BASE_HEX, NULL, 0,
	    NULL, HFILL }
	},
	{ &hf_iscsi_DesiredDataLength,
	  { "DesiredDataLength", "iscsi.desireddatalength",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Desired data length (bytes)", HFILL }
	},
	{ &hf_iscsi_AsyncEvent,
	  { "AsyncEvent", "iscsi.asyncevent",
	    FT_UINT8, BASE_HEX, VALS(iscsi_asyncevents), 0,
	    "Async event type", HFILL }
	},
	{ &hf_iscsi_EventVendorCode,
	  { "EventVendorCode", "iscsi.eventvendorcode",
	    FT_UINT8, BASE_HEX, NULL, 0,
	    "Event vendor code", HFILL }
	},
	{ &hf_iscsi_Parameter1,
	  { "Parameter1", "iscsi.parameter1",
	    FT_UINT16, BASE_HEX, NULL, 0,
	    "Parameter 1", HFILL }
	},
	{ &hf_iscsi_Parameter2,
	  { "Parameter2", "iscsi.parameter2",
	    FT_UINT16, BASE_HEX, NULL, 0,
	    "Parameter 2", HFILL }
	},
	{ &hf_iscsi_Parameter3,
	  { "Parameter3", "iscsi.parameter3",
	    FT_UINT16, BASE_HEX, NULL, 0,
	    "Parameter 3", HFILL }
	},
	{ &hf_iscsi_Reject_Reason,
	  { "Reason", "iscsi.reject.reason",
	    FT_UINT8, BASE_HEX, VALS(iscsi_reject_reasons), 0,
	    "Reason for command rejection", HFILL }
	},
	{ &hf_iscsi_snack_type,
	  { "S", "iscsi.snack.type",
	    FT_UINT8, BASE_DEC, VALS(iscsi_snack_types), 0x0f,
	    "Type of SNACK requested", HFILL }
	},
	{ &hf_iscsi_BegRun,
	  { "BegRun", "iscsi.snack.begrun",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "First missed DataSN or StatSN", HFILL }
	},
	{ &hf_iscsi_RunLength,
	  { "RunLength", "iscsi.snack.runlength",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Number of additional missing status PDUs in this run", HFILL }
	},
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
	&ett_iscsi,
	&ett_iscsi_KeyValues,
	&ett_iscsi_CDB,
	&ett_iscsi_Flags,
	&ett_iscsi_RejectHeader,
/* #ifndef DRAFT08 */
	&ett_iscsi_ISID,
/* #endif */
    };

    /* Register the protocol name and description */
    proto_iscsi = proto_register_protocol("iSCSI", "iSCSI", "iscsi");

    /* Required function calls to register the header fields and
     * subtrees used */
    proto_register_field_array(proto_iscsi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    iscsi_module = prefs_register_protocol(proto_iscsi, NULL);

    prefs_register_enum_preference(iscsi_module,
				   "protocol_version",
				   "Protocol version",
				   "The iSCSI protocol version",
				   &iscsi_protocol_version,
				   iscsi_protocol_versions,
				   FALSE);

    prefs_register_bool_preference(iscsi_module,
				   "desegment_iscsi_messages",
				   "Reassemble iSCSI messages\nspanning multiple TCP segments",
				   "Whether the iSCSI dissector should reassemble messages spanning multiple TCP segments."
				   " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
				   &iscsi_desegment);

    prefs_register_bool_preference(iscsi_module,
				   "bogus_pdu_filter",
				   "Enable bogus pdu filter",
				   "When enabled, packets that appear bogus are ignored",
				   &enable_bogosity_filter);

    prefs_register_bool_preference(iscsi_module,
				   "demand_good_f_bit",
				   "Ignore packets with bad F bit",
				   "Ignore packets that haven't set the F bit when they should have",
				   &demand_good_f_bit);

    prefs_register_uint_preference(iscsi_module,
				   "bogus_pdu_max_data_len",
				   "Bogus pdu max data length threshold",
				   "Treat packets whose data segment length is greater than this value as bogus",
				   10,
				   &bogus_pdu_data_length_threshold);

    range_convert_str(&global_iscsi_port_range, TCP_PORT_ISCSI_RANGE, MAX_TCP_PORT);
    prefs_register_range_preference(iscsi_module,
				   "target_ports",
				   "Target Ports Range",
				   "Range of iSCSI target ports"
				   "(default " TCP_PORT_ISCSI_RANGE ")",
				   &global_iscsi_port_range, MAX_TCP_PORT);

    prefs_register_uint_preference(iscsi_module,
				   "target_system_port",
				   "Target system port",
				   "System port number of iSCSI target",
				   10,
				   &iscsi_system_port);

    prefs_register_bool_preference(iscsi_module,
				   "enable_data_digests",
				   "Enable data digests",
				   "When enabled, pdus are assumed to contain a data digest",
				   &enableDataDigests);

    prefs_register_bool_preference(iscsi_module,
				   "data_digest_is_crc32c",
				   "Data digest is CRC32C",
				   "When enabled, data digests are assumed to be CRC32C",
				   &dataDigestIsCRC32);

    prefs_register_uint_preference(iscsi_module,
				   "data_digest_size",
				   "Data digest size",
				   "The size of a data digest (bytes)",
				   10,
				   &dataDigestSize);

    /* Preference supported in older versions.
       Register them as obsolete. */
    prefs_register_obsolete_preference(iscsi_module,
				   "version_03_compatible");
    prefs_register_obsolete_preference(iscsi_module,
				   "bogus_pdu_max_digest_padding");
    prefs_register_obsolete_preference(iscsi_module,
				   "header_digest_is_crc32c");
    prefs_register_obsolete_preference(iscsi_module,
				   "header_digest_size");
    prefs_register_obsolete_preference(iscsi_module,
				   "enable_header_digests");
}


/*
 * If this dissector uses sub-dissector registration add a
 * registration routine.
 */

/*
 * This format is required because a script is used to find these
 * routines and create the code that calls these routines.
 */
void
proto_reg_handoff_iscsi(void)
{
    heur_dissector_add("tcp", dissect_iscsi_heur, proto_iscsi);

    iscsi_handle = new_create_dissector_handle(dissect_iscsi_handle, proto_iscsi);
    dissector_add_handle("tcp.port", iscsi_handle);
}
