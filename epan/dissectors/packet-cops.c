/* packet-cops.c
 * Routines for the COPS (Common Open Policy Service) protocol dissection
 * RFC2748 & COPS-PR extension RFC3084
 *
 * Copyright 2000, Heikki Vatiainen <hessu@cs.tut.fi>
 *
 * Added PacketCable specifications by Dick Gooris <gooris@lucent.com>
 *
 * Taken from PacketCable specifications :
 *    PacketCable Dynamic Quality-of-Service Specification
 *    Based on PKT-SP-DQOS-I09-040402 (April 2, 2004)
 *    www.packetcable.com
 *
 * Implemented in ethereal at April 7-8, 2004
 *
 * $Id$
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
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <glib.h>

#include "isprint.h"

#include <epan/packet.h>
#include "packet-ipv6.h"
#include "packet-tcp.h"

#ifdef HAVE_SOME_SNMP
#ifdef HAVE_NET_SNMP
# include <net-snmp/net-snmp-config.h>
# include <net-snmp/mib_api.h>
# include <net-snmp/library/default_store.h>
# include <net-snmp/config_api.h>
#else /* HAVE_NET_SNMP */
# include <ucd-snmp/ucd-snmp-config.h>
# include <ucd-snmp/asn1.h>
# include <ucd-snmp/snmp_api.h>
# include <ucd-snmp/snmp_impl.h>
# include <ucd-snmp/mib.h>
# include <ucd-snmp/default_store.h>
# include <ucd-snmp/read_config.h>
# include <ucd-snmp/tools.h>
#endif /* HAVE_NET_SNMP */
#endif /* HAVE_SOME_SNMP */

#include "asn1.h"
#include "format-oid.h"
#include "prefs.h"

/* For PacketCable, port 2126 */
#define TCP_PORT_COPS 3288

/* Preference: Variable to hold the tcp port preference */
static guint global_cops_tcp_port = TCP_PORT_COPS;

/* Preference: desegmentation of COPS */
static gboolean cops_desegment = TRUE;

/* Variable to allow for proper deletion of dissector registration
 * when the user changes port from the gui
 */

static guint cops_tcp_port = 0;

/*Some local globals needed to read COPS-PR ASN.1 Types from PIB-MIBs */
/*MAX_OID_LEN from NET-SNMP's asn1.h*/

#ifdef HAVE_NET_SNMP
static  subid_t last_decoded_prid_oid[MAX_OID_LEN]={0};
static  subid_t last_decoded_prid_oid_length=0;
extern struct tree *tree_head;

/* Preference: COPS-PR ASN.1 type decoding based on PIB/MIB or data in packet */
static gboolean cops_typefrommib = FALSE;

#endif /* HAVE_NET_SNMP */

#define COPS_OBJECT_HDR_SIZE 4

/* Null string of type "guchar[]". */
static const guchar nullstring[] = "";

#define	SAFE_STRING(s)	(((s) != NULL) ? (s) : nullstring)

/* COPS PR Tags */

#define COPS_IPA    0		/* IP Address */
#define COPS_U32    2		/* Unsigned 32*/
#define COPS_TIT    3		/* TimeTicks */
#define COPS_OPQ    4		/* Opaque */
#define COPS_I64    10		/* Integer64 */
#define COPS_U64    11		/* Uinteger64 */

/* COPS PR Types */

#define COPS_NULL                0
#define COPS_INTEGER             1    /* l  */
#define COPS_OCTETSTR            2    /* c  */
#define COPS_OBJECTID            3    /* ul */
#define COPS_IPADDR              4    /* uc */
#define COPS_UNSIGNED32          5    /* ul */
#define COPS_TIMETICKS           7    /* ul */
#define COPS_OPAQUE              8    /* c  */
#define COPS_INTEGER64           10   /* ll */
#define COPS_UNSIGNED64          11   /* ull  */


typedef struct _COPS_CNV COPS_CNV;

struct _COPS_CNV
{
  guint class;
  guint tag;
  gint  syntax;
  gchar *name;
};

static COPS_CNV CopsCnv [] =
{
  {ASN1_UNI, ASN1_NUL, COPS_NULL,      "NULL"},
  {ASN1_UNI, ASN1_INT, COPS_INTEGER,   "INTEGER"},
  {ASN1_UNI, ASN1_OTS, COPS_OCTETSTR,  "OCTET STRING"},
  {ASN1_UNI, ASN1_OJI, COPS_OBJECTID,  "OBJECTID"},
  {ASN1_APL, COPS_IPA, COPS_IPADDR,    "IPADDR"},
  {ASN1_APL, COPS_U32, COPS_UNSIGNED32,"UNSIGNED32"},
  {ASN1_APL, COPS_TIT, COPS_TIMETICKS, "TIMETICKS"},
  {ASN1_APL, COPS_OPQ, COPS_OPAQUE,    "OPAQUE"},
  {ASN1_APL, COPS_I64, COPS_INTEGER64, "INTEGER64"},
  {ASN1_APL, COPS_U64, COPS_UNSIGNED64, "UNSIGNED64"},
  {0,       0,         -1,                  NULL}
};

static gchar *
cops_tag_cls2syntax ( guint tag, guint cls, gushort *syntax)
{
  COPS_CNV *cnv;

  cnv = CopsCnv;
  while (cnv->syntax != -1)
  {
    if (cnv->tag == tag && cnv->class == cls)
    {
      *syntax = cnv->syntax;
      return cnv->name;
    }
    cnv++;
  }
  return NULL;
}

static const value_string cops_flags_vals[] = {
  { 0x00,          "None" },
  { 0x01,          "Solicited Message Flag Bit" },
  { 0, NULL },
};

/* The different COPS message types */
enum cops_op_code {
  COPS_NO_MSG,          /* Not a COPS Message type     */

  COPS_MSG_REQ,         /* Request (REQ)               */
  COPS_MSG_DEC,         /* Decision (DEC)              */
  COPS_MSG_RPT,         /* Report State (RPT)          */
  COPS_MSG_DRQ,         /* Delete Request State (DRQ)  */
  COPS_MSG_SSQ,         /* Synchronize State Req (SSQ) */
  COPS_MSG_OPN,         /* Client-Open (OPN)           */
  COPS_MSG_CAT,         /* Client-Accept (CAT)         */
  COPS_MSG_CC,          /* Client-Close (CC)           */
  COPS_MSG_KA,          /* Keep-Alive (KA)             */
  COPS_MSG_SSC,         /* Synchronize Complete (SSC)  */

  COPS_LAST_OP_CODE     /* For error checking          */
};

static const value_string cops_op_code_vals[] = {
  { COPS_MSG_REQ,          "Request (REQ)" },
  { COPS_MSG_DEC,          "Decision (DEC)" },
  { COPS_MSG_RPT,          "Report State (RPT)" },
  { COPS_MSG_DRQ,          "Delete Request State (DRQ)" },
  { COPS_MSG_SSQ,          "Synchronize State Req (SSQ)" },
  { COPS_MSG_OPN,          "Client-Open (OPN)" },
  { COPS_MSG_CAT,          "Client-Accept (CAT)" },
  { COPS_MSG_CC,           "Client-Close (CC)" },
  { COPS_MSG_KA,           "Keep-Alive (KA)" },
  { COPS_MSG_SSC,          "Synchronize Complete (SSC)" },
  { 0, NULL },
};


/* The different objects in COPS messages */
enum cops_c_num {
  COPS_NO_OBJECT,        /* Not a COPS Object type               */

  COPS_OBJ_HANDLE,       /* Handle Object (Handle)               */
  COPS_OBJ_CONTEXT,      /* Context Object (Context)             */
  COPS_OBJ_IN_INT,       /* In-Interface Object (IN-Int)         */
  COPS_OBJ_OUT_INT,      /* Out-Interface Object (OUT-Int)       */
  COPS_OBJ_REASON,       /* Reason Object (Reason)               */
  COPS_OBJ_DECISION,     /* Decision Object (Decision)           */
  COPS_OBJ_LPDPDECISION, /* LPDP Decision Object (LPDPDecision)  */
  COPS_OBJ_ERROR,        /* Error Object (Error)                 */
  COPS_OBJ_CLIENTSI,     /* Client Specific Information Object (ClientSI) */
  COPS_OBJ_KATIMER,      /* Keep-Alive Timer Object (KATimer)    */
  COPS_OBJ_PEPID,        /* PEP Identification Object (PEPID)    */
  COPS_OBJ_REPORT_TYPE,  /* Report-Type Object (Report-Type)     */
  COPS_OBJ_PDPREDIRADDR, /* PDP Redirect Address Object (PDPRedirAddr) */
  COPS_OBJ_LASTPDPADDR,  /* Last PDP Address (LastPDPaddr)       */
  COPS_OBJ_ACCTTIMER,    /* Accounting Timer Object (AcctTimer)  */
  COPS_OBJ_INTEGRITY,    /* Message Integrity Object (Integrity) */
  COPS_LAST_C_NUM        /* For error checking                   */
};

static const value_string cops_c_num_vals[] = {
  { COPS_OBJ_HANDLE,       "Handle Object (Handle)" },
  { COPS_OBJ_CONTEXT,      "Context Object (Context)" },
  { COPS_OBJ_IN_INT,       "In-Interface Object (IN-Int)" },
  { COPS_OBJ_OUT_INT,      "Out-Interface Object (OUT-Int)" },
  { COPS_OBJ_REASON,       "Reason Object (Reason)" },
  { COPS_OBJ_DECISION,     "Decision Object (Decision)" },
  { COPS_OBJ_LPDPDECISION, "LPDP Decision Object (LPDPDecision)" },
  { COPS_OBJ_ERROR,        "Error Object (Error)" },
  { COPS_OBJ_CLIENTSI,     "Client Specific Information Object (ClientSI)" },
  { COPS_OBJ_KATIMER,      "Keep-Alive Timer Object (KATimer)" },
  { COPS_OBJ_PEPID,        "PEP Identification Object (PEPID)" },
  { COPS_OBJ_REPORT_TYPE,  "Report-Type Object (Report-Type)" },
  { COPS_OBJ_PDPREDIRADDR, "PDP Redirect Address Object (PDPRedirAddr)" },
  { COPS_OBJ_LASTPDPADDR,  "Last PDP Address (LastPDPaddr)" },
  { COPS_OBJ_ACCTTIMER,    "Accounting Timer Object (AcctTimer)" },
  { COPS_OBJ_INTEGRITY,    "Message Integrity Object (Integrity)" },
  { 0, NULL },
};


/* The different objects in COPS-PR messages */
enum cops_s_num {
  COPS_NO_PR_OBJECT,     /* Not a COPS-PR Object type               */
  COPS_OBJ_PRID,         /* Provisioning Instance Identifier (PRID) */
  COPS_OBJ_PPRID,        /* Prefix Provisioning Instance Identifier (PPRID) */
  COPS_OBJ_EPD,          /* Encoded Provisioning Instance Data (EPD) */
  COPS_OBJ_GPERR,        /* Global Provisioning Error Object (GPERR) */
  COPS_OBJ_CPERR,        /* PRC Class Provisioning Error Object (CPERR) */
  COPS_OBJ_ERRPRID,      /* Error Provisioning Instance Identifier (ErrorPRID)*/

  COPS_LAST_S_NUM        /* For error checking                   */
};


static const value_string cops_s_num_vals[] = {
  { COPS_OBJ_PRID,         "Provisioning Instance Identifier (PRID)" },
  { COPS_OBJ_PPRID,        "Prefix Provisioning Instance Identifier (PPRID)" },
  { COPS_OBJ_EPD,          "Encoded Provisioning Instance Data (EPD)" },
  { COPS_OBJ_GPERR,        "Global Provisioning Error Object (GPERR)" },
  { COPS_OBJ_CPERR,        "PRC Class Provisioning Error Object (CPERR)" },
  { COPS_OBJ_ERRPRID,      "Error Provisioning Instance Identifier (ErrorPRID)" },
  { 0, NULL },

};

/* R-Type is carried within the Context Object */
static const value_string cops_r_type_vals[] = {
  { 0x01, "Incoming-Message/Admission Control request" },
  { 0x02, "Resource-Allocation request" },
  { 0x04, "Outgoing-Message request" },
  { 0x08, "Configuration request" },
  { 0, NULL },
};
/* S-Type is carried within the ClientSI Object for COPS-PR*/
static const value_string cops_s_type_vals[] = {
  { 0x01, "BER" },
  { 0, NULL },
};

/* Reason-Code is carried within the Reason object */
static const value_string cops_reason_vals[] = {
  { 1,  "Unspecified" },
  { 2,  "Management" },
  { 3,  "Preempted (Another request state takes precedence)" },
  { 4,  "Tear (Used to communicate a signaled state removal)" },
  { 5,  "Timeout (Local state has timed-out)" },
  { 6,  "Route Change (Change invalidates request state)" },
  { 7,  "Insufficient Resources (No local resource available)" },
  { 8,  "PDP's Directive (PDP decision caused the delete)" },
  { 9,  "Unsupported decision (PDP decision not supported)" },
  { 10, "Synchronize Handle Unknown" },
  { 11, "Transient Handle (stateless event)" },
  { 12, "Malformed Decision (could not recover)" },
  { 13, "Unknown COPS Object from PDP" },
  { 0, NULL },
};

/* Command-Code is carried within the Decision object if C-Type is 1 */
static const value_string cops_dec_cmd_code_vals[] = {
  { 0, "NULL Decision (No configuration data available)" },
  { 1, "Install (Admit request/Install configuration)" },
  { 2, "Remove (Remove request/Remove configuration)" },
  { 0, NULL },
};

/* Decision flags are also carried with the Decision object if C-Type is 1 */
static const value_string cops_dec_cmd_flag_vals[] = {
  { 0x00, "<None set>" },
  { 0x01, "Trigger Error (Trigger error message if set)" },
  { 0, NULL },
};

/* Error-Code from Error object */
static const value_string cops_error_vals[] = {
  {1,  "Bad handle" },
  {2,  "Invalid handle reference" },
  {3,  "Bad message format (Malformed Message)" },
  {4,  "Unable to process (server gives up on query)" },
  {5,  "Mandatory client-specific info missing" },
  {6,  "Unsupported client" },
  {7,  "Mandatory COPS object missing" },
  {8,  "Client Failure" },
  {9,  "Communication Failure" },
  {10, "Unspecified" },
  {11, "Shutting down" },
  {12, "Redirect to Preferred Server" },
  {13, "Unknown COPS Object" },
  {14, "Authentication Failure" },
  {15, "Authentication Required" },
  {0,  NULL },
};
/* Error-Code from GPERR object */
static const value_string cops_gperror_vals[] = {
  {1,  "AvailMemLow" },
  {2,  "AvailMemExhausted" },
  {3,  "unknownASN.1Tag" },
  {4,  "maxMsgSizeExceeded" },
  {5,  "unknownError" },
  {6,  "maxRequestStatesOpen" },
  {7,  "invalidASN.1Length" },
  {8,  "invalidObjectPad" },
  {9,  "unknownPIBData" },
  {10, "unknownCOPSPRObject" },
  {11, "malformedDecision" },
  {0,  NULL },
};

/* Error-Code from CPERR object */
static const value_string cops_cperror_vals[] = {
  {1,  "priSpaceExhausted" },
  {2,  "priInstanceInvalid" },
  {3,  "attrValueInvalid" },
  {4,  "attrValueSupLimited" },
  {5,  "attrEnumSupLimited" },
  {6,  "attrMaxLengthExceeded" },
  {7,  "attrReferenceUnknown" },
  {8,  "priNotifyOnly" },
  {9,  "unknownPrc" },
  {10, "tooFewAttrs" },
  {11, "invalidAttrType" },
  {12, "deletedInRef" },
  {13, "priSpecificError" },
 	{0,  NULL },
};


/* Report-Type from Report-Type object */
static const value_string cops_report_type_vals[] = {
  {1, " Success   : Decision was successful at the PEP" },
  {2, " Failure   : Decision could not be completed by PEP" },
  {3, " Accounting: Accounting update for an installed state" },
  {0, NULL },
};

/* The next tables are for PacketCable */

/* Transaction ID table */
static const value_string table_cops_transaction_id[] =
{
  { 0x1,  "Gate Alloc" },
  { 0x2,  "Gate Alloc Ack" },
  { 0x3,  "Gate Alloc Err" },
  { 0x4,  "Gate Set" },
  { 0x5,  "Gate Set Ack" },
  { 0x6,  "Gate Set Err" },
  { 0x7,  "Gate Info" },
  { 0x8,  "Gate Info Ack" },
  { 0x9,  "Gate Info Err" },
  { 0xa,  "Gate Delete" },
  { 0xb,  "Gate Delete Ack" },
  { 0xc,  "Gate Delete Err" },
  { 0xd,  "Gate Open" },
  { 0xe,  "Gate Close" },
  { 0xFF, NULL },
};

/* Direction */
static const value_string table_cops_direction[] =
{
  { 0x0,  "Downstream gate" },
  { 0x1,  "Upstream gate" },
  { 0xFF, NULL },
};

/* Session Class */
static const value_string table_cops_session_class[] =
{
  { 0x0,  "Unspecified" },
  { 0x1,  "Normal priority VoIP session" },
  { 0x2,  "High priority VoIP session" },
  { 0x3,  "Reserved" },
  { 0xFF, NULL },
};

/* Reason Code */
static const value_string table_cops_reason_code[] =
{
  { 0x0,  "Gate Delete Operation" },
  { 0x1,  "Gate Close Operation" },
  { 0xFF, NULL },
};

/* Reason Sub Code - Delete */
static const value_string table_cops_reason_subcode_delete[] =
{
  { 0x0,  "Normal Operation" },
  { 0x1,  "Local Gate-coordination not completed" },
  { 0x2,  "Remote Gate-coordination not completed" },
  { 0x3,  "Authorization revoked" },
  { 0x4,  "Unexpected Gate-Open" },
  { 0x5,  "Local Gate-Close failure" },
  { 0x127,"Unspecified error" },
  { 0xFF, NULL },
};

/* Reason Sub Code - Close */
static const value_string table_cops_reason_subcode_close[] =
{
  { 0x0,  "Client initiated release (normal operation)" },
  { 0x1,  "Reservation reassignment" },
  { 0x2,  "Lack of reservation maintenance" },
  { 0x3,  "Lack of Docsis Mac-layer responses" },
  { 0x4,  "Timer T0 expiration; no Gate-Set received from CMS" },
  { 0x5,  "Timer T1 expiration; no Commit received from MTA" },
  { 0x6,  "Timer T7 expiration; Service Flow reservation timeout" },
  { 0x7,  "Timer T8 expiration; Service Flow inactivity in the upstream direction" },
  { 0x127,"Unspecified error" },
  { 0xFF, NULL },
};

/* PacketCable Error */
static const value_string table_cops_packetcable_error[] =
{
  { 0x1,  "No gates urrently available" },
  { 0x2,  "Unknown Gate ID" },
  { 0x3,  "Illegal Session Class value" },
  { 0x4,  "Subscriber exceeded gate limit" },
  { 0x5,  "Gate already set" },
  { 0x6,  "Missing Required Object" },
  { 0x7,  "Invalid Object" },
  { 0x127,"Unspecified error" },
  { 0xFF, NULL },
};

/* End of PacketCable Tables */


/* Initialize the protocol and registered fields */
static gint proto_cops = -1;
static gint hf_cops_ver_flags = -1;
static gint hf_cops_version = -1;
static gint hf_cops_flags = -1;

static gint hf_cops_op_code = -1;
static gint hf_cops_client_type = -1;
static gint hf_cops_msg_len = -1;

static gint hf_cops_obj_len = -1;
static gint hf_cops_obj_c_num = -1;
static gint hf_cops_obj_c_type = -1;

static gint hf_cops_obj_s_num = -1;
static gint hf_cops_obj_s_type = -1;

static gint hf_cops_r_type_flags = -1;
static gint hf_cops_m_type_flags = -1;

static gint hf_cops_in_int_ipv4 = -1;
static gint hf_cops_in_int_ipv6 = -1;
static gint hf_cops_out_int_ipv4 = -1;
static gint hf_cops_out_int_ipv6 = -1;
static gint hf_cops_int_ifindex = -1;

static gint hf_cops_reason = -1;
static gint hf_cops_reason_sub = -1;

static gint hf_cops_dec_cmd_code = -1;
static gint hf_cops_dec_flags = -1;

static gint hf_cops_error = -1;
static gint hf_cops_error_sub = -1;

static gint hf_cops_gperror = -1;
static gint hf_cops_gperror_sub = -1;

static gint hf_cops_cperror = -1;
static gint hf_cops_cperror_sub = -1;

static gint hf_cops_katimer = -1;

static gint hf_cops_pepid = -1;

static gint hf_cops_report_type = -1;

static gint hf_cops_pdprediraddr_ipv4 = -1;
static gint hf_cops_pdprediraddr_ipv6 = -1;
static gint hf_cops_lastpdpaddr_ipv4 = -1;
static gint hf_cops_lastpdpaddr_ipv6 = -1;
static gint hf_cops_pdp_tcp_port = -1;

static gint hf_cops_accttimer = -1;

static gint hf_cops_key_id = -1;
static gint hf_cops_seq_num = -1;

/* For PacketCable */
static gint hf_cops_subtree = -1;
static gint hf_cops_pc_activity_count = -1;
static gint hf_cops_pc_algorithm = -1;
static gint hf_cops_pc_close_subcode = -1;
static gint hf_cops_pc_cmts_ip = -1;
static gint hf_cops_pc_cmts_ip_port = -1;
static gint hf_cops_pc_prks_ip = -1;
static gint hf_cops_pc_prks_ip_port = -1;
static gint hf_cops_pc_srks_ip = -1;
static gint hf_cops_pc_srks_ip_port = -1;
static gint hf_cops_pc_delete_subcode = -1;
static gint hf_cops_pc_dest_ip = -1;
static gint hf_cops_pc_dest_port = -1;
static gint hf_cops_pc_direction = -1;
static gint hf_cops_pc_ds_field = -1;
static gint hf_cops_pc_gate_id = -1;
static gint hf_cops_pc_gate_spec_flags = -1;
static gint hf_cops_pc_gate_command_type = -1;
static gint hf_cops_pc_key = -1;
static gint hf_cops_pc_max_packet_size = -1;
static gint hf_cops_pc_min_policed_unit = -1;
static gint hf_cops_pc_packetcable_err_code = -1;
static gint hf_cops_pc_packetcable_sub_code = -1;
static gint hf_cops_pc_peak_data_rate = -1;
static gint hf_cops_pc_protocol_id = -1;
static gint hf_cops_pc_reason_code = -1;
static gint hf_cops_pc_remote_flags = -1;
static gint hf_cops_pc_remote_gate_id = -1;
static gint hf_cops_pc_reserved = -1;
static gint hf_cops_pc_session_class = -1;
static gint hf_cops_pc_slack_term = -1;
static gint hf_cops_pc_spec_rate = -1;
static gint hf_cops_pc_src_ip = -1;
static gint hf_cops_pc_src_port = -1;
static gint hf_cops_pc_subscriber_id = -1;
static gint hf_cops_pc_t1_value = -1;
static gint hf_cops_pc_t7_value = -1;
static gint hf_cops_pc_t8_value = -1;
static gint hf_cops_pc_token_bucket_rate = -1;
static gint hf_cops_pc_token_bucket_size = -1;
static gint hf_cops_pc_transaction_id = -1;
static gint hf_cops_pc_bcid_ts = -1;
static gint hf_cops_pc_bcid = -1;
static gint hf_cops_pc_bcid_ev = -1;
static gint hf_cops_pc_dfcdc_ip = -1;
static gint hf_cops_pc_dfccc_ip = -1;
static gint hf_cops_pc_dfcdc_ip_port = -1;
static gint hf_cops_pc_dfccc_ip_port = -1;

/* Initialize the subtree pointers */
static gint ett_cops = -1;
static gint ett_cops_ver_flags = -1;
static gint ett_cops_obj = -1;
static gint ett_cops_pr_obj = -1;
static gint ett_cops_obj_data = -1;
static gint ett_cops_r_type_flags = -1;
static gint ett_cops_itf = -1;
static gint ett_cops_reason = -1;
static gint ett_cops_decision = -1;
static gint ett_cops_error = -1;
static gint ett_cops_clientsi = -1;
static gint ett_cops_asn1 = -1;
static gint ett_cops_gperror = -1;
static gint ett_cops_cperror = -1;
static gint ett_cops_pdp = -1;

/* For PacketCable */
static gint ett_cops_subtree = -1;

void proto_reg_handoff_cops(void);

static guint get_cops_pdu_len(tvbuff_t *tvb, int offset);
static void dissect_cops_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static int dissect_cops_object(tvbuff_t *tvb, guint32 offset, proto_tree *tree);
static void dissect_cops_object_data(tvbuff_t *tvb, guint32 offset, proto_tree *tree,
                                     guint8 c_num, guint8 c_type, guint16 len);

static void dissect_cops_pr_objects(tvbuff_t *tvb, guint32 offset, proto_tree *tree, guint16 pr_len);
static int dissect_cops_pr_object_data(tvbuff_t *tvb, guint32 offset, proto_tree *tree,
                                       guint8 s_num, guint8 s_type, guint16 len);

/* Added for PacketCable */
proto_tree *info_to_cops_subtree(tvbuff_t *, proto_tree *, int, int, char *);
void   info_to_display(tvbuff_t *, proto_item *, int, int, char *, const value_string *, int, gint *);
void   cops_transaction_id(tvbuff_t *, proto_tree *, guint, guint32);
void   cops_subscriber_id_v4(tvbuff_t *, proto_tree *, guint, guint32);
void   cops_gate_id(tvbuff_t *, proto_tree *, guint, guint32);
void   cops_activity_count(tvbuff_t *, proto_tree *, guint, guint32);
void   cops_gate_specs(tvbuff_t *, proto_tree *, guint, guint32);
void   cops_remote_gate_info(tvbuff_t *, proto_tree *, guint, guint32);
void   cops_packetcable_reason(tvbuff_t *, proto_tree *, guint, guint32);
void   cops_packetcable_error(tvbuff_t *, proto_tree *, guint, guint32);
void   cops_analyze_packetcable_obj(tvbuff_t *, proto_tree *, guint32);
void   cops_event_generation_info(tvbuff_t *, proto_tree *, guint, guint32);
void   cops_surveillance_parameters(tvbuff_t *, proto_tree *, guint, guint32);

static packet_info *cpinfo;
static guint8 opcode_idx;
static gboolean cops_packetcable = TRUE;
/* End of addition for PacketCable */


/* Code to actually dissect the packets */
static void
dissect_cops(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tcp_dissect_pdus(tvb, pinfo, tree, cops_desegment, 8,
                   get_cops_pdu_len, dissect_cops_pdu);
}

static guint
get_cops_pdu_len(tvbuff_t *tvb, int offset)
{
  /*
   * Get the length of the COPS message.
   */
  return tvb_get_ntohl(tvb, offset + 4);
}

static void
dissect_cops_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint8 op_code;
  int object_len;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "COPS");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  op_code = tvb_get_guint8(tvb, 1);
  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_fstr(pinfo->cinfo, COL_INFO, "COPS %s",
                 val_to_str(op_code, cops_op_code_vals, "Unknown Op Code"));

  /* PacketCable: Remember the next two values to manipulate the info field in the Gui */
  cpinfo = pinfo;
  opcode_idx = op_code;

  if (tree) {
    proto_item *ti, *tv;
    proto_tree *cops_tree, *ver_flags_tree;
    guint32 msg_len;
    guint32 offset = 0;
    guint8 ver_flags;
    gint garbage;

    ti = proto_tree_add_item(tree, proto_cops, tvb, offset, -1, FALSE);
    cops_tree = proto_item_add_subtree(ti, ett_cops);

    /* Version and flags share the same byte, put them in a subtree */
    ver_flags = tvb_get_guint8(tvb, offset);
    tv = proto_tree_add_uint_format(cops_tree, hf_cops_ver_flags, tvb, offset, 1,
                                      ver_flags, "Version: %u, Flags: %s",
                                      hi_nibble(ver_flags),
                                      val_to_str(lo_nibble(ver_flags), cops_flags_vals, "Unknown"));
    ver_flags_tree = proto_item_add_subtree(tv, ett_cops_ver_flags);
    proto_tree_add_uint(ver_flags_tree, hf_cops_version, tvb, offset, 1, ver_flags);
    proto_tree_add_uint(ver_flags_tree, hf_cops_flags, tvb, offset, 1, ver_flags);
    offset++;

    proto_tree_add_item(cops_tree, hf_cops_op_code, tvb, offset, 1, FALSE);
    offset ++;
    proto_tree_add_item(cops_tree, hf_cops_client_type, tvb, offset, 2, FALSE);
    offset += 2;

    msg_len = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(cops_tree, hf_cops_msg_len, tvb, offset, 4, msg_len);
    offset += 4;

    while (tvb_reported_length_remaining(tvb, offset) >= COPS_OBJECT_HDR_SIZE) {
      object_len = dissect_cops_object(tvb, offset, cops_tree);
      if (object_len < 0)
        return;
      offset += object_len;
    }

    garbage = tvb_length_remaining(tvb, offset);
    if (garbage > 0)
      proto_tree_add_text(cops_tree, tvb, offset, garbage,
                          "Trailing garbage: %d byte%s", garbage,
                          plurality(garbage, "", "s"));
  }
}

static char *cops_c_type_to_str(guint8 c_num, guint8 c_type)
{
  switch (c_num) {
  case COPS_OBJ_HANDLE:
    if (c_type == 1)
      return "Client Handle";
    break;
  case COPS_OBJ_IN_INT:
  case COPS_OBJ_OUT_INT:
    if (c_type == 1)
      return "IPv4 Address + Interface";
    else if (c_type == 2)
      return "IPv6 Address + Interface";
    break;
  case COPS_OBJ_DECISION:
  case COPS_OBJ_LPDPDECISION:
    if (c_type == 1)
      return "Decision Flags (Mandatory)";
    else if (c_type == 2)
      return "Stateless Data";
    else if (c_type == 3)
      return "Replacement Data";
    else if (c_type == 4)
      return "Client Specific Decision Data";
    else if (c_type == 5)
      return "Named Decision Data";
    break;
  case COPS_OBJ_CLIENTSI:
    if (c_type == 1)
      return "Signaled ClientSI";
    else if (c_type == 2)
      return "Named ClientSI";
    break;
  case COPS_OBJ_KATIMER:
    if (c_type == 1)
      return "Keep-alive timer value";
    break;
  case COPS_OBJ_PDPREDIRADDR:
  case COPS_OBJ_LASTPDPADDR:
    if (c_type == 1)
      return "IPv4 Address + TCP Port";
    else if (c_type == 2)
      return "IPv6 Address + TCP Port";
    break;
  case COPS_OBJ_ACCTTIMER:
    if (c_type == 1)
      return "Accounting timer value";
    break;
  case COPS_OBJ_INTEGRITY:
    if (c_type == 1)
      return "HMAC digest";
    break;
  }

  return "";
}

static int dissect_cops_object(tvbuff_t *tvb, guint32 offset, proto_tree *tree)
{
  guint16 object_len, contents_len;
  guint8 c_num, c_type;
  proto_item *ti;
  proto_tree *obj_tree;
  char *type_str;

  object_len = tvb_get_ntohs(tvb, offset);
  if (object_len < COPS_OBJECT_HDR_SIZE) {
    /* Bogus! */
    proto_tree_add_text(tree, tvb, offset, 2,
                        "Bad COPS object length: %u, should be at least %u",
                        object_len, COPS_OBJECT_HDR_SIZE);
    return -1;
  }
  c_num = tvb_get_guint8(tvb, offset + 2);
  c_type = tvb_get_guint8(tvb, offset + 3);

  ti = proto_tree_add_uint_format(tree, hf_cops_obj_c_num, tvb, offset, object_len, c_num,
                                  "%s: %s", val_to_str(c_num, cops_c_num_vals, "Unknown"),
                                  cops_c_type_to_str(c_num, c_type));
  obj_tree = proto_item_add_subtree(ti, ett_cops_obj);

  proto_tree_add_uint(obj_tree, hf_cops_obj_len, tvb, offset, 2, object_len);
  offset += 2;

  proto_tree_add_uint(obj_tree, hf_cops_obj_c_num, tvb, offset, 1, c_num);
  offset++;

  type_str = cops_c_type_to_str(c_num, c_type);
  proto_tree_add_text(obj_tree, tvb, offset, 1, "C-Type: %s%s%u%s",
                      type_str,
                      strlen(type_str) ? " (" : "",
                      c_type,
                      strlen(type_str) ? ")" : "");
  offset++;

  contents_len = object_len - COPS_OBJECT_HDR_SIZE;
  dissect_cops_object_data(tvb, offset, obj_tree, c_num, c_type, contents_len);

  /* Pad to 32bit boundary */
  if (object_len % sizeof (guint32))
    object_len += (sizeof (guint32) - object_len % sizeof (guint32));

  return object_len;
}

static void dissect_cops_pr_objects(tvbuff_t *tvb, guint32 offset, proto_tree *tree, guint16 pr_len)
{
  guint16 object_len, contents_len;
  guint8 s_num, s_type;
  char *type_str;
  int ret;
  proto_tree *cops_pr_tree, *obj_tree;
  proto_item *ti;

  cops_pr_tree = proto_item_add_subtree(tree, ett_cops_pr_obj);

  while (pr_len >= COPS_OBJECT_HDR_SIZE) {
    object_len = tvb_get_ntohs(tvb, offset);
    if (object_len < COPS_OBJECT_HDR_SIZE) {
      /* Bogus! */
      proto_tree_add_text(tree, tvb, offset, 2,
                          "Bad COPS PR object length: %u, should be at least %u",
                          object_len, COPS_OBJECT_HDR_SIZE);
      return;
    }
    s_num = tvb_get_guint8(tvb, offset + 2);

    ti = proto_tree_add_uint_format(cops_pr_tree, hf_cops_obj_s_num, tvb, offset, object_len, s_num,
                                    "%s", val_to_str(s_num, cops_s_num_vals, "Unknown"));
    obj_tree = proto_item_add_subtree(cops_pr_tree, ett_cops_pr_obj);

    proto_tree_add_uint(obj_tree, hf_cops_obj_len, tvb, offset, 2, object_len);
    offset += 2;
    pr_len -= 2;

    proto_tree_add_uint(obj_tree, hf_cops_obj_s_num, tvb, offset, 1, s_num);
    offset++;
    pr_len--;

    s_type = tvb_get_guint8(tvb, offset);
    type_str = val_to_str(s_type, cops_s_type_vals, "Unknown");
    proto_tree_add_text(obj_tree, tvb, offset, 1, "S-Type: %s%s%u%s",
                        type_str,
                        strlen(type_str) ? " (" : "",
                        s_type,
                        strlen(type_str) ? ")" : "");
    offset++;
    pr_len--;

    contents_len = object_len - COPS_OBJECT_HDR_SIZE;
    ret = dissect_cops_pr_object_data(tvb, offset, obj_tree, s_num, s_type, contents_len);
    if (ret < 0)
      break;

    /*Pad to 32bit boundary */
    if (object_len % sizeof (guint32))
      object_len += (sizeof (guint32) - object_len % sizeof (guint32));

    pr_len -= object_len - COPS_OBJECT_HDR_SIZE;
    offset += object_len - COPS_OBJECT_HDR_SIZE;
  }
}

static void dissect_cops_object_data(tvbuff_t *tvb, guint32 offset, proto_tree *tree,
                                     guint8 c_num, guint8 c_type, guint16 len)
{
  proto_item *ti;
  proto_tree *r_type_tree, *itf_tree, *reason_tree, *dec_tree, *error_tree, *clientsi_tree, *pdp_tree;
  guint16 r_type, m_type, reason, reason_sub, cmd_code, cmd_flags, error, error_sub, tcp_port;
  guint32 ipv4addr, ifindex;
  struct e_in6_addr ipv6addr;

  switch (c_num) {
  case COPS_OBJ_CONTEXT:
    r_type = tvb_get_ntohs(tvb, offset);
    m_type = tvb_get_ntohs(tvb, offset + 2);
    ti = proto_tree_add_text(tree, tvb, offset, 4, "Contents: R-Type: %s, M-Type: %u",
                             val_to_str(r_type, cops_r_type_vals, "Unknown"),
                             m_type);

    r_type_tree = proto_item_add_subtree(ti, ett_cops_r_type_flags);
    proto_tree_add_uint(r_type_tree, hf_cops_r_type_flags, tvb, offset, 2, r_type);
    offset += 2;
    proto_tree_add_uint(r_type_tree, hf_cops_m_type_flags, tvb, offset, 2, m_type);

    break;
  case COPS_OBJ_IN_INT:
  case COPS_OBJ_OUT_INT:
    if (c_type == 1) {          /* IPv4 */
      tvb_memcpy(tvb, (guint8 *)&ipv4addr, offset, 4);
      ifindex = tvb_get_ntohl(tvb, offset + 4);
      ti = proto_tree_add_text(tree, tvb, offset, 8, "Contents: IPv4 address %s, ifIndex: %u",
                               ip_to_str((guint8 *)&ipv4addr), ifindex);
      itf_tree = proto_item_add_subtree(ti, ett_cops_itf);
      proto_tree_add_ipv4(itf_tree,
                          (c_num == COPS_OBJ_IN_INT) ? hf_cops_in_int_ipv4 : hf_cops_out_int_ipv4,
                          tvb, offset, 4, ipv4addr);
      offset += 4;
    } else if (c_type == 2) {   /* IPv6 */
      tvb_memcpy(tvb, (guint8 *)&ipv6addr, offset, sizeof ipv6addr);
      ifindex = tvb_get_ntohl(tvb, offset + sizeof ipv6addr);
      ti = proto_tree_add_text(tree, tvb, offset, 20, "Contents: IPv6 address %s, ifIndex: %u",
                               ip6_to_str(&ipv6addr), ifindex);
      itf_tree = proto_item_add_subtree(ti, ett_cops_itf);
      proto_tree_add_ipv6(itf_tree,
                          (c_num == COPS_OBJ_IN_INT) ? hf_cops_in_int_ipv6 : hf_cops_out_int_ipv6,
                          tvb, offset, 16, (guint8 *)&ipv6addr);
      offset += 16;
    } else {
      break;
    }
    proto_tree_add_uint(itf_tree, hf_cops_int_ifindex, tvb, offset, 4, ifindex);

    break;
  case COPS_OBJ_REASON:
    reason = tvb_get_ntohs(tvb, offset);
    reason_sub = tvb_get_ntohs(tvb, offset + 2);
    ti = proto_tree_add_text(tree, tvb, offset, 4, "Contents: Reason-Code: %s, Reason Sub-code: 0x%04x",
                             val_to_str(reason, cops_reason_vals, "<Unknown value>"), reason_sub);
    reason_tree = proto_item_add_subtree(ti, ett_cops_reason);
    proto_tree_add_uint(reason_tree, hf_cops_reason, tvb, offset, 2, reason);
    offset += 2;
    if (reason == 13) {
      proto_tree_add_text(reason_tree, tvb, offset, 2, "Reason Sub-code: "
                          "Unknown object's C-Num %u, C-Type %u",
                          tvb_get_guint8(tvb, offset), tvb_get_guint8(tvb, offset + 1));
    } else
      proto_tree_add_uint(reason_tree, hf_cops_reason_sub, tvb, offset, 2, reason_sub);

    break;
  case COPS_OBJ_DECISION:
  case COPS_OBJ_LPDPDECISION:
    if (c_type == 1) {
      cmd_code = tvb_get_ntohs(tvb, offset);
      cmd_flags = tvb_get_ntohs(tvb, offset + 2);
      ti = proto_tree_add_text(tree, tvb, offset, 4, "Contents: Command-Code: %s, Flags: %s",
                               val_to_str(cmd_code, cops_dec_cmd_code_vals, "<Unknown value>"),
                               val_to_str(cmd_flags, cops_dec_cmd_flag_vals, "<Unknown flag>"));
      dec_tree = proto_item_add_subtree(ti, ett_cops_decision);
      proto_tree_add_uint(dec_tree, hf_cops_dec_cmd_code, tvb, offset, 2, cmd_code);
      offset += 2;
      proto_tree_add_uint(dec_tree, hf_cops_dec_flags, tvb, offset, 2, cmd_flags);
    } else if (c_type == 5) { /*COPS-PR Data*/
      ti = proto_tree_add_text(tree, tvb, offset, 4, "Contents: %u bytes", len);
      dec_tree = proto_item_add_subtree(ti, ett_cops_decision);
      dissect_cops_pr_objects(tvb, offset, dec_tree, len);
    }

    /* PacketCable : Analyze the remaining data if available */
    cops_analyze_packetcable_obj(tvb, tree, offset);

    break;
  case COPS_OBJ_ERROR:
    if (c_type != 1)
      break;

    error = tvb_get_ntohs(tvb, offset);
    error_sub = tvb_get_ntohs(tvb, offset + 2);
    ti = proto_tree_add_text(tree, tvb, offset, 4, "Contents: Error-Code: %s, Error Sub-code: 0x%04x",
                             val_to_str(error, cops_error_vals, "<Unknown value>"), error_sub);
    error_tree = proto_item_add_subtree(ti, ett_cops_error);
    proto_tree_add_uint(error_tree, hf_cops_error, tvb, offset, 2, error);
    offset += 2;
    if (error == 13) {
      proto_tree_add_text(error_tree, tvb, offset, 2, "Error Sub-code: "
                          "Unknown object's C-Num %u, C-Type %u",
                          tvb_get_guint8(tvb, offset), tvb_get_guint8(tvb, offset + 1));
    } else
      proto_tree_add_uint(error_tree, hf_cops_error_sub, tvb, offset, 2, error_sub);

    break;
  case COPS_OBJ_CLIENTSI:

    /* For PacketCable */
    if (c_type == 1) {
       cops_analyze_packetcable_obj(tvb, tree, offset);
       break;
    }

    if (c_type != 2) /*Not COPS-PR data*/
      break;

    ti = proto_tree_add_text(tree, tvb, offset, 4, "Contents: %u bytes", len);
    clientsi_tree = proto_item_add_subtree(ti, ett_cops_clientsi);

    dissect_cops_pr_objects(tvb, offset, clientsi_tree, len);

    break;
  case COPS_OBJ_KATIMER:
    if (c_type != 1)
      break;

    proto_tree_add_item(tree, hf_cops_katimer, tvb, offset + 2, 2, FALSE);
    if (tvb_get_ntohs(tvb, offset + 2) == 0)
      proto_tree_add_text(tree, tvb, offset, 0, "Value of zero implies infinity.");

    break;
  case COPS_OBJ_PEPID:
    if (c_type != 1)
      break;

    if (tvb_strnlen(tvb, offset, len) == -1)
      proto_tree_add_text(tree, tvb, offset, len, "<PEP Id is not a NUL terminated ASCII string>");
    else
      proto_tree_add_item(tree, hf_cops_pepid, tvb, offset,
                          tvb_strnlen(tvb, offset, len) + 1, FALSE);

    break;
  case COPS_OBJ_REPORT_TYPE:
    if (c_type != 1)
      break;

    proto_tree_add_item(tree, hf_cops_report_type, tvb, offset, 2, FALSE);

    break;
  case COPS_OBJ_PDPREDIRADDR:
  case COPS_OBJ_LASTPDPADDR:
    if (c_type == 1) {          /* IPv4 */
      tvb_memcpy(tvb, (guint8 *)&ipv4addr, offset, 4);
      tcp_port = tvb_get_ntohs(tvb, offset + 4 + 2);
      ti = proto_tree_add_text(tree, tvb, offset, 8, "Contents: IPv4 address %s, TCP Port Number: %u",
                               ip_to_str((guint8 *)&ipv4addr), tcp_port);
      pdp_tree = proto_item_add_subtree(ti, ett_cops_pdp);
      proto_tree_add_ipv4(pdp_tree,
                          (c_num == COPS_OBJ_PDPREDIRADDR) ? hf_cops_pdprediraddr_ipv4 : hf_cops_lastpdpaddr_ipv4,
                          tvb, offset, 4, ipv4addr);
      offset += 4;
    } else if (c_type == 2) {   /* IPv6 */
      tvb_memcpy(tvb, (guint8 *)&ipv6addr, offset, sizeof ipv6addr);
      tcp_port = tvb_get_ntohs(tvb, offset + sizeof ipv6addr + 2);
      ti = proto_tree_add_text(tree, tvb, offset, 20, "Contents: IPv6 address %s, TCP Port Number: %u",
                               ip6_to_str(&ipv6addr), tcp_port);
      pdp_tree = proto_item_add_subtree(ti, ett_cops_pdp);
      proto_tree_add_ipv6(pdp_tree,
                          (c_num == COPS_OBJ_PDPREDIRADDR) ? hf_cops_pdprediraddr_ipv6 : hf_cops_lastpdpaddr_ipv6,
                          tvb, offset, 16, (guint8 *)&ipv6addr);
      offset += 16;
    } else {
      break;
    }
    offset += 2;
    proto_tree_add_uint(pdp_tree, hf_cops_pdp_tcp_port, tvb, offset, 2, tcp_port);

    break;
  case COPS_OBJ_ACCTTIMER:
    if (c_type != 1)
      break;

    proto_tree_add_item(tree, hf_cops_accttimer, tvb, offset + 2, 2, FALSE);
    if (tvb_get_ntohs(tvb, offset + 2) == 0)
      proto_tree_add_text(tree, tvb, offset, 0, "Value of zero means "
                          "there SHOULD be no unsolicited accounting updates.");

    break;
  case COPS_OBJ_INTEGRITY:
    if (c_type != 1)
      break;      /* Not HMAC digest */

    proto_tree_add_item(tree, hf_cops_key_id, tvb, offset, 4, FALSE);
    proto_tree_add_item(tree, hf_cops_seq_num, tvb, offset + 4, 4, FALSE);
    proto_tree_add_text(tree, tvb, offset + 8 , len - 8, "Contents: Keyed Message Digest");

    break;
  default:
    proto_tree_add_text(tree, tvb, offset, len, "Contents: %u bytes", len);

    break;
  }
}

#ifdef HAVE_NET_SNMP
static guchar*format_asn_value (struct variable_list *variable, subid_t *variable_oid,
                                guint variable_oid_length, u_char type_from_packet)
{
  struct tree *subtree=tree_head;

  guchar *buf=NULL;
  size_t buf_len=0;
  size_t out_len=0;

  /*Get the ASN.1 type etc. from the PIB-MIB. If unsuccessful use the type from packet*/
  subtree = get_tree(variable_oid,variable_oid_length, subtree);

  if (subtree->type == 0)
    variable->type= type_from_packet;

  buf_len = SPRINT_MAX_LEN; /*defined in NET-SNMP's snmp-impl.h*/
  buf = g_malloc(buf_len);
  *buf = '\0';
  out_len = 0;

  /*If the ASN.1 type was found from PIB-MIB, use it for decoding*/
  if (!variable->type)
    variable->type=mib_to_asn_type(subtree->type);

  if (!sprint_realloc_by_type(&buf, &buf_len, &out_len, TRUE, variable, subtree->enums, subtree->hint, NULL))
    sprintf(buf,"%s","sprint_realloc_by_type failed");

  return buf;
}
#endif	/* HAVE_NET_SNMP */

static int decode_cops_pr_asn1_data(tvbuff_t *tvb, guint32 offset,
    proto_tree *tree, guint asnlen, guint8 cops_pr_obj
#ifndef HAVE_NET_SNMP
						  _U_
#endif
    )
{
  ASN1_SCK asn1;
  int start;
  gboolean def;
  guint length;

  guint vb_length;
  gushort vb_type;
  gchar *vb_type_name;

  int ret;
  guint cls, con, tag;
  subid_t epd_attribute_index=0;

  gint32 vb_integer_value;
  guint32 vb_uinteger_value;

  guint8 *vb_octet_string;

  subid_t *vb_oid;
  guint vb_oid_length;

  gchar *vb_display_string;
  gchar *vb_display_string2;

#ifdef HAVE_NET_SNMP
  struct variable_list variable;
  long value;
#endif	/* HAVE_NET_SNMP */

  unsigned int i;
  gchar *buf;
  int len;

  while (asnlen > 0) { /*while there is ASN stuff to be decoded*/

    epd_attribute_index++;
#ifdef HAVE_NET_SNMP
    last_decoded_prid_oid[last_decoded_prid_oid_length-1]=epd_attribute_index;
#endif	/* HAVE_NET_SNMP */
    asn1_open(&asn1, tvb, offset);

    /* parse the type of the object */

    start = asn1.offset;

    ret = asn1_header_decode (&asn1, &cls, &con, &tag, &def, &vb_length);
    if (ret != ASN1_ERR_NOERROR)
      return 0;
    if (!def)
      return ASN1_ERR_LENGTH_NOT_DEFINITE;

    /* Convert the class, constructed flag, and tag to a type. */
    vb_type_name = cops_tag_cls2syntax(tag, cls, &vb_type);
    if (vb_type_name == NULL) {
      /*
       * Unsupported type.
       * Dissect the value as an opaque string of octets.
       */
      vb_type_name = "unsupported type";
      vb_type = COPS_OPAQUE;
    }

    /* parse the value */

    switch (vb_type) {

    case COPS_INTEGER:
      ret = asn1_int32_value_decode(&asn1, vb_length, &vb_integer_value);
      if (ret != ASN1_ERR_NOERROR)
        return ret;
      length = asn1.offset - start;
      if (tree) {
#ifdef HAVE_NET_SNMP
        if (cops_typefrommib == TRUE)
        {
          variable.type = 0;
          value = vb_integer_value;
          variable.val.integer = &value;
          variable.val_len = vb_length ;
          vb_display_string=format_asn_value(&variable,
                                             last_decoded_prid_oid,last_decoded_prid_oid_length,ASN_INTEGER);

          proto_tree_add_text(tree, asn1.tvb, offset, length,
                              "Value: %s", vb_display_string);
          g_free(vb_display_string);
        }
        else
#endif /* HAVE_NET_SNMP */
          proto_tree_add_text(tree, asn1.tvb, offset, length,
                              "Value: %s: %d (%#x)", vb_type_name,
                              vb_integer_value, vb_integer_value);
      }
      break;

    case COPS_UNSIGNED32:
    case COPS_TIMETICKS:
      ret = asn1_uint32_value_decode(&asn1, vb_length, &vb_uinteger_value);
      if (ret != ASN1_ERR_NOERROR)
        return ret;
      length = asn1.offset - start;
      if (tree) {
#ifdef HAVE_NET_SNMP
        if (cops_typefrommib == TRUE)
        {
          variable.type = 0;
          value = vb_uinteger_value;
          variable.val.integer = &value;
          variable.val_len = vb_length;

          vb_display_string=format_asn_value(&variable,
                                             last_decoded_prid_oid,last_decoded_prid_oid_length,ASN_UINTEGER);

          proto_tree_add_text(tree, asn1.tvb, offset, length, "Value %s: %s",vb_type_name, vb_display_string);

          g_free(vb_display_string);
        }
        else
#endif /* HAVE_NET_SNMP */
          proto_tree_add_text(tree, asn1.tvb, offset, length,
                              "Value: %s: %u (%#x)", vb_type_name,
                              vb_uinteger_value, vb_uinteger_value);
      }
      break;

    case COPS_OCTETSTR:
    case COPS_IPADDR:
    case COPS_OPAQUE:
    case COPS_UNSIGNED64:
    case COPS_INTEGER64:
      ret = asn1_string_value_decode (&asn1, vb_length, &vb_octet_string);
      if (ret != ASN1_ERR_NOERROR)
        return ret;
      length = asn1.offset - start;
      if (tree) {
#ifdef HAVE_NET_SNMP
        if (cops_typefrommib == TRUE)
        {
          variable.type = 0;
          variable.val.string = vb_octet_string;
          variable.val_len = vb_length;
          vb_display_string = format_asn_value(&variable,
                                               last_decoded_prid_oid,last_decoded_prid_oid_length,ASN_OCTET_STR);
          proto_tree_add_text(tree, asn1.tvb, offset, length,
                              "Value: %s (ASN.1 type from packet: %s)", vb_display_string, vb_type_name);

          g_free(vb_display_string);
        }
        else
        {
#endif /* HAVE_NET_SNMP */
          for (i = 0; i < vb_length; i++) {
            if (!(isprint(vb_octet_string[i]) ||isspace(vb_octet_string[i])))
              break;
          }

          /*
           * If some characters are not printable, display the string as bytes.
           */
          if (i < vb_length) {
            /*
             * We stopped, due to a non-printable character, before we got
             * to the end of the string.
             */
            vb_display_string = g_malloc(4*vb_length);
            buf = &vb_display_string[0];
            len = sprintf(buf, "%03u", vb_octet_string[0]);
            buf += len;
            for (i = 1; i < vb_length; i++) {
              len = sprintf(buf, ".%03u", vb_octet_string[i]);
              buf += len;
            }
            proto_tree_add_text(tree, asn1.tvb, offset, length,
                                "Value: %s: %s", vb_type_name, vb_display_string);
            g_free(vb_display_string);
          } else {
            proto_tree_add_text(tree, asn1.tvb, offset, length,
                                "Value: %s: %.*s", vb_type_name, (int)vb_length,
                                SAFE_STRING(vb_octet_string));
          }
#ifdef HAVE_NET_SNMP
        }
#endif /* HAVE_NET_SNMP */
      }
      g_free(vb_octet_string);
      break;

    case COPS_NULL:
      ret = asn1_null_decode (&asn1, vb_length);
      if (ret != ASN1_ERR_NOERROR)
        return ret;
      length = asn1.offset - start;
      if (tree)
        proto_tree_add_text(tree, asn1.tvb, offset, length, "Value: %s", vb_type_name);
      break;

    case COPS_OBJECTID:
      ret = asn1_oid_value_decode (&asn1, vb_length, &vb_oid, &vb_oid_length);
      if (ret != ASN1_ERR_NOERROR)
        return ret;
      length = asn1.offset - start;

      if (tree) {
	if (cops_pr_obj == COPS_OBJ_PPRID){
	  /*we're decoding Prefix PRID, that doesn't have a instance Id,
	   *Use full length of the OID when decoding it.
	   */
	  new_format_oid(vb_oid,vb_oid_length,&vb_display_string,&vb_display_string2);

	  if (!vb_display_string2)   /*if OID couldn't be decoded, print only numeric format*/
	    proto_tree_add_text(tree, asn1.tvb, offset, length,
				"Value: %s: %s", vb_type_name, vb_display_string);
	  else
	    proto_tree_add_text(tree, asn1.tvb, offset, length,
				"Value: %s: %s (%s)", vb_type_name,
				vb_display_string,
				vb_display_string2);
	}
	else { /*we're decoding PRID, Error PRID or EPD*/
	  /*strip the instance Id from the OIDs before decoding and paste it back during printing*/
	  new_format_oid(vb_oid,vb_oid_length-1,&vb_display_string,&vb_display_string2);

	  if (!vb_display_string2)  /*if OID couldn't be decoded, print only numeric format*/
	    proto_tree_add_text(tree, asn1.tvb, offset, length,
				"Value: %s: %s.%lu", vb_type_name,
				vb_display_string,
				(unsigned long)vb_oid[vb_oid_length-1]);
	  else
	    proto_tree_add_text(tree, asn1.tvb, offset, length,
				"Value: %s: %s.%lu (%s.%lu)", vb_type_name,
				vb_display_string,
				(unsigned long)vb_oid[vb_oid_length-1],
				vb_display_string2,
				(unsigned long)vb_oid[vb_oid_length-1]);
	}
#ifdef HAVE_NET_SNMP
        if (cops_pr_obj != COPS_OBJ_EPD) {
          /* we're not decoding EPD, so let's store the OID of the PRID so that later
             when we're decoding this PRID's EPD we can finetune the output.*/
          memcpy(last_decoded_prid_oid,vb_oid,vb_oid_length*sizeof(subid_t));
          last_decoded_prid_oid_length=vb_oid_length;
        }
#endif /* HAVE_NET_SNMP */

      g_free(vb_display_string);
      if(vb_display_string2)
        g_free(vb_display_string2);
      }
      g_free(vb_oid);
      break;

    default:
      g_assert_not_reached();
      return ASN1_ERR_WRONG_TYPE;
    }

    asn1_close(&asn1,&offset);

    asnlen -= length;
  }
  epd_attribute_index=0;
  return 0;
}

static int dissect_cops_pr_object_data(tvbuff_t *tvb, guint32 offset, proto_tree *tree,
                                       guint8 s_num, guint8 s_type, guint16 len)
{
  proto_item *ti;
  proto_tree *asn1_object_tree, *gperror_tree, *cperror_tree;
  guint16 gperror=0, gperror_sub=0, cperror=0, cperror_sub=0;

  switch (s_num){
  case COPS_OBJ_PRID:
   if (s_type != 1) /* Not Provisioning Instance Identifier (PRID) */
      break;

    ti=proto_tree_add_text(tree, tvb, offset, len, "Contents:");
    asn1_object_tree = proto_item_add_subtree(ti, ett_cops_asn1);

    decode_cops_pr_asn1_data(tvb, offset, asn1_object_tree, len, COPS_OBJ_PRID);

    break;
  case COPS_OBJ_PPRID:
    if (s_type != 1) /* Not Prefix Provisioning Instance Identifier (PPRID) */
      break;

    ti = proto_tree_add_text(tree, tvb, offset, len, "Contents:");
    asn1_object_tree = proto_item_add_subtree(ti, ett_cops_asn1);

    decode_cops_pr_asn1_data(tvb, offset, asn1_object_tree, len, COPS_OBJ_PPRID);

    break;
  case COPS_OBJ_EPD:
    if (s_type != 1) /* Not  Encoded Provisioning Instance Data (EPD) */
      break;

    ti = proto_tree_add_text(tree, tvb, offset, len, "Contents:");
    asn1_object_tree = proto_item_add_subtree(ti, ett_cops_asn1);

    decode_cops_pr_asn1_data(tvb, offset, asn1_object_tree, len, COPS_OBJ_EPD);

    break;
  case COPS_OBJ_GPERR:
    if (s_type != 1) /* Not Global Provisioning Error Object (GPERR) */
      break;

    gperror = tvb_get_ntohs(tvb, offset);
    gperror_sub = tvb_get_ntohs(tvb, offset + 2);
    ti = proto_tree_add_text(tree, tvb, offset, 4, "Contents: Error-Code: %s, Error Sub-code: 0x%04x",
                       val_to_str(gperror, cops_gperror_vals, "<Unknown value>"), gperror_sub);
    gperror_tree = proto_item_add_subtree(ti, ett_cops_gperror);
    proto_tree_add_uint(gperror_tree, hf_cops_gperror, tvb, offset, 2, gperror);
    offset += 2;
    if (cperror == 13) {
      proto_tree_add_text(gperror_tree, tvb, offset, 2, "Error Sub-code: "
                          "Unknown object's C-Num %u, C-Type %u",
                          tvb_get_guint8(tvb, offset), tvb_get_guint8(tvb, offset + 1));
    } else
      proto_tree_add_uint(gperror_tree, hf_cops_gperror_sub, tvb, offset, 2, gperror_sub);

    break;
  case COPS_OBJ_CPERR:
    if (s_type != 1) /*Not PRC Class Provisioning Error Object (CPERR) */
      break;

    break;

    cperror = tvb_get_ntohs(tvb, offset);
    cperror_sub = tvb_get_ntohs(tvb, offset + 2);
    ti = proto_tree_add_text(tree, tvb, offset, 4, "Contents: Error-Code: %s, Error Sub-code: 0x%04x",
                       val_to_str(cperror, cops_cperror_vals, "<Unknown value>"), cperror_sub);
    cperror_tree = proto_item_add_subtree(ti, ett_cops_cperror);
    proto_tree_add_uint(cperror_tree, hf_cops_cperror, tvb, offset, 2, cperror);
    offset += 2;
    if (cperror == 13) {
      proto_tree_add_text(cperror_tree, tvb, offset, 2, "Error Sub-code: "
                          "Unknown object's S-Num %u, C-Type %u",
                          tvb_get_guint8(tvb, offset), tvb_get_guint8(tvb, offset + 1));
    } else
      proto_tree_add_uint(cperror_tree, hf_cops_cperror_sub, tvb, offset, 2, cperror_sub);

    break;
  case COPS_OBJ_ERRPRID:
    if (s_type != 1) /*Not  Error Provisioning Instance Identifier (ErrorPRID)*/
      break;

    ti = proto_tree_add_text(tree, tvb, offset, len, "Contents:");
    asn1_object_tree = proto_item_add_subtree(ti, ett_cops_asn1);

    decode_cops_pr_asn1_data(tvb, offset, asn1_object_tree, len, COPS_OBJ_ERRPRID);

    break;
  default:
    proto_tree_add_text(tree, tvb, offset, len, "Contents: %u bytes", len);
    break;
  }

  return 0;
}


/* Register the protocol with Ethereal */
void proto_register_cops(void)
{
  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_cops_ver_flags,
      { "Version and Flags",           "cops.ver_flags",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "Version and Flags in COPS Common Header", HFILL }
    },
    { &hf_cops_version,
      { "Version",           "cops.version",
      FT_UINT8, BASE_DEC, NULL, 0xF0,
      "Version in COPS Common Header", HFILL }
    },
    { &hf_cops_flags,
      { "Flags",           "cops.flags",
      FT_UINT8, BASE_HEX, VALS(cops_flags_vals), 0x0F,
      "Flags in COPS Common Header", HFILL }
    },
    { &hf_cops_op_code,
      { "Op Code",           "cops.op_code",
      FT_UINT8, BASE_DEC, VALS(cops_op_code_vals), 0x0,
      "Op Code in COPS Common Header", HFILL }
    },
    { &hf_cops_client_type,
      { "Client Type",           "cops.client_type",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Client Type in COPS Common Header", HFILL }
    },
    { &hf_cops_msg_len,
      { "Message Length",           "cops.msg_len",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Message Length in COPS Common Header", HFILL }
    },
    { &hf_cops_obj_len,
      { "Object Length",           "cops.obj.len",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Object Length in COPS Object Header", HFILL }
    },
    { &hf_cops_obj_c_num,
      { "C-Num",           "cops.c_num",
      FT_UINT8, BASE_DEC, VALS(cops_c_num_vals), 0x0,
      "C-Num in COPS Object Header", HFILL }
    },
    { &hf_cops_obj_c_type,
      { "C-Type",           "cops.c_type",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "C-Type in COPS Object Header", HFILL }
    },

    { &hf_cops_obj_s_num,
      { "S-Num",           "cops.s_num",
      FT_UINT8, BASE_DEC, VALS(cops_s_num_vals), 0x0,
      "S-Num in COPS-PR Object Header", HFILL }
    },
    { &hf_cops_obj_s_type,
      { "S-Type",           "cops.s_type",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "S-Type in COPS-PR Object Header", HFILL }
    },

    { &hf_cops_r_type_flags,
      { "R-Type",           "cops.context.r_type",
      FT_UINT16, BASE_HEX, VALS(cops_r_type_vals), 0xFFFF,
      "R-Type in COPS Context Object", HFILL }
    },
    { &hf_cops_m_type_flags,
      { "M-Type",           "cops.context.m_type",
      FT_UINT16, BASE_HEX, NULL, 0xFFFF,
      "M-Type in COPS Context Object", HFILL }
    },
    { &hf_cops_in_int_ipv4,
      { "IPv4 address",           "cops.in-int.ipv4",
      FT_IPv4, 0, NULL, 0xFFFF,
      "IPv4 address in COPS IN-Int object", HFILL }
    },
    { &hf_cops_in_int_ipv6,
      { "IPv6 address",           "cops.in-int.ipv6",
      FT_IPv6, 0, NULL, 0xFFFF,
      "IPv6 address in COPS IN-Int object", HFILL }
    },
    { &hf_cops_out_int_ipv4,
      { "IPv4 address",           "cops.out-int.ipv4",
      FT_IPv4, 0, NULL, 0xFFFF,
      "IPv4 address in COPS OUT-Int object", HFILL }
    },
    { &hf_cops_out_int_ipv6,
      { "IPv6 address",           "cops.out-int.ipv6",
      FT_IPv6, 0, NULL, 0xFFFF,
      "IPv6 address in COPS OUT-Int", HFILL }
    },
    { &hf_cops_int_ifindex,
      { "ifIndex",           "cops.in-out-int.ifindex",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "If SNMP is supported, corresponds to MIB-II ifIndex", HFILL }
    },
    { &hf_cops_reason,
      { "Reason",           "cops.reason",
      FT_UINT16, BASE_DEC, VALS(cops_reason_vals), 0,
      "Reason in Reason object", HFILL }
    },
    { &hf_cops_reason_sub,
      { "Reason Sub-code",           "cops.reason_sub",
      FT_UINT16, BASE_HEX, NULL, 0,
      "Reason Sub-code in Reason object", HFILL }
    },
    { &hf_cops_dec_cmd_code,
      { "Command-Code",           "cops.decision.cmd",
      FT_UINT16, BASE_DEC, VALS(cops_dec_cmd_code_vals), 0,
      "Command-Code in Decision/LPDP Decision object", HFILL }
    },
    { &hf_cops_dec_flags,
      { "Flags",           "cops.decision.flags",
      FT_UINT16, BASE_HEX, VALS(cops_dec_cmd_flag_vals), 0xffff,
      "Flags in Decision/LPDP Decision object", HFILL }
    },
    { &hf_cops_error,
      { "Error",           "cops.error",
      FT_UINT16, BASE_DEC, VALS(cops_error_vals), 0,
      "Error in Error object", HFILL }
    },
    { &hf_cops_error_sub,
      { "Error Sub-code",           "cops.error_sub",
      FT_UINT16, BASE_HEX, NULL, 0,
      "Error Sub-code in Error object", HFILL }
    },
    { &hf_cops_katimer,
      { "Contents: KA Timer Value",           "cops.katimer.value",
      FT_UINT16, BASE_DEC, NULL, 0,
      "Keep-Alive Timer Value in KATimer object", HFILL }
    },
    { &hf_cops_pepid,
      { "Contents: PEP Id",           "cops.pepid.id",
      FT_STRING, BASE_NONE, NULL, 0,
      "PEP Id in PEPID object", HFILL }
    },
    { &hf_cops_report_type,
      { "Contents: Report-Type",           "cops.report_type",
      FT_UINT16, BASE_DEC, VALS(cops_report_type_vals), 0,
      "Report-Type in Report-Type object", HFILL }
    },
    { &hf_cops_pdprediraddr_ipv4,
      { "IPv4 address",           "cops.pdprediraddr.ipv4",
      FT_IPv4, 0, NULL, 0xFFFF,
      "IPv4 address in COPS PDPRedirAddr object", HFILL }
    },
    { &hf_cops_pdprediraddr_ipv6,
      { "IPv6 address",           "cops.pdprediraddr.ipv6",
      FT_IPv6, 0, NULL, 0xFFFF,
      "IPv6 address in COPS PDPRedirAddr object", HFILL }
    },
    { &hf_cops_lastpdpaddr_ipv4,
      { "IPv4 address",           "cops.lastpdpaddr.ipv4",
      FT_IPv4, 0, NULL, 0xFFFF,
      "IPv4 address in COPS LastPDPAddr object", HFILL }
    },
    { &hf_cops_lastpdpaddr_ipv6,
      { "IPv6 address",           "cops.lastpdpaddr.ipv6",
      FT_IPv6, 0, NULL, 0xFFFF,
      "IPv6 address in COPS LastPDPAddr object", HFILL }
    },
    { &hf_cops_pdp_tcp_port,
      { "TCP Port Number",           "cops.pdp.tcp_port",
      FT_UINT32, BASE_DEC, NULL, 0x0,
       "TCP Port Number of PDP in PDPRedirAddr/LastPDPAddr object", HFILL }
    },
    { &hf_cops_accttimer,
      { "Contents: ACCT Timer Value",           "cops.accttimer.value",
      FT_UINT16, BASE_DEC, NULL, 0,
      "Accounting Timer Value in AcctTimer object", HFILL }
    },
    { &hf_cops_key_id,
      { "Contents: Key ID",           "cops.integrity.key_id",
      FT_UINT32, BASE_DEC, NULL, 0,
      "Key ID in Integrity object", HFILL }
    },
    { &hf_cops_seq_num,
      { "Contents: Sequence Number",           "cops.integrity.seq_num",
      FT_UINT32, BASE_DEC, NULL, 0,
      "Sequence Number in Integrity object", HFILL }
    },
    { &hf_cops_gperror,
      { "Error",           "cops.gperror",
      FT_UINT16, BASE_DEC, VALS(cops_gperror_vals), 0,
      "Error in Error object", HFILL }
    },
    { &hf_cops_gperror_sub,
      { "Error Sub-code",           "cops.gperror_sub",
      FT_UINT16, BASE_HEX, NULL, 0,
      "Error Sub-code in Error object", HFILL }
    },
    { &hf_cops_cperror,
      { "Error",           "cops.cperror",
      FT_UINT16, BASE_DEC, VALS(cops_cperror_vals), 0,
      "Error in Error object", HFILL }
    },
    { &hf_cops_cperror_sub,
      { "Error Sub-code",           "cops.cperror_sub",
      FT_UINT16, BASE_HEX, NULL, 0,
      "Error Sub-code in Error object", HFILL }
    },

    /* Added for PacketCable */

    { &hf_cops_subtree,
      { "Object Subtree", "cops.pc_subtree",
        FT_UINT16, BASE_HEX, NULL, 0,
        "Object Subtree", HFILL }
    },
    { &hf_cops_pc_ds_field,
      { "DS Field (DSCP or TOS)", "cops.pc_ds_field",
        FT_UINT8, BASE_HEX, NULL, 0x00,
        "DS Field (DSCP or TOS)", HFILL }
    },
    { &hf_cops_pc_direction,
      { "Direction", "cops.pc_direction",
        FT_UINT8, BASE_HEX, NULL, 0x00,
        "Direction", HFILL }
    },
    { &hf_cops_pc_gate_spec_flags,
      { "Flags", "cops.pc_gate_spec_flags",
        FT_UINT8, BASE_HEX, NULL, 0x00,
        "Flags", HFILL }
    },
    { &hf_cops_pc_protocol_id,
      { "Protocol ID", "cops.pc_protocol_id",
        FT_UINT8, BASE_HEX, NULL, 0x00,
        "Protocol ID", HFILL }
    },
    { &hf_cops_pc_session_class,
      { "Session Class", "cops.pc_session_class",
        FT_UINT8, BASE_HEX, NULL, 0x00,
        "Session Class", HFILL }
    },
    { &hf_cops_pc_algorithm,
      { "Algorithm", "cops.pc_algorithm",
        FT_UINT16, BASE_HEX, NULL, 0x00,
        "Algorithm", HFILL }
    },
    { &hf_cops_pc_cmts_ip_port,
      { "CMTS IP Port", "cops.pc_cmts_ip_port",
        FT_UINT16, BASE_HEX, NULL, 0x00,
        "CMTS IP Port", HFILL }
    },
    { &hf_cops_pc_prks_ip_port,
      { "PRKS IP Port", "cops.pc_prks_ip_port",
        FT_UINT16, BASE_HEX, NULL, 0x00,
        "PRKS IP Port", HFILL }
    },
    { &hf_cops_pc_srks_ip_port,
      { "SRKS IP Port", "cops.pc_srks_ip_port",
        FT_UINT16, BASE_HEX, NULL, 0x00,
        "SRKS IP Port", HFILL }
    },
    { &hf_cops_pc_dest_port,
      { "Destination IP Port", "cops.pc_dest_port",
        FT_UINT16, BASE_HEX, NULL, 0x00,
        "Destination IP Port", HFILL }
    },
    { &hf_cops_pc_packetcable_err_code,
      { "Error Code", "cops.pc_packetcable_err_code",
        FT_UINT16, BASE_HEX, NULL, 0x00,
        "Error Code", HFILL }
    },
    { &hf_cops_pc_packetcable_sub_code,
      { "Error Sub Code", "cops.pc_packetcable_sub_code",
        FT_UINT16, BASE_HEX, NULL, 0x00,
        "Error Sub Code", HFILL }
    },
    { &hf_cops_pc_remote_flags,
      { "Flags", "cops.pc_remote_flags",
        FT_UINT16, BASE_HEX, NULL, 0x00,
        "Flags", HFILL }
    },
    { &hf_cops_pc_close_subcode,
      { "Reason Sub Code", "cops.pc_close_subcode",
        FT_UINT16, BASE_HEX, NULL, 0x00,
        "Reason Sub Code", HFILL }
    },
    { &hf_cops_pc_gate_command_type,
      { "Gate Command Type", "cops.pc_gate_command_type",
        FT_UINT16, BASE_HEX, NULL, 0x00,
        "Gate Command Type", HFILL }
    },
    { &hf_cops_pc_reason_code,
      { "Reason Code", "cops.pc_reason_code",
        FT_UINT16, BASE_HEX, NULL, 0x00,
        "Reason Code", HFILL }
    },
    { &hf_cops_pc_delete_subcode,
      { "Reason Sub Code", "cops.pc_delete_subcode",
        FT_UINT16, BASE_HEX, NULL, 0x00,
        "Reason Sub Code", HFILL }
    },
    { &hf_cops_pc_src_port,
      { "Source IP Port", "cops.pc_src_port",
        FT_UINT16, BASE_HEX, NULL, 0x00,
        "Source IP Port", HFILL }
    },
    { &hf_cops_pc_t1_value,
      { "Timer T1 Value (sec)", "cops.pc_t1_value",
        FT_UINT16, BASE_HEX, NULL, 0x00,
        "Timer T1 Value (sec)", HFILL }
    },
    { &hf_cops_pc_t7_value,
      { "Timer T7 Value (sec)", "cops.pc_t7_value",
        FT_UINT16, BASE_HEX, NULL, 0x00,
        "Timer T7 Value (sec)", HFILL }
    },
    { &hf_cops_pc_t8_value,
      { "Timer T8 Value (sec)", "cops.pc_t8_value",
        FT_UINT16, BASE_HEX, NULL, 0x00,
        "Timer T8 Value (sec)", HFILL }
    },
    { &hf_cops_pc_transaction_id,
      { "Transaction Identifier", "cops.pc_transaction_id",
        FT_UINT16, BASE_HEX, NULL, 0x00,
        "Transaction Identifier", HFILL }
    },
    { &hf_cops_pc_cmts_ip,
      { "CMTS IP Address", "cops.pc_cmts_ip",
        FT_UINT32, BASE_HEX, NULL, 0x00,
        "CMTS IP Address", HFILL }
    },
    { &hf_cops_pc_prks_ip,
      { "PRKS IP Address", "cops.pc_prks_ip",
        FT_UINT32, BASE_HEX, NULL, 0x00,
        "PRKS IP Address", HFILL }
    },
    { &hf_cops_pc_srks_ip,
      { "SRKS IP Address", "cops.pc_srks_ip",
        FT_UINT32, BASE_HEX, NULL, 0x00,
        "SRKS IP Address", HFILL }
    },
    { &hf_cops_pc_dfcdc_ip,
      { "DF IP Address CDC", "cops.pc_dfcdc_ip",
        FT_UINT32, BASE_HEX, NULL, 0x00,
        "DF IP Address CDC", HFILL }
    },
    { &hf_cops_pc_dfccc_ip,
      { "DF IP Address CCC", "cops.pc_dfccc_ip",
        FT_UINT32, BASE_HEX, NULL, 0x00,
        "DF IP Address CCC", HFILL }
    },
    { &hf_cops_pc_dfcdc_ip_port,
      { "DF IP Port CDC", "cops.pc_dfcdc_ip_port",
        FT_UINT16, BASE_HEX, NULL, 0x00,
        "DF IP Port CDC", HFILL }
    },
    { &hf_cops_pc_dfccc_ip_port,
      { "DF IP Port CCC", "cops.pc_dfccc_ip_port",
        FT_UINT16, BASE_HEX, NULL, 0x00,
        "DF IP Port CCC", HFILL }
    },
    { &hf_cops_pc_activity_count,
      { "Count", "cops.pc_activity_count",
        FT_UINT32, BASE_HEX, NULL, 0x00,
        "Count", HFILL }
    },
    { &hf_cops_pc_dest_ip,
      { "Destination IP Address", "cops.pc_dest_ip",
        FT_UINT32, BASE_HEX, NULL, 0x00,
        "Destination IP Address", HFILL }
    },
    { &hf_cops_pc_gate_id,
      { "Gate Identifier", "cops.pc_gate_id",
        FT_UINT32, BASE_HEX, NULL, 0x00,
        "Gate Identifier", HFILL }
    },
    { &hf_cops_pc_max_packet_size,
      { "Maximum Packet Size", "cops.pc_max_packet_size",
        FT_UINT32, BASE_HEX, NULL, 0x00,
        "Maximum Packet Size", HFILL }
    },
    { &hf_cops_pc_min_policed_unit,
      { "Minimum Policed Unit", "cops.pc_min_policed_unit",
        FT_UINT32, BASE_HEX, NULL, 0x00,
        "Minimum Policed Unit", HFILL }
    },
    { &hf_cops_pc_peak_data_rate,
      { "Peak Data Rate", "cops.pc_peak_data_rate",
        FT_FLOAT, BASE_NONE, NULL, 0x00,
        "Peak Data Rate", HFILL }
    },
    { &hf_cops_pc_spec_rate,
      { "Rate", "cops.pc_spec_rate",
        FT_FLOAT, BASE_NONE, NULL, 0x00,
        "Rate", HFILL }
    },
    { &hf_cops_pc_remote_gate_id,
      { "Remote Gate ID", "cops.pc_remote_gate_id",
        FT_UINT32, BASE_HEX, NULL, 0x00,
        "Remote Gate ID", HFILL }
    },
    { &hf_cops_pc_reserved,
      { "Reserved", "cops.pc_reserved",
        FT_UINT32, BASE_HEX, NULL, 0x00,
        "Reserved", HFILL }
    },
    { &hf_cops_pc_key,
      { "Security Key", "cops.pc_key",
        FT_UINT32, BASE_HEX, NULL, 0x00,
        "Security Key", HFILL }
    },
    { &hf_cops_pc_slack_term,
      { "Slack Term", "cops.pc_slack_term",
        FT_UINT32, BASE_HEX, NULL, 0x00,
        "Slack Term", HFILL }
    },
    { &hf_cops_pc_src_ip,
      { "Source IP Address", "cops.pc_src_ip",
        FT_UINT32, BASE_HEX, NULL, 0x00,
        "Source IP Address", HFILL }
    },
    { &hf_cops_pc_subscriber_id,
      { "Subscriber Identifier (IPv4)", "cops.pc_subscriber_id",
        FT_UINT32, BASE_HEX, NULL, 0x00,
        "Subscriber Identifier (IPv4)", HFILL }
    },
    { &hf_cops_pc_token_bucket_rate,
      { "Token Bucket Rate", "cops.pc_token_bucket_rate",
        FT_FLOAT, BASE_NONE, NULL, 0x00,
        "Token Bucket Rate", HFILL }
    },
    { &hf_cops_pc_token_bucket_size,
      { "Token Bucket Size", "cops.pc_token_bucket_size",
        FT_FLOAT, BASE_NONE, NULL, 0x00,
        "Token Bucket Size", HFILL }
    },
    { &hf_cops_pc_bcid,
      { "Billing Correlation ID", "cops.pc_bcid",
        FT_UINT32, BASE_HEX, NULL, 0x00,
        "Billing Correlation ID", HFILL }
    },
    { &hf_cops_pc_bcid_ts,
      { "BDID Timestamp", "cops.pc_bcid_ts",
        FT_UINT32, BASE_HEX, NULL, 0x00,
        "BCID Timestamp", HFILL }
    },
    { &hf_cops_pc_bcid_ev,
      { "BDID Event Counter", "cops.pc_bcid_ev",
        FT_UINT32, BASE_HEX, NULL, 0x00,
        "BCID Event Counter", HFILL }
    },


    /* End of addition for PacketCable */

  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_cops,
    &ett_cops_ver_flags,
    &ett_cops_obj,
    &ett_cops_pr_obj,
    &ett_cops_obj_data,
    &ett_cops_r_type_flags,
    &ett_cops_itf,
    &ett_cops_reason,
    &ett_cops_decision,
    &ett_cops_error,
    &ett_cops_clientsi,
    &ett_cops_asn1,
    &ett_cops_gperror,
    &ett_cops_cperror,
    &ett_cops_pdp,
    &ett_cops_subtree,
  };

  module_t* cops_module;

  /* Register the protocol name and description */
  proto_cops = proto_register_protocol("Common Open Policy Service",
      "COPS", "cops");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_cops, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register our configuration options for cops */
  cops_module = prefs_register_protocol(proto_cops, proto_reg_handoff_cops);
  prefs_register_uint_preference(cops_module,"tcp.cops_port",
                                 "COPS TCP Port",
                                 "Set the TCP port for COPS messages",
                                 10,&global_cops_tcp_port);
  prefs_register_bool_preference(cops_module, "desegment",
                                 "Reassemble COPS messages spanning multiple TCP segments",
                                 "Whether the COPS dissector should reassemble messages spanning multiple TCP segments."
                                 " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                 &cops_desegment);

  /* For PacketCable */
  prefs_register_bool_preference(cops_module, "packetcable",
                                 "Decode for PacketCable clients",
                                 "Decode the COPS messages using PacketCable clients. (Select port 2126)",
                                 &cops_packetcable);

#ifdef HAVE_NET_SNMP /*enable preference only if compiled with NET-SNMP*/
  prefs_register_bool_preference(cops_module, "typefrommib",
                                 "Decode COPS-PR ASN.1 types by reading them\nfrom PIBs (converted to MIBs)",
                                 "Whether the COPS dissector should decode COPS-PR ASN.1 types based on data types read from packet or PIBs (converted to MIBs)",
                                 &cops_typefrommib);
#endif /*HAVE_NET_SNMP*/
}

void proto_reg_handoff_cops(void)
{
  static int cops_prefs_initialized = FALSE;
  static dissector_handle_t cops_handle;

  if (!cops_prefs_initialized) {
    cops_handle = create_dissector_handle(dissect_cops, proto_cops);
    cops_prefs_initialized = TRUE;
  } else
    dissector_delete("tcp.port",cops_tcp_port,cops_handle);

  /* Set our port numbers for future use */
  cops_tcp_port = global_cops_tcp_port;

  dissector_add("tcp.port", cops_tcp_port, cops_handle);
}


/* Additions for PacketCable ( Added by Dick Gooris, Lucent Technologies ) */

/* Definitions for print formatting */
#define   FMT_DEC   0
#define   FMT_HEX   1
#define   FMT_IP    2
#define   FMT_FLT   3

/* Print the translated information in the display gui in a formatted way
 *
 * octets = The number of octets to obtain from the buffer
 *
 * vsp    = If not a NULL pointer, it points to an array with text
 *
 * mode   = 0 -> print decimal value
 *          1 -> print hexadecimal vaue
 *          2 -> print value as an ip address
 *          3 -> print value as an ieee float
 *
 * This function in combination with the separate function info_to_cops_subtree() for subtrees.
 *
 */

void info_to_display(tvbuff_t *tvb, proto_item *stt, int offset, int octets, char *str, const value_string *vsp, int mode,gint *hf_proto_parameter)
{

     guint8   code8  = 0;
     guint16  code16 = 0;
     guint32  code32 = 0;
     guint32  codeip = 0;
     float    codefl = 0.0;

     /* Print information elements in the specified way */
     switch (octets) {

     case 1:
             /* Get the octet */
             code8 = tvb_get_guint8( tvb, offset );
             if (vsp == NULL) {
                /* Hexadecimal format */
                if (mode==FMT_HEX)
                   proto_tree_add_uint_format(stt, *hf_proto_parameter,tvb,
                       offset, octets, code8,"%-28s : 0x%02x",str,code8);
                else
                   /* Print an 8 bits integer */
                   proto_tree_add_uint_format(stt, *hf_proto_parameter,tvb,
                       offset, octets, code8,"%-28s : %u",str,code8);
             } else {
               if (mode==FMT_HEX)
                  /* Hexadecimal format */
                  proto_tree_add_uint_format(
                      stt, *hf_proto_parameter,tvb, offset, octets, code8,
                      "%-28s : %s (0x%02x)",str,val_to_str(code8, vsp, "Unknown"),code8);
               else
                  /* String table indexed */
                  proto_tree_add_uint_format(
                      stt, *hf_proto_parameter,tvb, offset, octets, code8,
                      "%-28s : %s (%u)",str,val_to_str(code8, vsp, "Unknown"),code8);
             }
             break;

       case 2:

             /* Get the next two octets */
             code16 = tvb_get_ntohs(tvb,offset);
             if (vsp == NULL) {
                /* Hexadecimal format */
                if (mode==FMT_HEX)
                   proto_tree_add_uint_format(stt, *hf_proto_parameter,tvb,
                       offset, octets, code16,"%-28s : 0x%04x",str,code16);
                else
                   /* Print a 16 bits integer */
                   proto_tree_add_uint_format(stt, *hf_proto_parameter,tvb,
                       offset, octets, code16,"%-28s : %u",str,code16);
             }  else {
                if (mode==FMT_HEX)
                   /* Hexadecimal format */
                   proto_tree_add_uint_format(stt, *hf_proto_parameter,tvb,
                       offset, octets, code16,"%-28s : %s (0x%04x)", str,
                       val_to_str(code16, vsp, "Unknown (0x%04x)"),code16);
                else
                   /* Print a 16 bits integer */
                   proto_tree_add_uint_format(
                       stt, *hf_proto_parameter,tvb, offset, octets, code16,
                       "%-28s : %s (%u)",str,val_to_str(code16, vsp, "Unknown (0x%04x)"),code16);
             }
             break;

        case 4:

             /* Get the next four octets */
             switch (mode) {
               case FMT_FLT:  codefl  = tvb_get_ntohieee_float(tvb,offset);
                              break;
               case FMT_IP:   tvb_memcpy(tvb, (guint8 *)&code32, offset, 4);
                              codeip  = tvb_get_ntohl(tvb,offset);
                              break;
               default:       code32  = tvb_get_ntohl(tvb,offset);
	     }

             if (vsp == NULL) {
                /* Hexadecimal format */
                if (mode==FMT_HEX) {
                   proto_tree_add_uint_format(stt, *hf_proto_parameter,tvb,
                       offset, octets, code32,"%-28s : 0x%08x",str,code32);
                   break;
                }
                /* Ip address format*/
                if (mode==FMT_IP) {
                   proto_tree_add_uint_format(stt, *hf_proto_parameter,tvb, offset,octets,
                       codeip,"%-28s : %s",str,ip_to_str((guint8 *)&code32));
                   break;
                }
                /* Ieee float format */
                if (mode==FMT_FLT) {
                   proto_tree_add_float_format(stt, *hf_proto_parameter,tvb, offset, octets,
                       codefl,"%-28s : %.10g",str,codefl);
                   break;
                }
                /* Print a 32 bits integer */
                proto_tree_add_uint_format(stt, *hf_proto_parameter,tvb, offset, octets,
                    code32,"%-28s : %u",str,code32);
             } else {
                /* Hexadecimal format */
                if (mode==FMT_HEX)
                   proto_tree_add_uint_format(stt, *hf_proto_parameter,tvb, offset, octets,
                           code32,"%-28s : %s (0x%08x)",str,val_to_str(code32, vsp, "Unknown"),code32);
                else
                   /* String table indexed */
                   proto_tree_add_uint_format(stt, *hf_proto_parameter,tvb, offset, octets,
                       code32,"%-28s : %s (%u)",str,val_to_str(code32, vsp, "Unknown"),code32);
             }
             break;

        /* In case of more than 4 octets.... */
        default: {
             if (mode==FMT_HEX)
                proto_tree_add_bytes(stt, *hf_proto_parameter,
                   tvb, offset, octets, tvb_get_ptr(tvb, offset,octets));
             else
                proto_tree_add_uint_format(stt, *hf_proto_parameter,
                   tvb, offset, octets, code32,"%s",str);
             break;
        }

     }
}

/* Print the subtree information for cops */
proto_tree *info_to_cops_subtree(tvbuff_t *tvb, proto_tree *st, int n, int offset, char *str) {
     proto_item *tv;

     tv  = proto_tree_add_uint_format( st, hf_cops_subtree, tvb, offset, n, (guint)NULL, str);
     return( proto_item_add_subtree( tv, ett_cops_subtree ) );
}

/* Cops - Section : Transaction ID */
void cops_transaction_id(tvbuff_t *tvb, proto_tree *st, guint n, guint32 offset) {

     proto_tree *stt;
     guint16  code16;
     char info[50];

     /* Create a subtree */
     stt = info_to_cops_subtree(tvb,st,n,offset,"Transaction ID");

     /* Transaction Identifier */
     info_to_display(tvb,stt,offset,2,"Transaction Identifier", NULL,FMT_DEC,&hf_cops_pc_transaction_id);
     offset +=2;

     /* Gate Command Type */
     code16 = tvb_get_ntohs(tvb,offset);
     proto_tree_add_uint_format(stt, hf_cops_pc_gate_command_type,tvb, offset, 2,
            code16,"%-28s : %s (%u)", "Gate Command Type",
            val_to_str(code16,table_cops_transaction_id, "Unknown (0x%04x)"),code16);

     /* Write the right data into the 'info field' on the Gui */
     sprintf(info,"COPS %-20s - ",val_to_str(opcode_idx,cops_op_code_vals, "Unknown"));
     strcat(info,val_to_str(code16,table_cops_transaction_id, "Unknown"));

     if (check_col(cpinfo->cinfo, COL_INFO)) {
          col_clear(cpinfo->cinfo, COL_INFO);
          col_add_str(cpinfo->cinfo, COL_INFO,info);
     }

}

/* Cops - Section : Subscriber ID */
void cops_subscriber_id_v4(tvbuff_t *tvb, proto_tree *st, guint n, guint32 offset) {

     proto_item *tv;

     /* Create a subtree */
     tv = info_to_cops_subtree(tvb,st,n,offset,"Subscriber ID");

     /* Subscriber Identifier */
     info_to_display(tvb,tv,offset,4,"Subscriber Identifier (IPv4)", NULL,FMT_IP,&hf_cops_pc_subscriber_id);
}

/* Cops - Section : Gate ID */
void cops_gate_id(tvbuff_t *tvb, proto_tree *st, guint n, guint32 offset) {

     proto_tree *stt;

     /* Create a subtree */
     stt = info_to_cops_subtree(tvb,st,n,offset,"Gate ID");

     /* Gate Identifier */
     info_to_display(tvb,stt,offset,4,"Gate Identifier", NULL,FMT_HEX,&hf_cops_pc_gate_id);
}

/* Cops - Section : Activity Count */
void cops_activity_count(tvbuff_t *tvb, proto_tree *st, guint n, guint32 offset) {

     proto_tree *stt;

     /* Create a subtree */
     stt = info_to_cops_subtree(tvb,st,n,offset,"Activity Count");

     /* Activity Count */
     info_to_display(tvb,stt,offset,4,"Count", NULL,FMT_DEC,&hf_cops_pc_activity_count);
}

/* Cops - Section : Gate Specifications */
void cops_gate_specs(tvbuff_t *tvb, proto_tree *st, guint n, guint32 offset) {

     proto_tree *stt;

     /* Create a subtree */
     stt = info_to_cops_subtree(tvb,st,n,offset,"Gate Specifications");

     /* Direction */
     info_to_display(tvb,stt,offset,1,"Direction",table_cops_direction,FMT_DEC,&hf_cops_pc_direction);
     offset += 1;

     /* Protocol ID */
     info_to_display(tvb,stt,offset,1,"Protocol ID",NULL,FMT_DEC,&hf_cops_pc_protocol_id);
     offset += 1;

     /* Flags */
     info_to_display(tvb,stt,offset,1,"Flags",NULL,FMT_DEC,&hf_cops_pc_gate_spec_flags);
     offset += 1;

     /* Session Class */
     info_to_display(tvb,stt,offset,1,"Session Class",table_cops_session_class,FMT_DEC,&hf_cops_pc_session_class);
     offset += 1;

     /* Source IP Address */
     info_to_display(tvb,stt,offset,4,"Source IP Address",NULL,FMT_IP,&hf_cops_pc_src_ip);
     offset += 4;

     /* Destination IP Address */
     info_to_display(tvb,stt,offset,4,"Destination IP Address",NULL,FMT_IP,&hf_cops_pc_dest_ip);
     offset += 4;

     /* Source IP Port */
     info_to_display(tvb,stt,offset,2,"Source IP Port",NULL,FMT_DEC,&hf_cops_pc_src_port);
     offset += 2;

     /* Destination IP Port */
     info_to_display(tvb,stt,offset,2,"Destination IP Port",NULL,FMT_DEC,&hf_cops_pc_dest_port);
     offset += 2;

     /* DiffServ Code Point */
     info_to_display(tvb,stt,offset,1,"DS Field (DSCP or TOS)",NULL,FMT_HEX,&hf_cops_pc_ds_field);
     offset += 1;

     /* 3 octets Not specified */
     offset += 3;

     /* Timer T1 Value */
     info_to_display(tvb,stt,offset,2,"Timer T1 Value (sec)",NULL,FMT_DEC,&hf_cops_pc_t1_value);
     offset += 2;

     /* Reserved */
     info_to_display(tvb,stt,offset,2,"Reserved",NULL,FMT_DEC,&hf_cops_pc_reserved);
     offset += 2;

     /* Timer T7 Value */
     info_to_display(tvb,stt,offset,2,"Timer T7 Value (sec)",NULL,FMT_DEC,&hf_cops_pc_t7_value);
     offset += 2;

     /* Timer T8 Value */
     info_to_display(tvb,stt,offset,2,"Timer T8 Value (sec)",NULL,FMT_DEC,&hf_cops_pc_t8_value);
     offset += 2;

     /* Token Bucket Rate */
     info_to_display(tvb,stt,offset,4,"Token Bucket Rate",NULL,FMT_FLT,&hf_cops_pc_token_bucket_rate);
     offset += 4;

     /* Token Bucket Size */
     info_to_display(tvb,stt,offset,4,"Token Bucket Size",NULL,FMT_FLT,&hf_cops_pc_token_bucket_size);
     offset += 4;

     /* Peak Data Rate */
     info_to_display(tvb,stt,offset,4,"Peak Data Rate",NULL,FMT_FLT,&hf_cops_pc_peak_data_rate);
     offset += 4;

     /* Minimum Policed Unit */
     info_to_display(tvb,stt,offset,4,"Minimum Policed Unit",NULL,FMT_DEC,&hf_cops_pc_min_policed_unit);
     offset += 4;

     /* Maximum Packet Size */
     info_to_display(tvb,stt,offset,4,"Maximum Packet Size",NULL,FMT_DEC,&hf_cops_pc_max_packet_size);
     offset += 4;

     /* Rate */
     info_to_display(tvb,stt,offset,4,"Rate",NULL,FMT_FLT,&hf_cops_pc_spec_rate);
     offset += 4;

     /* Slack Term */
     info_to_display(tvb,stt,offset,4,"Slack Term",NULL,FMT_DEC,&hf_cops_pc_slack_term);
}

/* Cops - Section : Electronic Surveillance Parameters  */
void  cops_surveillance_parameters(tvbuff_t *tvb, proto_tree *st, guint n, guint32 offset) {

     proto_tree *stt;
     guint8 *bcid_str;

     /* Create a subtree */
     stt = info_to_cops_subtree(tvb,st,n,offset,"Electronic Surveillance Parameters");

     /* DF IP Address for CDC */
     info_to_display(tvb,stt,offset,4,"DF IP Address for CDC", NULL,FMT_IP,&hf_cops_pc_dfcdc_ip);
     offset += 4;

     /* DF IP Port for CDC */
     info_to_display(tvb,stt,offset,2,"DF IP Port for CDC",NULL,FMT_DEC,&hf_cops_pc_dfcdc_ip_port);
     offset += 2;

     /* Flags */
     info_to_display(tvb,stt,offset,2,"Flags",NULL,FMT_HEX,&hf_cops_pc_gate_spec_flags);
     offset += 2;

     /* DF IP Address for CCC */
     info_to_display(tvb,stt,offset,4,"DF IP Address for CCC", NULL,FMT_IP,&hf_cops_pc_dfccc_ip);
     offset += 4;

     /* DF IP Port for CCC */
     info_to_display(tvb,stt,offset,2,"DF IP Port for CCC",NULL,FMT_DEC,&hf_cops_pc_dfccc_ip_port);
     offset += 2;

     /* Reserved */
     info_to_display(tvb,stt,offset,2,"Reserved",NULL,FMT_HEX,&hf_cops_pc_reserved);
     offset += 2;

     /* CCCID */
     info_to_display(tvb,stt,offset,4,"CCCID", NULL,FMT_HEX,&hf_cops_pc_srks_ip);
     offset += 4;

     /* BCID Timestamp */
     info_to_display(tvb,stt,offset,4,"BCID - Timestamp",NULL,FMT_HEX,&hf_cops_pc_bcid_ts);
     offset += 4;

     /* BCID Element ID */
     bcid_str = tvb_get_string(tvb, offset, 8);
     proto_tree_add_text(stt, tvb, offset, 8,"%-28s : '%s'","BCID - Element ID",bcid_str);
     offset += 8;

     /* BCID Time Zone */
     bcid_str = tvb_get_string(tvb, offset, 8);
     proto_tree_add_text(stt, tvb, offset, 8,"%-28s : '%s'","BCID - Time Zone",bcid_str);
     offset += 8;

     /* BCID Event Counter */
     info_to_display(tvb,stt,offset,4,"BCID - Event Counter",NULL,FMT_DEC,&hf_cops_pc_bcid_ev);
}

/* Cops - Section : Event Gereration-Info */
void  cops_event_generation_info(tvbuff_t *tvb, proto_tree *st, guint n, guint32 offset) {

     proto_tree *stt;
     guint8 *bcid_str;

     /* Create a subtree */
     stt = info_to_cops_subtree(tvb,st,n,offset,"Event Generation Info");

     /* Primary Record Keeping Server IP Address */
     info_to_display(tvb,stt,offset,4,"PRKS IP Address", NULL,FMT_IP,&hf_cops_pc_prks_ip);
     offset += 4;

     /* Primary Record Keeping Server IP Port */
     info_to_display(tvb,stt,offset,2,"PRKS IP Port",NULL,FMT_DEC,&hf_cops_pc_prks_ip_port);
     offset += 2;

     /* Flags */
     info_to_display(tvb,stt,offset,1,"Flags",NULL,FMT_HEX,&hf_cops_pc_gate_spec_flags);
     offset += 1;

     /* Reserved */
     info_to_display(tvb,stt,offset,1,"Reserved",NULL,FMT_HEX,&hf_cops_pc_reserved);
     offset += 1;

     /* Secundary Record Keeping Server IP Address */
     info_to_display(tvb,stt,offset,4,"SRKS IP Address", NULL,FMT_IP,&hf_cops_pc_srks_ip);
     offset += 4;

     /* Secundary Record Keeping Server IP Port */
     info_to_display(tvb,stt,offset,2,"SRKS IP Port",NULL,FMT_DEC,&hf_cops_pc_srks_ip_port);
     offset += 2;

     /* Flags */
     info_to_display(tvb,stt,offset,1,"Flags",NULL,FMT_DEC,&hf_cops_pc_gate_spec_flags);
     offset += 1;

     /* Reserved */
     info_to_display(tvb,stt,offset,1,"Reserved",NULL,FMT_HEX,&hf_cops_pc_reserved);
     offset += 1;

     /* BCID Timestamp */
     info_to_display(tvb,stt,offset,4,"BCID - Timestamp",NULL,FMT_HEX,&hf_cops_pc_bcid_ts);
     offset += 4;

     /* BCID Element ID */
     bcid_str = tvb_get_string(tvb, offset, 8);
     proto_tree_add_text(stt, tvb, offset, 8,"%-28s : '%s'","BCID - Element ID",bcid_str);
     offset += 8;

     /* BCID Time Zone */
     bcid_str = tvb_get_string(tvb, offset, 8);
     proto_tree_add_text(stt, tvb, offset, 8,"%-28s : '%s'","BCID - Time Zone",bcid_str);
     offset += 8;

     /* BCID Event Counter */
     info_to_display(tvb,stt,offset,4,"BCID - Event Counter",NULL,FMT_DEC,&hf_cops_pc_bcid_ev);
}

/* Cops - Section : Remote Gate */
void cops_remote_gate_info(tvbuff_t *tvb, proto_tree *st, guint n, guint32 offset) {

     proto_tree *stt;

     /* Create a subtree */
     stt = info_to_cops_subtree(tvb,st,n,offset,"Remote Gate Info");

     /* CMTS IP Address */
     info_to_display(tvb,stt,offset,4,"CMTS IP Address", NULL,FMT_IP,&hf_cops_pc_cmts_ip);
     offset += 4;

     /* CMTS IP Port */
     info_to_display(tvb,stt,offset,2,"CMTS IP Port",NULL,FMT_DEC,&hf_cops_pc_cmts_ip_port);
     offset += 2;

     /* Flags */
     info_to_display(tvb,stt,offset,2,"Flags",NULL,FMT_DEC,&hf_cops_pc_remote_flags);
     offset += 2;

     /* Remote Gate ID */
     info_to_display(tvb,stt,offset,4,"Remote Gate ID", NULL,FMT_HEX,&hf_cops_pc_remote_gate_id);
     offset += 4;

     /* Algorithm */
     info_to_display(tvb,stt,offset,2,"Algorithm", NULL,FMT_IP,&hf_cops_pc_algorithm);
     offset += 2;

     /* Reserved */
     info_to_display(tvb,stt,offset,4,"Reserved", NULL,FMT_IP,&hf_cops_pc_reserved);
     offset += 4;

     /* Security Key */
     info_to_display(tvb,stt,offset,4,"Security Key", NULL,FMT_HEX,&hf_cops_pc_key);
     offset += 4;

     /* Security Key */
     info_to_display(tvb,stt,offset,4,"Security Key (cont)", NULL,FMT_HEX,&hf_cops_pc_key);
     offset += 4;

     /* Security Key */
     info_to_display(tvb,stt,offset,4,"Security Key (cont)", NULL,FMT_HEX,&hf_cops_pc_key);
     offset += 4;

     /* Security Key */
     info_to_display(tvb,stt,offset,4,"Security Key (cont)", NULL,FMT_HEX,&hf_cops_pc_key);
}

/* Cops - Section : PacketCable reason */
void cops_packetcable_reason(tvbuff_t *tvb, proto_tree *st, guint n, guint32 offset) {

     proto_tree *stt;
     guint16  code16;

     /* Create a subtree */
     stt = info_to_cops_subtree(tvb,st,n,offset,"PacketCable Reason");

     /* Reason Code */
     code16 = tvb_get_ntohs(tvb,offset);
     proto_tree_add_uint_format(stt, hf_cops_pc_reason_code,tvb, offset, 2,
       code16, "%-28s : %s (%u)","Reason Code",
       val_to_str(code16, table_cops_reason_code, "Unknown (0x%04x)"),code16);
     offset += 2;

     if ( code16 == 0 ) {
        /* Reason Sub Code with Delete */
        info_to_display(tvb,stt,offset,2,"Reason Sub Code",table_cops_reason_subcode_delete,FMT_DEC,&hf_cops_pc_delete_subcode);
     } else {
        /* Reason Sub Code with Close */
        info_to_display(tvb,stt,offset,2,"Reason Sub Code",table_cops_reason_subcode_close,FMT_DEC,&hf_cops_pc_close_subcode);
     }
}

/* Cops - Section : PacketCable error */
void cops_packetcable_error(tvbuff_t *tvb, proto_tree *st, guint n, guint32 offset) {

     proto_tree *stt;

     /* Create a subtree */
     stt = info_to_cops_subtree(tvb,st,n,offset,"PacketCable Error");

     /* Error Code */
     info_to_display(tvb,stt,offset,2,"Error Code",table_cops_packetcable_error,FMT_DEC,&hf_cops_pc_packetcable_err_code);
     offset += 2;

     /* Error Sub Code */
     info_to_display(tvb,stt,offset,2,"Error Sub Code",NULL,FMT_HEX,&hf_cops_pc_packetcable_sub_code);

}

/* Analyze the PacketCable objects */
void cops_analyze_packetcable_obj(tvbuff_t *tvb, proto_tree *tree, guint32 offset) {

    gint remdata;
    guint16 object_len;
    guint8 s_num, s_type;

    /* Only if this option is enabled by the Gui */
    if ( cops_packetcable == FALSE ) {
       return;
    }

    /* Do the remaining client specific objects */
    remdata = tvb_length_remaining(tvb, offset);
    while (remdata > 4) {

       /* In case we have remaining data, then lets try to get this analyzed */
       object_len   = tvb_get_ntohs(tvb, offset);
       if (object_len < 4) {
	proto_tree_add_text(tree, tvb, offset, 2,
	    "Incorrect PacketCable object length %u < 4", object_len);
	return;
       }
	
       s_num        = tvb_get_guint8(tvb, offset + 2);
       s_type       = tvb_get_guint8(tvb, offset + 3);

       /* Tune offset */
       offset += 4;

       /* Perform the appropriate functions */
       switch (s_num){
        case 1:
               if (s_type == 1) {
                  cops_transaction_id(tvb, tree, object_len, offset);
               }
               break;
        case 2:
               if (s_type == 1) {
                  cops_subscriber_id_v4(tvb, tree, object_len, offset);
               }
               break;
        case 3:
               if (s_type == 1) {
                  cops_gate_id(tvb, tree, object_len, offset);
               }
               break;
        case 4:
               if (s_type == 1) {
                  cops_activity_count(tvb, tree, object_len, offset);
               }
               break;
        case 5:
               if (s_type == 1) {
                  cops_gate_specs(tvb, tree, object_len, offset);
               }
               break;
        case 6:
               if (s_type == 1) {
                  cops_remote_gate_info(tvb, tree, object_len, offset);
               }
               break;
        case 7:
               if (s_type == 1) {
                  cops_event_generation_info(tvb, tree, object_len, offset);
               }
               break;
        case 9:
               if (s_type == 1) {
                  cops_packetcable_error(tvb, tree, object_len, offset);
               }
               break;
        case 10:
               if (s_type == 1) {
                  cops_surveillance_parameters(tvb, tree, object_len, offset);
               }
               break;
        case 13:
               if (s_type == 1) {
                  cops_packetcable_reason(tvb, tree, object_len, offset);
               }
               break;
       }

       /* Tune offset */
       offset += object_len-4;

       /* See what we can still get from the buffer */
       remdata = tvb_length_remaining(tvb, offset);
    }
}

/* End of PacketCable Addition */


