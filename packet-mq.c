/* packet-mq.c
 * Routines for IBM WebSphere MQ packet dissection
 *
 * metatech <metatech@flashmail.com>
 *
 * $Id: packet-mq.c,v 1.1 2004/03/16 19:23:24 guy Exp $
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

/*  WebSphere MQ in a nutshell
*
*   IBM WebSphere MQ (formerly IBM MQSeries) is an asynchronous messaging middleware that is based on message queues.
*   MQ can run on more than 35 platforms, amongst which UNIX, Windows and mainframes.
*   MQ can be transported on top of TCP, UDP, NetBIOS, SPX, SNA LU 6.2, DECnet.
*   MQ has language bindings for C, C++, Java, .NET, COBOL, PL/I, OS/390 assembler, TAL, Visual Basic.
*
*   The basic MQ topology is on one side the queue manager which hosts the queues.  On the other side the 
*   applications connect to the queue manager, open a queue, and put or get messages to/from that queue.
*
*	The MQ middleware allows very generic operations (send, receive) and can be compared to the 
*   socket API in terms of genericity, but it is more abstract and offers higher-level functionalities
*   (eg transactions, ...)
*
*   The MQ middleware is not really intended to be run over public networks between parties
*   that do not know each other in advance, but is rather used on private corporate networks 
*   between business applications (it can be compared to a database server for that aspect).
*
*   The wire format of an MQ segment is a sequence of structures.  Most structures start with a 4-letter struct identifier.
*   MQ is a fixed-sized format, most fields have maximum lengths defined in the MQ API.
*   MQ is popular on mainframes because it was available before TCP/IP.
*   MQ supports both ASCII-based and EBCDIC-based character sets.
*
*   This dissector is a beta version.  To be improved 
*   - Merged packets do not work very well.
*   - Translate the integers/flags into their descriptions
*   - Find the semantics of the unknown fields
*   - Display EBCDIC strings as ASCII
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

static int proto_mq = -1;
static int hf_mq_tsh_structid = -1;
static int hf_mq_tsh_packetlength = -1;
static int hf_mq_tsh_byteorder = -1;
static int hf_mq_tsh_opcode = -1;
static int hf_mq_tsh_controlflags = -1;
static int hf_mq_tsh_unknown2 = -1;
static int hf_mq_tsh_luwid = -1;
static int hf_mq_tsh_encoding = -1;
static int hf_mq_tsh_ccsid = -1;
static int hf_mq_tsh_unknown4 = -1;
static int hf_mq_tsh_length = -1;
static int hf_mq_tsh_completioncode = -1;
static int hf_mq_tsh_reasoncode = -1;
static int hf_mq_tsh_queuehandle = -1;
static int hf_mq_tsh_tcf_confirmreq = -1;
static int hf_mq_tsh_tcf_error = -1;
static int hf_mq_tsh_tcf_reqclose = -1;
static int hf_mq_tsh_tcf_closechann = -1;
static int hf_mq_tsh_tcf_first = -1;
static int hf_mq_tsh_tcf_last = -1;
static int hf_mq_id_structid = -1;
static int hf_mq_id_level = -1;
static int hf_mq_id_flags = -1;
static int hf_mq_id_unknown2 = -1;
static int hf_mq_id_ieflags = -1;
static int hf_mq_id_unknown4 = -1;
static int hf_mq_id_maxmsgperbatch = -1;
static int hf_mq_id_maxtransmissionsize = -1;
static int hf_mq_id_maxmsgsize = -1;
static int hf_mq_id_sequencewrapvalue = -1;
static int hf_mq_id_channel = -1;
static int hf_mq_id_flags2 = -1;
static int hf_mq_id_unknown5 = -1;
static int hf_mq_id_ccsid = -1;
static int hf_mq_id_queuemanager = -1;
static int hf_mq_id_heartbeatinterval = -1;
static int hf_mq_id_unknown6 = -1;
static int hf_mq_id_ief_ccsid = -1;
static int hf_mq_id_ief_enc = -1;
static int hf_mq_id_ief_mxtrsz = -1;
static int hf_mq_id_ief_fap = -1;
static int hf_mq_id_ief_mxmsgsz = -1;
static int hf_mq_id_ief_mxmsgpb = -1;
static int hf_mq_id_ief_seqwrap = -1;
static int hf_mq_id_ief_hbint = -1;
static int hf_mq_uid_structid = -1;
static int hf_mq_uid_userid = -1;
static int hf_mq_uid_password = -1;
static int hf_mq_uid_longuserid = -1;
static int hf_mq_uid_securityid = -1;
static int hf_mq_conn_queuemanager = -1;
static int hf_mq_conn_putapplname = -1;
static int hf_mq_conn_unknown1 = -1;
static int hf_mq_conn_acttoken = -1;
static int hf_mq_conn_unknown2 = -1;
static int hf_mq_conn_unknown3 = -1;
static int hf_mq_od_structid = -1;
static int hf_mq_od_version = -1;
static int hf_mq_od_objecttype = -1;
static int hf_mq_od_objectname = -1;
static int hf_mq_od_objectqmgrname = -1;
static int hf_mq_od_dynamicqname = -1;
static int hf_mq_od_alternateuserid = -1;
static int hf_mq_od_recspresent = -1;
static int hf_mq_od_knowndestcount = -1;
static int hf_mq_od_unknowndestcount = -1;
static int hf_mq_od_invaliddestcount = -1;
static int hf_mq_od_objectrecoffset = -1;
static int hf_mq_od_responserecoffset = -1;
static int hf_mq_od_objectrecptr = -1;
static int hf_mq_od_responserecptr = -1;
static int hf_mq_od_alternatesecurityid = -1;
static int hf_mq_od_resolvedqname = -1;
static int hf_mq_od_resolvedqmgrname = -1;
static int hf_mq_md_structid = -1;
static int hf_mq_md_version = -1;
static int hf_mq_md_report = -1;
static int hf_mq_md_msgtype = -1;
static int hf_mq_md_expiry = -1;
static int hf_mq_md_feedback = -1;
static int hf_mq_md_encoding = -1;
static int hf_mq_md_ccsid = -1;
static int hf_mq_md_format = -1;
static int hf_mq_md_priority = -1;
static int hf_mq_md_persistence = -1;
static int hf_mq_md_msgid = -1;
static int hf_mq_md_correlid = -1;
static int hf_mq_md_backountcount = -1;
static int hf_mq_md_replytoq = -1;
static int hf_mq_md_replytoqmgr = -1;
static int hf_mq_md_userid = -1;
static int hf_mq_md_acttoken = -1;
static int hf_mq_md_appliddata = -1;
static int hf_mq_md_putappltype = -1;
static int hf_mq_md_putapplname = -1;
static int hf_mq_md_putdate = -1;
static int hf_mq_md_puttime = -1;
static int hf_mq_md_applorigindata = -1;
static int hf_mq_md_groupid = -1;
static int hf_mq_md_msgseqnumber = -1;
static int hf_mq_md_offset = -1;
static int hf_mq_md_msgflags = -1;
static int hf_mq_md_originallength = -1;
static int hf_mq_gmo_structid = -1;
static int hf_mq_gmo_version = -1;
static int hf_mq_gmo_options = -1;
static int hf_mq_gmo_waitinterval = -1;
static int hf_mq_gmo_signal1 = -1;
static int hf_mq_gmo_signal2 = -1;
static int hf_mq_gmo_resolvedqname = -1;
static int hf_mq_gmo_matchoptions = -1;
static int hf_mq_gmo_groupstatus = -1;
static int hf_mq_gmo_segmentstatus = -1;
static int hf_mq_gmo_segmentation = -1;
static int hf_mq_gmo_reserved = -1;
static int hf_mq_gmo_msgtoken = -1;
static int hf_mq_gmo_returnedlength = -1;
static int hf_mq_buffer_length = -1;
static int hf_mq_buffer_data = -1;
static int hf_mq_pmo_structid = -1;
static int hf_mq_pmo_version = -1;
static int hf_mq_pmo_options = -1;
static int hf_mq_pmo_timeout = -1;
static int hf_mq_pmo_context = -1;
static int hf_mq_pmo_knowndestcount = -1;
static int hf_mq_pmo_unknowndestcount = -1;
static int hf_mq_pmo_invaliddestcount = -1;
static int hf_mq_pmo_resolvedqname = -1;
static int hf_mq_pmo_resolvedqmgrname = -1;
static int hf_mq_pmo_recspresent = -1;
static int hf_mq_pmo_putmsgrecfields = -1;
static int hf_mq_pmo_putmsgrecoffset = -1;
static int hf_mq_pmo_responserecoffset = -1;
static int hf_mq_pmo_putmsgrecptr = -1;
static int hf_mq_pmo_responserecptr = -1;

static gint ett_mq = -1;
static gint ett_mq_tsh = -1;
static gint ett_mq_tsh_tcf = -1;
static gint ett_mq_id = -1;
static gint ett_mq_id_ief = -1;
static gint ett_mq_uid = -1;
static gint ett_mq_conn = -1;
static gint ett_mq_od = -1;
static gint ett_mq_md = -1;
static gint ett_mq_gmo = -1;
static gint ett_mq_pmo = -1;
static gint ett_mq_buffer = -1;

static dissector_handle_t mq_handle;

#define MQ_PORT_TCP    1414

#define MQ_STRUCTID_AIR           0x41495220
#define MQ_STRUCTID_BO            0x424F2020
#define MQ_STRUCTID_CIH           0x43494820
#define MQ_STRUCTID_CNO           0x434E4F20
#define MQ_STRUCTID_DH            0x44482020
#define MQ_STRUCTID_DLH           0x444C4820
#define MQ_STRUCTID_GMO           0x474D4F20
#define MQ_STRUCTID_ID            0x49442020
#define MQ_STRUCTID_IIH           0x49494820
#define MQ_STRUCTID_MD            0x4D442020
#define MQ_STRUCTID_MDE           0x4D444520
#define MQ_STRUCTID_OD            0x4F442020
#define MQ_STRUCTID_PMO           0x504D4F20
#define MQ_STRUCTID_RMH           0x524D4820
#define MQ_STRUCTID_SCO           0x53434F20
#define MQ_STRUCTID_TM            0x544D2020
#define MQ_STRUCTID_TMC2          0x544D4332
#define MQ_STRUCTID_TSH           0x54534820
#define MQ_STRUCTID_UID           0x55494420
#define MQ_STRUCTID_WIH           0x57494820
#define MQ_STRUCTID_XP            0x58502020
#define MQ_STRUCTID_XQH           0x58514820
#define MQ_STRUCTID_AIR_EBCDIC    0xC1C9D940
#define MQ_STRUCTID_BO_EBCDIC     0xC2D64040
#define MQ_STRUCTID_CIH_EBCDIC    0xC3C9C840
#define MQ_STRUCTID_CNO_EBCDIC    0xC3D5D640
#define MQ_STRUCTID_DH_EBCDIC     0xC4C84040
#define MQ_STRUCTID_DLH_EBCDIC    0xC4D3C840
#define MQ_STRUCTID_DLH_EBCDIC    0xC4D3C840
#define MQ_STRUCTID_GMO_EBCDIC    0xC7D4D640
#define MQ_STRUCTID_ID_EBCDIC     0xC9C44040 
#define MQ_STRUCTID_IIH_EBCDIC    0xC9C9C840 
#define MQ_STRUCTID_MD_EBCDIC     0xD4C44040
#define MQ_STRUCTID_MDE_EBCDIC    0xD4C4C540
#define MQ_STRUCTID_OD_EBCDIC     0xD6C44040
#define MQ_STRUCTID_PMO_EBCDIC    0xD7D4D640
#define MQ_STRUCTID_RMH_EBCDIC    0xD9D4C840
#define MQ_STRUCTID_SCO_EBCDIC    0xE2C3D640
#define MQ_STRUCTID_TM_EBCDIC     0xE3D44040
#define MQ_STRUCTID_TMC2_EBCDIC   0xE3D4C3F2
#define MQ_STRUCTID_TSH_EBCDIC    0xE3E2C840 
#define MQ_STRUCTID_UID_EBCDIC    0xE4C9C440
#define MQ_STRUCTID_WIH_EBCDIC    0xE6C9C840
#define MQ_STRUCTID_XP_EBCDIC     0xE7D74040
#define MQ_STRUCTID_XQH_EBCDIC    0xE7D8C840

#define MQ_TST_INITIAL            0x01
#define MQ_TST_RESYNC             0x02
#define MQ_TST_RESET              0x03
#define MQ_TST_MESSAGE            0x04
#define MQ_TST_STATUS             0x05
#define MQ_TST_SECURITY           0x06
#define MQ_TST_PING               0x07
#define MQ_TST_USERID             0x08
#define MQ_TST_HEARTBEAT          0x09
#define MQ_TST_MQCONN             0x81
#define MQ_TST_MQDISC             0x82
#define MQ_TST_MQOPEN             0x83
#define MQ_TST_MQCLOSE            0x84
#define MQ_TST_MQGET              0x85
#define MQ_TST_MQPUT              0x86
#define MQ_TST_MQPUT1             0x87
#define MQ_TST_MQSET              0x88
#define MQ_TST_MQINQ              0x89
#define MQ_TST_MQCMIT             0x8A
#define MQ_TST_MQBACK             0x8B
#define MQ_TST_SPI                0x8C
#define MQ_TST_MQCONN_REPLY       0x91
#define MQ_TST_MQDISC_REPLY       0x92
#define MQ_TST_MQOPEN_REPLY       0x93
#define MQ_TST_MQCLOSE_REPLY      0x94
#define MQ_TST_MQGET_REPLY        0x95
#define MQ_TST_MQPUT_REPLY        0x96
#define MQ_TST_MQPUT1_REPLY       0x97
#define MQ_TST_MQSET_REPLY        0x98
#define MQ_TST_MQINQ_REPLY        0x99
#define MQ_TST_MQCMIT_REPLY       0x9A
#define MQ_TST_MQBACK_REPLY       0x9B
#define MQ_TST_SPI_REPLY          0x9C
#define MQ_TST_XA_START           0xA1
#define MQ_TST_XA_END             0xA2
#define MQ_TST_XA_OPEN            0xA3
#define MQ_TST_XA_CLOSE           0xA4
#define MQ_TST_XA_PREPARE         0xA5
#define MQ_TST_XA_COMMIT          0xA6
#define MQ_TST_XA_ROLLBACK        0xA7
#define MQ_TST_XA_FORGET          0xA8
#define MQ_TST_XA_RECOVER         0xA9
#define MQ_TST_XA_COMPLETE        0xAA
#define MQ_TST_XA_START_REPLY     0xB1
#define MQ_TST_XA_END_REPLY       0xB2
#define MQ_TST_XA_OPEN_REPLY      0xB3
#define MQ_TST_XA_CLOSE_REPLY     0xB4
#define MQ_TST_XA_PREPARE_REPLY   0xB5
#define MQ_TST_XA_COMMIT_REPLY    0xB6
#define MQ_TST_XA_ROLLBACK_REPLY  0xB7
#define MQ_TST_XA_FORGET_REPLY    0xB8
#define MQ_TST_XA_RECOVER_REPLY   0xB9
#define MQ_TST_XA_COMPLETE_REPLY  0xBA
#define MQ_TST_SPI_CAN_WAIT       0xC1
#define MQ_TST_SPI_CAN_WAIT_REPLY 0xD1

#define MQ_TCF_CONFIRM_REQUEST    0x01
#define MQ_TCF_ERROR              0x02
#define MQ_TCF_REQUEST_CLOSE      0x04
#define MQ_TCF_CLOSE_CHANNEL      0x08
#define MQ_TCF_FIRST              0x10
#define MQ_TCF_LAST               0x20

#define MQ_IEF_CCSID                  0x01
#define MQ_IEF_ENCODING               0x02
#define MQ_IEF_MAX_TRANSMISSION_SIZE  0x04
#define MQ_IEF_FAP_LEVEL              0x08
#define MQ_IEF_MAX_MSG_SIZE           0x10
#define MQ_IEF_MAX_MSG_PER_BATCH      0x20
#define MQ_IEF_SEQ_WRAP_VALUE         0x40
#define MQ_IEF_HEARTBEAT_INTERVAL     0x80

#define MQ_BIG_ENDIAN          0x01
#define MQ_LITTLE_ENDIAN       0x02

/* MQ structures */
/* Undocumented structures */
#define MQ_TEXT_TSH  "Transmission Segment Header"
#define MQ_TEXT_ID   "Initial Data"
#define MQ_TEXT_UID  "User Id Data"
#define MQ_TEXT_CONN "MQCONN"
#define MQ_TEXT_BUFF "Buffer"
#define MQ_TEXT_DATA "Data"

/* Documented structures with structid */
#define MQ_TEXT_AIR  "Authentication Information Record"
#define MQ_TEXT_BO   "Begin Options"
#define MQ_TEXT_CIH  "CICS bridge Header"
#define MQ_TEXT_CNO  "Connect Options"
#define MQ_TEXT_DH   "Distribution Header"
#define MQ_TEXT_DLH  "Dead-Letter Header"
#define MQ_TEXT_GMO  "Get Message Options"
#define MQ_TEXT_IIH  "IMS Information Header"
#define MQ_TEXT_MD   "Message Descriptor"
#define MQ_TEXT_MDE  "Message Descriptor Extension"
#define MQ_TEXT_OD   "Object Descriptor"
#define MQ_TEXT_PMO  "Put Message Options"
#define MQ_TEXT_RMH  "Reference Message Header"
#define MQ_TEXT_SCO  "SSL Configuration Options"
#define MQ_TEXT_TM   "Trigger Message"
#define MQ_TEXT_TMC2 "Trigger Message 2 (character format)"
#define MQ_TEXT_WIH  "Work Information Header"
#define MQ_TEXT_XP   "Exit Parameter block"
#define MQ_TEXT_XQH  "Transmission Queue Header"

/* Documented structures without structid */
#define MQ_TEXT_OR   "Object Record"
#define MQ_TEXT_PMR  "Put Message Record"
#define MQ_TEXT_RR   "Response Record"


static const value_string mq_opcode_vals[] = {
  { MQ_TST_INITIAL,           "INITIAL" },
  { MQ_TST_RESYNC,            "RESYNC" },
  { MQ_TST_RESET,             "RESET" },
  { MQ_TST_MESSAGE,           "MESSAGE" },
  { MQ_TST_STATUS,            "STATUS" },
  { MQ_TST_SECURITY,          "SECURITY" },
  { MQ_TST_PING,              "PING" },
  { MQ_TST_USERID,            "USERID" },
  { MQ_TST_HEARTBEAT,         "HEARTBEAT" },
  { MQ_TST_MQCONN,            "MQCONN" },
  { MQ_TST_MQDISC,            "MQDISC" },
  { MQ_TST_MQOPEN,            "MQOPEN" },
  { MQ_TST_MQCLOSE,           "MQCLOSE" },
  { MQ_TST_MQGET,             "MQGET" },
  { MQ_TST_MQPUT,             "MQPUT" },
  { MQ_TST_MQPUT1,            "MQPUT1" },
  { MQ_TST_MQSET,             "MQSET" },
  { MQ_TST_MQINQ,             "MQINQ" },
  { MQ_TST_MQCMIT,            "MQCMIT" },
  { MQ_TST_MQBACK,            "MQBACK" },
  { MQ_TST_SPI,               "MQSPI" },
  { MQ_TST_MQCONN_REPLY,      "MQCONN_REPLY" },
  { MQ_TST_MQDISC_REPLY,      "MQDISC_REPLY" },
  { MQ_TST_MQOPEN_REPLY,      "MQOPEN_REPLY" },
  { MQ_TST_MQCLOSE_REPLY,     "MQCLOSE_REPLY" },
  { MQ_TST_MQGET_REPLY,       "MQGET_REPLY" },
  { MQ_TST_MQPUT_REPLY,       "MQPUT_REPLY" },
  { MQ_TST_MQPUT1_REPLY,      "MQPUT1_REPLY" },
  { MQ_TST_MQSET_REPLY,       "MQSET_REPLY" },
  { MQ_TST_MQINQ_REPLY,       "MQINQ_REPLY" },
  { MQ_TST_MQCMIT_REPLY,      "MQCMIT_REPLY" },
  { MQ_TST_MQBACK_REPLY,      "MQBACK_REPLY" },
  { MQ_TST_SPI_REPLY,         "SPI_REPLY" },
  { MQ_TST_XA_START,          "XA_START" },
  { MQ_TST_XA_END,            "XA_END" },
  { MQ_TST_XA_OPEN,           "XA_OPEN" },
  { MQ_TST_XA_CLOSE,          "XA_CLOSE" },
  { MQ_TST_XA_PREPARE,        "XA_PREPARE" },
  { MQ_TST_XA_COMMIT,         "XA_COMMIT" },
  { MQ_TST_XA_ROLLBACK,       "XA_ROLLBACK" },
  { MQ_TST_XA_FORGET,         "XA_FORGET" },
  { MQ_TST_XA_RECOVER,        "XA_RECOVER" },
  { MQ_TST_XA_COMPLETE,       "XA_COMPLETE" },
  { MQ_TST_XA_START_REPLY,    "XA_START_REPLY" },
  { MQ_TST_XA_END_REPLY,      "XA_END_REPLY" },
  { MQ_TST_XA_OPEN_REPLY,     "XA_OPEN_REPLY" },
  { MQ_TST_XA_CLOSE_REPLY,    "XA_CLOSE_REPLY" },
  { MQ_TST_XA_PREPARE_REPLY,  "XA_PREPARE_REPLY" },
  { MQ_TST_XA_COMMIT_REPLY,   "XA_COMMIT_REPLY" },
  { MQ_TST_XA_ROLLBACK_REPLY, "XA_ROLLBACK_REPLY" },
  { MQ_TST_XA_FORGET_REPLY,   "XA_FORGET_REPLY" },
  { MQ_TST_XA_RECOVER_REPLY,  "XA_RECOVER_REPLY" },
  { MQ_TST_XA_COMPLETE_REPLY, "XA_COMPLETE_REPLY" },
  { MQ_TST_SPI_CAN_WAIT,      "SPI_CAN_WAIT" },
  { MQ_TST_SPI_CAN_WAIT_REPLY,"SPI_CAN_WAIT_REPLY" },
  { 0,          NULL }
};

static const value_string mq_structid_vals[] = {
  { MQ_STRUCTID_AIR,         MQ_TEXT_AIR },
  { MQ_STRUCTID_BO,          MQ_TEXT_BO },
  { MQ_STRUCTID_CIH,         MQ_TEXT_CIH },
  { MQ_STRUCTID_CNO,         MQ_TEXT_CNO },
  { MQ_STRUCTID_DH,          MQ_TEXT_DH },
  { MQ_STRUCTID_DLH,         MQ_TEXT_DLH },
  { MQ_STRUCTID_GMO,         MQ_TEXT_GMO },
  { MQ_STRUCTID_ID,          MQ_TEXT_ID },
  { MQ_STRUCTID_IIH,         MQ_TEXT_IIH },
  { MQ_STRUCTID_MD,          MQ_TEXT_MD },
  { MQ_STRUCTID_MDE,         MQ_TEXT_MDE },
  { MQ_STRUCTID_OD,          MQ_TEXT_OD },
  { MQ_STRUCTID_PMO,         MQ_TEXT_PMO },
  { MQ_STRUCTID_RMH,         MQ_TEXT_RMH },
  { MQ_STRUCTID_SCO,         MQ_TEXT_SCO },
  { MQ_STRUCTID_TM,          MQ_TEXT_TM },
  { MQ_STRUCTID_TMC2,        MQ_TEXT_TMC2 },
  { MQ_STRUCTID_TSH,         MQ_TEXT_TSH },
  { MQ_STRUCTID_UID,         MQ_TEXT_UID },
  { MQ_STRUCTID_WIH,         MQ_TEXT_WIH },
  { MQ_STRUCTID_XP,          MQ_TEXT_XP },
  { MQ_STRUCTID_XQH,         MQ_TEXT_XQH },
  { MQ_STRUCTID_AIR_EBCDIC,  MQ_TEXT_AIR },
  { MQ_STRUCTID_BO_EBCDIC,   MQ_TEXT_BO },
  { MQ_STRUCTID_CIH_EBCDIC,  MQ_TEXT_CIH },
  { MQ_STRUCTID_CNO_EBCDIC,  MQ_TEXT_CNO },
  { MQ_STRUCTID_DH_EBCDIC,   MQ_TEXT_DH },
  { MQ_STRUCTID_DLH_EBCDIC,  MQ_TEXT_DLH },
  { MQ_STRUCTID_GMO_EBCDIC,  MQ_TEXT_GMO },
  { MQ_STRUCTID_ID_EBCDIC,   MQ_TEXT_ID },
  { MQ_STRUCTID_IIH_EBCDIC,  MQ_TEXT_IIH },
  { MQ_STRUCTID_MD_EBCDIC,   MQ_TEXT_MD },
  { MQ_STRUCTID_MDE_EBCDIC,  MQ_TEXT_MDE },
  { MQ_STRUCTID_OD_EBCDIC,   MQ_TEXT_OD },
  { MQ_STRUCTID_PMO_EBCDIC,  MQ_TEXT_PMO },
  { MQ_STRUCTID_RMH_EBCDIC,  MQ_TEXT_RMH },
  { MQ_STRUCTID_SCO_EBCDIC,  MQ_TEXT_SCO },
  { MQ_STRUCTID_TM_EBCDIC,   MQ_TEXT_TM },
  { MQ_STRUCTID_TMC2_EBCDIC, MQ_TEXT_TMC2 },
  { MQ_STRUCTID_TSH_EBCDIC,  MQ_TEXT_TSH },
  { MQ_STRUCTID_UID_EBCDIC,  MQ_TEXT_UID },
  { MQ_STRUCTID_WIH_EBCDIC,  MQ_TEXT_WIH },
  { MQ_STRUCTID_XP_EBCDIC,   MQ_TEXT_XP },
  { MQ_STRUCTID_XQH_EBCDIC,  MQ_TEXT_XQH },
  { 0,          NULL }
};

static const value_string mq_byteorder_vals[] = {
  { MQ_LITTLE_ENDIAN,  "Little endian" },
  { MQ_BIG_ENDIAN,     "Big endian" },
  { 0,          NULL }
};


/* This routine truncates the string at the first blank space */
static gint strip_trailing_blanks(guint8* a_string, gint a_size)
{
	gint i = 0;
	for (i = 0; i < a_size; i++)
	{
		if (a_string[i] == ' ' || a_string[i] == '\0') 
		{
			a_string[i] = '\0';
			break;	
		}
	}
	return i;
}

static void
dissect_mq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*mq_tree = NULL;
	proto_tree	*mqroot_tree = NULL;
	proto_item	*ti;
	conversation_t  *conversation;
	gint offset = 0;
	guint32 structId;
	guint8 opcode;
	gboolean bLittleEndian = FALSE;
	gboolean bPayload = FALSE;
	gboolean bEBCDIC = FALSE;
	
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) col_set_str(pinfo->cinfo, COL_PROTOCOL, "MQ");	  	
	conversation = find_conversation(&pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
	if (conversation == NULL) 
	{
		conversation = conversation_new(&pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
		conversation_set_dissector(conversation, mq_handle);
	}
	
	if (tvb_reported_length(tvb) >= 28)
	{
		structId = tvb_get_ntohl(tvb, offset);
		if (structId == MQ_STRUCTID_TSH || structId == MQ_STRUCTID_TSH_EBCDIC)
		{
			/* An MQ packet always starts with this structure*/
			gint iSizeTSH = 0;
			if (structId == MQ_STRUCTID_TSH_EBCDIC) bEBCDIC = TRUE;
			opcode = tvb_get_guint8(tvb, offset + 9);		
			iSizeTSH = (opcode <= 0x10 ? 28 : 44); /* guess */
			if (opcode == MQ_TST_STATUS) iSizeTSH = 36;	

			if (check_col(pinfo->cinfo, COL_INFO)) 
			{					
				col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(opcode, mq_opcode_vals, "Unknown (0x%02x)"));		
			}

			if (tree)
			{
				ti = proto_tree_add_item(tree, proto_mq, tvb, offset, -1, FALSE);
				if (bEBCDIC == TRUE) proto_item_append_text(ti, " (EBCDIC)");
				mqroot_tree = proto_item_add_subtree(ti, ett_mq);
		
				ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSizeTSH, MQ_TEXT_TSH);
				mq_tree = proto_item_add_subtree(ti, ett_mq_tsh);
	
				proto_tree_add_item(mq_tree, hf_mq_tsh_structid, tvb, offset + 0, 4, FALSE);		
				proto_tree_add_item(mq_tree, hf_mq_tsh_packetlength, tvb, offset + 4, 4, FALSE);
	
				bLittleEndian = (tvb_get_guint8(tvb, offset + 8) == MQ_LITTLE_ENDIAN ? TRUE : FALSE);
				proto_tree_add_item(mq_tree, hf_mq_tsh_byteorder, tvb, offset + 8, 1, FALSE);

				proto_tree_add_item(mq_tree, hf_mq_tsh_opcode, tvb, offset + 9, 1, FALSE);		

				/* Control flags */
				{
				proto_tree	*mq_tree_sub = NULL;
					guint8 iControlFlags;

					ti = proto_tree_add_item(mq_tree, hf_mq_tsh_controlflags, tvb, offset + 10, 1, FALSE);
					mq_tree_sub = proto_item_add_subtree(ti, ett_mq_tsh_tcf);
					iControlFlags = tvb_get_guint8(tvb, offset + 10);	
					
					proto_tree_add_boolean(mq_tree_sub, hf_mq_tsh_tcf_last, tvb, offset + 10, 1, iControlFlags);
					proto_tree_add_boolean(mq_tree_sub, hf_mq_tsh_tcf_first, tvb, offset + 10, 1, iControlFlags);
					proto_tree_add_boolean(mq_tree_sub, hf_mq_tsh_tcf_closechann, tvb, offset + 10, 1, iControlFlags);
					proto_tree_add_boolean(mq_tree_sub, hf_mq_tsh_tcf_reqclose, tvb, offset + 10, 1, iControlFlags);
					proto_tree_add_boolean(mq_tree_sub, hf_mq_tsh_tcf_error, tvb, offset + 10, 1, iControlFlags);
					proto_tree_add_boolean(mq_tree_sub, hf_mq_tsh_tcf_confirmreq, tvb, offset + 10, 1, iControlFlags);
				}
				
				proto_tree_add_item(mq_tree, hf_mq_tsh_unknown2, tvb, offset + 11, 1, FALSE);
				proto_tree_add_item(mq_tree, hf_mq_tsh_luwid, tvb, offset + 12, 8, FALSE);
				proto_tree_add_item(mq_tree, hf_mq_tsh_encoding, tvb, offset + 20, 4, bLittleEndian);
				proto_tree_add_item(mq_tree, hf_mq_tsh_ccsid, tvb, offset + 24, 2, bLittleEndian);
				proto_tree_add_item(mq_tree, hf_mq_tsh_unknown4, tvb, offset + 26, 2, FALSE);

				if (iSizeTSH >= 44 && tvb_length_remaining(tvb, offset) >= 44)
				{				
						proto_tree_add_item(mq_tree, hf_mq_tsh_length, tvb, offset + 28, 4, FALSE);
						proto_tree_add_item(mq_tree, hf_mq_tsh_completioncode, tvb, offset + 32, 4, bLittleEndian);
						proto_tree_add_item(mq_tree, hf_mq_tsh_reasoncode, tvb, offset + 36, 4, bLittleEndian);	
						proto_tree_add_item(mq_tree, hf_mq_tsh_queuehandle, tvb, offset + 40, 4, bLittleEndian);
				}
				else if (iSizeTSH == 36 && tvb_length_remaining(tvb, offset) >= 36)
				{
					proto_tree_add_item(mq_tree, hf_mq_tsh_length, tvb, offset + 28, 4, bLittleEndian);
					proto_tree_add_item(mq_tree, hf_mq_tsh_reasoncode, tvb, offset + 32, 4, bLittleEndian);	
				}
			}
			offset += iSizeTSH;

			/* Now dissect the embedded structures */
			if (tvb_length_remaining(tvb, offset) >= 4)
			{
				structId = tvb_get_ntohl(tvb, offset);
				if (opcode == MQ_TST_MQCONN && tvb_length_remaining(tvb, offset) >= 112)
				{
					gint iSizeCONN = 0;
					/* The MQCONN structure is special because it does not start with a structid */
					if (check_col(pinfo->cinfo, COL_INFO)) 
					{
						guint8* sApplicationName;
						guint8* sQueueManager;
						sApplicationName = tvb_get_string(tvb, offset + 48, 28);
						if (strip_trailing_blanks(sApplicationName, 28) != 0)
						{
							col_append_fstr(pinfo->cinfo, COL_INFO, ": by application %s", sApplicationName);
						}
						sQueueManager = tvb_get_string(tvb, offset, 48);
						if (strip_trailing_blanks(sQueueManager, 48) != 0)
						{
							col_append_fstr(pinfo->cinfo, COL_INFO, " to queue manager %s", sQueueManager);
						}
					}

					/*iSizeCONN = ((iVersionID == 4 || iVersionID == 6) ? 120 : 112);*/ /* guess */
					/* The iVersionID is available in the previous ID segment, we should keep a state */	
					iSizeCONN = 112;
	
					if (tree)
					{
						ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSizeCONN, MQ_TEXT_CONN);
						mq_tree = proto_item_add_subtree(ti, ett_mq_conn);

						proto_tree_add_item(mq_tree, hf_mq_conn_queuemanager, tvb, offset, 48, FALSE);
						proto_tree_add_item(mq_tree, hf_mq_conn_putapplname, tvb, offset + 48, 28, FALSE);
						proto_tree_add_item(mq_tree, hf_mq_conn_unknown1, tvb, offset + 76, 4, FALSE);
						proto_tree_add_item(mq_tree, hf_mq_conn_acttoken, tvb, offset + 80, 32, FALSE);
					}
						
					if (tvb_length_remaining(tvb, offset) >= 120)
					{						
						iSizeCONN = 120;
						if (tree)
						{
							proto_tree_add_item(mq_tree, hf_mq_conn_unknown2, tvb, offset + 112, 4, bLittleEndian);				
							proto_tree_add_item(mq_tree, hf_mq_conn_unknown3, tvb, offset + 116, 4, bLittleEndian);				
						}
					}
					offset += iSizeCONN;
				}
				else if ((structId == MQ_STRUCTID_ID || structId == MQ_STRUCTID_ID_EBCDIC) && tvb_length_remaining(tvb, offset) >= 44)
				{
					guint8 iVersionID = 0;
					gint iSizeID = 0;
					iVersionID = tvb_get_guint8(tvb, offset + 4);		
					iSizeID = (iVersionID < 4 ? 44 : 104); /* guess */
					/* actually 102 but must be aligned to multiple of 4 */
	
					if (check_col(pinfo->cinfo, COL_INFO)) 
					{
						guint8* sChannel;
						sChannel = tvb_get_string(tvb, offset + 24, 20);
						if (strip_trailing_blanks(sChannel, 20) != 0)
						{
							col_append_fstr(pinfo->cinfo, COL_INFO, ": via channel %s", sChannel);
						}
					}
	
					if (tree)
					{	
						ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSizeID, MQ_TEXT_ID);
						mq_tree = proto_item_add_subtree(ti, ett_mq_id);
		
						proto_tree_add_item(mq_tree, hf_mq_id_structid, tvb, offset, 4, FALSE);
						proto_tree_add_item(mq_tree, hf_mq_id_level, tvb, offset + 4, 1, FALSE);
						proto_tree_add_item(mq_tree, hf_mq_id_flags, tvb, offset + 5, 1, FALSE);
						proto_tree_add_item(mq_tree, hf_mq_id_unknown2, tvb, offset + 6, 1, FALSE);

						/* Error flags */
						{
							proto_tree	*mq_tree_sub = NULL;
							guint8 iErrorFlags;
		
							ti = proto_tree_add_item(mq_tree, hf_mq_id_ieflags, tvb, offset + 7, 1, FALSE);
							mq_tree_sub = proto_item_add_subtree(ti, ett_mq_id_ief);
							iErrorFlags = tvb_get_guint8(tvb, offset + 7);	

							proto_tree_add_boolean(mq_tree_sub, hf_mq_id_ief_hbint, tvb, offset + 7, 1, iErrorFlags);
							proto_tree_add_boolean(mq_tree_sub, hf_mq_id_ief_seqwrap, tvb, offset + 7, 1, iErrorFlags);
							proto_tree_add_boolean(mq_tree_sub, hf_mq_id_ief_mxmsgpb, tvb, offset + 7, 1, iErrorFlags);
							proto_tree_add_boolean(mq_tree_sub, hf_mq_id_ief_mxmsgsz, tvb, offset + 7, 1, iErrorFlags);
							proto_tree_add_boolean(mq_tree_sub, hf_mq_id_ief_fap, tvb, offset + 7, 1, iErrorFlags);
							proto_tree_add_boolean(mq_tree_sub, hf_mq_id_ief_mxtrsz, tvb, offset + 7, 1, iErrorFlags);
							proto_tree_add_boolean(mq_tree_sub, hf_mq_id_ief_enc, tvb, offset + 7, 1, iErrorFlags);							
							proto_tree_add_boolean(mq_tree_sub, hf_mq_id_ief_ccsid, tvb, offset + 7, 1, iErrorFlags);
						}


						proto_tree_add_item(mq_tree, hf_mq_id_unknown4, tvb, offset + 8, 2, FALSE);
						proto_tree_add_item(mq_tree, hf_mq_id_maxmsgperbatch, tvb, offset + 10, 2, bLittleEndian);
						proto_tree_add_item(mq_tree, hf_mq_id_maxtransmissionsize, tvb, offset + 12, 4, bLittleEndian);
						proto_tree_add_item(mq_tree, hf_mq_id_maxmsgsize, tvb, offset + 16, 4, bLittleEndian);
						proto_tree_add_item(mq_tree, hf_mq_id_sequencewrapvalue, tvb, offset + 20, 4, bLittleEndian);
						proto_tree_add_item(mq_tree, hf_mq_id_channel, tvb, offset + 24, 20, FALSE);
					}
						
					if (iSizeID == 104 && tvb_length_remaining(tvb, offset) >= 104)
					{
						if (check_col(pinfo->cinfo, COL_INFO)) 
						{
							guint8* sQueueManager;
							sQueueManager = tvb_get_string(tvb, offset + 48, 48);
							if (strip_trailing_blanks(sQueueManager,48) != 0)
							{
								col_append_fstr(pinfo->cinfo, COL_INFO, " to queue manager %s", sQueueManager);
							}
						}
	
						if (tree)
						{
							proto_tree_add_item(mq_tree, hf_mq_id_flags2, tvb, offset + 44, 1, FALSE);
							proto_tree_add_item(mq_tree, hf_mq_id_unknown5, tvb, offset + 45, 1, FALSE);
							proto_tree_add_item(mq_tree, hf_mq_id_ccsid, tvb, offset + 46, 2, bLittleEndian);
							proto_tree_add_item(mq_tree, hf_mq_id_queuemanager, tvb, offset + 48, 48, FALSE);
							proto_tree_add_item(mq_tree, hf_mq_id_heartbeatinterval, tvb, offset + 96, 4, bLittleEndian);
						}
	
					}
					offset += iSizeID;
				}			
				else if ((structId == MQ_STRUCTID_UID || structId == MQ_STRUCTID_UID_EBCDIC) && tvb_length_remaining(tvb, offset) >= 28)
				{
					guint8 iVersionUID = 0;
					gint iSizeUID = 0;
					if (check_col(pinfo->cinfo, COL_INFO)) 
					{
						guint8* sUserId;
						sUserId = tvb_get_string(tvb, offset + 4, 12);
						if (strip_trailing_blanks(sUserId, 12) != 0)
						{
							col_append_fstr(pinfo->cinfo, COL_INFO, ": user %s", sUserId);
						}
					}
	
					/* iSizeUID = (iVersionID < 5 ? 28 : 132);  guess */
					/* The iVersionID is available in the previous ID segment, we should keep a state */
					iSizeUID = 28;
					if (tree)
					{
						ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSizeUID, MQ_TEXT_UID);
						mq_tree = proto_item_add_subtree(ti, ett_mq_uid);
			
						proto_tree_add_item(mq_tree, hf_mq_uid_structid, tvb, offset, 4, FALSE);
						proto_tree_add_item(mq_tree, hf_mq_uid_userid, tvb, offset + 4, 12, FALSE);
						proto_tree_add_item(mq_tree, hf_mq_uid_password, tvb, offset + 16, 12, FALSE);
					}
							
					if (tvb_length_remaining(tvb, offset) >= 132)
					{				
						iSizeUID = 132;
						if (tree)
						{
							proto_tree_add_item(mq_tree, hf_mq_uid_longuserid, tvb, offset + 28, 64, FALSE);
							proto_tree_add_item(mq_tree, hf_mq_uid_securityid, tvb, offset + 92, 40, FALSE);
						}
					}
					offset += iSizeUID;
				}
				else if ((structId == MQ_STRUCTID_OD || structId == MQ_STRUCTID_OD_EBCDIC) && tvb_length_remaining(tvb, offset) >= 168)
				{
					guint8 iVersionOD = 0;
					gint iSizeOD = 0;
					/* Compute length according to version */
					if (bLittleEndian)
						iVersionOD = tvb_get_letohl(tvb, offset + 4);
					else
						iVersionOD =  tvb_get_ntohl(tvb, offset + 4);
					switch (iVersionOD) 
					{
						case 1: iSizeOD = 168; break;		
						case 2: iSizeOD = 200; break;	
						case 3: iSizeOD = 336; break;
					}
					
					if (check_col(pinfo->cinfo, COL_INFO)) 
					{
						guint8* sQueue;
						sQueue = tvb_get_string(tvb, offset + 12, 48);
						if (strip_trailing_blanks(sQueue,48) != 0)
						{
							col_append_fstr(pinfo->cinfo, COL_INFO, " for object %s", sQueue);
						}
					}
	
					if (tree)
					{
						ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSizeOD, MQ_TEXT_OD);
						mq_tree = proto_item_add_subtree(ti, ett_mq_od);
		
						proto_tree_add_item(mq_tree, hf_mq_od_structid, tvb, offset, 4, FALSE);
						proto_tree_add_item(mq_tree, hf_mq_od_version, tvb, offset + 4, 4, bLittleEndian);
						proto_tree_add_item(mq_tree, hf_mq_od_objecttype, tvb, offset + 8, 4, bLittleEndian);
						proto_tree_add_item(mq_tree, hf_mq_od_objectname, tvb, offset + 12, 48, FALSE);
						proto_tree_add_item(mq_tree, hf_mq_od_objectqmgrname, tvb, offset + 60, 48, FALSE);
						proto_tree_add_item(mq_tree, hf_mq_od_dynamicqname, tvb, offset + 108, 48, FALSE);
						proto_tree_add_item(mq_tree, hf_mq_od_alternateuserid, tvb, offset + 156, 12, FALSE);

						if (iSizeOD >= 200 && tvb_length_remaining(tvb, offset) >= 200)
						{
							proto_tree_add_item(mq_tree, hf_mq_od_recspresent, tvb, offset + 168, 4, bLittleEndian);
							proto_tree_add_item(mq_tree, hf_mq_od_knowndestcount, tvb, offset + 172, 4, bLittleEndian);
							proto_tree_add_item(mq_tree, hf_mq_od_unknowndestcount, tvb, offset + 176, 4, bLittleEndian);
							proto_tree_add_item(mq_tree, hf_mq_od_invaliddestcount, tvb, offset + 180, 4, bLittleEndian);
							proto_tree_add_item(mq_tree, hf_mq_od_objectrecoffset, tvb, offset + 184, 4, bLittleEndian);
							proto_tree_add_item(mq_tree, hf_mq_od_responserecoffset, tvb, offset + 188, 4, bLittleEndian);
							proto_tree_add_item(mq_tree, hf_mq_od_objectrecptr, tvb, offset + 192, 4, bLittleEndian);
							proto_tree_add_item(mq_tree, hf_mq_od_responserecptr, tvb, offset + 196, 4, bLittleEndian);
						}

						if (iSizeOD >= 336 && tvb_length_remaining(tvb, offset) >= 336)
						{
							proto_tree_add_item(mq_tree, hf_mq_od_alternatesecurityid, tvb, offset + 200, 40, FALSE);
							proto_tree_add_item(mq_tree, hf_mq_od_resolvedqname, tvb, offset + 240, 48, FALSE);
							proto_tree_add_item(mq_tree, hf_mq_od_resolvedqmgrname, tvb, offset + 288, 48, FALSE);
						}

					}
					offset += iSizeOD;
				}
				else if ((structId == MQ_STRUCTID_MD || structId == MQ_STRUCTID_MD_EBCDIC) && tvb_length_remaining(tvb, offset) >= 324)
				{
					guint8 iVersionMD = 0;
					gint iSizeMD = 0;
					/* Compute length according to version */
					if (bLittleEndian)
						iVersionMD = tvb_get_letohl(tvb, offset + 4);
					else
						iVersionMD =  tvb_get_ntohl(tvb, offset + 4);
					switch (iVersionMD) 
					{
						case 1: iSizeMD = 324; break;		
						case 2: iSizeMD = 364; break;
					}
	
					if (tree)
					{
						ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSizeMD, MQ_TEXT_MD);
						mq_tree = proto_item_add_subtree(ti, ett_mq_md);
		
						proto_tree_add_item(mq_tree, hf_mq_md_structid, tvb, offset, 4, FALSE);
						proto_tree_add_item(mq_tree, hf_mq_md_version, tvb, offset + 4, 4, bLittleEndian);
						proto_tree_add_item(mq_tree, hf_mq_md_report, tvb, offset + 8, 4, bLittleEndian);
						proto_tree_add_item(mq_tree, hf_mq_md_msgtype, tvb, offset + 12, 4, bLittleEndian);
						proto_tree_add_item(mq_tree, hf_mq_md_expiry, tvb, offset + 16, 4, bLittleEndian);
						proto_tree_add_item(mq_tree, hf_mq_md_feedback, tvb, offset + 20, 4, bLittleEndian);
						proto_tree_add_item(mq_tree, hf_mq_md_encoding, tvb, offset + 24, 4, bLittleEndian);
						proto_tree_add_item(mq_tree, hf_mq_md_ccsid, tvb, offset + 28, 4, bLittleEndian);
						proto_tree_add_item(mq_tree, hf_mq_md_format, tvb, offset + 32, 8, FALSE);
						proto_tree_add_item(mq_tree, hf_mq_md_priority, tvb, offset + 40, 4, bLittleEndian);
						proto_tree_add_item(mq_tree, hf_mq_md_persistence, tvb, offset + 44, 4, bLittleEndian);
						proto_tree_add_item(mq_tree, hf_mq_md_msgid, tvb, offset + 48, 24, FALSE);
						proto_tree_add_item(mq_tree, hf_mq_md_correlid, tvb, offset + 72, 24, FALSE);
						proto_tree_add_item(mq_tree, hf_mq_md_backountcount, tvb, offset + 96, 4, bLittleEndian);
						proto_tree_add_item(mq_tree, hf_mq_md_replytoq, tvb, offset + 100, 48, FALSE);
						proto_tree_add_item(mq_tree, hf_mq_md_replytoqmgr, tvb, offset + 148, 48, FALSE);
						proto_tree_add_item(mq_tree, hf_mq_md_userid, tvb, offset + 196, 12, FALSE);
						proto_tree_add_item(mq_tree, hf_mq_md_acttoken, tvb, offset + 208, 32, FALSE);
						proto_tree_add_item(mq_tree, hf_mq_md_appliddata, tvb, offset + 240, 32, FALSE);
						proto_tree_add_item(mq_tree, hf_mq_md_putappltype, tvb, offset + 272, 4, bLittleEndian);
						proto_tree_add_item(mq_tree, hf_mq_md_putapplname, tvb, offset + 276, 28, FALSE);
						proto_tree_add_item(mq_tree, hf_mq_md_putdate, tvb, offset + 304, 8, FALSE);
						proto_tree_add_item(mq_tree, hf_mq_md_puttime, tvb, offset + 312, 8, FALSE);
						proto_tree_add_item(mq_tree, hf_mq_md_applorigindata, tvb, offset + 320, 4, FALSE);
						
						if (iSizeMD == 364 && tvb_length_remaining(tvb, offset) >= 364)
						{				
							proto_tree_add_item(mq_tree, hf_mq_md_groupid, tvb, offset + 324, 24, FALSE);
							proto_tree_add_item(mq_tree, hf_mq_md_msgseqnumber, tvb, offset + 348, 4, bLittleEndian);
							proto_tree_add_item(mq_tree, hf_mq_md_offset, tvb, offset + 352, 4, bLittleEndian);
							proto_tree_add_item(mq_tree, hf_mq_md_msgflags, tvb, offset + 356, 4, bLittleEndian);
							proto_tree_add_item(mq_tree, hf_mq_md_originallength, tvb, offset + 360, 4, bLittleEndian);
						}
					}
					offset += iSizeMD;
					/* Now dissect the embedded structures */
					if (tvb_length_remaining(tvb, offset) >= 4)
					{
						structId = tvb_get_ntohl(tvb, offset);

						if ((structId == MQ_STRUCTID_GMO || structId == MQ_STRUCTID_GMO_EBCDIC) && tvb_length_remaining(tvb, offset) >= 72)
						{
							guint8 iVersionGMO = 0;
							gint iSizeGMO = 0;
							/* Compute length according to version */
							if (bLittleEndian)
								iVersionGMO = tvb_get_letohl(tvb, offset + 4);
							else
								iVersionGMO =  tvb_get_ntohl(tvb, offset + 4);
							switch (iVersionGMO) 
							{
								case 1: iSizeGMO = 72; break;		
								case 2: iSizeGMO = 80; break;	
								case 3: iSizeGMO = 100; break;
							}
							
							if (check_col(pinfo->cinfo, COL_INFO)) 
							{
								guint8* sQueue;
								sQueue = tvb_get_string(tvb, offset + 24, 48);
								if (strip_trailing_blanks(sQueue, 48) != 0)
								{
									col_append_fstr(pinfo->cinfo, COL_INFO, " for queue %s", sQueue);
								}
							}

							if (tree)
							{
								ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSizeGMO, MQ_TEXT_GMO);
								mq_tree = proto_item_add_subtree(ti, ett_mq_gmo);
				
								proto_tree_add_item(mq_tree, hf_mq_gmo_structid, tvb, offset, 4, FALSE);
								proto_tree_add_item(mq_tree, hf_mq_gmo_version, tvb, offset + 4, 4, bLittleEndian);
								proto_tree_add_item(mq_tree, hf_mq_gmo_options, tvb, offset + 8, 4, bLittleEndian);
								proto_tree_add_item(mq_tree, hf_mq_gmo_waitinterval, tvb, offset + 12, 4, bLittleEndian);
								proto_tree_add_item(mq_tree, hf_mq_gmo_signal1, tvb, offset + 16, 4, bLittleEndian);
								proto_tree_add_item(mq_tree, hf_mq_gmo_signal2, tvb, offset + 20, 4, bLittleEndian);
								proto_tree_add_item(mq_tree, hf_mq_gmo_resolvedqname, tvb, offset + 24, 48, FALSE);

								if (iSizeGMO >= 80 && tvb_length_remaining(tvb, offset) >= 80)
								{
									proto_tree_add_item(mq_tree, hf_mq_gmo_matchoptions, tvb, offset + 72, 4, FALSE);
									proto_tree_add_item(mq_tree, hf_mq_gmo_groupstatus, tvb, offset + 76, 1, FALSE);
									proto_tree_add_item(mq_tree, hf_mq_gmo_segmentstatus, tvb, offset + 77, 1, FALSE);
									proto_tree_add_item(mq_tree, hf_mq_gmo_segmentation, tvb, offset + 78, 1, FALSE);
									proto_tree_add_item(mq_tree, hf_mq_gmo_reserved, tvb, offset + 79, 1, FALSE);
								}

								if (iSizeGMO >= 100 && tvb_length_remaining(tvb, offset) >= 100)
								{
									proto_tree_add_item(mq_tree, hf_mq_gmo_msgtoken, tvb, offset + 80, 16, FALSE);
									proto_tree_add_item(mq_tree, hf_mq_gmo_returnedlength, tvb, offset + 96, 4, bLittleEndian);
								}
							}
							offset += iSizeGMO;
							bPayload = TRUE;
						}
						else if ((structId == MQ_STRUCTID_PMO || structId == MQ_STRUCTID_PMO_EBCDIC) && tvb_length_remaining(tvb, offset) >= 128)
						{
							guint8 iVersionPMO = 0;
							gint iSizePMO = 0;
							/* Compute length according to version */
							if (bLittleEndian)
								iVersionPMO = tvb_get_letohl(tvb, offset + 4);
							else
								iVersionPMO =  tvb_get_ntohl(tvb, offset + 4);
							switch (iVersionPMO) 
							{
								case 1: iSizePMO = 128; break;		
								case 2: iSizePMO = 152; break;	
							}
							
							if (check_col(pinfo->cinfo, COL_INFO)) 
							{
								guint8* sQueue;
								sQueue = tvb_get_string(tvb, offset + 32, 48);
								if (strip_trailing_blanks(sQueue, 48) != 0)
								{
									col_append_fstr(pinfo->cinfo, COL_INFO, " for queue %s", sQueue);
								}
							}

							if (tree)
							{
								ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSizePMO, MQ_TEXT_PMO);
								mq_tree = proto_item_add_subtree(ti, ett_mq_pmo);
								proto_tree_add_item(mq_tree, hf_mq_pmo_structid, tvb, offset, 4, FALSE);
								proto_tree_add_item(mq_tree, hf_mq_pmo_version, tvb, offset + 4, 4, bLittleEndian);
								proto_tree_add_item(mq_tree, hf_mq_pmo_options, tvb, offset + 8, 4, bLittleEndian);
								proto_tree_add_item(mq_tree, hf_mq_pmo_timeout, tvb, offset + 12, 4, bLittleEndian);
								proto_tree_add_item(mq_tree, hf_mq_pmo_context, tvb, offset + 16, 4, bLittleEndian);
								proto_tree_add_item(mq_tree, hf_mq_pmo_knowndestcount, tvb, offset + 20, 4, bLittleEndian);
								proto_tree_add_item(mq_tree, hf_mq_pmo_unknowndestcount, tvb, offset + 24, 4, bLittleEndian);
								proto_tree_add_item(mq_tree, hf_mq_pmo_invaliddestcount, tvb, offset + 28, 4, bLittleEndian);
								proto_tree_add_item(mq_tree, hf_mq_pmo_resolvedqname, tvb, offset + 32, 48, FALSE);
								proto_tree_add_item(mq_tree, hf_mq_pmo_resolvedqmgrname, tvb, offset + 80, 48, FALSE);

								if (iSizePMO >= 152 && tvb_length_remaining(tvb, offset) >= 152)
								{
									proto_tree_add_item(mq_tree, hf_mq_pmo_recspresent, tvb, offset + 128, 4, bLittleEndian);
									proto_tree_add_item(mq_tree, hf_mq_pmo_putmsgrecfields, tvb, offset + 132, 4, bLittleEndian);
									proto_tree_add_item(mq_tree, hf_mq_pmo_putmsgrecoffset, tvb, offset + 136, 4, bLittleEndian);
									proto_tree_add_item(mq_tree, hf_mq_pmo_responserecoffset, tvb, offset + 140, 4, bLittleEndian);
									proto_tree_add_item(mq_tree, hf_mq_pmo_putmsgrecptr, tvb, offset + 144, 4, bLittleEndian);
									proto_tree_add_item(mq_tree, hf_mq_pmo_responserecptr, tvb, offset + 148, 4, bLittleEndian);
								}

							}
							offset += iSizePMO;
							bPayload = TRUE;
						}
						if (bPayload)
						{
							/* Now dissect the payload */
							gint sizeBUFF = 0;
							/* Compute length according to endian */
							if (bLittleEndian)
								sizeBUFF = tvb_get_letohl(tvb, offset);
							else
								sizeBUFF =  tvb_get_ntohl(tvb, offset);

							if (tree)
							{
								ti = proto_tree_add_text(mqroot_tree, tvb, offset, -1, MQ_TEXT_BUFF);
								mq_tree = proto_item_add_subtree(ti, ett_mq_buffer);
								proto_tree_add_item(mq_tree, hf_mq_buffer_length, tvb, offset, 4, bLittleEndian);
							}
							
							if (sizeBUFF != 0 && tvb_length_remaining(tvb, offset) > 4)
							{
								if (check_col(pinfo->cinfo, COL_INFO)) 
									col_append_fstr(pinfo->cinfo, COL_INFO, " (%d bytes)", sizeBUFF);		

								/* At this point we could call another dissector, but the MQ middleware
								   does not really have a standard out-of-band information like the TCP port
								   which is centrally registered and that allows to know which format
								   the application messages are.
								*/
									
								if (tree)
								{
									proto_tree_add_item(mq_tree, hf_mq_buffer_data, tvb, offset + 4, -1, FALSE);
									/* Add a tree for the payload */
									ti = proto_tree_add_text(tree, tvb, offset + 4, -1, MQ_TEXT_DATA);								
									proto_item_append_text(ti, " (%d bytes)", sizeBUFF);
								}
							}
							offset = tvb_reported_length(tvb);
						}
					}
				}
			}
			/* After all recognised structures have been dissected, process remaining structure*/
			if (tvb_length_remaining(tvb, offset) >= 4)
			{
				structId = tvb_get_ntohl(tvb, offset);
				if (tree)
				{
					ti = proto_tree_add_text(mqroot_tree, tvb, offset, -1, val_to_str(structId, mq_structid_vals, "Unknown (0x%08x)"));								
				}
			}
		}
		else
		{
			/* This packet is a continuation of a segment */
			if (check_col(pinfo->cinfo, COL_INFO)) col_set_str(pinfo->cinfo, COL_INFO, "Continuation");		
			if (tree)
			{
				ti = proto_tree_add_item(tree, proto_mq, tvb, offset, -1, FALSE);
				ti = proto_tree_add_text(tree, tvb, offset, -1, MQ_TEXT_DATA);								
			}
		}
	}
}

static gboolean
dissect_mq_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if (tvb_reported_length(tvb) >= 28)
	{
		guint32 structId;
		guint32 iLength;
		guint8 cEndian;
		structId = tvb_get_ntohl(tvb, 0);
		iLength = tvb_get_ntohl(tvb, 4);
		cEndian = tvb_get_guint8(tvb, 8);

		if ((structId == MQ_STRUCTID_TSH || structId == MQ_STRUCTID_TSH_EBCDIC) 
			&& (cEndian == MQ_LITTLE_ENDIAN || cEndian == MQ_BIG_ENDIAN)
			&& iLength == tvb_reported_length(tvb))
		{
			dissect_mq(tvb, pinfo, tree);
			return TRUE;
		}
	}
	return FALSE;
}

void
proto_register_mq(void)
{
  static hf_register_info hf[] = {
   { &hf_mq_tsh_structid,
      { "TSH structid", "mq.tsh.structid", FT_STRINGZ, BASE_DEC, NULL, 0x0, "TSH structid", HFILL }},

    { &hf_mq_tsh_packetlength,
      { "MQ Segment length", "mq.tsh.seglength", FT_UINT32, BASE_DEC, NULL, 0x0, "TSH MQ Segment length", HFILL }},

    { &hf_mq_tsh_byteorder,
      { "Byte order", "mq.tsh.byteorder", FT_UINT8, BASE_HEX, VALS(mq_byteorder_vals), 0x0, "TSH Byte order", HFILL }},

    { &hf_mq_tsh_opcode,
      { "Segment type", "mq.tsh.type", FT_UINT8, BASE_HEX, VALS(mq_opcode_vals), 0x0, "TSH MQ segment type", HFILL }},

    { &hf_mq_tsh_controlflags,
      { "Control flags", "mq.tsh.cflags", FT_UINT8, BASE_HEX, NULL, 0x0, "TSH Control flags", HFILL }},

    { &hf_mq_tsh_unknown2,
      { "Unknown2", "mq.tsh.unknown2", FT_UINT8, BASE_HEX, NULL, 0x0, "TSH Unknown2", HFILL }},
      	
    { &hf_mq_tsh_luwid,
      { "Logical unit of work identifier", "mq.tsh.luwid", FT_BYTES, BASE_HEX, NULL, 0x0, "TSH logical unit of work identifier", HFILL }},
      	
    { &hf_mq_tsh_encoding,
      { "Encoding", "mq.tsh.encoding", FT_UINT32, BASE_DEC, NULL, 0x0, "TSH Encoding", HFILL }},

    { &hf_mq_tsh_ccsid,
      { "Character set", "mq.tsh.ccsid", FT_UINT32, BASE_DEC, NULL, 0x0, "TSH CCSID", HFILL }},
      	
    { &hf_mq_tsh_unknown4,
      { "Unknown4", "mq.tsh.unknown4", FT_UINT16, BASE_HEX, NULL, 0x0, "TSH Unknown4", HFILL }},

    { &hf_mq_tsh_length,
      { "Length", "mq.tsh.length", FT_UINT32, BASE_DEC, NULL, 0x0, "TSH Length", HFILL }},

    { &hf_mq_tsh_completioncode,
      { "Completion code", "mq.tsh.completioncode", FT_UINT32, BASE_DEC, NULL, 0x0, "TSH Completion code", HFILL }},

    { &hf_mq_tsh_reasoncode,
      { "Reason code", "mq.tsh.reasoncode", FT_UINT32, BASE_DEC, NULL, 0x0, "TSH Reason code", HFILL }},

    { &hf_mq_tsh_queuehandle,
      { "Queue handle", "mq.tsh.queuehandle", FT_UINT32, BASE_HEX, NULL, 0x0, "TSH Queue handle", HFILL }},

    { &hf_mq_tsh_tcf_confirmreq,
      { "Confirm request", "mq.tsh.tcf.confirmreq", FT_BOOLEAN, 8, TFS(&flags_set_truth), MQ_TCF_CONFIRM_REQUEST, "TSH TCF Confirm request", HFILL }},

    { &hf_mq_tsh_tcf_error,
      { "Error", "mq.tsh.tcf.error", FT_BOOLEAN, 8, TFS(&flags_set_truth), MQ_TCF_ERROR, "TSH TCF Error", HFILL }},

    { &hf_mq_tsh_tcf_reqclose,
      { "Request close", "mq.tsh.tcf.reqclose", FT_BOOLEAN, 8, TFS(&flags_set_truth), MQ_TCF_REQUEST_CLOSE, "TSH TCF Request close", HFILL }},

    { &hf_mq_tsh_tcf_closechann,
      { "Close channel", "mq.tsh.tcf.closechann", FT_BOOLEAN, 8, TFS(&flags_set_truth), MQ_TCF_CLOSE_CHANNEL, "TSH TCF Close channel", HFILL }},

    { &hf_mq_tsh_tcf_first,
      { "First", "mq.tsh.tcf.first", FT_BOOLEAN, 8, TFS(&flags_set_truth), MQ_TCF_FIRST, "TSH TCF First", HFILL }},

    { &hf_mq_tsh_tcf_last,
      { "Last", "mq.tsh.tcf.last", FT_BOOLEAN, 8, TFS(&flags_set_truth), MQ_TCF_LAST, "TSH TCF Last", HFILL }},

    { &hf_mq_id_structid,
      { "ID structid", "mq.id.structid", FT_STRINGZ, BASE_DEC, NULL, 0x0, "ID structid", HFILL }},

    { &hf_mq_id_level,
      { "FAP level", "mq.id.level", FT_UINT8, BASE_DEC, NULL, 0x0, "ID FAP level", HFILL }},

    { &hf_mq_id_flags,
      { "Flags", "mq.id.flags", FT_UINT8, BASE_HEX, NULL, 0x0, "ID flags", HFILL }},

    { &hf_mq_id_unknown2,
      { "Unknown2", "mq.id.unknown2", FT_UINT8, BASE_HEX, NULL, 0x0, "ID unknown2", HFILL }},

    { &hf_mq_id_ieflags,
      { "Initial error flags", "mq.id.ief", FT_UINT8, BASE_HEX, NULL, 0x0, "ID initial error flags", HFILL }},

    { &hf_mq_id_unknown4,
      { "Unknown4", "mq.id.unknown4", FT_UINT16, BASE_HEX, NULL, 0x0, "ID unknown4", HFILL }},

    { &hf_mq_id_maxmsgperbatch,
      { "Maximum messages per batch", "mq.id.maxmsgperbatch", FT_UINT16, BASE_DEC, NULL, 0x0, "ID max msg per batch", HFILL }},

    { &hf_mq_id_maxtransmissionsize,
      { "Maximum transmission size", "mq.id.maxtranssize", FT_UINT32, BASE_DEC, NULL, 0x0, "ID max trans size", HFILL }},

    { &hf_mq_id_maxmsgsize,
      { "Maximum message size", "mq.id.maxmsgsize", FT_UINT32, BASE_DEC, NULL, 0x0, "ID max msg size", HFILL }},

    { &hf_mq_id_sequencewrapvalue,
      { "Sequence wrap value", "mq.id.seqwrap", FT_UINT32, BASE_HEX, NULL, 0x0, "ID seq wrap value", HFILL }},

    { &hf_mq_id_channel,
      { "Channel name", "mq.id.channelname", FT_STRINGZ, BASE_HEX, NULL, 0x0, "ID channel name", HFILL }},

    { &hf_mq_id_flags2,
      { "Flags2", "mq.id.flags2", FT_UINT8, BASE_HEX, NULL, 0x0, "ID flags2", HFILL }},

    { &hf_mq_id_unknown5,
      { "Unknown5", "mq.id.unknown5", FT_UINT8, BASE_HEX, NULL, 0x0, "ID unknown5", HFILL }},

    { &hf_mq_id_ccsid,
      { "Character set", "mq.id.ccsid", FT_UINT16, BASE_DEC, NULL, 0x0, "ID unknown5", HFILL }},

    { &hf_mq_id_queuemanager,
      { "Queue manager", "mq.id.qm", FT_STRINGZ, BASE_HEX, NULL, 0x0, "Queue manager", HFILL }},

    { &hf_mq_id_heartbeatinterval,
      { "Heartbeat interval", "mq.id.hbint", FT_UINT32, BASE_DEC, NULL, 0x0, "Heartbeat interval", HFILL }},

    { &hf_mq_id_unknown6,
      { "Unknown6", "mq.id.unknown6", FT_UINT16, BASE_HEX, NULL, 0x0, "ID unknown6", HFILL }},

    { &hf_mq_id_ief_ccsid,
      { "Invalid CCSID", "mq.id.ief.ccsid", FT_BOOLEAN, 8, TFS(&flags_set_truth), MQ_IEF_CCSID, "ID invalid CCSID", HFILL }},

    { &hf_mq_id_ief_enc,
      { "Invalid encoding", "mq.id.ief.enc", FT_BOOLEAN, 8, TFS(&flags_set_truth), MQ_IEF_ENCODING, "ID invalid encoding", HFILL }},

    { &hf_mq_id_ief_mxtrsz,
      { "Invalid maximum transmission size", "mq.id.ief.mxtrsz", FT_BOOLEAN, 8, TFS(&flags_set_truth), MQ_IEF_MAX_TRANSMISSION_SIZE, "ID invalid maximum transmission size", HFILL }},

    { &hf_mq_id_ief_fap,
      { "Invalid FAP level", "mq.id.ief.fap", FT_BOOLEAN, 8, TFS(&flags_set_truth), MQ_IEF_FAP_LEVEL, "ID invalid FAP level", HFILL }},

    { &hf_mq_id_ief_mxmsgsz,
      { "Invalid message size", "mq.id.ief.mxmsgsz", FT_BOOLEAN, 8, TFS(&flags_set_truth), MQ_IEF_MAX_MSG_SIZE, "ID invalid message size", HFILL }},

    { &hf_mq_id_ief_mxmsgpb,
      { "Invalid maximum message per batch", "mq.id.ief.mxmsgpb", FT_BOOLEAN, 8, TFS(&flags_set_truth), MQ_IEF_MAX_MSG_PER_BATCH, "ID maximum message per batch", HFILL }},

    { &hf_mq_id_ief_seqwrap,
      { "Invalid sequence wrap value", "mq.id.ief.seqwrap", FT_BOOLEAN, 8, TFS(&flags_set_truth), MQ_IEF_SEQ_WRAP_VALUE, "ID invalid sequence wrap value", HFILL }},

    { &hf_mq_id_ief_hbint,
      { "Invalid heartbeat interval", "mq.id.ief.hbint", FT_BOOLEAN, 8, TFS(&flags_set_truth), MQ_IEF_HEARTBEAT_INTERVAL, "ID invalid heartbeat interval", HFILL }},

    { &hf_mq_uid_structid,
      { "UID structid", "mq.uid.structid", FT_STRINGZ, BASE_HEX, NULL, 0x0, "UID structid", HFILL }},

    { &hf_mq_uid_userid,
      { "User ID", "mq.uid.userid", FT_STRINGZ, BASE_HEX, NULL, 0x0, "UID structid", HFILL }},

    { &hf_mq_uid_password,
      { "Password", "mq.uid.password", FT_STRINGZ, BASE_HEX, NULL, 0x0, "UID password", HFILL }},

    { &hf_mq_uid_longuserid,
      { "Long User ID", "mq.uid.longuserid", FT_STRINGZ, BASE_HEX, NULL, 0x0, "UID long user id", HFILL }},

    { &hf_mq_uid_securityid,
      { "Security ID", "mq.uid.securityid", FT_BYTES, BASE_HEX, NULL, 0x0, "UID security id", HFILL }},

    { &hf_mq_conn_queuemanager,
      { "Queue manager", "mq.conn.qm", FT_STRINGZ, BASE_HEX, NULL, 0x0, "CONN queue manager", HFILL }},

    { &hf_mq_conn_putapplname,
      { "Put Application name", "mq.conn.app", FT_STRINGZ, BASE_HEX, NULL, 0x0, "CONN put application name", HFILL }},

    { &hf_mq_conn_unknown1,
      { "Unknown1", "mq.conn.unknown1", FT_UINT32, BASE_HEX, NULL, 0x0, "CONN unknown1", HFILL }},

    { &hf_mq_conn_acttoken,
      { "Accounting token", "mq.conn.acttoken", FT_BYTES, BASE_HEX, NULL, 0x0, "CONN accounting token", HFILL }},

    { &hf_mq_conn_unknown2,
      { "Unknown2", "mq.conn.unknown2", FT_UINT32, BASE_HEX, NULL, 0x0, "CONN unknown2", HFILL }},

    { &hf_mq_conn_unknown3,
      { "Unknown3", "mq.conn.unknown3", FT_UINT32, BASE_HEX, NULL, 0x0, "CONN unknown3", HFILL }},

    { &hf_mq_od_structid,
      { "OD structid", "mq.od.structid", FT_STRINGZ, BASE_HEX, NULL, 0x0, "OD structid", HFILL }},

    { &hf_mq_od_version,
      { "Version", "mq.od.version", FT_UINT32, BASE_DEC, NULL, 0x0, "OD version", HFILL }},

    { &hf_mq_od_objecttype,
      { "Object type", "mq.od.objtype", FT_UINT32, BASE_DEC, NULL, 0x0, "OD object type", HFILL }},

    { &hf_mq_od_objectname,
      { "Object name", "mq.od.objname", FT_STRINGZ, BASE_DEC, NULL, 0x0, "OD object name", HFILL }},

    { &hf_mq_od_objectqmgrname,
      { "Object queue manager name", "mq.od.objqmgrname", FT_STRINGZ, BASE_DEC, NULL, 0x0, "OD object queue manager name", HFILL }},

    { &hf_mq_od_dynamicqname,
      { "Dynamic queue name", "mq.od.dynqname", FT_STRINGZ, BASE_DEC, NULL, 0x0, "OD dynamic queue name", HFILL }},

    { &hf_mq_od_alternateuserid,
      { "Alternate user id", "mq.od.altuserid", FT_STRINGZ, BASE_DEC, NULL, 0x0, "OD alternate userid", HFILL }},

    { &hf_mq_od_recspresent,
      { "Number of records", "mq.od.nbrrec", FT_UINT32, BASE_DEC, NULL, 0x0, "OD number of records", HFILL }},

    { &hf_mq_od_knowndestcount,
      { "Known destination count", "mq.od.kdestcount", FT_UINT32, BASE_DEC, NULL, 0x0, "OD known destination count", HFILL }},

    { &hf_mq_od_unknowndestcount,
      { "Unknown destination count", "mq.od.udestcount", FT_UINT32, BASE_DEC, NULL, 0x0, "OD unknown destination count", HFILL }},

    { &hf_mq_od_invaliddestcount,
      { "Invalid destination count", "mq.od.idestcount", FT_UINT32, BASE_DEC, NULL, 0x0, "OD invalid destination count", HFILL }},

    { &hf_mq_od_objectrecoffset,
      { "Offset of first record", "mq.od.offsetrec", FT_UINT32, BASE_DEC, NULL, 0x0, "OD offset of first record", HFILL }},

    { &hf_mq_od_responserecoffset,
      { "Offset of first response record", "mq.od.offsetres", FT_UINT32, BASE_DEC, NULL, 0x0, "OD offset of first response record", HFILL }},

    { &hf_mq_od_objectrecptr,
      { "Address of first record", "mq.od.addrrec", FT_UINT32, BASE_HEX, NULL, 0x0, "OD address of first record", HFILL }},

    { &hf_mq_od_responserecptr,
      { "Address of first response record", "mq.od.addrres", FT_UINT32, BASE_HEX, NULL, 0x0, "OD address of first response record", HFILL }},

    { &hf_mq_od_alternatesecurityid,
      { "Alternate security id", "mq.od.altsecid", FT_STRINGZ, BASE_HEX, NULL, 0x0, "OD alternate security id", HFILL }},

    { &hf_mq_od_resolvedqname,
      { "Resolved queue name", "mq.od.resolvq", FT_STRINGZ, BASE_HEX, NULL, 0x0, "OD resolved queue name", HFILL }},

    { &hf_mq_od_resolvedqmgrname,
      { "Resolved queue manager name", "mq.od.resolvqmgr", FT_STRINGZ, BASE_HEX, NULL, 0x0, "OD resolved queue manager name", HFILL }},

    { &hf_mq_md_structid,
      { "MD structid", "mq.md.structid", FT_STRINGZ, BASE_DEC, NULL, 0x0, "MD structid", HFILL }},

    { &hf_mq_md_version,
      { "Version", "mq.md.version", FT_UINT32, BASE_DEC, NULL, 0x0, "MD version", HFILL }},

    { &hf_mq_md_report,
      { "Report", "mq.md.report", FT_UINT32, BASE_DEC, NULL, 0x0, "MD report", HFILL }},

    { &hf_mq_md_msgtype,
      { "Message type", "mq.md.msgtype", FT_UINT32, BASE_DEC, NULL, 0x0, "MD message type", HFILL }},

    { &hf_mq_md_expiry,
      { "Expiry", "mq.md.expiry", FT_UINT32, BASE_DEC, NULL, 0x0, "MD expiry", HFILL }},

    { &hf_mq_md_feedback,
      { "Feedback", "mq.md.feedback", FT_UINT32, BASE_DEC, NULL, 0x0, "MD feedback", HFILL }},

    { &hf_mq_md_encoding,
      { "Encoding", "mq.md.encoding", FT_UINT32, BASE_DEC, NULL, 0x0, "MD encoding", HFILL }},

    { &hf_mq_md_ccsid,
      { "Character set", "mq.md.ccsid", FT_UINT32, BASE_DEC, NULL, 0x0, "MD character set", HFILL }},

    { &hf_mq_md_format,
      { "Format", "mq.md.format", FT_STRINGZ, BASE_DEC, NULL, 0x0, "MD format", HFILL }},

    { &hf_mq_md_priority,
      { "Priority", "mq.md.priority", FT_UINT32, BASE_DEC, NULL, 0x0, "MD priority", HFILL }},

    { &hf_mq_md_persistence,
      { "Persistence", "mq.md.persistence", FT_UINT32, BASE_DEC, NULL, 0x0, "MD persistence", HFILL }},

    { &hf_mq_md_msgid,
      { "MessageId", "mq.md.msgid", FT_BYTES, BASE_DEC, NULL, 0x0, "MD Message Id", HFILL }},

    { &hf_mq_md_correlid,
      { "CorrelationId", "mq.md.correlid", FT_BYTES, BASE_DEC, NULL, 0x0, "MD Correlation Id", HFILL }},

    { &hf_mq_md_backountcount,
      { "Backount count", "mq.md.backount", FT_UINT32, BASE_DEC, NULL, 0x0, "MD Backount count", HFILL }},

    { &hf_mq_md_replytoq,
      { "ReplyToQ", "mq.md.correlid", FT_STRINGZ, BASE_DEC, NULL, 0x0, "MD ReplyTo queue manager", HFILL }},

    { &hf_mq_md_replytoqmgr,
      { "ReplyToQMgr", "mq.md.correlid", FT_STRINGZ, BASE_DEC, NULL, 0x0, "MD ReplyTo queue", HFILL }},

    { &hf_mq_md_userid,
      { "UserId", "mq.md.userid", FT_STRINGZ, BASE_DEC, NULL, 0x0, "MD UserId", HFILL }},

    { &hf_mq_md_acttoken,
      { "Accounting token", "mq.md.acttoken", FT_BYTES, BASE_DEC, NULL, 0x0, "MD accounting token", HFILL }},

    { &hf_mq_md_appliddata,
      { "ApplicationId data", "mq.md.appldata", FT_STRINGZ, BASE_DEC, NULL, 0x0, "MD Put applicationId data", HFILL }},

    { &hf_mq_md_putappltype,
      { "Put Application Type", "mq.md.appltype", FT_UINT32, BASE_DEC, NULL, 0x0, "MD Put application type", HFILL }},

    { &hf_mq_md_putapplname,
      { "Put Application Name", "mq.md.applname", FT_STRINGZ, BASE_DEC, NULL, 0x0, "MD Put application name", HFILL }},

    { &hf_mq_md_putdate,
      { "Put date", "mq.md.date", FT_STRINGZ, BASE_DEC, NULL, 0x0, "MD Put date", HFILL }},

    { &hf_mq_md_puttime,
      { "Put time", "mq.md.time", FT_STRINGZ, BASE_DEC, NULL, 0x0, "MD Put time", HFILL }},

    { &hf_mq_md_applorigindata,
      { "Application original data", "mq.md.origdata", FT_STRINGZ, BASE_DEC, NULL, 0x0, "MD Application original data", HFILL }},

    { &hf_mq_md_groupid,
      { "GroupId", "mq.md.groupid", FT_BYTES, BASE_DEC, NULL, 0x0, "MD GroupId", HFILL }},

    { &hf_mq_md_msgseqnumber,
      { "Message sequence number", "mq.md.msgseqnumber", FT_UINT32, BASE_DEC, NULL, 0x0, "MD Message sequence number", HFILL }},

    { &hf_mq_md_offset,
      { "Offset", "mq.md.offset", FT_UINT32, BASE_DEC, NULL, 0x0, "MD Offset", HFILL }},

    { &hf_mq_md_msgflags,
      { "Message flags", "mq.md.msgflags", FT_UINT32, BASE_HEX, NULL, 0x0, "MD Message flags", HFILL }},

    { &hf_mq_md_originallength,
      { "Original length", "mq.md.origdata", FT_UINT32, BASE_DEC, NULL, 0x0, "MD Original length", HFILL }},

    { &hf_mq_gmo_structid,
      { "GMO structid", "mq.gmo.structid", FT_STRINGZ, BASE_DEC, NULL, 0x0, "GMO structid", HFILL }},

    { &hf_mq_gmo_version,
      { "Version", "mq.gmo.version", FT_UINT32, BASE_DEC, NULL, 0x0, "GMO version", HFILL }},

    { &hf_mq_gmo_options,
      { "Options", "mq.gmo.options", FT_UINT32, BASE_HEX, NULL, 0x0, "GMO options", HFILL }},

    { &hf_mq_gmo_waitinterval,
      { "Wait Interval", "mq.gmo.waitint", FT_UINT32, BASE_DEC, NULL, 0x0, "GMO wait interval", HFILL }},

    { &hf_mq_gmo_signal1,
      { "Signal 1", "mq.gmo.signal1", FT_UINT32, BASE_HEX, NULL, 0x0, "GMO signal 1", HFILL }},

    { &hf_mq_gmo_signal2,
      { "Signal 2", "mq.gmo.signal2", FT_UINT32, BASE_HEX, NULL, 0x0, "GMO signal 2", HFILL }},

    { &hf_mq_gmo_resolvedqname,
      { "Resolved queue name", "mq.gmo.resolvq", FT_STRINGZ, BASE_HEX, NULL, 0x0, "GMO resolved queue name", HFILL }},

    { &hf_mq_gmo_matchoptions,
      { "Match options", "mq.gmo.matchopt", FT_UINT32, BASE_HEX, NULL, 0x0, "GMO match options", HFILL }},

    { &hf_mq_gmo_groupstatus,
      { "Group status", "mq.gmo.grpstat", FT_UINT8, BASE_HEX, NULL, 0x0, "GMO group status", HFILL }},

    { &hf_mq_gmo_segmentstatus,
      { "Segment status", "mq.gmo.sgmtstat", FT_UINT8, BASE_HEX, NULL, 0x0, "GMO segment status", HFILL }},

    { &hf_mq_gmo_segmentation,
      { "Segmentation", "mq.gmo.segmentation", FT_UINT8, BASE_HEX, NULL, 0x0, "GMO segmentation", HFILL }},

    { &hf_mq_gmo_reserved,
      { "Reserved", "mq.gmo.reserved", FT_UINT8, BASE_HEX, NULL, 0x0, "GMO reserved", HFILL }},

    { &hf_mq_gmo_msgtoken,
      { "Message token", "mq.gmo.msgtoken", FT_BYTES, BASE_HEX, NULL, 0x0, "GMO message token", HFILL }},

    { &hf_mq_gmo_returnedlength,
      { "Returned length", "mq.gmo.retlen", FT_UINT32, BASE_DEC, NULL, 0x0, "GMO returned length", HFILL }},

    { &hf_mq_buffer_length,
      { "Buffer length", "mq.buffer.length", FT_UINT32, BASE_DEC, NULL, 0x0, "Buffer length", HFILL }},

    { &hf_mq_buffer_data,
      { "Buffer data", "mq.buffer.data", FT_BYTES, BASE_DEC, NULL, 0x0, "Buffer data", HFILL }},

    { &hf_mq_pmo_structid,
      { "PMO structid", "mq.pmo.structid", FT_STRINGZ, BASE_DEC, NULL, 0x0, "PMO structid", HFILL }},

    { &hf_mq_pmo_version,
      { "Version", "mq.pmo.structid", FT_UINT32, BASE_DEC, NULL, 0x0, "PMO version", HFILL }},

    { &hf_mq_pmo_options,
      { "Options", "mq.pmo.options", FT_UINT32, BASE_HEX, NULL, 0x0, "PMO options", HFILL }},

    { &hf_mq_pmo_timeout,
      { "Timeout", "mq.pmo.timeout", FT_UINT32, BASE_DEC, NULL, 0x0, "PMO time out", HFILL }},

    { &hf_mq_pmo_context,
      { "Context", "mq.pmo.context", FT_UINT32, BASE_HEX, NULL, 0x0, "PMO context", HFILL }},

    { &hf_mq_pmo_knowndestcount,
      { "Known destination count", "mq.pmo.kdstcount", FT_UINT32, BASE_DEC, NULL, 0x0, "PMO known destination count", HFILL }},

    { &hf_mq_pmo_unknowndestcount,
      { "Unknown destination count", "mq.pmo.udestcount", FT_UINT32, BASE_DEC, NULL, 0x0, "PMO unknown destination count", HFILL }},

    { &hf_mq_pmo_invaliddestcount,
      { "Invalid destination count", "mq.pmo.idestcount", FT_UINT32, BASE_DEC, NULL, 0x0, "PMO invalid destination count", HFILL }},

    { &hf_mq_pmo_resolvedqname,
      { "Resolved queue name", "mq.pmo.resolvq", FT_STRINGZ, BASE_DEC, NULL, 0x0, "PMO resolved queue name", HFILL }},

    { &hf_mq_pmo_resolvedqmgrname,
      { "Resolved queue name manager", "mq.pmo.resolvqmgr", FT_STRINGZ, BASE_DEC, NULL, 0x0, "PMO resolved queue manager name", HFILL }},

    { &hf_mq_pmo_recspresent,
      { "Number of records", "mq.pmo.nbrrec", FT_UINT32, BASE_DEC, NULL, 0x0, "PMO number of records", HFILL }},

    { &hf_mq_pmo_putmsgrecfields,
      { "Flags PMR fields", "mq.pmo.flagspmr", FT_UINT32, BASE_HEX, NULL, 0x0, "PMO flags PMR fields", HFILL }},

    { &hf_mq_pmo_putmsgrecoffset,
      { "Offset of first record", "mq.pmo.offsetrec", FT_UINT32, BASE_DEC, NULL, 0x0, "PMO offset of first record", HFILL }},

    { &hf_mq_pmo_responserecoffset,
      { "Offset of first response record", "mq.pmo.offsetres", FT_UINT32, BASE_DEC, NULL, 0x0, "PMO offset of first response record", HFILL }},

    { &hf_mq_pmo_putmsgrecptr,
      { "Address of first record", "mq.pmo.addrrec", FT_UINT32, BASE_HEX, NULL, 0x0, "PMO address of first record", HFILL }},

    { &hf_mq_pmo_responserecptr,
      { "Address of first response record", "mq.pmo.addrres", FT_UINT32, BASE_HEX, NULL, 0x0, "PMO qddress of first response record", HFILL }}
  };
  static gint *ett[] = {
    &ett_mq,
    &ett_mq_tsh,
    &ett_mq_tsh_tcf,
    &ett_mq_id,
    &ett_mq_id_ief,
    &ett_mq_uid,
    &ett_mq_conn,
    &ett_mq_od,
    &ett_mq_md,
    &ett_mq_gmo,
    &ett_mq_pmo,
    &ett_mq_buffer,
  };

  proto_mq = proto_register_protocol("WebSphere MQ", "MQ", "mq");
  proto_register_field_array(proto_mq, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  mq_handle = create_dissector_handle(dissect_mq, proto_mq);

}

void
proto_reg_handoff_mq(void)
{
	/*  Unlike some protocol (HTTP, POP3, ...) that clearly map to a standard
	*  class of applications (web browser, e-mail client, ...) and have a very well
	*  known port number, the MQ applications are most often specific to a business application */

	dissector_add("tcp.port", MQ_PORT_TCP, mq_handle);
	
	heur_dissector_add("tcp", dissect_mq_heur, proto_mq);

}
