/* packet-mq.c
 * Routines for IBM WebSphere MQ packet dissection
 *
 * metatech <metatechbe@gmail.com>
 * Robert Grange <robionekenobi@bluewin.ch>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

 /*  WebSphere MQ in a nutshell
  *
  *   IBM WebSphere MQ (formerly IBM MQSeries) is an asynchronous proprietary messaging middleware that is
  *    based on message queues.
  *   MQ can run on more than 35 platforms, amongst which UNIX, Windows and mainframes.
  *   MQ can be transported on top of TCP, UDP, HTTP, NetBIOS, SPX, SNA LU 6.2, DECnet.
  *   MQ has language bindings for C, C++, Java, .NET, COBOL, PL/I, OS/390 assembler, TAL, Visual Basic.
  *
  *   The basic MQ topology is on one side the queue manager which hosts the queues.  On the other side the
  *   applications connect to the queue manager, open a queue, and put or get messages to/from that queue.
  *
  *   The MQ middleware allows very generic operations (send, receive) and can be compared to the
  *   socket API in terms of genericity, but it is more abstract and offers higher-level functionalities
  *   (eg transactions, ...)
  *
  *   The MQ middleware is not really intended to be run over public networks between parties
  *   that do not know each other in advance, but is rather used on private corporate networks
  *   between business applications (it can be compared to a database server for that aspect).
  *
  *   The wire format of an MQ segment is a sequence of structures.
  *   Most structures start with a 4-letter struct identifier.
  *   MQ is a fixed-sized format, most fields have maximum lengths defined in the MQ API.
  *   MQ is popular on mainframes because it was available before TCP/IP.
  *   MQ supports both ASCII-based and EBCDIC-based character sets.
  *
  *   MQ API documentation is called "WebSphere MQ Application Programming
  *   Reference"
  *
  *   See:
  *
  *       https://www.ibm.com/docs/en/ibm-mq/7.5?topic=structure-application-programming-reference
  *
  *   Possible structures combinations :
  *   TSH [ ID ^ UID ^ CONN ^ INQ ^ OD ]
  *   TSH MSH XQH MD [ PAYLOAD ]
  *   TSH [OD] MD [ GMO ^ PMO ] [ [XQH MD] PAYLOAD ]
  *   TSH [ SPQU ^ SPPU ^ SPGU ^ SPAU [ SPQI ^ SPQO ^ SPPI ^ SPPO ^ SPGI ^ SPGO ^ SPAI ^ SPAO]]
  *   TSH [ XA ] [ XINFO | XID ]
  *   where PAYLOAD = [ DH ] [ DLH ] [ MDE ] BUFF
  *
  *   This dissector is a beta version.  To be improved
  *   - Translate the integers/flags into their descriptions
  *   - Find the semantics of the unknown fields
  *   - Display EBCDIC strings as ASCII
  *   - Packets which structures built on different platforms
  */

#include "config.h"

#include <epan/packet.h>
#include <epan/ptvcursor.h>
#include <epan/exceptions.h>
#include <epan/reassemble.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/strutil.h>

#include "packet-windows-common.h"
#include "packet-tcp.h"
#include "packet-tls.h"

#include "packet-mq.h"

void proto_register_mq(void);
void proto_reg_handoff_mq(void);

static int proto_mq;
static int hf_mq_tsh_StructID;
static int hf_mq_tsh_mqseglen;
static int hf_mq_tsh_convid;
static int hf_mq_tsh_requestid;
static int hf_mq_tsh_byteorder;
static int hf_mq_tsh_opcode;
static int hf_mq_tsh_ctlflgs1;

static int hf_mq_tsh_ctlflgs2;
static int hf_mq_tsh_luwid;
static int hf_mq_tsh_encoding;

static int hf_mq_tsh_ccsid;
static int hf_mq_tsh_reserved;

/* Transmission Segment Control Flags 1 */
static int hf_mq_tsh_tcf_confirmreq;
static int hf_mq_tsh_tcf_error;
static int hf_mq_tsh_tcf_reqclose;
static int hf_mq_tsh_tcf_closechann;
static int hf_mq_tsh_tcf_first;
static int hf_mq_tsh_tcf_last;
static int hf_mq_tsh_tcf_reqacc;
static int hf_mq_tsh_tcf_dlq;
static int* const pf_flds_tcf[] =
{
    &hf_mq_tsh_tcf_dlq,
    &hf_mq_tsh_tcf_reqacc,
    &hf_mq_tsh_tcf_last,
    &hf_mq_tsh_tcf_first,
    &hf_mq_tsh_tcf_closechann,
    &hf_mq_tsh_tcf_reqclose,
    &hf_mq_tsh_tcf_error,
    &hf_mq_tsh_tcf_confirmreq,
    NULL
};

/* Transmission Segment Control Flags 2 */
static int hf_mq_tsh_tcf2_HdrComp;
static int hf_mq_tsh_tcf2_MsgComp;
static int hf_mq_tsh_tcf2_CSH;
static int hf_mq_tsh_tcf2_CmitIntv;
static int* const pf_flds_tcf2[] =
{
    &hf_mq_tsh_tcf2_CmitIntv,
    &hf_mq_tsh_tcf2_CSH,
    &hf_mq_tsh_tcf2_MsgComp,
    &hf_mq_tsh_tcf2_HdrComp,
    NULL
};

static int hf_mq_api_replylen;
static int hf_mq_api_compcode;
static int hf_mq_api_reascode;
static int hf_mq_api_objecthdl;
static int hf_mq_socket_conversid;
static int hf_mq_socket_requestid;
static int hf_mq_socket_type;
static int hf_mq_socket_parm1;
static int hf_mq_socket_parm2;
static int hf_mq_msh_StructID;
static int hf_mq_msh_seqnum;
static int hf_mq_msh_datalength;
static int hf_mq_msh_unknown1;
static int hf_mq_msh_msglength;
static int hf_mq_xqh_StructID;
static int hf_mq_xqh_version;
static int hf_mq_xqh_remoteq;
static int hf_mq_xqh_remoteqmgr;

static int hf_mq_id_StructID;
static int hf_mq_id_FapLevel;
static int hf_mq_id_cf1;
static int hf_mq_id_ecf1;
static int hf_mq_id_ief1;
static int hf_mq_id_Reserved;
static int hf_mq_id_MaxMsgBatch;
static int hf_mq_id_MaxTrSize;
static int hf_mq_id_MaxMsgSize;
static int hf_mq_id_SeqWrapVal;
static int hf_mq_id_channel;
static int hf_mq_id_cf2;
static int hf_mq_id_ecf2;
static int hf_mq_id_ccsid;
static int hf_mq_id_qmgrname;
static int hf_mq_id_HBInterval;
static int hf_mq_id_EFLLength;
static int hf_mq_id_ief2;
static int hf_mq_id_Reserved1;
static int hf_mq_id_HdrCprsLst;
static int hf_mq_id_MsgCprsLst;
static int hf_mq_id_Reserved2;
static int hf_mq_id_SSLKeyRst;
static int hf_mq_id_ConvBySkt;
static int hf_mq_id_cf3;
static int hf_mq_id_ecf3;
static int hf_mq_id_Reserved3;
static int hf_mq_id_ProcessId;
static int hf_mq_id_ThreadId;
static int hf_mq_id_TraceId;
static int hf_mq_id_ProdId;
static int hf_mq_id_mqmid;
static int hf_mq_id_pal;
static int hf_mq_id_r;

/* Initial Data - Capability Flag 1 */
static int hf_mq_id_cf1_msgseq;
static int hf_mq_id_cf1_convcap;
static int hf_mq_id_cf1_splitmsg;
static int hf_mq_id_cf1_RqstInit;
static int hf_mq_id_cf1_RqstSecu;
static int hf_mq_id_cf1_mqreq;
static int hf_mq_id_cf1_svrsec;
static int hf_mq_id_cf1_runtime;
static int* const pf_flds_cf1[] =
{
    &hf_mq_id_cf1_runtime,
    &hf_mq_id_cf1_svrsec,
    &hf_mq_id_cf1_mqreq,
    &hf_mq_id_cf1_RqstSecu,
    &hf_mq_id_cf1_RqstInit,
    &hf_mq_id_cf1_splitmsg,
    &hf_mq_id_cf1_convcap,
    &hf_mq_id_cf1_msgseq,
    NULL
};

/* Initial Data - Init Error Flag 1 */
static int hf_mq_id_ief1_ccsid;
static int hf_mq_id_ief1_enc;
static int hf_mq_id_ief1_mxtrsz;
static int hf_mq_id_ief1_fap;
static int hf_mq_id_ief1_mxmsgsz;
static int hf_mq_id_ief1_mxmsgpb;
static int hf_mq_id_ief1_seqwrap;
static int hf_mq_id_ief1_hbint;
static int* const pf_flds_ef1[] =
{
    &hf_mq_id_ief1_hbint,
    &hf_mq_id_ief1_seqwrap,
    &hf_mq_id_ief1_mxmsgpb,
    &hf_mq_id_ief1_mxmsgsz,
    &hf_mq_id_ief1_fap,
    &hf_mq_id_ief1_mxtrsz,
    &hf_mq_id_ief1_enc,
    &hf_mq_id_ief1_ccsid,
    NULL
};

/* Initial Data - Capability Flag 2 */
static int hf_mq_id_cf2_CanDstLst;
static int hf_mq_id_cf2_FstMsgReq;
static int hf_mq_id_cf2_RespConv;
static int hf_mq_id_cf2_XARequest;
static int hf_mq_id_cf2_XARunTApp;
static int hf_mq_id_cf2_SPIRqst;
static int hf_mq_id_cf2_DualUOW;
static int hf_mq_id_cf2_CanTrcRte;
static int* const pf_flds_cf2[] =
{
    &hf_mq_id_cf2_CanTrcRte,
    &hf_mq_id_cf2_SPIRqst,
    &hf_mq_id_cf2_XARunTApp,
    &hf_mq_id_cf2_XARequest,
    &hf_mq_id_cf2_DualUOW,
    &hf_mq_id_cf2_RespConv,
    &hf_mq_id_cf2_FstMsgReq,
    &hf_mq_id_cf2_CanDstLst,
    NULL
};

/* Initial Data - Init Error Flag 2 */
static int hf_mq_id_ief2_HdrCmpLst;
static int hf_mq_id_ief2_MsgCmpLst;
static int hf_mq_id_ief2_SSLReset;
static int* const pf_flds_ef2[] =
{
    &hf_mq_id_ief2_SSLReset,
    &hf_mq_id_ief2_MsgCmpLst,
    &hf_mq_id_ief2_HdrCmpLst,
    NULL
};

/* Initial Data - Capability Flag 3 */
static int hf_mq_id_cf3_CanMsgPrp;
static int hf_mq_id_cf3_CanMulticast;
static int hf_mq_id_cf3_PropIntSep;
static int hf_mq_id_cf3_MPlxSyGet;
static int hf_mq_id_cf3_ProtAlgorit;
static int hf_mq_id_cf3_CanGenConnTag;

static int* const pf_flds_cf3[] =
{
    &hf_mq_id_cf3_ProtAlgorit,
    &hf_mq_id_cf3_MPlxSyGet,
    &hf_mq_id_cf3_PropIntSep,
    &hf_mq_id_cf3_CanMulticast,
    &hf_mq_id_cf3_CanMsgPrp,
    &hf_mq_id_cf3_CanGenConnTag,
    NULL
};

static int hf_mq_uid_StructID;
static int hf_mq_uid_userid;
static int hf_mq_uid_password;
static int hf_mq_uid_longuserid;
static int hf_mq_sidlen;
static int hf_mq_sidtyp;
static int hf_mq_securityid;

static int hf_mq_conn_QMgr;
static int hf_mq_conn_appname;
static int hf_mq_conn_apptype;
static int hf_mq_conn_acttoken;
static int hf_mq_conn_Xoptions;
static int hf_mq_conn_options;
static int hf_mq_fcno_StructID;
static int hf_mq_fcno_prodid;
static int hf_mq_fcno_mqmid;
static int hf_mq_fcno_version;
static int hf_mq_fcno_capflag;
static int hf_mq_fcno_conn_tag;
static int hf_mq_fcno_retconn_tag;
static int hf_mq_fcno_unknowb01;

static int hf_mq_inq_nbsel;
static int hf_mq_inq_nbint;
static int hf_mq_inq_charlen;
static int hf_mq_inq_sel;
static int hf_mq_inq_intvalue;
static int hf_mq_inq_charvalues;

static int hf_mq_spi_verb;
static int hf_mq_spi_version;
static int hf_mq_spi_length;
static int hf_mq_spi_base_StructID;
static int hf_mq_spi_base_version;
static int hf_mq_spi_base_length;
static int hf_mq_spi_spqo_nbverb;
static int hf_mq_spi_spqo_verbid;
static int hf_mq_spi_spqo_maxiover;
static int hf_mq_spi_spqo_maxinver;
static int hf_mq_spi_spqo_maxouver;
static int hf_mq_spi_spqo_flags;
static int hf_mq_spi_spai_mode;
static int hf_mq_spi_spai_unknown1;
static int hf_mq_spi_spai_unknown2;
static int hf_mq_spi_spai_msgid;
static int hf_mq_spi_spgi_batchsz;
static int hf_mq_spi_spgi_batchint;
static int hf_mq_spi_spgi_maxmsgsz;
static int hf_mq_spi_spgo_options;
static int hf_mq_spi_spgo_size;

static int hf_mq_spi_opt_blank;
static int hf_mq_spi_opt_syncp;
static int hf_mq_spi_opt_deferred;
static int* const pf_flds_spiopt[] =
{
    &hf_mq_spi_opt_deferred,
    &hf_mq_spi_opt_syncp,
    &hf_mq_spi_opt_blank,
    NULL
};

static int hf_mq_put_length;

static int hf_mq_close_options;
static int hf_mq_close_options_DELETE;
static int hf_mq_close_options_DELETE_PURGE;
static int hf_mq_close_options_KEEP_SUB;
static int hf_mq_close_options_REMOVE_SUB;
static int hf_mq_close_options_QUIESCE;
static int* const pf_flds_clsopt[] =
{
    &hf_mq_close_options_QUIESCE,
    &hf_mq_close_options_REMOVE_SUB,
    &hf_mq_close_options_KEEP_SUB,
    &hf_mq_close_options_DELETE_PURGE,
    &hf_mq_close_options_DELETE,
    NULL
};

static int hf_mq_open_options;
static int hf_mq_open_options_INPUT_SHARED;
static int hf_mq_open_options_INPUT_AS_Q_DEF;
static int hf_mq_open_options_INPUT_EXCLUSIVE;
static int hf_mq_open_options_BROWSE;
static int hf_mq_open_options_OUTPUT;
static int hf_mq_open_options_INQUIRE;
static int hf_mq_open_options_SET;
static int hf_mq_open_options_SAVE_ALL_CTX;
static int hf_mq_open_options_PASS_IDENT_CTX;
static int hf_mq_open_options_PASS_ALL_CTX;
static int hf_mq_open_options_SET_IDENT_CTX;
static int hf_mq_open_options_SET_ALL_CONTEXT;
static int hf_mq_open_options_ALT_USER_AUTH;
static int hf_mq_open_options_FAIL_IF_QUIESC;
static int hf_mq_open_options_BIND_ON_OPEN;
static int hf_mq_open_options_BIND_NOT_FIXED;
static int hf_mq_open_options_RESOLVE_NAMES;
static int hf_mq_open_options_CO_OP;
static int hf_mq_open_options_RESOLVE_LOCAL_Q;
static int hf_mq_open_options_NO_READ_AHEAD;
static int hf_mq_open_options_READ_AHEAD;
static int hf_mq_open_options_NO_MULTICAST;
static int hf_mq_open_options_BIND_ON_GROUP;
static int* const pf_flds_opnopt[] =
{
    &hf_mq_open_options_BIND_ON_GROUP,
    &hf_mq_open_options_NO_MULTICAST,
    &hf_mq_open_options_READ_AHEAD,
    &hf_mq_open_options_NO_READ_AHEAD,
    &hf_mq_open_options_RESOLVE_LOCAL_Q,
    &hf_mq_open_options_CO_OP,
    &hf_mq_open_options_RESOLVE_NAMES,
    &hf_mq_open_options_BIND_NOT_FIXED,
    &hf_mq_open_options_BIND_ON_OPEN,
    &hf_mq_open_options_FAIL_IF_QUIESC,
    &hf_mq_open_options_ALT_USER_AUTH,
    &hf_mq_open_options_SET_ALL_CONTEXT,
    &hf_mq_open_options_SET_IDENT_CTX,
    &hf_mq_open_options_PASS_ALL_CTX,
    &hf_mq_open_options_PASS_IDENT_CTX,
    &hf_mq_open_options_SAVE_ALL_CTX,
    &hf_mq_open_options_SET,
    &hf_mq_open_options_INQUIRE,
    &hf_mq_open_options_OUTPUT,
    &hf_mq_open_options_BROWSE,
    &hf_mq_open_options_INPUT_EXCLUSIVE,
    &hf_mq_open_options_INPUT_SHARED,
    &hf_mq_open_options_INPUT_AS_Q_DEF,
    NULL
};

static int hf_mq_fopa_StructID;
static int hf_mq_fopa_version;
static int hf_mq_fopa_length;
static int hf_mq_fopa_DefPersistence;
static int hf_mq_fopa_DefPutRespType;
static int hf_mq_fopa_DefReadAhead;
static int hf_mq_fopa_PropertyControl;
static int hf_mq_fopa_Unknown;

static int hf_mq_fcmi_StructID;
static int hf_mq_fcmi_unknown;

static int hf_mq_ping_length;
static int hf_mq_ping_buffer;
static int hf_mq_reset_length;
static int hf_mq_reset_seqnum;
static int hf_mq_status_length;
static int hf_mq_status_code;
static int hf_mq_status_value;

static int hf_mq_caut_StructID;
static int hf_mq_caut_AuthType;
static int hf_mq_caut_UsrMaxLen;
static int hf_mq_caut_PwdMaxLen;
static int hf_mq_caut_UsrLength;
static int hf_mq_caut_PwdLength;
static int hf_mq_caut_usr;
static int hf_mq_caut_psw;

static int hf_mq_od_StructID;
static int hf_mq_od_version;
static int hf_mq_od_objecttype;
static int hf_mq_od_objectname;
static int hf_mq_od_objqmgrname;
static int hf_mq_od_dynqname;
static int hf_mq_od_altuserid;
static int hf_mq_od_recspresent;
static int hf_mq_od_knowndstcnt;
static int hf_mq_od_unknowdstcnt;
static int hf_mq_od_invaldstcnt;
static int hf_mq_od_objrecofs;
static int hf_mq_od_resprecofs;
static int hf_mq_od_objrecptr;
static int hf_mq_od_resprecptr;
static int hf_mq_od_altsecurid;
static int hf_mq_od_resolvqname;
static int hf_mq_od_resolvqmgrnm;
static int hf_mq_od_resolvobjtyp;

static int hf_mq_or_objname;
static int hf_mq_or_objqmgrname;
static int hf_mq_rr_compcode;
static int hf_mq_rr_reascode;
static int hf_mq_pmr_msgid;
static int hf_mq_pmr_correlid;
static int hf_mq_pmr_groupid;
static int hf_mq_pmr_feedback;
static int hf_mq_pmr_acttoken;
static int hf_mq_md_StructID;
static int hf_mq_md_version;
static int hf_mq_md_report;
static int hf_mq_md_msgtype;
static int hf_mq_md_expiry;
static int hf_mq_md_feedback;
static int hf_mq_md_encoding;
static int hf_mq_md_ccsid;
static int hf_mq_md_format;
static int hf_mq_md_priority;
static int hf_mq_md_persistence;
static int hf_mq_md_msgid;
static int hf_mq_md_correlid;
static int hf_mq_md_backoutcnt;
static int hf_mq_md_replytoq;
static int hf_mq_md_replytoqmgr;
static int hf_mq_md_userid;
static int hf_mq_md_acttoken;
static int hf_mq_md_appliddata;
static int hf_mq_md_putappltype;
static int hf_mq_md_putapplname;
static int hf_mq_md_putdate;
static int hf_mq_md_puttime;
static int hf_mq_md_apporigdata;
static int hf_mq_md_groupid;
static int hf_mq_md_msgseqnumber;
static int hf_mq_md_offset;
static int hf_mq_md_msgflags;
static int hf_mq_md_origlen;
static int hf_mq_dlh_StructID;
static int hf_mq_dlh_version;
static int hf_mq_dlh_reason;
static int hf_mq_dlh_destq;
static int hf_mq_dlh_destqmgr;
static int hf_mq_dlh_encoding;
static int hf_mq_dlh_ccsid;
static int hf_mq_dlh_format;
static int hf_mq_dlh_putappltype;
static int hf_mq_dlh_putapplname;
static int hf_mq_dlh_putdate;
static int hf_mq_dlh_puttime;

static int hf_mq_gmo_StructID;
static int hf_mq_gmo_version;
static int hf_mq_gmo_options;
static int hf_mq_gmo_waitinterval;
static int hf_mq_gmo_signal1;
static int hf_mq_gmo_signal2;
static int hf_mq_gmo_resolvqname;
static int hf_mq_gmo_matchoptions;
static int hf_mq_gmo_groupstatus;
static int hf_mq_gmo_segmstatus;
static int hf_mq_gmo_segmentation;
static int hf_mq_gmo_reserved;
static int hf_mq_gmo_msgtoken;
static int hf_mq_gmo_returnedlen;
static int hf_mq_gmo_reserved2;
static int hf_mq_gmo_msghandle;

static int hf_mq_gmo_options_PROPERTIES_COMPATIBILITY;
static int hf_mq_gmo_options_PROPERTIES_IN_HANDLE;
static int hf_mq_gmo_options_NO_PROPERTIES;
static int hf_mq_gmo_options_PROPERTIES_FORCE_MQRFH2;
static int hf_mq_gmo_options_UNMARKED_BROWSE_MSG;
static int hf_mq_gmo_options_UNMARK_BROWSE_HANDLE;
static int hf_mq_gmo_options_UNMARK_BROWSE_CO_OP;
static int hf_mq_gmo_options_MARK_BROWSE_CO_OP;
static int hf_mq_gmo_options_MARK_BROWSE_HANDLE;
static int hf_mq_gmo_options_ALL_SEGMENTS_AVAILABLE;
static int hf_mq_gmo_options_ALL_MSGS_AVAILABLE;
static int hf_mq_gmo_options_COMPLETE_MSG;
static int hf_mq_gmo_options_LOGICAL_ORDER;
static int hf_mq_gmo_options_CONVERT;
static int hf_mq_gmo_options_FAIL_IF_QUIESCING;
static int hf_mq_gmo_options_SYNCPOINT_IF_PERSISTENT;
static int hf_mq_gmo_options_BROWSE_MSG_UNDER_CURSOR;
static int hf_mq_gmo_options_UNLOCK;
static int hf_mq_gmo_options_LOCK;
static int hf_mq_gmo_options_MSG_UNDER_CURSOR;
static int hf_mq_gmo_options_MARK_SKIP_BACKOUT;
static int hf_mq_gmo_options_ACCEPT_TRUNCATED_MSG;
static int hf_mq_gmo_options_BROWSE_NEXT;
static int hf_mq_gmo_options_BROWSE_FIRST;
static int hf_mq_gmo_options_SET_SIGNAL;
static int hf_mq_gmo_options_NO_SYNCPOINT;
static int hf_mq_gmo_options_SYNCPOINT;
static int hf_mq_gmo_options_WAIT;
static int* const pf_flds_gmoopt[] =
{
    &hf_mq_gmo_options_PROPERTIES_COMPATIBILITY,
    &hf_mq_gmo_options_PROPERTIES_IN_HANDLE,
    &hf_mq_gmo_options_NO_PROPERTIES,
    &hf_mq_gmo_options_PROPERTIES_FORCE_MQRFH2,
    &hf_mq_gmo_options_UNMARKED_BROWSE_MSG,
    &hf_mq_gmo_options_UNMARK_BROWSE_HANDLE,
    &hf_mq_gmo_options_UNMARK_BROWSE_CO_OP,
    &hf_mq_gmo_options_MARK_BROWSE_CO_OP,
    &hf_mq_gmo_options_MARK_BROWSE_HANDLE,
    &hf_mq_gmo_options_ALL_SEGMENTS_AVAILABLE,
    &hf_mq_gmo_options_ALL_MSGS_AVAILABLE,
    &hf_mq_gmo_options_COMPLETE_MSG,
    &hf_mq_gmo_options_LOGICAL_ORDER,
    &hf_mq_gmo_options_CONVERT,
    &hf_mq_gmo_options_FAIL_IF_QUIESCING,
    &hf_mq_gmo_options_SYNCPOINT_IF_PERSISTENT,
    &hf_mq_gmo_options_BROWSE_MSG_UNDER_CURSOR,
    &hf_mq_gmo_options_UNLOCK,
    &hf_mq_gmo_options_LOCK,
    &hf_mq_gmo_options_MSG_UNDER_CURSOR,
    &hf_mq_gmo_options_MARK_SKIP_BACKOUT,
    &hf_mq_gmo_options_ACCEPT_TRUNCATED_MSG,
    &hf_mq_gmo_options_BROWSE_NEXT,
    &hf_mq_gmo_options_BROWSE_FIRST,
    &hf_mq_gmo_options_SET_SIGNAL,
    &hf_mq_gmo_options_NO_SYNCPOINT,
    &hf_mq_gmo_options_SYNCPOINT,
    &hf_mq_gmo_options_WAIT,
    NULL
};

static int hf_mq_gmo_matchoptions_MATCH_MSG_TOKEN;
static int hf_mq_gmo_matchoptions_MATCH_OFFSET;
static int hf_mq_gmo_matchoptions_MATCH_MSG_SEQ_NUMBER;
static int hf_mq_gmo_matchoptions_MATCH_GROUP_ID;
static int hf_mq_gmo_matchoptions_MATCH_CORREL_ID;
static int hf_mq_gmo_matchoptions_MATCH_MSG_ID;
static int* const pf_flds_mtchopt[] =
{
    &hf_mq_gmo_matchoptions_MATCH_MSG_TOKEN,
    &hf_mq_gmo_matchoptions_MATCH_OFFSET,
    &hf_mq_gmo_matchoptions_MATCH_MSG_SEQ_NUMBER,
    &hf_mq_gmo_matchoptions_MATCH_GROUP_ID,
    &hf_mq_gmo_matchoptions_MATCH_CORREL_ID,
    &hf_mq_gmo_matchoptions_MATCH_MSG_ID,
    NULL
};

static int hf_mq_lpoo_StructID;
static int hf_mq_lpoo_version;
static int hf_mq_lpoo_lpiopts;
static int hf_mq_lpoo_defpersist;
static int hf_mq_lpoo_defputresptype;
static int hf_mq_lpoo_defreadahead;
static int hf_mq_lpoo_propertyctl;
static int hf_mq_lpoo_qprotect;
static int hf_mq_lpoo_qprotect_val1;
static int hf_mq_lpoo_qprotect_val2;

static int hf_mq_lpoo_lpiopts_SAVE_IDENTITY_CTXT;
static int hf_mq_lpoo_lpiopts_SAVE_ORIGIN_CTXT;
static int hf_mq_lpoo_lpiopts_SAVE_USER_CTXT;
static int* const pf_flds_lpooopt[] =
{
    &hf_mq_lpoo_lpiopts_SAVE_USER_CTXT,
    &hf_mq_lpoo_lpiopts_SAVE_ORIGIN_CTXT,
    &hf_mq_lpoo_lpiopts_SAVE_IDENTITY_CTXT,
    NULL
};


static int hf_mq_charv_vsptr;
static int hf_mq_charv_vsoffset;
static int hf_mq_charv_vsbufsize;
static int hf_mq_charv_vslength;
static int hf_mq_charv_vsccsid;
static int hf_mq_charv_vsvalue;

static int hf_mq_pmo_StructID;
static int hf_mq_pmo_version;
static int hf_mq_pmo_options;
static int hf_mq_pmo_timeout;
static int hf_mq_pmo_context;
static int hf_mq_pmo_knowndstcnt;
static int hf_mq_pmo_unkndstcnt;
static int hf_mq_pmo_invaldstcnt;
static int hf_mq_pmo_resolvqname;
static int hf_mq_pmo_resolvqmgr;
static int hf_mq_pmo_recspresent;
static int hf_mq_pmo_putmsgrecfld;
static int hf_mq_pmo_putmsgrecofs;
static int hf_mq_pmo_resprecofs;
static int hf_mq_pmo_putmsgrecptr;
static int hf_mq_pmo_resprecptr;
static int hf_mq_pmo_originalmsghandle;
static int hf_mq_pmo_newmsghandle;
static int hf_mq_pmo_action;
static int hf_mq_pmo_publevel;

static int hf_mq_xa_length;
static int hf_mq_xa_returnvalue;
static int hf_mq_xa_tmflags;
static int hf_mq_xa_rmid;
static int hf_mq_xa_count;
static int hf_mq_xa_xid_formatid;
static int hf_mq_xa_xid_glbxid_len;
static int hf_mq_xa_xid_brq_length;
static int hf_mq_xa_xid_globalxid;
static int hf_mq_xa_xid_brq;
static int hf_mq_xa_xainfo_length;
static int hf_mq_xa_xainfo_value;

static int hf_mq_pmo_options_NOT_OWN_SUBS;
static int hf_mq_pmo_options_SUPPRESS_REPLYTO;
static int hf_mq_pmo_options_SCOPE_QMGR;
static int hf_mq_pmo_options_MD_FOR_OUTPUT_ONLY;
static int hf_mq_pmo_options_RETAIN;
static int hf_mq_pmo_options_WARN_IF_NO_SUBS_MATCHED;
static int hf_mq_pmo_options_RESOLVE_LOCAL_Q;
static int hf_mq_pmo_options_SYNC_RESPONSE;
static int hf_mq_pmo_options_ASYNC_RESPONSE;
static int hf_mq_pmo_options_LOGICAL_ORDER;
static int hf_mq_pmo_options_NO_CONTEXT;
static int hf_mq_pmo_options_FAIL_IF_QUIESCING;
static int hf_mq_pmo_options_ALTERNATE_USER_AUTHORITY;
static int hf_mq_pmo_options_SET_ALL_CONTEXT;
static int hf_mq_pmo_options_SET_IDENTITY_CONTEXT;
static int hf_mq_pmo_options_PASS_ALL_CONTEXT;
static int hf_mq_pmo_options_PASS_IDENTITY_CONTEXT;
static int hf_mq_pmo_options_NEW_CORREL_ID;
static int hf_mq_pmo_options_NEW_MSG_ID;
static int hf_mq_pmo_options_DEFAULT_CONTEXT;
static int hf_mq_pmo_options_NO_SYNCPOINT;
static int hf_mq_pmo_options_SYNCPOINT;
static int* const pf_flds_pmoopt[] =
{
    &hf_mq_pmo_options_NOT_OWN_SUBS,
    &hf_mq_pmo_options_SUPPRESS_REPLYTO,
    &hf_mq_pmo_options_SCOPE_QMGR,
    &hf_mq_pmo_options_MD_FOR_OUTPUT_ONLY,
    &hf_mq_pmo_options_RETAIN,
    &hf_mq_pmo_options_WARN_IF_NO_SUBS_MATCHED,
    &hf_mq_pmo_options_RESOLVE_LOCAL_Q,
    &hf_mq_pmo_options_SYNC_RESPONSE,
    &hf_mq_pmo_options_ASYNC_RESPONSE,
    &hf_mq_pmo_options_LOGICAL_ORDER,
    &hf_mq_pmo_options_NO_CONTEXT,
    &hf_mq_pmo_options_FAIL_IF_QUIESCING,
    &hf_mq_pmo_options_ALTERNATE_USER_AUTHORITY,
    &hf_mq_pmo_options_SET_ALL_CONTEXT,
    &hf_mq_pmo_options_SET_IDENTITY_CONTEXT,
    &hf_mq_pmo_options_PASS_ALL_CONTEXT,
    &hf_mq_pmo_options_PASS_IDENTITY_CONTEXT,
    &hf_mq_pmo_options_NEW_CORREL_ID,
    &hf_mq_pmo_options_NEW_MSG_ID,
    &hf_mq_pmo_options_DEFAULT_CONTEXT,
    &hf_mq_pmo_options_NO_SYNCPOINT,
    &hf_mq_pmo_options_SYNCPOINT,
    NULL
};

static int hf_mq_xa_tmflags_join;
static int hf_mq_xa_tmflags_endrscan;
static int hf_mq_xa_tmflags_startrscan;
static int hf_mq_xa_tmflags_suspend;
static int hf_mq_xa_tmflags_success;
static int hf_mq_xa_tmflags_resume;
static int hf_mq_xa_tmflags_fail;
static int hf_mq_xa_tmflags_onephase;
static int* const pf_flds_tmflags[] =
{
    &hf_mq_xa_tmflags_onephase,
    &hf_mq_xa_tmflags_fail,
    &hf_mq_xa_tmflags_resume,
    &hf_mq_xa_tmflags_success,
    &hf_mq_xa_tmflags_suspend,
    &hf_mq_xa_tmflags_startrscan,
    &hf_mq_xa_tmflags_endrscan,
    &hf_mq_xa_tmflags_join,
    NULL
};

static int hf_mq_msgreq_version;
static int hf_mq_msgreq_handle;
static int hf_mq_msgreq_RecvBytes;
static int hf_mq_msgreq_RqstBytes;
static int hf_mq_msgreq_MaxMsgLen;
static int hf_mq_msgreq_WaitIntrv;
static int hf_mq_msgreq_QueStatus;
static int hf_mq_msgreq_RqstFlags;
static int hf_mq_msgreq_GlbMsgIdx;
static int hf_mq_msgreq_SelectIdx;
static int hf_mq_msgreq_MQMDVers;
static int hf_mq_msgreq_ccsid;
static int hf_mq_msgreq_encoding;
static int hf_mq_msgreq_MsgSeqNum;
static int hf_mq_msgreq_offset;
static int hf_mq_msgreq_mtchMsgId;
static int hf_mq_msgreq_mtchCorId;
static int hf_mq_msgreq_mtchGrpid;
static int hf_mq_msgreq_mtchMsgTk;

static int hf_mq_msgreq_flags_selection;
static int hf_mq_msgreq_flags_F00000008;
static int hf_mq_msgreq_flags_F00000004;
static int hf_mq_msgreq_flags_F00000002;
static int* const pf_flds_msgreq_flags[] =
{
    &hf_mq_msgreq_flags_selection,
    &hf_mq_msgreq_flags_F00000008,
    &hf_mq_msgreq_flags_F00000004,
    &hf_mq_msgreq_flags_F00000002,
    NULL
};

static int hf_mq_msgasy_version;
static int hf_mq_msgasy_handle;
static int hf_mq_msgasy_MsgIndex;
static int hf_mq_msgasy_GlbMsgIdx;
static int hf_mq_msgasy_SegLength;
static int hf_mq_msgasy_SeleIndex;
static int hf_mq_msgasy_SegmIndex;
static int hf_mq_msgasy_ReasonCod;
static int hf_mq_msgasy_ActMsgLen;
static int hf_mq_msgasy_TotMsgLen;
static int hf_mq_msgasy_MsgToken;
static int hf_mq_msgasy_Status;
static int hf_mq_msgasy_resolQNLn;
static int hf_mq_msgasy_resolQNme;
static int hf_mq_msgasy_padding;

static int hf_mq_notif_vers;
static int hf_mq_notif_handle;
static int hf_mq_notif_code;
static int hf_mq_notif_value;

static int hf_mq_head_StructID;
static int hf_mq_head_version;
static int hf_mq_head_length;
static int hf_mq_head_encoding;
static int hf_mq_head_ccsid;
static int hf_mq_head_format;
static int hf_mq_head_flags;
static int hf_mq_head_struct;

static int hf_mq_dh_flags_newmsgid;
static int* const pf_flds_dh_flags[] =
{
    &hf_mq_dh_flags_newmsgid,
    NULL
};
static int hf_mq_dh_putmsgrecfld;
static int hf_mq_dh_recspresent;
static int hf_mq_dh_objrecofs;
static int hf_mq_dh_putmsgrecofs;

static int hf_mq_iih_flags_passexpir;
static int hf_mq_iih_flags_replyfmtnone;
static int hf_mq_iih_flags_ignorepurg;
static int hf_mq_iih_flags_cmqrqstresp;
static int* const pf_flds_iih_flags[] =
{
    &hf_mq_iih_flags_cmqrqstresp,
    &hf_mq_iih_flags_ignorepurg,
    &hf_mq_iih_flags_replyfmtnone,
    &hf_mq_iih_flags_passexpir,
    NULL
};
static int hf_mq_iih_ltermoverride;
static int hf_mq_iih_mfsmapname;
static int hf_mq_iih_replytofmt;
static int hf_mq_iih_authenticator;
static int hf_mq_iih_transinstid;
static int hf_mq_iih_transstate;
static int hf_mq_iih_commimode;
static int hf_mq_iih_securityscope;
static int hf_mq_iih_reserved;

static int hf_mq_ims_ll;
static int hf_mq_ims_zz;
static int hf_mq_ims_trx;
static int hf_mq_ims_data;

static int hf_mq_tm_StructID;
static int hf_mq_tm_version;
static int hf_mq_tm_QName;
static int hf_mq_tm_ProcessNme;
static int hf_mq_tm_TriggerData;
static int hf_mq_tm_ApplType;
static int hf_mq_tm_ApplId;
static int hf_mq_tm_EnvData;
static int hf_mq_tm_UserData;

static int hf_mq_tmc2_StructID;
static int hf_mq_tmc2_version;
static int hf_mq_tmc2_QName;
static int hf_mq_tmc2_ProcessNme;
static int hf_mq_tmc2_TriggerData;
static int hf_mq_tmc2_ApplType;
static int hf_mq_tmc2_ApplId;
static int hf_mq_tmc2_EnvData;
static int hf_mq_tmc2_UserData;
static int hf_mq_tmc2_QMgrName;

static int hf_mq_cih_flags_synconret;
static int hf_mq_cih_flags_replywonulls;
static int hf_mq_cih_flags_passexpir;
static int* const pf_flds_cih_flags[] =
{
    &hf_mq_cih_flags_synconret,
    &hf_mq_cih_flags_replywonulls,
    &hf_mq_cih_flags_passexpir,
    NULL
};
static int hf_mq_cih_returncode;
static int hf_mq_cih_compcode;
static int hf_mq_cih_reasoncode;
static int hf_mq_cih_uowcontrols;
static int hf_mq_cih_getwaitintv;
static int hf_mq_cih_linktype;
static int hf_mq_cih_outdatalen;
static int hf_mq_cih_facilkeeptime;
static int hf_mq_cih_adsdescriptor;
static int hf_mq_cih_converstask;
static int hf_mq_cih_taskendstatus;
static int hf_mq_cih_bridgefactokn;
static int hf_mq_cih_function;
static int hf_mq_cih_abendcode;
static int hf_mq_cih_authenticator;
static int hf_mq_cih_reserved;
static int hf_mq_cih_replytofmt;
static int hf_mq_cih_remotesysid;
static int hf_mq_cih_remotetransid;
static int hf_mq_cih_transactionid;
static int hf_mq_cih_facilitylike;
static int hf_mq_cih_attentionid;
static int hf_mq_cih_startcode;
static int hf_mq_cih_cancelcode;
static int hf_mq_cih_nexttransid;
static int hf_mq_cih_reserved2;
static int hf_mq_cih_reserved3;
static int hf_mq_cih_cursorpos;
static int hf_mq_cih_erroroffset;
static int hf_mq_cih_inputitem;
static int hf_mq_cih_reserved4;

static int hf_mq_rfh_ccsid;
static int hf_mq_rfh_length;
static int hf_mq_rfh_string;

static int hf_mq_rmh_flags_last;
static int* const pf_flds_rmh_flags[] =
{
    &hf_mq_rmh_flags_last,
    NULL
};
static int hf_mq_rmh_objecttype;
static int hf_mq_rmh_objectinstid;
static int hf_mq_rmh_srcenvlen;
static int hf_mq_rmh_srcenvofs;
static int hf_mq_rmh_srcnamelen;
static int hf_mq_rmh_srcnameofs;
static int hf_mq_rmh_dstenvlen;
static int hf_mq_rmh_dstenvofs;
static int hf_mq_rmh_dstnamelen;
static int hf_mq_rmh_dstnameofs;
static int hf_mq_rmh_datalogiclen;
static int hf_mq_rmh_datalogicofsl;
static int hf_mq_rmh_datalogicofsh;

static int hf_mq_wih_servicename;
static int hf_mq_wih_servicestep;
static int hf_mq_wih_msgtoken;
static int hf_mq_wih_reserved;

static int ett_mq;
static int ett_mq_tsh;
static int ett_mq_tsh_tcf;
static int ett_mq_tsh_tcf2;
static int ett_mq_api;
static int ett_mq_socket;
static int ett_mq_caut;
static int ett_mq_msh;
static int ett_mq_xqh;
static int ett_mq_id;
static int ett_mq_id_cf1;
static int ett_mq_id_cf2;
static int ett_mq_id_cf3;
static int ett_mq_id_ecf1;
static int ett_mq_id_ecf2;
static int ett_mq_id_ecf3;
static int ett_mq_id_ief1;
static int ett_mq_id_ief2;
static int ett_mq_uid;
static int ett_mq_conn;
static int ett_mq_fcno;
static int ett_mq_msg;
static int ett_mq_inq;
static int ett_mq_spi;
static int ett_mq_spi_base; /* Factorisation of common SPI items */
static int ett_mq_spi_options;
static int ett_mq_put;
static int ett_mq_open;
static int ett_mq_open_option;
static int ett_mq_close_option;
static int ett_mq_fopa;
static int ett_mq_fcmi;
static int ett_mq_ping;
static int ett_mq_reset;
static int ett_mq_status;
static int ett_mq_od;
static int ett_mq_od_objstr;
static int ett_mq_od_selstr;
static int ett_mq_od_resobjstr;
static int ett_mq_or;
static int ett_mq_rr;
static int ett_mq_pmr;
static int ett_mq_md;
static int ett_mq_dlh;
static int ett_mq_dh;
static int ett_mq_gmo;
static int ett_mq_gmo_option;
static int ett_mq_gmo_matchoption;
static int ett_mq_pmo;
static int ett_mq_pmo_option;
static int ett_mq_rfh_ValueName;
static int ett_mq_msgreq_RqstFlags;

static int ett_mq_lpoo;
static int ett_mq_lpoo_lpiopts;

static int ett_mq_head; /* Factorisation of common Header structure items (DH, MDE, CIH, IIH, RFH, RMH, WIH, TM, TMC2 */
static int ett_mq_head_flags;
static int ett_mq_ims;

static int ett_mq_xa;
static int ett_mq_xa_tmflags;
static int ett_mq_xa_xid;
static int ett_mq_xa_info;
static int ett_mq_charv;
static int ett_mq_reassemb;
static int ett_mq_notif;

static int ett_mq_structid;

static expert_field ei_mq_reassembly_error;

static dissector_handle_t mq_handle;
static dissector_handle_t mq_spx_handle;
static dissector_handle_t mqpcf_handle;

static heur_dissector_list_t mq_heur_subdissector_list;

static bool mq_desegment = true;
static bool mq_reassembly = true;

static bool mq_in_reassembly;

static reassembly_table mq_reassembly_table;

DEF_VALSB(notifcode)
/*  1*/ DEF_VALS2(NC_GET_INHIBITED, "GET_INHIBITED"),
/*  2*/ DEF_VALS2(NC_GET_ALLOWED, "GET_ALLOWED"),
/*  3*/ DEF_VALS2(NC_CONN_STATE, "CONN_STATE"),
/*  4*/ DEF_VALS2(NC_CONN_STATE_REPLY, "CONN_STATE_REPLY"),
/*  5*/ DEF_VALS2(NC_Q_STATE, "Q_STATE"),
/*  6*/ DEF_VALS2(NC_Q_STATE_REPLY, "Q_STATE_REPLY"),
/*  7*/ DEF_VALS2(NC_QM_QUIESCING, "QM_QUIESCING"),
/*  8*/ DEF_VALS2(NC_TXN_ALLOWED, "TXN_ALLOWED"),
/*  9*/ DEF_VALS2(NC_TXN_REVOKE, "TXN_REVOKE"),
/* 10*/ DEF_VALS2(NC_TXN_REVOKE_REPLY, "TXN_REVOKE_REPLY"),
/* 11*/ DEF_VALS2(NC_CHECK_MSG, "CHECK_MSG"),
/* 12*/ DEF_VALS2(NC_BROWSE_FIRST, "BROWSE_FIRST"),
/* 13*/ DEF_VALS2(NC_MESSAGE_TOO_LARGE, "MESSAGE_TOO_LARGE"),
/* 14*/ DEF_VALS2(NC_STREAMING_FAILURE, "STREAMING_FAILURE"),
/* 15*/ DEF_VALS2(NC_CLIENT_ASYNC_EMPTY, "CLIENT_ASYNC_EMPTY"),
/* 16*/ DEF_VALS2(NC_STREAMING_TXN_PAUSED, "STREAMING_TXN_PAUSED"),
/* 17*/ DEF_VALS2(NC_RECONNECTION_COMPLETE, "RECONNECTION_COMPLETE"),
DEF_VALSE;

DEF_VALSB(spi_verbs)
/*  1*/ DEF_VALS2(SPI_QUERY, "QUERY"),
/*  2*/ DEF_VALS2(SPI_PUT, "PUT"),
/*  3*/ DEF_VALS2(SPI_GET, "GET"),
/*  4*/ DEF_VALS2(SPI_ACTIVATE, "ACTIVATE"),
/*  5*/ DEF_VALS2(SPI_SYNCHPOINT, "SYNCHPOINT"),
/*  6*/ DEF_VALS2(SPI_RESERVE, "RESERVE"),
/*  7*/ DEF_VALS2(SPI_SUBSCRIBE, "SUBSCRIBE"),
/* 11*/ DEF_VALS2(SPI_NOTIFY, "NOTIFY"),
/* 12*/ DEF_VALS2(SPI_OPEN, "OPEN"),
DEF_VALSE;

DEF_VALSB(spi_activate)
/* 1*/ DEF_VALS2(SPI_ACTIVATE_ENABLE, "ENABLE"),
/* 2*/ DEF_VALS2(SPI_ACTIVATE_DISABLE, "DISABLE"),
DEF_VALSE;

DEF_VALSB(status)
/*    1*/ DEF_VALS2(STATUS_ERR_NO_CHANNEL, "NO_CHANNEL"),
/*    2*/ DEF_VALS2(STATUS_ERR_CHANNEL_WRONG_TYPE, "CHANNEL_WRONG_TYPE"),
/*    3*/ DEF_VALS2(STATUS_ERR_QM_UNAVAILABLE, "QM_UNAVAILABLE"),
/*    4*/ DEF_VALS2(STATUS_ERR_MSG_SEQUENCE_ERROR, "MSG_SEQUENCE_ERROR"),
/*    5*/ DEF_VALS2(STATUS_ERR_QM_TERMINATING, "QM_TERMINATING"),
/*    6*/ DEF_VALS2(STATUS_ERR_CAN_NOT_STORE, "CAN_NOT_STORE"),
/*    7*/ DEF_VALS2(STATUS_ERR_USER_CLOSED, "USER_CLOSED"),
/*   10*/ DEF_VALS2(STATUS_ERR_PROTOCOL_SEGMENT_TYPE, "REMOTE_PROTOCOL_ERROR"),
/*   11*/ DEF_VALS2(STATUS_ERR_PROTOCOL_LENGTH_ERROR, "BIND_FAILED"),
/*   12*/ DEF_VALS2(STATUS_ERR_PROTOCOL_INVALID_DATA, "MSGWRAP_DIFFERENT"),
/*   14*/ DEF_VALS2(STATUS_ERR_PROTOCOL_ID_ERROR, "REMOTE_CHANNEL_UNAVAILABLE"),
/*   15*/ DEF_VALS2(STATUS_ERR_PROTOCOL_MSH_ERROR, "TERMINATED_BY_REMOTE_EXIT"),
/*   16*/ DEF_VALS2(STATUS_ERR_PROTOCOL_GENERAL, "PROTOCOL_GENERAL"),
/*   17*/ DEF_VALS2(STATUS_ERR_BATCH_FAILURE, "BATCH_FAILURE"),
/*   18*/ DEF_VALS2(STATUS_ERR_MESSAGE_LENGTH_ERROR, "MESSAGE_LENGTH_ERROR"),
/*   19*/ DEF_VALS2(STATUS_ERR_SEGMENT_NUMBER_ERROR, "SEGMENT_NUMBER_ERROR"),
/*   20*/ DEF_VALS2(STATUS_ERR_SECURITY_FAILURE, "SECURITY_FAILURE"),
/*   21*/ DEF_VALS2(STATUS_ERR_WRAP_VALUE_ERROR, "WRAP_VALUE_ERROR"),
/*   22*/ DEF_VALS2(STATUS_ERR_CHANNEL_UNAVAILABLE, "CHANNEL_UNAVAILABLE"),
/*   23*/ DEF_VALS2(STATUS_ERR_CLOSED_BY_EXIT, "CLOSED_BY_EXIT"),
/*   24*/ DEF_VALS2(STATUS_ERR_CIPHER_SPEC, "CIPHER_SPEC"),
/*   25*/ DEF_VALS2(STATUS_ERR_PEER_NAME, "PEER_NAME"),
/*   26*/ DEF_VALS2(STATUS_ERR_SSL_CLIENT_CERTIFICATE, "SSL_CLIENT_CERTIFICATE"),
/*   27*/ DEF_VALS2(STATUS_ERR_RMT_RSRCS_IN_RECOVERY, "RMT_RSRCS_IN_RECOVERY"),
/*   28*/ DEF_VALS2(STATUS_ERR_SSL_REFRESHING, "SSL_REFRESHING"),
/*   29*/ DEF_VALS2(STATUS_ERR_INVALID_HOBJ, "INVALID_HOBJ"),
/*   30*/ DEF_VALS2(STATUS_ERR_CONV_ID_ERROR, "CONV_ID_ERROR"),
/*   31*/ DEF_VALS2(STATUS_ERR_SOCKET_ACTION_TYPE, "SOCKET_ACTION_TYPE"),
/*   32*/ DEF_VALS2(STATUS_ERR_STANDBY_Q_MGR, "STANDBY_Q_MGR"),
/*  240*/ DEF_VALS2(STATUS_ERR_CCSID_NOT_SUPPORTED, "CCSID_NOT_SUPPORTED"),
/*  241*/ DEF_VALS2(STATUS_ERR_ENCODING_INVALID, "ENCODING_INVALID"),
/*  242*/ DEF_VALS2(STATUS_ERR_FAP_LEVEL, "FAP_LEVEL"),
/*  243*/ DEF_VALS2(STATUS_ERR_NEGOTIATION_FAILED, "NEGOTIATION_FAILED"),
DEF_VALSE;
DEF_VALS_EXTB(status);

DEF_VALSB(opcode)
/*    1*/ DEF_VALS2(TST_INITIAL, "INITIAL_DATA"),
/*    2*/ DEF_VALS2(TST_RESYNC, "RESYNC_DATA"),
/*    3*/ DEF_VALS2(TST_RESET, "RESET_DATA"),
/*    4*/ DEF_VALS2(TST_MESSAGE, "MESSAGE_DATA"),
/*    5*/ DEF_VALS2(TST_STATUS, "STATUS_DATA"),
/*    6*/ DEF_VALS2(TST_SECURITY, "SECURITY_DATA"),
/*    7*/ DEF_VALS2(TST_PING, "PING_DATA"),
/*    8*/ DEF_VALS2(TST_USERID, "USERID_DATA"),
/*    9*/ DEF_VALS2(TST_HEARTBEAT, "HEARTBEAT"),
/*   10*/ DEF_VALS2(TST_CONAUTH_INFO, "CONAUTH_INFO"),
/*   11*/ DEF_VALS2(TST_RENEGOTIATE_DATA, "RENEGOTIATE_DATA"),
/*   12*/ DEF_VALS2(TST_SOCKET_ACTION, "SOCKET_ACTION"),
/*   13*/ DEF_VALS2(TST_ASYNC_MESSAGE, "ASYNC_MESSAGE"),
/*   14*/ DEF_VALS2(TST_REQUEST_MSGS, "REQUEST_MSGS"),
/*   15*/ DEF_VALS2(TST_NOTIFICATION, "NOTIFICATION"),
/*  129*/ DEF_VALS2(TST_MQCONN, "MQCONN"),
/*  130*/ DEF_VALS2(TST_MQDISC, "MQDISC"),
/*  131*/ DEF_VALS2(TST_MQOPEN, "MQOPEN"),
/*  132*/ DEF_VALS2(TST_MQCLOSE, "MQCLOSE"),
/*  133*/ DEF_VALS2(TST_MQGET, "MQGET"),
/*  134*/ DEF_VALS2(TST_MQPUT, "MQPUT"),
/*  135*/ DEF_VALS2(TST_MQPUT1, "MQPUT1"),
/*  136*/ DEF_VALS2(TST_MQSET, "MQSET"),
/*  137*/ DEF_VALS2(TST_MQINQ, "MQINQ"),
/*  138*/ DEF_VALS2(TST_MQCMIT, "MQCMIT"),
/*  139*/ DEF_VALS2(TST_MQBACK, "MQBACK"),
/*  140*/ DEF_VALS2(TST_SPI, "SPI"),
/*  141*/ DEF_VALS2(TST_MQSTAT, "MQSTAT"),
/*  142*/ DEF_VALS2(TST_MQSUB, "MQSUB"),
/*  143*/ DEF_VALS2(TST_MQSUBRQ, "MQSUBRQ"),
/*  145*/ DEF_VALS2(TST_MQCONN_REPLY, "MQCONN_REPLY"),
/*  146*/ DEF_VALS2(TST_MQDISC_REPLY, "MQDISC_REPLY"),
/*  147*/ DEF_VALS2(TST_MQOPEN_REPLY, "MQOPEN_REPLY"),
/*  148*/ DEF_VALS2(TST_MQCLOSE_REPLY, "MQCLOSE_REPLY"),
/*  149*/ DEF_VALS2(TST_MQGET_REPLY, "MQGET_REPLY"),
/*  150*/ DEF_VALS2(TST_MQPUT_REPLY, "MQPUT_REPLY"),
/*  151*/ DEF_VALS2(TST_MQPUT1_REPLY, "MQPUT1_REPLY"),
/*  152*/ DEF_VALS2(TST_MQSET_REPLY, "MQSET_REPLY"),
/*  153*/ DEF_VALS2(TST_MQINQ_REPLY, "MQINQ_REPLY"),
/*  154*/ DEF_VALS2(TST_MQCMIT_REPLY, "MQCMIT_REPLY"),
/*  155*/ DEF_VALS2(TST_MQBACK_REPLY, "MQBACK_REPLY"),
/*  156*/ DEF_VALS2(TST_SPI_REPLY, "SPI_REPLY"),
/*  157*/ DEF_VALS2(TST_MQSTAT_REPLY, "MQSTAT_REPLY"),
/*  158*/ DEF_VALS2(TST_MQSUB_REPLY, "MQSUB_REPLY"),
/*  159*/ DEF_VALS2(TST_MQSUBRQ_REPLY, "MQSUBRQ_REPLY"),
/*  161*/ DEF_VALS2(TST_XA_START, "XA_START"),
/*  162*/ DEF_VALS2(TST_XA_END, "XA_END"),
/*  163*/ DEF_VALS2(TST_XA_OPEN, "XA_OPEN"),
/*  164*/ DEF_VALS2(TST_XA_CLOSE, "XA_CLOSE"),
/*  165*/ DEF_VALS2(TST_XA_PREPARE, "XA_PREPARE"),
/*  166*/ DEF_VALS2(TST_XA_COMMIT, "XA_COMMIT"),
/*  167*/ DEF_VALS2(TST_XA_ROLLBACK, "XA_ROLLBACK"),
/*  168*/ DEF_VALS2(TST_XA_FORGET, "XA_FORGET"),
/*  169*/ DEF_VALS2(TST_XA_RECOVER, "XA_RECOVER"),
/*  170*/ DEF_VALS2(TST_XA_COMPLETE, "XA_COMPLETE"),
/*  177*/ DEF_VALS2(TST_XA_START_REPLY, "XA_START_REPLY"),
/*  178*/ DEF_VALS2(TST_XA_END_REPLY, "XA_END_REPLY"),
/*  179*/ DEF_VALS2(TST_XA_OPEN_REPLY, "XA_OPEN_REPLY"),
/*  180*/ DEF_VALS2(TST_XA_CLOSE_REPLY, "XA_CLOSE_REPLY"),
/*  181*/ DEF_VALS2(TST_XA_PREPARE_REPLY, "XA_PREPARE_REPLY"),
/*  182*/ DEF_VALS2(TST_XA_COMMIT_REPLY, "XA_COMMIT_REPLY"),
/*  183*/ DEF_VALS2(TST_XA_ROLLBACK_REPLY, "XA_ROLLBACK_REPLY"),
/*  184*/ DEF_VALS2(TST_XA_FORGET_REPLY, "XA_FORGET_REPLY"),
/*  185*/ DEF_VALS2(TST_XA_RECOVER_REPLY, "XA_RECOVER_REPLY"),
/*  186*/ DEF_VALS2(TST_XA_COMPLETE_REPLY, "XA_COMPLETE_REPLY"),
DEF_VALSE;
DEF_VALS_EXTB(opcode);

DEF_VALSB(xaer)
/*   0*/ DEF_VALS2(XA_OK, "XA_OK"),
/*   3*/ DEF_VALS2(XA_RDONLY, "XA_RDONLY"),
/*   4*/ DEF_VALS2(XA_RETRY, "XA_RETRY"),
/*   5*/ DEF_VALS2(XA_HEURMIX, "XA_HEURMIX"),
/*   6*/ DEF_VALS2(XA_HEURRB, "XA_HEURRB"),
/*   7*/ DEF_VALS2(XA_HEURCOM, "XA_HEURCOM"),
/*   8*/ DEF_VALS2(XA_HEURHAZ, "XA_HEURHAZ"),
/*   9*/ DEF_VALS2(XA_NOMIGRATE, "XA_NOMIGRATE"),
/* 100*/ DEF_VALS2(XA_RBROLLBACK, "XA_RBROLLBACK"),
/* 101*/ DEF_VALS2(XA_RBCOMMFAIL, "XA_RBCOMMFAIL"),
/* 102*/ DEF_VALS2(XA_RBDEADLOCK, "XA_RBDEADLOCK"),
/* 103*/ DEF_VALS2(XA_RBINTEGRITY, "XA_RBINTEGRITY"),
/* 104*/ DEF_VALS2(XA_RBOTHER, "XA_RBOTHER"),
/* 105*/ DEF_VALS2(XA_RBPROTO, "XA_RBPROTO"),
/* 106*/ DEF_VALS2(XA_RBTIMEOUT, "XA_RBTIMEOUT"),
/* 107*/ DEF_VALS2(XA_RBTRANSIENT, "XA_RBTRANSIENT"),
/*  -9*/ DEF_VALS2(XAER_OUTSIDE, "XAER_OUTSIDE"),
/*  -8*/ DEF_VALS2(XAER_DUPID, "XAER_DUPID"),
/*  -7*/ DEF_VALS2(XAER_RMFAIL, "XAER_RMFAIL"),
/*  -6*/ DEF_VALS2(XAER_PROTO, "XAER_PROTO"),
/*  -5*/ DEF_VALS2(XAER_INVAL, "XAER_INVAL"),
/*  -4*/ DEF_VALS2(XAER_NOTA, "XAER_NOTA"),
/*  -3*/ DEF_VALS2(XAER_RMERR, "XAER_RMERR"),
/*  -2*/ DEF_VALS2(XAER_ASYNC, "XAER_ASYNC"),
DEF_VALSE;

DEF_VALSB(StructID)
/* CAUT*/ DEF_VALS2(STRUCTID_CAUT, MQ_TEXT_CAUT),
/* CIH */ DEF_VALS2(STRUCTID_CIH, MQ_TEXT_CIH),
/* DH  */ DEF_VALS2(STRUCTID_DH, MQ_TEXT_DH),
/* DLH */ DEF_VALS2(STRUCTID_DLH, MQ_TEXT_DLH),
/* FCNO*/ DEF_VALS2(STRUCTID_FCNO, MQ_TEXT_FCNO),
/* FOPA*/ DEF_VALS2(STRUCTID_FOPA, MQ_TEXT_FOPA),
/* GMO */ DEF_VALS2(STRUCTID_GMO, MQ_TEXT_GMO),
/* ID  */ DEF_VALS2(STRUCTID_ID, MQ_TEXT_ID),
/* IIH */ DEF_VALS2(STRUCTID_IIH, MQ_TEXT_IIH),
/* LPOO*/ DEF_VALS2(STRUCTID_LPOO, MQ_TEXT_LPOO),
/* MD  */ DEF_VALS2(STRUCTID_MD, MQ_TEXT_MD),
/* MDE */ DEF_VALS2(STRUCTID_MDE, MQ_TEXT_MDE),
/* MSH */ DEF_VALS2(STRUCTID_MSH, MQ_TEXT_MSH),
/* OD  */ DEF_VALS2(STRUCTID_OD, MQ_TEXT_OD),
/* PMO */ DEF_VALS2(STRUCTID_PMO, MQ_TEXT_PMO),
/* RFH */ DEF_VALS2(STRUCTID_RFH, MQ_TEXT_RFH),
/* RMH */ DEF_VALS2(STRUCTID_RMH, MQ_TEXT_RMH),
/* SPAI*/ DEF_VALS2(STRUCTID_SPAI, MQ_TEXT_SPAI),
/* SPAO*/ DEF_VALS2(STRUCTID_SPAO, MQ_TEXT_SPAO),
/* SPAU*/ DEF_VALS2(STRUCTID_SPAU, MQ_TEXT_SPAU),
/* SPGI*/ DEF_VALS2(STRUCTID_SPGI, MQ_TEXT_SPGI),
/* SPGO*/ DEF_VALS2(STRUCTID_SPGO, MQ_TEXT_SPGO),
/* SPGU*/ DEF_VALS2(STRUCTID_SPGU, MQ_TEXT_SPGU),
/* SPOI*/ DEF_VALS2(STRUCTID_SPOI, MQ_TEXT_SPOI),
/* SPOO*/ DEF_VALS2(STRUCTID_SPOO, MQ_TEXT_SPOO),
/* SPOU*/ DEF_VALS2(STRUCTID_SPOU, MQ_TEXT_SPOU),
/* SPPI*/ DEF_VALS2(STRUCTID_SPPI, MQ_TEXT_SPPI),
/* SPPO*/ DEF_VALS2(STRUCTID_SPPO, MQ_TEXT_SPPO),
/* SPPU*/ DEF_VALS2(STRUCTID_SPPU, MQ_TEXT_SPPU),
/* SPQI*/ DEF_VALS2(STRUCTID_SPQI, MQ_TEXT_SPQI),
/* SPQO*/ DEF_VALS2(STRUCTID_SPQO, MQ_TEXT_SPQO),
/* SPQU*/ DEF_VALS2(STRUCTID_SPQU, MQ_TEXT_SPQU),
/* TM  */ DEF_VALS2(STRUCTID_TM, MQ_TEXT_TM),
/* TMC2*/ DEF_VALS2(STRUCTID_TMC2, MQ_TEXT_TMC2),
/* TSH */ DEF_VALS2(STRUCTID_TSH, MQ_TEXT_TSH),
/* TSHC*/ DEF_VALS2(STRUCTID_TSHC, MQ_TEXT_TSHC),
/* TSHM*/ DEF_VALS2(STRUCTID_TSHM, MQ_TEXT_TSHM),
/* UID */ DEF_VALS2(STRUCTID_UID, MQ_TEXT_UID),
/* WIH */ DEF_VALS2(STRUCTID_WIH, MQ_TEXT_WIH),
/* XQH */ DEF_VALS2(STRUCTID_XQH, MQ_TEXT_XQH),

/* CAUT*/ DEF_VALS2(STRUCTID_CAUT_EBCDIC, MQ_TEXT_CAUT),
/* CIH */ DEF_VALS2(STRUCTID_CIH_EBCDIC, MQ_TEXT_CIH),
/* DH  */ DEF_VALS2(STRUCTID_DH_EBCDIC, MQ_TEXT_DH),
/* DLH */ DEF_VALS2(STRUCTID_DLH_EBCDIC, MQ_TEXT_DLH),
/* FCNO*/ DEF_VALS2(STRUCTID_FCNO_EBCDIC, MQ_TEXT_FCNO),
/* FOPA*/ DEF_VALS2(STRUCTID_FOPA_EBCDIC, MQ_TEXT_FOPA),
/* GMO */ DEF_VALS2(STRUCTID_GMO_EBCDIC, MQ_TEXT_GMO),
/* ID  */ DEF_VALS2(STRUCTID_ID_EBCDIC, MQ_TEXT_ID),
/* IIH */ DEF_VALS2(STRUCTID_IIH_EBCDIC, MQ_TEXT_IIH),
/* LPOO*/ DEF_VALS2(STRUCTID_LPOO_EBCDIC, MQ_TEXT_LPOO),
/* MD  */ DEF_VALS2(STRUCTID_MD_EBCDIC, MQ_TEXT_MD),
/* MDE */ DEF_VALS2(STRUCTID_MDE_EBCDIC, MQ_TEXT_MDE),
/* OD  */ DEF_VALS2(STRUCTID_OD_EBCDIC, MQ_TEXT_OD),
/* PMO */ DEF_VALS2(STRUCTID_PMO_EBCDIC, MQ_TEXT_PMO),
/* RFH */ DEF_VALS2(STRUCTID_RFH_EBCDIC, MQ_TEXT_RFH),
/* RMH */ DEF_VALS2(STRUCTID_RMH_EBCDIC, MQ_TEXT_RMH),
/* SPAI*/ DEF_VALS2(STRUCTID_SPAI_EBCDIC, MQ_TEXT_SPAI),
/* SPAO*/ DEF_VALS2(STRUCTID_SPAO_EBCDIC, MQ_TEXT_SPAO),
/* SPAU*/ DEF_VALS2(STRUCTID_SPAU_EBCDIC, MQ_TEXT_SPAU),
/* SPGI*/ DEF_VALS2(STRUCTID_SPGI_EBCDIC, MQ_TEXT_SPGI),
/* SPGO*/ DEF_VALS2(STRUCTID_SPGO_EBCDIC, MQ_TEXT_SPGO),
/* SPGU*/ DEF_VALS2(STRUCTID_SPGU_EBCDIC, MQ_TEXT_SPGU),
/* SPOI*/ DEF_VALS2(STRUCTID_SPOI_EBCDIC, MQ_TEXT_SPOI),
/* SPOO*/ DEF_VALS2(STRUCTID_SPOO_EBCDIC, MQ_TEXT_SPOO),
/* SPOU*/ DEF_VALS2(STRUCTID_SPOU_EBCDIC, MQ_TEXT_SPOU),
/* SPPI*/ DEF_VALS2(STRUCTID_SPPI_EBCDIC, MQ_TEXT_SPPI),
/* SPPO*/ DEF_VALS2(STRUCTID_SPPO_EBCDIC, MQ_TEXT_SPPO),
/* SPPU*/ DEF_VALS2(STRUCTID_SPPU_EBCDIC, MQ_TEXT_SPPU),
/* SPQI*/ DEF_VALS2(STRUCTID_SPQI_EBCDIC, MQ_TEXT_SPQI),
/* SPQO*/ DEF_VALS2(STRUCTID_SPQO_EBCDIC, MQ_TEXT_SPQO),
/* SPQU*/ DEF_VALS2(STRUCTID_SPQU_EBCDIC, MQ_TEXT_SPQU),
/* TM  */ DEF_VALS2(STRUCTID_TM_EBCDIC, MQ_TEXT_TM),
/* TMC2*/ DEF_VALS2(STRUCTID_TMC2_EBCDIC, MQ_TEXT_TMC2),
/* TSH */ DEF_VALS2(STRUCTID_TSH_EBCDIC, MQ_TEXT_TSH),
/* TSHC*/ DEF_VALS2(STRUCTID_TSHC_EBCDIC, MQ_TEXT_TSHC),
/* TSHM*/ DEF_VALS2(STRUCTID_TSHM_EBCDIC, MQ_TEXT_TSHM),
/* UID */ DEF_VALS2(STRUCTID_UID_EBCDIC, MQ_TEXT_UID),
/* WIH */ DEF_VALS2(STRUCTID_WIH_EBCDIC, MQ_TEXT_WIH),
/* XQH */ DEF_VALS2(STRUCTID_XQH_EBCDIC, MQ_TEXT_XQH),
DEF_VALSE;
DEF_VALS_EXTB(StructID);

DEF_VALSB(byteorder)
/* 1*/ DEF_VALS2(BIG_ENDIAN, "Big endian"),
/* 2*/ DEF_VALS2(LITTLE_ENDIAN, "Little endian"),
DEF_VALSE;

DEF_VALSB(conn_options)
/* 1*/ DEF_VALS2(CONN_OPTION, "MQCONN"),
/* 3*/ DEF_VALS2(CONNX_OPTION, "MQCONNX"),
DEF_VALSE;

DEF_VALSB(sidtype)
/* 0*/ DEF_VALS1(MQSIDT_NONE),
/* 1*/ DEF_VALS1(MQSIDT_NT_SECURITY_ID),
/* 2*/ DEF_VALS1(MQSIDT_WAS_SECURITY_ID),
DEF_VALSE;

static int dissect_mq_encoding(proto_tree* tree, int hfindex, tvbuff_t* tvb, const int start, int length, const unsigned encoding)
{
    char   sEnc[128] = "";
    char* pEnc;
    unsigned  uEnc;

    if (length == 2)
    {
        uEnc = (int)tvb_get_uint16(tvb, start, encoding);
    }
    else
    {
        uEnc = tvb_get_uint32(tvb, start, encoding);
    }
    pEnc = sEnc;

#define CHECK_ENC(M, T) ((uEnc & M) == T)
#define DOPRT(A) pEnc += snprintf(pEnc, sizeof(sEnc)-1-(pEnc-sEnc), A);
    if (CHECK_ENC(MQ_MQENC_FLOAT_MASK, MQ_MQENC_FLOAT_UNDEFINED))
    {
        DOPRT("FLT_UNDEFINED");
    }
    else if (CHECK_ENC(MQ_MQENC_FLOAT_MASK, MQ_MQENC_FLOAT_IEEE_NORMAL))
    {
        DOPRT("FLT_IEEE_NORMAL");
    }
    else if (CHECK_ENC(MQ_MQENC_FLOAT_MASK, MQ_MQENC_FLOAT_IEEE_REVERSED))
    {
        DOPRT("FLT_IEEE_REVERSED");
    }
    else if (CHECK_ENC(MQ_MQENC_FLOAT_MASK, MQ_MQENC_FLOAT_S390))
    {
        DOPRT("FLT_S390");
    }
    else if (CHECK_ENC(MQ_MQENC_FLOAT_MASK, MQ_MQENC_FLOAT_TNS))
    {
        DOPRT("FLT_TNS");
    }
    else
    {
        DOPRT("FLT_UNKNOWN");
    }

    DOPRT("/");
    if (CHECK_ENC(MQ_MQENC_DECIMAL_MASK, MQ_MQENC_DECIMAL_UNDEFINED))
    {
        DOPRT("DEC_UNDEFINED");
    }
    else if (CHECK_ENC(MQ_MQENC_DECIMAL_MASK, MQ_MQENC_DECIMAL_NORMAL))
    {
        DOPRT("DEC_NORMAL");
    }
    else if (CHECK_ENC(MQ_MQENC_DECIMAL_MASK, MQ_MQENC_DECIMAL_REVERSED))
    {
        DOPRT("DEC_REVERSED");
    }
    else
    {
        DOPRT("DEC_UNKNOWN");
    }

    DOPRT("/");
    if (CHECK_ENC(MQ_MQENC_INTEGER_MASK, MQ_MQENC_INTEGER_UNDEFINED))
    {
        DOPRT("INT_UNDEFINED");
    }
    else if (CHECK_ENC(MQ_MQENC_INTEGER_MASK, MQ_MQENC_INTEGER_NORMAL))
    {
        DOPRT("INT_NORMAL");
    }
    else if (CHECK_ENC(MQ_MQENC_INTEGER_MASK, MQ_MQENC_INTEGER_REVERSED))
    {
        DOPRT("INT_REVERSED");
    }
    else
    {
        DOPRT("INT_UNKNOWN");
    }
#undef CHECK_ENC
#undef DOPRT

    proto_tree_add_uint_format_value(tree, hfindex, tvb, start, length, uEnc,
        "%8x-%d (%s)", uEnc, uEnc, sEnc);

    return length;
}

static int dissect_mq_MQMO(tvbuff_t* tvb, proto_tree* mq_tree, int offset, int ett_subtree, mq_parm_t* p_mq_parm)
{
    unsigned     uMoOpt;

    uMoOpt = tvb_get_uint32(tvb, offset, p_mq_parm->mq_int_enc);

    if (uMoOpt == 0)
    {
        proto_item* ti;
        proto_tree* mq_tree_sub;
        ti = proto_tree_add_item(mq_tree, hf_mq_gmo_matchoptions, tvb, offset, 4, p_mq_parm->mq_int_enc); /* ENC_BIG_ENDIAN); */
        mq_tree_sub = proto_item_add_subtree(ti, ett_subtree);
        proto_tree_add_subtree_format(mq_tree_sub, tvb, offset, 4, ett_subtree, NULL, MQ_TEXT_MQMO_NONE);
    }
    else
    {
        proto_tree_add_bitmask(mq_tree, tvb, offset, hf_mq_gmo_matchoptions, ett_subtree, pf_flds_mtchopt, p_mq_parm->mq_int_enc);
    }
    return 4;
}
static int dissect_mq_LPOO_LPIOPTS(tvbuff_t* tvb, proto_tree* mq_tree, int offset, int ett_subtree, mq_parm_t* p_mq_parm)
{
    unsigned     uLpiOpts;

    uLpiOpts = tvb_get_uint32(tvb, offset, p_mq_parm->mq_int_enc);

    if (uLpiOpts == 0)
    {
        proto_item* ti;
        proto_tree* mq_tree_sub;
        ti = proto_tree_add_item(mq_tree, hf_mq_lpoo_lpiopts, tvb, offset, 4, p_mq_parm->mq_int_enc);
        mq_tree_sub = proto_item_add_subtree(ti, ett_subtree);
        proto_tree_add_subtree_format(mq_tree_sub, tvb, offset, 4, ett_subtree, NULL, MQ_TEXT_LPOOOPT_NONE);
    }
    else
    {
        proto_tree_add_bitmask(mq_tree, tvb, offset, hf_mq_lpoo_lpiopts, ett_subtree, pf_flds_lpooopt, p_mq_parm->mq_int_enc);
    }
    return 4;
}
static int dissect_mq_MQGMO(tvbuff_t* tvb, proto_tree* mq_tree, int offset, int ett_subtree, mq_parm_t* p_mq_parm)
{
    unsigned     uGmoOpt;

    uGmoOpt = tvb_get_uint32(tvb, offset, p_mq_parm->mq_int_enc);

    if (uGmoOpt == 0)
    {
        proto_item* ti;
        proto_tree* mq_tree_sub;
        ti = proto_tree_add_item(mq_tree, hf_mq_gmo_options, tvb, offset, 4, p_mq_parm->mq_int_enc); /* ENC_BIG_ENDIAN); */
        mq_tree_sub = proto_item_add_subtree(ti, ett_subtree);
        proto_tree_add_subtree_format(mq_tree_sub, tvb, offset, 4, ett_subtree, NULL, MQ_TEXT_MQGMO_NONE);
    }
    else
    {
        proto_tree_add_bitmask(mq_tree, tvb, offset, hf_mq_gmo_options, ett_subtree, pf_flds_gmoopt, p_mq_parm->mq_int_enc);
    }
    return 4;
}

static int dissect_mq_MQPMO(tvbuff_t* tvb, proto_tree* mq_tree, int offset, int ett_subtree, mq_parm_t* p_mq_parm)
{
    unsigned     uPmoOpt;

    uPmoOpt = tvb_get_uint32(tvb, offset, p_mq_parm->mq_int_enc);

    if (uPmoOpt == 0)
    {
        proto_item* ti;
        proto_tree* mq_tree_sub;
        ti = proto_tree_add_item(mq_tree, hf_mq_pmo_options, tvb, offset, 4, p_mq_parm->mq_int_enc); /* ENC_BIG_ENDIAN); */
        mq_tree_sub = proto_item_add_subtree(ti, ett_subtree);
        proto_tree_add_subtree_format(mq_tree_sub, tvb, offset, 4, ett_subtree, NULL, MQ_TEXT_MQPMO_NONE);
    }
    else
    {
        proto_tree_add_bitmask(mq_tree, tvb, offset, hf_mq_pmo_options, ett_subtree, pf_flds_pmoopt, p_mq_parm->mq_int_enc);
    }
    return 4;
}

static int dissect_mq_MQOO(tvbuff_t* tvb, proto_tree* mq_tree, int offset, int ett_subtree, int hfindex, mq_parm_t* p_mq_parm)
{
    unsigned     uOpenOpt;

    uOpenOpt = tvb_get_uint32(tvb, offset, p_mq_parm->mq_int_enc);

    if (uOpenOpt == 0)
    {
        proto_item* ti;
        proto_tree* mq_tree_sub;
        ti = proto_tree_add_item(mq_tree, hfindex, tvb, offset, 4, p_mq_parm->mq_int_enc);
        mq_tree_sub = proto_item_add_subtree(ti, ett_subtree);
        proto_tree_add_subtree_format(mq_tree_sub, tvb, offset, 4, ett_subtree, NULL, MQ_TEXT_BIND_READAHEAD_AS_Q_DEF);
    }
    else
    {
        proto_tree_add_bitmask(mq_tree, tvb, offset, hfindex, ett_subtree, pf_flds_opnopt, p_mq_parm->mq_int_enc);
    }
    return 4;
}
static int dissect_mq_MQCO(tvbuff_t* tvb, proto_tree* mq_tree, int offset, mq_parm_t* p_mq_parm)
{
    unsigned     iCloseOpt;

    iCloseOpt = tvb_get_uint32(tvb, offset, p_mq_parm->mq_int_enc);

    if (iCloseOpt == 0)
    {
        proto_item* ti;
        proto_tree* mq_tree_sub;
        ti = proto_tree_add_item(mq_tree, hf_mq_close_options, tvb, offset, 4, p_mq_parm->mq_int_enc);
        mq_tree_sub = proto_item_add_subtree(ti, ett_mq_close_option);
        proto_tree_add_subtree_format(mq_tree_sub, tvb, offset, 4, ett_mq_close_option, NULL, MQ_TEXT_IMMEDIATE_NONE);
    }
    else
    {
        proto_tree_add_bitmask(mq_tree, tvb, offset, hf_mq_close_options, ett_mq_close_option, pf_flds_clsopt, p_mq_parm->mq_int_enc);
    }
    return 4;
}
static int dissect_mq_charv(tvbuff_t* tvb, proto_tree* tree, int offset, int iSize, int idx, const char* pStr, mq_parm_t* p_mq_parm)
{
    proto_tree* mq_tree_sub;
    uint32_t    lStr;
    uint32_t    oStr;
    int32_t     eStr;
    const char* sStr;

    lStr = tvb_get_uint32(tvb, offset + 12, p_mq_parm->mq_int_enc);
    oStr = tvb_get_uint32(tvb, offset + 4, p_mq_parm->mq_int_enc);
    eStr = tvb_get_uint32(tvb, offset + 16, p_mq_parm->mq_int_enc);
    if (lStr && oStr)
    {
        sStr = (const char*)tvb_get_string_enc(wmem_packet_scope(), tvb, oStr, lStr, p_mq_parm->mq_str_enc);
    }
    else
        sStr = NULL;

    mq_tree_sub = proto_tree_add_subtree_format(tree, tvb, offset, iSize, idx, NULL, "%s - %s", pStr, (sStr) ? sStr : "[Empty]");

    proto_tree_add_item(mq_tree_sub, hf_mq_charv_vsptr, tvb, offset, 4, p_mq_parm->mq_int_enc);
    proto_tree_add_item(mq_tree_sub, hf_mq_charv_vsoffset, tvb, offset + 4, 4, p_mq_parm->mq_int_enc);
    proto_tree_add_item(mq_tree_sub, hf_mq_charv_vsbufsize, tvb, offset + 8, 4, p_mq_parm->mq_int_enc);
    proto_tree_add_item(mq_tree_sub, hf_mq_charv_vslength, tvb, offset + 12, 4, p_mq_parm->mq_int_enc);
    proto_tree_add_item(mq_tree_sub, hf_mq_charv_vsccsid, tvb, offset + 16, 4, p_mq_parm->mq_int_enc);
    proto_tree_add_item(mq_tree_sub, hf_mq_charv_vsvalue, tvb, oStr, lStr, IS_EBCDIC(eStr) ? ENC_EBCDIC : ENC_ASCII);

    return 20;
}
static int dissect_mq_pmr(tvbuff_t* tvb, proto_tree* tree, int offset, int iNbrRecords, int offsetPMR, uint32_t recFlags, mq_parm_t* p_mq_parm)
{
    int iSizePMR1 = 0;
    int iSizePMR = 0;

    iSizePMR1 = ((((recFlags & MQ_PMRF_MSG_ID) != 0) * 24)
        + (((recFlags & MQ_PMRF_CORREL_ID) != 0) * 24)
        + (((recFlags & MQ_PMRF_GROUP_ID) != 0) * 24)
        + (((recFlags & MQ_PMRF_FEEDBACK) != 0) * 4)
        + (((recFlags & MQ_PMRF_ACCOUNTING_TOKEN) != 0) * 32));

    if (offsetPMR != 0 && iSizePMR1 != 0)
    {
        iSizePMR = iNbrRecords * iSizePMR1;
        if (tvb_reported_length_remaining(tvb, offset) >= iSizePMR)
        {
            int iOffsetPMR = 0;
            int iRecord = 0;
            for (iRecord = 0; iRecord < iNbrRecords; iRecord++)
            {
                proto_tree* mq_tree = proto_tree_add_subtree(tree, tvb, offset + iOffsetPMR, iSizePMR1, ett_mq_pmr, NULL, MQ_TEXT_PMR);
                if ((recFlags & MQ_PMRF_MSG_ID) != 0)
                {
                    proto_tree_add_item(mq_tree, hf_mq_pmr_msgid, tvb, offset + iOffsetPMR, 24, ENC_NA);
                    iOffsetPMR += 24;
                }
                if ((recFlags & MQ_PMRF_CORREL_ID) != 0)
                {
                    proto_tree_add_item(mq_tree, hf_mq_pmr_correlid, tvb, offset + iOffsetPMR, 24, ENC_NA);
                    iOffsetPMR += 24;
                }
                if ((recFlags & MQ_PMRF_GROUP_ID) != 0)
                {
                    proto_tree_add_item(mq_tree, hf_mq_pmr_groupid, tvb, offset + iOffsetPMR, 24, ENC_NA);
                    iOffsetPMR += 24;
                }
                if ((recFlags & MQ_PMRF_FEEDBACK) != 0)
                {
                    proto_tree_add_item(mq_tree, hf_mq_pmr_feedback, tvb, offset + iOffsetPMR, 4, p_mq_parm->mq_int_enc);
                    iOffsetPMR += 4;
                }
                if ((recFlags & MQ_PMRF_ACCOUNTING_TOKEN) != 0)
                {
                    proto_tree_add_item(mq_tree, hf_mq_pmr_acttoken, tvb, offset + iOffsetPMR, 32, ENC_NA);
                    iOffsetPMR += 32;
                }
            }
        }
        else iSizePMR = 0;
    }
    return iSizePMR;
}
static int dissect_mq_or(tvbuff_t* tvb, proto_tree* tree, int offset, int iNbrRecords, int offsetOR, mq_parm_t* p_mq_parm)
{
    int iSizeOR = 0;
    if (offsetOR != 0)
    {
        iSizeOR = iNbrRecords * 96;
        if (tvb_reported_length_remaining(tvb, offset) >= iSizeOR)
        {
            int iOffsetOR = 0;
            int iRecord = 0;
            for (iRecord = 0; iRecord < iNbrRecords; iRecord++)
            {
                proto_tree* mq_tree = proto_tree_add_subtree(tree, tvb, offset + iOffsetOR, 96, ett_mq_or, NULL, MQ_TEXT_OR);
                proto_tree_add_item(mq_tree, hf_mq_or_objname, tvb, offset + iOffsetOR, 48, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_or_objqmgrname, tvb, offset + iOffsetOR + 48, 48, p_mq_parm->mq_str_enc);
                iOffsetOR += 96;
            }
        }
        else iSizeOR = 0;
    }
    return iSizeOR;
}
static int dissect_mq_rr(tvbuff_t* tvb, proto_tree* tree, int offset, int iNbrRecords, int offsetRR, mq_parm_t* p_mq_parm)
{
    int iSizeRR = 0;
    if (offsetRR != 0)
    {
        iSizeRR = iNbrRecords * 8;
        if (tvb_reported_length_remaining(tvb, offset) >= iSizeRR)
        {
            int iOffsetRR = 0;
            int iRecord = 0;
            for (iRecord = 0; iRecord < iNbrRecords; iRecord++)
            {
                proto_tree* mq_tree = proto_tree_add_subtree(tree, tvb, offset + iOffsetRR, 8, ett_mq_rr, NULL, MQ_TEXT_RR);
                proto_tree_add_item(mq_tree, hf_mq_rr_compcode, tvb, offset + iOffsetRR, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_rr_reascode, tvb, offset + iOffsetRR + 4, 4, p_mq_parm->mq_int_enc);
                iOffsetRR += 8;
            }
        }
        else iSizeRR = 0;
    }
    return iSizeRR;
}
static int dissect_mq_gmo(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, mq_parm_t* p_mq_parm)
{
    int iSize = 0;

    p_mq_parm->mq_strucID = (tvb_reported_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
    if (p_mq_parm->mq_strucID == MQ_STRUCTID_GMO || p_mq_parm->mq_strucID == MQ_STRUCTID_GMO_EBCDIC)
    {
        uint32_t iVersion = 0;
        iVersion = tvb_get_uint32(tvb, offset + 4, p_mq_parm->mq_int_enc);
        /* Compute length according to version */
        switch (iVersion)
        {
            case 1: iSize = 72; break;
            case 2: iSize = 80; break;
            case 3: iSize = 100; break;
            case 4: iSize = 112; break;
        }

        if (iSize != 0 && tvb_reported_length_remaining(tvb, offset) >= iSize)
        {
            uint8_t* sQueue;
            sQueue = tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 24, 48, p_mq_parm->mq_str_enc);
            if (strip_trailing_blanks(sQueue, 48) > 0)
            {
                if (pinfo)
                    col_append_fstr(pinfo->cinfo, COL_INFO, " Q=%s", sQueue);
            }

            if (tree)
            {
                proto_tree* mq_tree;

                mq_tree = proto_tree_add_subtree(tree, tvb, offset, iSize, ett_mq_gmo, NULL, MQ_TEXT_GMO);

                proto_tree_add_item(mq_tree, hf_mq_gmo_StructID, tvb, offset, 4, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_gmo_version, tvb, offset + 4, 4, p_mq_parm->mq_int_enc);

                dissect_mq_MQGMO(tvb, mq_tree, offset + 8, ett_mq_gmo_option, p_mq_parm);

                proto_tree_add_item(mq_tree, hf_mq_gmo_waitinterval, tvb, offset + 12, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_gmo_signal1, tvb, offset + 16, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_gmo_signal2, tvb, offset + 20, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_gmo_resolvqname, tvb, offset + 24, 48, p_mq_parm->mq_str_enc);

                if (iVersion >= 2)
                {
                    dissect_mq_MQMO(tvb, mq_tree, offset + 72, ett_mq_gmo_matchoption, p_mq_parm);

                    proto_tree_add_item(mq_tree, hf_mq_gmo_groupstatus, tvb, offset + 76, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(mq_tree, hf_mq_gmo_segmstatus, tvb, offset + 77, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(mq_tree, hf_mq_gmo_segmentation, tvb, offset + 78, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(mq_tree, hf_mq_gmo_reserved, tvb, offset + 79, 1, ENC_BIG_ENDIAN);
                }

                if (iVersion >= 3)
                {
                    proto_tree_add_item(mq_tree, hf_mq_gmo_msgtoken, tvb, offset + 80, 16, ENC_NA);
                    proto_tree_add_item(mq_tree, hf_mq_gmo_returnedlen, tvb, offset + 96, 4, p_mq_parm->mq_int_enc);
                }
                if (iVersion >= 4)
                {
                    proto_tree_add_item(mq_tree, hf_mq_gmo_reserved2, tvb, offset + 100, 4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_gmo_msghandle, tvb, offset + 104, 8, p_mq_parm->mq_int_enc);
                }
            }
        }
    }
    return iSize;
}

static int dissect_mq_pmo(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, mq_parm_t* p_mq_parm, int* iDistributionListSize)
{
    int iSize = 0;
    int iPosV2 = offset + 128;
    int offsetb = offset;

    p_mq_parm->mq_strucID = (tvb_reported_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
    if (p_mq_parm->mq_strucID == MQ_STRUCTID_PMO || p_mq_parm->mq_strucID == MQ_STRUCTID_PMO_EBCDIC)
    {
        uint32_t iVersion = 0;
        iVersion = tvb_get_uint32(tvb, offset + 4, p_mq_parm->mq_int_enc);
        /* Compute length according to version */
        switch (iVersion)
        {
            case 1: iSize = 128; break;
            case 2: iSize = 152; break;
            case 3: iSize = 176; break;
        }

        if (iSize != 0 && tvb_reported_length_remaining(tvb, offset) >= iSize)
        {
            uint8_t* sQueue;
            uint8_t* sQueueA;

            sQueueA = tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 32, 48, 0);
            sQueue = tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 32, 48, p_mq_parm->mq_str_enc);
            if (strip_trailing_blanks(sQueue, 48) > 0 && strip_trailing_blanks(sQueueA, 48) > 0)
            {
                if (pinfo)
                    col_append_fstr(pinfo->cinfo, COL_INFO, " Q=%s", sQueue);
            }

            if (tree)
            {
                proto_tree* mq_tree;

                mq_tree = proto_tree_add_subtree(tree, tvb, offset, iSize, ett_mq_pmo, NULL, MQ_TEXT_PMO);
                proto_tree_add_item(mq_tree, hf_mq_pmo_StructID, tvb, offset, 4, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_pmo_version, tvb, offset + 4, 4, p_mq_parm->mq_int_enc);

                dissect_mq_MQPMO(tvb, mq_tree, offset + 8, ett_mq_pmo_option, p_mq_parm);

                proto_tree_add_item(mq_tree, hf_mq_pmo_timeout, tvb, offset + 12, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_pmo_context, tvb, offset + 16, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_pmo_knowndstcnt, tvb, offset + 20, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_pmo_unkndstcnt, tvb, offset + 24, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_pmo_invaldstcnt, tvb, offset + 28, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_pmo_resolvqname, tvb, offset + 32, 48, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_pmo_resolvqmgr, tvb, offset + 80, 48, p_mq_parm->mq_str_enc);
                offset += 128;
                if (iVersion >= 2)
                {
                    proto_tree_add_item(mq_tree, hf_mq_pmo_recspresent, tvb, offset, 4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_pmo_putmsgrecfld, tvb, offset + 4, 4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_pmo_putmsgrecofs, tvb, offset + 8, 4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_pmo_resprecofs, tvb, offset + 12, 4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_pmo_putmsgrecptr, tvb, offset + 16, 4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_pmo_resprecptr, tvb, offset + 20, 4, p_mq_parm->mq_int_enc);
                    offset += 24;
                }
                if (iVersion >= 3)
                {
                    proto_tree_add_item(mq_tree, hf_mq_pmo_originalmsghandle, tvb, offset, 8, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_pmo_newmsghandle, tvb, offset + 8, 8, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_pmo_action, tvb, offset + 16, 4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_pmo_publevel, tvb, offset + 20, 4, p_mq_parm->mq_int_enc);
                }
            }
            if (iVersion >= 2)
            {
                int iNbrRecords = 0;
                uint32_t iRecFlags = 0;

                iNbrRecords = tvb_get_uint32(tvb, iPosV2, p_mq_parm->mq_int_enc);
                iRecFlags = tvb_get_uint32(tvb, iPosV2 + 4, p_mq_parm->mq_int_enc);

                if (iNbrRecords > 0)
                {
                    int iOffsetPMR = 0;
                    int iOffsetRR = 0;

                    if (iDistributionListSize)
                        *iDistributionListSize = iNbrRecords;
                    iOffsetPMR = tvb_get_uint32(tvb, iPosV2 + 8, p_mq_parm->mq_int_enc);
                    iOffsetRR = tvb_get_uint32(tvb, iPosV2 + 12, p_mq_parm->mq_int_enc);
                    iSize += dissect_mq_pmr(tvb, tree, offsetb + iSize, iNbrRecords, iOffsetPMR, iRecFlags, p_mq_parm);
                    iSize += dissect_mq_rr(tvb, tree, offsetb + iSize, iNbrRecords, iOffsetRR, p_mq_parm);
                }
            }
        }
    }
    return iSize;
}

static int dissect_mq_od(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, mq_parm_t* p_mq_parm, int* iDistributionListSize)
{
    int iSize = 0;

    p_mq_parm->mq_strucID = (tvb_reported_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
    if (p_mq_parm->mq_strucID == MQ_STRUCTID_OD || p_mq_parm->mq_strucID == MQ_STRUCTID_OD_EBCDIC)
    {
        /* The OD struct can be present in several messages at different levels */
        uint32_t iVersion = 0;
        iVersion = tvb_get_uint32(tvb, offset + 4, p_mq_parm->mq_int_enc);
        /* Compute length according to version */
        switch (iVersion)
        {
            case 1: iSize = 168; break;
            case 2: iSize = 200; break;
            case 3: iSize = 336; break;
            case 4: iSize = 336 + 3 * 20 + 4; break;
        }

        if (iSize != 0 && tvb_reported_length_remaining(tvb, offset) >= iSize)
        {
            int      iNbrRecords = 0;
            uint8_t* sObj;
            uint32_t uTyp;

            if (iVersion >= 2)
                iNbrRecords = tvb_get_uint32(tvb, offset + 168, p_mq_parm->mq_int_enc);

            uTyp = tvb_get_uint32(tvb, offset + 8, p_mq_parm->mq_int_enc);
            sObj = tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 12, 48, p_mq_parm->mq_str_enc);
            if (pinfo)
                col_append_fstr(pinfo->cinfo, COL_INFO, " Typ=%s", try_val_to_str_ext(uTyp, GET_VALS_EXTP(objtype)));
            if (strip_trailing_blanks(sObj, 48) > 0)
            {
                if (pinfo)
                    col_append_fstr(pinfo->cinfo, COL_INFO, " Obj=%s", sObj);
            }

            if (tree)
            {
                proto_tree* mq_tree;

                mq_tree = proto_tree_add_subtree(tree, tvb, offset, iSize, ett_mq_od, NULL, MQ_TEXT_OD);

                proto_tree_add_item(mq_tree, hf_mq_od_StructID, tvb, offset, 4, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_od_version, tvb, offset + 4, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_od_objecttype, tvb, offset + 8, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_od_objectname, tvb, offset + 12, 48, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_od_objqmgrname, tvb, offset + 60, 48, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_od_dynqname, tvb, offset + 108, 48, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_od_altuserid, tvb, offset + 156, 12, p_mq_parm->mq_str_enc);

                if (iVersion >= 2)
                {
                    proto_tree_add_item(mq_tree, hf_mq_od_recspresent, tvb, offset + 168, 4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_od_knowndstcnt, tvb, offset + 172, 4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_od_unknowdstcnt, tvb, offset + 176, 4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_od_invaldstcnt, tvb, offset + 180, 4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_od_objrecofs, tvb, offset + 184, 4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_od_resprecofs, tvb, offset + 188, 4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_od_objrecptr, tvb, offset + 192, 4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_od_resprecptr, tvb, offset + 196, 4, p_mq_parm->mq_int_enc);
                }
                if (iVersion >= 3)
                {
                    proto_tree_add_item(mq_tree, hf_mq_od_altsecurid, tvb, offset + 200, 40, p_mq_parm->mq_str_enc);
                    proto_tree_add_item(mq_tree, hf_mq_od_resolvqname, tvb, offset + 240, 48, p_mq_parm->mq_str_enc);
                    proto_tree_add_item(mq_tree, hf_mq_od_resolvqmgrnm, tvb, offset + 288, 48, p_mq_parm->mq_str_enc);
                }
                if (iVersion >= 4)
                {
                    dissect_mq_charv(tvb, mq_tree, offset + 336, 20, ett_mq_od_objstr, "Object string", p_mq_parm);
                    dissect_mq_charv(tvb, mq_tree, offset + 356, 20, ett_mq_od_selstr, "Selection string", p_mq_parm);
                    dissect_mq_charv(tvb, mq_tree, offset + 376, 20, ett_mq_od_resobjstr, "Resolved object string", p_mq_parm);
                    proto_tree_add_item(mq_tree, hf_mq_od_resolvobjtyp, tvb, offset + 396, 4, p_mq_parm->mq_int_enc);
                }
            }
            if (iNbrRecords > 0)
            {
                int iOffsetOR = 0;
                int iOffsetRR = 0;

                *iDistributionListSize = iNbrRecords;
                iOffsetOR = tvb_get_uint32(tvb, offset + 184, p_mq_parm->mq_int_enc);
                iOffsetRR = tvb_get_uint32(tvb, offset + 188, p_mq_parm->mq_int_enc);

                iSize += dissect_mq_or(tvb, tree, offset, iNbrRecords, iOffsetOR, p_mq_parm);
                iSize += dissect_mq_rr(tvb, tree, offset, iNbrRecords, iOffsetRR, p_mq_parm);
            }
        }
    }
    return iSize;
}

static int dissect_mq_xid(tvbuff_t* tvb, proto_tree* tree, mq_parm_t* p_mq_parm, int offset)
{
    int iSizeXid = 0;
    if (tvb_reported_length_remaining(tvb, offset) >= 6)
    {
        uint8_t iXidLength = 0;
        uint8_t iBqLength = 0;

        iXidLength = tvb_get_uint8(tvb, offset + 4);
        iBqLength = tvb_get_uint8(tvb, offset + 5);
        iSizeXid = 6 + iXidLength + iBqLength;

        if (tvb_reported_length_remaining(tvb, offset) >= iSizeXid)
        {
            proto_tree* mq_tree;

            mq_tree = proto_tree_add_subtree(tree, tvb, offset, iSizeXid, ett_mq_xa_xid, NULL, MQ_TEXT_XID);

            proto_tree_add_item(mq_tree, hf_mq_xa_xid_formatid, tvb, offset, 4, p_mq_parm->mq_int_enc);
            proto_tree_add_item(mq_tree, hf_mq_xa_xid_glbxid_len, tvb, offset + 4, 1, p_mq_parm->mq_int_enc);
            proto_tree_add_item(mq_tree, hf_mq_xa_xid_brq_length, tvb, offset + 5, 1, p_mq_parm->mq_int_enc);
            proto_tree_add_item(mq_tree, hf_mq_xa_xid_globalxid, tvb, offset + 6, iXidLength, ENC_NA);
            proto_tree_add_item(mq_tree, hf_mq_xa_xid_brq, tvb, offset + 6 + iXidLength, iBqLength, ENC_NA);

            iSizeXid += (4 - (iSizeXid % 4)) % 4; /* Pad for alignment with 4 byte word boundary */
            if (tvb_reported_length_remaining(tvb, offset) < iSizeXid)
                iSizeXid = 0;
        }
        else iSizeXid = 0;
    }
    return iSizeXid;
}

static int dissect_mq_sid(tvbuff_t* tvb, proto_tree* tree, mq_parm_t* p_mq_parm, int offset)
{
    uint8_t iSIDL;
    uint8_t iSID;
    char* sid_str;
    int    bOffset = offset;

    iSIDL = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_mq_sidlen, tvb, offset, 1, p_mq_parm->mq_int_enc);
    offset++;
    if (iSIDL > 0)
    {
        iSID = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(tree, hf_mq_sidtyp, tvb, offset, 1, p_mq_parm->mq_int_enc);
        offset++;
        if (iSID == MQ_MQSIDT_NT_SECURITY_ID)
        {
            offset = dissect_nt_sid(tvb, offset, tree, "SID", &sid_str, -1);
        }
        else
        {
            proto_tree_add_item(tree, hf_mq_securityid, tvb, offset, 40, ENC_NA);
            offset += 40;
        }
    }
    return offset - bOffset;
}
static void dissect_mq_addCR_colinfo(packet_info* pinfo, mq_parm_t* p_mq_parm)
{
    if (p_mq_parm->mq_convID)
        col_append_fstr(pinfo->cinfo, COL_INFO, " C.R=%d.%d", p_mq_parm->mq_convID, p_mq_parm->mq_rqstID);
}
static int dissect_mq_id(tvbuff_t* tvb, packet_info* pinfo, proto_tree* mqroot_tree, int offset, mq_parm_t* p_mq_parm)
{
    uint8_t iFAPLvl;
    int    iSize;
    int    iPktSz;

    iPktSz = tvb_reported_length_remaining(tvb, offset);
    iFAPLvl = tvb_get_uint8(tvb, offset + 4);

    if (iFAPLvl < 4)
        iSize = 44;
    else if (iFAPLvl < 9)
        iSize = 102;
    else if (iFAPLvl < 11)
        iSize = 208;
    else
        iSize = 240;
    iSize = MIN(iSize, iPktSz);

    if (iSize != 0 && tvb_reported_length_remaining(tvb, offset) >= iSize)
    {
        uint8_t* sChannel;
        sChannel = tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 24, 20, p_mq_parm->mq_str_enc);
        dissect_mq_addCR_colinfo(pinfo, p_mq_parm);
        col_append_fstr(pinfo->cinfo, COL_INFO, " FAPLvl=%d", iFAPLvl);
        if (strip_trailing_blanks(sChannel, 20) > 0)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, ", CHL=%s", sChannel);
        }
        if (iSize > 48)
        {
            uint8_t* sQMgr;
            sQMgr = tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 48, 48, p_mq_parm->mq_str_enc);
            if (strip_trailing_blanks(sQMgr, 48) > 0)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, ", QM=%s", sQMgr);
            }
            p_mq_parm->mq_id_ccsid.ccsid = (uint32_t)tvb_get_uint16(tvb, offset + 46, p_mq_parm->mq_int_enc);
        }
        if (mqroot_tree)
        {
            proto_tree* mq_tree = proto_tree_add_subtree(mqroot_tree, tvb, offset, iSize, ett_mq_id, NULL, MQ_TEXT_ID);

            proto_tree_add_item(mq_tree, hf_mq_id_StructID, tvb, offset, 4, p_mq_parm->mq_str_enc);
            proto_tree_add_item(mq_tree, hf_mq_id_FapLevel, tvb, offset + 4, 1, ENC_BIG_ENDIAN);

            /* ID Capability flags 1 */
            proto_tree_add_bitmask(mq_tree, tvb, offset + 5, hf_mq_id_cf1, ett_mq_id_cf1, pf_flds_cf1, ENC_BIG_ENDIAN);
            proto_tree_add_bitmask(mq_tree, tvb, offset + 6, hf_mq_id_ecf1, ett_mq_id_ecf1, pf_flds_cf1, ENC_BIG_ENDIAN);

            /* Error flags 1*/
            proto_tree_add_bitmask(mq_tree, tvb, offset + 7, hf_mq_id_ief1, ett_mq_id_ief1, pf_flds_ef1, ENC_BIG_ENDIAN);

            proto_tree_add_item(mq_tree, hf_mq_id_Reserved, tvb, offset + 8, 2, p_mq_parm->mq_int_enc);
            proto_tree_add_item(mq_tree, hf_mq_id_MaxMsgBatch, tvb, offset + 10, 2, p_mq_parm->mq_int_enc);
            proto_tree_add_item(mq_tree, hf_mq_id_MaxTrSize, tvb, offset + 12, 4, p_mq_parm->mq_int_enc);
            proto_tree_add_item(mq_tree, hf_mq_id_MaxMsgSize, tvb, offset + 16, 4, p_mq_parm->mq_int_enc);
            proto_tree_add_item(mq_tree, hf_mq_id_SeqWrapVal, tvb, offset + 20, 4, p_mq_parm->mq_int_enc);
            proto_tree_add_item(mq_tree, hf_mq_id_channel, tvb, offset + 24, 20, p_mq_parm->mq_str_enc);

            if (iSize > 44 || (iPktSz > iSize && iPktSz > 44))
            {
                /* ID Capability flags 2 */
                proto_tree_add_bitmask(mq_tree, tvb, offset + 44, hf_mq_id_cf2, ett_mq_id_cf2, pf_flds_cf2, ENC_BIG_ENDIAN);
                proto_tree_add_bitmask(mq_tree, tvb, offset + 45, hf_mq_id_ecf2, ett_mq_id_ecf2, pf_flds_cf2, ENC_BIG_ENDIAN);

                proto_tree_add_item(mq_tree, hf_mq_id_ccsid, tvb, offset + 46, 2, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_id_qmgrname, tvb, offset + 48, 48, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_id_HBInterval, tvb, offset + 96, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_id_EFLLength, tvb, offset + 100, 2, p_mq_parm->mq_int_enc);
                if (iSize > 102 || (iPktSz > iSize && iPktSz > 102))
                {
                    /* Error flags 2*/
                    proto_tree_add_bitmask(mq_tree, tvb, offset + 102, hf_mq_id_ief2, ett_mq_id_ief2, pf_flds_ef2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(mq_tree, hf_mq_id_Reserved1, tvb, offset + 103, 1, ENC_BIG_ENDIAN);

                    if (iSize > 104 || (iPktSz > iSize && iPktSz > 104))
                    {
                        proto_tree_add_item(mq_tree, hf_mq_id_HdrCprsLst, tvb, offset + 104, 2, p_mq_parm->mq_int_enc);
                        proto_tree_add_item(mq_tree, hf_mq_id_MsgCprsLst, tvb, offset + 106, 16, p_mq_parm->mq_int_enc);
                        proto_tree_add_item(mq_tree, hf_mq_id_Reserved2, tvb, offset + 122, 2, p_mq_parm->mq_int_enc);
                        proto_tree_add_item(mq_tree, hf_mq_id_SSLKeyRst, tvb, offset + 124, 4, p_mq_parm->mq_int_enc);
                        if (iSize > 128 || (iPktSz > iSize && iPktSz > 128))
                        {
                            proto_tree_add_item(mq_tree, hf_mq_id_ConvBySkt, tvb, offset + 128, 4, p_mq_parm->mq_int_enc);

                            /* ID Capability flags 3 */
                            proto_tree_add_bitmask(mq_tree, tvb, offset + 132, hf_mq_id_cf3, ett_mq_id_cf3, pf_flds_cf3, ENC_BIG_ENDIAN);
                            proto_tree_add_bitmask(mq_tree, tvb, offset + 133, hf_mq_id_ecf3, ett_mq_id_ecf3, pf_flds_cf3, ENC_BIG_ENDIAN);

                            proto_tree_add_item(mq_tree, hf_mq_id_Reserved3, tvb, offset + 134, 2, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_id_ProcessId, tvb, offset + 136, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_id_ThreadId, tvb, offset + 140, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_id_TraceId, tvb, offset + 144, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_id_ProdId, tvb, offset + 148, 12, p_mq_parm->mq_str_enc);
                        }
                    }
                }
                if (iSize > 160 || (iPktSz > iSize && iPktSz > 160))
                {
                    proto_tree_add_item(mq_tree, hf_mq_id_mqmid, tvb, offset + 160, 48, p_mq_parm->mq_str_enc);
                }
                if (iSize > 208 || (iPktSz > iSize && iPktSz > 208))
                {
                    proto_tree_add_item(mq_tree, hf_mq_id_pal, tvb, offset + 208, 20, p_mq_parm->mq_str_enc);
                    proto_tree_add_item(mq_tree, hf_mq_id_r, tvb, offset + 228, 12, p_mq_parm->mq_str_enc);
                }
            }
        }
    }
    return iPktSz;
}
static int dissect_mq_md(tvbuff_t* tvb, proto_tree* tree, int offset, mq_parm_t* p_mq_parm, bool bDecode)
{
    int iSize = 0;

    p_mq_parm->mq_strucID = (tvb_reported_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
    if (p_mq_parm->mq_strucID == MQ_STRUCTID_MD || p_mq_parm->mq_strucID == MQ_STRUCTID_MD_EBCDIC)
    {
        uint32_t iVersion = 0;
        iVersion = tvb_get_uint32(tvb, offset + 4, p_mq_parm->mq_int_enc);
        /* Compute length according to version */
        switch (iVersion)
        {
            case 1: iSize = 324; break;
            case 2: iSize = 364; break;
        }

        if (bDecode && iSize != 0 && tvb_reported_length_remaining(tvb, offset) >= iSize)
        {
            p_mq_parm->iOfsEnc = offset + 24;
            p_mq_parm->iOfsCcs = offset + 28;
            p_mq_parm->iOfsFmt = offset + 32;

            p_mq_parm->mq_md_ccsid.encod = tvb_get_uint32(tvb, offset + 24, p_mq_parm->mq_int_enc);
            p_mq_parm->mq_md_ccsid.ccsid = tvb_get_uint32(tvb, offset + 28, p_mq_parm->mq_int_enc);
            if (tree)
            {
                proto_tree* mq_tree = proto_tree_add_subtree(tree, tvb, offset, iSize, ett_mq_md, NULL, MQ_TEXT_MD);

                proto_tree_add_item(mq_tree, hf_mq_md_StructID, tvb, offset, 4, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_version, tvb, offset + 4, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_report, tvb, offset + 8, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_msgtype, tvb, offset + 12, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_expiry, tvb, offset + 16, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_feedback, tvb, offset + 20, 4, p_mq_parm->mq_int_enc);
                dissect_mq_encoding(mq_tree, hf_mq_md_encoding, tvb, offset + 24, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_ccsid, tvb, offset + 28, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_format, tvb, offset + 32, 8, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_priority, tvb, offset + 40, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_persistence, tvb, offset + 44, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_msgid, tvb, offset + 48, 24, ENC_NA);
                proto_tree_add_item(mq_tree, hf_mq_md_correlid, tvb, offset + 72, 24, ENC_NA);
                proto_tree_add_item(mq_tree, hf_mq_md_backoutcnt, tvb, offset + 96, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_replytoq, tvb, offset + 100, 48, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_replytoqmgr, tvb, offset + 148, 48, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_userid, tvb, offset + 196, 12, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_acttoken, tvb, offset + 208, 32, ENC_NA);
                proto_tree_add_item(mq_tree, hf_mq_md_appliddata, tvb, offset + 240, 32, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_putappltype, tvb, offset + 272, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_putapplname, tvb, offset + 276, 28, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_putdate, tvb, offset + 304, 8, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_puttime, tvb, offset + 312, 8, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_apporigdata, tvb, offset + 320, 4, p_mq_parm->mq_str_enc);

                if (iVersion >= 2)
                {
                    proto_tree_add_item(mq_tree, hf_mq_md_groupid, tvb, offset + 324, 24, ENC_NA);
                    proto_tree_add_item(mq_tree, hf_mq_md_msgseqnumber, tvb, offset + 348, 4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_md_offset, tvb, offset + 352, 4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_md_msgflags, tvb, offset + 356, 4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_md_origlen, tvb, offset + 360, 4, p_mq_parm->mq_int_enc);
                }
            }
        }
    }
    return iSize;
}
static int dissect_mq_fopa(tvbuff_t* tvb, proto_tree* tree, int offset, mq_parm_t* p_mq_parm)
{
    int iSize = 0;
    int iVers = 0;

    p_mq_parm->mq_strucID = (tvb_reported_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
    if (p_mq_parm->mq_strucID == MQ_STRUCTID_FOPA || p_mq_parm->mq_strucID == MQ_STRUCTID_FOPA_EBCDIC)
    {
        iVers = tvb_get_uint32(tvb, offset + 4, p_mq_parm->mq_int_enc);
        iSize = tvb_get_uint32(tvb, offset + 8, p_mq_parm->mq_int_enc);
        if (iSize != 0 && tvb_reported_length_remaining(tvb, offset) >= iSize)
        {
            proto_tree* mq_tree = proto_tree_add_subtree(tree, tvb, offset, iSize, ett_mq_fopa, NULL, MQ_TEXT_FOPA);

            proto_tree_add_item(mq_tree, hf_mq_fopa_StructID, tvb, offset, 4, p_mq_parm->mq_str_enc);
            proto_tree_add_item(mq_tree, hf_mq_fopa_version, tvb, offset + 4, 4, p_mq_parm->mq_int_enc);
            proto_tree_add_item(mq_tree, hf_mq_fopa_length, tvb, offset + 8, 4, p_mq_parm->mq_int_enc);

            proto_tree_add_item(mq_tree, hf_mq_fopa_DefPersistence, tvb, offset + 12, 4, p_mq_parm->mq_int_enc);
            proto_tree_add_item(mq_tree, hf_mq_fopa_DefPutRespType, tvb, offset + 16, 4, p_mq_parm->mq_int_enc);
            proto_tree_add_item(mq_tree, hf_mq_fopa_DefReadAhead, tvb, offset + 20, 4, p_mq_parm->mq_int_enc);
            proto_tree_add_item(mq_tree, hf_mq_fopa_PropertyControl, tvb, offset + 24, 4, p_mq_parm->mq_int_enc);

            if ((iVers > 1) && (iSize > 28))
                proto_tree_add_item(mq_tree, hf_mq_fopa_Unknown, tvb, offset + 28, iSize - 28, p_mq_parm->mq_int_enc);
        }
    }
    return iSize;
}
static int dissect_mq_fcmi(tvbuff_t* tvb, proto_tree* tree, int offset, mq_parm_t* p_mq_parm)
{
    int iSize = 0;

    p_mq_parm->mq_strucID = (tvb_reported_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
    if (p_mq_parm->mq_strucID == MQ_STRUCTID_FCMI || p_mq_parm->mq_strucID == MQ_STRUCTID_FCMI_EBCDIC)
    {
        iSize = 8;
        if (iSize != 0 && tvb_reported_length_remaining(tvb, offset) >= iSize)
        {
            proto_tree* mq_tree = proto_tree_add_subtree(tree, tvb, offset, iSize, ett_mq_fcmi, NULL, MQ_TEXT_FCMI);

            proto_tree_add_item(mq_tree, hf_mq_fcmi_StructID, tvb, offset, 4, p_mq_parm->mq_str_enc);
            proto_tree_add_item(mq_tree, hf_mq_fcmi_unknown, tvb, offset + 4, 4, p_mq_parm->mq_int_enc);
        }
    }
    return iSize;
}
static void dissect_mq_pdu(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree)
{
    int        offset = 0;
    uint32_t   iSegmentLength = 0;
    uint32_t   iSizePayload = 0;
    int        iSizeMD = 0;
    bool       bPayload = false;
    bool       bEBCDIC = false;
    unsigned   strid_enc;
    int        iDistributionListSize = 0;
    int        capLen;
    mq_parm_t* p_mq_parm;
    heur_dtbl_entry_t* hdtbl_entry;

    p_mq_parm = wmem_new0(wmem_packet_scope(), mq_parm_t);

    p_mq_parm->mq_strucID = MQ_STRUCTID_NULL;
    p_mq_parm->mq_int_enc = ENC_BIG_ENDIAN;
    p_mq_parm->mq_str_enc = ENC_UTF_8 | ENC_NA;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MQ");

    p_mq_parm->iOfsEnc = 0;
    p_mq_parm->iOfsFmt = 0;
    p_mq_parm->iOfsCcs = 0;

    if (tvb_reported_length(tvb) >= 4)
    {
        p_mq_parm->mq_strucID = tvb_get_ntohl(tvb, offset);
        if (((p_mq_parm->mq_strucID & MQ_MASK_TSHx) == MQ_STRUCTID_TSHx ||
            (p_mq_parm->mq_strucID & MQ_MASK_TSHx) == MQ_STRUCTID_TSHx_EBCDIC)
            && tvb_reported_length_remaining(tvb, offset) >= 28)
        {
            proto_tree* mq_tree = NULL;
            proto_tree* mqroot_tree = NULL;
            proto_item* ti = NULL;

            /* An MQ packet always starts with this structure*/
            int iSizeTSH = 28;
            int iSizeMPF = 0;  /* Size Of Multiplexed Field */

            strid_enc = ENC_ASCII | ENC_NA;
            if ((p_mq_parm->mq_strucID & MQ_MASK_TSHx) == MQ_STRUCTID_TSHx_EBCDIC)
            {
                bEBCDIC = true;
                strid_enc = ENC_EBCDIC | ENC_NA;
                p_mq_parm->mq_str_enc = ENC_EBCDIC | ENC_NA;
            }

            iSegmentLength = tvb_get_ntohl(tvb, offset + 4);

            if (p_mq_parm->mq_strucID == MQ_STRUCTID_TSHM || p_mq_parm->mq_strucID == MQ_STRUCTID_TSHM_EBCDIC)
            {
                if (tvb_reported_length_remaining(tvb, offset) < 36)
                    return;
                iSizeMPF += 8;
                iSizeTSH += iSizeMPF;
                p_mq_parm->mq_convID = tvb_get_ntohl(tvb, offset + 8);
                p_mq_parm->mq_rqstID = tvb_get_ntohl(tvb, offset + 12);
            }
            p_mq_parm->mq_opcode = tvb_get_uint8(tvb, offset + iSizeMPF + 9);

            if (p_mq_parm->mq_opcode == MQ_TST_REQUEST_MSGS || p_mq_parm->mq_opcode == MQ_TST_ASYNC_MESSAGE)
            {
                p_mq_parm->iOfsEnc = offset + iSizeMPF + 20;
                p_mq_parm->iOfsCcs = offset + iSizeMPF + 24;
                p_mq_parm->iOfsFmt = offset;
            }
            p_mq_parm->mq_int_enc = (tvb_get_uint8(tvb, offset + iSizeMPF + 8) == MQ_LITTLE_ENDIAN ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
            p_mq_parm->mq_ctlf1 = tvb_get_uint8(tvb, offset + iSizeMPF + 10);
            p_mq_parm->mq_ctlf2 = tvb_get_uint8(tvb, offset + iSizeMPF + 11);

            p_mq_parm->mq_tsh_ccsid.encod = tvb_get_uint32(tvb, offset + iSizeMPF + 20, p_mq_parm->mq_int_enc);
            p_mq_parm->mq_tsh_ccsid.ccsid = tvb_get_uint16(tvb, offset + iSizeMPF + 24, p_mq_parm->mq_int_enc);

            if (IS_EBCDIC(p_mq_parm->mq_tsh_ccsid.ccsid) && !bEBCDIC)
            {
                bEBCDIC = true;
                p_mq_parm->mq_str_enc = ENC_EBCDIC | ENC_NA;
            }

            if (!mq_in_reassembly)
            {
                col_clear_fence(pinfo->cinfo, COL_INFO);
                col_clear(pinfo->cinfo, COL_INFO);
                col_add_fstr(pinfo->cinfo, COL_INFO, "%-17s", val_to_str_ext(p_mq_parm->mq_opcode, GET_VALS_EXTP(opcode), "Unknown (0x%02x)"));
            }

            if (tree)
            {
                if (p_mq_parm->mq_opcode != MQ_TST_ASYNC_MESSAGE)
                {
                    ti = proto_tree_add_item(tree, proto_mq, tvb, offset, -1, ENC_NA);
                    proto_item_append_text(ti, " (%s)", val_to_str_ext(p_mq_parm->mq_opcode, GET_VALS_EXTP(opcode), "Unknown (0x%02x)"));
                    if (bEBCDIC == true)
                        proto_item_append_text(ti, " (EBCDIC)");
                    mqroot_tree = proto_item_add_subtree(ti, ett_mq);
                }
                else
                {
                    mqroot_tree = tree;
                }

                mq_tree = proto_tree_add_subtree(mqroot_tree, tvb, offset, iSizeTSH, ett_mq_tsh, NULL, MQ_TEXT_TSH);

                proto_tree_add_item(mq_tree, hf_mq_tsh_StructID, tvb, offset + 0, 4, strid_enc);
                proto_tree_add_item(mq_tree, hf_mq_tsh_mqseglen, tvb, offset + 4, 4, ENC_BIG_ENDIAN);

                if (iSizeTSH == 36)
                {
                    proto_tree_add_item(mq_tree, hf_mq_tsh_convid, tvb, offset + 8, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(mq_tree, hf_mq_tsh_requestid, tvb, offset + 12, 4, ENC_BIG_ENDIAN);
                }

                proto_tree_add_item(mq_tree, hf_mq_tsh_byteorder, tvb, offset + iSizeMPF + 8, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(mq_tree, hf_mq_tsh_opcode, tvb, offset + iSizeMPF + 9, 1, ENC_BIG_ENDIAN);

                proto_tree_add_bitmask(mq_tree, tvb, offset + iSizeMPF + 10, hf_mq_tsh_ctlflgs1, ett_mq_tsh_tcf, pf_flds_tcf, ENC_BIG_ENDIAN);
                proto_tree_add_bitmask(mq_tree, tvb, offset + iSizeMPF + 11, hf_mq_tsh_ctlflgs2, ett_mq_tsh_tcf2, pf_flds_tcf2, ENC_BIG_ENDIAN);

                proto_tree_add_item(mq_tree, hf_mq_tsh_luwid, tvb, offset + iSizeMPF + 12, 8, ENC_NA);
                dissect_mq_encoding(mq_tree, hf_mq_tsh_encoding, tvb, offset + iSizeMPF + 20, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_tsh_ccsid, tvb, offset + iSizeMPF + 24, 2, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_tsh_reserved, tvb, offset + iSizeMPF + 26, 2, p_mq_parm->mq_int_enc);
            }
            offset += iSizeTSH;

            /* Now dissect the embedded structures */
            if (tvb_reported_length_remaining(tvb, offset) >= 4)
            {
                p_mq_parm->mq_strucID = tvb_get_ntohl(tvb, offset);
                if (((p_mq_parm->mq_ctlf1 & MQ_TCF_FIRST) != 0) || p_mq_parm->mq_opcode < 0x80)
                {
                    /* First MQ segment (opcodes below 0x80 never span several TSH) */
                    int iSizeAPI = 16;
                    if (p_mq_parm->mq_opcode >= 0x80 && p_mq_parm->mq_opcode <= 0x9F && tvb_reported_length_remaining(tvb, offset) >= 16)
                    {
                        uint32_t iReturnCode = 0;
                        uint32_t iHdl = 0;
                        iReturnCode = tvb_get_uint32(tvb, offset + 8, p_mq_parm->mq_int_enc);
                        iHdl = tvb_get_uint32(tvb, offset + 12, p_mq_parm->mq_int_enc);
                        if (!mq_in_reassembly)
                            dissect_mq_addCR_colinfo(pinfo, p_mq_parm);
                        if (iHdl != 0 && iHdl != 0xffffffff && !mq_in_reassembly)
                            col_append_fstr(pinfo->cinfo, COL_INFO, " Hdl=0x%04x", iHdl);
                        if (iReturnCode != 0)
                            col_append_fstr(pinfo->cinfo, COL_INFO, " [RC=%d]", iReturnCode);

                        mq_tree = proto_tree_add_subtree(mqroot_tree, tvb, offset, iSizeAPI, ett_mq_api, NULL, MQ_TEXT_API);

                        proto_tree_add_item(mq_tree, hf_mq_api_replylen, tvb, offset, 4, ENC_BIG_ENDIAN);
                        proto_tree_add_item(mq_tree, hf_mq_api_compcode, tvb, offset + 4, 4, p_mq_parm->mq_int_enc);
                        proto_tree_add_item(mq_tree, hf_mq_api_reascode, tvb, offset + 8, 4, p_mq_parm->mq_int_enc);
                        proto_tree_add_item(mq_tree, hf_mq_api_objecthdl, tvb, offset + 12, 4, p_mq_parm->mq_int_enc);

                        offset += iSizeAPI;
                        p_mq_parm->mq_strucID = (tvb_reported_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
                    }
                    capLen = tvb_reported_length_remaining(tvb, offset);
                    if ((p_mq_parm->mq_strucID == MQ_STRUCTID_MSH || p_mq_parm->mq_strucID == MQ_STRUCTID_MSH_EBCDIC) && capLen >= 20)
                    {
                        int iSize = 20;
                        iSizePayload = tvb_get_uint32(tvb, offset + 16, p_mq_parm->mq_int_enc);
                        bPayload = true;

                        mq_tree = proto_tree_add_subtree(mqroot_tree, tvb, offset, iSize, ett_mq_msh, NULL, MQ_TEXT_MSH);

                        proto_tree_add_item(mq_tree, hf_mq_msh_StructID, tvb, offset + 0, 4, p_mq_parm->mq_str_enc);
                        proto_tree_add_item(mq_tree, hf_mq_msh_seqnum, tvb, offset + 4, 4, p_mq_parm->mq_int_enc);
                        proto_tree_add_item(mq_tree, hf_mq_msh_datalength, tvb, offset + 8, 4, p_mq_parm->mq_int_enc);
                        proto_tree_add_item(mq_tree, hf_mq_msh_unknown1, tvb, offset + 12, 4, p_mq_parm->mq_int_enc);
                        proto_tree_add_item(mq_tree, hf_mq_msh_msglength, tvb, offset + 16, 4, p_mq_parm->mq_int_enc);

                        offset += iSize;
                    }
                    else if (p_mq_parm->mq_opcode == MQ_TST_CONAUTH_INFO && capLen >= 20)
                    {
                        int iSize = 24;
                        int iUsr = 0;
                        int iPsw = 0;

                        iUsr = tvb_get_uint32(tvb, offset + 16, p_mq_parm->mq_int_enc);
                        iPsw = tvb_get_uint32(tvb, offset + 20, p_mq_parm->mq_int_enc);

                        mq_tree = proto_tree_add_subtree(mqroot_tree, tvb, offset, iSize, ett_mq_caut, NULL, MQ_TEXT_CAUT);

                        proto_tree_add_item(mq_tree, hf_mq_caut_StructID, tvb, offset, 4, p_mq_parm->mq_str_enc);
                        proto_tree_add_item(mq_tree, hf_mq_caut_AuthType, tvb, offset + 4, 4, p_mq_parm->mq_int_enc);
                        proto_tree_add_item(mq_tree, hf_mq_caut_UsrMaxLen, tvb, offset + 8, 4, p_mq_parm->mq_int_enc);
                        proto_tree_add_item(mq_tree, hf_mq_caut_PwdMaxLen, tvb, offset + 12, 4, p_mq_parm->mq_int_enc);
                        proto_tree_add_item(mq_tree, hf_mq_caut_UsrLength, tvb, offset + 16, 4, p_mq_parm->mq_int_enc);
                        proto_tree_add_item(mq_tree, hf_mq_caut_PwdLength, tvb, offset + 20, 4, p_mq_parm->mq_int_enc);

                        if (iUsr)
                            proto_tree_add_item(mq_tree, hf_mq_caut_usr, tvb, offset + 24, iUsr, p_mq_parm->mq_str_enc);
                        if (iPsw)
                            proto_tree_add_item(mq_tree, hf_mq_caut_psw, tvb, offset + 24 + iUsr, iPsw, p_mq_parm->mq_str_enc);

                        offset += iSize + iUsr + iPsw;
                        p_mq_parm->mq_strucID = (tvb_reported_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
                    }
                    else if (p_mq_parm->mq_opcode == MQ_TST_SOCKET_ACTION && capLen >= 20)
                    {
                        int iSize = 20;
                        int iTy;
                        int iP1;
                        int iP2;

                        p_mq_parm->mq_convID = tvb_get_uint32(tvb, offset, p_mq_parm->mq_int_enc);
                        p_mq_parm->mq_rqstID = tvb_get_uint32(tvb, offset + 4, p_mq_parm->mq_int_enc);
                        dissect_mq_addCR_colinfo(pinfo, p_mq_parm);
                        iTy = tvb_get_uint32(tvb, offset + 8, p_mq_parm->mq_int_enc);
                        iP1 = tvb_get_uint32(tvb, offset + 12, p_mq_parm->mq_int_enc);
                        iP2 = tvb_get_uint32(tvb, offset + 16, p_mq_parm->mq_int_enc);
                        col_append_fstr(pinfo->cinfo, COL_INFO, " Type=%d, P1=%d, P2=%d", iTy, iP1, iP2);

                        mq_tree = proto_tree_add_subtree(mqroot_tree, tvb, offset, iSizeAPI, ett_mq_socket, NULL, MQ_TEXT_SOCKET);

                        proto_tree_add_item(mq_tree, hf_mq_socket_conversid, tvb, offset, 4, p_mq_parm->mq_int_enc);
                        proto_tree_add_item(mq_tree, hf_mq_socket_requestid, tvb, offset + 4, 4, p_mq_parm->mq_int_enc);
                        proto_tree_add_item(mq_tree, hf_mq_socket_type, tvb, offset + 8, 4, p_mq_parm->mq_int_enc);
                        proto_tree_add_item(mq_tree, hf_mq_socket_parm1, tvb, offset + 12, 4, p_mq_parm->mq_int_enc);
                        proto_tree_add_item(mq_tree, hf_mq_socket_parm2, tvb, offset + 16, 4, p_mq_parm->mq_int_enc);

                        offset += iSize;
                        p_mq_parm->mq_strucID = (tvb_reported_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
                    }
                    else if (p_mq_parm->mq_opcode == MQ_TST_STATUS && capLen >= 8)
                    {
                        /* Some status are 28 bytes long and some are 36 bytes long */
                        int iStatus = 0;
                        int iStatusLength = 0;

                        iStatus = tvb_get_uint32(tvb, offset + 4, p_mq_parm->mq_int_enc);
                        iStatusLength = tvb_get_uint32(tvb, offset, p_mq_parm->mq_int_enc);

                        if (tvb_reported_length_remaining(tvb, offset) >= iStatusLength)
                        {
                            if (iStatus != 0)
                                col_append_fstr(pinfo->cinfo, COL_INFO, " Code=%s", val_to_str_ext(iStatus, GET_VALS_EXTP(status), "Unknown (0x%08x)"));

                            mq_tree = proto_tree_add_subtree(mqroot_tree, tvb, offset, 8, ett_mq_status, NULL, MQ_TEXT_STAT);

                            proto_tree_add_item(mq_tree, hf_mq_status_length, tvb, offset, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_status_code, tvb, offset + 4, 4, p_mq_parm->mq_int_enc);

                            if (iStatusLength >= 12)
                                proto_tree_add_item(mq_tree, hf_mq_status_value, tvb, offset + 8, 4, p_mq_parm->mq_int_enc);

                            offset += iStatusLength;
                        }
                    }
                    else if (p_mq_parm->mq_opcode == MQ_TST_PING && capLen > 4)
                    {
                        mq_tree = proto_tree_add_subtree(mqroot_tree, tvb, offset, -1, ett_mq_ping, NULL, MQ_TEXT_PING);

                        proto_tree_add_item(mq_tree, hf_mq_ping_length, tvb, offset, 4, p_mq_parm->mq_int_enc);
                        proto_tree_add_item(mq_tree, hf_mq_ping_buffer, tvb, offset + 4, -1, ENC_NA);

                        offset = tvb_reported_length(tvb);
                    }
                    else if (p_mq_parm->mq_opcode == MQ_TST_RESET && capLen >= 8)
                    {
                        mq_tree = proto_tree_add_subtree(mqroot_tree, tvb, offset, -1, ett_mq_reset, NULL, MQ_TEXT_RESET);

                        proto_tree_add_item(mq_tree, hf_mq_reset_length, tvb, offset, 4, p_mq_parm->mq_int_enc);
                        proto_tree_add_item(mq_tree, hf_mq_reset_seqnum, tvb, offset + 4, 4, p_mq_parm->mq_int_enc);

                        offset = tvb_reported_length(tvb);
                    }
                    else if ((p_mq_parm->mq_opcode == MQ_TST_MQOPEN || p_mq_parm->mq_opcode == MQ_TST_MQCLOSE ||
                        p_mq_parm->mq_opcode == MQ_TST_MQOPEN_REPLY || p_mq_parm->mq_opcode == MQ_TST_MQCLOSE_REPLY) && capLen >= 4)
                    {
                        offset += dissect_mq_od(tvb, pinfo, mqroot_tree, offset, p_mq_parm, &iDistributionListSize);
                        if (tree)
                        {
                            mq_tree = proto_tree_add_subtree(mqroot_tree, tvb, offset, 4, ett_mq_open, NULL, MQ_TEXT_OPEN);
                            if (p_mq_parm->mq_opcode == MQ_TST_MQOPEN || p_mq_parm->mq_opcode == MQ_TST_MQOPEN_REPLY)
                            {
                                dissect_mq_MQOO(tvb, mq_tree, offset, ett_mq_open_option, hf_mq_open_options, p_mq_parm);
                            }
                            if (p_mq_parm->mq_opcode == MQ_TST_MQCLOSE || p_mq_parm->mq_opcode == MQ_TST_MQCLOSE_REPLY)
                            {
                                dissect_mq_MQCO(tvb, mq_tree, offset, p_mq_parm);
                            }
                        }
                        offset += 4;
                        offset += dissect_mq_fopa(tvb, mqroot_tree, offset, p_mq_parm);
                        offset += dissect_mq_fcmi(tvb, mqroot_tree, offset, p_mq_parm);
                    }
                    else if ((p_mq_parm->mq_opcode == MQ_TST_MQCONN || p_mq_parm->mq_opcode == MQ_TST_MQCONN_REPLY) && capLen > 0)
                    {
                        int iSizeCONN = 0;

                        /*iSizeCONN = ((iVersionID == 4 || iVersionID == 6) ? 120 : 112);*/ /* guess */
                        /* The iVersionID is available in the previous ID segment, we should keep a state
                        * Instead we rely on the segment length announced in the TSH */
                        /* The MQCONN structure is special because it does not start with a structid */
                        iSizeCONN = iSegmentLength - iSizeTSH - iSizeAPI;
                        if (iSizeCONN != 120 && /*FAPLvl <= 5 - 6 Version 1 */
                            iSizeCONN != 260 && /*FAPLvl == 7 - 11 Version 1 */
                            iSizeCONN != 332 && /*FAPLvl == 12 -13 Version 2 */
                            iSizeCONN != 460)   /*FAPLvl == 14     Version 3 */
                            iSizeCONN = 0;

                        if (iSizeCONN != 0 && tvb_reported_length_remaining(tvb, offset) >= iSizeCONN)
                        {
                            char* sApplicationName;
                            char* sQMgr;
                            uint32_t iEnc;
                            uint32_t iCod;
                            uint32_t iApp;
                            char    cChr;

                            /*
                            We have to handle the ccsid/coding of the MQCONN REPLY
                            on z/OS it is always EBCDIC
                            integer are always BIG_ENDIAN
                            */
                            if (p_mq_parm->mq_opcode == MQ_TST_MQCONN_REPLY)
                            {
                                iApp = tvb_get_letohl(tvb, offset + 48 + 28);
                                if (iApp <= 65536)
                                    iCod = ENC_LITTLE_ENDIAN;
                                else
                                    iCod = ENC_BIG_ENDIAN;
                                cChr = tvb_get_uint8(tvb, offset + 48);
                                if ((cChr >= 'A' && cChr <= 'Z') ||
                                    (cChr >= 'a' && cChr <= 'z') ||
                                    (cChr >= '0' && cChr <= '9') ||
                                    (cChr == '\\'))
                                {
                                    iEnc = p_mq_parm->mq_str_enc;
                                }
                                else
                                {
                                    iEnc = ENC_EBCDIC;
                                }
                            }
                            else
                            {
                                iCod = p_mq_parm->mq_int_enc;
                                iEnc = p_mq_parm->mq_str_enc;
                            }
                            iApp = tvb_get_uint32(tvb, offset + 48 + 28, iCod);

                            sApplicationName = tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 48, 28, iEnc);
                            sApplicationName = format_text_chr(wmem_packet_scope(), sApplicationName, strlen(sApplicationName), '.');
                            if (strip_trailing_blanks((uint8_t*)sApplicationName, (uint32_t)strlen(sApplicationName)) > 0)
                            {
                                col_append_fstr(pinfo->cinfo, COL_INFO, " App=%s", sApplicationName);
                            }
                            sQMgr = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 48, iEnc);
                            sQMgr = format_text_chr(wmem_packet_scope(), sQMgr, strlen(sQMgr), '.');
                            if (strip_trailing_blanks((uint8_t*)sQMgr, (uint32_t)strlen(sQMgr)) > 0)
                            {
                                col_append_fstr(pinfo->cinfo, COL_INFO, " QM=%s", sQMgr);
                            }

                            if (tree)
                            {
                                ptvcursor_t* cursor;
                                mq_tree = proto_tree_add_subtree(mqroot_tree, tvb, offset, iSizeCONN, ett_mq_conn, NULL, MQ_TEXT_CONN);

                                cursor = ptvcursor_new(pinfo->pool, mq_tree, tvb, offset);

                                ptvcursor_add(cursor, hf_mq_conn_QMgr, 48, iEnc);
                                ptvcursor_add(cursor, hf_mq_conn_appname, 28, iEnc);
                                ptvcursor_add(cursor, hf_mq_conn_apptype, 4, iCod);
                                ptvcursor_add(cursor, hf_mq_conn_acttoken, 32, ENC_NA);

                                ptvcursor_add(cursor, hf_mq_conn_options, 4, iCod);
                                ptvcursor_add(cursor, hf_mq_conn_Xoptions, 4, iCod);
                                if (iSizeCONN == 120)
                                {
                                    int tRemain = tvb_reported_length_remaining(tvb, ptvcursor_current_offset(cursor));
                                    if (tRemain > 0)
                                    {
                                        if (tRemain >= 24 && iApp != MQ_MQAT_JAVA)
                                        {
                                            ptvcursor_add(cursor, hf_mq_fcno_prodid, 24, iEnc);
                                            tRemain -= 24;
                                        }
                                        if (tRemain >= 48 && iApp != MQ_MQAT_JAVA)
                                        {
                                            ptvcursor_add(cursor, hf_mq_fcno_mqmid, 48, iEnc);
                                            tRemain -= 48;
                                        }
                                        if (tRemain > 0)
                                            ptvcursor_add(cursor, hf_mq_fcno_unknowb01, tRemain, ENC_NA);
                                    }
                                }
                                else
                                {
                                    proto_tree* mq_tree_sub;
                                    int iOption;
                                    int iVersion;
                                    int nofs = ptvcursor_current_offset(cursor);

                                    iVersion = tvb_get_uint32(tvb, nofs + 4, iCod);
                                    iOption = tvb_get_uint32(tvb, nofs + 8, iCod);
                                    mq_tree_sub = proto_tree_add_subtree(mq_tree, tvb, nofs, iSizeCONN - nofs, ett_mq_fcno, NULL, MQ_TEXT_FCNO);

                                    ptvcursor_set_tree(cursor, mq_tree_sub);

                                    ptvcursor_add(cursor, hf_mq_fcno_StructID, 4, iEnc);
                                    ptvcursor_add(cursor, hf_mq_fcno_version, 4, iCod);
                                    ptvcursor_add(cursor, hf_mq_fcno_capflag, 4, iCod);
                                    if (iVersion >= 1)
                                    {
                                        ptvcursor_add(cursor, hf_mq_fcno_conn_tag, 128, ENC_NA);
                                    }
                                    if (iVersion >= 3)
                                    {
                                        ptvcursor_add(cursor, hf_mq_fcno_retconn_tag, 128, ENC_NA);
                                    }
                                    int tRemain = tvb_reported_length_remaining(tvb, ptvcursor_current_offset(cursor));
                                    if (tRemain > 0)
                                    {
                                        if (tRemain >= 24 && iApp != MQ_MQAT_JAVA)
                                        {
                                            ptvcursor_add(cursor, hf_mq_fcno_prodid, 24, iEnc);
                                            tRemain -= 24;
                                        }
                                        if (tRemain >= 48 && iApp != MQ_MQAT_JAVA)
                                        {
                                            ptvcursor_add(cursor, hf_mq_fcno_mqmid, 48, iEnc);
                                            tRemain -= 48;
                                        }
                                        if (tRemain > 0)
                                        {
                                            if (iOption != 0)
                                            {
                                                uint32_t tUsed = dissect_mqpcf_parm(tvb, pinfo, mq_tree_sub, ptvcursor_current_offset(cursor), tRemain, iCod, true);
                                                tRemain -= tUsed;
                                            }
                                            if (tRemain > 0)
                                                ptvcursor_add(cursor, hf_mq_fcno_unknowb01, tRemain, ENC_NA);
                                        }
                                    }

                                    iSizeCONN = ptvcursor_current_offset(cursor) - offset;
                                }
                                ptvcursor_free(cursor);
                            }
                            offset += iSizeCONN;
                        }
                    }
                    else if ((p_mq_parm->mq_opcode == MQ_TST_MQINQ || p_mq_parm->mq_opcode == MQ_TST_MQINQ_REPLY || p_mq_parm->mq_opcode == MQ_TST_MQSET) && capLen >= 12)
                    {
                        /* The MQINQ/MQSET structure is special because it does not start with a structid */
                        int iNbSelectors;
                        int iNbIntegers;
                        int iCharLen;
                        int iOffsetINQ;
                        int iSelector;

                        iNbSelectors = tvb_get_uint32(tvb, offset, p_mq_parm->mq_int_enc);
                        iNbIntegers = tvb_get_uint32(tvb, offset + 4, p_mq_parm->mq_int_enc);
                        iCharLen = tvb_get_uint32(tvb, offset + 8, p_mq_parm->mq_int_enc);

                        mq_tree = proto_tree_add_subtree(mqroot_tree, tvb, offset, -1, ett_mq_inq, NULL, MQ_TEXT_INQ);

                        proto_tree_add_item(mq_tree, hf_mq_inq_nbsel, tvb, offset, 4, p_mq_parm->mq_int_enc);
                        proto_tree_add_item(mq_tree, hf_mq_inq_nbint, tvb, offset + 4, 4, p_mq_parm->mq_int_enc);
                        proto_tree_add_item(mq_tree, hf_mq_inq_charlen, tvb, offset + 8, 4, p_mq_parm->mq_int_enc);

                        iOffsetINQ = 12;
                        if (tvb_reported_length_remaining(tvb, offset + iOffsetINQ) >= iNbSelectors * 4)
                        {
                            unsigned _posSel = offset + iOffsetINQ;
                            unsigned _posSelE = _posSel + iNbSelectors * 4 + 4;
                            const uint8_t* _pVal = NULL;
                            for (iSelector = 0; iSelector < iNbSelectors; iSelector++)
                            {
                                proto_tree_add_item(mq_tree, hf_mq_inq_sel, tvb, offset + iOffsetINQ + iSelector * 4, 4, p_mq_parm->mq_int_enc);
                            }
                            iOffsetINQ += iNbSelectors * 4;
                            if (p_mq_parm->mq_opcode == MQ_TST_MQINQ_REPLY || p_mq_parm->mq_opcode == MQ_TST_MQSET)
                            {
                                int iSizeINQValues;
                                iSizeINQValues = iNbIntegers * 4 + iCharLen;
                                if (tvb_reported_length_remaining(tvb, offset + iOffsetINQ) >= iSizeINQValues)
                                {
                                    int iInteger;
                                    unsigned _lVal;
                                    unsigned _lSel;
                                    for (iInteger = 0; iInteger < iNbIntegers; iInteger++)
                                    {
                                        _lSel = tvb_get_uint32(tvb, _posSel, p_mq_parm->mq_int_enc);
                                        while (_posSel < _posSelE && (_lSel < MQ_MQIA_FIRST || _lSel > MQ_MQIA_LAST))
                                        {
                                            _posSel += 4;
                                            _lSel = tvb_get_uint32(tvb, _posSel, p_mq_parm->mq_int_enc);
                                        }
                                        _lVal = tvb_get_uint32(tvb, offset + iOffsetINQ + iInteger * 4, p_mq_parm->mq_int_enc);
                                        _pVal = dissect_mqpcf_parm_getintval(_lSel, _lVal);
                                        _posSel += 4;
                                        if (_pVal)
                                            proto_tree_add_uint_format(mq_tree, hf_mq_inq_intvalue, tvb, offset + iOffsetINQ + iInteger * 4, 4, 0,
                                                "Integer value...: %s (%d)", _pVal, _lVal);
                                        else
                                            proto_tree_add_item(mq_tree, hf_mq_inq_intvalue, tvb, offset + iOffsetINQ + iInteger * 4, 4, p_mq_parm->mq_int_enc);
                                    }
                                    iOffsetINQ += iNbIntegers * 4;
                                    if (iCharLen != 0)
                                    {
                                        proto_tree_add_item(mq_tree, hf_mq_inq_charvalues, tvb, offset + iOffsetINQ, iCharLen, p_mq_parm->mq_str_enc);
                                    }
                                }
                            }
                        }
                        offset += tvb_reported_length(tvb);
                    }
                    else if (p_mq_parm->mq_opcode == MQ_TST_NOTIFICATION)
                    {
                        unsigned uHdl;
                        unsigned uCod;

                        uHdl = tvb_get_uint32(tvb, offset + 4, p_mq_parm->mq_int_enc);
                        uCod = tvb_get_uint32(tvb, offset + 8, p_mq_parm->mq_int_enc);

                        dissect_mq_addCR_colinfo(pinfo, p_mq_parm);
                        col_append_fstr(pinfo->cinfo, COL_INFO, " Hdl=0x%04x Cod=%s(0x%x)",
                            uHdl, try_val_to_str(uCod, GET_VALSV(notifcode)), uCod);

                        mq_tree = proto_tree_add_subtree(mqroot_tree, tvb, offset, -1, ett_mq_notif, NULL, MQ_TEXT_NOTIFICATION);

                        proto_tree_add_item(mq_tree, hf_mq_notif_vers, tvb, offset, 4, p_mq_parm->mq_int_enc);
                        proto_tree_add_item(mq_tree, hf_mq_notif_handle, tvb, offset + 4, 4, p_mq_parm->mq_int_enc);
                        proto_tree_add_item(mq_tree, hf_mq_notif_code, tvb, offset + 8, 4, p_mq_parm->mq_int_enc);
                        proto_tree_add_item(mq_tree, hf_mq_notif_value, tvb, offset + 12, 4, p_mq_parm->mq_int_enc);

                        offset += 16;
                        p_mq_parm->mq_strucID = (tvb_reported_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
                    }
                    else if (p_mq_parm->mq_opcode == MQ_TST_REQUEST_MSGS)
                    {
                        int iHdl;
                        int iFlags;
                        int iGlbMsgIdx;
                        int iMaxMsgLen;
                        int iOpt;

                        iHdl = tvb_get_uint32(tvb, offset + 4, p_mq_parm->mq_int_enc);
                        iMaxMsgLen = tvb_get_uint32(tvb, offset + 16, p_mq_parm->mq_int_enc);
                        iFlags = tvb_get_uint32(tvb, offset + 32, p_mq_parm->mq_int_enc);
                        iGlbMsgIdx = tvb_get_uint32(tvb, offset + 36, p_mq_parm->mq_int_enc);
                        if (iFlags & MQ_REQUEST_MSG_SELECTION)
                        {
                            p_mq_parm->mq_msgreq_ccsid.encod = tvb_get_uint32(tvb, offset + 44, p_mq_parm->mq_int_enc);
                            p_mq_parm->mq_msgreq_ccsid.ccsid = tvb_get_uint32(tvb, offset + 48, p_mq_parm->mq_int_enc);
                        }
                        dissect_mq_addCR_colinfo(pinfo, p_mq_parm);
                        col_append_fstr(pinfo->cinfo, COL_INFO, " Hdl=0x%04x RqstFlags=%08x GlbMsgIdx=%d MaxLen=%d ",
                            iHdl, iFlags, iGlbMsgIdx, iMaxMsgLen);

                        if (tree)
                        {
                            mq_tree = proto_tree_add_subtree(mqroot_tree, tvb, offset, -1, ett_mq_msg, NULL, MQ_TEXT_REQMSG);

                            proto_tree_add_item(mq_tree, hf_mq_msgreq_version, tvb, offset, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_msgreq_handle, tvb, offset + 4, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_msgreq_RecvBytes, tvb, offset + 8, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_msgreq_RqstBytes, tvb, offset + 12, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_msgreq_MaxMsgLen, tvb, offset + 16, 4, p_mq_parm->mq_int_enc);
                            dissect_mq_MQGMO(tvb, mq_tree, offset + 20, ett_mq_gmo_option, p_mq_parm);

                            proto_tree_add_item(mq_tree, hf_mq_msgreq_WaitIntrv, tvb, offset + 24, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_msgreq_QueStatus, tvb, offset + 28, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_bitmask(mq_tree, tvb, offset + 32, hf_mq_msgreq_RqstFlags, ett_mq_msgreq_RqstFlags, pf_flds_msgreq_flags, p_mq_parm->mq_int_enc);

                            proto_tree_add_item(mq_tree, hf_mq_msgreq_GlbMsgIdx, tvb, offset + 36, 4, p_mq_parm->mq_int_enc);

                            if (iFlags & MQ_REQUEST_MSG_SELECTION)
                            {
                                proto_tree_add_item(mq_tree, hf_mq_msgreq_SelectIdx, tvb, offset + 40, 2, p_mq_parm->mq_int_enc);
                                proto_tree_add_item(mq_tree, hf_mq_msgreq_MQMDVers, tvb, offset + 42, 2, p_mq_parm->mq_int_enc);
                                proto_tree_add_item(mq_tree, hf_mq_msgreq_ccsid, tvb, offset + 44, 4, p_mq_parm->mq_int_enc);
                                dissect_mq_encoding(mq_tree, hf_mq_msgreq_encoding, tvb, offset + 48, 4, p_mq_parm->mq_int_enc);
                                proto_tree_add_item(mq_tree, hf_mq_msgreq_MsgSeqNum, tvb, offset + 52, 4, p_mq_parm->mq_int_enc);
                                proto_tree_add_item(mq_tree, hf_mq_msgreq_offset, tvb, offset + 56, 4, p_mq_parm->mq_int_enc);
                                dissect_mq_MQMO(tvb, mq_tree, offset + 60, ett_mq_gmo_matchoption, p_mq_parm);
                                iOpt = tvb_get_uint32(tvb, offset + 60, p_mq_parm->mq_int_enc);

                                offset += MQ_REQUEST_MSG_SIZE_V1_SELECTION_FIXED_PART;
                                if (iOpt & MQ_MQMO_MATCH_MSG_ID)
                                {
                                    proto_tree_add_item(mq_tree, hf_mq_msgreq_mtchMsgId, tvb, offset, 24, p_mq_parm->mq_str_enc);
                                    offset += 24;
                                }
                                if (iOpt & MQ_MQMO_MATCH_CORREL_ID)
                                {
                                    proto_tree_add_item(mq_tree, hf_mq_msgreq_mtchCorId, tvb, offset, 24, p_mq_parm->mq_str_enc);
                                    offset += 24;
                                }
                                if (iOpt & MQ_MQMO_MATCH_GROUP_ID)
                                {
                                    proto_tree_add_item(mq_tree, hf_mq_msgreq_mtchGrpid, tvb, offset, 24, p_mq_parm->mq_str_enc);
                                    offset += 24;
                                }
                                if (iOpt & MQ_MQMO_MATCH_MSG_TOKEN)
                                {
                                    proto_tree_add_item(mq_tree, hf_mq_msgreq_mtchMsgTk, tvb, offset, 16, p_mq_parm->mq_str_enc);
                                    offset += 16;
                                }
                            }
                            else
                            {
                                offset += MQ_REQUEST_MSG_SIZE_V1_NO_SELECTION;
                            }
                        }
                        p_mq_parm->mq_strucID = (tvb_reported_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
                    }
                    else if (p_mq_parm->mq_opcode == MQ_TST_ASYNC_MESSAGE)
                    {
                        int   iReasnCode = 0;
                        int   iSegmIndex;
                        int   iGlbMsgIdx;
                        int   iPadLen;

                        int8_t iStrLen;
                        int   iHdl;
                        int   iHdrL;

                        iHdl = tvb_get_uint32(tvb, offset + 4, p_mq_parm->mq_int_enc);
                        iGlbMsgIdx = tvb_get_uint32(tvb, offset + 12, p_mq_parm->mq_int_enc);
                        iSegmIndex = tvb_get_uint16(tvb, offset + 20, p_mq_parm->mq_int_enc);

                        if (p_mq_parm->mq_ctlf1 & MQ_TCF_FIRST)
                        {
                            iReasnCode = tvb_get_uint32(tvb, offset + 24, p_mq_parm->mq_int_enc);
                        }

                        if (iSegmIndex == 0)
                        {
                            iStrLen = tvb_get_uint8(tvb, offset + 54);
                            iPadLen = (2 + 1 + iStrLen) % 4;
                            iPadLen = (iPadLen) ? 4 - iPadLen : 0;
                        }
                        else
                        {
                            iPadLen = 0;
                            iStrLen = 0;
                        }

                        iHdrL = (iSegmIndex == 0) ? (54 + 1 + iStrLen + iPadLen) : 24;

                        if (!mq_in_reassembly)
                        {
                            dissect_mq_addCR_colinfo(pinfo, p_mq_parm);
                            col_append_fstr(pinfo->cinfo, COL_INFO,
                                " Hdl=0x%04x GlbMsgIdx=%d, Full Message",
                                iHdl, iGlbMsgIdx);
                            if (iReasnCode != MQ_MQRC_NONE)
                                col_append_fstr(pinfo->cinfo, COL_INFO,
                                    ", RC=%d(0x%x) - %s",
                                    iReasnCode, iReasnCode,
                                    val_to_str_ext(iReasnCode, GET_VALS_EXTP(MQRC), "Unknown (0x%02x)"));
                        }

                        mq_tree = proto_tree_add_subtree(mqroot_tree, tvb, offset, iHdrL, ett_mq_msg, NULL, MQ_TEXT_ASYMSG);

                        proto_tree_add_item(mq_tree, hf_mq_msgasy_version, tvb, offset, 4, p_mq_parm->mq_int_enc);
                        proto_tree_add_item(mq_tree, hf_mq_msgasy_handle, tvb, offset + 4, 4, p_mq_parm->mq_int_enc);
                        proto_tree_add_item(mq_tree, hf_mq_msgasy_MsgIndex, tvb, offset + 8, 4, p_mq_parm->mq_int_enc);
                        proto_tree_add_item(mq_tree, hf_mq_msgasy_GlbMsgIdx, tvb, offset + 12, 4, p_mq_parm->mq_int_enc);
                        proto_tree_add_item(mq_tree, hf_mq_msgasy_SegLength, tvb, offset + 16, 4, p_mq_parm->mq_int_enc);
                        proto_tree_add_item(mq_tree, hf_mq_msgasy_SegmIndex, tvb, offset + 20, 2, p_mq_parm->mq_int_enc);
                        proto_tree_add_item(mq_tree, hf_mq_msgasy_SeleIndex, tvb, offset + 22, 2, p_mq_parm->mq_int_enc);
                        if (p_mq_parm->mq_ctlf1 & MQ_TCF_FIRST)
                        {
                            proto_tree_add_item(mq_tree, hf_mq_msgasy_ReasonCod, tvb, offset + 24, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_msgasy_TotMsgLen, tvb, offset + 28, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_msgasy_ActMsgLen, tvb, offset + 32, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_msgasy_MsgToken, tvb, offset + 36, 16, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_msgasy_Status, tvb, offset + 52, 2, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_msgasy_resolQNLn, tvb, offset + 54, 1, ENC_NA);
                            proto_tree_add_item(mq_tree, hf_mq_msgasy_resolQNme, tvb, offset + 55, iStrLen, p_mq_parm->mq_str_enc);
                            if (iPadLen)
                                proto_tree_add_item(mq_tree, hf_mq_msgasy_padding, tvb, offset + 55 + iStrLen, iPadLen, p_mq_parm->mq_str_enc);
                        }
                        offset += iHdrL;
                        p_mq_parm->mq_strucID = (tvb_reported_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;

                        iSizePayload = tvb_reported_length_remaining(tvb, offset);
                        bPayload = (iSizePayload > 0);
                    }
                    else if ((p_mq_parm->mq_opcode == MQ_TST_SPI || p_mq_parm->mq_opcode == MQ_TST_SPI_REPLY) && capLen >= 12)
                    {
                        int     iOffsetSPI = 0;
                        uint32_t iSpiVerb = 0;

                        p_mq_parm->iOfsEnc = offset + 12;
                        p_mq_parm->iOfsCcs = offset + 16;
                        p_mq_parm->iOfsFmt = offset + 20;

                        iSpiVerb = tvb_get_uint32(tvb, offset, p_mq_parm->mq_int_enc);
                        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", val_to_str(iSpiVerb, mq_spi_verbs_vals, "Unknown (0x%08x)"));

                        mq_tree = proto_tree_add_subtree(mqroot_tree, tvb, offset, 12, ett_mq_spi, NULL, MQ_TEXT_SPI);

                        proto_tree_add_item(mq_tree, hf_mq_spi_verb, tvb, offset, 4, p_mq_parm->mq_int_enc);
                        proto_tree_add_item(mq_tree, hf_mq_spi_version, tvb, offset + 4, 4, p_mq_parm->mq_int_enc);
                        proto_tree_add_item(mq_tree, hf_mq_spi_length, tvb, offset + 8, 4, p_mq_parm->mq_int_enc);

                        offset += 12;
                        p_mq_parm->mq_strucID = (tvb_reported_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
                        if (((p_mq_parm->mq_strucID & MQ_MASK_SPxZ) == MQ_STRUCTID_SPxU ||
                            (p_mq_parm->mq_strucID & MQ_MASK_SPxZ) == MQ_STRUCTID_SPxU_EBCDIC)
                            && tvb_reported_length_remaining(tvb, offset) >= 12)
                        {
                            int iSizeSPIMD = 0;
                            uint8_t* sStructId;

                            if ((p_mq_parm->mq_strucID & MQ_MASK_SPxx) == MQ_STRUCTID_SPxx)
                            {
                                strid_enc = ENC_ASCII | ENC_NA;
                            }
                            else
                            {
                                strid_enc = ENC_EBCDIC | ENC_NA;
                            }
                            sStructId = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 4, strid_enc);
                            mq_tree = proto_tree_add_subtree(mqroot_tree, tvb, offset, 12, ett_mq_spi_base, NULL, (const char*)sStructId);

                            proto_tree_add_item(mq_tree, hf_mq_spi_base_StructID, tvb, offset, 4, strid_enc);
                            proto_tree_add_item(mq_tree, hf_mq_spi_base_version, tvb, offset + 4, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_spi_base_length, tvb, offset + 8, 4, p_mq_parm->mq_int_enc);

                            offset += 12;
                            p_mq_parm->mq_strucID = (tvb_reported_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;

                            if ((iSizeSPIMD = dissect_mq_md(tvb, mqroot_tree, offset, p_mq_parm, true)) != 0)
                            {
                                offset += iSizeSPIMD;
                                offset += dissect_mq_gmo(tvb, pinfo, mqroot_tree, offset, p_mq_parm);
                                offset += dissect_mq_pmo(tvb, pinfo, mqroot_tree, offset, p_mq_parm, &iDistributionListSize);
                                p_mq_parm->mq_strucID = (tvb_reported_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
                            }

                            offset += dissect_mq_od(tvb, pinfo, mqroot_tree, offset, p_mq_parm, &iDistributionListSize);

                            if (((p_mq_parm->mq_strucID & MQ_MASK_SPxZ) == MQ_STRUCTID_SPxO ||
                                (p_mq_parm->mq_strucID & MQ_MASK_SPxZ) == MQ_STRUCTID_SPxO_EBCDIC ||
                                (p_mq_parm->mq_strucID & MQ_MASK_SPxZ) == MQ_STRUCTID_SPxI ||
                                (p_mq_parm->mq_strucID & MQ_MASK_SPxZ) == MQ_STRUCTID_SPxI_EBCDIC)
                                && tvb_reported_length_remaining(tvb, offset) >= 12)
                            {
                                /* Dissect the common part of these structures */
                                if ((p_mq_parm->mq_strucID & MQ_MASK_SPxx) == MQ_STRUCTID_SPxx)
                                {
                                    strid_enc = ENC_ASCII | ENC_NA;
                                }
                                else
                                {
                                    strid_enc = ENC_EBCDIC | ENC_NA;
                                }
                                sStructId = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 4, strid_enc);
                                mq_tree = proto_tree_add_subtree(mqroot_tree, tvb, offset, -1, ett_mq_spi_base, NULL, (const char*)sStructId);

                                proto_tree_add_item(mq_tree, hf_mq_spi_base_StructID, tvb, offset, 4, strid_enc);
                                proto_tree_add_item(mq_tree, hf_mq_spi_base_version, tvb, offset + 4, 4, p_mq_parm->mq_int_enc);
                                proto_tree_add_item(mq_tree, hf_mq_spi_base_length, tvb, offset + 8, 4, p_mq_parm->mq_int_enc);

                                if ((p_mq_parm->mq_strucID == MQ_STRUCTID_SPQO || p_mq_parm->mq_strucID == MQ_STRUCTID_SPQO_EBCDIC)
                                    && tvb_reported_length_remaining(tvb, offset) >= 16)
                                {
                                    if (tree)
                                    {
                                        int iVerbNumber = 0;
                                        proto_tree_add_item(mq_tree, hf_mq_spi_spqo_nbverb, tvb, offset + 12, 4, p_mq_parm->mq_int_enc);
                                        iVerbNumber = tvb_get_uint32(tvb, offset + 12, p_mq_parm->mq_int_enc);

                                        if (tvb_reported_length_remaining(tvb, offset) >= iVerbNumber * 20 + 16)
                                        {
                                            int iVerb = 0;
                                            iOffsetSPI = offset + 16;
                                            for (iVerb = 0; iVerb < iVerbNumber; iVerb++)
                                            {
                                                proto_tree_add_item(mq_tree, hf_mq_spi_spqo_verbid, tvb, iOffsetSPI, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_spi_spqo_maxiover, tvb, iOffsetSPI + 4, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_spi_spqo_maxinver, tvb, iOffsetSPI + 8, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_spi_spqo_maxouver, tvb, iOffsetSPI + 12, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_spi_spqo_flags, tvb, iOffsetSPI + 16, 4, p_mq_parm->mq_int_enc);
                                                iOffsetSPI += 20;
                                            }
                                            offset += iVerbNumber * 20 + 16;
                                        }
                                    }
                                }
                                else if ((p_mq_parm->mq_strucID == MQ_STRUCTID_SPAI || p_mq_parm->mq_strucID == MQ_STRUCTID_SPAI_EBCDIC)
                                    && tvb_reported_length_remaining(tvb, offset) >= 136)
                                {
                                    proto_tree_add_item(mq_tree, hf_mq_spi_spai_mode, tvb, offset + 12, 4, p_mq_parm->mq_int_enc);
                                    proto_tree_add_item(mq_tree, hf_mq_spi_spai_unknown1, tvb, offset + 16, 48, p_mq_parm->mq_str_enc);
                                    proto_tree_add_item(mq_tree, hf_mq_spi_spai_unknown2, tvb, offset + 64, 48, p_mq_parm->mq_str_enc);
                                    proto_tree_add_item(mq_tree, hf_mq_spi_spai_msgid, tvb, offset + 112, 24, p_mq_parm->mq_str_enc);
                                    offset += 136;
                                }
                                else if ((p_mq_parm->mq_strucID == MQ_STRUCTID_SPGI || p_mq_parm->mq_strucID == MQ_STRUCTID_SPGI_EBCDIC)
                                    && tvb_reported_length_remaining(tvb, offset) >= 24)
                                {
                                    proto_tree_add_item(mq_tree, hf_mq_spi_spgi_batchsz, tvb, offset + 12, 4, p_mq_parm->mq_int_enc);
                                    proto_tree_add_item(mq_tree, hf_mq_spi_spgi_batchint, tvb, offset + 16, 4, p_mq_parm->mq_int_enc);
                                    proto_tree_add_item(mq_tree, hf_mq_spi_spgi_maxmsgsz, tvb, offset + 20, 4, p_mq_parm->mq_int_enc);
                                    offset += 24;
                                }
                                else if ((p_mq_parm->mq_strucID == MQ_STRUCTID_SPGO || p_mq_parm->mq_strucID == MQ_STRUCTID_SPPI ||
                                    p_mq_parm->mq_strucID == MQ_STRUCTID_SPGO_EBCDIC || p_mq_parm->mq_strucID == MQ_STRUCTID_SPPI_EBCDIC)
                                    && tvb_reported_length_remaining(tvb, offset) >= 20)
                                {
                                    proto_tree_add_bitmask(mq_tree, tvb, offset + 12, hf_mq_spi_spgo_options, ett_mq_spi_options, pf_flds_spiopt, ENC_BIG_ENDIAN);
                                    proto_tree_add_item(mq_tree, hf_mq_spi_spgo_size, tvb, offset + 16, 4, p_mq_parm->mq_int_enc);
                                    iSizePayload = tvb_get_uint32(tvb, offset + 16, p_mq_parm->mq_int_enc);
                                    offset += 20;
                                    bPayload = true;
                                }
                                else
                                {
                                    offset += 12;
                                }
                                p_mq_parm->mq_strucID = (tvb_reported_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
                            }
                        }
                    }
                    else if ((p_mq_parm->mq_opcode >= 0xA0 && p_mq_parm->mq_opcode <= 0xB9) && capLen >= 16)
                    {
                        /* The XA structures are special because they do not start with a structid */
                        mq_tree = proto_tree_add_subtree_format(mqroot_tree, tvb, offset, 16, ett_mq_xa, NULL,
                            "%s (%s)", MQ_TEXT_XA, val_to_str_ext(p_mq_parm->mq_opcode, GET_VALS_EXTP(opcode), "Unknown (0x%02x)"));

                        proto_tree_add_item(mq_tree, hf_mq_xa_length, tvb, offset, 4, ENC_BIG_ENDIAN);
                        proto_tree_add_item(mq_tree, hf_mq_xa_returnvalue, tvb, offset + 4, 4, p_mq_parm->mq_int_enc);

                        proto_tree_add_bitmask(mq_tree, tvb, offset + 8, hf_mq_xa_tmflags, ett_mq_xa_tmflags, pf_flds_tmflags, ENC_BIG_ENDIAN);

                        proto_tree_add_item(mq_tree, hf_mq_xa_rmid, tvb, offset + 12, 4, p_mq_parm->mq_int_enc);
                        offset += 16;
                        if (p_mq_parm->mq_opcode == MQ_TST_XA_START || p_mq_parm->mq_opcode == MQ_TST_XA_END || p_mq_parm->mq_opcode == MQ_TST_XA_PREPARE
                            || p_mq_parm->mq_opcode == MQ_TST_XA_COMMIT || p_mq_parm->mq_opcode == MQ_TST_XA_ROLLBACK || p_mq_parm->mq_opcode == MQ_TST_XA_FORGET
                            || p_mq_parm->mq_opcode == MQ_TST_XA_COMPLETE)
                        {
                            int iSizeXid = 0;
                            if ((iSizeXid = dissect_mq_xid(tvb, mqroot_tree, p_mq_parm, offset)) != 0)
                                offset += iSizeXid;
                        }
                        else if ((p_mq_parm->mq_opcode == MQ_TST_XA_OPEN || p_mq_parm->mq_opcode == MQ_TST_XA_CLOSE)
                            && tvb_reported_length_remaining(tvb, offset) >= 1)
                        {
                            uint8_t iXAInfoLength = 0;
                            iXAInfoLength = tvb_get_uint8(tvb, offset);
                            if (tvb_reported_length_remaining(tvb, offset) >= iXAInfoLength + 1)
                            {
                                mq_tree = proto_tree_add_subtree(mqroot_tree, tvb, offset, iXAInfoLength + 1, ett_mq_xa_info, NULL, MQ_TEXT_XINF);

                                proto_tree_add_item(mq_tree, hf_mq_xa_xainfo_length, tvb, offset, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(mq_tree, hf_mq_xa_xainfo_value, tvb, offset + 1, iXAInfoLength, p_mq_parm->mq_str_enc);
                            }
                            offset += 1 + iXAInfoLength;
                        }
                        else if ((p_mq_parm->mq_opcode == MQ_TST_XA_RECOVER || p_mq_parm->mq_opcode == MQ_TST_XA_RECOVER_REPLY)
                            && tvb_reported_length_remaining(tvb, offset) >= 4)
                        {
                            int iNbXid = 0;
                            iNbXid = tvb_get_uint32(tvb, offset, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_xa_count, tvb, offset, 4, p_mq_parm->mq_int_enc);
                            offset += 4;
                            if (p_mq_parm->mq_opcode == MQ_TST_XA_RECOVER_REPLY)
                            {
                                int iXid = 0;
                                for (iXid = 0; iXid < iNbXid; iXid++)
                                {
                                    int iSizeXid = 0;
                                    if ((iSizeXid = dissect_mq_xid(tvb, mqroot_tree, p_mq_parm, offset)) != 0)
                                        offset += iSizeXid;
                                    else
                                        break;
                                }
                            }
                        }
                    }
                    /* LPOO seems to be a bug for SPOO */
                    if ((p_mq_parm->mq_strucID == MQ_STRUCTID_LPOO || p_mq_parm->mq_strucID == MQ_STRUCTID_LPOO_EBCDIC) && tvb_reported_length_remaining(tvb, offset) >= 32)
                    {
                        unsigned iVersion;
                        unsigned iXtraData = 0;
                        int   iSize = 32;
                        int   iPos = 0;
                        int   iSegSize = tvb_reported_length_remaining(tvb, offset);
                        iVersion = tvb_get_uint32(tvb, offset + 4, p_mq_parm->mq_int_enc);
                        if (iSegSize >= 488)
                        {
                            iSize += 56;
                            iXtraData = tvb_get_uint32(tvb, offset + 84, p_mq_parm->mq_int_enc);
                        }

                        if (iSize != 0 && iSegSize >= iSize)
                        {
                            mq_tree = proto_tree_add_subtree(mqroot_tree, tvb, offset, iSize, ett_mq_lpoo, NULL, MQ_TEXT_LPOO);

                            proto_tree_add_item(mq_tree, hf_mq_lpoo_StructID, tvb, offset, 4, p_mq_parm->mq_str_enc);
                            proto_tree_add_item(mq_tree, hf_mq_lpoo_version, tvb, offset + 4, 4, p_mq_parm->mq_int_enc);
                            dissect_mq_MQOO(tvb, mq_tree, offset + 8, ett_mq_open_option, hf_mq_open_options, p_mq_parm);
                            dissect_mq_LPOO_LPIOPTS(tvb, mq_tree, offset + 12, ett_mq_lpoo_lpiopts, p_mq_parm);

                            proto_tree_add_item(mq_tree, hf_mq_lpoo_defpersist, tvb, offset + 16, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_lpoo_defputresptype, tvb, offset + 20, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_lpoo_defreadahead, tvb, offset + 24, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_lpoo_propertyctl, tvb, offset + 28, 4, p_mq_parm->mq_int_enc);
                            iPos += 32;
                            if (iSize == 88)
                            {
                                proto_tree_add_item(mq_tree, hf_mq_lpoo_qprotect, tvb, offset + iPos, 48, p_mq_parm->mq_str_enc);
                                proto_tree_add_item(mq_tree, hf_mq_lpoo_qprotect_val1, tvb, offset + iPos + 48, 4, p_mq_parm->mq_str_enc);
                                proto_tree_add_item(mq_tree, hf_mq_lpoo_qprotect_val2, tvb, offset + iPos + 52, 4, p_mq_parm->mq_str_enc);
                                iPos += 56;
                            }
                            if (iVersion >= 1)
                            {
                                unsigned iDistributionListSize2;
                                iSize = dissect_mq_od(tvb, pinfo, mqroot_tree, offset + iPos, p_mq_parm, &iDistributionListSize2);
                            }
                            offset += iPos + iSize;
                            p_mq_parm->mq_strucID = (tvb_reported_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
                            if (iXtraData > 0)
                            {
                                if (p_mq_parm->mq_opcode == MQ_TST_SPI_REPLY)
                                {
                                    bPayload = true;
                                    iSizePayload = iXtraData;
                                    p_mq_parm->iOfsFmt = (offset - iSize);
                                }
                            }
                        }
                    }
                    if ((p_mq_parm->mq_strucID == MQ_STRUCTID_ID || p_mq_parm->mq_strucID == MQ_STRUCTID_ID_EBCDIC) && tvb_reported_length_remaining(tvb, offset) >= 5)
                    {
                        offset += dissect_mq_id(tvb, pinfo, mqroot_tree, offset, p_mq_parm);
                        p_mq_parm->mq_strucID = (tvb_reported_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
                    }
                    if ((p_mq_parm->mq_strucID == MQ_STRUCTID_UID || p_mq_parm->mq_strucID == MQ_STRUCTID_UID_EBCDIC) && tvb_reported_length_remaining(tvb, offset) > 0)
                    {
                        int iSizeUID;
                        /* iSizeUID = (iVersionID < 5 ? 28 : 132);  guess */
                        /* The iVersionID is available in the previous ID segment, we should keep a state *
                         * Instead we rely on the segment length announced in the TSH */
                        iSizeUID = iSegmentLength - iSizeTSH;
                        if (iSizeUID != 28 && iSizeUID != 132)
                            iSizeUID = 0;

                        if (iSizeUID != 0 && tvb_reported_length_remaining(tvb, offset) >= iSizeUID)
                        {
                            uint8_t* sUserId;
                            sUserId = tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 4, 12, p_mq_parm->mq_str_enc);
                            dissect_mq_addCR_colinfo(pinfo, p_mq_parm);
                            if (strip_trailing_blanks(sUserId, 12) > 0)
                            {
                                col_append_fstr(pinfo->cinfo, COL_INFO, " User=%s", sUserId);
                            }

                            mq_tree = proto_tree_add_subtree(mqroot_tree, tvb, offset, iSizeUID, ett_mq_uid, NULL, MQ_TEXT_UID);

                            proto_tree_add_item(mq_tree, hf_mq_uid_StructID, tvb, offset, 4, p_mq_parm->mq_str_enc);
                            proto_tree_add_item(mq_tree, hf_mq_uid_userid, tvb, offset + 4, 12, p_mq_parm->mq_str_enc);
                            proto_tree_add_item(mq_tree, hf_mq_uid_password, tvb, offset + 16, 12, p_mq_parm->mq_str_enc);

                            if (iSizeUID == 132)
                            {
                                proto_tree_add_item(mq_tree, hf_mq_uid_longuserid, tvb, offset + 28, 64, p_mq_parm->mq_str_enc);
                                dissect_mq_sid(tvb, mq_tree, p_mq_parm, offset + 92);
                            }
                        }
                        offset += iSizeUID;
                        p_mq_parm->mq_strucID = (tvb_reported_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
                    }

                    offset += dissect_mq_od(tvb, pinfo, mqroot_tree, offset, p_mq_parm, &iDistributionListSize);

                    if ((iSizeMD = dissect_mq_md(tvb, mqroot_tree, offset, p_mq_parm, true)) != 0)
                    {
                        int iSizeGMO = 0;
                        int iSizePMO = 0;
                        offset += iSizeMD;

                        if ((iSizeGMO = dissect_mq_gmo(tvb, pinfo, mqroot_tree, offset, p_mq_parm)) != 0)
                        {
                            offset += iSizeGMO;
                            bPayload = true;
                        }
                        else if ((iSizePMO = dissect_mq_pmo(tvb, pinfo, mqroot_tree, offset, p_mq_parm, &iDistributionListSize)) != 0)
                        {
                            offset += iSizePMO;
                            bPayload = true;
                        }
                        if (tvb_reported_length_remaining(tvb, offset) >= 4)
                        {
                            if (bPayload == true && (p_mq_parm->mq_opcode != MQ_TST_ASYNC_MESSAGE))
                            {
                                iSizePayload = tvb_get_uint32(tvb, offset, p_mq_parm->mq_int_enc);
                                if (tree)
                                {
                                    mq_tree = proto_tree_add_subtree(mqroot_tree, tvb, offset, 4, ett_mq_put, NULL, MQ_TEXT_PUT);
                                    proto_tree_add_item(mq_tree, hf_mq_put_length, tvb, offset, 4, p_mq_parm->mq_int_enc);
                                }
                                offset += 4;
                            }
                        }
                    }
                    if (iDistributionListSize > 0)
                    {
                        col_append_fstr(pinfo->cinfo, COL_INFO, " (Distribution List, Size=%d)", iDistributionListSize);
                    }
                    if (bPayload == true)
                    {
                        if (iSizePayload != 0 && tvb_reported_length_remaining(tvb, offset) > 0)
                        {
                            /* For the following header structures, each structure has a "format" field
                            which announces the type of the following structure.  For dissection we
                            do not use it and rely on the structid instead. */
                            uint32_t iHeadersLength = 0;
                            if (tvb_reported_length_remaining(tvb, offset) >= 4)
                            {
                                int iSizeMD2 = 0;
                                p_mq_parm->mq_strucID = tvb_get_ntohl(tvb, offset);

                                if ((p_mq_parm->mq_strucID == MQ_STRUCTID_XQH || p_mq_parm->mq_strucID == MQ_STRUCTID_XQH_EBCDIC) && tvb_reported_length_remaining(tvb, offset) >= 104)
                                {
                                    /* if MD.format == MQXMIT */
                                    int iSizeXQH = 104;
                                    if (tree)
                                    {
                                        mq_tree = proto_tree_add_subtree(mqroot_tree, tvb, offset, iSizeXQH, ett_mq_xqh, NULL, MQ_TEXT_XQH);

                                        proto_tree_add_item(mq_tree, hf_mq_xqh_StructID, tvb, offset, 4, p_mq_parm->mq_str_enc);
                                        proto_tree_add_item(mq_tree, hf_mq_xqh_version, tvb, offset + 4, 4, p_mq_parm->mq_int_enc);
                                        proto_tree_add_item(mq_tree, hf_mq_xqh_remoteq, tvb, offset + 8, 48, p_mq_parm->mq_str_enc);
                                        proto_tree_add_item(mq_tree, hf_mq_xqh_remoteqmgr, tvb, offset + 56, 48, p_mq_parm->mq_str_enc);
                                    }
                                    offset += iSizeXQH;
                                    iHeadersLength += iSizeXQH;

                                    if ((iSizeMD2 = dissect_mq_md(tvb, mqroot_tree, offset, p_mq_parm, true)) != 0)
                                    {
                                        offset += iSizeMD2;
                                        iHeadersLength += iSizeMD2;
                                    }

                                    p_mq_parm->mq_strucID = (tvb_reported_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
                                }
                                if ((p_mq_parm->mq_strucID == MQ_STRUCTID_DLH || p_mq_parm->mq_strucID == MQ_STRUCTID_DLH_EBCDIC) && tvb_reported_length_remaining(tvb, offset) >= 172)
                                {
                                    /* if MD.format == MQDEAD */
                                    int iSizeDLH = 172;
                                    p_mq_parm->iOfsEnc = offset + 108;
                                    p_mq_parm->iOfsCcs = offset + 112;
                                    p_mq_parm->iOfsFmt = offset + 116;

                                    p_mq_parm->mq_dlh_ccsid.encod = tvb_get_uint32(tvb, offset + 108, p_mq_parm->mq_int_enc);
                                    p_mq_parm->mq_dlh_ccsid.ccsid = tvb_get_uint32(tvb, offset + 112, p_mq_parm->mq_int_enc);

                                    if (tree)
                                    {
                                        mq_tree = proto_tree_add_subtree(mqroot_tree, tvb, offset, iSizeDLH, ett_mq_dlh, NULL, MQ_TEXT_DLH);

                                        proto_tree_add_item(mq_tree, hf_mq_dlh_StructID, tvb, offset, 4, p_mq_parm->mq_str_enc);
                                        proto_tree_add_item(mq_tree, hf_mq_dlh_version, tvb, offset + 4, 4, p_mq_parm->mq_int_enc);
                                        proto_tree_add_item(mq_tree, hf_mq_dlh_reason, tvb, offset + 8, 4, p_mq_parm->mq_int_enc);
                                        proto_tree_add_item(mq_tree, hf_mq_dlh_destq, tvb, offset + 12, 48, p_mq_parm->mq_str_enc);
                                        proto_tree_add_item(mq_tree, hf_mq_dlh_destqmgr, tvb, offset + 60, 48, p_mq_parm->mq_str_enc);
                                        dissect_mq_encoding(mq_tree, hf_mq_dlh_encoding, tvb, offset + 108, 4, p_mq_parm->mq_int_enc);
                                        proto_tree_add_item(mq_tree, hf_mq_dlh_ccsid, tvb, offset + 112, 4, p_mq_parm->mq_int_enc);
                                        proto_tree_add_item(mq_tree, hf_mq_dlh_format, tvb, offset + 116, 8, p_mq_parm->mq_str_enc);
                                        proto_tree_add_item(mq_tree, hf_mq_dlh_putappltype, tvb, offset + 124, 4, p_mq_parm->mq_int_enc);
                                        proto_tree_add_item(mq_tree, hf_mq_dlh_putapplname, tvb, offset + 128, 28, p_mq_parm->mq_str_enc);
                                        proto_tree_add_item(mq_tree, hf_mq_dlh_putdate, tvb, offset + 156, 8, p_mq_parm->mq_str_enc);
                                        proto_tree_add_item(mq_tree, hf_mq_dlh_puttime, tvb, offset + 164, 8, p_mq_parm->mq_str_enc);
                                    }
                                    offset += iSizeDLH;
                                    iHeadersLength += iSizeDLH;
                                    p_mq_parm->mq_strucID = (tvb_reported_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
                                }
                                if ((p_mq_parm->mq_strucID == MQ_STRUCTID_TM || p_mq_parm->mq_strucID == MQ_STRUCTID_TM_EBCDIC)
                                    && tvb_reported_length_remaining(tvb, offset) >= 8)
                                {

                                    if (tree)
                                    {
                                        mq_tree = proto_tree_add_subtree(mqroot_tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), ett_mq_head, NULL,
                                            val_to_str_ext(p_mq_parm->mq_strucID, GET_VALS_EXTP(StructID), "Unknown (0x%08x)"));
                                    }
                                    proto_tree_add_item(mq_tree, hf_mq_tm_StructID, tvb, offset + 0, 4, p_mq_parm->mq_str_enc);
                                    proto_tree_add_item(mq_tree, hf_mq_tm_version, tvb, offset + 4, 4, p_mq_parm->mq_int_enc);
                                    proto_tree_add_item(mq_tree, hf_mq_tm_QName, tvb, offset + 8, 48, p_mq_parm->mq_str_enc);
                                    proto_tree_add_item(mq_tree, hf_mq_tm_ProcessNme, tvb, offset + 56, 48, p_mq_parm->mq_str_enc);
                                    proto_tree_add_item(mq_tree, hf_mq_tm_TriggerData, tvb, offset + 104, 64, p_mq_parm->mq_str_enc);
                                    proto_tree_add_item(mq_tree, hf_mq_tm_ApplType, tvb, offset + 168, 4, p_mq_parm->mq_int_enc);
                                    proto_tree_add_item(mq_tree, hf_mq_tm_ApplId, tvb, offset + 172, 256, p_mq_parm->mq_str_enc);
                                    proto_tree_add_item(mq_tree, hf_mq_tm_EnvData, tvb, offset + 428, 128, p_mq_parm->mq_str_enc);
                                    proto_tree_add_item(mq_tree, hf_mq_tm_UserData, tvb, offset + 556, 128, p_mq_parm->mq_str_enc);
                                    offset += 684;
                                }
                                if ((p_mq_parm->mq_strucID == MQ_STRUCTID_TMC2 || p_mq_parm->mq_strucID == MQ_STRUCTID_TMC2_EBCDIC)
                                    && tvb_reported_length_remaining(tvb, offset) >= 8)
                                {
                                    if (tree)
                                    {
                                        mq_tree = proto_tree_add_subtree(mqroot_tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), ett_mq_head, NULL,
                                            val_to_str_ext(p_mq_parm->mq_strucID, GET_VALS_EXTP(StructID), "Unknown (0x%08x)"));
                                    }
                                    proto_tree_add_item(mq_tree, hf_mq_tmc2_StructID, tvb, offset + 0, 4, p_mq_parm->mq_str_enc);
                                    proto_tree_add_item(mq_tree, hf_mq_tmc2_version, tvb, offset + 4, 4, p_mq_parm->mq_str_enc);
                                    proto_tree_add_item(mq_tree, hf_mq_tmc2_QName, tvb, offset + 8, 48, p_mq_parm->mq_str_enc);
                                    proto_tree_add_item(mq_tree, hf_mq_tmc2_ProcessNme, tvb, offset + 56, 48, p_mq_parm->mq_str_enc);
                                    proto_tree_add_item(mq_tree, hf_mq_tmc2_TriggerData, tvb, offset + 104, 64, p_mq_parm->mq_str_enc);
                                    proto_tree_add_item(mq_tree, hf_mq_tmc2_ApplType, tvb, offset + 168, 4, p_mq_parm->mq_str_enc);
                                    proto_tree_add_item(mq_tree, hf_mq_tmc2_ApplId, tvb, offset + 172, 256, p_mq_parm->mq_str_enc);
                                    proto_tree_add_item(mq_tree, hf_mq_tmc2_EnvData, tvb, offset + 428, 128, p_mq_parm->mq_str_enc);
                                    proto_tree_add_item(mq_tree, hf_mq_tmc2_UserData, tvb, offset + 556, 128, p_mq_parm->mq_str_enc);
                                    proto_tree_add_item(mq_tree, hf_mq_tmc2_QMgrName, tvb, offset + 684, 48, p_mq_parm->mq_str_enc);
                                    offset += 732;
                                }
                                if ((p_mq_parm->mq_strucID == MQ_STRUCTID_MDE || p_mq_parm->mq_strucID == MQ_STRUCTID_MDE_EBCDIC
                                    || p_mq_parm->mq_strucID == MQ_STRUCTID_CIH || p_mq_parm->mq_strucID == MQ_STRUCTID_CIH_EBCDIC
                                    || p_mq_parm->mq_strucID == MQ_STRUCTID_IIH || p_mq_parm->mq_strucID == MQ_STRUCTID_IIH_EBCDIC
                                    || p_mq_parm->mq_strucID == MQ_STRUCTID_RFH || p_mq_parm->mq_strucID == MQ_STRUCTID_RFH_EBCDIC
                                    || p_mq_parm->mq_strucID == MQ_STRUCTID_RMH || p_mq_parm->mq_strucID == MQ_STRUCTID_RMH_EBCDIC
                                    || p_mq_parm->mq_strucID == MQ_STRUCTID_WIH || p_mq_parm->mq_strucID == MQ_STRUCTID_WIH_EBCDIC
                                    )
                                    && tvb_reported_length_remaining(tvb, offset) >= 12)
                                {
                                    /* Dissect the generic part of the other pre-defined headers */
                                    /* We assume that only one such header is present */
                                    int iSizeHeader;
                                    int oIntEnc = p_mq_parm->mq_int_enc;
                                    /* Use MD encoding */
                                    p_mq_parm->mq_int_enc = ((p_mq_parm->mq_md_ccsid.encod & MQ_MQENC_INTEGER_MASK) == MQ_MQENC_INTEGER_NORMAL) ? ENC_BIG_ENDIAN : ENC_LITTLE_ENDIAN;
                                    iSizeHeader = (int)tvb_get_uint32(tvb, offset + 8, p_mq_parm->mq_int_enc);
                                    /* XXX - 32 is inferred from the code below.  What's the
                                    * correct minimum? */
                                    if (iSizeHeader <= 32)
                                        return;

                                    p_mq_parm->mq_head_ccsid.encod = tvb_get_uint32(tvb, offset + 12, p_mq_parm->mq_int_enc);
                                    p_mq_parm->mq_head_ccsid.ccsid = tvb_get_uint32(tvb, offset + 16, p_mq_parm->mq_int_enc);

                                    if (tvb_reported_length_remaining(tvb, offset) >= iSizeHeader)
                                    {
                                        int iTmp;
                                        int iVer;
                                        int iLen;
                                        int oStrEnc = p_mq_parm->mq_str_enc;

                                        p_mq_parm->iOfsEnc = offset + 12;
                                        p_mq_parm->iOfsCcs = offset + 16;
                                        p_mq_parm->iOfsFmt = offset + 20;

                                        iVer = (int)tvb_get_uint32(tvb, offset + 4, p_mq_parm->mq_int_enc);
                                        iLen = (int)tvb_get_uint32(tvb, offset + 8, p_mq_parm->mq_int_enc);
                                        iTmp = p_mq_parm->mq_head_ccsid.ccsid;
                                        if (iTmp == 0)
                                            iTmp = p_mq_parm->mq_md_ccsid.ccsid;

                                        if (IS_EBCDIC(iTmp))
                                            p_mq_parm->mq_str_enc = ENC_EBCDIC | ENC_NA;
                                        else
                                            p_mq_parm->mq_str_enc = ENC_UTF_8 | ENC_NA;

                                        if (tree)
                                        {
                                            mq_tree = proto_tree_add_subtree(mqroot_tree, tvb, offset, iSizeHeader, ett_mq_head, NULL,
                                                val_to_str_ext(p_mq_parm->mq_strucID, GET_VALS_EXTP(StructID), "Unknown (0x%08x)"));

                                            proto_tree_add_item(mq_tree, hf_mq_head_StructID, tvb, offset, 4, p_mq_parm->mq_str_enc);
                                            proto_tree_add_item(mq_tree, hf_mq_head_version, tvb, offset + 4, 4, p_mq_parm->mq_int_enc);
                                            proto_tree_add_item(mq_tree, hf_mq_head_length, tvb, offset + 8, 4, p_mq_parm->mq_int_enc);
                                            dissect_mq_encoding(mq_tree, hf_mq_head_encoding, tvb, offset + 12, 4, p_mq_parm->mq_int_enc);
                                            proto_tree_add_item(mq_tree, hf_mq_head_ccsid, tvb, offset + 16, 4, p_mq_parm->mq_int_enc);
                                            proto_tree_add_item(mq_tree, hf_mq_head_format, tvb, offset + 20, 8, p_mq_parm->mq_str_enc);

                                            if (p_mq_parm->mq_strucID == MQ_STRUCTID_DH || p_mq_parm->mq_strucID == MQ_STRUCTID_DH_EBCDIC)
                                            {
                                                int iRec;
                                                iRec = tvb_get_uint32(tvb, offset + 36, p_mq_parm->mq_int_enc);

                                                proto_tree_add_bitmask(mq_tree, tvb, offset + 28, hf_mq_head_flags, ett_mq_head_flags, pf_flds_dh_flags, ENC_BIG_ENDIAN);
                                                proto_tree_add_item(mq_tree, hf_mq_dh_putmsgrecfld, tvb, offset + 32, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_dh_recspresent, tvb, offset + 36, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_dh_objrecofs, tvb, offset + 40, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_dh_putmsgrecofs, tvb, offset + 44, 4, p_mq_parm->mq_int_enc);

                                                if (iRec)
                                                {
                                                    int iOfs1;
                                                    int iOfs2;
                                                    int iFlgs;
                                                    int iSize;

                                                    iFlgs = (int)tvb_get_uint32(tvb, offset + 32, p_mq_parm->mq_int_enc);
                                                    iOfs1 = (int)tvb_get_uint32(tvb, offset + 40, p_mq_parm->mq_int_enc);
                                                    iOfs2 = (int)tvb_get_uint32(tvb, offset + 44, p_mq_parm->mq_int_enc);

                                                    iSize = dissect_mq_or(tvb, mq_tree, offset + 48, iRec, iOfs1, p_mq_parm);
                                                    /*iSize = */dissect_mq_pmr(tvb, mqroot_tree, offset + 48 + iSize, iRec, iOfs2, iFlgs, p_mq_parm);
                                                }
                                            }
                                            else if (p_mq_parm->mq_strucID == MQ_STRUCTID_MDE || p_mq_parm->mq_strucID == MQ_STRUCTID_MDE_EBCDIC)
                                            {
                                                proto_tree_add_item(mq_tree, hf_mq_head_flags, tvb, offset + 28, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_md_groupid, tvb, offset + 32, 24, ENC_NA);
                                                proto_tree_add_item(mq_tree, hf_mq_md_msgseqnumber, tvb, offset + 56, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_md_offset, tvb, offset + 60, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_md_msgflags, tvb, offset + 64, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_md_origlen, tvb, offset + 68, 4, p_mq_parm->mq_int_enc);
                                            }
                                            else if (p_mq_parm->mq_strucID == MQ_STRUCTID_IIH || p_mq_parm->mq_strucID == MQ_STRUCTID_IIH_EBCDIC)
                                            {
                                                int16_t sLen;
                                                int32_t iPos;
                                                proto_tree* mq_ims;

                                                proto_tree_add_bitmask(mq_tree, tvb, offset + 28, hf_mq_head_flags, ett_mq_head_flags, pf_flds_iih_flags, ENC_BIG_ENDIAN);
                                                proto_tree_add_item(mq_tree, hf_mq_iih_ltermoverride, tvb, offset + 32, 8, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_iih_mfsmapname, tvb, offset + 40, 8, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_iih_replytofmt, tvb, offset + 48, 8, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_iih_authenticator, tvb, offset + 56, 8, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_iih_transinstid, tvb, offset + 64, 16, ENC_NA);
                                                proto_tree_add_item(mq_tree, hf_mq_iih_transstate, tvb, offset + 80, 1, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_iih_commimode, tvb, offset + 81, 1, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_iih_securityscope, tvb, offset + 82, 1, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_iih_reserved, tvb, offset + 83, 1, p_mq_parm->mq_str_enc);

                                                iPos = offset + iSizeHeader;
                                                sLen = tvb_get_uint16(tvb, iPos, p_mq_parm->mq_int_enc);
                                                mq_ims = proto_tree_add_subtree(mq_tree, tvb, iPos, sLen, ett_mq_ims, NULL, "IMS Message");
                                                proto_tree_add_item(mq_ims, hf_mq_ims_ll, tvb, iPos + 0, 2, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_ims, hf_mq_ims_zz, tvb, iPos + 2, 2, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_ims, hf_mq_ims_trx, tvb, iPos + 4, 8, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_ims, hf_mq_ims_data, tvb, iPos + 12, sLen - 12, ENC_NA);
                                                offset += sLen;
                                            }
                                            else if (p_mq_parm->mq_strucID == MQ_STRUCTID_CIH || p_mq_parm->mq_strucID == MQ_STRUCTID_CIH_EBCDIC)
                                            {
                                                proto_tree_add_bitmask(mq_tree, tvb, offset + 28, hf_mq_head_flags, ett_mq_head_flags, pf_flds_cih_flags, ENC_BIG_ENDIAN);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_returncode, tvb, offset + 32, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_compcode, tvb, offset + 36, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_reasoncode, tvb, offset + 40, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_uowcontrols, tvb, offset + 44, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_getwaitintv, tvb, offset + 48, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_linktype, tvb, offset + 52, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_outdatalen, tvb, offset + 56, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_facilkeeptime, tvb, offset + 60, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_adsdescriptor, tvb, offset + 64, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_converstask, tvb, offset + 68, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_taskendstatus, tvb, offset + 72, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_bridgefactokn, tvb, offset + 76, 8, ENC_NA);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_function, tvb, offset + 84, 4, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_abendcode, tvb, offset + 88, 4, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_authenticator, tvb, offset + 92, 8, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_reserved, tvb, offset + 100, 8, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_replytofmt, tvb, offset + 108, 8, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_remotesysid, tvb, offset + 116, 4, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_remotetransid, tvb, offset + 120, 4, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_transactionid, tvb, offset + 124, 4, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_facilitylike, tvb, offset + 128, 4, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_attentionid, tvb, offset + 132, 4, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_startcode, tvb, offset + 136, 4, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_cancelcode, tvb, offset + 140, 4, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_nexttransid, tvb, offset + 144, 4, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_reserved2, tvb, offset + 148, 8, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_reserved3, tvb, offset + 156, 8, p_mq_parm->mq_str_enc);
                                                if (iVer == 2)
                                                {
                                                    proto_tree_add_item(mq_tree, hf_mq_cih_cursorpos, tvb, offset + 164, 4, p_mq_parm->mq_int_enc);
                                                    proto_tree_add_item(mq_tree, hf_mq_cih_erroroffset, tvb, offset + 168, 4, p_mq_parm->mq_int_enc);
                                                    proto_tree_add_item(mq_tree, hf_mq_cih_inputitem, tvb, offset + 172, 4, p_mq_parm->mq_int_enc);
                                                    proto_tree_add_item(mq_tree, hf_mq_cih_reserved4, tvb, offset + 176, 4, p_mq_parm->mq_int_enc);
                                                }
                                            }
                                            else if (p_mq_parm->mq_strucID == MQ_STRUCTID_RMH || p_mq_parm->mq_strucID == MQ_STRUCTID_RMH_EBCDIC)
                                            {
                                                proto_tree_add_bitmask(mq_tree, tvb, offset + 28, hf_mq_head_flags, ett_mq_head_flags, pf_flds_rmh_flags, ENC_BIG_ENDIAN);
                                                proto_tree_add_item(mq_tree, hf_mq_rmh_objecttype, tvb, offset + 32, 8, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_rmh_objectinstid, tvb, offset + 36, 24, ENC_NA);
                                                proto_tree_add_item(mq_tree, hf_mq_rmh_srcenvlen, tvb, offset + 60, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_rmh_srcenvofs, tvb, offset + 64, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_rmh_srcnamelen, tvb, offset + 68, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_rmh_srcnameofs, tvb, offset + 72, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_rmh_dstenvlen, tvb, offset + 76, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_rmh_dstenvofs, tvb, offset + 80, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_rmh_dstnamelen, tvb, offset + 84, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_rmh_dstnameofs, tvb, offset + 88, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_rmh_datalogiclen, tvb, offset + 92, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_rmh_datalogicofsl, tvb, offset + 96, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_rmh_datalogicofsh, tvb, offset + 100, 4, p_mq_parm->mq_int_enc);
                                            }
                                            else if (p_mq_parm->mq_strucID == MQ_STRUCTID_WIH || p_mq_parm->mq_strucID == MQ_STRUCTID_WIH_EBCDIC)
                                            {
                                                proto_tree_add_item(mq_tree, hf_mq_head_flags, tvb, offset + 28, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_wih_servicename, tvb, offset + 32, 32, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_wih_servicestep, tvb, offset + 64, 8, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_wih_msgtoken, tvb, offset + 72, 16, ENC_NA);
                                                proto_tree_add_item(mq_tree, hf_mq_wih_reserved, tvb, offset + 88, 32, p_mq_parm->mq_str_enc);
                                            }
                                            else if (p_mq_parm->mq_strucID == MQ_STRUCTID_RFH || p_mq_parm->mq_strucID == MQ_STRUCTID_RFH_EBCDIC)
                                            {
                                                int iPos, iEnd, iCCSID;
                                                int iLenStr;
                                                uint8_t* sStr;

                                                proto_tree* rfh_tree;

                                                proto_tree_add_item(mq_tree, hf_mq_head_flags, tvb, offset + 28, 4, p_mq_parm->mq_int_enc);
                                                iPos = offset + 32;
                                                iEnd = offset + iLen;
                                                if (iVer > 1)
                                                {
                                                    iCCSID = (int)tvb_get_uint32(tvb, iPos, p_mq_parm->mq_int_enc);
                                                    proto_tree_add_item(mq_tree, hf_mq_rfh_ccsid, tvb, iPos, 4, p_mq_parm->mq_int_enc);
                                                    iPos += 4;
                                                }
                                                else
                                                    iCCSID = iTmp;

                                                while (iPos < iEnd)
                                                {
                                                    iLenStr = (int)tvb_get_uint32(tvb, iPos, p_mq_parm->mq_int_enc);
                                                    sStr = tvb_get_string_enc(wmem_packet_scope(), tvb, iPos + 4, iLenStr, IS_EBCDIC(iCCSID) ? ENC_EBCDIC : ENC_ASCII);
                                                    if (*sStr)
                                                        strip_trailing_blanks(sStr, iLenStr);
                                                    if (*sStr)
                                                        sStr = (uint8_t*)format_text_chr(wmem_packet_scope(), sStr, strlen((const char*)sStr), '.');

                                                    rfh_tree = proto_tree_add_subtree_format(mq_tree, tvb, iPos, iLenStr + 4, ett_mq_rfh_ValueName, NULL, "NameValue: %s", sStr);

                                                    proto_tree_add_item(rfh_tree, hf_mq_rfh_length, tvb, iPos, 4, p_mq_parm->mq_int_enc);
                                                    proto_tree_add_item(rfh_tree, hf_mq_rfh_string, tvb, iPos + 4, iLenStr, p_mq_parm->mq_str_enc);
                                                    iPos += (iLenStr + 4);
                                                }
                                            }
                                            else
                                            {
                                                proto_tree_add_item(mq_tree, hf_mq_head_flags, tvb, offset + 28, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_head_struct, tvb, offset + 32, iSizeHeader - 32, ENC_NA);
                                            }
                                        }
                                        offset += iSizeHeader;
                                        iHeadersLength += iSizeHeader;
                                        p_mq_parm->mq_strucID = (tvb_reported_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
                                        p_mq_parm->mq_str_enc = oStrEnc;
                                    }
                                    p_mq_parm->mq_int_enc = oIntEnc;
                                }
                            }

                            if (!mq_in_reassembly)
                            {
                                col_append_fstr(pinfo->cinfo, COL_INFO, " (Data %d bytes)", iSizePayload - iHeadersLength);

                                /* Call subdissector for the payload */
                                tvbuff_t* next_tvb;
                                p_mq_parm->mq_cur_ccsid.encod = tvb_get_uint32(tvb, p_mq_parm->iOfsEnc, p_mq_parm->mq_int_enc);
                                p_mq_parm->mq_cur_ccsid.ccsid = tvb_get_uint32(tvb, p_mq_parm->iOfsCcs, p_mq_parm->mq_int_enc);
                                memcpy(p_mq_parm->mq_format,
                                    tvb_get_string_enc(wmem_packet_scope(), tvb, p_mq_parm->iOfsFmt, sizeof(p_mq_parm->mq_format), p_mq_parm->mq_str_enc),
                                    sizeof(p_mq_parm->mq_format));

                                next_tvb = tvb_new_subset_remaining(tvb, offset);
                                if (!dissector_try_heuristic(mq_heur_subdissector_list, next_tvb, pinfo, mqroot_tree, &hdtbl_entry, p_mq_parm))
                                    call_data_dissector(next_tvb, pinfo, mqroot_tree);
                            }
                            else
                            {
                                tvbuff_t* next_tvb;
                                next_tvb = tvb_new_subset_remaining(tvb, offset);
                                call_data_dissector(next_tvb, pinfo, mqroot_tree);
                            }
                        }
                        offset = tvb_reported_length(tvb);
                    }
                    /* After all recognised structures have been dissected, process remaining structure*/
                    if (tvb_reported_length_remaining(tvb, offset) >= 4)
                    {
                        p_mq_parm->mq_strucID = tvb_get_ntohl(tvb, offset);
                        proto_tree_add_subtree_format(mqroot_tree, tvb, offset, -1, ett_mq_structid, NULL,
                            "%s", val_to_str_ext(p_mq_parm->mq_strucID, GET_VALS_EXTP(StructID), "Unknown (0x%08x)"));
                    }
                }
                else
                {
                    /* This is a MQ segment continuation (if MQ reassembly is not enabled) */
                    if (!mq_in_reassembly)
                        col_append_str(pinfo->cinfo, COL_INFO, " [Unreassembled MQ]");
                    call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo, (mqroot_tree) ? mqroot_tree : tree);
                }
            }
        }
        else
        {
            /* This packet is a TCP continuation of a segment (if desegmentation is not enabled) */
            col_append_str(pinfo->cinfo, COL_INFO, " [Undesegmented]");
            if (tree)
            {
                proto_tree_add_item(tree, proto_mq, tvb, offset, -1, ENC_NA);
            }
            call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo, tree);
        }
    }
}

static int reassemble_mq(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    mq_parm_t mq_parm;

    /* Reassembly of the MQ messages that span several PDU (several TSH) */
    /* Typically a TCP PDU is 1460 bytes and a MQ PDU is 32766 bytes */
    if (tvb_reported_length(tvb) < 28)
        return 0;

    memset(&mq_parm, 0, sizeof(mq_parm_t));
    mq_parm.mq_strucID = tvb_get_ntohl(tvb, 0);

    if ((mq_parm.mq_strucID & MQ_MASK_TSHx) == MQ_STRUCTID_TSHx || (mq_parm.mq_strucID & MQ_MASK_TSHx) == MQ_STRUCTID_TSHx_EBCDIC)
    {
        uint8_t  iCtlF = 0;
        int32_t  iSegL = 0;
        int32_t  iBegL = 0;
        int32_t  iEnco = 0;
        int32_t  iMulS = 0;
        int32_t  iHdrL = 0;
        int32_t  iNxtP = 0;
        uint8_t  iOpcd = 0;
        bool bSeg1st = false;
        bool bSegLst = false;
        bool bMore = false;

        int32_t  iHdl = 0;
        int32_t  iGlbMsgIdx = 0;
        int32_t  iSegLength = 0;
        int16_t  iSegmIndex = 0;

        uint32_t uStrL = 0;
        uint32_t uPadL = 0;

        /* TSHM structure as 8 bytes more after the length (convid/requestid) */
        if (mq_parm.mq_strucID == MQ_STRUCTID_TSHM || mq_parm.mq_strucID == MQ_STRUCTID_TSHM_EBCDIC)
            iMulS = 8;

        /* Get the Segment Length */
        iSegL = tvb_get_ntohl(tvb, 4);
        if (iMulS == 8)
        {
            mq_parm.mq_convID = tvb_get_ntohl(tvb, 8);
            mq_parm.mq_rqstID = tvb_get_ntohl(tvb, 12);
        }
        else
        {
            mq_parm.mq_convID = 0;
            mq_parm.mq_rqstID = 0;
        }

        /* Get the Encoding scheme */
        iEnco = (tvb_get_uint8(tvb, 8 + iMulS) == MQ_LITTLE_ENDIAN ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
        mq_parm.mq_int_enc = iEnco;
        /* Get the Operation Code */
        iOpcd = tvb_get_uint8(tvb, 9 + iMulS);
        mq_parm.mq_opcode = iOpcd;
        /* Get the Control Flag */
        iCtlF = tvb_get_uint8(tvb, 10 + iMulS);
        mq_parm.mq_ctlf1 = iCtlF;
        /* First Segment ? */
        bSeg1st = ((iCtlF & MQ_TCF_FIRST) != 0);
        /* Last Segment */
        bSegLst = ((iCtlF & MQ_TCF_LAST) != 0);

        mq_in_reassembly = false;

        if ((iOpcd > 0x80 && !(bSeg1st && bSegLst)) || iOpcd == MQ_TST_ASYNC_MESSAGE)
        {
            proto_tree* mq_tree = NULL;

            /* Optimisation : only fragmented segments go through the reassembly process */
            /*
              It seems that after a PUT on a Queue, when doing a GET, MQ first get
              a small part of the response (4096 bytes)
              The response contain the number of bytes returned for this request (ActMsgLen)
              and the total number of bytes of this reply    (TotMsgLen)

              this mean the flow seems to be :

              PUT
              REQUEST_MSG (MaxLen=4096)
              ASYNC_MSG (1st/Lst Segment, ActMsgLen=4096, TotMsgLen=279420)
              as ActMsgLen!=TotMsgLen, this mean the MSG is not complete, we only receive some of 279420 bytes
              REQUEST_MSG (MaxLen=279420)
              ASYNC_MSG (1st Segment, SegIndex=0 ActMsgLen=279420, TotMsgLen=279420)
              ASYNC_MSG (Mid Segment, SegIndex=1)
              ASYNC_MSG (Mid Segment, SegIndex=2)
              .
              ASYNC_MSG (Lst Segment, SegIndex=n)
              End of reassembling (we have 279420 bytes to decode)

              PUT with Reassembly
              GET with Reassembly not using ASYNC_MSG
            */

            if (mq_reassembly)
            {
                fragment_head* fd_head;
                uint32_t iConnectionId = ((pinfo->srcport << 16) + pinfo->destport);
                bool reassembly_error = false;
                uint8_t* pTmp = "Full";
                if (bSeg1st && !bSegLst)
                    pTmp = "First ";
                if (!bSeg1st && bSegLst)
                    pTmp = "Last  ";
                if (!bSeg1st && !bSegLst)
                    pTmp = "Middle";

                iHdrL = 28 + iMulS;

                if (iOpcd == MQ_TST_ASYNC_MESSAGE)
                {
                    /* Get the MQ Handle of the Object */
                    iHdl = tvb_get_uint32(tvb, iHdrL + 4, iEnco);
                    /* Get the Global Message Index */
                    iGlbMsgIdx = tvb_get_uint32(tvb, iHdrL + 12, iEnco);
                    /* Get the Segment Length */
                    iSegLength = tvb_get_uint32(tvb, iHdrL + 16, iEnco);
                    /* Get the Segment Index */
                    iSegmIndex = tvb_get_uint16(tvb, iHdrL + 20, iEnco);

                    /*
                      if SegmIndex == 0, it has 54 bytes + the length and padding
                      of a variable string at the end of the Header
                    */

                    if (iSegmIndex == 0)
                    {
                        mq_parm.mq_AsyMsgRsn = tvb_get_uint32(tvb, iHdrL + 24, iEnco);
                        mq_parm.mq_MsgActLen = tvb_get_uint32(tvb, iHdrL + 28, iEnco);
                        mq_parm.mq_MsgTotLen = tvb_get_uint32(tvb, iHdrL + 32, iEnco);
                        uStrL = tvb_get_uint8(tvb, iHdrL + 54);
                        uPadL = ((((2 + 1 + uStrL) / 4) + 1) * 4) - (2 + 1 + uStrL);
                        mq_parm.mq_MsgActLen = iSegL - iHdrL;
                    }
                    /*
                      First segment has a longer header
                    */
                    iNxtP = iHdrL + ((bSeg1st) ? (54 + 1 + uStrL + uPadL) : (24));
                    mq_parm.mq_MsgActLen -= ((bSeg1st) ? (54 + 1 + uStrL + uPadL) : (24));
                }
                else
                {
                    if (bSeg1st)
                    {
                        uStrL = mq_parm.mq_API_Len = tvb_get_uint32(tvb, iHdrL, ENC_BIG_ENDIAN);
                        mq_parm.mq_API_CC = tvb_get_uint32(tvb, iHdrL + 4, iEnco);
                        mq_parm.mq_API_RC = tvb_get_uint32(tvb, iHdrL + 8, iEnco);
                        iHdl = mq_parm.mq_API_Hdl = tvb_get_uint32(tvb, iHdrL + 12, iEnco);
                        mq_parm.mq_MsgTotLen = uStrL;
                        mq_parm.mq_MsgActLen = iSegL - iHdrL;
                        mq_parm.mq_MsgActLen -= 16; /* API */
                    }
                    else
                    {
                        fragment_head* _head = fragment_get_reassembled_id(&mq_reassembly_table, pinfo, iConnectionId);
                        if (_head)
                        {
                            uStrL = mq_parm.mq_API_Len = tvb_get_uint32(_head->tvb_data, iHdrL, ENC_BIG_ENDIAN);
                            mq_parm.mq_API_CC = tvb_get_uint32(_head->tvb_data, iHdrL + 4, iEnco);
                            mq_parm.mq_API_RC = tvb_get_uint32(_head->tvb_data, iHdrL + 8, iEnco);
                            iHdl = mq_parm.mq_API_Hdl = tvb_get_uint32(_head->tvb_data, iHdrL + 12, iEnco);
                            mq_parm.mq_MsgTotLen = uStrL;
                        }
                    }

                    iNxtP = iHdrL + ((bSeg1st) ? 16 : 0);
                }
                bMore = !bSegLst;
                /*
                  First segment has a longer header (API Header)

                  If it is a PUT1 Message Type TSHx + API + OD + MD + PMO
                  If it is a PUT  Message Type TSHx + API + MD + PMO
                  If it is a GET  Message Type TSHx + API + MD + GMO
                */
                if (bSeg1st)
                {
                    uint32_t _iLen;
                    if (iOpcd == MQ_TST_MQPUT1 || iOpcd == MQ_TST_MQPUT1_REPLY)
                    {
                        unsigned iDistributionListSize2;
                        _iLen = dissect_mq_od(tvb, NULL, NULL, iNxtP, &mq_parm, &iDistributionListSize2);
                        iNxtP += _iLen;
                        mq_parm.mq_MsgActLen -= _iLen;
                    }

                    _iLen = dissect_mq_md(tvb, NULL, iNxtP, &mq_parm, false);
                    iNxtP += _iLen;
                    mq_parm.mq_MsgActLen -= _iLen;

                    if (iOpcd == MQ_TST_MQGET || iOpcd == MQ_TST_MQGET_REPLY)
                        _iLen = dissect_mq_gmo(tvb, NULL, NULL, iNxtP, &mq_parm);
                    else
                        _iLen = dissect_mq_pmo(tvb, NULL, NULL, iNxtP, &mq_parm, NULL);
                    iNxtP += _iLen;
                    mq_parm.mq_MsgActLen -= _iLen;
                }

                /*
                  if it is the 1st Segment, it means we are
                  of the beginning of a reassembling. We must take the whole segment (with TSHM, and headers)
                */
                iBegL = (bSeg1st) ? 0 : iNxtP;

                if (iSegL <= iBegL)
                {
                    /* negative or null fragment length - something is wrong; skip reassembly */
                    fd_head = NULL;
                    reassembly_error = true;
                }
                else
                {
                    fd_head = fragment_add_seq_next(&mq_reassembly_table,
                        tvb, iBegL,
                        pinfo, iConnectionId, NULL,
                        iSegL - iBegL, bMore);
                }

                if (tree)
                {
                    proto_item* ti = proto_tree_add_item(tree, proto_mq, tvb, 0, -1, ENC_NA);

                    if (fd_head && !fd_head->next && mq_parm.mq_MsgActLen == mq_parm.mq_MsgTotLen)
                    {
                        proto_item_append_text(ti, " %s %s Segment",
                            val_to_str_ext(iOpcd, GET_VALS_EXTP(opcode), "Unknown (0x%02x)"),
                            pTmp);
                        if (mq_parm.mq_API_RC != MQ_MQRC_NONE)
                            proto_item_append_text(ti, ", Reason=%d(0x%x) - %s",
                                mq_parm.mq_API_RC, mq_parm.mq_API_RC,
                                val_to_str_ext(mq_parm.mq_API_RC, GET_VALS_EXTP(MQRC), "Unknown (0x%02x)"));
                    }
                    else
                    {
                        proto_item_append_text(ti, " [%s %s Segment]",
                            val_to_str_ext(iOpcd, GET_VALS_EXTP(opcode), "Unknown (0x%02x)"),
                            pTmp);
                    }
                    if (iOpcd == MQ_TST_ASYNC_MESSAGE)
                        proto_item_append_text(ti, ", Hdl=0x%04x, GlbMsgIdx=%d, SegIdx=%d, SegLen=%d",
                            iHdl, iGlbMsgIdx, iSegmIndex, iSegLength);
                    else
                        proto_item_append_text(ti, ", Hdl=0x%04x, Len=%d",
                            mq_parm.mq_API_Hdl, mq_parm.mq_MsgTotLen);
                    if (reassembly_error)
                    {
                        expert_add_info_format(pinfo, ti, &ei_mq_reassembly_error,
                            "Wrong fragment length (%d) - skipping reassembly", iSegL - iBegL);
                    }
                    mq_tree = proto_item_add_subtree(ti, ett_mq_reassemb);
                }
                else
                {
                    mq_tree = tree;
                }

                if (fd_head != NULL && pinfo->num == fd_head->reassembled_in && !bMore)
                {
                    tvbuff_t* next_tvb;

                    /* Reassembly finished */
                    if (fd_head->next != NULL)
                    {
                        proto_item* ti;

                        /* dissect the last(s) MQ segment received */
                        /* Reassembly in progress, so no decode */

                        mq_in_reassembly = true;
                        dissect_mq_pdu(tvb, pinfo, mq_tree);
                        mq_in_reassembly = false;

                        /*
                        2 or more fragments.
                        Build Up the full pdu to be dissected correwctly
                        */
                        next_tvb = tvb_new_chain(tvb, fd_head->tvb_data);
                        add_new_data_source(pinfo, next_tvb, "Reassembled MQ");

                        /* Create the tree element for the full reassembled MQ Msg */
                        ti = proto_tree_add_item(tree, proto_mq, tvb, 0, -1, ENC_NA);
                        proto_item_append_text(ti, " %s Full Segment",
                            val_to_str_ext(iOpcd, GET_VALS_EXTP(opcode), "Unknown (0x%02x)"));
                        if (iOpcd == MQ_TST_ASYNC_MESSAGE)
                        {
                            proto_item_append_text(ti, ", Hdl=0x%04x, GlbMsgIdx=%d, Len=%d",
                                iHdl, iGlbMsgIdx,
                                tvb_reported_length_remaining(next_tvb, 0));
                            if (mq_parm.mq_AsyMsgRsn != MQ_MQRC_NONE)
                                proto_item_append_text(ti, ", Reason=%d(0x%x) - %s",
                                    mq_parm.mq_AsyMsgRsn, mq_parm.mq_AsyMsgRsn,
                                    val_to_str_ext(mq_parm.mq_AsyMsgRsn, GET_VALS_EXTP(MQRC), "Unknown (0x%02x)"));
                        }
                        else
                        {
                            proto_item_append_text(ti, ", Hdl=0x%04x, Len=%d",
                                mq_parm.mq_API_Hdl,
                                tvb_reported_length_remaining(next_tvb, 0));
                            if (mq_parm.mq_API_RC != MQ_MQRC_NONE)
                                proto_item_append_text(ti, ", RC=%d(0x%x) - %s",
                                    mq_parm.mq_API_RC, mq_parm.mq_API_RC,
                                    val_to_str_ext(mq_parm.mq_API_RC, GET_VALS_EXTP(MQRC), "Unknown (0x%02x)"));
                        }
                        mq_tree = proto_item_add_subtree(ti, ett_mq_reassemb);
                    }
                    else
                    {
                        /* Only 1 fragment */
                        next_tvb = tvb;
                    }
                    dissect_mq_pdu(next_tvb, pinfo, mq_tree);
                    return tvb_reported_length(tvb);
                }
                else
                {
                    mq_in_reassembly = true;
                    /* Reassembly in progress */

                    col_add_fstr(pinfo->cinfo, COL_INFO, "[%s %s Segment]",
                        val_to_str_ext(iOpcd, GET_VALS_EXTP(opcode), "Unknown (0x%02x)"),
                        pTmp);
                    dissect_mq_addCR_colinfo(pinfo, &mq_parm);
                    if (iOpcd == MQ_TST_ASYNC_MESSAGE)
                        col_append_fstr(pinfo->cinfo, COL_INFO, " Hdl=0x%04x, GlbMsgIdx=%d, SegIdx=%d, SegLen=%d",
                            iHdl, iGlbMsgIdx, iSegmIndex, iSegLength);
                    else
                        col_append_fstr(pinfo->cinfo, COL_INFO, " Hdl=0x%04x, Len=%d",
                            mq_parm.mq_API_Hdl, mq_parm.mq_MsgTotLen);
                    dissect_mq_pdu(tvb, pinfo, mq_tree);
                    return tvb_reported_length(tvb);
                }
            }
            else
            {
                dissect_mq_pdu(tvb, pinfo, tree);
                if (bSeg1st)
                {
                    /* MQ segment is the first of a unreassembled series */
                    col_append_str(pinfo->cinfo, COL_INFO, " [Unreassembled MQ]");
                }
                return tvb_reported_length(tvb);
            }
        }
        /* Reassembly not enabled or non-fragmented message */
        dissect_mq_pdu(tvb, pinfo, tree);
    }

    return tvb_reported_length(tvb);
}

static unsigned get_mq_pdu_len(packet_info* pinfo _U_, tvbuff_t* tvb,
    int offset, void* data _U_)
{
    unsigned uLen = tvb_reported_length_remaining(tvb, offset);
    if (uLen >= 8)
    {
        uint32_t mq_strucID = tvb_get_ntohl(tvb, offset + 0);
        if ((mq_strucID & MQ_MASK_TSHx) == MQ_STRUCTID_TSHx || (mq_strucID & MQ_MASK_TSHx) == MQ_STRUCTID_TSHx_EBCDIC)
        {
            uLen = tvb_get_ntohl(tvb, offset + 4);
        }
    }
    return uLen;
}

static int dissect_mq_tcp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, mq_desegment, 28, get_mq_pdu_len, reassemble_mq, data);
    return tvb_captured_length(tvb);
}

static int dissect_mq_spx(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    /* Since SPX has no standard desegmentation, MQ cannot be performed as well */
    dissect_mq_pdu(tvb, pinfo, tree);
    return tvb_captured_length(tvb);
}

static bool dissect_mq_heur(tvbuff_t* tvb, packet_info* pinfo,
    proto_tree* tree, bool is_tcp, dissector_handle_t* ssl_app_handle)
{
    if ((tvb_captured_length(tvb) >= 4) && (tvb_reported_length(tvb) >= 28))
    {
        uint32_t mq_strucID = tvb_get_ntohl(tvb, 0);
        if ((mq_strucID & MQ_MASK_TSHx) == MQ_STRUCTID_TSHx || (mq_strucID & MQ_MASK_TSHx) == MQ_STRUCTID_TSHx_EBCDIC)
        {
            /* Register this dissector for this conversation */
            conversation_t* conversation;

            conversation = find_or_create_conversation(pinfo);
            if (is_tcp)
                conversation_set_dissector(conversation, mq_handle);
            else if (ssl_app_handle)
                *ssl_app_handle = mq_handle;

            /* Dissect the packet */
            reassemble_mq(tvb, pinfo, tree, NULL);
            return true;
        }
    }
    return false;
}

static bool    dissect_mq_heur_tcp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    return dissect_mq_heur(tvb, pinfo, tree, true, NULL);
}

static bool    dissect_mq_heur_nontcp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    return dissect_mq_heur(tvb, pinfo, tree, false, NULL);
}

static bool    dissect_mq_heur_ssl(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{
    struct tlsinfo *tlsinfo = (struct tlsinfo*)data;
    return dissect_mq_heur(tvb, pinfo, tree, false, tlsinfo->app_handle);
}

void proto_register_mq(void)
{
    static hf_register_info hf[] =
    {
        {&hf_mq_tsh_StructID, {"StructID..", "mq.tsh.structid", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_mq_tsh_mqseglen, {"MQSegmLen.", "mq.tsh.seglength", FT_UINT32, BASE_DEC, NULL, 0x0, "TSH MQ Segment length", HFILL}},
        {&hf_mq_tsh_convid, {"Convers ID", "mq.tsh.convid", FT_UINT32, BASE_DEC, NULL, 0x0, "TSH Conversation ID", HFILL}},
        {&hf_mq_tsh_requestid, {"Request ID", "mq.tsh.requestid", FT_UINT32, BASE_DEC, NULL, 0x0, "TSH Request ID", HFILL}},
        {&hf_mq_tsh_byteorder, {"Byte order", "mq.tsh.byteorder", FT_UINT8, BASE_HEX, VALS(GET_VALSV(byteorder)), 0x0, "TSH Byte order", HFILL}},
        {&hf_mq_tsh_opcode, {"SegmType..", "mq.tsh.type", FT_UINT8, BASE_HEX | BASE_EXT_STRING, GET_VALS_EXTP(opcode), 0x0, "TSH MQ segment type", HFILL}},
        {&hf_mq_tsh_ctlflgs1, {"Ctl Flag 1", "mq.tsh.cflags1", FT_UINT8, BASE_HEX, NULL, 0x0, "TSH Control flags 1", HFILL}},
        {&hf_mq_tsh_ctlflgs2, {"Ctl Flag 2", "mq.tsh.cflags2", FT_UINT8, BASE_HEX, NULL, 0x0, "TSH Control flags 2", HFILL}},
        {&hf_mq_tsh_luwid, {"LUW Ident.", "mq.tsh.luwid", FT_BYTES, BASE_NONE, NULL, 0x0, "TSH logical unit of work identifier", HFILL}},
        {&hf_mq_tsh_encoding, {"Encoding..", "mq.tsh.encoding", FT_UINT32, BASE_DEC, NULL, 0x0, "TSH Encoding", HFILL}},
        {&hf_mq_tsh_ccsid, {"CCSID.....", "mq.tsh.ccsid", FT_INT16, BASE_DEC | BASE_RANGE_STRING, RVALS(GET_VALRV(ccsid)), 0x0, "TSH CCSID", HFILL}},
        {&hf_mq_tsh_reserved, {"Reserved..", "mq.tsh.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, "TSH Reserved", HFILL}},

        {&hf_mq_tsh_tcf_confirmreq, {"Confirm Req", "mq.tsh.tcf.confirmreq", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_TCF_CONFIRM_REQUEST, "TSH TCF Confirm request", HFILL}},
        {&hf_mq_tsh_tcf_error, {"Error", "mq.tsh.tcf.error", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_TCF_ERROR, "TSH TCF Error", HFILL}},
        {&hf_mq_tsh_tcf_reqclose, {"Req close", "mq.tsh.tcf.reqclose", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_TCF_REQUEST_CLOSE, "TSH TCF Request close", HFILL}},
        {&hf_mq_tsh_tcf_closechann, {"Close Chnl", "mq.tsh.tcf.closechann", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_TCF_CLOSE_CHANNEL, "TSH TCF Close channel", HFILL}},
        {&hf_mq_tsh_tcf_first, {"First Seg", "mq.tsh.tcf.first", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_TCF_FIRST, "TSH TCF First", HFILL}},
        {&hf_mq_tsh_tcf_last, {"Last Seg", "mq.tsh.tcf.last", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_TCF_LAST, "TSH TCF Last", HFILL}},
        {&hf_mq_tsh_tcf_reqacc, {"Req accept", "mq.tsh.tcf.reqacc", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_TCF_REQUEST_ACCEPTED, "TSH TCF Request accepted", HFILL}},
        {&hf_mq_tsh_tcf_dlq, {"DLQ used", "mq.tsh.tcf.dlq", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_TCF_DLQ_USED, "TSH TCF DLQ used", HFILL}},

        {&hf_mq_tsh_tcf2_HdrComp, {"HDR Comp", "mq.tsh.tcf2.hdrcomp", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_TCF2_HDRCOMP, "TSH TCF2 Header Compressed", HFILL}},
        {&hf_mq_tsh_tcf2_MsgComp, {"MSG Comp", "mq.tsh.tcf2.msgcomp", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_TCF2_MSGCOMP, "TSH TCF2 Message Compressed", HFILL}},
        {&hf_mq_tsh_tcf2_CSH, {"CSH", "mq.tsh.tcf2.csh", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_TCF2_CSH, "TSH TCF2 CSH", HFILL}},
        {&hf_mq_tsh_tcf2_CmitIntv, {"CommitIntvl", "mq.tsh.tcf.cmitintv", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_TCF2_CMIT_INTERVAL, "TSH TCF2 Commit Interval", HFILL}},

        {&hf_mq_api_replylen, {"Reply len..", "mq.api.replylength", FT_UINT32, BASE_DEC, NULL, 0x0, "API Reply length", HFILL}},
        {&hf_mq_api_compcode, {"Compl Code.", "mq.api.completioncode", FT_UINT32, BASE_DEC, VALS(GET_VALSV(mqcc)), 0x0, "API Completion code", HFILL}},
        {&hf_mq_api_reascode, {"Reason Code", "mq.api.reasoncode", FT_UINT32, BASE_DEC | BASE_EXT_STRING, GET_VALS_EXTP(MQRC), 0x0, "API Reason code", HFILL}},
        {&hf_mq_api_objecthdl, {"Object Hdl.", "mq.api.hobj", FT_UINT32, BASE_HEX, NULL, 0x0, "API Object handle", HFILL}},

        {&hf_mq_socket_conversid, {"ConversId", "mq.socket.conversid", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "Socket Conversation Id", HFILL}},
        {&hf_mq_socket_requestid, {"RequestId", "mq.socket.requestid", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "Socket Request Id", HFILL}},
        {&hf_mq_socket_type, {"Type.....", "mq.socket.type", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "Socket Type", HFILL}},
        {&hf_mq_socket_parm1, {"Parm1....", "mq.socket.parm1", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "Socket Parameter 1", HFILL}},
        {&hf_mq_socket_parm2, {"Parm2....", "mq.socket.parm2", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "Socket Parameter 2", HFILL}},

        {&hf_mq_caut_StructID, {"StructID.", "mq.caut.structid", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_mq_caut_AuthType, {"AuthType.", "mq.caut.authtype", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "CAUT Authority Type", HFILL}},
        {&hf_mq_caut_UsrMaxLen, {"UsrMaxLen", "mq.caut.usrmaxlen", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "CAUT userid Maximum length", HFILL}},
        {&hf_mq_caut_PwdMaxLen, {"PwdMaxLen", "mq.caut.pwdmaxlen", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "CAUT password Maximum length", HFILL}},
        {&hf_mq_caut_UsrLength, {"UsrLength", "mq.caut.usrlength", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "CAUT userid length", HFILL}},
        {&hf_mq_caut_PwdLength, {"PwdLength", "mq.caut.pswlength", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "CAUT password length", HFILL}},
        {&hf_mq_caut_usr, {"userid...", "mq.msh.userid", FT_STRING, BASE_NONE, NULL, 0x0, "CAUT UserId", HFILL}},
        {&hf_mq_caut_psw, {"password.", "mq.msh.password", FT_STRING, BASE_NONE, NULL, 0x0, "CAUT Password", HFILL}},

        {&hf_mq_msh_StructID, {"StructID", "mq.msh.structid", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_mq_msh_seqnum, {"Seq Numb", "mq.msh.seqnum", FT_UINT32, BASE_DEC, NULL, 0x0, "MSH sequence number", HFILL}},
        {&hf_mq_msh_datalength, {"Buf len.", "mq.msh.buflength", FT_UINT32, BASE_DEC, NULL, 0x0, "MSH buffer length", HFILL}},
        {&hf_mq_msh_unknown1, {"Unknown1", "mq.msh.unknown1", FT_UINT32, BASE_HEX, NULL, 0x0, "MSH unknown1", HFILL}},
        {&hf_mq_msh_msglength, {"Msg len.", "mq.msh.msglength", FT_UINT32, BASE_DEC, NULL, 0x0, "MSH message length", HFILL}},

        {&hf_mq_xqh_StructID, {"StructID", "mq.xqh.structid", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_mq_xqh_version, {"Version.", "mq.xqh.version", FT_UINT32, BASE_DEC, NULL, 0x0, "XQH version", HFILL}},
        {&hf_mq_xqh_remoteq, {"Remote Q", "mq.xqh.remoteq", FT_STRING, BASE_NONE, NULL, 0x0, "XQH remote queue", HFILL}},
        {&hf_mq_xqh_remoteqmgr, {"Rmt QMgr", "mq.xqh.remoteqmgr", FT_STRING, BASE_NONE, NULL, 0x0, "XQH remote queue manager", HFILL}},

        {&hf_mq_id_StructID, {"Structid..", "mq.id.structid", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_mq_id_FapLevel, {"FAP level.", "mq.id.faplevel", FT_UINT8, BASE_DEC, NULL, 0x0, "ID Formats And Protocols level", HFILL}},
        {&hf_mq_id_cf1, {"CapFlag1..", "mq.id.cflags", FT_UINT8, BASE_HEX, NULL, 0x0, "ID Capability Flags 1", HFILL}},
        {&hf_mq_id_ecf1, {"ECapFlag1.", "mq.id.ecflags", FT_UINT8, BASE_HEX, NULL, 0x0, "ID E Capability Flags 1", HFILL}},
        {&hf_mq_id_ief1, {"IniErrFlg1", "mq.id.inierrflg1", FT_UINT8, BASE_HEX, NULL, 0x0, "ID Initial Error Flags 1", HFILL}},
        {&hf_mq_id_Reserved, {"Reserved..", "mq.id.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, "ID Reserved", HFILL}},
        {&hf_mq_id_MaxMsgBatch, {"MaxMsgBtch", "mq.id.maxmsgbatch", FT_UINT16, BASE_DEC, NULL, 0x0, "ID max msg per batch", HFILL}},
        {&hf_mq_id_MaxTrSize, {"MaxTrSize.", "mq.id.maxtrsize", FT_UINT32, BASE_DEC, NULL, 0x0, "ID max trans size", HFILL}},
        {&hf_mq_id_MaxMsgSize, {"MaxMsgSize", "mq.id.maxmsgsize", FT_UINT32, BASE_DEC, NULL, 0x0, "ID max msg size", HFILL}},
        {&hf_mq_id_SeqWrapVal, {"SeqWrapVal", "mq.id.seqwrap", FT_UINT32, BASE_DEC, NULL, 0x0, "ID seq wrap value", HFILL}},
        {&hf_mq_id_channel, {"ChannelNme", "mq.id.channelname", FT_STRING, BASE_NONE, NULL, 0x0, "ID channel name", HFILL}},
        {&hf_mq_id_cf2, {"CapFlag2..", "mq.id.cflags2", FT_UINT8, BASE_HEX, NULL, 0x0, "ID Capability flags 2", HFILL}},
        {&hf_mq_id_ecf2, {"ECapFlag2.", "mq.id.ecflags2", FT_UINT8, BASE_HEX, NULL, 0x0, "ID E Capability flags 2", HFILL}},
        {&hf_mq_id_ccsid, {"ccsid.....", "mq.id.ccsid", FT_INT16, BASE_DEC | BASE_RANGE_STRING, RVALS(GET_VALRV(ccsid)), 0x0, "ID Coded Character Set ID", HFILL}},
        {&hf_mq_id_qmgrname, {"QMgrName..", "mq.id.qm", FT_STRING, BASE_NONE, NULL, 0x0, "ID Queue Manager Name", HFILL}},
        {&hf_mq_id_HBInterval, {"HBInterval", "mq.id.hbint", FT_UINT32, BASE_DEC, NULL, 0x0, "ID Heartbeat interval", HFILL}},
        {&hf_mq_id_EFLLength, {"EFLLength.", "mq.id.efllength", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, "ID EFL Length", HFILL}},
        {&hf_mq_id_ief2, {"IniErrFlg2", "mq.id.inierrflg2", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, "ID Initial Error Flags 2", HFILL}},
        {&hf_mq_id_Reserved1, {"Reserved1.", "mq.id.reserved1", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, "ID Reserved 1", HFILL}},
        {&hf_mq_id_HdrCprsLst, {"HdrCprsLst", "mq.id.hdrcprslst", FT_BYTES, BASE_NONE, NULL, 0x0, "ID Hdr Cprs Lst", HFILL}},
        {&hf_mq_id_MsgCprsLst, {"MsgCprsLst", "mq.id.msgcprslst", FT_BYTES, BASE_NONE, NULL, 0x0, "ID Msg Cprs Lst", HFILL}},
        {&hf_mq_id_Reserved2, {"Reserved2.", "mq.id.reserved2", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, "ID Reserved 2", HFILL}},
        {&hf_mq_id_SSLKeyRst, {"SSLKeyRst.", "mq.id.sslkeyrst", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "ID SSL Key Reset", HFILL}},
        {&hf_mq_id_ConvBySkt, {"ConvBySkt.", "mq.id.convbyskt", FT_INT32, BASE_DEC, NULL, 0x0, "ID Conv Per Socket", HFILL}},
        {&hf_mq_id_cf3, {"CapFlag3..", "mq.id.cflags3", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, "ID Capability flags 3", HFILL}},
        {&hf_mq_id_ecf3, {"ECapFlag3.", "mq.id.ecflags3", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, "ID E Capability flags 3", HFILL}},
        {&hf_mq_id_Reserved3, {"Reserved3.", "mq.id.reserved3", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, "ID Reserved 3", HFILL}},
        {&hf_mq_id_ProcessId, {"ProcessId.", "mq.id.processid", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "ID Process Identifier", HFILL}},
        {&hf_mq_id_ThreadId, {"ThreadId..", "mq.id.threadid", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "ID Thread Identifier", HFILL}},
        {&hf_mq_id_TraceId, {"TraceId...", "mq.id.traceid", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "ID Trace Identifier", HFILL}},
        {&hf_mq_id_ProdId, {"ProdId....", "mq.id.prodid", FT_STRING, BASE_NONE, NULL, 0x0, "ID Product Identifier", HFILL}},
        {&hf_mq_id_mqmid, {"MQM ID....", "mq.id.mqmid", FT_STRING, BASE_NONE, NULL, 0x0, "ID MQM ID", HFILL}},
        {&hf_mq_id_pal, {"PAL.......", "mq.id.pal", FT_BYTES, BASE_NONE, NULL, 0x0, "ID PAL", HFILL}},
        {&hf_mq_id_r, {"R.........", "mq.id.r", FT_BYTES, BASE_NONE, NULL, 0x0, "ID R", HFILL}},

        {&hf_mq_id_cf1_msgseq, {"Message sequence", "mq.id.icf.msgseq", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_CF1_MSG_SEQ, "ID ICF Message sequence", HFILL}},
        {&hf_mq_id_cf1_convcap, {"Conversion capable", "mq.id.icf.convcap", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_CF1_CONVERSION_CAPABLE, "ID ICF Conversion capable", HFILL}},
        {&hf_mq_id_cf1_splitmsg, {"Split messages", "mq.id.icf.splitmsg", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_CF1_SPLIT_MESSAGE, "ID ICF Split message", HFILL}},
        {&hf_mq_id_cf1_RqstInit, {"Request Initiation", "mq.id.icf.rqstinit", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_CF1_REQUEST_INITIATION, "ID ICF Request Initiation", HFILL}},
        {&hf_mq_id_cf1_RqstSecu, {"Request Security", "mq.id.icf.rqstsecu", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_CF1_REQUEST_SECURITY, "ID ICF Request Security", HFILL}},
        {&hf_mq_id_cf1_mqreq, {"MQ request", "mq.id.icf.mqreq", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_CF1_MQREQUEST, "ID ICF MQ request", HFILL}},
        {&hf_mq_id_cf1_svrsec, {"Srvr Con security", "mq.id.icf.svrsec", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_CF1_SVRCONN_SECURITY, "ID ICF Server connection security", HFILL}},
        {&hf_mq_id_cf1_runtime, {"Runtime applic", "mq.id.icf.runtime", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_CF1_RUNTIME, "ID ICF Runtime application", HFILL}},

        {&hf_mq_id_cf2_CanDstLst, {"DistListCapable", "mq.id.icf2.distlistcap", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_CF2_DIST_LIST_CAPABLE, "ID ICF2 Distribution List Capable", HFILL}},
        {&hf_mq_id_cf2_FstMsgReq, {"Fast Msg Reqrd", "mq.id.icf2.fastmsgrqrd", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_CF2_FAST_MESSAGES_REQUIRED, "ID ICF2 Fast Message Required", HFILL}},
        {&hf_mq_id_cf2_RespConv, {"RspndrConversion", "mq.id.icf2.respndrconvers", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_CF2_RESPONDER_CONVERSION, "ID ICF2 Responder Conversion", HFILL}},
        {&hf_mq_id_cf2_XARequest, {"XARequest", "mq.id.icf2.xarequest", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_CF2_XAREQUEST, "ID ICF2 XA Request", HFILL}},
        {&hf_mq_id_cf2_XARunTApp, {"XARunTypApp", "mq.id.icf2.xaruntypapp", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_CF2_XARUNTIME_APP, "ID ICF2 XA Runtime App", HFILL}},
        {&hf_mq_id_cf2_SPIRqst, {"SPIRequest", "mq.id.icf2.spirequest", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_CF2_SPIREQUEST, "ID ICF2 SPI Request", HFILL}},
        {&hf_mq_id_cf2_DualUOW, {"DualUOW", "mq.id.icf2.dualuow", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_CF2_DUAL_UOW, "ID ICF2 Dual UOW", HFILL}},
        {&hf_mq_id_cf2_CanTrcRte, {"Trace Rte Capab", "mq.id.icf2.cantraceroute", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_CF2_TRACE_ROUTE_CAPABLE, "ID ICF2 Trace Route Capable", HFILL}},

        {&hf_mq_id_cf3_CanMsgPrp, {"Msg Property Cap", "mq.id.ief3.msgpropertycap", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_CF3_MSG_PROP_CAPABLE, "ID ICF3 Message PropertyCapable", HFILL}},
        {&hf_mq_id_cf3_CanMulticast, {"Multicast Cap", "mq.id.ief3.multicastcap", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_CF3_MULTICAST_CAPABLE, "ID ICF3 Mutlicast Capabilities", HFILL}},
        {&hf_mq_id_cf3_PropIntSep, {"Prop Int Separate", "mq.id.ief3.propintseparate", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_CF3_MSG_PROP_INT_SEPARATE, "ID ICF3 Property Int Separate", HFILL}},
        {&hf_mq_id_cf3_MPlxSyGet, {"Multiplex_synchget", "mq.id.ief3.multiplexsynchget", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_CF3_MULTIPLEX_SYNCGET, "ID ICF3 MULTIPLEX_SYNCGET", HFILL}},
        {&hf_mq_id_cf3_ProtAlgorit, {"Prot Algorithms", "mq.id.ief3.protalgorithms", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_CF3_PROT_ALGORITHMS, "ID ICF3 Prot Algorithms", HFILL}},
        {&hf_mq_id_cf3_CanGenConnTag, {"Gen ConnTag Cap", "mq.id.ief3.genconntagcap", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_CF3_GEN_CONNTAG_CAP, "ID ICF3 Generate ConnTag Capable", HFILL}},

        {&hf_mq_id_ief1_ccsid, {"Invalid CCSID", "mq.id.ief1.ccsid", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_IEF1_CCSID_NOT_SUPPORTED, "ID invalid CCSID", HFILL}},
        {&hf_mq_id_ief1_enc, {"Invalid encoding", "mq.id.ief1.enc", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_IEF1_ENCODING_INVALID, "ID invalid encoding", HFILL}},
        {&hf_mq_id_ief1_mxtrsz, {"Invalid Max Trans Size", "mq.id.ief1.mxtrsz", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_IEF1_MAX_TRANSMISSION_SIZE, "ID invalid maximum transmission size", HFILL}},
        {&hf_mq_id_ief1_fap, {"Invalid FAP level", "mq.id.ief1.fap", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_IEF1_FAP_LEVEL, "ID invalid FAP level", HFILL}},
        {&hf_mq_id_ief1_mxmsgsz, {"Invalid message size", "mq.id.ief1.mxmsgsz", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_IEF1_MAX_MSG_SIZE, "ID invalid message size", HFILL}},
        {&hf_mq_id_ief1_mxmsgpb, {"Invalid Max Msg batch", "mq.id.ief1.mxmsgpb", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_IEF1_MAX_MSG_PER_BATCH, "ID maximum message per batch", HFILL}},
        {&hf_mq_id_ief1_seqwrap, {"Invalid Seq Wrap Value", "mq.id.ief1.seqwrap", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_IEF1_SEQ_WRAP_VALUE, "ID invalid sequence wrap value", HFILL}},
        {&hf_mq_id_ief1_hbint, {"Invalid HB interval", "mq.id.ief1.hbint", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_IEF1_HEARTBEAT_INTERVAL, "ID invalid heartbeat interval", HFILL}},

        {&hf_mq_id_ief2_HdrCmpLst, {"Invalid HDR CompLst", "mq.id.ief2.hdrcomplst", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_IEF2_HDRCOMPLIST, "ID invalid Header Compression List", HFILL}},
        {&hf_mq_id_ief2_MsgCmpLst, {"Invalid Msg CompLst", "mq.id.ief2.msgcomplst", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_IEF2_MSGCOMPLIST, "ID invalid Message Compression List", HFILL}},
        {&hf_mq_id_ief2_SSLReset, {"Invalid SSL Reset", "mq.id.ief2.sslreset", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_IEF2_SSL_RESET, "ID invalid SSL Reset", HFILL}},

        {&hf_mq_uid_StructID, {"Structid", "mq.uid.structid", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_mq_uid_userid, {"User ID.", "mq.uid.userid", FT_STRING, BASE_NONE, NULL, 0x0, "UID structid", HFILL}},
        {&hf_mq_uid_password, {"Password", "mq.uid.password", FT_STRING, BASE_NONE, NULL, 0x0, "UID password", HFILL}},
        {&hf_mq_uid_longuserid, {"Long UID", "mq.uid.longuserid", FT_STRING, BASE_NONE, NULL, 0x0, "UID long user id", HFILL}},

        {&hf_mq_sidlen, {"SID Len.", "mq.uid.sidlen", FT_UINT8, BASE_DEC, NULL, 0x0, "Sid Len", HFILL}},
        {&hf_mq_sidtyp, {"SIDType.", "mq.uid.sidtyp", FT_UINT8, BASE_DEC, VALS(GET_VALSV(sidtype)), 0x0, "Sid Typ", HFILL}},
        {&hf_mq_securityid, {"SecurID.", "mq.uid.securityid", FT_BYTES, BASE_NONE, NULL, 0x0, "Security ID", HFILL}},

        {&hf_mq_conn_QMgr, {"QMgr....", "mq.conn.qm", FT_STRING, BASE_NONE, NULL, 0x0, "CONN queue manager", HFILL}},
        {&hf_mq_conn_appname, {"ApplName", "mq.conn.appname", FT_STRING, BASE_NONE, NULL, 0x0, "CONN application name", HFILL}},
        {&hf_mq_conn_apptype, {"ApplType", "mq.conn.apptype", FT_INT32, BASE_DEC | BASE_EXT_STRING, GET_VALS_EXTP(MQAT), 0x0, "CONN application type", HFILL}},
        {&hf_mq_conn_acttoken, {"AccntTok", "mq.conn.acttoken", FT_BYTES, BASE_NONE, NULL, 0x0, "CONN accounting token", HFILL}},
        {&hf_mq_conn_options, {"Options.", "mq.conn.options", FT_UINT32, BASE_DEC, VALS(mq_conn_options_vals), 0x0, "CONN options", HFILL}},
        {&hf_mq_conn_Xoptions, {"XOptions", "mq.conn.xoptions", FT_UINT32, BASE_HEX, NULL, 0x0, "CONN Xoptions", HFILL}},

        {&hf_mq_fcno_StructID, {"StructId..", "mq.fcno.structid", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_mq_fcno_version, {"version...", "mq.fcno.version", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "FCNO version", HFILL}},
        {&hf_mq_fcno_capflag, {"CapFlag...", "mq.fcno.capflag", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "FCNO Capability Flag", HFILL}},

        {&hf_mq_fcno_prodid, {"prodid....", "mq.fcno.prodid", FT_STRING, BASE_NONE, NULL, 0x0, "FCNO Product Id", HFILL}},
        {&hf_mq_fcno_mqmid, {"MqmId.....", "mq.fcno.mqmid", FT_STRING, BASE_NONE, NULL, 0x0, "FCNO Mqm ID", HFILL}},

        {&hf_mq_fcno_conn_tag, {"conntag...", "mq.fcno.conntag", FT_BYTES, BASE_NONE, NULL, 0x0, "FCNO Connection Tag", HFILL}},
        {&hf_mq_fcno_retconn_tag, {"retconntag", "mq.fcno.retconntag", FT_BYTES, BASE_NONE, NULL, 0x0, "FCNO Retry Connection Tag", HFILL}},
        {&hf_mq_fcno_unknowb01, {"unknowb01.", "mq.fcno.unknowb01", FT_BYTES, BASE_NONE, NULL, 0x0, "FCNO unknown bytes 01", HFILL}},


        {&hf_mq_inq_nbsel, {"Selector count..", "mq.inq.nbsel", FT_UINT32, BASE_DEC, NULL, 0x0, "INQ Selector count", HFILL}},
        {&hf_mq_inq_nbint, {"Integer count...", "mq.inq.nbint", FT_UINT32, BASE_DEC, NULL, 0x0, "INQ Integer count", HFILL}},
        {&hf_mq_inq_charlen, {"Character length", "mq.inq.charlen", FT_UINT32, BASE_DEC, NULL, 0x0, "INQ Character length", HFILL}},
        {&hf_mq_inq_sel, {"Selector........", "mq.inq.sel", FT_UINT32, BASE_DEC | BASE_EXT_STRING, GET_VALS_EXTP(selector), 0x0, "INQ Selector", HFILL}},
        {&hf_mq_inq_intvalue, {"Integer value...", "mq.inq.intvalue", FT_UINT32, BASE_DEC, NULL, 0x0, "INQ Integer value", HFILL}},
        {&hf_mq_inq_charvalues, {"Char values.....", "mq.inq.charvalues", FT_STRING, BASE_NONE, NULL, 0x0, "INQ Character values", HFILL}},

        {&hf_mq_spi_verb, {"SPI Verb", "mq.spi.verb", FT_UINT32, BASE_DEC, VALS(GET_VALSV(spi_verbs)), 0x0, NULL, HFILL}},
        {&hf_mq_spi_version, {"Version", "mq.spi.version", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Version", HFILL}},
        {&hf_mq_spi_length, {"Max reply size", "mq.spi.replength", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Max reply size", HFILL}},

        {&hf_mq_spi_base_StructID, {"SPI Structid", "mq.spib.structid", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_mq_spi_base_version, {"Version", "mq.spib.version", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Base Version", HFILL}},
        {&hf_mq_spi_base_length, {"Length", "mq.spib.length", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Base Length", HFILL}},

        {&hf_mq_spi_spqo_nbverb, {"Number of verbs", "mq.spqo.nbverb", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Query Output Number of verbs", HFILL}},
        {&hf_mq_spi_spqo_verbid, {"Verb", "mq.spqo.verb", FT_UINT32, BASE_DEC, VALS(GET_VALSV(spi_verbs)), 0x0, "SPI Query Output VerbId", HFILL}},
        {&hf_mq_spi_spqo_maxiover, {"Max InOut Version", "mq.spqo.maxiov", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Query Output Max InOut Version", HFILL}},
        {&hf_mq_spi_spqo_maxinver, {"Max In Version", "mq.spqo.maxiv", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Query Output Max In Version", HFILL}},
        {&hf_mq_spi_spqo_maxouver, {"Max Out Version", "mq.spqo.maxov", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Query Output Max Out Version", HFILL}},
        {&hf_mq_spi_spqo_flags, {"Flags", "mq.spqo.flags", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Query Output flags", HFILL}},

        {&hf_mq_spi_spai_mode, {"Mode", "mq.spai.mode", FT_UINT32, BASE_DEC, VALS(GET_VALSV(spi_activate)), 0x0, "SPI Activate Input mode", HFILL}},
        {&hf_mq_spi_spai_unknown1, {"Unknown1", "mq.spai.unknown1", FT_STRING, BASE_NONE, NULL, 0x0, "SPI Activate Input unknown1", HFILL}},
        {&hf_mq_spi_spai_unknown2, {"Unknown2", "mq.spai.unknown2", FT_STRING, BASE_NONE, NULL, 0x0, "SPI Activate Input unknown2", HFILL}},
        {&hf_mq_spi_spai_msgid, {"Message Id", "mq.spai.msgid", FT_STRING, BASE_NONE, NULL, 0x0, "SPI Activate Input message id", HFILL}},
        {&hf_mq_spi_spgi_batchsz, {"Batch size", "mq.spgi.batchsize", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Get Input batch size", HFILL}},
        {&hf_mq_spi_spgi_batchint, {"Batch interval", "mq.spgi.batchint", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Get Input batch interval", HFILL}},
        {&hf_mq_spi_spgi_maxmsgsz, {"Max message size", "mq.spgi.maxmsgsize", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Get Input max message size", HFILL}},

        {&hf_mq_spi_spgo_options, {"Options", "mq.spgo.options", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Get Output options", HFILL}},
        {&hf_mq_spi_spgo_size, {"Size", "mq.spgo.size", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Get Output size", HFILL}},
        {&hf_mq_spi_opt_blank, {"Blank padded", "mq.spi.options.blank", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_SPI_OPTIONS_BLANK_PADDED, "SPI Options blank padded", HFILL}},
        {&hf_mq_spi_opt_syncp, {"Syncpoint", "mq.spi.options.sync", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_SPI_OPTIONS_SYNCPOINT, "SPI Options syncpoint", HFILL}},
        {&hf_mq_spi_opt_deferred, {"Deferred", "mq.spi.options.deferred", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_SPI_OPTIONS_DEFERRED, "SPI Options deferred", HFILL}},

        {&hf_mq_put_length, {"Data length", "mq.put.length", FT_UINT32, BASE_DEC, NULL, 0x0, "PUT Data length", HFILL}},

        {&hf_mq_close_options, {"Options", "mq.close.options", FT_UINT32, BASE_HEX, NULL, 0x0, "CLOSE options", HFILL}},
        {&hf_mq_close_options_DELETE, {"DELETE", "mq.close.options.Delete", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQCO_DELETE, "CLOSE options DELETE", HFILL}},
        {&hf_mq_close_options_DELETE_PURGE, {"DELETE_PURGE", "mq.close.options.DeletePurge", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQCO_DELETE_PURGE, "CLOSE options DELETE_PURGE", HFILL}},
        {&hf_mq_close_options_KEEP_SUB, {"KEEPSUB", "mq.close.options.KeepSub", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQCO_KEEP_SUB, "CLOSE options KEEP_SUB", HFILL}},
        {&hf_mq_close_options_REMOVE_SUB, {"REMOVE_SUB", "mq.close.options.RemoveSub", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQCO_REMOVE_SUB, "CLOSE options REMOVE_SUB", HFILL}},
        {&hf_mq_close_options_QUIESCE, {"QUIESCE", "mq.close.options.Quiesce", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQCO_QUIESCE, "CLOSE options QUIESCE", HFILL}},

        {&hf_mq_open_options, {"Options", "mq.open.options", FT_UINT32, BASE_HEX, NULL, 0x0, "OPEN options", HFILL}},
        {&hf_mq_open_options_INPUT_AS_Q_DEF, {"INPUT_AS_Q_DEF", "mq.open.options.InputAsQDef", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_INPUT_AS_Q_DEF, "OPEN options INPUT_AS_Q_DEF", HFILL}},
        {&hf_mq_open_options_INPUT_SHARED, {"INPUT_SHARED", "mq.open.options.InputShared", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_INPUT_SHARED, "OPEN options INPUT_SHARED", HFILL}},
        {&hf_mq_open_options_INPUT_EXCLUSIVE, {"INPUT_EXCLUSIVE", "mq.open.options.InputExclusive", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_INPUT_EXCLUSIVE, "OPEN options INPUT_EXCLUSIVE", HFILL}},
        {&hf_mq_open_options_BROWSE, {"BROWSE", "mq.open.options.Browse", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_BROWSE, "OPEN options BROWSE", HFILL}},
        {&hf_mq_open_options_OUTPUT, {"OUTPUT", "mq.open.options.Output", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_OUTPUT, "OPEN options OUTPUT", HFILL}},
        {&hf_mq_open_options_INQUIRE, {"INQUIRE", "mq.open.options.Inquire", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_INQUIRE, "OPEN options INQUIRE", HFILL}},
        {&hf_mq_open_options_SET, {"SET", "mq.open.options.Set", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_SET, "OPEN options SET", HFILL}},
        {&hf_mq_open_options_SAVE_ALL_CTX, {"SAVE_ALL_CONTEXT", "mq.open.options.SaveAllContext", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_SAVE_ALL_CONTEXT, "OPEN options SAVE_ALL_CONTEXT", HFILL}},
        {&hf_mq_open_options_PASS_IDENT_CTX, {"PASS_IDENTITY_CONTEXT", "mq.open.options.PassIdentityContext", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_PASS_IDENTITY_CONTEXT, "OPEN options PASS_IDENTITY_CONTEXT", HFILL}},
        {&hf_mq_open_options_PASS_ALL_CTX, {"PASS_ALL_CONTEXT", "mq.open.options.PassAllContext", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_PASS_ALL_CONTEXT, "OPEN options PASS_ALL_CONTEXT", HFILL}},
        {&hf_mq_open_options_SET_IDENT_CTX, {"SET_IDENTITY_CONTEXT", "mq.open.options.SetIdentityContext", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_SET_IDENTITY_CONTEXT, "OPEN options SET_IDENTITY_CONTEXT", HFILL}},
        {&hf_mq_open_options_SET_ALL_CONTEXT, {"SET_ALL_CONTEXT", "mq.open.options.SetAllContext", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_SET_ALL_CONTEXT, "OPEN options SET_ALL_CONTEXT", HFILL}},
        {&hf_mq_open_options_ALT_USER_AUTH, {"ALTERNATE_USER_AUTHORITY", "mq.open.options.AlternateUserAuthority", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_ALTERNATE_USER_AUTHORITY, "OPEN options ALTERNATE_USER_AUTHORITY", HFILL}},
        {&hf_mq_open_options_FAIL_IF_QUIESC, {"FAIL_IF_QUIESCING", "mq.open.options.FailIfQuiescing", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_FAIL_IF_QUIESCING, "OPEN options FAIL_IF_QUIESCING", HFILL}},
        {&hf_mq_open_options_BIND_ON_OPEN, {"BIND_ON_OPEN", "mq.open.options.BindOnOpen", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_BIND_ON_OPEN, "OPEN options BIND_ON_OPEN", HFILL}},
        {&hf_mq_open_options_BIND_NOT_FIXED, {"BIND_NOT_FIXED", "mq.open.options.BindNotFixed", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_BIND_NOT_FIXED, "OPEN options BIND_NOT_FIXED", HFILL}},
        {&hf_mq_open_options_RESOLVE_NAMES, {"RESOLVE_NAMES", "mq.open.options.ResolveNames", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_RESOLVE_NAMES, "OPEN options RESOLVE_NAMES", HFILL}},
        {&hf_mq_open_options_CO_OP, {"CO_OP", "mq.open.options.CoOp", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_CO_OP, "OPEN options CO_OP", HFILL}},
        {&hf_mq_open_options_RESOLVE_LOCAL_Q, {"RESOLVE_LOCAL_Q", "mq.open.options.ResolveLocalQueueOrTopic", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_RESOLVE_LOCAL_Q, "OPEN options RESOLVE_LOCAL_Q", HFILL}},
        {&hf_mq_open_options_NO_READ_AHEAD, {"NO_READ_AHEAD", "mq.open.options.NoReadAhead", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_NO_READ_AHEAD, "OPEN options NO_READ_AHEAD", HFILL}},
        {&hf_mq_open_options_READ_AHEAD, {"READ_AHEAD", "mq.open.options.ReadAhead", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_READ_AHEAD, "OPEN options READ_AHEAD", HFILL}},
        {&hf_mq_open_options_NO_MULTICAST, {"NO_MULTICAST", "mq.open.options.NoMulticast", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_NO_MULTICAST, "OPEN options NO_MULTICAST", HFILL}},
        {&hf_mq_open_options_BIND_ON_GROUP, {"BIND_ON_GROUP", "mq.open.options.BindOnGroup", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_BIND_ON_GROUP, "OPEN options BIND_ON_GROUP", HFILL}},

        {&hf_mq_fopa_StructID, {"StructId.......", "mq.fopa.structid", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_mq_fopa_version, {"Version........", "mq.fopa.version", FT_UINT32, BASE_DEC, NULL, 0x0, "FOPA Version", HFILL}},
        {&hf_mq_fopa_length, {"Length.........", "mq.fopa.length", FT_UINT32, BASE_DEC, NULL, 0x0, "FOPA Length", HFILL}},
        {&hf_mq_fopa_DefPersistence, {"DefPersistence.", "mq.fopa.defpersistence", FT_INT32, BASE_DEC, VALS(GET_VALSV(MQPER)), 0x0, "FOPA DefPersistence", HFILL}},
        {&hf_mq_fopa_DefPutRespType, {"DefPutRespType.", "mq.fopa.defputresponsetype", FT_INT32, BASE_DEC, VALS(GET_VALSV(MQPRT)), 0x0, "FOPA DefPutRespType", HFILL}},
        {&hf_mq_fopa_DefReadAhead, {"DefReadAhead...", "mq.fopa.defreadahaed", FT_INT32, BASE_DEC, VALS(GET_VALSV(MQREADA)), 0x0, "FOPA DefReadAhead", HFILL}},
        {&hf_mq_fopa_PropertyControl, {"PropertyControl", "mq.fopa.propertycontrol", FT_INT32, BASE_DEC, VALS(GET_VALSV(MQPROP)), 0x0, "FOPA PropertyControl", HFILL}},
        {&hf_mq_fopa_Unknown, {"Unknown........", "mq.fopa.unknown", FT_BYTES, BASE_NONE, NULL, 0x0, "FOPA Unknown", HFILL}},

        {&hf_mq_fcmi_StructID, {"StructId.......", "mq.fcmi.structid", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_mq_fcmi_unknown, {"Unknown........", "mq.fcmi.unknown", FT_UINT32, BASE_DEC, NULL, 0x0, "FCMI Unknown", HFILL}},

        {&hf_mq_msgreq_version, {"version..", "mq.msgreq.version", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "MSGREQ version", HFILL}},
        {&hf_mq_msgreq_handle, {"handle...", "mq.msgreq.handle", FT_UINT32, BASE_HEX, NULL, 0x0, "MSGREQ handle", HFILL}},
        {&hf_mq_msgreq_RecvBytes, {"RecvBytes", "mq.msgreq.unknown1", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "MSGREQ Received Bytes", HFILL}},
        {&hf_mq_msgreq_RqstBytes, {"RqstBytes", "mq.msgreq.rqstbytes", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "MSGREQ Requested Bytes", HFILL}},
        {&hf_mq_msgreq_MaxMsgLen, {"MaxMsgLen", "mq.msgreq.maxmsglen", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "MSGREQ Maximum Msg Length", HFILL}},
        {&hf_mq_msgreq_WaitIntrv, {"WaitIntrv", "mq.msgreq.waitintrv", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "MSGREQ Wait Interval", HFILL}},
        {&hf_mq_msgreq_QueStatus, {"QueStatus", "mq.msgreq.questatus", FT_UINT32, BASE_HEX, NULL, 0x0, "MSGREQ Queue Status", HFILL}},
        {&hf_mq_msgreq_RqstFlags, {"RqstFlags", "mq.msgreq.rqstflags", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "MSGREQ Request Flags", HFILL}},
        {&hf_mq_msgreq_flags_selection, {"REQ_MSG_SELECTION", "mq.msgreq.rqstflags.SELECTION", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_REQUEST_MSG_SELECTION, "Request Message flag SELECTION", HFILL}},
        {&hf_mq_msgreq_flags_F00000008, {"REQ_MSG_F00000008", "mq.msgreq.rqstflags.F00000008", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_REQUEST_MSG_F00000008, "Request Message flag F00000008", HFILL}},
        {&hf_mq_msgreq_flags_F00000004, {"REQ_MSG_F00000004", "mq.msgreq.rqstflags.F00000004", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_REQUEST_MSG_F00000004, "Request Message flag F00000004", HFILL}},
        {&hf_mq_msgreq_flags_F00000002, {"REQ_MSG_F00000002", "mq.msgreq.rqstflags.F00000002", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_REQUEST_MSG_F00000002, "Request Message flag F00000002", HFILL}},

        {&hf_mq_msgreq_GlbMsgIdx, {"GlbMsgIdx", "mq.msgreq.glbmsgidx", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "MSGREQ Global Message Index", HFILL}},
        {&hf_mq_msgreq_SelectIdx, {"SelectIdx", "mq.msgreq.selectIdx", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, "MSGREQ Selection Index", HFILL}},
        {&hf_mq_msgreq_MQMDVers, {"MQMDVers.", "mq.msgreq.mqmdvers", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, "MSGREQ MQMD Version", HFILL}},
        {&hf_mq_msgreq_ccsid, {"CCSID....", "mq.msgreq.ccsid", FT_INT32, BASE_DEC | BASE_RANGE_STRING, RVALS(GET_VALRV(ccsid)), 0x0, "MSGREQ ccsid", HFILL}},
        {&hf_mq_msgreq_encoding, {"Encoding.", "mq.msgreq.encoding", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "MSGREQ encoding", HFILL}},
        {&hf_mq_msgreq_MsgSeqNum, {"MsgSeqNum", "mq.msgreq.msgseqnum", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "MSGREQ Message Sequence Number", HFILL}},
        {&hf_mq_msgreq_offset, {"Offset...", "mq.msgreq.offset", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "MSGREQ Offset", HFILL}},
        {&hf_mq_msgreq_mtchMsgId, {"mtchMsgId", "mq.msgreq.mtchMsgId", FT_BYTES, BASE_NONE, NULL, 0x0, "MSGREQ match MsgID", HFILL}},
        {&hf_mq_msgreq_mtchCorId, {"mtchCorID", "mq.msgreq.mtchcorid", FT_BYTES, BASE_NONE, NULL, 0x0, "MSGREQ match Correlation Id", HFILL}},
        {&hf_mq_msgreq_mtchGrpid, {"mtchGrpID", "mq.msgreq.mtchgrpid", FT_BYTES, BASE_NONE, NULL, 0x0, "MSGREQ match Group ID", HFILL}},
        {&hf_mq_msgreq_mtchMsgTk, {"mtchMsgTk", "mq.msgreq.mtchmsgtk", FT_BYTES, BASE_NONE, NULL, 0x0, "MSGREQ match Message Token", HFILL}},

        {&hf_mq_msgasy_version, {"version..", "mq.msgasy.version", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "MSGASYNC version", HFILL}},
        {&hf_mq_msgasy_handle, {"handle...", "mq.msgasy.handle", FT_UINT32, BASE_HEX, NULL, 0x0, "MSGASYNC handle", HFILL}},
        {&hf_mq_msgasy_MsgIndex, {"MsgIndex.", "mq.msgasy.msgindex", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "MSGASYNC Message Index", HFILL}},
        {&hf_mq_msgasy_GlbMsgIdx, {"GlbMsgIdx", "mq.msgasy.glbmsgidx", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "MSGASYNC Global Message Index", HFILL}},
        {&hf_mq_msgasy_SegLength, {"SegLength", "mq.msgasy.seglength", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "MSGASYNC Segment Length", HFILL}},
        {&hf_mq_msgasy_SegmIndex, {"SegmIndex", "mq.msgasy.segmindex", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, "MSGASYNC Segment Index", HFILL}},
        {&hf_mq_msgasy_SeleIndex, {"SeleIndex", "mq.msgasy.seleindex", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, "MSGASYNC Selection Index", HFILL}},
        {&hf_mq_msgasy_ReasonCod, {"ReasonCod", "mq.msgasy.reasoncod", FT_UINT32, BASE_DEC | BASE_EXT_STRING, GET_VALS_EXTP(MQRC), 0x0, "MSGASYNC Reason Code", HFILL}},
        {&hf_mq_msgasy_ActMsgLen, {"ActMsgLen", "mq.msgasy.actmsglen", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "MSGASYNC Actual Message Length", HFILL}},
        {&hf_mq_msgasy_TotMsgLen, {"TotMsgLen", "mq.msgasy.totmsglen", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "MSGASYNC Total Message Length", HFILL}},
        {&hf_mq_msgasy_MsgToken, {"MsgToken.", "mq.msgasy.msgtoken", FT_BYTES, BASE_NONE, NULL, 0x0, "MSGASYNC Mesasage Token", HFILL}},
        {&hf_mq_msgasy_Status, {"status...", "mq.msgasy.status", FT_UINT16, BASE_HEX, NULL, 0x0, "MSGASYNC Status", HFILL}},
        {&hf_mq_msgasy_resolQNLn, {"resolQNLn", "mq.msgasy.resolqnln", FT_UINT8, BASE_DEC, NULL, 0x0, "MSGASYNC Resolved Queue Name Length", HFILL}},
        {&hf_mq_msgasy_resolQNme, {"resolQNme", "mq.msgasy.resolqnme", FT_STRING, BASE_NONE, NULL, 0x0, "MSGASYNC Resolved Queue Name", HFILL}},
        {&hf_mq_msgasy_padding, {"Padding..", "mq.msgasy.padding", FT_BYTES, BASE_NONE, NULL, 0x0, "MSGASYNC Padding", HFILL}},

        {&hf_mq_notif_vers, {"version.", "mq.notif.vers", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "NOTIFICATION version", HFILL}},
        {&hf_mq_notif_handle, {"handle..", "mq.notif.handle", FT_UINT32, BASE_HEX, NULL, 0x0, "NOTIFICATION handle", HFILL}},
        {&hf_mq_notif_code, {"code....", "mq.notif.code", FT_UINT32, BASE_HEX_DEC, VALS(GET_VALSV(notifcode)), 0x0, "NOTIFICATION code", HFILL}},
        {&hf_mq_notif_value, {"value...", "mq.notif.value", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "NOTIFICATION MQRC", HFILL}},

        {&hf_mq_ping_length, {"Length", "mq.ping.length", FT_UINT32, BASE_DEC, NULL, 0x0, "PING length", HFILL}},
        {&hf_mq_ping_buffer, {"Buffer", "mq.ping.buffer", FT_BYTES, BASE_NONE, NULL, 0x0, "PING buffer", HFILL}},

        {&hf_mq_reset_length, {"Length", "mq.reset.length", FT_UINT32, BASE_DEC, NULL, 0x0, "RESET length", HFILL}},
        {&hf_mq_reset_seqnum, {"SeqNum", "mq.reset.seqnum", FT_UINT32, BASE_DEC, NULL, 0x0, "RESET sequence number", HFILL}},

        {&hf_mq_status_length, {"Length", "mq.status.length", FT_UINT32, BASE_DEC, NULL, 0x0, "STATUS length", HFILL}},
        {&hf_mq_status_code, {"Code..", "mq.status.code", FT_UINT32, BASE_DEC | BASE_EXT_STRING, GET_VALS_EXTP(status), 0x0, "STATUS code", HFILL}},
        {&hf_mq_status_value, {"Value.", "mq.status.value", FT_UINT32, BASE_DEC, NULL, 0x0, "STATUS value", HFILL}},

        {&hf_mq_od_StructID, {"StructID.........", "mq.od.structid", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_mq_od_version, {"version..........", "mq.od.version", FT_UINT32, BASE_DEC, NULL, 0x0, "OD version", HFILL}},
        {&hf_mq_od_objecttype, {"ObjType..........", "mq.od.objtype", FT_UINT32, BASE_DEC | BASE_EXT_STRING, GET_VALS_EXTP(objtype), 0x0, "OD object type", HFILL}},
        {&hf_mq_od_objectname, {"ObjName..........", "mq.od.objname", FT_STRING, BASE_NONE, NULL, 0x0, "OD object name", HFILL}},
        {&hf_mq_od_objqmgrname, {"ObjQMgr..........", "mq.od.objqmgrname", FT_STRING, BASE_NONE, NULL, 0x0, "OD object queue manager name", HFILL}},
        {&hf_mq_od_dynqname, {"DynQName.........", "mq.od.dynqname", FT_STRING, BASE_NONE, NULL, 0x0, "OD dynamic queue name", HFILL}},
        {&hf_mq_od_altuserid, {"AltUserID........", "mq.od.altuserid", FT_STRING, BASE_NONE, NULL, 0x0, "OD alternate userid", HFILL}},
        {&hf_mq_od_recspresent, {"NbrRecord........", "mq.od.nbrrec", FT_UINT32, BASE_DEC, NULL, 0x0, "OD number of records", HFILL}},
        {&hf_mq_od_knowndstcnt, {"Known Dest Count.", "mq.od.kdestcount", FT_UINT32, BASE_DEC, NULL, 0x0, "OD known destination count", HFILL}},
        {&hf_mq_od_unknowdstcnt, {"Unknown Dest Cnt.", "mq.od.udestcount", FT_UINT32, BASE_DEC, NULL, 0x0, "OD unknown destination count", HFILL}},
        {&hf_mq_od_invaldstcnt, {"Invalid Dest Cnt.", "mq.od.idestcount", FT_UINT32, BASE_DEC, NULL, 0x0, "OD invalid destination count", HFILL}},
        {&hf_mq_od_objrecofs, {"Offset of 1st OR.", "mq.od.offsetor", FT_UINT32, BASE_DEC, NULL, 0x0, "OD offset of first OR", HFILL}},
        {&hf_mq_od_resprecofs, {"Offset of 1st RR.", "mq.od.offsetrr", FT_UINT32, BASE_DEC, NULL, 0x0, "OD offset of first RR", HFILL}},
        {&hf_mq_od_objrecptr, {"Addr   of 1st OR.", "mq.od.addror", FT_UINT32, BASE_HEX, NULL, 0x0, "OD address of first OR", HFILL}},
        {&hf_mq_od_resprecptr, {"Addr   of 1st RR.", "mq.od.addrrr", FT_UINT32, BASE_HEX, NULL, 0x0, "OD address of first RR", HFILL}},
        {&hf_mq_od_altsecurid, {"Alt security id..", "mq.od.altsecid", FT_STRING, BASE_NONE, NULL, 0x0, "OD alternate security id", HFILL}},
        {&hf_mq_od_resolvqname, {"Resolved Q Name..", "mq.od.resolvq", FT_STRING, BASE_NONE, NULL, 0x0, "OD resolved queue name", HFILL}},
        {&hf_mq_od_resolvqmgrnm, {"Resolved QMgrName", "mq.od.resolvqmgr", FT_STRING, BASE_NONE, NULL, 0x0, "OD resolved queue manager name", HFILL}},
        {&hf_mq_od_resolvobjtyp, {"Resolv Obj Type..", "mq.od.resolvedobjtype", FT_UINT32, BASE_DEC | BASE_EXT_STRING, GET_VALS_EXTP(objtype), 0x0, "OD resolved object type", HFILL}},

        {&hf_mq_or_objname, {"Object name...", "mq.or.objname", FT_STRING, BASE_NONE, NULL, 0x0, "OR object name", HFILL}},
        {&hf_mq_or_objqmgrname, {"Object QMgr Nm", "mq.or.objqmgrname", FT_STRING, BASE_NONE, NULL, 0x0, "OR object queue manager name", HFILL}},

        {&hf_mq_rr_compcode, {"Comp Code", "mq.rr.completioncode", FT_UINT32, BASE_DEC, NULL, 0x0, "OR completion code", HFILL}},
        {&hf_mq_rr_reascode, {"Reas Code", "mq.rr.reasoncode", FT_UINT32, BASE_DEC, NULL, 0x0, "OR reason code", HFILL}},

        {&hf_mq_pmr_msgid, {"Message Id", "mq.pmr.msgid", FT_BYTES, BASE_NONE, NULL, 0x0, "PMR Message Id", HFILL}},
        {&hf_mq_pmr_correlid, {"Correlation Id", "mq.pmr.correlid", FT_BYTES, BASE_NONE, NULL, 0x0, "PMR Correlation Id", HFILL}},
        {&hf_mq_pmr_groupid, {"GroupId", "mq.pmr.groupid", FT_BYTES, BASE_NONE, NULL, 0x0, "PMR GroupId", HFILL}},
        {&hf_mq_pmr_feedback, {"Feedback", "mq.pmr.feedback", FT_UINT32, BASE_DEC, NULL, 0x0, "PMR Feedback", HFILL}},
        {&hf_mq_pmr_acttoken, {"Accounting token", "mq.pmr.acttoken", FT_BYTES, BASE_NONE, NULL, 0x0, "PMR accounting token", HFILL}},

        {&hf_mq_md_StructID, {"StructID.", "mq.md.structid", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_mq_md_version, {"Version..", "mq.md.version", FT_UINT32, BASE_DEC, NULL, 0x0, "MD version", HFILL}},
        {&hf_mq_md_report, {"Report...", "mq.md.report", FT_UINT32, BASE_DEC, NULL, 0x0, "MD report", HFILL}},
        {&hf_mq_md_msgtype, {"Msg Type.", "mq.md.msgtype", FT_UINT32, BASE_DEC, VALS(GET_VALSV(MQMT)), 0x0, "MD message type", HFILL}},
        {&hf_mq_md_expiry, {"Expiry  .", "mq.md.expiry", FT_INT32, BASE_DEC, NULL, 0x0, "MD expiry", HFILL}},
        {&hf_mq_md_feedback, {"Feedback.", "mq.md.feedback", FT_UINT32, BASE_DEC, NULL, 0x0, "MD feedback", HFILL}},
        {&hf_mq_md_encoding, {"Encoding.", "mq.md.encoding", FT_UINT32, BASE_DEC, NULL, 0x0, "MD encoding", HFILL}},
        {&hf_mq_md_ccsid, {"CCSID....", "mq.md.ccsid", FT_INT32, BASE_DEC | BASE_RANGE_STRING, RVALS(GET_VALRV(ccsid)), 0x0, "MD character set", HFILL}},
        {&hf_mq_md_format, {"Format...", "mq.md.format", FT_STRING, BASE_NONE, NULL, 0x0, "MD format", HFILL}},
        {&hf_mq_md_priority, {"Priority.", "mq.md.priority", FT_INT32, BASE_DEC, NULL, 0x0, "MD priority", HFILL}},
        {&hf_mq_md_persistence, {"Persist..", "mq.md.persistence", FT_UINT32, BASE_DEC, VALS(GET_VALSV(MQPER)), 0x0, "MD persistence", HFILL}},
        {&hf_mq_md_msgid, {"Msg ID...", "mq.md.msgid", FT_BYTES, BASE_NONE, NULL, 0x0, "MD Message Id", HFILL}},
        {&hf_mq_md_correlid, {"CorrelID.", "mq.md.correlid", FT_BYTES, BASE_NONE, NULL, 0x0, "MD Correlation Id", HFILL}},
        {&hf_mq_md_backoutcnt, {"BackoCnt.", "mq.md.backoutcnt", FT_UINT32, BASE_DEC, NULL, 0x0, "MD Backout count", HFILL}},
        {&hf_mq_md_replytoq, {"ReplyToQ.", "mq.md.replytoq", FT_STRING, BASE_NONE, NULL, 0x0, "MD ReplyTo queue", HFILL}},
        {&hf_mq_md_replytoqmgr, {"RepToQMgr", "mq.md.replytoqmgr", FT_STRING, BASE_NONE, NULL, 0x0, "MD ReplyTo queue manager", HFILL}},
        {&hf_mq_md_userid, {"UserId...", "mq.md.userid", FT_STRING, BASE_NONE, NULL, 0x0, "MD UserId", HFILL}},
        {&hf_mq_md_acttoken, {"AccntTok.", "mq.md.acttoken", FT_BYTES, BASE_NONE, NULL, 0x0, "MD accounting token", HFILL}},
        {&hf_mq_md_appliddata, {"AppIdData", "mq.md.appldata", FT_STRING, BASE_NONE, NULL, 0x0, "MD Put applicationId data", HFILL}},
        {&hf_mq_md_putappltype, {"PutAppTyp", "mq.md.appltype", FT_INT32, BASE_DEC | BASE_EXT_STRING, GET_VALS_EXTP(MQAT), 0x0, "MD Put application type", HFILL}},
        {&hf_mq_md_putapplname, {"PutAppNme", "mq.md.applname", FT_STRING, BASE_NONE, NULL, 0x0, "MD Put application name", HFILL}},
        {&hf_mq_md_putdate, {"PutDatGMT", "mq.md.date", FT_STRING, BASE_NONE, NULL, 0x0, "MD Put date", HFILL}},
        {&hf_mq_md_puttime, {"PutTimGMT", "mq.md.time", FT_STRING, BASE_NONE, NULL, 0x0, "MD Put time", HFILL}},
        {&hf_mq_md_apporigdata, {"AppOriDat", "mq.md.origdata", FT_STRING, BASE_NONE, NULL, 0x0, "MD Application original data", HFILL}},
        {&hf_mq_md_groupid, {"GroupId..", "mq.md.groupid", FT_BYTES, BASE_NONE, NULL, 0x0, "MD GroupId", HFILL}},
        {&hf_mq_md_msgseqnumber, {"MsgSeqNum", "mq.md.msgseqnumber", FT_UINT32, BASE_DEC, NULL, 0x0, "MD Message sequence number", HFILL}},
        {&hf_mq_md_offset, {"Offset...", "mq.md.offset", FT_UINT32, BASE_DEC, NULL, 0x0, "MD Offset", HFILL}},
        {&hf_mq_md_msgflags, {"Msg flags", "mq.md.msgflags", FT_UINT32, BASE_HEX, NULL, 0x0, "MD Message flags", HFILL}},
        {&hf_mq_md_origlen, {"Orig len.", "mq.md.origlength", FT_INT32, BASE_DEC, NULL, 0x0, "MD Original length", HFILL}},

        {&hf_mq_dlh_StructID, {"StructID.", "mq.dlh.structid", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_mq_dlh_version, {"Version..", "mq.dlh.version", FT_UINT32, BASE_DEC, NULL, 0x0, "DLH version", HFILL}},
        {&hf_mq_dlh_reason, {"Reason...", "mq.dlh.reason", FT_UINT32, BASE_DEC, NULL, 0x0, "DLH reason", HFILL}},
        {&hf_mq_dlh_destq, {"Dest Q...", "mq.dlh.destq", FT_STRING, BASE_NONE, NULL, 0x0, "DLH destination queue", HFILL}},
        {&hf_mq_dlh_destqmgr, {"DestQMgr.", "mq.dlh.destqmgr", FT_STRING, BASE_NONE, NULL, 0x0, "DLH destination queue manager", HFILL}},
        {&hf_mq_dlh_encoding, {"Encoding.", "mq.dlh.encoding", FT_UINT32, BASE_DEC, NULL, 0x0, "DLH encoding", HFILL}},
        {&hf_mq_dlh_ccsid, {"CCSID....", "mq.dlh.ccsid", FT_INT32, BASE_DEC | BASE_RANGE_STRING, RVALS(GET_VALRV(ccsid)), 0x0, "DLH character set", HFILL}},
        {&hf_mq_dlh_format, {"Format...", "mq.dlh.format", FT_STRING, BASE_NONE, NULL, 0x0, "DLH format", HFILL}},
        {&hf_mq_dlh_putappltype, {"PutAppTyp", "mq.dlh.putappltype", FT_INT32, BASE_DEC | BASE_EXT_STRING, GET_VALS_EXTP(MQAT), 0x0, "DLH put application type", HFILL}},
        {&hf_mq_dlh_putapplname, {"PutAppNme", "mq.dlh.putapplname", FT_STRING, BASE_NONE, NULL, 0x0, "DLH put application name", HFILL}},
        {&hf_mq_dlh_putdate, {"PutDatGMT", "mq.dlh.putdate", FT_STRING, BASE_NONE, NULL, 0x0, "DLH put date", HFILL}},
        {&hf_mq_dlh_puttime, {"PutTimGMT", "mq.dlh.puttime", FT_STRING, BASE_NONE, NULL, 0x0, "DLH put time", HFILL}},

        {&hf_mq_gmo_StructID, {"StructID.", "mq.gmo.structid", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_mq_gmo_version, {"Version..", "mq.gmo.version", FT_UINT32, BASE_DEC, NULL, 0x0, "GMO version", HFILL}},
        {&hf_mq_gmo_options, {"GetMsgOpt", "mq.gmo.getmsgopt", FT_UINT32, BASE_HEX, NULL, 0x0, "GMO Get Message Options", HFILL}},

        {&hf_mq_gmo_options_PROPERTIES_COMPATIBILITY, {"PROPERTIES_COMPATIBILITY", "mq.gmo.options.PROPERTIES_COMPATIBILITY", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_PROPERTIES_COMPATIBILITY, "GMO options PROPERTIES_COMPATIBILITY", HFILL}},
        {&hf_mq_gmo_options_PROPERTIES_IN_HANDLE, {"PROPERTIES_IN_HANDLE", "mq.gmo.options.PROPERTIES_IN_HANDLE", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_PROPERTIES_IN_HANDLE, "GMO options PROPERTIES_IN_HANDLE", HFILL}},
        {&hf_mq_gmo_options_NO_PROPERTIES, {"NO_PROPERTIES", "mq.gmo.options.NO_PROPERTIES", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_NO_PROPERTIES, "GMO options NO_PROPERTIES", HFILL}},
        {&hf_mq_gmo_options_PROPERTIES_FORCE_MQRFH2, {"PROPERTIES_FORCE_MQRFH2", "mq.gmo.options.PROPERTIES_FORCE_MQRFH2", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_PROPERTIES_FORCE_MQRFH2, "GMO options PROPERTIES_FORCE_MQRFH2", HFILL}},
        {&hf_mq_gmo_options_UNMARKED_BROWSE_MSG, {"UNMARKED_BROWSE_MSG", "mq.gmo.options.UNMARKED_BROWSE_MSG", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_UNMARKED_BROWSE_MSG, "GMO options UNMARKED_BROWSE_MSG", HFILL}},
        {&hf_mq_gmo_options_UNMARK_BROWSE_HANDLE, {"UNMARK_BROWSE_HANDLE", "mq.gmo.options.UNMARK_BROWSE_HANDLE", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_UNMARK_BROWSE_HANDLE, "GMO options UNMARK_BROWSE_HANDLE", HFILL}},
        {&hf_mq_gmo_options_UNMARK_BROWSE_CO_OP, {"UNMARK_BROWSE_CO_OP", "mq.gmo.options.UNMARK_BROWSE_CO_OP", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_UNMARK_BROWSE_CO_OP, "GMO options UNMARK_BROWSE_CO_OP", HFILL}},
        {&hf_mq_gmo_options_MARK_BROWSE_CO_OP, {"MARK_BROWSE_CO_OP", "mq.gmo.options.MARK_BROWSE_CO_OP", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_MARK_BROWSE_CO_OP, "GMO options MARK_BROWSE_CO_OP", HFILL}},
        {&hf_mq_gmo_options_MARK_BROWSE_HANDLE, {"MARK_BROWSE_HANDLE", "mq.gmo.options.MARK_BROWSE_HANDLE", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_MARK_BROWSE_HANDLE, "GMO options MARK_BROWSE_HANDLE", HFILL}},
        {&hf_mq_gmo_options_ALL_SEGMENTS_AVAILABLE, {"ALL_SEGMENTS_AVAILABLE", "mq.gmo.options.ALL_SEGMENTS_AVAILABLE", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_ALL_SEGMENTS_AVAILABLE, "GMO options ALL_SEGMENTS_AVAILABLE", HFILL}},
        {&hf_mq_gmo_options_ALL_MSGS_AVAILABLE, {"ALL_MSGS_AVAILABLE", "mq.gmo.options.ALL_MSGS_AVAILABLE", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_ALL_MSGS_AVAILABLE, "GMO options ALL_MSGS_AVAILABLE", HFILL}},
        {&hf_mq_gmo_options_COMPLETE_MSG, {"COMPLETE_MSG", "mq.gmo.options.COMPLETE_MSG", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_COMPLETE_MSG, "GMO options COMPLETE_MSG", HFILL}},
        {&hf_mq_gmo_options_LOGICAL_ORDER, {"LOGICAL_ORDER", "mq.gmo.options.LOGICAL_ORDER", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_LOGICAL_ORDER, "GMO options LOGICAL_ORDER", HFILL}},
        {&hf_mq_gmo_options_CONVERT, {"CONVERT", "mq.gmo.options.CONVERT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_CONVERT, "GMO options CONVERT", HFILL}},
        {&hf_mq_gmo_options_FAIL_IF_QUIESCING, {"FAIL_IF_QUIESCING", "mq.gmo.options.FAIL_IF_QUIESCING", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_FAIL_IF_QUIESCING, "GMO options FAIL_IF_QUIESCING", HFILL}},
        {&hf_mq_gmo_options_SYNCPOINT_IF_PERSISTENT, {"SYNCPOINT_IF_PERSISTENT", "mq.gmo.options.SYNCPOINT_IF_PERSISTENT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_SYNCPOINT_IF_PERSISTENT, "GMO options SYNCPOINT_IF_PERSISTENT", HFILL}},
        {&hf_mq_gmo_options_BROWSE_MSG_UNDER_CURSOR, {"BROWSE_MSG_UNDER_CURSOR", "mq.gmo.options.BROWSE_MSG_UNDER_CURSOR", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_BROWSE_MSG_UNDER_CURSOR, "GMO options BROWSE_MSG_UNDER_CURSOR", HFILL}},
        {&hf_mq_gmo_options_UNLOCK, {"UNLOCK", "mq.gmo.options.UNLOCK", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_UNLOCK, "GMO options UNLOCK", HFILL}},
        {&hf_mq_gmo_options_LOCK, {"LOCK", "mq.gmo.options.LOCK", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_LOCK, "GMO options LOCK", HFILL}},
        {&hf_mq_gmo_options_MSG_UNDER_CURSOR, {"MSG_UNDER_CURSOR", "mq.gmo.options.MSG_UNDER_CURSOR", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_MSG_UNDER_CURSOR, "GMO options MSG_UNDER_CURSOR", HFILL}},
        {&hf_mq_gmo_options_MARK_SKIP_BACKOUT, {"MARK_SKIP_BACKOUT", "mq.gmo.options.MARK_SKIP_BACKOUT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_MARK_SKIP_BACKOUT, "GMO options MARK_SKIP_BACKOUT", HFILL}},
        {&hf_mq_gmo_options_ACCEPT_TRUNCATED_MSG, {"ACCEPT_TRUNCATED_MSG", "mq.gmo.options.ACCEPT_TRUNCATED_MSG", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_ACCEPT_TRUNCATED_MSG, "GMO options ACCEPT_TRUNCATED_MSG", HFILL}},
        {&hf_mq_gmo_options_BROWSE_NEXT, {"BROWSE_NEXT", "mq.gmo.options.BROWSE_NEXT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_BROWSE_NEXT, "GMO options BROWSE_NEXT", HFILL}},
        {&hf_mq_gmo_options_BROWSE_FIRST, {"BROWSE_FIRST", "mq.gmo.options.BROWSE_FIRST", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_BROWSE_FIRST, "GMO options BROWSE_FIRST", HFILL}},
        {&hf_mq_gmo_options_SET_SIGNAL, {"SET_SIGNAL", "mq.gmo.options.SET_SIGNAL", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_SET_SIGNAL, "GMO options SET_SIGNAL", HFILL}},
        {&hf_mq_gmo_options_NO_SYNCPOINT, {"NO_SYNCPOINT", "mq.gmo.options.NO_SYNCPOINT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_NO_SYNCPOINT, "GMO options NO_SYNCPOINT", HFILL}},
        {&hf_mq_gmo_options_SYNCPOINT, {"SYNCPOINT", "mq.gmo.options.SYNCPOINT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_SYNCPOINT, "GMO options SYNCPOINT", HFILL}},
        {&hf_mq_gmo_options_WAIT, {"WAIT", "mq.gmo.options.WAIT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_WAIT, "GMO options WAIT", HFILL}},

        {&hf_mq_gmo_waitinterval, {"WaitIntv.", "mq.gmo.waitint", FT_INT32, BASE_DEC, NULL, 0x0, "GMO wait interval", HFILL}},
        {&hf_mq_gmo_signal1, {"Signal 1.", "mq.gmo.signal1", FT_UINT32, BASE_HEX, NULL, 0x0, "GMO signal 1", HFILL}},
        {&hf_mq_gmo_signal2, {"Signal 2.", "mq.gmo.signal2", FT_UINT32, BASE_HEX, NULL, 0x0, "GMO signal 2", HFILL}},
        {&hf_mq_gmo_resolvqname, {"ResQName.", "mq.gmo.resolvq", FT_STRING, BASE_NONE, NULL, 0x0, "GMO resolved queue name", HFILL}},
        {&hf_mq_gmo_matchoptions, {"MatchOpt.", "mq.gmo.matchopt", FT_UINT32, BASE_HEX, NULL, 0x0, "GMO match options", HFILL}},

        {&hf_mq_gmo_matchoptions_MATCH_MSG_TOKEN, {"MATCH_MSG_TOKEN", "mq.gmo.matchoptions.MATCH_MSG_TOKEN", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQMO_MATCH_MSG_TOKEN, "GMO matchoptions MATCH_MSG_TOKEN", HFILL}},
        {&hf_mq_gmo_matchoptions_MATCH_OFFSET, {"MATCH_OFFSET", "mq.gmo.matchoptions.MATCH_OFFSET", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQMO_MATCH_OFFSET, "GMO matchoptions MATCH_OFFSET", HFILL}},
        {&hf_mq_gmo_matchoptions_MATCH_MSG_SEQ_NUMBER, {"MATCH_MSG_SEQ_NUMBER", "mq.gmo.matchoptions.MATCH_MSG_SEQ_NUMBER", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQMO_MATCH_MSG_SEQ_NUMBER, "GMO matchoptions MATCH_MSG_SEQ_NUMBER", HFILL}},
        {&hf_mq_gmo_matchoptions_MATCH_GROUP_ID, {"MATCH_GROUP_ID", "mq.gmo.matchoptions.MATCH_GROUP_ID", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQMO_MATCH_GROUP_ID, "GMO matchoptions MATCH_GROUP_ID", HFILL}},
        {&hf_mq_gmo_matchoptions_MATCH_CORREL_ID, {"MATCH_CORREL_ID", "mq.gmo.matchoptions.MATCH_CORREL_ID", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQMO_MATCH_CORREL_ID, "GMO matchoptions MATCH_CORREL_ID", HFILL}},
        {&hf_mq_gmo_matchoptions_MATCH_MSG_ID, {"MATCH_MSG_ID", "mq.gmo.matchoptions.MATCH_MSG_ID", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQMO_MATCH_MSG_ID, "GMO matchoptions MATCH_MSG_ID", HFILL}},

        {&hf_mq_gmo_groupstatus, {"GrpStatus", "mq.gmo.grpstat", FT_UINT8, BASE_HEX, NULL, 0x0, "GMO group status", HFILL}},
        {&hf_mq_gmo_segmstatus, {"SegStatus", "mq.gmo.sgmtstat", FT_UINT8, BASE_HEX, NULL, 0x0, "GMO segment status", HFILL}},
        {&hf_mq_gmo_segmentation, {"Segmentat", "mq.gmo.segmentation", FT_UINT8, BASE_HEX, NULL, 0x0, "GMO segmentation", HFILL}},
        {&hf_mq_gmo_reserved, {"Reserved.", "mq.gmo.reserved", FT_UINT8, BASE_HEX, NULL, 0x0, "GMO reserved", HFILL}},
        {&hf_mq_gmo_msgtoken, {"MsgToken.", "mq.gmo.msgtoken", FT_BYTES, BASE_NONE, NULL, 0x0, "GMO message token", HFILL}},
        {&hf_mq_gmo_returnedlen, {"RtnLength", "mq.gmo.retlen", FT_INT32, BASE_DEC, NULL, 0x0, "GMO returned length", HFILL}},
        {&hf_mq_gmo_reserved2, {"Reserved2", "mq.gmo.reserved2", FT_INT32, BASE_DEC, NULL, 0x0, "GMO reserved2", HFILL}},
        {&hf_mq_gmo_msghandle, {"MsgHandle", "mq.gmo.msghandle", FT_UINT64, BASE_DEC | BASE_HEX, NULL, 0x0, "GMO Message Handle", HFILL}},

        {&hf_mq_lpoo_StructID, {"StructID......", "mq.lpoo.structid", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_mq_lpoo_version, {"version.......", "mq.lpoo.version", FT_UINT32, BASE_DEC, NULL, 0x0, "LPOO version", HFILL}},
        {&hf_mq_lpoo_lpiopts, {"lpiopts.......", "mq.lpoo.lpioopts", FT_UINT32, BASE_HEX, NULL, 0x0, "LPOO Lpi Options", HFILL}},

        {&hf_mq_lpoo_lpiopts_SAVE_USER_CTXT, {"SAVE_USER_CTXT", "mq.lpoo.opts.SAVE_USER_CTXT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_LPOO_SAVE_USER_CTXT, "LPOO options SAVE_USER_CTXT", HFILL}},
        {&hf_mq_lpoo_lpiopts_SAVE_ORIGIN_CTXT, {"SAVE_ORIGIN_CTXT", "mq.lpoo.opts.SAVE_ORIGIN_CTXT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_LPOO_SAVE_ORIGIN_CTXT, "LPOO options SAVE_ORIGIN_CTXT", HFILL}},
        {&hf_mq_lpoo_lpiopts_SAVE_IDENTITY_CTXT, {"SAVE_IDENTITY_CTXT", "mq.lpoo.opts.SAVE_IDENTITY_CTXT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_LPOO_SAVE_IDENTITY_CTXT, "LPOO options SAVE_IDENTITY_CTXT", HFILL}},

        {&hf_mq_lpoo_defpersist, {"DefPersistence", "mq.lpoo.defpersist", FT_INT32, BASE_DEC, VALS(GET_VALSV(MQPER)), 0x0, "LPOO Default Persistence", HFILL}},
        {&hf_mq_lpoo_defputresptype, {"DefPutRespType", "mq.lpoo.defputresptype", FT_INT32, BASE_DEC, VALS(GET_VALSV(MQPRT)), 0x0, "LPOO Default Put Response Type", HFILL}},
        {&hf_mq_lpoo_defreadahead, {"DefReadAHead..", "mq.lpoo.defreadahead", FT_INT32, BASE_DEC, VALS(GET_VALSV(MQREADA)), 0x0, "LPOO Default Read AHead", HFILL}},
        {&hf_mq_lpoo_propertyctl, {"PropertyCtl...", "mq.lpoo.propertyctl", FT_INT32, BASE_DEC, NULL, 0x0, "LPOO Property Control", HFILL}},
        {&hf_mq_lpoo_qprotect, {"qprotect......", "mq.lpoo.qprotect", FT_STRING, BASE_NONE, NULL, 0x0, "LPOO queue protection", HFILL}},
        {&hf_mq_lpoo_qprotect_val1, {"qprotect_val1.", "mq.lpoo.qprotect.val1", FT_INT32, BASE_DEC, NULL, 0x0, "LPOO queue protection val1", HFILL}},
        {&hf_mq_lpoo_qprotect_val2, {"qprotect_val2.", "mq.lpoo.qprotect.val2", FT_INT32, BASE_DEC, NULL, 0x0, "LPOO queue protection val2", HFILL}},

        {&hf_mq_pmo_StructID, {"StructID...", "mq.pmo.structid", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_mq_pmo_version, {"Version....", "mq.pmo.version", FT_UINT32, BASE_DEC, NULL, 0x0, "PMO version", HFILL}},
        {&hf_mq_pmo_options, {"Options....", "mq.pmo.options", FT_UINT32, BASE_HEX, NULL, 0x0, "PMO options", HFILL}},
        {&hf_mq_pmo_options_NOT_OWN_SUBS, {"NOT_OWN_SUBS", "mq.pmo.options.NOT_OWN_SUBS", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_NOT_OWN_SUBS, "PMO options NOT_OWN_SUBS", HFILL}},
        {&hf_mq_pmo_options_SUPPRESS_REPLYTO, {"SUPPRESS_REPLYTO", "mq.pmo.options.SUPPRESS_REPLYTO", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_SUPPRESS_REPLYTO, "PMO options SUPPRESS_REPLYTO", HFILL}},
        {&hf_mq_pmo_options_SCOPE_QMGR, {"SCOPE_QMGR", "mq.pmo.options.SCOPE_QMGR", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_SCOPE_QMGR, "PMO options SCOPE_QMGR", HFILL}},
        {&hf_mq_pmo_options_MD_FOR_OUTPUT_ONLY, {"MD_FOR_OUTPUT_ONLY", "mq.pmo.options.MD_FOR_OUTPUT_ONLY", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_MD_FOR_OUTPUT_ONLY, "PMO options MD_FOR_OUTPUT_ONLY", HFILL}},
        {&hf_mq_pmo_options_RETAIN, {"RETAIN", "mq.pmo.options.RETAIN", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_RETAIN, "PMO options RETAIN", HFILL}},
        {&hf_mq_pmo_options_WARN_IF_NO_SUBS_MATCHED, {"WARN_IF_NO_SUBS_MATCHED", "mq.pmo.options.WARN_IF_NO_SUBS_MATCHED", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_WARN_IF_NO_SUBS_MATCHED, "PMO options WARN_IF_NO_SUBS_MATCHED", HFILL}},
        {&hf_mq_pmo_options_RESOLVE_LOCAL_Q, {"RESOLVE_LOCAL_Q", "mq.pmo.options.RESOLVE_LOCAL_Q", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_RESOLVE_LOCAL_Q, "PMO options RESOLVE_LOCAL_Q", HFILL}},
        {&hf_mq_pmo_options_SYNC_RESPONSE, {"SYNC_RESPONSE", "mq.pmo.options.SYNC_RESPONSE", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_SYNC_RESPONSE, "PMO options SYNC_RESPONSE", HFILL}},
        {&hf_mq_pmo_options_ASYNC_RESPONSE, {"ASYNC_RESPONSE", "mq.pmo.options.ASYNC_RESPONSE", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_ASYNC_RESPONSE, "PMO options ASYNC_RESPONSE", HFILL}},
        {&hf_mq_pmo_options_LOGICAL_ORDER, {"LOGICAL_ORDER", "mq.pmo.options.LOGICAL_ORDER", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_LOGICAL_ORDER, "PMO options LOGICAL_ORDER", HFILL}},
        {&hf_mq_pmo_options_NO_CONTEXT, {"NO_CONTEXT", "mq.pmo.options.NO_CONTEXT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_NO_CONTEXT, "PMO options NO_CONTEXT", HFILL}},
        {&hf_mq_pmo_options_FAIL_IF_QUIESCING, {"FAIL_IF_QUIESCING", "mq.pmo.options.FAIL_IF_QUIESCING", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_FAIL_IF_QUIESCING, "PMO options FAIL_IF_QUIESCING", HFILL}},
        {&hf_mq_pmo_options_ALTERNATE_USER_AUTHORITY, {"ALTERNATE_USER_AUTHORITY", "mq.pmo.options.ALTERNATE_USER_AUTHORITY", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_ALTERNATE_USER_AUTHORITY, "PMO options ALTERNATE_USER_AUTHORITY", HFILL}},
        {&hf_mq_pmo_options_SET_ALL_CONTEXT, {"SET_ALL_CONTEXT", "mq.pmo.options.SET_ALL_CONTEXT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_SET_ALL_CONTEXT, "PMO options SET_ALL_CONTEXT", HFILL}},
        {&hf_mq_pmo_options_SET_IDENTITY_CONTEXT, {"SET_IDENTITY_CONTEXT", "mq.pmo.options.SET_IDENTITY_CONTEXT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_SET_IDENTITY_CONTEXT, "PMO options SET_IDENTITY_CONTEXT", HFILL}},
        {&hf_mq_pmo_options_PASS_ALL_CONTEXT, {"PASS_ALL_CONTEXT", "mq.pmo.options.PASS_ALL_CONTEXT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_PASS_ALL_CONTEXT, "PMO options PASS_ALL_CONTEXT", HFILL}},
        {&hf_mq_pmo_options_PASS_IDENTITY_CONTEXT, {"PASS_IDENTITY_CONTEXT", "mq.pmo.options.PASS_IDENTITY_CONTEXT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_PASS_IDENTITY_CONTEXT, "PMO options PASS_IDENTITY_CONTEXT", HFILL}},
        {&hf_mq_pmo_options_NEW_CORREL_ID, {"NEW_CORREL_ID", "mq.pmo.options.NEW_CORREL_ID", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_NEW_CORREL_ID, "PMO options NEW_CORREL_ID", HFILL}},
        {&hf_mq_pmo_options_NEW_MSG_ID, {"NEW_MSG_ID", "mq.pmo.options.NEW_MSG_ID", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_NEW_MSG_ID, "PMO options NEW_MSG_ID", HFILL}},
        {&hf_mq_pmo_options_DEFAULT_CONTEXT, {"DEFAULT_CONTEXT", "mq.pmo.options.DEFAULT_CONTEXT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_DEFAULT_CONTEXT, "PMO options DEFAULT_CONTEXT", HFILL}},
        {&hf_mq_pmo_options_NO_SYNCPOINT, {"NO_SYNCPOINT", "mq.pmo.options.NO_SYNCPOINT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_NO_SYNCPOINT, "PMO options NO_SYNCPOINT", HFILL}},
        {&hf_mq_pmo_options_SYNCPOINT, {"SYNCPOINT", "mq.pmo.options.SYNCPOINT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_SYNCPOINT, "PMO options SYNCPOINT", HFILL}},

        {&hf_mq_pmo_timeout, {"Timeout....", "mq.pmo.timeout", FT_INT32, BASE_DEC, NULL, 0x0, "PMO time out", HFILL}},
        {&hf_mq_pmo_context, {"Context....", "mq.pmo.context", FT_UINT32, BASE_HEX, NULL, 0x0, "PMO context", HFILL}},
        {&hf_mq_pmo_knowndstcnt, {"KnDstCnt...", "mq.pmo.kdstcount", FT_UINT32, BASE_DEC, NULL, 0x0, "PMO known destination count", HFILL}},
        {&hf_mq_pmo_unkndstcnt, {"UkDstCnt...", "mq.pmo.udestcount", FT_UINT32, BASE_DEC, NULL, 0x0, "PMO unknown destination count", HFILL}},
        {&hf_mq_pmo_invaldstcnt, {"InDstCnt...", "mq.pmo.idestcount", FT_UINT32, BASE_DEC, NULL, 0x0, "PMO invalid destination count", HFILL}},
        {&hf_mq_pmo_resolvqname, {"ResQName...", "mq.pmo.resolvq", FT_STRING, BASE_NONE, NULL, 0x0, "PMO resolved queue name", HFILL}},
        {&hf_mq_pmo_resolvqmgr, {"ResQMgr....", "mq.pmo.resolvqmgr", FT_STRING, BASE_NONE, NULL, 0x0, "PMO resolved queue manager name", HFILL}},
        {&hf_mq_pmo_recspresent, {"NumRecs....", "mq.pmo.nbrrec", FT_UINT32, BASE_DEC, NULL, 0x0, "PMO number of records", HFILL}},
        {&hf_mq_pmo_putmsgrecfld, {"PMR Flag...", "mq.pmo.flagspmr", FT_UINT32, BASE_HEX, NULL, 0x0, "PMO flags PMR fields", HFILL}},
        {&hf_mq_pmo_putmsgrecofs, {"Ofs1stPMR..", "mq.pmo.offsetpmr", FT_UINT32, BASE_DEC, NULL, 0x0, "PMO offset of first PMR", HFILL}},
        {&hf_mq_pmo_resprecofs, {"Off1stRR...", "mq.pmo.offsetrr", FT_UINT32, BASE_DEC, NULL, 0x0, "PMO offset of first RR", HFILL}},
        {&hf_mq_pmo_putmsgrecptr, {"Adr1stPMR..", "mq.pmo.addrrec", FT_UINT32, BASE_HEX, NULL, 0x0, "PMO address of first record", HFILL}},
        {&hf_mq_pmo_resprecptr, {"Adr1stRR...", "mq.pmo.addrres", FT_UINT32, BASE_HEX, NULL, 0x0, "PMO address of first response record", HFILL}},
        {&hf_mq_pmo_originalmsghandle, {"OrigMsgHdl.", "mq.pmo.originalmsghandle", FT_UINT64, BASE_HEX, NULL, 0x0, "PMO original message handle", HFILL}},
        {&hf_mq_pmo_newmsghandle, {"NewMsgHdl..", "mq.pmo.newmsghandle", FT_UINT64, BASE_HEX, NULL, 0x0, "PMO new message handle", HFILL}},
        {&hf_mq_pmo_action, {"Action.....", "mq.pmo.action", FT_UINT32, BASE_DEC, NULL, 0x0, "PMO action", HFILL}},
        {&hf_mq_pmo_publevel, {"PubLevel...", "mq.pmo.publevel", FT_UINT32, BASE_DEC, NULL, 0x0, "PMO pub level", HFILL}},

        {&hf_mq_xa_length, {"Length.......", "mq.xa.length", FT_UINT32, BASE_DEC, NULL, 0x0, "XA Length", HFILL}},
        {&hf_mq_xa_returnvalue, {"Return value.", "mq.xa.returnvalue", FT_INT32, BASE_DEC, VALS(mq_xaer_vals), 0x0, "XA Return Value", HFILL}},
        {&hf_mq_xa_tmflags, {"TransMgrFlags", "mq.xa.tmflags", FT_UINT32, BASE_HEX, NULL, 0x0, "XA Transaction Manager Flags", HFILL}},
        {&hf_mq_xa_rmid, {"ResourceMgrID", "mq.xa.rmid", FT_UINT32, BASE_DEC, NULL, 0x0, "XA Resource Manager ID", HFILL}},
        {&hf_mq_xa_count, {"Number of Xid", "mq.xa.nbxid", FT_UINT32, BASE_DEC, NULL, 0x0, "XA Number of Xid", HFILL}},
        {&hf_mq_xa_tmflags_join, {"JOIN", "mq.xa.tmflags.join", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_XA_TMJOIN, "XA TM Flags JOIN", HFILL}},
        {&hf_mq_xa_tmflags_endrscan, {"ENDRSCAN", "mq.xa.tmflags.endrscan", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_XA_TMENDRSCAN, "XA TM Flags ENDRSCAN", HFILL}},
        {&hf_mq_xa_tmflags_startrscan, {"STARTRSCAN", "mq.xa.tmflags.startrscan", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_XA_TMSTARTRSCAN, "XA TM Flags STARTRSCAN", HFILL}},
        {&hf_mq_xa_tmflags_suspend, {"SUSPEND", "mq.xa.tmflags.suspend", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_XA_TMSUSPEND, "XA TM Flags SUSPEND", HFILL}},
        {&hf_mq_xa_tmflags_success, {"SUCCESS", "mq.xa.tmflags.success", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_XA_TMSUCCESS, "XA TM Flags SUCCESS", HFILL}},
        {&hf_mq_xa_tmflags_resume, {"RESUME", "mq.xa.tmflags.resume", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_XA_TMRESUME, "XA TM Flags RESUME", HFILL}},
        {&hf_mq_xa_tmflags_fail, {"FAIL", "mq.xa.tmflags.fail", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_XA_TMFAIL, "XA TM Flags FAIL", HFILL}},
        {&hf_mq_xa_tmflags_onephase, {"ONEPHASE", "mq.xa.tmflags.onephase", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_XA_TMONEPHASE, "XA TM Flags ONEPHASE", HFILL}},

        {&hf_mq_xa_xid_formatid, {"Format ID....", "mq.xa.xid.formatid", FT_STRING, BASE_NONE, NULL, 0x0, "XA Xid Format ID", HFILL}},
        {&hf_mq_xa_xid_glbxid_len, {"GlbTransIDLen", "mq.xa.xid.gxidl", FT_UINT8, BASE_DEC, NULL, 0x0, "XA Xid Global TransactionId Length", HFILL}},
        {&hf_mq_xa_xid_brq_length, {"BranchQualLen", "mq.xa.xid.bql", FT_UINT8, BASE_DEC, NULL, 0x0, "XA Xid Branch Qualifier Length", HFILL}},
        {&hf_mq_xa_xid_globalxid, {"GlbTransactID", "mq.xa.xid.gxid", FT_BYTES, BASE_NONE, NULL, 0x0, "XA Xid Global TransactionId", HFILL}},
        {&hf_mq_xa_xid_brq, {"BranchQualif.", "mq.xa.xid.bq", FT_BYTES, BASE_NONE, NULL, 0x0, "XA Xid Branch Qualifier", HFILL}},
        {&hf_mq_xa_xainfo_length, {"Length.......", "mq.xa.xainfo.length", FT_UINT8, BASE_DEC, NULL, 0x0, "XA XA_info Length", HFILL}},
        {&hf_mq_xa_xainfo_value, {"Value........", "mq.xa.xainfo.value", FT_STRING, BASE_NONE, NULL, 0x0, "XA XA_info Value", HFILL}},

        {&hf_mq_charv_vsptr, {"VLStr Addr.", "mq.charv.vsptr", FT_UINT32, BASE_HEX, NULL, 0x0, "VS Address", HFILL}},
        {&hf_mq_charv_vsoffset, {"VLStr Offs.", "mq.charv.vsoffset", FT_UINT32, BASE_DEC, NULL, 0x0, "VS Offset", HFILL}},
        {&hf_mq_charv_vsbufsize, {"VLStr BufSz", "mq.charv.vsbufsize", FT_UINT32, BASE_DEC, NULL, 0x0, "VS BufSize", HFILL}},
        {&hf_mq_charv_vslength, {"VLStr Len..", "mq.charv.vslength", FT_UINT32, BASE_DEC, NULL, 0x0, "VS Length", HFILL}},
        {&hf_mq_charv_vsccsid, {"VLStr Ccsid", "mq.charv.vsccsid", FT_INT32, BASE_DEC, NULL, 0x0, "VS CCSID", HFILL}},
        {&hf_mq_charv_vsvalue, {"VLStr Value", "mq.charv.vsvalue", FT_STRING, BASE_NONE, NULL, 0x0, "VS value", HFILL}},

        {&hf_mq_head_StructID, {"Structid", "mq.head.structid", FT_STRING, BASE_NONE, NULL, 0x0, "Header structid", HFILL}},
        {&hf_mq_head_version, {"version.", "mq.head.version", FT_UINT32, BASE_DEC, NULL, 0x0, "Header version", HFILL}},
        {&hf_mq_head_length, {"Length..", "mq.head.length", FT_UINT32, BASE_DEC, NULL, 0x0, "Header length", HFILL}},
        {&hf_mq_head_encoding, {"Encoding", "mq.head.encoding", FT_UINT32, BASE_DEC, NULL, 0x0, "Header encoding", HFILL}},
        {&hf_mq_head_ccsid, {"CCSID...", "mq.head.ccsid", FT_INT32, BASE_DEC | BASE_RANGE_STRING, RVALS(GET_VALRV(ccsid)), 0x0, "Header character set", HFILL}},
        {&hf_mq_head_format, {"Format..", "mq.head.format", FT_STRING, BASE_NONE, NULL, 0x0, "Header format", HFILL}},

        {&hf_mq_head_flags, {"Flags...", "mq.head.flags", FT_UINT32, BASE_HEX, NULL, 0x0, "Header flags", HFILL}},
        {&hf_mq_head_struct, {"Struct..", "mq.head.struct", FT_BYTES, BASE_NONE, NULL, 0x0, "Header struct", HFILL}},

        {&hf_mq_dh_flags_newmsgid, {"NEW_MSG_IDS", "mq.dh.flags.newmsgid", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQIIH_CM0_REQUEST_RESPONSE, "MQ DH Flags MQDHF_NEW_MSG_IDS", HFILL}},

        {&hf_mq_dh_putmsgrecfld, {"Flags PMR", "mq.dh.flagspmr", FT_UINT32, BASE_DEC, NULL, 0x0, "DH flags PMR", HFILL}},
        {&hf_mq_dh_recspresent, {"NumOfRecs", "mq.dh.nbrrec", FT_UINT32, BASE_DEC, NULL, 0x0, "DH number of records", HFILL}},
        {&hf_mq_dh_objrecofs, {"Ofs1stOR.", "mq.dh.offsetor", FT_UINT32, BASE_DEC, NULL, 0x0, "DH offset of first OR", HFILL}},
        {&hf_mq_dh_putmsgrecofs, {"Ofs1stPMR", "mq.dh.offsetpmr", FT_UINT32, BASE_DEC, NULL, 0x0, "DH offset of first PMR", HFILL}},

        {&hf_mq_iih_flags_cmqrqstresp, {"CMO_RQST_RESP", "mq.iih.flags.cmqrqstresp", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQIIH_CM0_REQUEST_RESPONSE, "MQ IIH Flags CM0_REQUEST_RESPONSE", HFILL}},
        {&hf_mq_iih_flags_ignorepurg, {"IGNORE_PURG..", "mq.iih.flags.ignorepurg", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQIIH_IGNORE_PURG, "MQ IIH Flags IGNORE_PURG", HFILL}},
        {&hf_mq_iih_flags_replyfmtnone, {"REPL_FMT_NONE", "mq.iih.flags.replyfmtnone", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQIIH_REPLY_FORMAT_NONE, "MQ IIH Flags REPLY_FORMAT_NONE", HFILL}},
        {&hf_mq_iih_flags_passexpir, {"PASS_EXPIR...", "mq.iih.flags.passexpir", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQIIH_PASS_EXPIRATION, "MQ IIH Flags PASS_EXPIRATION", HFILL}},

        {&hf_mq_iih_ltermoverride, {"LTerm Override", "mq.iih.ltermoverrid", FT_STRING, BASE_NONE, NULL, 0x0, "Logical Terminal Override", HFILL}},
        {&hf_mq_iih_mfsmapname, {"MFS Map Name..", "mq.iih.mfsmapname", FT_STRING, BASE_NONE, NULL, 0x0, "MFS Map Name", HFILL}},
        {&hf_mq_iih_replytofmt, {"ReplyToFormat.", "mq.iih.replytofmt", FT_STRING, BASE_NONE, NULL, 0x0, "Reply To Format", HFILL}},
        {&hf_mq_iih_authenticator, {"Authenticator.", "mq.iih.authenticator", FT_STRING, BASE_NONE, NULL, 0x0, "Password or Passcode", HFILL}},
        {&hf_mq_iih_transinstid, {"TransInstIdent", "mq.iih.transinstid", FT_BYTES, BASE_NONE, NULL, 0x0, "Transaction Instance Identifier", HFILL}},
        {&hf_mq_iih_transstate, {"TransactState.", "mq.iih.transstate", FT_STRING, BASE_NONE, NULL, 0x0, "Transaction State", HFILL}},
        {&hf_mq_iih_commimode, {"Commit Mode...", "mq.iih.commimode", FT_STRING, BASE_NONE, NULL, 0x0, "Commit Mode", HFILL}},
        {&hf_mq_iih_securityscope, {"SecurityScope.", "mq.iih.securityscope", FT_STRING, BASE_NONE, NULL, 0x0, "Security Scope", HFILL}},
        {&hf_mq_iih_reserved, {"Reserved......", "mq.iih.reserved", FT_STRING, BASE_NONE, NULL, 0x0, "Reserved", HFILL}},

        {&hf_mq_cih_flags_synconret, {"SYNC_ON_RETURN", "mq.iih.flags.synconret", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQCIH_SYNC_ON_RETURN, "MQ CIH Flags IGNORE_PURG", HFILL}},
        {&hf_mq_cih_flags_replywonulls, {"REPLY_WO_NULLS", "mq.iih.flags.replywonulls", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQCIH_REPLY_WITHOUT_NULLS, "MQ CIH Flags REPLY_WITHOUT_NULLS", HFILL}},
        {&hf_mq_cih_flags_passexpir, {"PASS_EXPIR....", "mq.iih.flags.passexpir", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQCIH_PASS_EXPIRATION, "MQ CIH Flags PASS_EXPIRATION", HFILL}},

        {&hf_mq_ims_ll, {"ll..", "mq.ims.ll", FT_UINT16, BASE_DEC, NULL, 0x0, "IMS ll", HFILL}},
        {&hf_mq_ims_zz, {"zz..", "mq.ims.zz", FT_UINT16, BASE_DEC, NULL, 0x0, "IMS zz", HFILL}},
        {&hf_mq_ims_trx, {"trx.", "mq.ims.trx", FT_STRING, BASE_NONE, NULL, 0x0, "IMS Transaction", HFILL}},
        {&hf_mq_ims_data, {"data", "mq.ims.data", FT_BYTES, BASE_NONE, NULL, 0x0, "Transaction Instance Identifier", HFILL}},

        {&hf_mq_tm_StructID, {"Structid", "mq.tm.structid", FT_STRING, BASE_NONE, NULL, 0x0, "TM structid", HFILL}},
        {&hf_mq_tm_version, {"version.", "mq.tm.version", FT_UINT32, BASE_DEC, NULL, 0x0, "TM version", HFILL}},
        {&hf_mq_tm_QName, {"QName...", "mq.tm.qname", FT_STRING, BASE_NONE, NULL, 0x0, "TM Queue Name", HFILL}},
        {&hf_mq_tm_ProcessNme, {"ProcName", "mq.tm.procname", FT_STRING, BASE_NONE, NULL, 0x0, "TM Process Name", HFILL}},
        {&hf_mq_tm_TriggerData, {"TrigData", "mq.tm.triggerdata", FT_STRING, BASE_NONE, NULL, 0x0, "TM Trigger Data", HFILL}},
        {&hf_mq_tm_ApplType, {"ApplType", "mq.tm.appltype", FT_UINT32, BASE_DEC | BASE_EXT_STRING, GET_VALS_EXTP(MQAT), 0x0, "TM Application Type", HFILL}},
        {&hf_mq_tm_ApplId, {"ApplId..", "mq.tm.applid", FT_STRING, BASE_NONE, NULL, 0x0, "TM Application ID", HFILL}},
        {&hf_mq_tm_EnvData, {"EnvData.", "mq.tm.envdaqta", FT_STRING, BASE_NONE, NULL, 0x0, "TM Environment Data", HFILL}},
        {&hf_mq_tm_UserData, {"UserData.", "mq.t2.userdata", FT_STRING, BASE_NONE, NULL, 0x0, "TM User Data", HFILL}},

        {&hf_mq_tmc2_StructID, {"Structid", "mq.tmc2.structid", FT_STRING, BASE_NONE, NULL, 0x0, "TMC2 structid", HFILL}},
        {&hf_mq_tmc2_version, {"version.", "mq.tmc2.version", FT_STRING, BASE_NONE, NULL, 0x0, "TMC2 version", HFILL}},
        {&hf_mq_tmc2_QName, {"QName...", "mq.tmc2.qname", FT_STRING, BASE_NONE, NULL, 0x0, "TMC2 Queue Name", HFILL}},
        {&hf_mq_tmc2_ProcessNme, {"ProcName", "mq.tmc2.procname", FT_STRING, BASE_NONE, NULL, 0x0, "TMC2 Process Name", HFILL}},
        {&hf_mq_tmc2_TriggerData, {"TrigData", "mq.tmc2.triggerdata", FT_STRING, BASE_NONE, NULL, 0x0, "TMC2 Trigger Data", HFILL}},
        {&hf_mq_tmc2_ApplType, {"ApplType", "mq.tmc2.appltype", FT_STRING, BASE_NONE, NULL, 0x0, "TMC2 Application Type", HFILL}},
        {&hf_mq_tmc2_ApplId, {"ApplId..", "mq.tmc2.applid", FT_STRING, BASE_NONE, NULL, 0x0, "TMC2 Application ID", HFILL}},
        {&hf_mq_tmc2_EnvData, {"EnvData.", "mq.tmc2.envdaqta", FT_STRING, BASE_NONE, NULL, 0x0, "TMC2 Environment Data", HFILL}},
        {&hf_mq_tmc2_UserData, {"UserData", "mq.tmc2.userdata", FT_STRING, BASE_NONE, NULL, 0x0, "TMC2 User Data", HFILL}},
        {&hf_mq_tmc2_QMgrName, {"QMgrName", "mq.tmc2.qmgrname", FT_STRING, BASE_NONE, NULL, 0x0, "TMC2 Queue Manager Name", HFILL}},

        {&hf_mq_cih_returncode, {"ReturnCode...", "mq.cih.returncode", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "Return Code", HFILL}},
        {&hf_mq_cih_compcode, {"ComplCode....", "mq.cih.compcode", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "Completion Code", HFILL}},
        {&hf_mq_cih_reasoncode, {"ReasonCode...", "mq.cih.reasoncode", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "Reason Code", HFILL}},
        {&hf_mq_cih_uowcontrols, {"UOWControls..", "mq.cih.uowcontrols", FT_UINT32, BASE_HEX_DEC, VALS(GET_VALSV(UOWControls)), 0x0, "Unit Of Work Controls", HFILL}},
        {&hf_mq_cih_getwaitintv, {"GetWaitIntv..", "mq.cih.getwaitintv", FT_INT32, BASE_DEC | BASE_RANGE_STRING, RVALS(GET_VALRV(WaitIntv)), 0x0, "Get Wait Interval", HFILL}},
        {&hf_mq_cih_linktype, {"LinkType.....", "mq.cih.linktype", FT_UINT32, BASE_DEC, VALS(GET_VALSV(LinkType)), 0x0, "LinkType", HFILL}},
        {&hf_mq_cih_outdatalen, {"OutDataLen...", "mq.cih.outdatalen", FT_INT32, BASE_DEC | BASE_RANGE_STRING, RVALS(GET_VALRV(OutDataLen)), 0x0, "Output Data Len", HFILL}},
        {&hf_mq_cih_facilkeeptime, {"FacilKeepTime", "mq.cih.facilkeeptime", FT_UINT32, BASE_DEC, NULL, 0x0, "Facility Keep Time", HFILL}},
        {&hf_mq_cih_adsdescriptor, {"ADSDescriptor", "mq.cih.adsdescr", FT_UINT32, BASE_DEC, VALS(GET_VALSV(ADSDescr)), 0x0, "ADS Descriptor", HFILL}},
        {&hf_mq_cih_converstask, {"ConversTask..", "mq.cih.converstask", FT_UINT32, BASE_DEC, VALS(GET_VALSV(ConvTaskOpt)), 0x0, "Conversational Task", HFILL}},
        {&hf_mq_cih_taskendstatus, {"TaskEndStatus", "mq.cih.taskendstatus", FT_UINT32, BASE_DEC, VALS(GET_VALSV(TaskEndStatus)), 0x0, "Status at End of Task", HFILL}},
        {&hf_mq_cih_bridgefactokn, {"BridgeFacTokn", "mq.cih.bridgefactokn", FT_BYTES, BASE_NONE, NULL, 0x0, "Bridge facility token", HFILL}},
        {&hf_mq_cih_function, {"Function.....", "mq.cih.function", FT_STRING, BASE_NONE, NULL, 0x0, "MQ call name or CICS EIBFN function", HFILL}},
        {&hf_mq_cih_abendcode, {"AbendCode....", "mq.cih.abendcode", FT_STRING, BASE_NONE, NULL, 0x0, "Abend Code", HFILL}},
        {&hf_mq_cih_authenticator, {"Authenticator", "mq.cih.authenticator", FT_STRING, BASE_NONE, NULL, 0x0, "Password or Passcode", HFILL}},
        {&hf_mq_cih_reserved, {"Reserved.....", "mq.cih.reserved", FT_STRING, BASE_NONE, NULL, 0x0, "Reserved", HFILL}},
        {&hf_mq_cih_replytofmt, {"ReplyToFormat", "mq.cih.replytofmt", FT_STRING, BASE_NONE, NULL, 0x0, "Reply To Format", HFILL}},
        {&hf_mq_cih_remotesysid, {"RemoteSysId..", "mq.cih.remotesysid", FT_STRING, BASE_NONE, NULL, 0x0, "Remote System Id", HFILL}},
        {&hf_mq_cih_remotetransid, {"RemoteTransId", "mq.cih.remotetransid", FT_STRING, BASE_NONE, NULL, 0x0, "Remote Transaction Id", HFILL}},
        {&hf_mq_cih_transactionid, {"TransactionId", "mq.cih.transactionid", FT_STRING, BASE_NONE, NULL, 0x0, "Transaction to attach", HFILL}},
        {&hf_mq_cih_facilitylike, {"FacilityLike.", "mq.cih.facilitylike", FT_STRING, BASE_NONE, NULL, 0x0, "Terminal emulated attributes", HFILL}},
        {&hf_mq_cih_attentionid, {"AttentionID..", "mq.cih.attentionid", FT_STRING, BASE_NONE, NULL, 0x0, "Attention Id (AID) Key", HFILL}},
        {&hf_mq_cih_startcode, {"StartCode....", "mq.cih.startcode", FT_STRING, BASE_NONE, NULL, 0x0, "Transaction Start Code", HFILL}},
        {&hf_mq_cih_cancelcode, {"CancelCode...", "mq.cih.cancelcode", FT_STRING, BASE_NONE, NULL, 0x0, "Abend transaction code", HFILL}},
        {&hf_mq_cih_nexttransid, {"NextTransId..", "mq.cih.nexttransid", FT_STRING, BASE_NONE, NULL, 0x0, "Next transaction to attach", HFILL}},
        {&hf_mq_cih_reserved2, {"Reserved2....", "mq.cih.reserved2", FT_STRING, BASE_NONE, NULL, 0x0, "Reserved 2", HFILL}},
        {&hf_mq_cih_reserved3, {"Reserved3....", "mq.cih.reserved3", FT_STRING, BASE_NONE, NULL, 0x0, "Reserved 3", HFILL}},
        {&hf_mq_cih_cursorpos, {"CursorPos....", "mq.cih.cursorpos", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, "Cursor Position", HFILL}},
        {&hf_mq_cih_erroroffset, {"ErrorOffset..", "mq.cih.erroroffset", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, "Offset of error in message", HFILL}},
        {&hf_mq_cih_inputitem, {"InputItem....", "mq.cih.inputitem", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, "Input Item", HFILL}},
        {&hf_mq_cih_reserved4, {"Reserved4....", "mq.cih.reserved4", FT_STRING, BASE_NONE, NULL, 0x0, "Reserved 4", HFILL}},

        {&hf_mq_rfh_ccsid, {"NmeValCCSID", "mq.rfh.ccsid", FT_INT32, BASE_DEC | BASE_RANGE_STRING, RVALS(GET_VALRV(ccsid)), 0x0, "RFH NameValue CCSID", HFILL}},
        {&hf_mq_rfh_length, {"Len.", "mq.rfh.length", FT_UINT32, BASE_DEC, NULL, 0x0, "RFH NameValue Length", HFILL}},
        {&hf_mq_rfh_string, {"Val.", "mq.rfh.string", FT_STRING, BASE_NONE, NULL, 0x0, "RFH NameValue", HFILL}},

        {&hf_mq_rmh_flags_last, {"LAST", "mq.rmh.flags.last", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQRMHF_LAST, "MQ RMH LAST", HFILL}},

        {&hf_mq_rmh_objecttype, {"ObjectType...", "mq.rmh.objecttype", FT_STRING, BASE_NONE, NULL, 0x0, "Object Type", HFILL}},
        {&hf_mq_rmh_objectinstid, {"ObjectInstId.", "mq.rmh.objectinstid", FT_BYTES, BASE_NONE, NULL, 0x0, "Object Instance Identifier", HFILL}},
        {&hf_mq_rmh_srcenvlen, {"SrcEnvLen....", "mq.rmh.srcenvlen", FT_UINT32, BASE_DEC, NULL, 0x0, "Length of source environment data", HFILL}},
        {&hf_mq_rmh_srcenvofs, {"SrcEnvOfs....", "mq.rmh.srcenvofs", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, "Offset of source environment data", HFILL}},
        {&hf_mq_rmh_srcnamelen, {"SrcNameLen...", "mq.rmh.srcnamelen", FT_UINT32, BASE_DEC, NULL, 0x0, "Length of source object name", HFILL}},
        {&hf_mq_rmh_srcnameofs, {"SrcNameOfs...", "mq.rmh.srcnameofs", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, "Offset of source object name", HFILL}},
        {&hf_mq_rmh_dstenvlen, {"DstEnvLen....", "mq.rmh.dstenvlen", FT_UINT32, BASE_DEC, NULL, 0x0, "Length of destination environment data", HFILL}},
        {&hf_mq_rmh_dstenvofs, {"DstEnvOfs....", "mq.rmh.dstenvofs", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, "Offset of destination environment data", HFILL}},
        {&hf_mq_rmh_dstnamelen, {"DstNameLen...", "mq.rmh.dstnamelen", FT_UINT32, BASE_DEC, NULL, 0x0, "Length of destination object name", HFILL}},
        {&hf_mq_rmh_dstnameofs, {"DstNameOfs...", "mq.rmh.dstnameofs", FT_UINT32, BASE_DEC | BASE_HEX, NULL, 0x0, "Offset of destination object name", HFILL}},
        {&hf_mq_rmh_datalogiclen, {"DataLogicLen.", "mq.rmh.datalogiclen", FT_UINT32, BASE_DEC, NULL, 0x0, "Length of bulk data", HFILL}},
        {&hf_mq_rmh_datalogicofsl, {"DataLogicOfsL", "mq.rmh.datalogicofsl", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, "Low offset of bulk data", HFILL}},
        {&hf_mq_rmh_datalogicofsh, {"DataLogicOfsH", "mq.rmh.datalogicofsh", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, "High offset of bulk data", HFILL}},

        {&hf_mq_wih_servicename, {"ServiceName..", "mq.wih.servicename", FT_STRING, BASE_NONE, NULL, 0x0, "Service Name", HFILL}},
        {&hf_mq_wih_servicestep, {"ServiceStep..", "mq.wih.servicestep", FT_STRING, BASE_NONE, NULL, 0x0, "Service Step Name", HFILL}},
        {&hf_mq_wih_msgtoken, {"MsgToken.....", "mq.wih.msgtoken", FT_BYTES, BASE_NONE, NULL, 0x0, "Message Token", HFILL}},
        {&hf_mq_wih_reserved, {"Reserved.....", "mq.wih.reserved", FT_STRING, BASE_NONE, NULL, 0x0, "Reserved", HFILL}},
    };

    static int* ett[] =
    {
        &ett_mq,
        &ett_mq_tsh,
        &ett_mq_tsh_tcf,
        &ett_mq_tsh_tcf2,
        &ett_mq_api,
        &ett_mq_socket,
        &ett_mq_msh,
        &ett_mq_caut,
        &ett_mq_xqh,
        &ett_mq_id,
        &ett_mq_id_cf1,
        &ett_mq_id_cf2,
        &ett_mq_id_cf3,
        &ett_mq_id_ecf1,
        &ett_mq_id_ecf2,
        &ett_mq_id_ecf3,
        &ett_mq_id_ief1,
        &ett_mq_id_ief2,
        &ett_mq_uid,
        &ett_mq_conn,
        &ett_mq_msg,
        &ett_mq_notif,
        &ett_mq_inq,
        &ett_mq_spi,
        &ett_mq_spi_base,
        &ett_mq_spi_options,
        &ett_mq_put,
        &ett_mq_open,
        &ett_mq_open_option,
        &ett_mq_close_option,
        &ett_mq_ping,
        &ett_mq_reset,
        &ett_mq_status,
        &ett_mq_od,
        &ett_mq_od_objstr,
        &ett_mq_od_selstr,
        &ett_mq_od_resobjstr,
        &ett_mq_or,
        &ett_mq_rr,
        &ett_mq_pmr,
        &ett_mq_md,
        &ett_mq_dlh,
        &ett_mq_dh,
        &ett_mq_gmo,
        &ett_mq_gmo_option,
        &ett_mq_gmo_matchoption,
        &ett_mq_msgreq_RqstFlags,
        &ett_mq_pmo,
        &ett_mq_pmo_option,
        &ett_mq_fcno,
        &ett_mq_fopa,
        &ett_mq_fcmi,
        &ett_mq_lpoo,
        &ett_mq_lpoo_lpiopts,
        &ett_mq_head,
        &ett_mq_head_flags,
        &ett_mq_ims,
        &ett_mq_xa,
        &ett_mq_xa_tmflags,
        &ett_mq_xa_xid,
        &ett_mq_xa_info,
        &ett_mq_charv,
        &ett_mq_rfh_ValueName,
        &ett_mq_reassemb,
        &ett_mq_structid
    };

    module_t* mq_module;
    expert_module_t* expert_mq;

    static ei_register_info ei[] = {
        {&ei_mq_reassembly_error, {"mq.reassembly_error",
        PI_REASSEMBLE, PI_ERROR, "Reassembly error", EXPFILL}}
    };

    proto_mq = proto_register_protocol("WebSphere MQ", "MQ", "mq");
    proto_register_field_array(proto_mq, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_mq = expert_register_protocol(proto_mq);
    expert_register_field_array(expert_mq, ei, array_length(ei));

    mq_heur_subdissector_list = register_heur_dissector_list_with_description("mq", "WebSphere MQ data", proto_mq);

    reassembly_table_register(&mq_reassembly_table,
        &addresses_reassembly_table_functions);

    mq_module = prefs_register_protocol(proto_mq, NULL);
    mq_handle = register_dissector("mq", dissect_mq_tcp, proto_mq);
    mq_spx_handle = register_dissector("mq.spx", dissect_mq_spx, proto_mq);


    prefs_register_bool_preference(mq_module, "desegment",
        "Reassemble MQ messages spanning multiple TCP segments",
        "Whether the MQ dissector should reassemble messages spanning multiple TCP segments."
        " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
        &mq_desegment);
    prefs_register_bool_preference(mq_module, "reassembly",
        "Reassemble segmented MQ messages",
        "Whether the MQ dissector should reassemble MQ messages spanning multiple TSH segments",
        &mq_reassembly);
}

void proto_reg_handoff_mq(void)
{
    /*  Unlike some protocol (HTTP, POP3, ...) that clearly map to a standard
    *  class of applications (web browser, e-mail client, ...) and have a very well
    *  known port number, the MQ applications are most often specific to a business application */

    dissector_add_for_decode_as_with_preference("tcp.port", mq_handle);
    ssl_dissector_add(0, mq_handle);
    heur_dissector_add("tcp", dissect_mq_heur_tcp, "WebSphere MQ over TCP", "mq_tcp", proto_mq, HEURISTIC_ENABLE);
    heur_dissector_add("netbios", dissect_mq_heur_nontcp, "WebSphere MQ over Netbios", "mq_netbios", proto_mq, HEURISTIC_ENABLE);
    heur_dissector_add("http", dissect_mq_heur_nontcp, "WebSphere MQ over HTTP", "mq_http", proto_mq, HEURISTIC_ENABLE);
    heur_dissector_add("tls", dissect_mq_heur_ssl, "WebSphere MQ over TLS", "mq_tls", proto_mq, HEURISTIC_ENABLE);
    dissector_add_uint("spx.socket", MQ_SOCKET_SPX, mq_spx_handle);
    mqpcf_handle = find_dissector("mqpcf");
}

/*
 * Editor modelines - https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
