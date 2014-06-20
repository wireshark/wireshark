/* packet-mq.c
 * Routines for IBM WebSphere MQ packet dissection
 *
 * metatech <metatechbe@gmail.com>
 * robionekenobi <robionekenobi@bluewin.ch>
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
 *   MQ API documentation is called "WebSphere MQ Application Programming Reference"
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

#include <glib.h>
#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/conversation.h>
#include <epan/reassemble.h>

#include <epan/dissectors/packet-windows-common.h>
#include <epan/dissectors/packet-dcerpc.h>
#include <epan/expert.h>
#include <epan/dissector_filters.h>
#include <epan/show_exception.h>

#include <epan/prefs.h>
#include <epan/wmem/wmem.h>
#include <epan/strutil.h>

#include "packet-tcp.h"
#include "packet-mq.h"

void proto_register_mq(void);
void proto_reg_handoff_mq(void);

static int proto_mq = -1;
static int hf_mq_tsh_StructID = -1;
static int hf_mq_tsh_mqseglen = -1;
static int hf_mq_tsh_convid = -1;
static int hf_mq_tsh_requestid = -1;
static int hf_mq_tsh_byteorder = -1;
static int hf_mq_tsh_opcode = -1;
static int hf_mq_tsh_ctlflgs1 = -1;

static int hf_mq_tsh_ctlflgs2 = -1;
static int hf_mq_tsh_luwid = -1;
static int hf_mq_tsh_encoding = -1;

static int hf_mq_tsh_ccsid = -1;
static int hf_mq_tsh_reserved = -1;

/* Transmission Segment Control Flags 1 */
static int hf_mq_tsh_tcf_confirmreq = -1;
static int hf_mq_tsh_tcf_error = -1;
static int hf_mq_tsh_tcf_reqclose = -1;
static int hf_mq_tsh_tcf_closechann = -1;
static int hf_mq_tsh_tcf_first = -1;
static int hf_mq_tsh_tcf_last = -1;
static int hf_mq_tsh_tcf_reqacc = -1;
static int hf_mq_tsh_tcf_dlq = -1;
static const int *pf_flds_tcf[] =
{
    &hf_mq_tsh_tcf_dlq       ,
    &hf_mq_tsh_tcf_reqacc    ,
    &hf_mq_tsh_tcf_last      ,
    &hf_mq_tsh_tcf_first     ,
    &hf_mq_tsh_tcf_closechann,
    &hf_mq_tsh_tcf_reqclose  ,
    &hf_mq_tsh_tcf_error     ,
    &hf_mq_tsh_tcf_confirmreq,
    NULL
};

/* Transmission Segment Control Flags 2 */
static int hf_mq_tsh_tcf2_HdrComp  = -1;
static int hf_mq_tsh_tcf2_MsgComp  = -1;
static int hf_mq_tsh_tcf2_CSH      = -1;
static int hf_mq_tsh_tcf2_CmitIntv = -1;
static const int *pf_flds_tcf2[] =
{
    &hf_mq_tsh_tcf2_CmitIntv,
    &hf_mq_tsh_tcf2_CSH     ,
    &hf_mq_tsh_tcf2_MsgComp ,
    &hf_mq_tsh_tcf2_HdrComp ,
    NULL
};

static int hf_mq_api_replylen = -1;
static int hf_mq_api_compcode = -1;
static int hf_mq_api_reascode = -1;
static int hf_mq_api_objecthdl = -1;
static int hf_mq_socket_conversid = -1;
static int hf_mq_socket_requestid = -1;
static int hf_mq_socket_type = -1;
static int hf_mq_socket_parm1 = -1;
static int hf_mq_socket_parm2 = -1;
static int hf_mq_msh_StructID = -1;
static int hf_mq_msh_seqnum = -1;
static int hf_mq_msh_datalength = -1;
static int hf_mq_msh_unknown1 = -1;
static int hf_mq_msh_msglength = -1;
static int hf_mq_xqh_StructID = -1;
static int hf_mq_xqh_version = -1;
static int hf_mq_xqh_remoteq = -1;
static int hf_mq_xqh_remoteqmgr = -1;

static int hf_mq_id_StructID = -1;
static int hf_mq_id_FapLevel = -1;
static int hf_mq_id_icf1 = -1;
static int hf_mq_id_Eicf1 = -1;
static int hf_mq_id_ief1 = -1;
static int hf_mq_id_Reserved = -1;
static int hf_mq_id_MaxMsgBatch = -1;
static int hf_mq_id_MaxTrSize = -1;
static int hf_mq_id_MaxMsgSize = -1;
static int hf_mq_id_SeqWrapVal = -1;
static int hf_mq_id_channel = -1;
static int hf_mq_id_icf2 = -1;
static int hf_mq_id_Eicf2 = -1;
static int hf_mq_id_ccsid = -1;
static int hf_mq_id_qmgrname = -1;
static int hf_mq_id_HBInterval = -1;
static int hf_mq_id_EFLLength = -1;
static int hf_mq_id_ief2 = -1;
static int hf_mq_id_Reserved1 = -1;
static int hf_mq_id_HdrCprsLst = -1;
static int hf_mq_id_MsgCprsLst = -1;
static int hf_mq_id_Reserved2 = -1;
static int hf_mq_id_SSLKeyRst = -1;
static int hf_mq_id_ConvBySkt = -1;
static int hf_mq_id_icf3 = -1;
static int hf_mq_id_Eicf3 = -1;
static int hf_mq_id_Reserved3 = -1;
static int hf_mq_id_ProcessId = -1;
static int hf_mq_id_ThreadId = -1;
static int hf_mq_id_TraceId = -1;
static int hf_mq_id_ProdId = -1;
static int hf_mq_id_mqmid = -1;

/* Initial Data Capability Flag 1 */
static int hf_mq_id_icf1_msgseq = -1;
static int hf_mq_id_icf1_convcap = -1;
static int hf_mq_id_icf1_splitmsg = -1;
static int hf_mq_id_icf1_RqstInit = -1;
static int hf_mq_id_icf1_RqstSecu = -1;
static int hf_mq_id_icf1_mqreq = -1;
static int hf_mq_id_icf1_svrsec = -1;
static int hf_mq_id_icf1_runtime = -1;
static const int *pf_flds_icf1[] =
{
    &hf_mq_id_icf1_runtime ,
    &hf_mq_id_icf1_svrsec  ,
    &hf_mq_id_icf1_mqreq   ,
    &hf_mq_id_icf1_RqstSecu,
    &hf_mq_id_icf1_RqstInit,
    &hf_mq_id_icf1_splitmsg,
    &hf_mq_id_icf1_convcap ,
    &hf_mq_id_icf1_msgseq  ,
    NULL
};

/* Initial Data Error Flag 1 */
static int hf_mq_id_ief1_ccsid = -1;
static int hf_mq_id_ief1_enc = -1;
static int hf_mq_id_ief1_mxtrsz = -1;
static int hf_mq_id_ief1_fap = -1;
static int hf_mq_id_ief1_mxmsgsz = -1;
static int hf_mq_id_ief1_mxmsgpb = -1;
static int hf_mq_id_ief1_seqwrap = -1;
static int hf_mq_id_ief1_hbint = -1;
static const int *pf_flds_ief1[] =
{
    &hf_mq_id_ief1_hbint  ,
    &hf_mq_id_ief1_seqwrap,
    &hf_mq_id_ief1_mxmsgpb,
    &hf_mq_id_ief1_mxmsgsz,
    &hf_mq_id_ief1_fap    ,
    &hf_mq_id_ief1_mxtrsz ,
    &hf_mq_id_ief1_enc    ,
    &hf_mq_id_ief1_ccsid  ,
    NULL
};

/* Initial Data Capability Flag 2 */
static int hf_mq_id_icf2_CanDstLst = -1;
static int hf_mq_id_icf2_FstMsgReq = -1;
static int hf_mq_id_icf2_RespConv  = -1;
static int hf_mq_id_icf2_XARequest = -1;
static int hf_mq_id_icf2_XARunTApp = -1;
static int hf_mq_id_icf2_SPIRqst   = -1;
static int hf_mq_id_icf2_DualUOW   = -1;
static int hf_mq_id_icf2_CanTrcRte = -1;
static const int *pf_flds_icf2[] =
{
    &hf_mq_id_icf2_CanTrcRte,
    &hf_mq_id_icf2_SPIRqst  ,
    &hf_mq_id_icf2_XARunTApp,
    &hf_mq_id_icf2_XARequest,
    &hf_mq_id_icf2_DualUOW  ,
    &hf_mq_id_icf2_RespConv ,
    &hf_mq_id_icf2_FstMsgReq,
    &hf_mq_id_icf2_CanDstLst,
    NULL
};

/* Initial Data Error Flag 2 */
static int hf_mq_id_ief2_HdrCmpLst = -1;
static int hf_mq_id_ief2_MsgCmpLst = -1;
static int hf_mq_id_ief2_SSLReset  = -1;
static const int *pf_flds_ief2[] =
{
    &hf_mq_id_ief2_HdrCmpLst,
    &hf_mq_id_ief2_MsgCmpLst,
    &hf_mq_id_ief2_SSLReset ,
    NULL
};

/* Initial Data Capability Flag 3 */
static int hf_mq_id_icf3_CanMsgPrp = -1;
static int hf_mq_id_icf3_Unknown02 = -1;
static const int *pf_flds_icf3[] =
{
    &hf_mq_id_icf3_Unknown02,
    &hf_mq_id_icf3_CanMsgPrp,
    NULL
};

static int hf_mq_uid_StructID = -1;
static int hf_mq_uid_userid = -1;
static int hf_mq_uid_password = -1;
static int hf_mq_uid_longuserid = -1;
static int hf_mq_sidlen = -1;
static int hf_mq_sidtyp = -1;
static int hf_mq_securityid = -1;

static int hf_mq_conn_QMgr = -1;
static int hf_mq_conn_appname = -1;
static int hf_mq_conn_apptype = -1;
static int hf_mq_conn_acttoken = -1;
static int hf_mq_conn_version = -1;
static int hf_mq_conn_options = -1;
static int hf_mq_fcno_StructID = -1;
static int hf_mq_fcno_msgid = -1;
static int hf_mq_fcno_mqmid = -1;
static int hf_mq_fcno_unknown00 = -1;
static int hf_mq_fcno_unknown01 = -1;
static int hf_mq_fcno_unknown02 = -1;

static int hf_mq_inq_nbsel = -1;
static int hf_mq_inq_nbint = -1;
static int hf_mq_inq_charlen = -1;
static int hf_mq_inq_sel = -1;
static int hf_mq_inq_intvalue = -1;
static int hf_mq_inq_charvalues = -1;

static int hf_mq_spi_verb = -1;
static int hf_mq_spi_version = -1;
static int hf_mq_spi_length = -1;
static int hf_mq_spi_base_StructID = -1;
static int hf_mq_spi_base_version = -1;
static int hf_mq_spi_base_length = -1;
static int hf_mq_spi_spqo_nbverb = -1;
static int hf_mq_spi_spqo_verbid = -1;
static int hf_mq_spi_spqo_maxiover = -1;
static int hf_mq_spi_spqo_maxinver = -1;
static int hf_mq_spi_spqo_maxouver = -1;
static int hf_mq_spi_spqo_flags = -1;
static int hf_mq_spi_spai_mode = -1;
static int hf_mq_spi_spai_unknown1 = -1;
static int hf_mq_spi_spai_unknown2 = -1;
static int hf_mq_spi_spai_msgid = -1;
static int hf_mq_spi_spgi_batchsz = -1;
static int hf_mq_spi_spgi_batchint = -1;
static int hf_mq_spi_spgi_maxmsgsz = -1;
static int hf_mq_spi_spgo_options = -1;
static int hf_mq_spi_spgo_size = -1;

static int hf_mq_spi_opt_blank = -1;
static int hf_mq_spi_opt_syncp = -1;
static int hf_mq_spi_opt_deferred = -1;
static const int *pf_flds_spiopt[] =
{
    &hf_mq_spi_opt_deferred,
    &hf_mq_spi_opt_syncp,
    &hf_mq_spi_opt_blank,
    NULL
};

static int hf_mq_put_length = -1;

static int hf_mq_close_options = -1;
static int hf_mq_close_options_DELETE                 = -1;
static int hf_mq_close_options_DELETE_PURGE           = -1;
static int hf_mq_close_options_KEEP_SUB               = -1;
static int hf_mq_close_options_REMOVE_SUB             = -1;
static int hf_mq_close_options_QUIESCE                = -1;
static const int *pf_flds_clsopt[] =
{
    &hf_mq_close_options_QUIESCE     ,
    &hf_mq_close_options_REMOVE_SUB  ,
    &hf_mq_close_options_KEEP_SUB    ,
    &hf_mq_close_options_DELETE_PURGE,
    &hf_mq_close_options_DELETE      ,
    NULL
};

static int hf_mq_open_options = -1;
static int hf_mq_open_options_INPUT_SHARED = -1;
static int hf_mq_open_options_INPUT_AS_Q_DEF = -1;
static int hf_mq_open_options_INPUT_EXCLUSIVE = -1;
static int hf_mq_open_options_BROWSE = -1;
static int hf_mq_open_options_OUTPUT = -1;
static int hf_mq_open_options_INQUIRE = -1;
static int hf_mq_open_options_SET = -1;
static int hf_mq_open_options_SAVE_ALL_CTX = -1;
static int hf_mq_open_options_PASS_IDENT_CTX = -1;
static int hf_mq_open_options_PASS_ALL_CTX = -1;
static int hf_mq_open_options_SET_IDENT_CTX = -1;
static int hf_mq_open_options_SET_ALL_CONTEXT = -1;
static int hf_mq_open_options_ALT_USER_AUTH = -1;
static int hf_mq_open_options_FAIL_IF_QUIESC = -1;
static int hf_mq_open_options_BIND_ON_OPEN = -1;
static int hf_mq_open_options_BIND_NOT_FIXED = -1;
static int hf_mq_open_options_RESOLVE_NAMES = -1;
static int hf_mq_open_options_CO_OP = -1;
static int hf_mq_open_options_RESOLVE_LOCAL_Q = -1;
static int hf_mq_open_options_NO_READ_AHEAD = -1;
static int hf_mq_open_options_READ_AHEAD = -1;
static int hf_mq_open_options_NO_MULTICAST = -1;
static int hf_mq_open_options_BIND_ON_GROUP = -1;
static const int *pf_flds_opnopt[] =
{
    &hf_mq_open_options_BIND_ON_GROUP  ,
    &hf_mq_open_options_NO_MULTICAST   ,
    &hf_mq_open_options_READ_AHEAD     ,
    &hf_mq_open_options_NO_READ_AHEAD  ,
    &hf_mq_open_options_RESOLVE_LOCAL_Q,
    &hf_mq_open_options_CO_OP          ,
    &hf_mq_open_options_RESOLVE_NAMES  ,
    &hf_mq_open_options_BIND_NOT_FIXED ,
    &hf_mq_open_options_BIND_ON_OPEN   ,
    &hf_mq_open_options_FAIL_IF_QUIESC ,
    &hf_mq_open_options_ALT_USER_AUTH  ,
    &hf_mq_open_options_SET_ALL_CONTEXT,
    &hf_mq_open_options_SET_IDENT_CTX  ,
    &hf_mq_open_options_PASS_ALL_CTX   ,
    &hf_mq_open_options_PASS_IDENT_CTX ,
    &hf_mq_open_options_SAVE_ALL_CTX   ,
    &hf_mq_open_options_SET            ,
    &hf_mq_open_options_INQUIRE        ,
    &hf_mq_open_options_OUTPUT         ,
    &hf_mq_open_options_BROWSE         ,
    &hf_mq_open_options_INPUT_EXCLUSIVE,
    &hf_mq_open_options_INPUT_SHARED   ,
    &hf_mq_open_options_INPUT_AS_Q_DEF ,
    NULL
};

static int hf_mq_fopa_StructID = -1;
static int hf_mq_fopa_version = -1;
static int hf_mq_fopa_length = -1;
static int hf_mq_fopa_unknown1 = -1;
static int hf_mq_fopa_unknown2 = -1;
static int hf_mq_fopa_unknown3 = -1;
static int hf_mq_fopa_qprotect = -1;
static int hf_mq_fopa_unknown4 = -1;
static int hf_mq_fopa_unknown5 = -1;

static int hf_mq_ping_length = -1;
static int hf_mq_ping_buffer = -1;
static int hf_mq_reset_length = -1;
static int hf_mq_reset_seqnum = -1;
static int hf_mq_status_length = -1;
static int hf_mq_status_code = -1;
static int hf_mq_status_value = -1;

static int hf_mq_caut_StructID = -1;
static int hf_mq_caut_AuthType = -1;
static int hf_mq_caut_UsrMaxLen = -1;
static int hf_mq_caut_PwdMaxLen = -1;
static int hf_mq_caut_UsrLength = -1;
static int hf_mq_caut_PwdLength = -1;
static int hf_mq_caut_usr = -1;
static int hf_mq_caut_psw = -1;

static int hf_mq_od_StructID = -1;
static int hf_mq_od_version = -1;
static int hf_mq_od_objecttype = -1;
static int hf_mq_od_objectname = -1;
static int hf_mq_od_objqmgrname = -1;
static int hf_mq_od_dynqname = -1;
static int hf_mq_od_altuserid = -1;
static int hf_mq_od_recspresent = -1;
static int hf_mq_od_knowndstcnt = -1;
static int hf_mq_od_unknowdstcnt = -1;
static int hf_mq_od_invaldstcnt = -1;
static int hf_mq_od_objrecofs = -1;
static int hf_mq_od_resprecofs = -1;
static int hf_mq_od_objrecptr = -1;
static int hf_mq_od_resprecptr = -1;
static int hf_mq_od_altsecurid = -1;
static int hf_mq_od_resolvqname = -1;
static int hf_mq_od_resolvqmgrnm = -1;
static int hf_mq_od_resolvobjtyp = -1;

static int hf_mq_or_objname = -1;
static int hf_mq_or_objqmgrname = -1;
static int hf_mq_rr_compcode = -1;
static int hf_mq_rr_reascode = -1;
static int hf_mq_pmr_msgid = -1;
static int hf_mq_pmr_correlid = -1;
static int hf_mq_pmr_groupid = -1;
static int hf_mq_pmr_feedback = -1;
static int hf_mq_pmr_acttoken = -1;
static int hf_mq_md_StructID = -1;
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
static int hf_mq_md_backoutcnt = -1;
static int hf_mq_md_replytoq = -1;
static int hf_mq_md_replytoqmgr = -1;
static int hf_mq_md_userid = -1;
static int hf_mq_md_acttoken = -1;
static int hf_mq_md_appliddata = -1;
static int hf_mq_md_putappltype = -1;
static int hf_mq_md_putapplname = -1;
static int hf_mq_md_putdate = -1;
static int hf_mq_md_puttime = -1;
static int hf_mq_md_apporigdata = -1;
static int hf_mq_md_groupid = -1;
static int hf_mq_md_msgseqnumber = -1;
static int hf_mq_md_offset = -1;
static int hf_mq_md_msgflags = -1;
static int hf_mq_md_origlen = -1;
static int hf_mq_dlh_StructID = -1;
static int hf_mq_dlh_version = -1;
static int hf_mq_dlh_reason = -1;
static int hf_mq_dlh_destq = -1;
static int hf_mq_dlh_destqmgr = -1;
static int hf_mq_dlh_encoding = -1;
static int hf_mq_dlh_ccsid = -1;
static int hf_mq_dlh_format = -1;
static int hf_mq_dlh_putappltype = -1;
static int hf_mq_dlh_putapplname = -1;
static int hf_mq_dlh_putdate = -1;
static int hf_mq_dlh_puttime = -1;

static int hf_mq_gmo_StructID = -1;
static int hf_mq_gmo_version = -1;
static int hf_mq_gmo_options = -1;
static int hf_mq_gmo_waitinterval = -1;
static int hf_mq_gmo_signal1 = -1;
static int hf_mq_gmo_signal2 = -1;
static int hf_mq_gmo_resolvqname = -1;
static int hf_mq_gmo_matchoptions = -1;
static int hf_mq_gmo_groupstatus = -1;
static int hf_mq_gmo_segmstatus = -1;
static int hf_mq_gmo_segmentation = -1;
static int hf_mq_gmo_reserved = -1;
static int hf_mq_gmo_msgtoken = -1;
static int hf_mq_gmo_returnedlen = -1;

static int hf_mq_gmo_options_PROPERTIES_COMPATIBILITY = -1;
static int hf_mq_gmo_options_PROPERTIES_IN_HANDLE = -1;
static int hf_mq_gmo_options_NO_PROPERTIES = -1;
static int hf_mq_gmo_options_PROPERTIES_FORCE_MQRFH2 = -1;
static int hf_mq_gmo_options_UNMARKED_BROWSE_MSG = -1;
static int hf_mq_gmo_options_UNMARK_BROWSE_HANDLE = -1;
static int hf_mq_gmo_options_UNMARK_BROWSE_CO_OP = -1;
static int hf_mq_gmo_options_MARK_BROWSE_CO_OP = -1;
static int hf_mq_gmo_options_MARK_BROWSE_HANDLE = -1;
static int hf_mq_gmo_options_ALL_SEGMENTS_AVAILABLE = -1;
static int hf_mq_gmo_options_ALL_MSGS_AVAILABLE = -1;
static int hf_mq_gmo_options_COMPLETE_MSG = -1;
static int hf_mq_gmo_options_LOGICAL_ORDER = -1;
static int hf_mq_gmo_options_CONVERT = -1;
static int hf_mq_gmo_options_FAIL_IF_QUIESCING = -1;
static int hf_mq_gmo_options_SYNCPOINT_IF_PERSISTENT = -1;
static int hf_mq_gmo_options_BROWSE_MSG_UNDER_CURSOR = -1;
static int hf_mq_gmo_options_UNLOCK = -1;
static int hf_mq_gmo_options_LOCK = -1;
static int hf_mq_gmo_options_MSG_UNDER_CURSOR = -1;
static int hf_mq_gmo_options_MARK_SKIP_BACKOUT = -1;
static int hf_mq_gmo_options_ACCEPT_TRUNCATED_MSG = -1;
static int hf_mq_gmo_options_BROWSE_NEXT = -1;
static int hf_mq_gmo_options_BROWSE_FIRST = -1;
static int hf_mq_gmo_options_SET_SIGNAL = -1;
static int hf_mq_gmo_options_NO_SYNCPOINT = -1;
static int hf_mq_gmo_options_SYNCPOINT = -1;
static int hf_mq_gmo_options_WAIT = -1;
static const int *pf_flds_gmoopt[] =
{
    &hf_mq_gmo_options_PROPERTIES_COMPATIBILITY,
    &hf_mq_gmo_options_PROPERTIES_IN_HANDLE    ,
    &hf_mq_gmo_options_NO_PROPERTIES           ,
    &hf_mq_gmo_options_PROPERTIES_FORCE_MQRFH2 ,
    &hf_mq_gmo_options_UNMARKED_BROWSE_MSG     ,
    &hf_mq_gmo_options_UNMARK_BROWSE_HANDLE    ,
    &hf_mq_gmo_options_UNMARK_BROWSE_CO_OP     ,
    &hf_mq_gmo_options_MARK_BROWSE_CO_OP       ,
    &hf_mq_gmo_options_MARK_BROWSE_HANDLE      ,
    &hf_mq_gmo_options_ALL_SEGMENTS_AVAILABLE  ,
    &hf_mq_gmo_options_ALL_MSGS_AVAILABLE      ,
    &hf_mq_gmo_options_COMPLETE_MSG            ,
    &hf_mq_gmo_options_LOGICAL_ORDER           ,
    &hf_mq_gmo_options_CONVERT                 ,
    &hf_mq_gmo_options_FAIL_IF_QUIESCING       ,
    &hf_mq_gmo_options_SYNCPOINT_IF_PERSISTENT ,
    &hf_mq_gmo_options_BROWSE_MSG_UNDER_CURSOR ,
    &hf_mq_gmo_options_UNLOCK                  ,
    &hf_mq_gmo_options_LOCK                    ,
    &hf_mq_gmo_options_MSG_UNDER_CURSOR        ,
    &hf_mq_gmo_options_MARK_SKIP_BACKOUT       ,
    &hf_mq_gmo_options_ACCEPT_TRUNCATED_MSG    ,
    &hf_mq_gmo_options_BROWSE_NEXT             ,
    &hf_mq_gmo_options_BROWSE_FIRST            ,
    &hf_mq_gmo_options_SET_SIGNAL              ,
    &hf_mq_gmo_options_NO_SYNCPOINT            ,
    &hf_mq_gmo_options_SYNCPOINT               ,
    &hf_mq_gmo_options_WAIT                    ,
    NULL
};

static int hf_mq_gmo_matchoptions_MATCH_MSG_TOKEN = -1;
static int hf_mq_gmo_matchoptions_MATCH_OFFSET = -1;
static int hf_mq_gmo_matchoptions_MATCH_MSG_SEQ_NUMBER = -1;
static int hf_mq_gmo_matchoptions_MATCH_GROUP_ID = -1;
static int hf_mq_gmo_matchoptions_MATCH_CORREL_ID = -1;
static int hf_mq_gmo_matchoptions_MATCH_MSG_ID = -1;
static const int *pf_flds_mtchopt[] =
{
    &hf_mq_gmo_matchoptions_MATCH_MSG_TOKEN     ,
    &hf_mq_gmo_matchoptions_MATCH_OFFSET        ,
    &hf_mq_gmo_matchoptions_MATCH_MSG_SEQ_NUMBER,
    &hf_mq_gmo_matchoptions_MATCH_GROUP_ID      ,
    &hf_mq_gmo_matchoptions_MATCH_CORREL_ID     ,
    &hf_mq_gmo_matchoptions_MATCH_MSG_ID        ,
    NULL
};

static int hf_mq_lpoo_StructID = -1;
static int hf_mq_lpoo_version = -1;
static int hf_mq_lpoo_options = -1;
static int hf_mq_lpoo_lpiopts = -1;
static int hf_mq_lpoo_defpersist = -1;
static int hf_mq_lpoo_defputresptype = -1;
static int hf_mq_lpoo_defreadahead = -1;
static int hf_mq_lpoo_qprotect = -1;
static int hf_mq_lpoo_unknown6 = -1;
/*static int hf_mq_lpoo_unknown7 = -1;*/
static int hf_mq_lpoo_xtradata = -1;

static int hf_mq_lpoo_lpiopts_SAVE_IDENTITY_CTXT = -1;
static int hf_mq_lpoo_lpiopts_SAVE_ORIGIN_CTXT = -1 ;
static int hf_mq_lpoo_lpiopts_SAVE_USER_CTXT = -1;
static const int *pf_flds_lpooopt[] =
{
    &hf_mq_lpoo_lpiopts_SAVE_IDENTITY_CTXT,
    &hf_mq_lpoo_lpiopts_SAVE_ORIGIN_CTXT,
    &hf_mq_lpoo_lpiopts_SAVE_USER_CTXT,
    NULL
};


static int hf_mq_charv_vsptr = -1;
static int hf_mq_charv_vsoffset = -1;
static int hf_mq_charv_vsbufsize = -1;
static int hf_mq_charv_vslength = -1;
static int hf_mq_charv_vsccsid = -1;
static int hf_mq_charv_vsvalue = -1;

static int hf_mq_pmo_StructID = -1;
static int hf_mq_pmo_version = -1;
static int hf_mq_pmo_options = -1;
static int hf_mq_pmo_timeout = -1;
static int hf_mq_pmo_context = -1;
static int hf_mq_pmo_knowndstcnt = -1;
static int hf_mq_pmo_unkndstcnt = -1;
static int hf_mq_pmo_invaldstcnt = -1;
static int hf_mq_pmo_resolvqname = -1;
static int hf_mq_pmo_resolvqmgr = -1;
static int hf_mq_pmo_recspresent = -1;
static int hf_mq_pmo_putmsgrecfld = -1;
static int hf_mq_pmo_putmsgrecofs = -1;
static int hf_mq_pmo_resprecofs = -1;
static int hf_mq_pmo_putmsgrecptr = -1;
static int hf_mq_pmo_resprecptr = -1;

static int hf_mq_xa_length = -1;
static int hf_mq_xa_returnvalue = -1;
static int hf_mq_xa_tmflags = -1;
static int hf_mq_xa_rmid = -1;
static int hf_mq_xa_count = -1;
static int hf_mq_xa_xid_formatid = -1;
static int hf_mq_xa_xid_glbxid_len = -1;
static int hf_mq_xa_xid_brq_length = -1;
static int hf_mq_xa_xid_globalxid = -1;
static int hf_mq_xa_xid_brq = -1;
static int hf_mq_xa_xainfo_length = -1;
static int hf_mq_xa_xainfo_value = -1;

static int hf_mq_pmo_options_NOT_OWN_SUBS = -1;
static int hf_mq_pmo_options_SUPPRESS_REPLYTO = -1;
static int hf_mq_pmo_options_SCOPE_QMGR = -1;
static int hf_mq_pmo_options_MD_FOR_OUTPUT_ONLY = -1;
static int hf_mq_pmo_options_RETAIN = -1;
static int hf_mq_pmo_options_WARN_IF_NO_SUBS_MATCHED = -1;
static int hf_mq_pmo_options_RESOLVE_LOCAL_Q = -1;
static int hf_mq_pmo_options_SYNC_RESPONSE = -1;
static int hf_mq_pmo_options_ASYNC_RESPONSE = -1;
static int hf_mq_pmo_options_LOGICAL_ORDER = -1;
static int hf_mq_pmo_options_NO_CONTEXT = -1;
static int hf_mq_pmo_options_FAIL_IF_QUIESCING = -1;
static int hf_mq_pmo_options_ALTERNATE_USER_AUTHORITY = -1;
static int hf_mq_pmo_options_SET_ALL_CONTEXT = -1;
static int hf_mq_pmo_options_SET_IDENTITY_CONTEXT = -1;
static int hf_mq_pmo_options_PASS_ALL_CONTEXT = -1;
static int hf_mq_pmo_options_PASS_IDENTITY_CONTEXT = -1;
static int hf_mq_pmo_options_NEW_CORREL_ID = -1;
static int hf_mq_pmo_options_NEW_MSG_ID = -1;
static int hf_mq_pmo_options_DEFAULT_CONTEXT = -1;
static int hf_mq_pmo_options_NO_SYNCPOINT = -1;
static int hf_mq_pmo_options_SYNCPOINT = -1;
static const int *pf_flds_pmoopt[] =
{
    &hf_mq_pmo_options_NOT_OWN_SUBS            ,
    &hf_mq_pmo_options_SUPPRESS_REPLYTO        ,
    &hf_mq_pmo_options_SCOPE_QMGR              ,
    &hf_mq_pmo_options_MD_FOR_OUTPUT_ONLY      ,
    &hf_mq_pmo_options_RETAIN                  ,
    &hf_mq_pmo_options_WARN_IF_NO_SUBS_MATCHED ,
    &hf_mq_pmo_options_RESOLVE_LOCAL_Q         ,
    &hf_mq_pmo_options_SYNC_RESPONSE           ,
    &hf_mq_pmo_options_ASYNC_RESPONSE          ,
    &hf_mq_pmo_options_LOGICAL_ORDER           ,
    &hf_mq_pmo_options_NO_CONTEXT              ,
    &hf_mq_pmo_options_FAIL_IF_QUIESCING       ,
    &hf_mq_pmo_options_ALTERNATE_USER_AUTHORITY,
    &hf_mq_pmo_options_SET_ALL_CONTEXT         ,
    &hf_mq_pmo_options_SET_IDENTITY_CONTEXT    ,
    &hf_mq_pmo_options_PASS_ALL_CONTEXT        ,
    &hf_mq_pmo_options_PASS_IDENTITY_CONTEXT   ,
    &hf_mq_pmo_options_NEW_CORREL_ID           ,
    &hf_mq_pmo_options_NEW_MSG_ID              ,
    &hf_mq_pmo_options_DEFAULT_CONTEXT         ,
    &hf_mq_pmo_options_NO_SYNCPOINT            ,
    &hf_mq_pmo_options_SYNCPOINT               ,
    NULL
};

static int hf_mq_xa_tmflags_join = -1;
static int hf_mq_xa_tmflags_endrscan = -1;
static int hf_mq_xa_tmflags_startrscan = -1;
static int hf_mq_xa_tmflags_suspend = -1;
static int hf_mq_xa_tmflags_success = -1;
static int hf_mq_xa_tmflags_resume = -1;
static int hf_mq_xa_tmflags_fail = -1;
static int hf_mq_xa_tmflags_onephase = -1;
static const int *pf_flds_tmflags[] =
{
    &hf_mq_xa_tmflags_onephase  ,
    &hf_mq_xa_tmflags_fail      ,
    &hf_mq_xa_tmflags_resume    ,
    &hf_mq_xa_tmflags_success   ,
    &hf_mq_xa_tmflags_suspend   ,
    &hf_mq_xa_tmflags_startrscan,
    &hf_mq_xa_tmflags_endrscan  ,
    &hf_mq_xa_tmflags_join      ,
    NULL
};

static int hf_mq_msgreq_version = -1;
static int hf_mq_msgreq_handle = -1;
static int hf_mq_msgreq_RecvBytes = -1;
static int hf_mq_msgreq_RqstBytes = -1;
static int hf_mq_msgreq_MaxMsgLen = -1;
static int hf_mq_msgreq_WaitIntrv = -1;
static int hf_mq_msgreq_QueStatus = -1;
static int hf_mq_msgreq_RqstFlags = -1;
static int hf_mq_msgreq_GlbMsgIdx = -1;
static int hf_mq_msgreq_SelectIdx = -1;
static int hf_mq_msgreq_MQMDVers = -1;
static int hf_mq_msgreq_ccsid = -1;
static int hf_mq_msgreq_encoding = -1;
static int hf_mq_msgreq_MsgSeqNum = -1;
static int hf_mq_msgreq_offset = -1;
static int hf_mq_msgreq_mtchMsgId = -1;
static int hf_mq_msgreq_mtchCorId = -1;
static int hf_mq_msgreq_mtchGrpid = -1;
static int hf_mq_msgreq_mtchMsgTk = -1;

static int hf_mq_msgasy_version = -1;
static int hf_mq_msgasy_handle = -1;
static int hf_mq_msgasy_MsgIndex = -1;
static int hf_mq_msgasy_GlbMsgIdx = -1;
static int hf_mq_msgasy_SegLength = -1;
static int hf_mq_msgasy_SeleIndex = -1;
static int hf_mq_msgasy_SegmIndex = -1;
static int hf_mq_msgasy_ReasonCod = -1;
static int hf_mq_msgasy_ActMsgLen = -1;
static int hf_mq_msgasy_TotMsgLen = -1;
static int hf_mq_msgasy_MsgToken = -1;
static int hf_mq_msgasy_Status = -1;
static int hf_mq_msgasy_resolQNLn = -1;
static int hf_mq_msgasy_resolQNme = -1;
static int hf_mq_msgasy_padding = -1;

static int hf_mq_notif_vers   = -1;
static int hf_mq_notif_handle = -1;
static int hf_mq_notif_code   = -1;
static int hf_mq_notif_value  = -1;

static int hf_mq_head_StructID = -1;
static int hf_mq_head_version = -1;
static int hf_mq_head_length = -1;
static int hf_mq_head_encoding = -1;
static int hf_mq_head_ccsid = -1;
static int hf_mq_head_format = -1;
static int hf_mq_head_flags = -1;
static int hf_mq_head_struct = -1;

static int hf_mq_dh_flags_newmsgid = -1;
static const int *pf_flds_dh_flags[] =
{
    &hf_mq_dh_flags_newmsgid,
    NULL
};
static int hf_mq_dh_putmsgrecfld = -1;
static int hf_mq_dh_recspresent = -1;
static int hf_mq_dh_objrecofs = -1;
static int hf_mq_dh_putmsgrecofs = -1;

static int hf_mq_iih_flags_passexpir    = -1;
static int hf_mq_iih_flags_replyfmtnone = -1;
static int hf_mq_iih_flags_ignorepurg   = -1;
static int hf_mq_iih_flags_cmqrqstresp  = -1;
static const int *pf_flds_iih_flags[] =
{
    &hf_mq_iih_flags_cmqrqstresp ,
    &hf_mq_iih_flags_ignorepurg  ,
    &hf_mq_iih_flags_replyfmtnone,
    &hf_mq_iih_flags_passexpir   ,
    NULL
};
static int hf_mq_iih_ltermoverride = -1;
static int hf_mq_iih_mfsmapname    = -1;
static int hf_mq_iih_replytofmt    = -1;
static int hf_mq_iih_authenticator = -1;
static int hf_mq_iih_transinstid   = -1;
static int hf_mq_iih_transstate    = -1;
static int hf_mq_iih_commimode     = -1;
static int hf_mq_iih_securityscope = -1;
static int hf_mq_iih_reserved      = -1;

static int hf_mq_cih_flags_synconret    = -1;
static int hf_mq_cih_flags_replywonulls = -1;
static int hf_mq_cih_flags_passexpir    = -1;
static const int *pf_flds_cih_flags[] =
{
    &hf_mq_cih_flags_synconret   ,
    &hf_mq_cih_flags_replywonulls,
    &hf_mq_cih_flags_passexpir   ,
    NULL
};
static int hf_mq_cih_returncode    = -1;
static int hf_mq_cih_compcode      = -1;
static int hf_mq_cih_reasoncode    = -1;
static int hf_mq_cih_uowcontrols   = -1;
static int hf_mq_cih_getwaitintv   = -1;
static int hf_mq_cih_linktype      = -1;
static int hf_mq_cih_outdatalen    = -1;
static int hf_mq_cih_facilkeeptime = -1;
static int hf_mq_cih_adsdescriptor = -1;
static int hf_mq_cih_converstask   = -1;
static int hf_mq_cih_taskendstatus = -1;
static int hf_mq_cih_bridgefactokn = -1;
static int hf_mq_cih_function      = -1;
static int hf_mq_cih_abendcode     = -1;
static int hf_mq_cih_authenticator = -1;
static int hf_mq_cih_reserved      = -1;
static int hf_mq_cih_replytofmt    = -1;
static int hf_mq_cih_remotesysid   = -1;
static int hf_mq_cih_remotetransid = -1;
static int hf_mq_cih_transactionid = -1;
static int hf_mq_cih_facilitylike  = -1;
static int hf_mq_cih_attentionid   = -1;
static int hf_mq_cih_startcode     = -1;
static int hf_mq_cih_cancelcode    = -1;
static int hf_mq_cih_nexttransid   = -1;
static int hf_mq_cih_reserved2     = -1;
static int hf_mq_cih_reserved3     = -1;
static int hf_mq_cih_cursorpos     = -1;
static int hf_mq_cih_erroroffset   = -1;
static int hf_mq_cih_inputitem     = -1;
static int hf_mq_cih_reserved4     = -1;

static int hf_mq_rmh_flags_last    = -1;
static const int *pf_flds_rmh_flags[] =
{
    &hf_mq_rmh_flags_last,
    NULL
};
static int hf_mq_rmh_objecttype    = -1;
static int hf_mq_rmh_objectinstid  = -1;
static int hf_mq_rmh_srcenvlen     = -1;
static int hf_mq_rmh_srcenvofs     = -1;
static int hf_mq_rmh_srcnamelen    = -1;
static int hf_mq_rmh_srcnameofs    = -1;
static int hf_mq_rmh_dstenvlen     = -1;
static int hf_mq_rmh_dstenvofs     = -1;
static int hf_mq_rmh_dstnamelen    = -1;
static int hf_mq_rmh_dstnameofs    = -1;
static int hf_mq_rmh_datalogiclen  = -1;
static int hf_mq_rmh_datalogicofsl = -1;
static int hf_mq_rmh_datalogicofsh = -1;

static int hf_mq_wih_servicename  = -1;
static int hf_mq_wih_servicestep  = -1;
static int hf_mq_wih_msgtoken     = -1;
static int hf_mq_wih_reserved     = -1;

static gint ett_mq = -1;
static gint ett_mq_tsh = -1;
static gint ett_mq_tsh_tcf = -1;
static gint ett_mq_tsh_tcf2 = -1;
static gint ett_mq_api = -1;
static gint ett_mq_socket = -1;
static gint ett_mq_caut = -1;
static gint ett_mq_msh = -1;
static gint ett_mq_xqh = -1;
static gint ett_mq_id = -1;
static gint ett_mq_id_icf1 = -1;
static gint ett_mq_id_icf2 = -1;
static gint ett_mq_id_icf3 = -1;
static gint ett_mq_id_ief1 = -1;
static gint ett_mq_id_ief2 = -1;
static gint ett_mq_uid = -1;
static gint ett_mq_conn = -1;
static gint ett_mq_fcno = -1;
static gint ett_mq_msg = -1;
static gint ett_mq_inq = -1;
static gint ett_mq_spi = -1;
static gint ett_mq_spi_base = -1; /* Factorisation of common SPI items */
static gint ett_mq_spi_options = -1;
static gint ett_mq_put = -1;
static gint ett_mq_open = -1;
static gint ett_mq_open_option = -1;
static gint ett_mq_close_option = -1;
static gint ett_mq_fopa = -1;
static gint ett_mq_ping = -1;
static gint ett_mq_reset = -1;
static gint ett_mq_status = -1;
static gint ett_mq_od = -1;
static gint ett_mq_od_objstr = -1;
static gint ett_mq_od_selstr = -1;
static gint ett_mq_od_resobjstr = -1;
static gint ett_mq_or = -1;
static gint ett_mq_rr = -1;
static gint ett_mq_pmr = -1;
static gint ett_mq_md = -1;
static gint ett_mq_dlh = -1;
static gint ett_mq_dh = -1;
static gint ett_mq_gmo = -1;
static gint ett_mq_gmo_option = -1;
static gint ett_mq_gmo_matchoption = -1;
static gint ett_mq_pmo = -1;
static gint ett_mq_pmo_option = -1;

static gint ett_mq_lpoo = -1;
static gint ett_mq_lpoo_options = -1;
static gint ett_mq_lpoo_lpiopts = -1;

static gint ett_mq_head = -1; /* Factorisation of common Header structure items (DH, MDE, CIH, IIH, RFH, RMH, WIH */
static gint ett_mq_head_flags = -1;

static gint ett_mq_xa = -1;
static gint ett_mq_xa_tmflags = -1;
static gint ett_mq_xa_xid = -1;
static gint ett_mq_xa_info = -1;
static gint ett_mq_charv = -1;
static gint ett_mq_reaasemb = -1;
static gint ett_mq_notif = -1;

static dissector_handle_t mq_tcp_handle;
static dissector_handle_t mq_spx_handle;
static dissector_handle_t data_handle;
static dissector_handle_t mqpcf_handle;

static heur_dissector_list_t mq_heur_subdissector_list;

static gboolean mq_desegment = TRUE;
static gboolean mq_reassembly = TRUE;

static gboolean mq_in_reassembly = FALSE;

static reassembly_table mq_reassembly_table;

#define MQ_PORT_TCP    1414
#define MQ_SOCKET_SPX  0x5E86

#define MQ_XPT_TCP      0x02
#define MQ_XPT_NETBIOS  0x03
#define MQ_XPT_SPX      0x04
#define MQ_XPT_HTTP     0x07

#define MQ_STRUCTID_NULL          0x00000000

#define MQ_STRUCTID_CIH           0x43494820
#define MQ_STRUCTID_DH            0x44482020
#define MQ_STRUCTID_DLH           0x444C4820
#define MQ_STRUCTID_GMO           0x474D4F20
#define MQ_STRUCTID_ID            0x49442020
#define MQ_STRUCTID_IIH           0x49494820
#define MQ_STRUCTID_MD            0x4D442020
#define MQ_STRUCTID_MDE           0x4D444520
#define MQ_STRUCTID_MSH           0x4D534820
#define MQ_STRUCTID_OD            0x4F442020
#define MQ_STRUCTID_PMO           0x504D4F20
#define MQ_STRUCTID_RFH           0x52464820
#define MQ_STRUCTID_RMH           0x524D4820
#define MQ_STRUCTID_TM            0x544D2020
#define MQ_STRUCTID_TMC2          0x544D4332
#define MQ_STRUCTID_CAUT          0x43415554

#define MQ_STRUCTID_TSH           0x54534820
#define MQ_STRUCTID_TSHC          0x54534843
#define MQ_STRUCTID_TSHM          0x5453484D

#define MQ_MASK_TSHx              0xffffff00
#define MQ_STRUCTID_TSHx          0x54534800 /* TSHx */

#define MQ_STRUCTID_SPxx          0x53500000 /* SPxx */
#define MQ_STRUCTID_UID           0x55494420
#define MQ_STRUCTID_WIH           0x57494820
#define MQ_STRUCTID_XQH           0x58514820
#define MQ_STRUCTID_FOPA          0x464F5041

#define MQ_STRUCTID_CIH_EBCDIC    0xC3C9C840
#define MQ_STRUCTID_DH_EBCDIC     0xC4C84040
#define MQ_STRUCTID_DLH_EBCDIC    0xC4D3C840
#define MQ_STRUCTID_GMO_EBCDIC    0xC7D4D640
#define MQ_STRUCTID_ID_EBCDIC     0xC9C44040
#define MQ_STRUCTID_IIH_EBCDIC    0xC9C9C840
#define MQ_STRUCTID_MD_EBCDIC     0xD4C44040
#define MQ_STRUCTID_MDE_EBCDIC    0xD4C4C540
#define MQ_STRUCTID_MSH_EBCDIC    0xD4E2C840
#define MQ_STRUCTID_OD_EBCDIC     0xD6C44040
#define MQ_STRUCTID_PMO_EBCDIC    0xD7D4D640
#define MQ_STRUCTID_RFH_EBCDIC    0xD9C6C840
#define MQ_STRUCTID_RMH_EBCDIC    0xD9D4C840
#define MQ_STRUCTID_TM_EBCDIC     0xE3D44040
#define MQ_STRUCTID_TMC2_EBCDIC   0xE3D4C3F2
#define MQ_STRUCTID_CAUT_EBCDIC   0xC3C1E4E3

#define MQ_STRUCTID_TSH_EBCDIC    0xE3E2C840
#define MQ_STRUCTID_TSHC_EBCDIC   0xE3E2C8C3
#define MQ_STRUCTID_TSHM_EBCDIC   0xE3E2C8D4
#define MQ_STRUCTID_TSHx_EBCDIC   0xE3E2C800

#define MQ_STRUCTID_UID_EBCDIC    0xE4C9C440
#define MQ_STRUCTID_WIH_EBCDIC    0xE6C9C840
#define MQ_STRUCTID_XQH_EBCDIC    0xE7D8C840
#define MQ_STRUCTID_FOPA_EBCDIC   0xD64FD7C1

#define MQ_MASK_SPxx              0xffff0000
#define MQ_MASK_SPxZ              0xffff00ff

#define MQ_STRUCTID_SPxx          0x53500000 /* SPxx */
#define MQ_STRUCTID_SPxU          0x53500055 /* SPxU */
#define MQ_STRUCTID_SPxI          0x53500049 /* SPxI */
#define MQ_STRUCTID_SPxO          0x5350004F /* SPxO */

#define MQ_STRUCTID_SPQU          0x53505155 /* SPI Query InOut */
#define MQ_STRUCTID_SPQI          0x53505149 /* SPI Query In */
#define MQ_STRUCTID_SPQO          0x5350514F /* SPI Query Out */
#define MQ_STRUCTID_SPPU          0x53505055 /* SPI Put InOut */
#define MQ_STRUCTID_SPPI          0x53505049 /* SPI Put In */
#define MQ_STRUCTID_SPPO          0x5350504F /* SPI Put Out */
#define MQ_STRUCTID_SPGU          0x53504755 /* SPI Get InOut */
#define MQ_STRUCTID_SPGI          0x53504749 /* SPI Get In */
#define MQ_STRUCTID_SPGO          0x5350474F /* SPI Get Out */
#define MQ_STRUCTID_SPAU          0x53504155 /* SPI Activate InOut */
#define MQ_STRUCTID_SPAI          0x53504149 /* SPI Activate In */
#define MQ_STRUCTID_SPAO          0x5350414F /* SPI Activate Out */
#define MQ_STRUCTID_SPOU          0x53504F55 /* SPI InOut */
#define MQ_STRUCTID_SPOI          0x53504F49 /* SPI In */
#define MQ_STRUCTID_SPOO          0x53504F4F /* SPI Out */
#define MQ_STRUCTID_LPOO          0x4C504F4F /* LPOO */
#define MQ_STRUCTID_FCNO          0x46434E4F /* FCNO */

#define MQ_STRUCTID_SPxx_EBCDIC   0xE2D70000 /* SPxx */
#define MQ_STRUCTID_SPxU_EBCDIC   0xE2D700E4 /* SPxU */
#define MQ_STRUCTID_SPxI_EBCDIC   0xE2D700C9 /* SPxI */
#define MQ_STRUCTID_SPxO_EBCDIC   0xE2D700D6 /* SPxO */

#define MQ_STRUCTID_SPQU_EBCDIC   0xE2D7D8E4 /* SPI Query InOut */
#define MQ_STRUCTID_SPQI_EBCDIC   0xE2D7D8C9 /* SPI Query In */
#define MQ_STRUCTID_SPQO_EBCDIC   0xE2D7D8D6 /* SPI Query Out */
#define MQ_STRUCTID_SPPU_EBCDIC   0xE2D7D7E4 /* SPI Put InOut */
#define MQ_STRUCTID_SPPI_EBCDIC   0xE2D7D7C9 /* SPI Put In */
#define MQ_STRUCTID_SPPO_EBCDIC   0xE2D7D7D6 /* SPI Put Out */
#define MQ_STRUCTID_SPGU_EBCDIC   0xE2D7C7E4 /* SPI Get InOut */
#define MQ_STRUCTID_SPGI_EBCDIC   0xE2D7C7C9 /* SPI Get In */
#define MQ_STRUCTID_SPGO_EBCDIC   0xE2D7C7D6 /* SPI Get Out */
#define MQ_STRUCTID_SPAU_EBCDIC   0xE2D7C1E4 /* SPI Activate InOut */
#define MQ_STRUCTID_SPAI_EBCDIC   0xE2D7C1C9 /* SPI Activate In */
#define MQ_STRUCTID_SPAO_EBCDIC   0xE2D7C1D6 /* SPI Activate Out */
#define MQ_STRUCTID_SPOU_EBCDIC   0xE2D7D6E4 /* SPI InOut */
#define MQ_STRUCTID_SPOI_EBCDIC   0xE2D7D6C9 /* SPI In */
#define MQ_STRUCTID_SPOO_EBCDIC   0xE2D7D6D6 /* SPI Out */
#define MQ_STRUCTID_LPOO_EBCDIC   0xD3D7D6D6 /* LPOO */
#define MQ_STRUCTID_FCNO_EBCDIC   0xC6C3D5D6 /* FCNO */

#define MQ_TST_INITIAL            0x01
#define MQ_TST_RESYNC             0x02
#define MQ_TST_RESET              0x03
#define MQ_TST_MESSAGE            0x04
#define MQ_TST_STATUS             0x05
#define MQ_TST_SECURITY           0x06
#define MQ_TST_PING               0x07
#define MQ_TST_USERID             0x08
#define MQ_TST_HEARTBEAT          0x09
#define MQ_TST_CONAUTH_INFO       0x0A
#define MQ_TST_RENEGOTIATE_DATA   0x0B
#define MQ_TST_SOCKET_ACTION      0x0C
#define MQ_TST_ASYNC_MESSAGE      0x0D
#define MQ_TST_REQUEST_MSGS       0x0E
#define MQ_TST_NOTIFICATION       0x0F
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
#define MQ_TST_MQSTAT             0x8D
#define MQ_TST_MQSUB              0x8E
#define MQ_TST_MQSUBRQ            0x8F
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
#define MQ_TST_MQSTAT_REPLY       0x9D
#define MQ_TST_MQSUB_REPLY        0x9E
#define MQ_TST_MQSUBRQ_REPLY      0x9F
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

#define MQ_SPI_QUERY              0x01
#define MQ_SPI_PUT                0x02
#define MQ_SPI_GET                0x03
#define MQ_SPI_ACTIVATE           0x04
#define MQ_SPI_OPEN               0x0C

#define MQ_SPI_ACTIVATE_ENABLE    0x01
#define MQ_SPI_ACTIVATE_DISABLE   0x02

#define MQ_SPI_OPTIONS_BLANK_PADDED  0x01
#define MQ_SPI_OPTIONS_SYNCPOINT     0x02
#define MQ_SPI_OPTIONS_DEFERRED      0x04

#define MQ_TCF_CONFIRM_REQUEST    0x01
#define MQ_TCF_ERROR              0x02
#define MQ_TCF_REQUEST_CLOSE      0x04
#define MQ_TCF_CLOSE_CHANNEL      0x08
#define MQ_TCF_FIRST              0x10
#define MQ_TCF_LAST               0x20
#define MQ_TCF_REQUEST_ACCEPTED   0x40
#define MQ_TCF_DLQ_USED           0x80

#define MQ_TCF2_HDRCOMP           0x01
#define MQ_TCF2_MSGCOMP           0x02
#define MQ_TCF2_CSH               0x04
#define MQ_TCF2_CMIT_INTERVAL     0x08

#define MQ_ICF1_MSG_SEQ            0x01
#define MQ_ICF1_CONVERSION_CAPABLE 0x02
#define MQ_ICF1_SPLIT_MESSAGE      0x04
#define MQ_ICF1_REQUEST_INITIATION 0x08
#define MQ_ICF1_REQUEST_SECURITY   0x10
#define MQ_ICF1_MQREQUEST          0x20
#define MQ_ICF1_SVRCONN_SECURITY   0x40
#define MQ_ICF1_RUNTIME            0x80

#define MQ_ICF2_DIST_LIST_CAPABLE      0x01
#define MQ_ICF2_FAST_MESSAGES_REQUIRED 0x02
#define MQ_ICF2_RESPONDER_CONVERSION   0x04
#define MQ_ICF2_DUAL_UOW               0x08
#define MQ_ICF2_XAREQUEST              0x10
#define MQ_ICF2_XARUNTIME_APP          0x20
#define MQ_ICF2_SPIREQUEST             0x40
#define MQ_ICF2_TRACE_ROUTE_CAPABLE    0x80

#define MQ_ICF3_MSG_PROP_CAPABLE       0x01
#define MQ_ICF3_UNKNOWNX02             0x02

#define MQ_IEF1_CCSID                  0x01
#define MQ_IEF1_ENCODING               0x02
#define MQ_IEF1_MAX_TRANSMISSION_SIZE  0x04
#define MQ_IEF1_FAP_LEVEL              0x08
#define MQ_IEF1_MAX_MSG_SIZE           0x10
#define MQ_IEF1_MAX_MSG_PER_BATCH      0x20
#define MQ_IEF1_SEQ_WRAP_VALUE         0x40
#define MQ_IEF1_HEARTBEAT_INTERVAL     0x80

#define MQ_IEF2_HDRCOMPLIST           0x01
#define MQ_IEF2_MSGCOMPLIST           0x02
#define MQ_IEF2_SSL_RESET             0x04

#define MQ_BIG_ENDIAN          0x01
#define MQ_LITTLE_ENDIAN       0x02

#define MQ_CONN_VERSION        0x01
#define MQ_CONNX_VERSION       0x03

#define MQ_STATUS_ERR_NO_CHANNEL              0x01
#define MQ_STATUS_ERR_CHANNEL_WRONG_TYPE      0x02
#define MQ_STATUS_ERR_QM_UNAVAILABLE          0x03
#define MQ_STATUS_ERR_MSG_SEQUENCE_ERROR      0x04
#define MQ_STATUS_ERR_QM_TERMINATING          0x05
#define MQ_STATUS_ERR_CAN_NOT_STORE           0x06
#define MQ_STATUS_ERR_USER_CLOSED             0x07
#define MQ_STATUS_ERR_TIMEOUT_EXPIRED         0x08
#define MQ_STATUS_ERR_TARGET_Q_UNKNOWN        0x09
#define MQ_STATUS_ERR_PROTOCOL_SEGMENT_TYPE   0x0A
#define MQ_STATUS_ERR_PROTOCOL_LENGTH_ERROR   0x0B
#define MQ_STATUS_ERR_PROTOCOL_INVALID_DATA   0x0C
#define MQ_STATUS_ERR_PROTOCOL_SEGMENT_ERROR  0x0D
#define MQ_STATUS_ERR_PROTOCOL_ID_ERROR       0x0E
#define MQ_STATUS_ERR_PROTOCOL_MSH_ERROR      0x0F
#define MQ_STATUS_ERR_PROTOCOL_GENERAL        0x10
#define MQ_STATUS_ERR_BATCH_FAILURE           0x11
#define MQ_STATUS_ERR_MESSAGE_LENGTH_ERROR    0x12
#define MQ_STATUS_ERR_SEGMENT_NUMBER_ERROR    0x13
#define MQ_STATUS_ERR_SECURITY_FAILURE        0x14
#define MQ_STATUS_ERR_WRAP_VALUE_ERROR        0x15
#define MQ_STATUS_ERR_CHANNEL_UNAVAILABLE     0x16
#define MQ_STATUS_ERR_CLOSED_BY_EXIT          0x17
#define MQ_STATUS_ERR_CIPHER_SPEC             0x18
#define MQ_STATUS_ERR_PEER_NAME               0x19
#define MQ_STATUS_ERR_SSL_CLIENT_CERTIFICATE  0x1A
#define MQ_STATUS_ERR_RMT_RSRCS_IN_RECOVERY   0x1B
#define MQ_STATUS_ERR_SSL_REFRESHING          0x1C
#define MQ_STATUS_ERR_INVALID_HOBJ            0x1D
#define MQ_STATUS_ERR_CONV_ID_ERROR           0x1E
#define MQ_STATUS_ERR_SOCKET_ACTION_TYPE      0x1F
#define MQ_STATUS_ERR_STANDBY_Q_MGR           0x20

#define MQ_STATUS_ERR_CCSID_NOT_SUPPORTED     0xF0
#define MQ_STATUS_ERR_ENCODING_INVALID        0xF1
#define MQ_STATUS_ERR_FAP_LEVEL               0xF2
#define MQ_STATUS_ERR_NEGOTIATION_FAILED      0xF3

/* These errors codes are documented in javax.transaction.xa.XAException */
#define MQ_XA_RBROLLBACK   100
#define MQ_XA_RBCOMMFAIL   101
#define MQ_XA_RBDEADLOCK   102
#define MQ_XA_RBINTEGRITY  103
#define MQ_XA_RBOTHER      104
#define MQ_XA_RBPROTO      105
#define MQ_XA_RBTIMEOUT    106
#define MQ_XA_RBTRANSIENT  107
#define MQ_XA_NOMIGRATE    9
#define MQ_XA_HEURHAZ      8
#define MQ_XA_HEURCOM      7
#define MQ_XA_HEURRB       6
#define MQ_XA_HEURMIX      5
#define MQ_XA_RETRY        4
#define MQ_XA_RDONLY       3
#define MQ_XA_OK           0
#define MQ_XAER_ASYNC      -2
#define MQ_XAER_RMERR      -3
#define MQ_XAER_NOTA       -4
#define MQ_XAER_INVAL      -5
#define MQ_XAER_PROTO      -6
#define MQ_XAER_RMFAIL     -7
#define MQ_XAER_DUPID      -8
#define MQ_XAER_OUTSIDE    -9

/* These flags are documented in javax.transaction.xa.XAResource */
#define MQ_XA_TMNOFLAGS     0
#define MQ_XA_TMJOIN        0x200000
#define MQ_XA_TMENDRSCAN    0x800000
#define MQ_XA_TMSTARTRSCAN  0x1000000
#define MQ_XA_TMSUSPEND     0x2000000
#define MQ_XA_TMSUCCESS     0x4000000
#define MQ_XA_TMRESUME      0x8000000
#define MQ_XA_TMFAIL        0x20000000
#define MQ_XA_TMONEPHASE    0x40000000

#define MQ_PMRF_NONE              0x00
#define MQ_PMRF_MSG_ID            0x01
#define MQ_PMRF_CORREL_ID         0x02
#define MQ_PMRF_GROUP_ID          0x04
#define MQ_PMRF_FEEDBACK          0x08
#define MQ_PMRF_ACCOUNTING_TOKEN  0x10

/* MQ structures */
/* Undocumented structures */
#define MQ_TEXT_TSH                     "Transmission Segment Header"
#define MQ_TEXT_TSHC                    "Transmission Segment Header Common"
#define MQ_TEXT_TSHM                    "Transmission Segment Header Multiplexed"
#define MQ_TEXT_FCNO                    "F Connect Option"
#define MQ_TEXT_API                     "API Header"
#define MQ_TEXT_SOCKET                  "Socket Action"
#define MQ_TEXT_ID                      "Initial Data"
#define MQ_TEXT_UID                     "User Id Data"
#define MQ_TEXT_MSH                     "Message Segment Header"
#define MQ_TEXT_CAUT                    "Connection Authority"
#define MQ_TEXT_CONN                    "MQCONN"
#define MQ_TEXT_INQ                     "MQINQ/MQSET"
#define MQ_TEXT_PUT                     "MQPUT/MQGET"
#define MQ_TEXT_OPEN                    "MQOPEN/MQCLOSE"
#define MQ_TEXT_REQMSG                  "REQUEST MESSAGE"
#define MQ_TEXT_ASYMSG                  "ASYNC MESSAGE"
#define MQ_TEXT_NOTIFICATION            "NOTIFICATION"
#define MQ_TEXT_BIND_READAHEAD_AS_Q_DEF "Bind/Read Ahead As Q Def"
#define MQ_TEXT_IMMEDIATE_NONE          "Close Immediate/No option"
#define MQ_TEXT_MQPMO_NONE              "Resp as Q Def/Resp as Topic Def/None"
#define MQ_TEXT_MQGMO_NONE              "No Wait/Prop as Q Def/None"
#define MQ_TEXT_MQMO_NONE               "None"
#define MQ_TEXT_LPOOOPT_NONE            "None"

#define MQ_TEXT_PING  "PING"
#define MQ_TEXT_RESET "RESET"
#define MQ_TEXT_STAT  "STATUS"
#define MQ_TEXT_SPI   "SPI"
#define MQ_TEXT_XA    "XA"
#define MQ_TEXT_XID   "Xid"
#define MQ_TEXT_XINF  "XA_info"

#define MQ_TEXT_SPQU  "SPI Query InOut"
#define MQ_TEXT_SPQI  "SPI Query In"
#define MQ_TEXT_SPQO  "SPI Query Out"
#define MQ_TEXT_SPPU  "SPI Put InOut"
#define MQ_TEXT_SPPI  "SPI Put In"
#define MQ_TEXT_SPPO  "SPI Put Out"
#define MQ_TEXT_SPGU  "SPI Get InOut"
#define MQ_TEXT_SPGI  "SPI Get In"
#define MQ_TEXT_SPGO  "SPI Get Out"
#define MQ_TEXT_SPAU  "SPI Activate InOut"
#define MQ_TEXT_SPAI  "SPI Activate In"
#define MQ_TEXT_SPAO  "SPI Activate Out"
#define MQ_TEXT_SPOU  "SPI InOut"
#define MQ_TEXT_SPOI  "SPI In"
#define MQ_TEXT_SPOO  "SPI Out"
#define MQ_TEXT_LPOO  "LPOO"
#define MQ_TEXT_FOPA  "FOPA"

/* Documented structures with structid */
#define MQ_TEXT_CIH  "CICS bridge Header"
#define MQ_TEXT_DH   "Distribution Header"
#define MQ_TEXT_DLH  "Dead-Letter Header"
#define MQ_TEXT_GMO  "Get Message Options"
#define MQ_TEXT_IIH  "IMS Information Header"
#define MQ_TEXT_MD   "Message Descriptor"
#define MQ_TEXT_MDE  "Message Descriptor Extension"
#define MQ_TEXT_OD   "Object Descriptor"
#define MQ_TEXT_PMO  "Put Message Options"
#define MQ_TEXT_RMH  "Reference Message Header"
#define MQ_TEXT_TM   "Trigger Message"
#define MQ_TEXT_TMC2 "Trigger Message 2 (character format)"
#define MQ_TEXT_WIH  "Work Information Header"
#define MQ_TEXT_XQH  "Transmission Queue Header"

/* Documented structures without structid */
#define MQ_TEXT_OR   "Object Record"
#define MQ_TEXT_PMR  "Put Message Record"
#define MQ_TEXT_RR   "Response Record"

#define MQ_NC_GET_INHIBITED          1
#define MQ_NC_GET_ALLOWED            2
#define MQ_NC_CONN_STATE             3
#define MQ_NC_CONN_STATE_REPLY       4
#define MQ_NC_Q_STATE                5
#define MQ_NC_Q_STATE_REPLY          6
#define MQ_NC_QM_QUIESCING           7
#define MQ_NC_TXN_ALLOWED            8
#define MQ_NC_TXN_REVOKE             9
#define MQ_NC_TXN_REVOKE_REPLY      10
#define MQ_NC_CHECK_MSG             11
#define MQ_NC_BROWSE_FIRST          12
#define MQ_NC_MESSAGE_TOO_LARGE     13
#define MQ_NC_STREAMING_FAILURE     14
#define MQ_NC_CLIENT_ASYNC_EMPTY    15
#define MQ_NC_STREAMING_TXN_PAUSED  16
#define MQ_NC_RECONNECTION_COMPLETE 17

DEF_VALSB(notifcode)
    DEF_VALS2(NC_GET_INHIBITED     , "GET_INHIBITED"),
    DEF_VALS2(NC_GET_ALLOWED       , "GET_ALLOWED"),
    DEF_VALS2(NC_CONN_STATE        , "CONN_STATE"),
    DEF_VALS2(NC_CONN_STATE_REPLY  , "CONN_STATE_REPLY"),
    DEF_VALS2(NC_Q_STATE           , "Q_STATE"),
    DEF_VALS2(NC_Q_STATE_REPLY     , "Q_STATE_REPLY"),
    DEF_VALS2(NC_QM_QUIESCING      , "QM_QUIESCING"),
    DEF_VALS2(NC_TXN_ALLOWED       , "TXN_ALLOWED"),
    DEF_VALS2(NC_TXN_REVOKE        , "TXN_REVOKE"),
    DEF_VALS2(NC_TXN_REVOKE_REPLY  , "TXN_REVOKE_REPLY"),
    DEF_VALS2(NC_CHECK_MSG         , "CHECK_MSG"),
    DEF_VALS2(NC_BROWSE_FIRST      , "BROWSE_FIRST"),
    DEF_VALS2(NC_MESSAGE_TOO_LARGE , "MESSAGE_TOO_LARGE"),
    DEF_VALS2(NC_STREAMING_FAILURE , "STREAMING_FAILURE"),
    DEF_VALS2(NC_CLIENT_ASYNC_EMPTY, "CLIENT_ASYNC_EMPTY"),
DEF_VALSE;

DEF_VALSB(opcode)
    DEF_VALS2(TST_INITIAL          , "INITIAL_DATA"),
    DEF_VALS2(TST_RESYNC           , "RESYNC_DATA"),
    DEF_VALS2(TST_RESET            , "RESET_DATA"),
    DEF_VALS2(TST_MESSAGE          , "MESSAGE_DATA"),
    DEF_VALS2(TST_STATUS           , "STATUS_DATA"),
    DEF_VALS2(TST_SECURITY         , "SECURITY_DATA"),
    DEF_VALS2(TST_PING             , "PING_DATA"),
    DEF_VALS2(TST_USERID           , "USERID_DATA"),
    DEF_VALS2(TST_HEARTBEAT        , "HEARTBEAT"),
    DEF_VALS2(TST_CONAUTH_INFO     , "CONAUTH_INFO"),
    DEF_VALS2(TST_RENEGOTIATE_DATA , "RENEGOTIATE_DATA"),
    DEF_VALS2(TST_SOCKET_ACTION    , "SOCKET_ACTION"),
    DEF_VALS2(TST_ASYNC_MESSAGE    , "ASYNC_MESSAGE"),
    DEF_VALS2(TST_REQUEST_MSGS     , "REQUEST_MSGS"),
    DEF_VALS2(TST_NOTIFICATION     , "NOTIFICATION"),
    DEF_VALS2(TST_MQCONN           , "MQCONN"),
    DEF_VALS2(TST_MQDISC           , "MQDISC"),
    DEF_VALS2(TST_MQOPEN           , "MQOPEN"),
    DEF_VALS2(TST_MQCLOSE          , "MQCLOSE"),
    DEF_VALS2(TST_MQGET            , "MQGET"),
    DEF_VALS2(TST_MQPUT            , "MQPUT"),
    DEF_VALS2(TST_MQPUT1           , "MQPUT1"),
    DEF_VALS2(TST_MQSET            , "MQSET"),
    DEF_VALS2(TST_MQINQ            , "MQINQ"),
    DEF_VALS2(TST_MQCMIT           , "MQCMIT"),
    DEF_VALS2(TST_MQBACK           , "MQBACK"),
    DEF_VALS2(TST_SPI              , "SPI"),
    DEF_VALS2(TST_MQSTAT           , "MQSTAT"),
    DEF_VALS2(TST_MQSUB            , "MQSUB"),
    DEF_VALS2(TST_MQSUBRQ          , "MQSUBRQ"),
    DEF_VALS2(TST_MQCONN_REPLY     , "MQCONN_REPLY"),
    DEF_VALS2(TST_MQDISC_REPLY     , "MQDISC_REPLY"),
    DEF_VALS2(TST_MQOPEN_REPLY     , "MQOPEN_REPLY"),
    DEF_VALS2(TST_MQCLOSE_REPLY    , "MQCLOSE_REPLY"),
    DEF_VALS2(TST_MQGET_REPLY      , "MQGET_REPLY"),
    DEF_VALS2(TST_MQPUT_REPLY      , "MQPUT_REPLY"),
    DEF_VALS2(TST_MQPUT1_REPLY     , "MQPUT1_REPLY"),
    DEF_VALS2(TST_MQSET_REPLY      , "MQSET_REPLY"),
    DEF_VALS2(TST_MQINQ_REPLY      , "MQINQ_REPLY"),
    DEF_VALS2(TST_MQCMIT_REPLY     , "MQCMIT_REPLY"),
    DEF_VALS2(TST_MQBACK_REPLY     , "MQBACK_REPLY"),
    DEF_VALS2(TST_SPI_REPLY        , "SPI_REPLY"),
    DEF_VALS2(TST_MQSTAT_REPLY     , "MQSTAT_REPLY"),
    DEF_VALS2(TST_MQSUB_REPLY      , "MQSUB_REPLY"),
    DEF_VALS2(TST_MQSUBRQ_REPLY    , "MQSUBRQ_REPLY"),
    DEF_VALS2(TST_XA_START         , "XA_START"),
    DEF_VALS2(TST_XA_END           , "XA_END"),
    DEF_VALS2(TST_XA_OPEN          , "XA_OPEN"),
    DEF_VALS2(TST_XA_CLOSE         , "XA_CLOSE"),
    DEF_VALS2(TST_XA_PREPARE       , "XA_PREPARE"),
    DEF_VALS2(TST_XA_COMMIT        , "XA_COMMIT"),
    DEF_VALS2(TST_XA_ROLLBACK      , "XA_ROLLBACK"),
    DEF_VALS2(TST_XA_FORGET        , "XA_FORGET"),
    DEF_VALS2(TST_XA_RECOVER       , "XA_RECOVER"),
    DEF_VALS2(TST_XA_COMPLETE      , "XA_COMPLETE"),
    DEF_VALS2(TST_XA_START_REPLY   , "XA_START_REPLY"),
    DEF_VALS2(TST_XA_END_REPLY     , "XA_END_REPLY"),
    DEF_VALS2(TST_XA_OPEN_REPLY    , "XA_OPEN_REPLY"),
    DEF_VALS2(TST_XA_CLOSE_REPLY   , "XA_CLOSE_REPLY"),
    DEF_VALS2(TST_XA_PREPARE_REPLY , "XA_PREPARE_REPLY"),
    DEF_VALS2(TST_XA_COMMIT_REPLY  , "XA_COMMIT_REPLY"),
    DEF_VALS2(TST_XA_ROLLBACK_REPLY, "XA_ROLLBACK_REPLY"),
    DEF_VALS2(TST_XA_FORGET_REPLY  , "XA_FORGET_REPLY"),
    DEF_VALS2(TST_XA_RECOVER_REPLY , "XA_RECOVER_REPLY"),
    DEF_VALS2(TST_XA_COMPLETE_REPLY, "XA_COMPLETE_REPLY"),
DEF_VALSE;

DEF_VALSB(spi_verbs)
    DEF_VALS2(SPI_QUERY   , "QUERY"),
    DEF_VALS2(SPI_PUT     , "PUT"),
    DEF_VALS2(SPI_GET     , "GET"),
    DEF_VALS2(SPI_ACTIVATE, "ACTIVATE"),
    DEF_VALS2(SPI_OPEN    , "OPEN"),
DEF_VALSE;

DEF_VALSB(spi_activate)
    DEF_VALS2(SPI_ACTIVATE_ENABLE , "ENABLE"),
    DEF_VALS2(SPI_ACTIVATE_DISABLE, "DISABLE"),
DEF_VALSE;

DEF_VALSB(status)
    DEF_VALS2(STATUS_ERR_NO_CHANNEL            , "NO_CHANNEL"),
    DEF_VALS2(STATUS_ERR_CHANNEL_WRONG_TYPE    , "CHANNEL_WRONG_TYPE"),
    DEF_VALS2(STATUS_ERR_QM_UNAVAILABLE        , "QM_UNAVAILABLE"),
    DEF_VALS2(STATUS_ERR_MSG_SEQUENCE_ERROR    , "MSG_SEQUENCE_ERROR"),
    DEF_VALS2(STATUS_ERR_QM_TERMINATING        , "QM_TERMINATING"),
    DEF_VALS2(STATUS_ERR_CAN_NOT_STORE         , "CAN_NOT_STORE"),
    DEF_VALS2(STATUS_ERR_USER_CLOSED           , "USER_CLOSED"),
    DEF_VALS2(STATUS_ERR_PROTOCOL_SEGMENT_TYPE , "REMOTE_PROTOCOL_ERROR"),
    DEF_VALS2(STATUS_ERR_PROTOCOL_LENGTH_ERROR , "BIND_FAILED"),
    DEF_VALS2(STATUS_ERR_PROTOCOL_INVALID_DATA , "MSGWRAP_DIFFERENT"),
    DEF_VALS2(STATUS_ERR_PROTOCOL_ID_ERROR     , "REMOTE_CHANNEL_UNAVAILABLE"),
    DEF_VALS2(STATUS_ERR_PROTOCOL_MSH_ERROR    , "TERMINATED_BY_REMOTE_EXIT"),
    DEF_VALS2(STATUS_ERR_PROTOCOL_GENERAL      , "PROTOCOL_GENERAL"),
    DEF_VALS2(STATUS_ERR_BATCH_FAILURE         , "BATCH_FAILURE"),
    DEF_VALS2(STATUS_ERR_MESSAGE_LENGTH_ERROR  , "MESSAGE_LENGTH_ERROR"),
    DEF_VALS2(STATUS_ERR_SEGMENT_NUMBER_ERROR  , "SEGMENT_NUMBER_ERROR"),
    DEF_VALS2(STATUS_ERR_SECURITY_FAILURE      , "SECURITY_FAILURE"),
    DEF_VALS2(STATUS_ERR_WRAP_VALUE_ERROR      , "WRAP_VALUE_ERROR"),
    DEF_VALS2(STATUS_ERR_CHANNEL_UNAVAILABLE   , "CHANNEL_UNAVAILABLE"),
    DEF_VALS2(STATUS_ERR_CLOSED_BY_EXIT        , "CLOSED_BY_EXIT"),
    DEF_VALS2(STATUS_ERR_CIPHER_SPEC           , "CIPHER_SPEC"),
    DEF_VALS2(STATUS_ERR_PEER_NAME             , "PEER_NAME"),
    DEF_VALS2(STATUS_ERR_SSL_CLIENT_CERTIFICATE, "SSL_CLIENT_CERTIFICATE"),
    DEF_VALS2(STATUS_ERR_RMT_RSRCS_IN_RECOVERY , "RMT_RSRCS_IN_RECOVERY"),
    DEF_VALS2(STATUS_ERR_SSL_REFRESHING        , "SSL_REFRESHING"),
    DEF_VALS2(STATUS_ERR_INVALID_HOBJ          , "INVALID_HOBJ"),
    DEF_VALS2(STATUS_ERR_CONV_ID_ERROR         , "CONV_ID_ERROR"),
    DEF_VALS2(STATUS_ERR_SOCKET_ACTION_TYPE    , "SOCKET_ACTION_TYPE"),
    DEF_VALS2(STATUS_ERR_STANDBY_Q_MGR         , "STANDBY_Q_MGR"),
    DEF_VALS2(STATUS_ERR_CCSID_NOT_SUPPORTED   , "CCSID_NOT_SUPPORTED"),
    DEF_VALS2(STATUS_ERR_ENCODING_INVALID      , "ENCODING_INVALID"),
    DEF_VALS2(STATUS_ERR_FAP_LEVEL             , "FAP_LEVEL"),
    DEF_VALS2(STATUS_ERR_NEGOTIATION_FAILED    , "NEGOTIATION_FAILED"),
DEF_VALSE;

DEF_VALSB(xaer)
    DEF_VALS2(XA_RBROLLBACK , "XA_RBROLLBACK"),
    DEF_VALS2(XA_RBCOMMFAIL , "XA_RBCOMMFAIL"),
    DEF_VALS2(XA_RBDEADLOCK , "XA_RBDEADLOCK"),
    DEF_VALS2(XA_RBINTEGRITY, "XA_RBINTEGRITY"),
    DEF_VALS2(XA_RBOTHER    , "XA_RBOTHER"),
    DEF_VALS2(XA_RBPROTO    , "XA_RBPROTO"),
    DEF_VALS2(XA_RBTIMEOUT  , "XA_RBTIMEOUT"),
    DEF_VALS2(XA_RBTRANSIENT, "XA_RBTRANSIENT"),
    DEF_VALS2(XA_NOMIGRATE  , "XA_NOMIGRATE"),
    DEF_VALS2(XA_HEURHAZ    , "XA_HEURHAZ"),
    DEF_VALS2(XA_HEURCOM    , "XA_HEURCOM"),
    DEF_VALS2(XA_HEURRB     , "XA_HEURRB"),
    DEF_VALS2(XA_HEURMIX    , "XA_HEURMIX"),
    DEF_VALS2(XA_RETRY      , "XA_RETRY"),
    DEF_VALS2(XA_RDONLY     , "XA_RDONLY"),
    DEF_VALS2(XA_OK         , "XA_OK"),
    DEF_VALS2(XAER_ASYNC    , "XAER_ASYNC"),
    DEF_VALS2(XAER_RMERR    , "XAER_RMERR"),
    DEF_VALS2(XAER_NOTA     , "XAER_NOTA"),
    DEF_VALS2(XAER_INVAL    , "XAER_INVAL"),
    DEF_VALS2(XAER_PROTO    , "XAER_PROTO"),
    DEF_VALS2(XAER_RMFAIL   , "XAER_RMFAIL"),
    DEF_VALS2(XAER_DUPID    , "XAER_DUPID"),
    DEF_VALS2(XAER_OUTSIDE  , "XAER_OUTSIDE"),
DEF_VALSE;

DEF_VALSB(StructID)
    DEF_VALS2(STRUCTID_CIH        , MQ_TEXT_CIH),
    DEF_VALS2(STRUCTID_DH         , MQ_TEXT_DH),
    DEF_VALS2(STRUCTID_DLH        , MQ_TEXT_DLH),
    DEF_VALS2(STRUCTID_GMO        , MQ_TEXT_GMO),
    DEF_VALS2(STRUCTID_ID         , MQ_TEXT_ID),
    DEF_VALS2(STRUCTID_IIH        , MQ_TEXT_IIH),
    DEF_VALS2(STRUCTID_MD         , MQ_TEXT_MD),
    DEF_VALS2(STRUCTID_MDE        , MQ_TEXT_MDE),
    DEF_VALS2(STRUCTID_MSH        , MQ_TEXT_MSH),
    DEF_VALS2(STRUCTID_OD         , MQ_TEXT_OD),
    DEF_VALS2(STRUCTID_PMO        , MQ_TEXT_PMO),
    DEF_VALS2(STRUCTID_RMH        , MQ_TEXT_RMH),
    DEF_VALS2(STRUCTID_TM         , MQ_TEXT_TM),
    DEF_VALS2(STRUCTID_TMC2       , MQ_TEXT_TMC2),
    DEF_VALS2(STRUCTID_CAUT       , MQ_TEXT_CAUT),
    DEF_VALS2(STRUCTID_TSH        , MQ_TEXT_TSH),
    DEF_VALS2(STRUCTID_TSHC       , MQ_TEXT_TSHC),
    DEF_VALS2(STRUCTID_TSHM       , MQ_TEXT_TSHM),
    DEF_VALS2(STRUCTID_UID        , MQ_TEXT_UID),
    DEF_VALS2(STRUCTID_WIH        , MQ_TEXT_WIH),
    DEF_VALS2(STRUCTID_XQH        , MQ_TEXT_XQH),
    DEF_VALS2(STRUCTID_SPQU       , MQ_TEXT_SPQU),
    DEF_VALS2(STRUCTID_SPQI       , MQ_TEXT_SPQI),
    DEF_VALS2(STRUCTID_SPQO       , MQ_TEXT_SPQO),
    DEF_VALS2(STRUCTID_SPPU       , MQ_TEXT_SPPU),
    DEF_VALS2(STRUCTID_SPPI       , MQ_TEXT_SPPI),
    DEF_VALS2(STRUCTID_SPPO       , MQ_TEXT_SPPO),
    DEF_VALS2(STRUCTID_SPGU       , MQ_TEXT_SPGU),
    DEF_VALS2(STRUCTID_SPGI       , MQ_TEXT_SPGI),
    DEF_VALS2(STRUCTID_SPGO       , MQ_TEXT_SPGO),
    DEF_VALS2(STRUCTID_SPAU       , MQ_TEXT_SPAU),
    DEF_VALS2(STRUCTID_SPAI       , MQ_TEXT_SPAI),
    DEF_VALS2(STRUCTID_SPAO       , MQ_TEXT_SPAO),
    DEF_VALS2(STRUCTID_SPOU       , MQ_TEXT_SPOU),
    DEF_VALS2(STRUCTID_SPOI       , MQ_TEXT_SPOI),
    DEF_VALS2(STRUCTID_SPOO       , MQ_TEXT_SPOO),
    DEF_VALS2(STRUCTID_LPOO       , MQ_TEXT_LPOO),
    DEF_VALS2(STRUCTID_FOPA       , MQ_TEXT_FOPA),
    DEF_VALS2(STRUCTID_FCNO       , MQ_TEXT_FCNO),
    DEF_VALS2(STRUCTID_CIH_EBCDIC , MQ_TEXT_CIH),
    DEF_VALS2(STRUCTID_DH_EBCDIC  , MQ_TEXT_DH),
    DEF_VALS2(STRUCTID_DLH_EBCDIC , MQ_TEXT_DLH),
    DEF_VALS2(STRUCTID_GMO_EBCDIC , MQ_TEXT_GMO),
    DEF_VALS2(STRUCTID_ID_EBCDIC  , MQ_TEXT_ID),
    DEF_VALS2(STRUCTID_IIH_EBCDIC , MQ_TEXT_IIH),
    DEF_VALS2(STRUCTID_MD_EBCDIC  , MQ_TEXT_MD),
    DEF_VALS2(STRUCTID_MDE_EBCDIC , MQ_TEXT_MDE),
    DEF_VALS2(STRUCTID_OD_EBCDIC  , MQ_TEXT_OD),
    DEF_VALS2(STRUCTID_PMO_EBCDIC , MQ_TEXT_PMO),
    DEF_VALS2(STRUCTID_RMH_EBCDIC , MQ_TEXT_RMH),
    DEF_VALS2(STRUCTID_TM_EBCDIC  , MQ_TEXT_TM),
    DEF_VALS2(STRUCTID_TMC2_EBCDIC, MQ_TEXT_TMC2),
    DEF_VALS2(STRUCTID_CAUT_EBCDIC, MQ_TEXT_CAUT),
    DEF_VALS2(STRUCTID_TSH_EBCDIC , MQ_TEXT_TSH),
    DEF_VALS2(STRUCTID_TSHC_EBCDIC, MQ_TEXT_TSHC),
    DEF_VALS2(STRUCTID_TSHM_EBCDIC, MQ_TEXT_TSHM),
    DEF_VALS2(STRUCTID_UID_EBCDIC , MQ_TEXT_UID),
    DEF_VALS2(STRUCTID_WIH_EBCDIC , MQ_TEXT_WIH),
    DEF_VALS2(STRUCTID_XQH_EBCDIC , MQ_TEXT_XQH),
    DEF_VALS2(STRUCTID_SPQU_EBCDIC, MQ_TEXT_SPQU),
    DEF_VALS2(STRUCTID_SPQI_EBCDIC, MQ_TEXT_SPQI),
    DEF_VALS2(STRUCTID_SPQO_EBCDIC, MQ_TEXT_SPQO),
    DEF_VALS2(STRUCTID_SPPU_EBCDIC, MQ_TEXT_SPPU),
    DEF_VALS2(STRUCTID_SPPI_EBCDIC, MQ_TEXT_SPPI),
    DEF_VALS2(STRUCTID_SPPO_EBCDIC, MQ_TEXT_SPPO),
    DEF_VALS2(STRUCTID_SPGU_EBCDIC, MQ_TEXT_SPGU),
    DEF_VALS2(STRUCTID_SPGI_EBCDIC, MQ_TEXT_SPGI),
    DEF_VALS2(STRUCTID_SPGO_EBCDIC, MQ_TEXT_SPGO),
    DEF_VALS2(STRUCTID_SPAU_EBCDIC, MQ_TEXT_SPAU),
    DEF_VALS2(STRUCTID_SPAI_EBCDIC, MQ_TEXT_SPAI),
    DEF_VALS2(STRUCTID_SPAO_EBCDIC, MQ_TEXT_SPAO),
    DEF_VALS2(STRUCTID_SPOU_EBCDIC, MQ_TEXT_SPOU),
    DEF_VALS2(STRUCTID_SPOI_EBCDIC, MQ_TEXT_SPOI),
    DEF_VALS2(STRUCTID_SPOO_EBCDIC, MQ_TEXT_SPOO),
    DEF_VALS2(STRUCTID_LPOO_EBCDIC, MQ_TEXT_LPOO),
    DEF_VALS2(STRUCTID_FOPA_EBCDIC, MQ_TEXT_FOPA),
    DEF_VALS2(STRUCTID_FCNO_EBCDIC, MQ_TEXT_FCNO),
DEF_VALSE;

DEF_VALSB(byteorder)
    DEF_VALS2(LITTLE_ENDIAN, "Little endian"),
    DEF_VALS2(BIG_ENDIAN   , "Big endian"),
DEF_VALSE;

DEF_VALSB(conn_version)
    DEF_VALS2(CONN_VERSION , "MQCONN"),
    DEF_VALS2(CONNX_VERSION, "MQCONNX"),
DEF_VALSE;

DEF_VALSB(sidtype)
    DEF_VALS1(MQSIDT_NONE),
    DEF_VALS1(MQSIDT_NT_SECURITY_ID),
    DEF_VALS1(MQSIDT_WAS_SECURITY_ID),
DEF_VALSE;

static gint dissect_mq_encoding(proto_tree *tree, int hfindex, tvbuff_t *tvb, const gint start, gint length, const guint encoding)
{
    gchar  sEnc[128] = "";
    gchar *pEnc;
    guint  uEnc;

    if (length == 2)
    {
        uEnc = (gint)tvb_get_guint16_endian(tvb, start, encoding);
    }
    else
    {
        uEnc = tvb_get_guint32_endian(tvb, start, encoding);
    }
    pEnc = sEnc;

#define CHECK_ENC(M, T) ((uEnc & M) == T)
#define DOPRT(A) pEnc += g_snprintf(pEnc, (gulong)(sizeof(sEnc)-1-(pEnc-sEnc)), A);
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
    } else
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

static gint dissect_mq_MQMO(tvbuff_t *tvb, proto_tree *mq_tree, gint offset, gint ett_subtree, mq_parm_t *p_mq_parm)
{
    guint        uMoOpt;

    uMoOpt = tvb_get_guint32_endian(tvb, offset, p_mq_parm->mq_int_enc);

    if (uMoOpt == 0)
    {
        proto_item  *ti;
        proto_tree  *mq_tree_sub;
        ti = proto_tree_add_item(mq_tree, hf_mq_gmo_matchoptions, tvb, offset, 4, p_mq_parm->mq_int_enc); /* ENC_BIG_ENDIAN); */
        mq_tree_sub = proto_item_add_subtree(ti, ett_subtree);
        proto_tree_add_text(mq_tree_sub, tvb, offset, 4, MQ_TEXT_MQMO_NONE);
    }
    else
    {
        proto_tree_add_bitmask(mq_tree, tvb, offset, hf_mq_gmo_matchoptions, ett_subtree, pf_flds_mtchopt, p_mq_parm->mq_int_enc);
    }
    return 4;
}
static gint dissect_mq_LPOO_LPIOPTS(tvbuff_t *tvb, proto_tree *mq_tree, gint offset, gint ett_subtree, mq_parm_t *p_mq_parm)
{
    guint        uLpiOpts;

    uLpiOpts = tvb_get_guint32_endian(tvb, offset, p_mq_parm->mq_int_enc);

    if (uLpiOpts == 0)
    {
        proto_item  *ti;
        proto_tree  *mq_tree_sub;
        ti = proto_tree_add_item(mq_tree, hf_mq_lpoo_lpiopts, tvb, offset, 4, p_mq_parm->mq_int_enc);
        mq_tree_sub = proto_item_add_subtree(ti, ett_subtree);
        proto_tree_add_text(mq_tree_sub, tvb, offset, 4, MQ_TEXT_LPOOOPT_NONE);
    }
    else
    {
        proto_tree_add_bitmask(mq_tree, tvb, offset, hf_mq_lpoo_lpiopts, ett_subtree, pf_flds_lpooopt, p_mq_parm->mq_int_enc);
    }
    return 4;
}
static gint dissect_mq_MQGMO(tvbuff_t *tvb, proto_tree *mq_tree, gint offset, gint ett_subtree, mq_parm_t *p_mq_parm)
{
    guint        uGmoOpt;

    uGmoOpt = tvb_get_guint32_endian(tvb, offset, p_mq_parm->mq_int_enc);

    if (uGmoOpt == 0)
    {
        proto_item  *ti;
        proto_tree  *mq_tree_sub;
        ti = proto_tree_add_item(mq_tree, hf_mq_gmo_options, tvb, offset, 4, p_mq_parm->mq_int_enc); /* ENC_BIG_ENDIAN); */
        mq_tree_sub = proto_item_add_subtree(ti, ett_subtree);
        proto_tree_add_text(mq_tree_sub, tvb, offset, 4, MQ_TEXT_MQGMO_NONE);
    }
    else
    {
        proto_tree_add_bitmask(mq_tree, tvb, offset, hf_mq_gmo_options, ett_subtree, pf_flds_gmoopt, p_mq_parm->mq_int_enc);
    }
    return 4;
}

static gint dissect_mq_MQPMO(tvbuff_t *tvb, proto_tree *mq_tree, gint offset, gint ett_subtree, mq_parm_t *p_mq_parm)
{
    guint        uPmoOpt;

    uPmoOpt = tvb_get_guint32_endian(tvb, offset, p_mq_parm->mq_int_enc);

    if (uPmoOpt == 0)
    {
        proto_item  *ti;
        proto_tree  *mq_tree_sub;
        ti = proto_tree_add_item(mq_tree, hf_mq_pmo_options, tvb, offset, 4, p_mq_parm->mq_int_enc); /* ENC_BIG_ENDIAN); */
        mq_tree_sub = proto_item_add_subtree(ti, ett_subtree);
        proto_tree_add_text(mq_tree_sub, tvb, offset, 4, MQ_TEXT_MQPMO_NONE);
    }
    else
    {
        proto_tree_add_bitmask(mq_tree, tvb, offset, hf_mq_pmo_options, ett_subtree, pf_flds_pmoopt, p_mq_parm->mq_int_enc);
    }
    return 4;
}

static gint dissect_mq_MQOO(tvbuff_t *tvb, proto_tree *mq_tree, gint offset, gint ett_subtree, gint hfindex, mq_parm_t *p_mq_parm)
{
    guint        uOpenOpt;

    uOpenOpt = tvb_get_guint32_endian(tvb, offset, p_mq_parm->mq_int_enc);

    if (uOpenOpt == 0)
    {
        proto_item  *ti;
        proto_tree  *mq_tree_sub;
        ti = proto_tree_add_item(mq_tree, hfindex, tvb, offset, 4, p_mq_parm->mq_int_enc);
        mq_tree_sub = proto_item_add_subtree(ti, ett_subtree);
        proto_tree_add_text(mq_tree_sub, tvb, offset, 4, MQ_TEXT_BIND_READAHEAD_AS_Q_DEF);
    }
    else
    {
        proto_tree_add_bitmask(mq_tree, tvb, offset, hfindex, ett_subtree, pf_flds_opnopt, p_mq_parm->mq_int_enc);
    }
    return 4;
}
static gint dissect_mq_MQCO(tvbuff_t *tvb, proto_tree *mq_tree, gint offset, mq_parm_t *p_mq_parm)
{
    guint        iCloseOpt;

    iCloseOpt = tvb_get_guint32_endian(tvb, offset, p_mq_parm->mq_int_enc);

    if (iCloseOpt == 0)
    {
        proto_item  *ti;
        proto_tree  *mq_tree_sub;
        ti = proto_tree_add_item(mq_tree, hf_mq_close_options, tvb, offset, 4, p_mq_parm->mq_int_enc);
        mq_tree_sub = proto_item_add_subtree(ti, ett_mq_close_option);
        proto_tree_add_text(mq_tree_sub, tvb, offset, 4, MQ_TEXT_IMMEDIATE_NONE);
    }
    else
    {
        proto_tree_add_bitmask(mq_tree, tvb, offset, hf_mq_close_options, ett_mq_close_option, pf_flds_clsopt, ENC_BIG_ENDIAN);
    }
    return 4;
}
static gint dissect_mq_charv(tvbuff_t *tvb, proto_tree *tree, gint offset, gint iSize, gint idx, guint8 *pStr, mq_parm_t *p_mq_parm)
{
    proto_item *ti;
    proto_tree *mq_tree_sub;
    guint32     lStr;
    guint32     oStr;
    gint32      eStr;
    guint8     *sStr;
    static guint8 sEmpty[] = "[Empty]";

    lStr = tvb_get_guint32_endian(tvb, offset + 12, p_mq_parm->mq_int_enc);
    oStr = tvb_get_guint32_endian(tvb, offset +  4, p_mq_parm->mq_int_enc);
    eStr = tvb_get_guint32_endian(tvb, offset + 16, p_mq_parm->mq_int_enc);
    if (lStr && oStr)
    {
        sStr = tvb_get_string_enc(wmem_packet_scope(), tvb, oStr, lStr, p_mq_parm->mq_str_enc);
    }
    else
        sStr = NULL;

    ti = proto_tree_add_text(tree, tvb, offset, iSize, "%s - %s", pStr, (sStr) ? sStr : sEmpty);
    mq_tree_sub = proto_item_add_subtree(ti, idx);
    proto_tree_add_item(mq_tree_sub, hf_mq_charv_vsptr    , tvb, offset,      4, p_mq_parm->mq_int_enc);
    proto_tree_add_item(mq_tree_sub, hf_mq_charv_vsoffset , tvb, offset +  4, 4, p_mq_parm->mq_int_enc);
    proto_tree_add_item(mq_tree_sub, hf_mq_charv_vsbufsize, tvb, offset +  8, 4, p_mq_parm->mq_int_enc);
    proto_tree_add_item(mq_tree_sub, hf_mq_charv_vslength , tvb, offset + 12, 4, p_mq_parm->mq_int_enc);
    proto_tree_add_item(mq_tree_sub, hf_mq_charv_vsccsid  , tvb, offset + 16, 4, p_mq_parm->mq_int_enc);
    proto_tree_add_item(mq_tree_sub, hf_mq_charv_vsvalue  , tvb, oStr, lStr, (eStr == 500) ? ENC_EBCDIC : ENC_ASCII);

    return 20;
}
static gint dissect_mq_pmr(tvbuff_t *tvb, proto_tree *tree, gint offset, gint iNbrRecords, gint offsetPMR, guint32 recFlags, mq_parm_t *p_mq_parm)
{
    gint iSizePMR1 = 0;
    gint iSizePMR  = 0;

    iSizePMR1 =  ((((recFlags & MQ_PMRF_MSG_ID) != 0) * 24)
        +(((recFlags & MQ_PMRF_CORREL_ID) != 0) * 24)
        +(((recFlags & MQ_PMRF_GROUP_ID) != 0) * 24)
        +(((recFlags & MQ_PMRF_FEEDBACK) != 0) * 4)
        +(((recFlags & MQ_PMRF_ACCOUNTING_TOKEN) != 0) * 32));

    if (offsetPMR != 0 && iSizePMR1 != 0)
    {
        iSizePMR = iNbrRecords * iSizePMR1;
        if (tvb_length_remaining(tvb, offset) >= iSizePMR)
        {
            if (tree)
            {
                gint iOffsetPMR = 0;
                gint iRecord = 0;
                for (iRecord = 0; iRecord < iNbrRecords; iRecord++)
                {
                    proto_item *ti = proto_tree_add_text(tree, tvb, offset + iOffsetPMR, iSizePMR1, MQ_TEXT_PMR);
                    proto_tree *mq_tree = proto_item_add_subtree(ti, ett_mq_pmr);
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
        }
        else iSizePMR = 0;
    }
    return iSizePMR;
}
static gint dissect_mq_or(tvbuff_t *tvb, proto_tree *tree, gint offset, gint iNbrRecords, gint offsetOR, mq_parm_t *p_mq_parm)
{
    gint iSizeOR = 0;
    if (offsetOR != 0)
    {
        iSizeOR = iNbrRecords * 96;
        if (tvb_length_remaining(tvb, offset) >= iSizeOR)
        {
            if (tree)
            {
                gint iOffsetOR = 0;
                gint iRecord = 0;
                for (iRecord = 0; iRecord < iNbrRecords ; iRecord++)
                {
                    proto_item *ti = proto_tree_add_text(tree, tvb, offset + iOffsetOR, 96, MQ_TEXT_OR);
                    proto_tree *mq_tree = proto_item_add_subtree(ti, ett_mq_or);
                    proto_tree_add_item(mq_tree, hf_mq_or_objname, tvb, offset + iOffsetOR, 48, p_mq_parm->mq_str_enc);
                    proto_tree_add_item(mq_tree, hf_mq_or_objqmgrname, tvb, offset + iOffsetOR + 48, 48, p_mq_parm->mq_str_enc);
                    iOffsetOR += 96;
                }
            }
        }
        else iSizeOR = 0;
    }
    return iSizeOR;
}
static gint dissect_mq_rr(tvbuff_t *tvb, proto_tree *tree, gint offset, gint iNbrRecords, gint offsetRR, mq_parm_t *p_mq_parm)
{
    gint iSizeRR = 0;
    if (offsetRR != 0)
    {
        iSizeRR = iNbrRecords * 8;
        if (tvb_length_remaining(tvb, offset) >= iSizeRR)
        {
            if (tree)
            {
                gint iOffsetRR = 0;
                gint iRecord = 0;
                for (iRecord = 0; iRecord < iNbrRecords; iRecord++)
                {
                    proto_item *ti = proto_tree_add_text(tree, tvb, offset + iOffsetRR, 8, MQ_TEXT_RR);
                    proto_tree *mq_tree = proto_item_add_subtree(ti, ett_mq_rr);
                    proto_tree_add_item(mq_tree, hf_mq_rr_compcode, tvb, offset + iOffsetRR, 4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_rr_reascode, tvb, offset + iOffsetRR + 4, 4, p_mq_parm->mq_int_enc);
                    iOffsetRR += 8;
                }
            }
        }
        else iSizeRR = 0;
    }
    return iSizeRR;
}
static gint dissect_mq_gmo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, mq_parm_t *p_mq_parm)
{
    gint iSize = 0;

    p_mq_parm->mq_strucID = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
    if (p_mq_parm->mq_strucID == MQ_STRUCTID_GMO || p_mq_parm->mq_strucID == MQ_STRUCTID_GMO_EBCDIC)
    {
        guint32 iVersion = 0;
        iVersion = tvb_get_guint32_endian(tvb, offset + 4, p_mq_parm->mq_int_enc);
        /* Compute length according to version */
        switch (iVersion)
        {
        case 1: iSize = 72; break;
        case 2: iSize = 80; break;
        case 3: iSize = 100; break;
        }

        if (iSize != 0 && tvb_length_remaining(tvb, offset) >= iSize)
        {
            guint8 *sQueue;
            sQueue = tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 24, 48, p_mq_parm->mq_str_enc);
            if (strip_trailing_blanks(sQueue, 48) > 0)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, " Q=%s", sQueue);
            }

            if (tree)
            {
                proto_tree *mq_tree;
                proto_item *ti;

                ti = proto_tree_add_text(tree, tvb, offset, iSize, MQ_TEXT_GMO);
                mq_tree = proto_item_add_subtree(ti, ett_mq_gmo);

                proto_tree_add_item(mq_tree, hf_mq_gmo_StructID, tvb, offset, 4, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_gmo_version , tvb, offset + 4, 4, p_mq_parm->mq_int_enc);

                dissect_mq_MQGMO(tvb, mq_tree, offset + 8, ett_mq_gmo_option, p_mq_parm);

                proto_tree_add_item(mq_tree, hf_mq_gmo_waitinterval, tvb, offset + 12, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_gmo_signal1     , tvb, offset + 16, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_gmo_signal2     , tvb, offset + 20, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_gmo_resolvqname , tvb, offset + 24, 48, p_mq_parm->mq_str_enc);

                if (iVersion >= 2)
                {
                    /*proto_tree_add_item(mq_tree, hf_mq_gmo_matchoptions, tvb, offset + 72, 4, ENC_BIG_ENDIAN);*/
                    dissect_mq_MQMO(tvb, mq_tree, offset + 8, ett_mq_gmo_matchoption, p_mq_parm);

                    proto_tree_add_item(mq_tree, hf_mq_gmo_groupstatus , tvb, offset + 76, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(mq_tree, hf_mq_gmo_segmstatus  , tvb, offset + 77, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(mq_tree, hf_mq_gmo_segmentation, tvb, offset + 78, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(mq_tree, hf_mq_gmo_reserved    , tvb, offset + 79, 1, ENC_BIG_ENDIAN);
                }

                if (iVersion >= 3)
                {
                    proto_tree_add_item(mq_tree, hf_mq_gmo_msgtoken   , tvb, offset + 80, 16, ENC_NA);
                    proto_tree_add_item(mq_tree, hf_mq_gmo_returnedlen, tvb, offset + 96, 4, p_mq_parm->mq_int_enc);
                }
            }
        }
    }
    return iSize;
}

static gint dissect_mq_pmo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, mq_parm_t *p_mq_parm, gint *iDistributionListSize)
{
    gint iSize = 0;

    p_mq_parm->mq_strucID = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
    if (p_mq_parm->mq_strucID == MQ_STRUCTID_PMO || p_mq_parm->mq_strucID == MQ_STRUCTID_PMO_EBCDIC)
    {
        guint32 iVersion = 0;
        iVersion = tvb_get_guint32_endian(tvb, offset + 4, p_mq_parm->mq_int_enc);
        /* Compute length according to version */
        switch (iVersion)
        {
        case 1: iSize = 128; break;
        case 2: iSize = 152;break;
        }

        if (iSize != 0 && tvb_length_remaining(tvb, offset) >= iSize)
        {
            guint8 *sQueue;

            sQueue = tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 32, 48, p_mq_parm->mq_str_enc);
            if (strip_trailing_blanks(sQueue, 48) > 0)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, " Q=%s", sQueue);
            }

            if (tree)
            {
                proto_tree  *mq_tree;
                proto_item  *ti;

                ti = proto_tree_add_text(tree, tvb, offset, iSize, MQ_TEXT_PMO);
                mq_tree = proto_item_add_subtree(ti, ett_mq_pmo);
                proto_tree_add_item(mq_tree, hf_mq_pmo_StructID, tvb, offset, 4, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_pmo_version, tvb, offset + 4, 4, p_mq_parm->mq_int_enc);

                dissect_mq_MQPMO(tvb, mq_tree, offset + 8, ett_mq_pmo_option, p_mq_parm);

                proto_tree_add_item(mq_tree, hf_mq_pmo_timeout    , tvb, offset + 12, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_pmo_context    , tvb, offset + 16, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_pmo_knowndstcnt, tvb, offset + 20, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_pmo_unkndstcnt , tvb, offset + 24, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_pmo_invaldstcnt, tvb, offset + 28, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_pmo_resolvqname, tvb, offset + 32, 48, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_pmo_resolvqmgr , tvb, offset + 80, 48, p_mq_parm->mq_str_enc);

                if (iVersion >= 2)
                {
                    proto_tree_add_item(mq_tree, hf_mq_pmo_recspresent , tvb, offset + 128, 4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_pmo_putmsgrecfld, tvb, offset + 132, 4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_pmo_putmsgrecofs, tvb, offset + 136, 4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_pmo_resprecofs  , tvb, offset + 140, 4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_pmo_putmsgrecptr, tvb, offset + 144, 4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_pmo_resprecptr  , tvb, offset + 148, 4, p_mq_parm->mq_int_enc);
                }
            }
            if (iVersion >= 2)
            {
                gint iNbrRecords = 0;
                guint32 iRecFlags = 0;

                iNbrRecords = tvb_get_guint32_endian(tvb, offset + 128, p_mq_parm->mq_int_enc);
                iRecFlags = tvb_get_guint32_endian(tvb, offset + 132, p_mq_parm->mq_int_enc);

                if (iNbrRecords > 0)
                {
                    gint iOffsetPMR = 0;
                    gint iOffsetRR = 0;

                    *iDistributionListSize = iNbrRecords;
                    iOffsetPMR = tvb_get_guint32_endian(tvb, offset + 136, p_mq_parm->mq_int_enc);
                    iOffsetRR  = tvb_get_guint32_endian(tvb, offset + 140, p_mq_parm->mq_int_enc);
                    iSize += dissect_mq_pmr(tvb, tree, offset + iSize, iNbrRecords, iOffsetPMR, iRecFlags, p_mq_parm);
                    iSize += dissect_mq_rr(tvb, tree, offset + iSize, iNbrRecords, iOffsetRR, p_mq_parm);
                }
            }
        }
    }
    return iSize;
}

static gint dissect_mq_od(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, mq_parm_t *p_mq_parm, gint *iDistributionListSize)
{
    gint iSize = 0;

    p_mq_parm->mq_strucID = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
    if (p_mq_parm->mq_strucID == MQ_STRUCTID_OD || p_mq_parm->mq_strucID == MQ_STRUCTID_OD_EBCDIC)
    {
        /* The OD struct can be present in several messages at different levels */
        guint32 iVersion = 0;
        iVersion = tvb_get_guint32_endian(tvb, offset + 4, p_mq_parm->mq_int_enc);
        /* Compute length according to version */
        switch (iVersion)
        {
        case 1: iSize = 168; break;
        case 2: iSize = 200; break;
        case 3: iSize = 336; break;
        case 4: iSize = 336+3*20+4; break;
        }

        if (iSize != 0 && tvb_length_remaining(tvb, offset) >= iSize)
        {
            gint     iNbrRecords = 0;
            guint8    *sObj;
            guint32     uTyp;

            if (iVersion >= 2)
                iNbrRecords = tvb_get_guint32_endian(tvb, offset + 168, p_mq_parm->mq_int_enc);

            uTyp = tvb_get_guint32_endian(tvb, offset + 8, p_mq_parm->mq_int_enc);
            sObj = tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 12, 48, p_mq_parm->mq_str_enc);
            col_append_fstr(pinfo->cinfo, COL_INFO, " Typ=%s", try_val_to_str(uTyp, GET_VALSV(objtype)));
            if (strip_trailing_blanks(sObj, 48) > 0)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, " Obj=%s", sObj);
            }

            if (tree)
            {
                proto_tree  *mq_tree;
                proto_item  *ti;

                ti = proto_tree_add_text(tree, tvb, offset, iSize, MQ_TEXT_OD);
                mq_tree = proto_item_add_subtree(ti, ett_mq_od);

                proto_tree_add_item(mq_tree, hf_mq_od_StructID   , tvb, offset,        4, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_od_version    , tvb, offset +   4,  4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_od_objecttype , tvb, offset +   8,  4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_od_objectname , tvb, offset +  12, 48, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_od_objqmgrname, tvb, offset +  60, 48, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_od_dynqname   , tvb, offset + 108, 48, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_od_altuserid  , tvb, offset + 156, 12, p_mq_parm->mq_str_enc);

                if (iVersion >= 2)
                {
                    proto_tree_add_item(mq_tree, hf_mq_od_recspresent , tvb, offset + 168, 4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_od_knowndstcnt , tvb, offset + 172, 4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_od_unknowdstcnt, tvb, offset + 176, 4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_od_invaldstcnt , tvb, offset + 180, 4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_od_objrecofs   , tvb, offset + 184, 4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_od_resprecofs  , tvb, offset + 188, 4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_od_objrecptr   , tvb, offset + 192, 4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_od_resprecptr  , tvb, offset + 196, 4, p_mq_parm->mq_int_enc);
                }
                if (iVersion >= 3)
                {
                    proto_tree_add_item(mq_tree, hf_mq_od_altsecurid  , tvb, offset + 200, 40, p_mq_parm->mq_str_enc);
                    proto_tree_add_item(mq_tree, hf_mq_od_resolvqname , tvb, offset + 240, 48, p_mq_parm->mq_str_enc);
                    proto_tree_add_item(mq_tree, hf_mq_od_resolvqmgrnm, tvb, offset + 288, 48, p_mq_parm->mq_str_enc);
                }
                if (iVersion >= 4)
                {
                    dissect_mq_charv(tvb, mq_tree, offset+336, 20, ett_mq_od_objstr,    (guint8 *)"Object string",          p_mq_parm);
                    dissect_mq_charv(tvb, mq_tree, offset+356, 20, ett_mq_od_selstr,    (guint8 *)"Selection string",       p_mq_parm);
                    dissect_mq_charv(tvb, mq_tree, offset+376, 20, ett_mq_od_resobjstr, (guint8 *)"Resolved object string", p_mq_parm);
                    proto_tree_add_item(mq_tree, hf_mq_od_resolvobjtyp, tvb, offset + 396, 4, p_mq_parm->mq_int_enc);
                }
            }
            if (iNbrRecords > 0)
            {
                gint iOffsetOR = 0;
                gint iOffsetRR = 0;

                *iDistributionListSize = iNbrRecords;
                iOffsetOR = tvb_get_guint32_endian(tvb, offset + 184, p_mq_parm->mq_int_enc);
                iOffsetRR = tvb_get_guint32_endian(tvb, offset + 188, p_mq_parm->mq_int_enc);

                iSize += dissect_mq_or(tvb, tree, offset, iNbrRecords, iOffsetOR, p_mq_parm);
                iSize += dissect_mq_rr(tvb, tree, offset, iNbrRecords, iOffsetRR, p_mq_parm);
            }
        }
    }
    return iSize;
}

static gint dissect_mq_xid(tvbuff_t *tvb, proto_tree *tree, mq_parm_t *p_mq_parm, gint offset)
{
    gint iSizeXid = 0;
    if (tvb_length_remaining(tvb, offset) >= 6)
    {
        guint8 iXidLength = 0;
        guint8 iBqLength  = 0;

        iXidLength = tvb_get_guint8(tvb, offset + 4);
        iBqLength  = tvb_get_guint8(tvb, offset + 5);
        iSizeXid   = 6 + iXidLength + iBqLength;

        if (tvb_length_remaining(tvb, offset) >= iSizeXid)
        {
            if (tree)
            {
                proto_tree  *mq_tree;
                proto_item  *ti;

                ti = proto_tree_add_text(tree, tvb, offset, iSizeXid, MQ_TEXT_XID);
                mq_tree = proto_item_add_subtree(ti, ett_mq_xa_xid);

                proto_tree_add_item(mq_tree, hf_mq_xa_xid_formatid  , tvb, offset                 , 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_xa_xid_glbxid_len, tvb, offset + 4             , 1, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_xa_xid_brq_length, tvb, offset + 5             , 1, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_xa_xid_globalxid , tvb, offset + 6             , iXidLength, ENC_NA);
                proto_tree_add_item(mq_tree, hf_mq_xa_xid_brq       , tvb, offset + 6 + iXidLength, iBqLength,  ENC_NA);
            }
            iSizeXid += (4 - (iSizeXid % 4)) % 4; /* Pad for alignment with 4 byte word boundary */
            if (tvb_length_remaining(tvb, offset) < iSizeXid)
                iSizeXid = 0;
        }
        else iSizeXid = 0;
    }
    return iSizeXid;
}

static gint dissect_mq_sid(tvbuff_t *tvb, proto_tree *tree, mq_parm_t *p_mq_parm, gint offset)
{
    guint8    iSIDL;
    guint8    iSID;
    char *sid_str;
    gint    bOffset    = offset;

    iSIDL = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_mq_sidlen, tvb, offset, 1, p_mq_parm->mq_int_enc);
    offset++;
    if (iSIDL > 0)
    {
        iSID = tvb_get_guint8(tvb, offset);
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
static gint dissect_mq_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *mqroot_tree, gint offset, mq_parm_t *p_mq_parm)
{
    guint8 iFAPLvl;
    gint   iSize;

    iFAPLvl = tvb_get_guint8(tvb, offset + 4);

    if (iFAPLvl < 4)
        iSize = 44;
    else if (iFAPLvl < 10)
        iSize = 102;
    else
        iSize = 208;

    if (iSize != 0 && tvb_length_remaining(tvb, offset) >= iSize)
    {
        guint8 *sChannel;
        sChannel = tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 24, 20, p_mq_parm->mq_str_enc);
        col_append_fstr(pinfo->cinfo, COL_INFO, " FAPLvl=%d", iFAPLvl);
        if (strip_trailing_blanks(sChannel, 20) > 0)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, ", CHL=%s", sChannel);
        }
        if (iFAPLvl >= 4)
        {
            guint8 *sQMgr;
            sQMgr = tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 48, 48, p_mq_parm->mq_str_enc);
            if (strip_trailing_blanks(sQMgr, 48) > 0)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, ", QM=%s", sQMgr);
            }
            p_mq_parm->mq_id_ccsid.ccsid = (guint32)tvb_get_guint16_endian(tvb, offset +  46,  p_mq_parm->mq_int_enc);
        }
        if (mqroot_tree)
        {
            proto_item *ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSize, MQ_TEXT_ID);
            proto_tree *mq_tree = proto_item_add_subtree(ti, ett_mq_id);

            proto_tree_add_item(mq_tree, hf_mq_id_StructID, tvb, offset, 4, p_mq_parm->mq_str_enc);
            proto_tree_add_item(mq_tree, hf_mq_id_FapLevel, tvb, offset + 4, 1, ENC_BIG_ENDIAN);

            /* ID Capability flags 1 */
            proto_tree_add_bitmask(mq_tree, tvb, offset + 44, hf_mq_id_icf1, ett_mq_id_icf1, pf_flds_icf1, ENC_BIG_ENDIAN);
            proto_tree_add_item(mq_tree, hf_mq_id_Eicf1, tvb, offset + 6, 1, ENC_BIG_ENDIAN);

            /* Error flags 1*/
            proto_tree_add_bitmask(mq_tree, tvb, offset + 7, hf_mq_id_ief1, ett_mq_id_ief1, pf_flds_ief1, ENC_BIG_ENDIAN);

            proto_tree_add_item(mq_tree, hf_mq_id_Reserved   , tvb, offset +  8,  2, p_mq_parm->mq_int_enc);
            proto_tree_add_item(mq_tree, hf_mq_id_MaxMsgBatch, tvb, offset + 10,  2, p_mq_parm->mq_int_enc);
            proto_tree_add_item(mq_tree, hf_mq_id_MaxTrSize  , tvb, offset + 12,  4, p_mq_parm->mq_int_enc);
            proto_tree_add_item(mq_tree, hf_mq_id_MaxMsgSize , tvb, offset + 16,  4, p_mq_parm->mq_int_enc);
            proto_tree_add_item(mq_tree, hf_mq_id_SeqWrapVal , tvb, offset + 20,  4, p_mq_parm->mq_int_enc);
            proto_tree_add_item(mq_tree, hf_mq_id_channel    , tvb, offset + 24, 20, p_mq_parm->mq_str_enc);

            if (iFAPLvl >= 4)
            {
                /* ID Capability flags 2 */
                proto_tree_add_bitmask(mq_tree, tvb, offset + 44, hf_mq_id_icf2, ett_mq_id_icf2, pf_flds_icf2, ENC_BIG_ENDIAN);
                proto_tree_add_item(mq_tree, hf_mq_id_Eicf2, tvb, offset + 45, 1, ENC_BIG_ENDIAN);

                proto_tree_add_item(mq_tree, hf_mq_id_ccsid     , tvb, offset +  46,  2, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_id_qmgrname  , tvb, offset +  48, 48, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_id_HBInterval, tvb, offset +  96,  4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_id_EFLLength , tvb, offset + 100,  2, p_mq_parm->mq_int_enc);
                if (iFAPLvl >= 10)
                {
                    /* Error flags 2*/
                    proto_tree_add_bitmask(mq_tree, tvb, offset + 102, hf_mq_id_ief2, ett_mq_id_ief2, pf_flds_ief2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(mq_tree, hf_mq_id_Reserved1 , tvb, offset + 103,  1, ENC_BIG_ENDIAN);

                    proto_tree_add_item(mq_tree, hf_mq_id_HdrCprsLst, tvb, offset + 104,  2, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_id_MsgCprsLst, tvb, offset + 106, 16, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_id_Reserved2 , tvb, offset + 122,  2, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_id_SSLKeyRst , tvb, offset + 124,  4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_id_ConvBySkt , tvb, offset + 128,  4, p_mq_parm->mq_int_enc);

                    /* ID Capability flags 3 */
                    proto_tree_add_bitmask(mq_tree, tvb, offset + 132, hf_mq_id_icf3, ett_mq_id_icf3, pf_flds_icf3, ENC_BIG_ENDIAN);
                    proto_tree_add_item(mq_tree, hf_mq_id_Eicf3, tvb, offset + 133, 1, ENC_BIG_ENDIAN);

                    proto_tree_add_item(mq_tree, hf_mq_id_Reserved3, tvb, offset + 134,  2, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_id_ProcessId, tvb, offset + 136,  4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_id_ThreadId , tvb, offset + 140,  4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_id_TraceId  , tvb, offset + 144,  4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_id_ProdId   , tvb, offset + 148, 12, p_mq_parm->mq_str_enc);
                    proto_tree_add_item(mq_tree, hf_mq_id_mqmid    , tvb, offset + 160, 48, p_mq_parm->mq_str_enc);
                }
            }
        }
    }
    return iSize;
}
static gint dissect_mq_md(tvbuff_t *tvb, proto_tree *tree, gint offset, mq_parm_t *p_mq_parm, gboolean bDecode)
{
    gint iSize = 0;

    p_mq_parm->mq_strucID = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
    if (p_mq_parm->mq_strucID == MQ_STRUCTID_MD || p_mq_parm->mq_strucID == MQ_STRUCTID_MD_EBCDIC)
    {
        guint32 iVersion = 0;
        iVersion = tvb_get_guint32_endian(tvb, offset + 4, p_mq_parm->mq_int_enc);
        /* Compute length according to version */
        switch (iVersion)
        {
        case 1: iSize = 324; break;
        case 2: iSize = 364; break;
        }

        if (bDecode && iSize != 0 && tvb_length_remaining(tvb, offset) >= iSize)
        {
            p_mq_parm->iOfsEnc = offset + 24;
            p_mq_parm->iOfsCcs = offset + 28;
            p_mq_parm->iOfsFmt = offset + 32;

            p_mq_parm->mq_md_ccsid.encod = tvb_get_guint32_endian(tvb, offset +  24,  p_mq_parm->mq_int_enc);
            p_mq_parm->mq_md_ccsid.ccsid = tvb_get_guint32_endian(tvb, offset +  28,  p_mq_parm->mq_int_enc);
            if (tree)
            {
                proto_item *ti = proto_tree_add_text(tree, tvb, offset, iSize, MQ_TEXT_MD);
                proto_tree *mq_tree = proto_item_add_subtree(ti, ett_mq_md);

                proto_tree_add_item(mq_tree, hf_mq_md_StructID   , tvb, offset,        4, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_version    , tvb, offset +   4,  4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_report     , tvb, offset +   8,  4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_msgtype    , tvb, offset +  12,  4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_expiry     , tvb, offset +  16,  4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_feedback   , tvb, offset +  20,  4, p_mq_parm->mq_int_enc);
                dissect_mq_encoding(mq_tree, hf_mq_md_encoding   , tvb, offset +  24,  4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_ccsid      , tvb, offset +  28,  4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_format     , tvb, offset +  32,  8, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_priority   , tvb, offset +  40,  4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_persistence, tvb, offset +  44,  4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_msgid      , tvb, offset +  48, 24, ENC_NA);
                proto_tree_add_item(mq_tree, hf_mq_md_correlid   , tvb, offset +  72, 24, ENC_NA);
                proto_tree_add_item(mq_tree, hf_mq_md_backoutcnt , tvb, offset +  96,  4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_replytoq   , tvb, offset + 100, 48, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_replytoqmgr, tvb, offset + 148, 48, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_userid     , tvb, offset + 196, 12, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_acttoken   , tvb, offset + 208, 32, ENC_NA);
                proto_tree_add_item(mq_tree, hf_mq_md_appliddata , tvb, offset + 240, 32, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_putappltype, tvb, offset + 272,  4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_putapplname, tvb, offset + 276, 28, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_putdate    , tvb, offset + 304,  8, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_puttime    , tvb, offset + 312,  8, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_md_apporigdata, tvb, offset + 320,  4, p_mq_parm->mq_str_enc);

                if (iVersion >= 2)
                {
                    proto_tree_add_item(mq_tree, hf_mq_md_groupid,        tvb, offset + 324, 24, ENC_NA);
                    proto_tree_add_item(mq_tree, hf_mq_md_msgseqnumber, tvb, offset + 348,  4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_md_offset,        tvb, offset + 352,  4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_md_msgflags,        tvb, offset + 356,  4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_md_origlen,        tvb, offset + 360,  4, p_mq_parm->mq_int_enc);
                }
            }
        }
    }
    return iSize;
}
static gint dissect_mq_fopa(tvbuff_t *tvb, proto_tree *tree, gint offset, mq_parm_t *p_mq_parm)
{
    gint iSize = 0;

    p_mq_parm->mq_strucID = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
    if (p_mq_parm->mq_strucID == MQ_STRUCTID_FOPA || p_mq_parm->mq_strucID == MQ_STRUCTID_FOPA_EBCDIC)
    {
        iSize = tvb_get_guint32_endian(tvb, offset+8, p_mq_parm->mq_int_enc);
        if (iSize != 0 && tvb_length_remaining(tvb, offset) >= iSize)
        {
            if (tree)
            {
                proto_item *ti = proto_tree_add_text(tree, tvb, offset, iSize, MQ_TEXT_FOPA);
                proto_tree *mq_tree = proto_item_add_subtree(ti, ett_mq_fopa);

                proto_tree_add_item(mq_tree, hf_mq_fopa_StructID, tvb, offset,      4, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_fopa_version , tvb, offset +  4, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_fopa_length  , tvb, offset +  8, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_fopa_unknown1, tvb, offset + 12, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_fopa_unknown2, tvb, offset + 16, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_fopa_unknown3, tvb, offset + 20, 8, p_mq_parm->mq_str_enc);
                if (iSize > 28)
                {
                    proto_tree_add_item(mq_tree, hf_mq_fopa_qprotect, tvb, offset + 28, 48, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_fopa_unknown4, tvb, offset + 76, 4, p_mq_parm->mq_int_enc);
                    proto_tree_add_item(mq_tree, hf_mq_fopa_unknown5, tvb, offset + 80, 4, p_mq_parm->mq_int_enc);
                }
            }
        }
    }
    return iSize;
}
static void dissect_mq_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint       offset                 = 0;
    guint32       iSegmentLength         = 0;
    guint32       iSizePayload             = 0;
    gint       iSizeMD                 = 0;
    gboolean   bPayload                 = FALSE;
    gboolean   bEBCDIC                 = FALSE;
    gint       iDistributionListSize = 0;
    mq_parm_t *p_mq_parm;
    heur_dtbl_entry_t *hdtbl_entry;

    p_mq_parm = wmem_new0(wmem_packet_scope(), mq_parm_t);

    p_mq_parm->mq_strucID = MQ_STRUCTID_NULL;
    p_mq_parm->mq_int_enc = ENC_BIG_ENDIAN;
    p_mq_parm->mq_str_enc = ENC_UTF_8|ENC_NA;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MQ");

    p_mq_parm->iOfsEnc = 0;
    p_mq_parm->iOfsFmt = 0;
    p_mq_parm->iOfsCcs = 0;
    if (tvb_length(tvb) >= 4)
    {
        p_mq_parm->mq_strucID = tvb_get_ntohl(tvb, offset);
        if (((p_mq_parm->mq_strucID & MQ_MASK_TSHx) == MQ_STRUCTID_TSHx ||
             (p_mq_parm->mq_strucID & MQ_MASK_TSHx) == MQ_STRUCTID_TSHx_EBCDIC)
            && tvb_length_remaining(tvb, offset) >= 28)
        {
            proto_tree *mq_tree        = NULL;
            proto_tree *mqroot_tree = NULL;
            proto_item *ti            = NULL;

            /* An MQ packet always starts with this structure*/
            gint iSizeTSH = 28;
            gint iSizeMPF = 0;  /* Size Of Multiplexed Field */

            if ((p_mq_parm->mq_strucID & MQ_MASK_TSHx) == MQ_STRUCTID_TSHx_EBCDIC)
            {
                bEBCDIC = TRUE;
                p_mq_parm->mq_str_enc = ENC_EBCDIC|ENC_NA;
            }

            iSegmentLength = tvb_get_ntohl(tvb, offset + 4);

            if (p_mq_parm->mq_strucID == MQ_STRUCTID_TSHM || p_mq_parm->mq_strucID == MQ_STRUCTID_TSHM_EBCDIC)
            {
                if (tvb_length_remaining(tvb, offset) < 36)
                    return;
                iSizeMPF += 8;
                iSizeTSH  = 36;
            }
            p_mq_parm->mq_opcode = tvb_get_guint8(tvb, offset + iSizeMPF + 9);

            if (p_mq_parm->mq_opcode == MQ_TST_REQUEST_MSGS || p_mq_parm->mq_opcode == MQ_TST_ASYNC_MESSAGE)
            {
                p_mq_parm->iOfsEnc = offset + iSizeMPF + 20;
                p_mq_parm->iOfsCcs = offset + iSizeMPF + 24;
                p_mq_parm->iOfsFmt = offset ;
            }
            p_mq_parm->mq_int_enc = (tvb_get_guint8(tvb, offset + iSizeMPF + 8) == MQ_LITTLE_ENDIAN ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
            p_mq_parm->mq_ctlf1 = tvb_get_guint8(tvb, offset + iSizeMPF + 10);
            p_mq_parm->mq_ctlf2 = tvb_get_guint8(tvb, offset + iSizeMPF + 11);

            p_mq_parm->mq_tsh_ccsid.encod = tvb_get_guint32_endian(tvb, offset + iSizeMPF + 20, p_mq_parm->mq_int_enc);
            p_mq_parm->mq_tsh_ccsid.ccsid = tvb_get_guint16_endian(tvb, offset + iSizeMPF + 24, p_mq_parm->mq_int_enc);

            if (p_mq_parm->mq_tsh_ccsid.ccsid == 500 && !bEBCDIC)
            {
                bEBCDIC = TRUE;
                p_mq_parm->mq_str_enc = ENC_EBCDIC|ENC_NA;
            }

            if (!mq_in_reassembly)
            {
                col_clear(pinfo->cinfo, COL_INFO);
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, " | ", "%-17s", val_to_str(p_mq_parm->mq_opcode, mq_opcode_vals, "Unknown (0x%02x)"));
                col_set_fence(pinfo->cinfo, COL_INFO);
            }

            if (tree)
            {
                if (p_mq_parm->mq_opcode!=MQ_TST_ASYNC_MESSAGE)
                {
                    ti = proto_tree_add_item(tree, proto_mq, tvb, offset, -1, ENC_NA);
                    proto_item_append_text(ti, " (%s)", val_to_str(p_mq_parm->mq_opcode, mq_opcode_vals, "Unknown (0x%02x)"));
                    if (bEBCDIC == TRUE)
                        proto_item_append_text(ti, " (EBCDIC)");
                    mqroot_tree = proto_item_add_subtree(ti, ett_mq);
                }
                else
                {
                    mqroot_tree = tree;
                }

                ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSizeTSH, MQ_TEXT_TSH);
                mq_tree = proto_item_add_subtree(ti, ett_mq_tsh);

                proto_tree_add_item(mq_tree, hf_mq_tsh_StructID, tvb, offset + 0, 4, p_mq_parm->mq_str_enc);
                proto_tree_add_item(mq_tree, hf_mq_tsh_mqseglen, tvb, offset + 4, 4, ENC_BIG_ENDIAN);

                if (iSizeTSH == 36)
                {
                    proto_tree_add_item(mq_tree, hf_mq_tsh_convid,    tvb, offset +  8, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(mq_tree, hf_mq_tsh_requestid, tvb, offset + 12, 4, ENC_BIG_ENDIAN);
                }

                proto_tree_add_item(mq_tree, hf_mq_tsh_byteorder, tvb, offset + iSizeMPF + 8, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(mq_tree, hf_mq_tsh_opcode,    tvb, offset + iSizeMPF + 9, 1, ENC_BIG_ENDIAN);

                proto_tree_add_bitmask(mq_tree, tvb, offset + iSizeMPF + 10, hf_mq_tsh_ctlflgs1, ett_mq_tsh_tcf, pf_flds_tcf, ENC_BIG_ENDIAN);
                proto_tree_add_bitmask(mq_tree, tvb, offset + iSizeMPF + 11, hf_mq_tsh_ctlflgs2, ett_mq_tsh_tcf2, pf_flds_tcf2, ENC_BIG_ENDIAN);

                proto_tree_add_item(mq_tree, hf_mq_tsh_luwid,    tvb, offset + iSizeMPF + 12, 8, ENC_NA);
                dissect_mq_encoding(mq_tree, hf_mq_tsh_encoding, tvb, offset + iSizeMPF + 20, 4, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_tsh_ccsid,    tvb, offset + iSizeMPF + 24, 2, p_mq_parm->mq_int_enc);
                proto_tree_add_item(mq_tree, hf_mq_tsh_reserved, tvb, offset + iSizeMPF + 26, 2, p_mq_parm->mq_int_enc);
            }
            offset += iSizeTSH;

            /* Now dissect the embedded structures */
            if (tvb_length_remaining(tvb, offset) >= 4)
            {
                p_mq_parm->mq_strucID = tvb_get_ntohl(tvb, offset);
                if (((p_mq_parm->mq_ctlf1 & MQ_TCF_FIRST) != 0) || p_mq_parm->mq_opcode < 0x80)
                {
                    /* First MQ segment (opcodes below 0x80 never span several TSH) */
                    gint iSizeAPI = 16;
                    if (p_mq_parm->mq_opcode >= 0x80 && p_mq_parm->mq_opcode <= 0x9F && tvb_length_remaining(tvb, offset) >= 16)
                    {
                        guint32 iReturnCode = 0;
                        guint32 iHdl = 0;
                        iReturnCode = tvb_get_guint32_endian(tvb, offset + 8, p_mq_parm->mq_int_enc);
                        iHdl = tvb_get_guint32_endian(tvb, offset + 12, p_mq_parm->mq_int_enc);
                        if (iHdl != 0 && iHdl != 0xffffffff)
                            col_append_fstr(pinfo->cinfo, COL_INFO, " Hdl=0x%08x", iHdl);
                        if (iReturnCode != 0)
                            col_append_fstr(pinfo->cinfo, COL_INFO, " [RC=%d]", iReturnCode);

                        if (tree)
                        {
                            ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSizeAPI, MQ_TEXT_API);
                            mq_tree = proto_item_add_subtree(ti, ett_mq_api);

                            proto_tree_add_item(mq_tree, hf_mq_api_replylen,  tvb, offset,      4, ENC_BIG_ENDIAN);
                            proto_tree_add_item(mq_tree, hf_mq_api_compcode,  tvb, offset +  4, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_api_reascode,  tvb, offset +  8, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_api_objecthdl, tvb, offset + 12, 4, p_mq_parm->mq_int_enc);
                        }
                        offset += iSizeAPI;
                        p_mq_parm->mq_strucID = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
                    }
                    if ((p_mq_parm->mq_strucID == MQ_STRUCTID_MSH || p_mq_parm->mq_strucID == MQ_STRUCTID_MSH_EBCDIC) && tvb_length_remaining(tvb, offset) >= 20)
                    {
                        gint iSize = 20;
                        iSizePayload = tvb_get_guint32_endian(tvb, offset + 16, p_mq_parm->mq_int_enc);
                        bPayload = TRUE;
                        if (tree)
                        {
                            ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSize, MQ_TEXT_MSH);
                            mq_tree = proto_item_add_subtree(ti, ett_mq_msh);

                            proto_tree_add_item(mq_tree, hf_mq_msh_StructID,   tvb, offset +  0, 4, p_mq_parm->mq_str_enc);
                            proto_tree_add_item(mq_tree, hf_mq_msh_seqnum,       tvb, offset +  4, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_msh_datalength, tvb, offset +  8, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_msh_unknown1,   tvb, offset + 12, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_msh_msglength,  tvb, offset + 16, 4, p_mq_parm->mq_int_enc);
                        }
                        offset += iSize;
                    }
                    else if (p_mq_parm->mq_opcode == MQ_TST_CONAUTH_INFO && tvb_length_remaining(tvb, offset) >= 20)
                    {
                        gint iSize = 24;
                        gint iUsr  = 0;
                        gint iPsw  = 0;

                        iUsr = tvb_get_guint32_endian(tvb, offset + 16, p_mq_parm->mq_int_enc);
                        iPsw = tvb_get_guint32_endian(tvb, offset + 20, p_mq_parm->mq_int_enc);

                        if (tree)
                        {
                            ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSize, MQ_TEXT_CAUT);
                            mq_tree = proto_item_add_subtree(ti, ett_mq_caut);

                            proto_tree_add_item(mq_tree, hf_mq_caut_StructID,  tvb, offset,      4, p_mq_parm->mq_str_enc);
                            proto_tree_add_item(mq_tree, hf_mq_caut_AuthType,  tvb, offset +  4, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_caut_UsrMaxLen, tvb, offset +  8, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_caut_PwdMaxLen, tvb, offset + 12, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_caut_UsrLength, tvb, offset + 16, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_caut_PwdLength, tvb, offset + 20, 4, p_mq_parm->mq_int_enc);

                            if (iUsr)
                                proto_tree_add_item(mq_tree, hf_mq_caut_usr, tvb, offset + 24,        iUsr, p_mq_parm->mq_str_enc);
                            if (iPsw)
                                proto_tree_add_item(mq_tree, hf_mq_caut_psw, tvb, offset + 24 + iUsr, iPsw, p_mq_parm->mq_str_enc);
}
                        offset += iSize + iUsr + iPsw;
                        p_mq_parm->mq_strucID = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
                    }
                    else if (p_mq_parm->mq_opcode == MQ_TST_SOCKET_ACTION && tvb_length_remaining(tvb, offset) >= 20)
                    {
                        gint iSize = 20;
                        if (tree)
                        {
                            ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSizeAPI, MQ_TEXT_SOCKET);
                            mq_tree = proto_item_add_subtree(ti, ett_mq_socket);

                            proto_tree_add_item(mq_tree, hf_mq_socket_conversid, tvb, offset,      4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_socket_requestid, tvb, offset +  4, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_socket_type,      tvb, offset +  8, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_socket_parm1,     tvb, offset + 12, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_socket_parm2,     tvb, offset + 16, 4, p_mq_parm->mq_int_enc);
                        }
                        offset += iSize;
                        p_mq_parm->mq_strucID = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
                    }
                    else if (p_mq_parm->mq_opcode == MQ_TST_STATUS && tvb_length_remaining(tvb, offset) >= 8)
                    {
                        /* Some status are 28 bytes long and some are 36 bytes long */
                        gint iStatus       = 0;
                        gint iStatusLength = 0;

                        iStatus = tvb_get_guint32_endian(tvb, offset + 4, p_mq_parm->mq_int_enc);
                        iStatusLength = tvb_get_guint32_endian(tvb, offset, p_mq_parm->mq_int_enc);

                        if (tvb_length_remaining(tvb, offset) >= iStatusLength)
                        {
                            if (iStatus != 0)
                                col_append_fstr(pinfo->cinfo, COL_INFO, " Code=%s", val_to_str(iStatus, GET_VALSV(status), "Unknown (0x%08x)"));

                            if (tree)
                            {
                                ti = proto_tree_add_text(mqroot_tree, tvb, offset, 8, MQ_TEXT_STAT);
                                mq_tree = proto_item_add_subtree(ti, ett_mq_status);

                                proto_tree_add_item(mq_tree, hf_mq_status_length, tvb, offset,     4, p_mq_parm->mq_int_enc);
                                proto_tree_add_item(mq_tree, hf_mq_status_code,   tvb, offset + 4, 4, p_mq_parm->mq_int_enc);

                                if (iStatusLength >= 12)
                                    proto_tree_add_item(mq_tree, hf_mq_status_value, tvb, offset + 8, 4, p_mq_parm->mq_int_enc);
                            }
                            offset += iStatusLength;
                        }
                    }
                    else if (p_mq_parm->mq_opcode == MQ_TST_PING && tvb_length_remaining(tvb, offset) > 4)
                    {
                        if (tree)
                        {
                            ti = proto_tree_add_text(mqroot_tree, tvb, offset, -1, MQ_TEXT_PING);
                            mq_tree = proto_item_add_subtree(ti, ett_mq_ping);

                            proto_tree_add_item(mq_tree, hf_mq_ping_length, tvb, offset,      4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_ping_buffer, tvb, offset + 4, -1, ENC_NA);
                        }
                        offset = tvb_length(tvb);
                    }
                    else if (p_mq_parm->mq_opcode == MQ_TST_RESET && tvb_length_remaining(tvb, offset) >= 8)
                    {
                        if (tree)
                        {
                            ti = proto_tree_add_text(mqroot_tree, tvb, offset, -1, MQ_TEXT_RESET);
                            mq_tree = proto_item_add_subtree(ti, ett_mq_reset);

                            proto_tree_add_item(mq_tree, hf_mq_reset_length, tvb, offset,     4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_reset_seqnum, tvb, offset + 4, 4, p_mq_parm->mq_int_enc);
                        }
                        offset = tvb_length(tvb);
                    }
                    else if ((p_mq_parm->mq_opcode == MQ_TST_MQOPEN || p_mq_parm->mq_opcode == MQ_TST_MQCLOSE ||
                         p_mq_parm->mq_opcode == MQ_TST_MQOPEN_REPLY || p_mq_parm->mq_opcode == MQ_TST_MQCLOSE_REPLY)
                         && tvb_length_remaining(tvb, offset) >= 4)
                    {
                        offset += dissect_mq_od(tvb, pinfo, mqroot_tree, offset, p_mq_parm, &iDistributionListSize);
                        if (tree)
                        {
                            ti = proto_tree_add_text(mqroot_tree, tvb, offset, 4, MQ_TEXT_OPEN);
                            mq_tree = proto_item_add_subtree(ti, ett_mq_open);
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
                        p_mq_parm->mq_strucID = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
                        offset += dissect_mq_fopa(tvb, mqroot_tree, offset, p_mq_parm);
                    }
                    else if ((p_mq_parm->mq_opcode == MQ_TST_MQCONN || p_mq_parm->mq_opcode == MQ_TST_MQCONN_REPLY) &&
                        tvb_length_remaining(tvb, offset) > 0)
                    {
                        gint iSizeCONN = 0;
                        gint nofs;

                        /*iSizeCONN = ((iVersionID == 4 || iVersionID == 6) ? 120 : 112);*/ /* guess */
                        /* The iVersionID is available in the previous ID segment, we should keep a state
                        * Instead we rely on the segment length announced in the TSH */
                        /* The MQCONN structure is special because it does not start with a structid */
                        iSizeCONN = iSegmentLength - iSizeTSH - iSizeAPI;
                        if (iSizeCONN != 112 && iSizeCONN != 120 && iSizeCONN != 260 && iSizeCONN != 332)
                            iSizeCONN = 0;

                        if (iSizeCONN != 0 && tvb_length_remaining(tvb, offset) >= iSizeCONN)
                        {
                            guint8 *sApplicationName;
                            guint8 *sQMgr;
                            sApplicationName = format_text_chr(tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 48, 28, p_mq_parm->mq_str_enc), 28, '.');
                            if (strip_trailing_blanks(sApplicationName, 28) > 0)
                            {
                                col_append_fstr(pinfo->cinfo, COL_INFO, " App=%s", sApplicationName);
                            }
                            sQMgr = format_text_chr(tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 48, p_mq_parm->mq_str_enc), 48, '.');
                            if (strip_trailing_blanks(sQMgr, 48) > 0)
                            {
                                col_append_fstr(pinfo->cinfo, COL_INFO, " QM=%s", sQMgr);
                            }

#define do_proto_add_item(a, b) b; nofs += a;
                            nofs = offset;
                            if (tree)
                            {
                                ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSizeCONN, MQ_TEXT_CONN);
                                mq_tree = proto_item_add_subtree(ti, ett_mq_conn);

                                do_proto_add_item(48, proto_tree_add_item(mq_tree, hf_mq_conn_QMgr    , tvb, nofs, 48, p_mq_parm->mq_str_enc));
                                do_proto_add_item(28, proto_tree_add_item(mq_tree, hf_mq_conn_appname , tvb, nofs, 28, p_mq_parm->mq_str_enc));
                                do_proto_add_item( 4, proto_tree_add_item(mq_tree, hf_mq_conn_apptype , tvb, nofs,  4, p_mq_parm->mq_int_enc));
                                do_proto_add_item(32, proto_tree_add_item(mq_tree, hf_mq_conn_acttoken, tvb, nofs, 32, ENC_NA));

                                if (iSizeCONN >= 120)
                                {
                                    do_proto_add_item(4, proto_tree_add_item(mq_tree, hf_mq_conn_version, tvb, nofs, 4, p_mq_parm->mq_int_enc));
                                    do_proto_add_item(4, proto_tree_add_item(mq_tree, hf_mq_conn_options, tvb, nofs, 4, p_mq_parm->mq_int_enc));
                                }
                                if (iSizeCONN >= 260)
                                {
                                    proto_tree  *mq_tree_sub;

                                    ti =  proto_tree_add_text(mq_tree, tvb, nofs, iSizeCONN - nofs, MQ_TEXT_FCNO);
                                    mq_tree_sub = proto_item_add_subtree(ti, ett_mq_fcno);

                                    do_proto_add_item(  4, proto_tree_add_item(mq_tree_sub, hf_mq_fcno_StructID , tvb, nofs, 4, p_mq_parm->mq_str_enc));
                                    do_proto_add_item(  4, proto_tree_add_item(mq_tree_sub, hf_mq_fcno_unknown00, tvb, nofs, 4, p_mq_parm->mq_int_enc));
                                    do_proto_add_item(  4, proto_tree_add_item(mq_tree_sub, hf_mq_fcno_unknown01, tvb, nofs, 4, p_mq_parm->mq_int_enc));

                                    if (iSizeCONN == 260)
                                    {
                                        do_proto_add_item( 12, proto_tree_add_item(mq_tree_sub, hf_mq_fcno_msgid    , tvb, nofs, 12, p_mq_parm->mq_str_enc));
                                        do_proto_add_item( 48, proto_tree_add_item(mq_tree_sub, hf_mq_fcno_mqmid    , tvb, nofs, 48, p_mq_parm->mq_str_enc));
                                        do_proto_add_item( 68, proto_tree_add_item(mq_tree_sub, hf_mq_fcno_unknown02, tvb, nofs, 68, ENC_NA));
                                    }
                                    if (iSizeCONN >= 332)
                                    {
                                        do_proto_add_item(152, proto_tree_add_item(mq_tree_sub, hf_mq_fcno_msgid    , tvb, nofs, 152, p_mq_parm->mq_str_enc));
                                        proto_tree_add_item(mq_tree_sub, hf_mq_fcno_mqmid    , tvb, nofs, 48, p_mq_parm->mq_int_enc);
                                    }
                                }
                            }
#undef do_proto_add_item
                            offset += iSizeCONN;
                        }
                    }
                    else if ((p_mq_parm->mq_opcode == MQ_TST_MQINQ || p_mq_parm->mq_opcode == MQ_TST_MQINQ_REPLY || p_mq_parm->mq_opcode == MQ_TST_MQSET) && tvb_length_remaining(tvb, offset) >= 12)
                    {
                        /* The MQINQ/MQSET structure is special because it does not start with a structid */
                        gint iNbSelectors;
                        gint iNbIntegers;
                        gint iCharLen;
                        gint iOffsetINQ;
                        gint iSelector;

                        iNbSelectors = tvb_get_guint32_endian(tvb, offset    , p_mq_parm->mq_int_enc);
                        iNbIntegers  = tvb_get_guint32_endian(tvb, offset + 4, p_mq_parm->mq_int_enc);
                        iCharLen     = tvb_get_guint32_endian(tvb, offset + 8, p_mq_parm->mq_int_enc);

                        if (tree)
                        {
                            ti = proto_tree_add_text(mqroot_tree, tvb, offset, -1, MQ_TEXT_INQ);
                            mq_tree = proto_item_add_subtree(ti, ett_mq_inq);

                            proto_tree_add_item(mq_tree, hf_mq_inq_nbsel,    tvb, offset,     4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_inq_nbint,    tvb, offset + 4, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_inq_charlen, tvb, offset + 8, 4, p_mq_parm->mq_int_enc);
                        }
                        iOffsetINQ = 12;
                        if (tvb_length_remaining(tvb, offset + iOffsetINQ) >= iNbSelectors * 4)
                        {
                            if (tree)
                            {
                                for (iSelector = 0; iSelector < iNbSelectors; iSelector++)
                                {
                                    proto_tree_add_item(mq_tree, hf_mq_inq_sel, tvb, offset + iOffsetINQ + iSelector * 4, 4, p_mq_parm->mq_int_enc);
                                }
                            }
                            iOffsetINQ += iNbSelectors * 4;
                            if (p_mq_parm->mq_opcode == MQ_TST_MQINQ_REPLY || p_mq_parm->mq_opcode == MQ_TST_MQSET)
                            {
                                gint iSizeINQValues;
                                iSizeINQValues = iNbIntegers * 4 + iCharLen;
                                if (tvb_length_remaining(tvb, offset + iOffsetINQ) >= iSizeINQValues)
                                {
                                    gint iInteger;
                                    if (tree)
                                    {
                                        for (iInteger = 0; iInteger < iNbIntegers; iInteger++)
                                        {
                                            proto_tree_add_item(mq_tree, hf_mq_inq_intvalue, tvb, offset + iOffsetINQ + iInteger * 4, 4, p_mq_parm->mq_int_enc);
                                        }
                                    }
                                    iOffsetINQ += iNbIntegers * 4;
                                    if (iCharLen != 0)
                                    {
                                        if (tree)
                                        {
                                            proto_tree_add_item(mq_tree, hf_mq_inq_charvalues, tvb, offset + iOffsetINQ, iCharLen, p_mq_parm->mq_str_enc);
                                        }
                                    }
                                }
                            }
                        }
                        offset += tvb_length(tvb);
                    }
                    else if (p_mq_parm->mq_opcode == MQ_TST_NOTIFICATION)
                    {
                        gint iHdl;

                        iHdl = tvb_get_guint32_endian(tvb, offset+4, p_mq_parm->mq_int_enc);

                        col_append_fstr(pinfo->cinfo, COL_INFO, " Hdl=0x%08x", iHdl);

                        if (tree)
                        {
                            ti = proto_tree_add_text(mqroot_tree, tvb, offset, -1, MQ_TEXT_NOTIFICATION);
                            mq_tree = proto_item_add_subtree(ti, ett_mq_notif);

                            proto_tree_add_item(mq_tree, hf_mq_notif_vers,     tvb, offset,      4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_notif_handle, tvb, offset +  4, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_notif_code,     tvb, offset +  8, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_notif_value,     tvb, offset + 12, 4, p_mq_parm->mq_int_enc);
                        }
                        offset+=16;
                        p_mq_parm->mq_strucID = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
                    }
                    else if (p_mq_parm->mq_opcode == MQ_TST_REQUEST_MSGS)
                    {
                        gint iHdl;
                        gint iFlags;
                        gint iGlbMsgIdx;
                        gint iMaxMsgLen;
                        gint xOfs;
                        gint iOpt;

                        xOfs       = 0;
                        iHdl       = tvb_get_guint32_endian(tvb, offset +  4, p_mq_parm->mq_int_enc);
                        iMaxMsgLen = tvb_get_guint32_endian(tvb, offset + 16, p_mq_parm->mq_int_enc);
                        iFlags     = tvb_get_guint32_endian(tvb, offset + 32, p_mq_parm->mq_int_enc);
                        iGlbMsgIdx = tvb_get_guint32_endian(tvb, offset + 36, p_mq_parm->mq_int_enc);
                        if (iFlags & 0x00000010)
                        {
                            p_mq_parm->mq_msgreq_ccsid.encod = tvb_get_guint32_endian(tvb, offset + 44, p_mq_parm->mq_int_enc);
                            p_mq_parm->mq_msgreq_ccsid.ccsid = tvb_get_guint32_endian(tvb, offset + 48, p_mq_parm->mq_int_enc);
                        }
                        col_append_fstr(pinfo->cinfo, COL_INFO, " Hdl=0x%08x GlbMsgIdx=%d, MaxLen=%d",
                            iHdl, iGlbMsgIdx, iMaxMsgLen);

                        if (tree)
                        {
                            ti = proto_tree_add_text(mqroot_tree, tvb, offset, -1, MQ_TEXT_REQMSG);
                            mq_tree = proto_item_add_subtree(ti, ett_mq_msg);

                            proto_tree_add_item(mq_tree, hf_mq_msgreq_version  , tvb, offset     ,  4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_msgreq_handle   , tvb, offset +  4,  4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_msgreq_RecvBytes, tvb, offset +  8,  4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_msgreq_RqstBytes, tvb, offset + 12,  4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_msgreq_MaxMsgLen, tvb, offset + 16,  4, p_mq_parm->mq_int_enc);
                            dissect_mq_MQGMO(tvb, mq_tree, offset + 20, ett_mq_gmo_option, p_mq_parm);

                            proto_tree_add_item(mq_tree, hf_mq_msgreq_WaitIntrv, tvb, offset + 24,  4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_msgreq_QueStatus, tvb, offset + 28,  4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_msgreq_RqstFlags, tvb, offset + 32,  4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_msgreq_GlbMsgIdx, tvb, offset + 36,  4, p_mq_parm->mq_int_enc);

                            if (iFlags & 0x00000010)
                            {
                                proto_tree_add_item(mq_tree, hf_mq_msgreq_SelectIdx, tvb, offset + 40,  2, p_mq_parm->mq_int_enc);
                                proto_tree_add_item(mq_tree, hf_mq_msgreq_MQMDVers , tvb, offset + 42,  2, p_mq_parm->mq_int_enc);
                                proto_tree_add_item(mq_tree, hf_mq_msgreq_ccsid    , tvb, offset + 44,  4, p_mq_parm->mq_int_enc);
                                dissect_mq_encoding(mq_tree, hf_mq_msgreq_encoding , tvb, offset + 48,  4, p_mq_parm->mq_int_enc);
                                proto_tree_add_item(mq_tree, hf_mq_msgreq_MsgSeqNum, tvb, offset + 52,  4, p_mq_parm->mq_int_enc);
                                proto_tree_add_item(mq_tree, hf_mq_msgreq_offset   , tvb, offset + 56,  4, p_mq_parm->mq_int_enc);
                                dissect_mq_MQMO(tvb, mq_tree, offset + 60, ett_mq_gmo_matchoption, p_mq_parm);
                                iOpt = tvb_get_guint32_endian(tvb, offset + 60, p_mq_parm->mq_int_enc);

                                if (iOpt & MQ_MQMO_MATCH_MSG_ID)
                                {
                                    proto_tree_add_item(mq_tree, hf_mq_msgreq_mtchMsgId, tvb, offset + 64 + xOfs, 24, p_mq_parm->mq_str_enc);
                                    xOfs += 24;
                                }
                                if (iOpt & MQ_MQMO_MATCH_CORREL_ID)
                                {
                                    proto_tree_add_item(mq_tree, hf_mq_msgreq_mtchCorId, tvb, offset + 64 + xOfs, 24, p_mq_parm->mq_str_enc);
                                    xOfs += 24;
                                }
                                if (iOpt & MQ_MQMO_MATCH_GROUP_ID)
                                {
                                    proto_tree_add_item(mq_tree, hf_mq_msgreq_mtchGrpid, tvb, offset + 64 + xOfs, 24, p_mq_parm->mq_str_enc);
                                    xOfs += 24;
                                }
                                if (iOpt & MQ_MQMO_MATCH_MSG_TOKEN)
                                {
                                    proto_tree_add_item(mq_tree, hf_mq_msgreq_mtchMsgTk, tvb, offset + 64 + xOfs, 16, p_mq_parm->mq_str_enc);
                                    xOfs += 16;
                                }
                            }
                        }
                        offset += (iFlags & 0x00000010) ? (64+xOfs) : 40;
                        p_mq_parm->mq_strucID = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
                    }
                    else if (p_mq_parm->mq_opcode == MQ_TST_ASYNC_MESSAGE)
                    {
                        gint  iSegmIndex;
                        gint  iGlbMsgIdx;
                        gint  iPadLen;
                        gint  iSegLength;
                        gint8 iStrLen;
                        gint  iHdl;
                        gint  iHdrL;

                        iHdl       = tvb_get_guint32_endian(tvb, offset +  4, p_mq_parm->mq_int_enc);
                        iGlbMsgIdx = tvb_get_guint32_endian(tvb, offset + 12, p_mq_parm->mq_int_enc);
                        iSegLength = tvb_get_guint32_endian(tvb, offset + 16, p_mq_parm->mq_int_enc);
                        iSegmIndex = tvb_get_guint16_endian(tvb, offset + 20, p_mq_parm->mq_int_enc);

                        if (iSegmIndex == 0)
                        {
                            iStrLen = tvb_get_guint8(tvb, offset + 54);
                            iPadLen = (2+1+iStrLen) % 4;
                            iPadLen = (iPadLen) ? 4-iPadLen : 0;
                        }
                        else
                        {
                            iPadLen = 0;
                            iStrLen = 0;
                        }

                        iHdrL = (iSegmIndex == 0) ? (54+1+iStrLen+iPadLen) : 24;

                        if (!mq_in_reassembly)
                        {
                            col_append_fstr(pinfo->cinfo, COL_INFO, " Hdl=0x%08x GlbMsgIdx=%d, SegIdx=%d, SegLen=%d",
                                iHdl, iGlbMsgIdx, iSegmIndex, iSegLength);
                        }

                        if (tree)
                        {
                            ti = proto_tree_add_text(mqroot_tree, tvb, offset, iHdrL, MQ_TEXT_ASYMSG);
                            mq_tree = proto_item_add_subtree(ti, ett_mq_msg);

                            proto_tree_add_item(mq_tree, hf_mq_msgasy_version  , tvb, offset     , 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_msgasy_handle   , tvb, offset +  4, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_msgasy_MsgIndex , tvb, offset +  8, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_msgasy_GlbMsgIdx, tvb, offset + 12, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_msgasy_SegLength, tvb, offset + 16, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_msgasy_SegmIndex, tvb, offset + 20, 2, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_msgasy_SeleIndex, tvb, offset + 22, 2, p_mq_parm->mq_int_enc);
                            if (p_mq_parm->mq_ctlf1 & MQ_TCF_FIRST)
                            {
                                proto_tree_add_item(mq_tree, hf_mq_msgasy_ReasonCod, tvb, offset + 24,  4, p_mq_parm->mq_int_enc);
                                proto_tree_add_item(mq_tree, hf_mq_msgasy_ActMsgLen, tvb, offset + 28,  4, p_mq_parm->mq_int_enc);
                                proto_tree_add_item(mq_tree, hf_mq_msgasy_TotMsgLen, tvb, offset + 32,  4, p_mq_parm->mq_int_enc);
                                proto_tree_add_item(mq_tree, hf_mq_msgasy_MsgToken , tvb, offset + 36, 16, p_mq_parm->mq_int_enc);
                                proto_tree_add_item(mq_tree, hf_mq_msgasy_Status   , tvb, offset + 52,  2, p_mq_parm->mq_int_enc);
                                proto_tree_add_item(mq_tree, hf_mq_msgasy_resolQNLn, tvb, offset + 54,  1, ENC_NA);
                                proto_tree_add_item(mq_tree, hf_mq_msgasy_resolQNme, tvb, offset + 55, iStrLen, p_mq_parm->mq_str_enc);
                                if (iPadLen)
                                    proto_tree_add_item(mq_tree, hf_mq_msgasy_padding  , tvb, offset + 55 + iStrLen, iPadLen, p_mq_parm->mq_str_enc);
                            }
                        }
                        offset+=iHdrL;
                        p_mq_parm->mq_strucID = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;

                        iSizePayload = tvb_length_remaining(tvb, offset);
                        bPayload = (iSizePayload>0);
                    }
                    else if ((p_mq_parm->mq_opcode == MQ_TST_SPI || p_mq_parm->mq_opcode == MQ_TST_SPI_REPLY) && tvb_length_remaining(tvb, offset) >= 12)
                    {
                        gint    iOffsetSPI = 0;
                        guint32 iSpiVerb   = 0;

                        p_mq_parm->iOfsEnc = offset + 12;
                        p_mq_parm->iOfsCcs = offset + 16;
                        p_mq_parm->iOfsFmt = offset + 20;

                        iSpiVerb = tvb_get_guint32_endian(tvb, offset, p_mq_parm->mq_int_enc);
                        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", val_to_str(iSpiVerb, mq_spi_verbs_vals, "Unknown (0x%08x)"));

                        if (tree)
                        {
                            ti = proto_tree_add_text(mqroot_tree, tvb, offset, 12, MQ_TEXT_SPI);
                            mq_tree = proto_item_add_subtree(ti, ett_mq_spi);

                            proto_tree_add_item(mq_tree, hf_mq_spi_verb   , tvb, offset,     4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_spi_version, tvb, offset + 4, 4, p_mq_parm->mq_int_enc);
                            proto_tree_add_item(mq_tree, hf_mq_spi_length , tvb, offset + 8, 4, p_mq_parm->mq_int_enc);
                        }

                        offset += 12;
                        p_mq_parm->mq_strucID = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
                        if (((p_mq_parm->mq_strucID & MQ_MASK_SPxZ) == MQ_STRUCTID_SPxU ||
                            (p_mq_parm->mq_strucID & MQ_MASK_SPxZ) == MQ_STRUCTID_SPxU_EBCDIC)
                            && tvb_length_remaining(tvb, offset) >= 12)
                        {
                            gint iSizeSPIMD = 0;
                            if (tree)
                            {
                                guint8 *sStructId;
                                sStructId = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 4, ((p_mq_parm->mq_strucID & MQ_MASK_SPxx) == MQ_STRUCTID_SPxx) ? ENC_ASCII : ENC_EBCDIC);
                                ti = proto_tree_add_text(mqroot_tree, tvb, offset, 12, "%s", sStructId);
                                mq_tree = proto_item_add_subtree(ti, ett_mq_spi_base);

                                proto_tree_add_item(mq_tree, hf_mq_spi_base_StructID, tvb, offset,     4, p_mq_parm->mq_str_enc);
                                proto_tree_add_item(mq_tree, hf_mq_spi_base_version , tvb, offset + 4, 4, p_mq_parm->mq_int_enc);
                                proto_tree_add_item(mq_tree, hf_mq_spi_base_length  , tvb, offset + 8, 4, p_mq_parm->mq_int_enc);
                            }
                            offset += 12;
                            p_mq_parm->mq_strucID = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;

                            if ((iSizeSPIMD = dissect_mq_md(tvb, mqroot_tree, offset, p_mq_parm, TRUE)) != 0)
                            {
                                offset += iSizeSPIMD;
                                offset += dissect_mq_gmo(tvb, pinfo, mqroot_tree, offset, p_mq_parm);
                                offset += dissect_mq_pmo(tvb, pinfo, mqroot_tree, offset, p_mq_parm, &iDistributionListSize);
                                p_mq_parm->mq_strucID = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
                            }

                            offset += dissect_mq_od(tvb, pinfo, mqroot_tree, offset, p_mq_parm, &iDistributionListSize);

                            if (((p_mq_parm->mq_strucID & MQ_MASK_SPxZ) == MQ_STRUCTID_SPxO ||
                                (p_mq_parm->mq_strucID & MQ_MASK_SPxZ) == MQ_STRUCTID_SPxO_EBCDIC ||
                                (p_mq_parm->mq_strucID & MQ_MASK_SPxZ) == MQ_STRUCTID_SPxI ||
                                (p_mq_parm->mq_strucID & MQ_MASK_SPxZ) == MQ_STRUCTID_SPxI_EBCDIC)
                                && tvb_length_remaining(tvb, offset) >= 12)
                            {
                                if (tree)
                                {
                                    /* Dissect the common part of these structures */
                                    guint8 *sStructId;
                                    sStructId = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 4, ((p_mq_parm->mq_strucID & MQ_MASK_SPxx) == MQ_STRUCTID_SPxx) ? ENC_ASCII : ENC_EBCDIC);
                                    ti = proto_tree_add_text(mqroot_tree, tvb, offset, -1, "%s", sStructId);
                                    mq_tree = proto_item_add_subtree(ti, ett_mq_spi_base);

                                    proto_tree_add_item(mq_tree, hf_mq_spi_base_StructID, tvb, offset, 4, p_mq_parm->mq_str_enc);
                                    proto_tree_add_item(mq_tree, hf_mq_spi_base_version , tvb, offset + 4, 4, p_mq_parm->mq_int_enc);
                                    proto_tree_add_item(mq_tree, hf_mq_spi_base_length  , tvb, offset + 8, 4, p_mq_parm->mq_int_enc);
                                }

                                if ((p_mq_parm->mq_strucID == MQ_STRUCTID_SPQO || p_mq_parm->mq_strucID == MQ_STRUCTID_SPQO_EBCDIC)
                                    && tvb_length_remaining(tvb, offset) >= 16)
                                {
                                    if (tree)
                                    {
                                        gint iVerbNumber = 0;
                                        proto_tree_add_item(mq_tree, hf_mq_spi_spqo_nbverb, tvb, offset + 12, 4, p_mq_parm->mq_int_enc);
                                        iVerbNumber = tvb_get_guint32_endian(tvb, offset + 12, p_mq_parm->mq_int_enc);

                                        if (tvb_length_remaining(tvb, offset) >= iVerbNumber * 20 + 16)
                                        {
                                            gint iVerb = 0;
                                            iOffsetSPI = offset + 16;
                                            for (iVerb = 0; iVerb < iVerbNumber; iVerb++)
                                            {
                                                proto_tree_add_item(mq_tree, hf_mq_spi_spqo_verbid  , tvb, iOffsetSPI,      4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_spi_spqo_maxiover, tvb, iOffsetSPI +  4, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_spi_spqo_maxinver, tvb, iOffsetSPI +  8, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_spi_spqo_maxouver, tvb, iOffsetSPI + 12, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_spi_spqo_flags   , tvb, iOffsetSPI + 16, 4, p_mq_parm->mq_int_enc);
                                                iOffsetSPI += 20;
                                            }
                                            offset += iVerbNumber * 20 + 16;
                                        }
                                    }
                                }
                                else if ((p_mq_parm->mq_strucID == MQ_STRUCTID_SPAI || p_mq_parm->mq_strucID == MQ_STRUCTID_SPAI_EBCDIC)
                                    && tvb_length_remaining(tvb, offset) >= 136)
                                {
                                    if (tree)
                                    {
                                        proto_tree_add_item(mq_tree, hf_mq_spi_spai_mode    , tvb, offset +  12,  4, p_mq_parm->mq_int_enc);
                                        proto_tree_add_item(mq_tree, hf_mq_spi_spai_unknown1, tvb, offset +  16, 48, p_mq_parm->mq_str_enc);
                                        proto_tree_add_item(mq_tree, hf_mq_spi_spai_unknown2, tvb, offset +  64, 48, p_mq_parm->mq_str_enc);
                                        proto_tree_add_item(mq_tree, hf_mq_spi_spai_msgid   , tvb, offset + 112, 24, p_mq_parm->mq_str_enc);
                                    }
                                    offset += 136;
                                }
                                else if ((p_mq_parm->mq_strucID == MQ_STRUCTID_SPGI || p_mq_parm->mq_strucID == MQ_STRUCTID_SPGI_EBCDIC)
                                    && tvb_length_remaining(tvb, offset) >= 24)
                                {
                                    if (tree)
                                    {
                                        proto_tree_add_item(mq_tree, hf_mq_spi_spgi_batchsz , tvb, offset + 12, 4, p_mq_parm->mq_int_enc);
                                        proto_tree_add_item(mq_tree, hf_mq_spi_spgi_batchint, tvb, offset + 16, 4, p_mq_parm->mq_int_enc);
                                        proto_tree_add_item(mq_tree, hf_mq_spi_spgi_maxmsgsz, tvb, offset + 20, 4, p_mq_parm->mq_int_enc);
                                    }
                                    offset += 24;
                                }
                                else if ((p_mq_parm->mq_strucID == MQ_STRUCTID_SPGO || p_mq_parm->mq_strucID == MQ_STRUCTID_SPPI ||
                                    p_mq_parm->mq_strucID == MQ_STRUCTID_SPGO_EBCDIC || p_mq_parm->mq_strucID == MQ_STRUCTID_SPPI_EBCDIC)
                                    && tvb_length_remaining(tvb, offset) >= 20)
                                {
                                    if (tree)
                                    {
                                        proto_tree_add_bitmask(mq_tree, tvb, offset + 12, hf_mq_spi_spgo_options, ett_mq_spi_options, pf_flds_spiopt, ENC_BIG_ENDIAN);
                                        proto_tree_add_item(mq_tree, hf_mq_spi_spgo_size, tvb, offset + 16, 4, p_mq_parm->mq_int_enc);
                                    }
                                    iSizePayload = tvb_get_guint32_endian(tvb, offset + 16, p_mq_parm->mq_int_enc);
                                    offset += 20;
                                    bPayload = TRUE;
                                }
                                else
                                {
                                    offset += 12;
                                }
                                p_mq_parm->mq_strucID = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
                            }
                        }
                    }
                    else if ((p_mq_parm->mq_opcode >= 0xA0 && p_mq_parm->mq_opcode <= 0xB9) && tvb_length_remaining(tvb, offset) >= 16)
                    {
                        /* The XA structures are special because they do not start with a structid */
                        if (tree)
                        {
                            ti = proto_tree_add_text(mqroot_tree, tvb, offset, 16, "%s (%s)", MQ_TEXT_XA,
                                val_to_str(p_mq_parm->mq_opcode, mq_opcode_vals, "Unknown (0x%02x)"));
                            mq_tree = proto_item_add_subtree(ti, ett_mq_xa);

                            proto_tree_add_item(mq_tree, hf_mq_xa_length,      tvb, offset,     4, ENC_BIG_ENDIAN);
                            proto_tree_add_item(mq_tree, hf_mq_xa_returnvalue, tvb, offset + 4, 4, p_mq_parm->mq_int_enc);

                            proto_tree_add_bitmask(mq_tree, tvb, offset + 8, hf_mq_xa_tmflags, ett_mq_xa_tmflags, pf_flds_tmflags, ENC_BIG_ENDIAN);

                            proto_tree_add_item(mq_tree, hf_mq_xa_rmid, tvb, offset + 12, 4, p_mq_parm->mq_int_enc);
                        }
                        offset += 16;
                        if (p_mq_parm->mq_opcode == MQ_TST_XA_START || p_mq_parm->mq_opcode == MQ_TST_XA_END || p_mq_parm->mq_opcode == MQ_TST_XA_PREPARE
                            || p_mq_parm->mq_opcode == MQ_TST_XA_COMMIT || p_mq_parm->mq_opcode == MQ_TST_XA_ROLLBACK || p_mq_parm->mq_opcode == MQ_TST_XA_FORGET
                            || p_mq_parm->mq_opcode == MQ_TST_XA_COMPLETE)
                        {
                            gint iSizeXid = 0;
                            if ((iSizeXid = dissect_mq_xid(tvb, mqroot_tree, p_mq_parm, offset)) != 0)
                                offset += iSizeXid;
                        }
                        else if ((p_mq_parm->mq_opcode == MQ_TST_XA_OPEN || p_mq_parm->mq_opcode == MQ_TST_XA_CLOSE)
                            && tvb_length_remaining(tvb, offset) >= 1)
                        {
                            guint8 iXAInfoLength = 0;
                            iXAInfoLength = tvb_get_guint8(tvb, offset);
                            if (tvb_length_remaining(tvb, offset) >= iXAInfoLength + 1)
                            {
                                if (tree)
                                {
                                    ti = proto_tree_add_text(mqroot_tree, tvb, offset, iXAInfoLength + 1, MQ_TEXT_XINF);
                                    mq_tree = proto_item_add_subtree(ti, ett_mq_xa_info);

                                    proto_tree_add_item(mq_tree, hf_mq_xa_xainfo_length, tvb, offset,     1, ENC_BIG_ENDIAN);
                                    proto_tree_add_item(mq_tree, hf_mq_xa_xainfo_value , tvb, offset + 1, iXAInfoLength, p_mq_parm->mq_str_enc);
                                }
                            }
                            offset += 1 + iXAInfoLength;
                        }
                        else if ((p_mq_parm->mq_opcode == MQ_TST_XA_RECOVER || p_mq_parm->mq_opcode == MQ_TST_XA_RECOVER_REPLY)
                            && tvb_length_remaining(tvb, offset) >= 4)
                        {
                            gint iNbXid = 0;
                            iNbXid = tvb_get_guint32_endian(tvb, offset, p_mq_parm->mq_int_enc);
                            if (tree)
                            {
                                proto_tree_add_item(mq_tree, hf_mq_xa_count, tvb, offset, 4, p_mq_parm->mq_int_enc);
                            }
                            offset += 4;
                            if (p_mq_parm->mq_opcode == MQ_TST_XA_RECOVER_REPLY)
                            {
                                gint iXid = 0;
                                for (iXid = 0; iXid < iNbXid; iXid++)
                                {
                                    gint iSizeXid = 0;
                                    if ((iSizeXid = dissect_mq_xid(tvb, mqroot_tree, p_mq_parm, offset)) != 0)
                                        offset += iSizeXid;
                                    else
                                        break;
                                }
                            }
                        }
                    }
                    if ((p_mq_parm->mq_strucID == MQ_STRUCTID_LPOO || p_mq_parm->mq_strucID == MQ_STRUCTID_LPOO_EBCDIC) && tvb_length_remaining(tvb, offset) >= 32)
                    {
                        guint iVersion;
                        guint iXtraData = 0;
                        gint  iSize = 32;
                        iVersion = tvb_get_guint32_endian(tvb, offset+4, p_mq_parm->mq_int_enc);
                        if (iVersion >= 3)
                        {
                            iSize += 56;
                            iXtraData = tvb_get_guint32_endian(tvb, offset + 84, p_mq_parm->mq_int_enc);
                        }

                        if (iSize != 0 && tvb_length_remaining(tvb, offset) >= iSize)
                        {
                            if (tree)
                            {
                                ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSize, MQ_TEXT_LPOO);
                                mq_tree = proto_item_add_subtree(ti, ett_mq_lpoo);

                                proto_tree_add_item(mq_tree, hf_mq_lpoo_StructID, tvb, offset,     4, p_mq_parm->mq_str_enc);
                                proto_tree_add_item(mq_tree, hf_mq_lpoo_version , tvb, offset + 4, 4, p_mq_parm->mq_int_enc);

                                dissect_mq_MQOO(tvb, mq_tree, offset+8, ett_mq_lpoo_options, hf_mq_lpoo_options, p_mq_parm);

                                dissect_mq_LPOO_LPIOPTS(tvb, mq_tree, offset+16, ett_mq_lpoo_lpiopts, p_mq_parm);
                                proto_tree_add_item(mq_tree, hf_mq_lpoo_defpersist    , tvb, offset + 20, 4, p_mq_parm->mq_int_enc);
                                proto_tree_add_item(mq_tree, hf_mq_lpoo_defputresptype, tvb, offset + 24, 4, p_mq_parm->mq_int_enc);
                                proto_tree_add_item(mq_tree, hf_mq_lpoo_defreadahead  , tvb, offset + 28, 4, p_mq_parm->mq_int_enc);
                                if (iVersion >= 3)
                                {
                                    proto_tree_add_item(mq_tree, hf_mq_lpoo_qprotect, tvb, offset + 32, 48, p_mq_parm->mq_int_enc);
                                    proto_tree_add_item(mq_tree, hf_mq_lpoo_unknown6, tvb, offset + 80,  4, p_mq_parm->mq_int_enc);
                                    proto_tree_add_item(mq_tree, hf_mq_lpoo_xtradata, tvb, offset + 84,  4, p_mq_parm->mq_int_enc);
                                }
                            }
                            offset += iSize;
                            p_mq_parm->mq_strucID = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
                            if (iXtraData>0)
                            {
                                if (p_mq_parm->mq_opcode == MQ_TST_SPI_REPLY)
                                {
                                    bPayload           = TRUE;
                                    iSizePayload       = iXtraData;
                                    p_mq_parm->iOfsFmt = (offset-iSize);
                                }
                            }
                        }
                    }
                    if ((p_mq_parm->mq_strucID == MQ_STRUCTID_ID || p_mq_parm->mq_strucID == MQ_STRUCTID_ID_EBCDIC) && tvb_length_remaining(tvb, offset) >= 5)
                    {
                        offset += dissect_mq_id(tvb, pinfo, mqroot_tree, offset, p_mq_parm);
                        p_mq_parm->mq_strucID = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
                    }
                    if ((p_mq_parm->mq_strucID == MQ_STRUCTID_UID || p_mq_parm->mq_strucID == MQ_STRUCTID_UID_EBCDIC) && tvb_length_remaining(tvb, offset) > 0)
                    {
                        gint iSizeUID;
                        /* iSizeUID = (iVersionID < 5 ? 28 : 132);  guess */
                        /* The iVersionID is available in the previous ID segment, we should keep a state *
                         * Instead we rely on the segment length announced in the TSH */
                        iSizeUID = iSegmentLength - iSizeTSH;
                        if (iSizeUID != 28 && iSizeUID != 132)
                            iSizeUID = 0;

                        if (iSizeUID != 0 && tvb_length_remaining(tvb, offset) >= iSizeUID)
                        {
                            guint8 *sUserId;
                            sUserId = tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 4, 12, p_mq_parm->mq_str_enc);
                            if (strip_trailing_blanks(sUserId, 12) > 0)
                            {
                                col_append_fstr(pinfo->cinfo, COL_INFO, " User=%s", sUserId);
                            }

                            if (tree)
                            {
                                ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSizeUID, MQ_TEXT_UID);
                                mq_tree = proto_item_add_subtree(ti, ett_mq_uid);

                                proto_tree_add_item(mq_tree, hf_mq_uid_StructID, tvb, offset,       4, p_mq_parm->mq_str_enc);
                                proto_tree_add_item(mq_tree, hf_mq_uid_userid  , tvb, offset +  4, 12, p_mq_parm->mq_str_enc);
                                proto_tree_add_item(mq_tree, hf_mq_uid_password, tvb, offset + 16, 12, p_mq_parm->mq_str_enc);
                            }

                            if (iSizeUID == 132)
                            {
                                if (tree)
                                {
                                    proto_tree_add_item(mq_tree, hf_mq_uid_longuserid, tvb, offset + 28, 64, p_mq_parm->mq_str_enc);
                                    dissect_mq_sid(tvb, mq_tree, p_mq_parm, offset + 92);
                                }
                            }
                        }
                        offset += iSizeUID;
                        p_mq_parm->mq_strucID = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
                    }

                    offset += dissect_mq_od(tvb, pinfo, mqroot_tree, offset, p_mq_parm, &iDistributionListSize);

                    if ((iSizeMD = dissect_mq_md(tvb, mqroot_tree, offset, p_mq_parm, TRUE)) != 0)
                    {
                        gint iSizeGMO = 0;
                        gint iSizePMO = 0;
                        offset += iSizeMD;

                        if ((iSizeGMO = dissect_mq_gmo(tvb, pinfo, mqroot_tree, offset, p_mq_parm)) != 0)
                        {
                            offset   += iSizeGMO;
                            bPayload  = TRUE;
                        }
                        else if ((iSizePMO = dissect_mq_pmo(tvb, pinfo, mqroot_tree, offset, p_mq_parm, &iDistributionListSize)) != 0)
                        {
                            offset   += iSizePMO;
                            bPayload  = TRUE;
                        }
                        if (tvb_length_remaining(tvb, offset) >= 4)
                        {
                            if (bPayload == TRUE && (p_mq_parm->mq_opcode != MQ_TST_ASYNC_MESSAGE))
                            {
                                iSizePayload = tvb_get_guint32_endian(tvb, offset, p_mq_parm->mq_int_enc);
                                if (tree)
                                {
                                    ti = proto_tree_add_text(mqroot_tree, tvb, offset, 4, MQ_TEXT_PUT);
                                    mq_tree = proto_item_add_subtree(ti, ett_mq_put);
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
                    if (bPayload == TRUE)
                    {
                        if (iSizePayload != 0 && tvb_length_remaining(tvb, offset) > 0)
                        {
                            /* For the following header structures, each structure has a "format" field
                            which announces the type of the following structure.  For dissection we
                            do not use it and rely on the structid instead. */
                            guint32 iHeadersLength = 0;
                            if (tvb_length_remaining(tvb, offset) >= 4)
                            {
                                gint iSizeMD2 = 0;
                                p_mq_parm->mq_strucID = tvb_get_ntohl(tvb, offset);

                                if ((p_mq_parm->mq_strucID == MQ_STRUCTID_XQH || p_mq_parm->mq_strucID == MQ_STRUCTID_XQH_EBCDIC) && tvb_length_remaining(tvb, offset) >= 104)
                                {
                                    /* if MD.format == MQXMIT */
                                    gint iSizeXQH = 104;
                                    if (tree)
                                    {
                                        ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSizeXQH, MQ_TEXT_XQH);
                                        mq_tree = proto_item_add_subtree(ti, ett_mq_xqh);

                                        proto_tree_add_item(mq_tree, hf_mq_xqh_StructID  , tvb, offset     ,  4, p_mq_parm->mq_str_enc);
                                        proto_tree_add_item(mq_tree, hf_mq_xqh_version   , tvb, offset +  4,  4, p_mq_parm->mq_int_enc);
                                        proto_tree_add_item(mq_tree, hf_mq_xqh_remoteq   , tvb, offset +  8, 48, p_mq_parm->mq_str_enc);
                                        proto_tree_add_item(mq_tree, hf_mq_xqh_remoteqmgr, tvb, offset + 56, 48, p_mq_parm->mq_str_enc);
                                    }
                                    offset += iSizeXQH;
                                    iHeadersLength += iSizeXQH;

                                    if ((iSizeMD2 = dissect_mq_md(tvb, mqroot_tree, offset, p_mq_parm, TRUE)) != 0)
                                    {
                                        offset += iSizeMD2;
                                        iHeadersLength += iSizeMD2;
                                    }

                                    p_mq_parm->mq_strucID = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
                                }
                                if ((p_mq_parm->mq_strucID == MQ_STRUCTID_DLH || p_mq_parm->mq_strucID == MQ_STRUCTID_DLH_EBCDIC) && tvb_length_remaining(tvb, offset) >= 172)
                                {
                                    /* if MD.format == MQDEAD */
                                    gint iSizeDLH = 172;
                                    p_mq_parm->iOfsEnc = offset + 108;
                                    p_mq_parm->iOfsCcs = offset + 112;
                                    p_mq_parm->iOfsFmt = offset + 116;

                                    p_mq_parm->mq_dlh_ccsid.encod = tvb_get_guint32_endian(tvb, offset + 108, p_mq_parm->mq_int_enc);
                                    p_mq_parm->mq_dlh_ccsid.ccsid = tvb_get_guint32_endian(tvb, offset + 112, p_mq_parm->mq_int_enc);

                                    if (tree)
                                    {
                                        ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSizeDLH, MQ_TEXT_DLH);
                                        mq_tree = proto_item_add_subtree(ti, ett_mq_dlh);

                                        proto_tree_add_item(mq_tree, hf_mq_dlh_StructID   , tvb, offset,        4, p_mq_parm->mq_str_enc);
                                        proto_tree_add_item(mq_tree, hf_mq_dlh_version    , tvb, offset +   4,  4, p_mq_parm->mq_int_enc);
                                        proto_tree_add_item(mq_tree, hf_mq_dlh_reason     , tvb, offset +   8,  4, p_mq_parm->mq_int_enc);
                                        proto_tree_add_item(mq_tree, hf_mq_dlh_destq      , tvb, offset +  12, 48, p_mq_parm->mq_str_enc);
                                        proto_tree_add_item(mq_tree, hf_mq_dlh_destqmgr   , tvb, offset +  60, 48, p_mq_parm->mq_str_enc);
                                        dissect_mq_encoding(mq_tree, hf_mq_dlh_encoding   , tvb, offset + 108,  4, p_mq_parm->mq_int_enc);
                                        proto_tree_add_item(mq_tree, hf_mq_dlh_ccsid      , tvb, offset + 112,  4, p_mq_parm->mq_int_enc);
                                        proto_tree_add_item(mq_tree, hf_mq_dlh_format     , tvb, offset + 116,  8, p_mq_parm->mq_str_enc);
                                        proto_tree_add_item(mq_tree, hf_mq_dlh_putappltype, tvb, offset + 124,  4, p_mq_parm->mq_int_enc);
                                        proto_tree_add_item(mq_tree, hf_mq_dlh_putapplname, tvb, offset + 128, 28, p_mq_parm->mq_str_enc);
                                        proto_tree_add_item(mq_tree, hf_mq_dlh_putdate    , tvb, offset + 156,  8, p_mq_parm->mq_str_enc);
                                        proto_tree_add_item(mq_tree, hf_mq_dlh_puttime    , tvb, offset + 164,  8, p_mq_parm->mq_str_enc);
                                    }
                                    offset += iSizeDLH;
                                    iHeadersLength += iSizeDLH;
                                    p_mq_parm->mq_strucID = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
                                }
                                if ((p_mq_parm->mq_strucID == MQ_STRUCTID_MDE || p_mq_parm->mq_strucID == MQ_STRUCTID_MDE_EBCDIC
                                    || p_mq_parm->mq_strucID == MQ_STRUCTID_CIH || p_mq_parm->mq_strucID == MQ_STRUCTID_CIH_EBCDIC
                                    || p_mq_parm->mq_strucID == MQ_STRUCTID_IIH || p_mq_parm->mq_strucID == MQ_STRUCTID_IIH_EBCDIC
                                    || p_mq_parm->mq_strucID == MQ_STRUCTID_RFH || p_mq_parm->mq_strucID == MQ_STRUCTID_RFH_EBCDIC
                                    || p_mq_parm->mq_strucID == MQ_STRUCTID_RMH || p_mq_parm->mq_strucID == MQ_STRUCTID_RMH_EBCDIC
                                    || p_mq_parm->mq_strucID == MQ_STRUCTID_WIH || p_mq_parm->mq_strucID == MQ_STRUCTID_WIH_EBCDIC)
                                    && tvb_length_remaining(tvb, offset) >= 12)
                                {
                                    /* Dissect the generic part of the other pre-defined headers */
                                    /* We assume that only one such header is present */
                                    gint iSizeHeader;
                                    iSizeHeader = (gint) tvb_get_guint32_endian(tvb, offset + 8, p_mq_parm->mq_int_enc);
                                    /* XXX - 32 is inferred from the code below.  What's the
                                    * correct minimum? */
                                    if (iSizeHeader <= 32)
                                        THROW(ReportedBoundsError);

                                    p_mq_parm->mq_head_ccsid.encod = tvb_get_guint32_endian(tvb, offset + 12, p_mq_parm->mq_int_enc);
                                    p_mq_parm->mq_head_ccsid.ccsid = tvb_get_guint32_endian(tvb, offset + 16, p_mq_parm->mq_int_enc);

                                    if (tvb_length_remaining(tvb, offset) >= iSizeHeader)
                                    {
                                        gint iTmp;
                                        gint iVer;
                                        gint oEnc = p_mq_parm->mq_str_enc;

                                        p_mq_parm->iOfsEnc = offset + 12;
                                        p_mq_parm->iOfsCcs = offset + 16;
                                        p_mq_parm->iOfsFmt = offset + 20;

                                        iVer=(gint)tvb_get_guint32_endian(tvb, offset +  4, p_mq_parm->mq_int_enc);
                                        iTmp=p_mq_parm->mq_head_ccsid.ccsid;
                                        if (iTmp == 0)
                                            iTmp = p_mq_parm->mq_md_ccsid.ccsid;

                                        if (iTmp == 500)
                                            p_mq_parm->mq_str_enc = ENC_EBCDIC|ENC_NA;
                                        else
                                            p_mq_parm->mq_str_enc = ENC_UTF_8|ENC_NA;

                                        if (tree)
                                        {
                                            ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSizeHeader, "%s", val_to_str(p_mq_parm->mq_strucID, mq_StructID_vals, "Unknown (0x%08x)"));
                                            mq_tree = proto_item_add_subtree(ti, ett_mq_head);

                                            proto_tree_add_item(mq_tree, hf_mq_head_StructID, tvb, offset,      4, p_mq_parm->mq_str_enc);
                                            proto_tree_add_item(mq_tree, hf_mq_head_version , tvb, offset +  4, 4, p_mq_parm->mq_int_enc);
                                            proto_tree_add_item(mq_tree, hf_mq_head_length  , tvb, offset +  8, 4, p_mq_parm->mq_int_enc);
                                            dissect_mq_encoding(mq_tree, hf_mq_head_encoding, tvb, offset + 12, 4, p_mq_parm->mq_int_enc);
                                            proto_tree_add_item(mq_tree, hf_mq_head_ccsid   , tvb, offset + 16, 4, p_mq_parm->mq_int_enc);
                                            proto_tree_add_item(mq_tree, hf_mq_head_format  , tvb, offset + 20, 8, p_mq_parm->mq_str_enc);

                                            if (p_mq_parm->mq_strucID == MQ_STRUCTID_DH || p_mq_parm->mq_strucID == MQ_STRUCTID_DH_EBCDIC)
                                            {
                                                gint iRec;
                                                iRec = tvb_get_guint32_endian(tvb, offset + 36, p_mq_parm->mq_int_enc);

                                                proto_tree_add_bitmask(mq_tree, tvb, offset + 28, hf_mq_head_flags, ett_mq_head_flags, pf_flds_dh_flags, ENC_BIG_ENDIAN);
                                                proto_tree_add_item(mq_tree, hf_mq_dh_putmsgrecfld, tvb, offset + 32, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_dh_recspresent , tvb, offset + 36, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_dh_objrecofs   , tvb, offset + 40, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_dh_putmsgrecofs, tvb, offset + 44, 4, p_mq_parm->mq_int_enc);

                                                if (iRec)
                                                {
                                                    gint iOfs1;
                                                    gint iOfs2;
                                                    gint iFlgs;
                                                    gint iSize;

                                                    iFlgs = (gint)tvb_get_guint32_endian(tvb, offset + 32, p_mq_parm->mq_int_enc);
                                                    iOfs1 = (gint)tvb_get_guint32_endian(tvb, offset + 40, p_mq_parm->mq_int_enc);
                                                    iOfs2 = (gint)tvb_get_guint32_endian(tvb, offset + 44, p_mq_parm->mq_int_enc);

                                                    iSize = dissect_mq_or(tvb, mq_tree, offset + 48, iRec, iOfs1, p_mq_parm);
                                                    /*iSize = */dissect_mq_pmr(tvb, mqroot_tree, offset + 48 + iSize, iRec, iOfs2, iFlgs, p_mq_parm);
                                                }
                                            }
                                            else if (p_mq_parm->mq_strucID == MQ_STRUCTID_MDE || p_mq_parm->mq_strucID == MQ_STRUCTID_MDE_EBCDIC)
                                            {
                                                proto_tree_add_item(mq_tree, hf_mq_head_flags     , tvb, offset + 28, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_md_groupid     , tvb, offset + 32, 24, ENC_NA);
                                                proto_tree_add_item(mq_tree, hf_mq_md_msgseqnumber, tvb, offset + 56,  4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_md_offset      , tvb, offset + 60,  4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_md_msgflags    , tvb, offset + 64,  4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_md_origlen     , tvb, offset + 68,  4, p_mq_parm->mq_int_enc);
                                            }
                                            else if (p_mq_parm->mq_strucID == MQ_STRUCTID_IIH || p_mq_parm->mq_strucID == MQ_STRUCTID_IIH_EBCDIC)
                                            {
                                                proto_tree_add_bitmask(mq_tree, tvb, offset + 28, hf_mq_head_flags, ett_mq_head_flags, pf_flds_iih_flags, ENC_BIG_ENDIAN);
                                                proto_tree_add_item(mq_tree, hf_mq_iih_ltermoverride, tvb, offset + 32,  8, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_iih_mfsmapname   , tvb, offset + 40,  8, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_iih_replytofmt   , tvb, offset + 48,  8, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_iih_authenticator, tvb, offset + 56,  8, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_iih_transinstid  , tvb, offset + 64, 16, ENC_NA);
                                                proto_tree_add_item(mq_tree, hf_mq_iih_transstate   , tvb, offset + 80,  1, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_iih_commimode    , tvb, offset + 81,  1, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_iih_securityscope, tvb, offset + 82,  1, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_iih_reserved     , tvb, offset + 83,  1, p_mq_parm->mq_str_enc);
                                            }
                                            else if (p_mq_parm->mq_strucID == MQ_STRUCTID_CIH || p_mq_parm->mq_strucID == MQ_STRUCTID_CIH_EBCDIC)
                                            {
                                                proto_tree_add_bitmask(mq_tree, tvb, offset + 28, hf_mq_head_flags, ett_mq_head_flags, pf_flds_cih_flags, ENC_BIG_ENDIAN);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_returncode   , tvb, offset +  32,  4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_compcode     , tvb, offset +  36,  4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_reasoncode   , tvb, offset +  40,  4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_uowcontrols  , tvb, offset +  44,  4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_getwaitintv  , tvb, offset +  48,  4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_linktype     , tvb, offset +  52,  4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_outdatalen   , tvb, offset +  56,  4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_facilkeeptime, tvb, offset +  60,  4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_adsdescriptor, tvb, offset +  64,  4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_converstask  , tvb, offset +  68,  4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_taskendstatus, tvb, offset +  72,  4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_bridgefactokn, tvb, offset +  76,  8, ENC_NA);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_function     , tvb, offset +  84,  4, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_abendcode    , tvb, offset +  88,  4, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_authenticator, tvb, offset +  92,  8, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_reserved     , tvb, offset + 100,  8, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_replytofmt   , tvb, offset + 108,  8, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_remotesysid  , tvb, offset + 116,  4, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_remotetransid, tvb, offset + 120,  4, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_transactionid, tvb, offset + 124,  4, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_facilitylike , tvb, offset + 128,  4, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_attentionid  , tvb, offset + 132,  4, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_startcode    , tvb, offset + 136,  4, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_cancelcode   , tvb, offset + 140,  4, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_nexttransid  , tvb, offset + 144,  4, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_reserved2    , tvb, offset + 148,  8, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_cih_reserved3    , tvb, offset + 156,  8, p_mq_parm->mq_str_enc);
                                                if (iVer == 2)
                                                {
                                                    proto_tree_add_item(mq_tree, hf_mq_cih_cursorpos    , tvb, offset + 164,  4, p_mq_parm->mq_int_enc);
                                                    proto_tree_add_item(mq_tree, hf_mq_cih_erroroffset  , tvb, offset + 168,  4, p_mq_parm->mq_int_enc);
                                                    proto_tree_add_item(mq_tree, hf_mq_cih_inputitem    , tvb, offset + 172,  4, p_mq_parm->mq_int_enc);
                                                    proto_tree_add_item(mq_tree, hf_mq_cih_reserved4    , tvb, offset + 176,  4, p_mq_parm->mq_int_enc);
                                                }
                                            }
                                            else if (p_mq_parm->mq_strucID == MQ_STRUCTID_RMH || p_mq_parm->mq_strucID == MQ_STRUCTID_RMH_EBCDIC)
                                            {
                                                proto_tree_add_bitmask(mq_tree, tvb, offset + 28, hf_mq_head_flags, ett_mq_head_flags, pf_flds_rmh_flags, ENC_BIG_ENDIAN);
                                                proto_tree_add_item(mq_tree, hf_mq_rmh_objecttype   , tvb, offset +  32,  8, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_rmh_objectinstid , tvb, offset +  36, 24, ENC_NA);
                                                proto_tree_add_item(mq_tree, hf_mq_rmh_srcenvlen    , tvb, offset +  60,  4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_rmh_srcenvofs    , tvb, offset +  64,  4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_rmh_srcnamelen   , tvb, offset +  68,  4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_rmh_srcnameofs   , tvb, offset +  72,  4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_rmh_dstenvlen    , tvb, offset +  76,  4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_rmh_dstenvofs    , tvb, offset +  80,  4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_rmh_dstnamelen   , tvb, offset +  84,  4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_rmh_dstnameofs   , tvb, offset +  88,  4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_rmh_datalogiclen , tvb, offset +  92,  4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_rmh_datalogicofsl, tvb, offset +  96,  4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_rmh_datalogicofsh, tvb, offset + 100,  4, p_mq_parm->mq_int_enc);
                                            }
                                            else if (p_mq_parm->mq_strucID == MQ_STRUCTID_WIH || p_mq_parm->mq_strucID == MQ_STRUCTID_WIH_EBCDIC)
                                            {
                                                proto_tree_add_item(mq_tree, hf_mq_head_flags       , tvb, offset +  28,  4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_wih_servicename  , tvb, offset +  32, 32, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_wih_servicestep  , tvb, offset +  64,  8, p_mq_parm->mq_str_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_wih_msgtoken     , tvb, offset +  72, 16, ENC_NA);
                                                proto_tree_add_item(mq_tree, hf_mq_wih_reserved     , tvb, offset +  86, 32, p_mq_parm->mq_str_enc);
                                            }
                                            else
                                            {
                                                proto_tree_add_item(mq_tree, hf_mq_head_flags , tvb, offset + 28, 4, p_mq_parm->mq_int_enc);
                                                proto_tree_add_item(mq_tree, hf_mq_head_struct, tvb, offset + 32, iSizeHeader - 32, ENC_NA);
                                            }
                                        }
                                        offset += iSizeHeader;
                                        iHeadersLength += iSizeHeader;
                                        p_mq_parm->mq_strucID = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
                                        p_mq_parm->mq_str_enc = oEnc;
                                    }
                                }
                            }

                            col_append_fstr(pinfo->cinfo, COL_INFO, " (%d bytes)", iSizePayload - iHeadersLength);

                            if (!mq_in_reassembly)
                            {
                                /* Call subdissector for the payload */
                                tvbuff_t *next_tvb;
                                p_mq_parm->mq_cur_ccsid.encod = tvb_get_guint32_endian(tvb, p_mq_parm->iOfsEnc, p_mq_parm->mq_int_enc);
                                p_mq_parm->mq_cur_ccsid.ccsid = tvb_get_guint32_endian(tvb, p_mq_parm->iOfsCcs, p_mq_parm->mq_int_enc);
                                memcpy(p_mq_parm->mq_format,
                                    tvb_get_string_enc(wmem_packet_scope(), tvb, p_mq_parm->iOfsFmt, sizeof(p_mq_parm->mq_format), p_mq_parm->mq_str_enc),
                                    sizeof(p_mq_parm->mq_format));

                                next_tvb = tvb_new_subset_remaining(tvb, offset);
                                if (!dissector_try_heuristic(mq_heur_subdissector_list, next_tvb, pinfo, mqroot_tree, &hdtbl_entry, p_mq_parm))
                                    call_dissector(data_handle, next_tvb, pinfo, mqroot_tree);
                            }
                            else
                            {
                                tvbuff_t *next_tvb;
                                next_tvb = tvb_new_subset_remaining(tvb, offset);
                                call_dissector(data_handle, next_tvb, pinfo, mqroot_tree);
                            }
                        }
                        offset = tvb_length(tvb);
                    }
                    /* After all recognised structures have been dissected, process remaining structure*/
                    if (tvb_length_remaining(tvb, offset) >= 4)
                    {
                        p_mq_parm->mq_strucID = tvb_get_ntohl(tvb, offset);
                        if (tree)
                        {
                            proto_tree_add_text(mqroot_tree, tvb, offset, -1, "%s", val_to_str(p_mq_parm->mq_strucID, mq_StructID_vals, "Unknown (0x%08x)"));
                        }
                    }
                }
                else
                {
                    /* This is a MQ segment continuation (if MQ reassembly is not enabled) */
                    col_append_str(pinfo->cinfo, COL_INFO, " [Unreassembled MQ]");
                    call_dissector(data_handle, tvb_new_subset_remaining(tvb, offset), pinfo, tree);
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
            call_dissector(data_handle, tvb_new_subset_remaining(tvb, offset), pinfo, tree);
        }
    }
}

static int reassemble_mq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    mq_parm_t mq_parm;

    /* Reassembly of the MQ messages that span several PDU (several TSH) */
    /* Typically a TCP PDU is 1460 bytes and a MQ PDU is 32766 bytes */
    if (tvb_length(tvb) < 28)
        return 0;

    memset(&mq_parm, 0, sizeof(mq_parm_t));
    mq_parm.mq_strucID = tvb_get_ntohl(tvb, 0);

    if ( (mq_parm.mq_strucID & MQ_MASK_TSHx) == MQ_STRUCTID_TSHx || (mq_parm.mq_strucID & MQ_MASK_TSHx) == MQ_STRUCTID_TSHx_EBCDIC )
    {
        guint8   iCtlF        = 0;
        gint32   iSegL        = 0;
        gint32   iBegL        = 0;
        gint32   iEnco        = 0;
        gint32   iMulS        = 0;
        gint32   iHdrL        = 0;
        gint32   iNxtP        = 0;
        guint8   iOpcd        = 0;
        gboolean bSeg1st    = FALSE;
        gboolean bSegLst    = FALSE;
        gboolean bMore        = FALSE;

        gint32     iHdl       = 0;
        gint32     iGlbMsgIdx = 0;
        gint32     iSegLength = 0;
        gint16     iSegmIndex = 0;

        guint32     uStrL        = 0;
        guint32     uPadL        = 0;

        /* TSHM structure as 8 bytes more after the length (convid/requestid) */
        if (mq_parm.mq_strucID == MQ_STRUCTID_TSHM || mq_parm.mq_strucID == MQ_STRUCTID_TSHM_EBCDIC)
            iMulS = 8;

        /* Get the Encoding scheme */
        iEnco    = (tvb_get_guint8(tvb,  8 + iMulS) == MQ_LITTLE_ENDIAN ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
        /* Get the Operation Code */
        iOpcd    = tvb_get_guint8( tvb,  9 + iMulS);
        /* Get the Control Flag */
        iCtlF    = tvb_get_guint8( tvb, 10 + iMulS);
        /* Get the Semgnet Length */
        iSegL    = tvb_get_ntohl ( tvb, 4);
        /* First Segment ? */
        bSeg1st = ((iCtlF & MQ_TCF_FIRST) != 0);
        /* Last Segment */
        bSegLst = ((iCtlF & MQ_TCF_LAST) != 0);

        mq_in_reassembly = FALSE;

        if ((iOpcd > 0x80 && !(bSeg1st && bSegLst)) || iOpcd == MQ_TST_ASYNC_MESSAGE)
        {
            proto_tree *mq_tree = NULL;

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
            */

            if (mq_reassembly)
            {
                fragment_head *fd_head;
                guint32 iConnectionId = (pinfo->srcport + pinfo->destport);
                iHdrL = 28 + iMulS;

                /* Get the MQ Handle of the Object */
                iHdl = tvb_get_guint32_endian(tvb, iHdrL + 4, iEnco);
                /* Get the Global Message Index */
                iGlbMsgIdx = tvb_get_guint32_endian(tvb, iHdrL + 12, iEnco);
                /* Get the Segment Length */
                iSegLength = tvb_get_guint32_endian(tvb, iHdrL + 16, iEnco);
                /* Get the Segment Index */
                iSegmIndex = tvb_get_guint16_endian(tvb, iHdrL +20, iEnco);

                /*
                  if SegmIndex == 0, it has 54 bytes + the length and padding
                  of a variable string at the end of the Header
                */

                if (iSegmIndex == 0)
                {
                    uStrL = tvb_get_guint8(tvb, iHdrL + 54);
                    uPadL = ((((2+1+uStrL)/4)+1)*4)-(2+1+uStrL);
                }
                bMore = !bSegLst;
                /*
                  First segment has a longer header
                */
                iNxtP  = iHdrL + ((bSeg1st) ? (54 + 1 + uStrL + uPadL) : (24));
                iNxtP += dissect_mq_md(tvb, NULL, iNxtP, &mq_parm, FALSE);

                /*
                  if it is the 1st Segment, it means we are
                  of the beginning of a reassembling. We must take the whole segment (with tSHM, and headers)
                */
                iBegL = (bSeg1st) ? 0 : iNxtP;

                fd_head = fragment_add_seq_next(&mq_reassembly_table,
                    tvb, iBegL,
                    pinfo, iConnectionId, NULL,
                    iSegL - iBegL, bMore);

                if (tree)
                {
                    proto_item *ti = proto_tree_add_item(tree, proto_mq, tvb, 0, -1, ENC_NA);
                    if (bMore)
                    {
                        proto_item_append_text(ti, " [%s of a Reassembled MQ Segment] Hdl=0x%08x GlbMsgIdx=%d, SegIdx=%d, SegLen=%d",
                            val_to_str(iOpcd, mq_opcode_vals, "Unknown (0x%02x)"),
                            iHdl, iGlbMsgIdx, iSegmIndex, iSegLength);
                    }
                    else
                    {
                        proto_item_append_text(ti, " %s Hdl=0x%08x GlbMsgIdx=%d, SegIdx=%d, SegLen=%d",
                            val_to_str(iOpcd, mq_opcode_vals, "Unknown (0x%02x)"),
                            iHdl, iGlbMsgIdx, iSegmIndex, iSegLength);
                    }
                    mq_tree = proto_item_add_subtree(ti, ett_mq_reaasemb);
                }
                else
                {
                    mq_tree = tree;
                }

                if (fd_head != NULL && pinfo->fd->num == fd_head->reassembled_in)
                {
                    tvbuff_t *next_tvb;

                    /* Reassembly finished */
                    if (fd_head->next != NULL)
                    {
                        /* 2 or more fragments */
                        next_tvb = tvb_new_chain(tvb, fd_head->tvb_data);
                        add_new_data_source(pinfo, next_tvb, "Reassembled MQ");
                    }
                    else
                    {
                        /* Only 1 fragment */
                        next_tvb = tvb;
                    }
                    dissect_mq_pdu(next_tvb, pinfo, mq_tree);
                    return tvb_length(tvb);
                }
                else
                {
                    mq_in_reassembly = TRUE;
                    /* Reassembly in progress */
                    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MQ");
                    col_add_fstr(pinfo->cinfo, COL_INFO, "[%s of a Reassembled MQ Segment] Hdl=0x%08x GlbMsgIdx=%d, SegIdx=%d, SegLen=%d",
                        val_to_str(iOpcd, mq_opcode_vals, "Unknown (0x%02x)"),
                        iHdl, iGlbMsgIdx, iSegmIndex, iSegLength);
                    dissect_mq_pdu(tvb, pinfo, mq_tree);
                    return tvb_length(tvb);
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
                return tvb_length(tvb);
            }
        }
        /* Reassembly not enabled or non-fragmented message */
        dissect_mq_pdu(tvb, pinfo, tree);
    }

    return tvb_length(tvb);
}

static guint get_mq_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
    if (tvb_length_remaining(tvb, offset) >= 8)
    {
        guint32 mq_strucID = tvb_get_ntohl(tvb, 0);
        if ( (mq_strucID & MQ_MASK_TSHx) == MQ_STRUCTID_TSHx || (mq_strucID & MQ_MASK_TSHx) == MQ_STRUCTID_TSHx_EBCDIC )
        {
            return tvb_get_ntohl(tvb, offset + 4);
        }
    }
    return 0;
}

static int dissect_mq_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, mq_desegment, 28, get_mq_pdu_len, reassemble_mq, data);
    return tvb_length(tvb);
}

static void dissect_mq_spx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Since SPX has no standard desegmentation, MQ cannot be performed as well */
    dissect_mq_pdu(tvb, pinfo, tree);
}

static gboolean dissect_mq_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint iProto, void *data)
{
    if (tvb_length(tvb) >= 28)
    {
        guint32 mq_strucID = tvb_get_ntohl(tvb, 0);
        if ( (mq_strucID & MQ_MASK_TSHx) == MQ_STRUCTID_TSHx || (mq_strucID & MQ_MASK_TSHx) == MQ_STRUCTID_TSHx_EBCDIC )
        {
            /* Register this dissector for this conversation */
            conversation_t  *conversation;

            conversation = find_or_create_conversation(pinfo);
            if (iProto == MQ_XPT_TCP)
                conversation_set_dissector(conversation, mq_tcp_handle);

            /* Dissect the packet */
            reassemble_mq(tvb, pinfo, tree, data);
            return TRUE;
        }
    }
    return FALSE;
}

static gboolean    dissect_mq_heur_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return dissect_mq_heur(tvb, pinfo, tree, MQ_XPT_TCP, NULL);
}

static gboolean    dissect_mq_heur_netbios(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return dissect_mq_heur(tvb, pinfo, tree, MQ_XPT_NETBIOS, NULL);
}

static gboolean    dissect_mq_heur_http(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return dissect_mq_heur(tvb, pinfo, tree, MQ_XPT_HTTP, NULL);
}

static void mq_init(void)
{
    reassembly_table_init(&mq_reassembly_table,
        &addresses_reassembly_table_functions);
}

void proto_register_mq(void)
{
    static hf_register_info hf[] =
    {
        { &hf_mq_tsh_StructID , {"StructID..", "mq.tsh.structid", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_mq_tsh_mqseglen , {"MQSegmLen.", "mq.tsh.seglength", FT_UINT32, BASE_DEC, NULL, 0x0, "TSH MQ Segment length", HFILL }},
        { &hf_mq_tsh_convid   , {"Convers ID", "mq.tsh.convid", FT_UINT32, BASE_DEC, NULL, 0x0, "TSH Conversation ID", HFILL }},
        { &hf_mq_tsh_requestid, {"Request ID", "mq.tsh.requestid", FT_UINT32, BASE_DEC, NULL, 0x0, "TSH Request ID", HFILL }},
        { &hf_mq_tsh_byteorder, {"Byte order", "mq.tsh.byteorder", FT_UINT8, BASE_HEX, VALS(GET_VALSV(byteorder)), 0x0, "TSH Byte order", HFILL }},
        { &hf_mq_tsh_opcode   , {"SegmType..", "mq.tsh.type", FT_UINT8, BASE_HEX, VALS(GET_VALSV(opcode)), 0x0, "TSH MQ segment type", HFILL }},
        { &hf_mq_tsh_ctlflgs1 , {"Ctl Flag 1", "mq.tsh.cflags1", FT_UINT8, BASE_HEX, NULL, 0x0, "TSH Control flags 1", HFILL }},
        { &hf_mq_tsh_ctlflgs2 , {"Ctl Flag 2", "mq.tsh.cflags2", FT_UINT8, BASE_HEX, NULL, 0x0, "TSH Control flags 2", HFILL }},
        { &hf_mq_tsh_luwid    , {"LUW Ident.", "mq.tsh.luwid", FT_BYTES, BASE_NONE, NULL, 0x0, "TSH logical unit of work identifier", HFILL }},
        { &hf_mq_tsh_encoding , {"Encoding..", "mq.tsh.encoding", FT_UINT32, BASE_DEC, NULL, 0x0, "TSH Encoding", HFILL }},
        { &hf_mq_tsh_ccsid    , {"CCSID.....", "mq.tsh.ccsid", FT_INT16, BASE_DEC | BASE_RANGE_STRING, RVALS(&GET_VALRV(ccsid)), 0x0, "TSH CCSID", HFILL }},
        { &hf_mq_tsh_reserved , {"Reserved..", "mq.tsh.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, "TSH Reserved", HFILL }},

        { &hf_mq_tsh_tcf_confirmreq, {"Confirm Req", "mq.tsh.tcf.confirmreq", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_TCF_CONFIRM_REQUEST, "TSH TCF Confirm request", HFILL }},
        { &hf_mq_tsh_tcf_error     , {"Error", "mq.tsh.tcf.error", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_TCF_ERROR, "TSH TCF Error", HFILL }},
        { &hf_mq_tsh_tcf_reqclose  , {"Req close", "mq.tsh.tcf.reqclose", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_TCF_REQUEST_CLOSE, "TSH TCF Request close", HFILL }},
        { &hf_mq_tsh_tcf_closechann, {"Close Chnl", "mq.tsh.tcf.closechann", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_TCF_CLOSE_CHANNEL, "TSH TCF Close channel", HFILL }},
        { &hf_mq_tsh_tcf_first     , {"First Seg", "mq.tsh.tcf.first", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_TCF_FIRST, "TSH TCF First", HFILL }},
        { &hf_mq_tsh_tcf_last      , {"Last Seg", "mq.tsh.tcf.last", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_TCF_LAST, "TSH TCF Last", HFILL }},
        { &hf_mq_tsh_tcf_reqacc    , {"Req accept", "mq.tsh.tcf.reqacc", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_TCF_REQUEST_ACCEPTED, "TSH TCF Request accepted", HFILL }},
        { &hf_mq_tsh_tcf_dlq       , {"DLQ used", "mq.tsh.tcf.dlq", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_TCF_DLQ_USED, "TSH TCF DLQ used", HFILL }},

        { &hf_mq_tsh_tcf2_HdrComp  , {"HDR Comp", "mq.tsh.tcf2.hdrcomp", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_TCF2_HDRCOMP      , "TSH TCF2 Header Compressed", HFILL }},
        { &hf_mq_tsh_tcf2_MsgComp  , {"MSG Comp", "mq.tsh.tcf2.msgcomp", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_TCF2_MSGCOMP      , "TSH TCF2 Message Compressed", HFILL }},
        { &hf_mq_tsh_tcf2_CSH      , {"CSH", "mq.tsh.tcf2.csh"    , FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_TCF2_CSH          , "TSH TCF2 CSH", HFILL }},
        { &hf_mq_tsh_tcf2_CmitIntv , {"ComitIntvl", "mq.tsh.tcf.cmitintv", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_TCF2_CMIT_INTERVAL, "TSH TCF2 Commit Interval", HFILL }},

        { &hf_mq_api_replylen , {"Reply len..", "mq.api.replylength", FT_UINT32, BASE_DEC, NULL, 0x0, "API Reply length", HFILL }},
        { &hf_mq_api_compcode , {"Compl Code.", "mq.api.completioncode", FT_UINT32, BASE_DEC, VALS(GET_VALSV(mqcc)), 0x0, "API Completion code", HFILL }},
        { &hf_mq_api_reascode , {"Reason Code", "mq.api.reasoncode", FT_UINT32, BASE_DEC, VALS(GET_VALSV(mqrc)), 0x0, "API Reason code", HFILL }},
        { &hf_mq_api_objecthdl, {"Object Hdl.", "mq.api.hobj", FT_UINT32, BASE_HEX, NULL, 0x0, "API Object handle", HFILL }},

        { &hf_mq_socket_conversid, {"ConversId", "mq.socket.conversid", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "Socket Conversation Id", HFILL }},
        { &hf_mq_socket_requestid, {"RequestId", "mq.socket.requestid", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "Socket Request Id", HFILL }},
        { &hf_mq_socket_type     , {"Type.....", "mq.socket.type", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "Socket Type", HFILL }},
        { &hf_mq_socket_parm1    , {"Parm1....", "mq.socket.parm1", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "Socket Parameter 1", HFILL }},
        { &hf_mq_socket_parm2    , {"Parm2....", "mq.socket.parm2", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "Socket Parameter 2", HFILL }},

        { &hf_mq_caut_StructID , {"StructID." , "mq.caut.structid" , FT_STRINGZ, BASE_NONE   , NULL, 0x0, NULL, HFILL }},
        { &hf_mq_caut_AuthType , {"AuthType." , "mq.caut.authtype" , FT_UINT32 , BASE_HEX_DEC, NULL, 0x0, "CAUT Authority Type", HFILL }},
        { &hf_mq_caut_UsrMaxLen, {"UsrMaxLen", "mq.caut.usrmaxlen", FT_UINT32 , BASE_HEX_DEC, NULL, 0x0, "CAUT userid Maximum length", HFILL }},
        { &hf_mq_caut_PwdMaxLen, {"PwdMaxLen", "mq.caut.pwdmaxlen", FT_UINT32 , BASE_HEX_DEC, NULL, 0x0, "CAUT password Maximum length", HFILL }},
        { &hf_mq_caut_UsrLength, {"UsrLength", "mq.caut.usrlength", FT_UINT32 , BASE_HEX_DEC, NULL, 0x0, "CAUT userid length", HFILL }},
        { &hf_mq_caut_PwdLength, {"PwdLength", "mq.caut.pswlength", FT_UINT32 , BASE_HEX_DEC, NULL, 0x0, "CAUT password length", HFILL }},
        { &hf_mq_caut_usr      , {"userid...", "mq.msh.userid"    , FT_STRINGZ, BASE_NONE   , NULL, 0x0, "CAUT UserId", HFILL }},
        { &hf_mq_caut_psw      , {"password.", "mq.msh.password"  , FT_STRINGZ, BASE_NONE   , NULL, 0x0, "CAUT Password", HFILL }},

        { &hf_mq_msh_StructID  , {"StructID", "mq.msh.structid", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_mq_msh_seqnum    , {"Seq Numb", "mq.msh.seqnum", FT_UINT32, BASE_DEC, NULL, 0x0, "MSH sequence number", HFILL }},
        { &hf_mq_msh_datalength, {"Buf len.", "mq.msh.buflength", FT_UINT32, BASE_DEC, NULL, 0x0, "MSH buffer length", HFILL }},
        { &hf_mq_msh_unknown1  , {"Unknown1", "mq.msh.unknown1", FT_UINT32, BASE_HEX, NULL, 0x0, "MSH unknown1", HFILL }},
        { &hf_mq_msh_msglength , {"Msg len.", "mq.msh.msglength", FT_UINT32, BASE_DEC, NULL, 0x0, "MSH message length", HFILL }},

        { &hf_mq_xqh_StructID  , {"StructID", "mq.xqh.structid", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_mq_xqh_version   , {"Version.", "mq.xqh.version", FT_UINT32, BASE_DEC, NULL, 0x0, "XQH version", HFILL }},
        { &hf_mq_xqh_remoteq   , {"Remote Q", "mq.xqh.remoteq", FT_STRINGZ, BASE_NONE, NULL, 0x0, "XQH remote queue", HFILL }},
        { &hf_mq_xqh_remoteqmgr, {"Rmt QMgr", "mq.xqh.remoteqmgr", FT_STRINGZ, BASE_NONE, NULL, 0x0, "XQH remote queue manager", HFILL }},

        { &hf_mq_id_StructID   , {"Structid..", "mq.id.structid", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_mq_id_FapLevel   , {"FAP level.", "mq.id.level", FT_UINT8, BASE_DEC, NULL, 0x0, "ID Formats And Protocols level", HFILL }},
        { &hf_mq_id_icf1       , {"CapFlag1..", "mq.id.idflags", FT_UINT8, BASE_HEX, NULL, 0x0, "ID Capability Flags 1", HFILL }},
        { &hf_mq_id_Eicf1      , {"ECapFlag1.", "mq.id.ideflags", FT_UINT8, BASE_HEX, NULL, 0x0, "ID E Capability Flags 1", HFILL }},
        { &hf_mq_id_ief1       , {"IniErrFlg1", "mq.id.ief", FT_UINT8, BASE_HEX, NULL, 0x0, "ID Initial Error Flags 1", HFILL }},
        { &hf_mq_id_Reserved   , {"Reserved..", "mq.id.unknown04", FT_UINT16, BASE_HEX, NULL, 0x0, "ID Reserved", HFILL }},
        { &hf_mq_id_MaxMsgBatch, {"MaxMsgBtch", "mq.id.MaxMsgBatch", FT_UINT16, BASE_DEC, NULL, 0x0, "ID max msg per batch", HFILL }},
        { &hf_mq_id_MaxTrSize  , {"MaxTrSize.", "mq.id.MaxTrSize", FT_UINT32, BASE_DEC, NULL, 0x0, "ID max trans size", HFILL }},
        { &hf_mq_id_MaxMsgSize , {"MaxMsgSize", "mq.id.maxmsgsize", FT_UINT32, BASE_DEC, NULL, 0x0, "ID max msg size", HFILL }},
        { &hf_mq_id_SeqWrapVal , {"SeqWrapVal", "mq.id.seqwrap", FT_UINT32, BASE_DEC, NULL, 0x0, "ID seq wrap value", HFILL }},
        { &hf_mq_id_channel    , {"ChannelNme", "mq.id.channelname", FT_STRINGZ, BASE_NONE, NULL, 0x0, "ID channel name", HFILL }},
        { &hf_mq_id_icf2       , {"CapFlag2..", "mq.id.idflags2", FT_UINT8, BASE_HEX, NULL, 0x0, "ID Capability flags 2", HFILL }},
        { &hf_mq_id_Eicf2      , {"ECapFlag2.", "mq.id.ideflags2", FT_UINT8, BASE_HEX, NULL, 0x0, "ID E Capabitlity flags 2", HFILL }},
        { &hf_mq_id_ccsid      , {"ccsid.....", "mq.id.ccsid", FT_INT16, BASE_DEC | BASE_RANGE_STRING, RVALS(&GET_VALRV(ccsid)), 0x0, "ID Coded Character Set ID", HFILL }},
        { &hf_mq_id_qmgrname   , {"QMgrName..", "mq.id.qm", FT_STRINGZ, BASE_NONE, NULL, 0x0, "ID Queue Manager Name", HFILL }},
        { &hf_mq_id_HBInterval , {"HBInterval", "mq.id.hbint", FT_UINT32, BASE_DEC, NULL, 0x0, "ID Heartbeat interval", HFILL }},
        { &hf_mq_id_EFLLength  , {"EFLLength.", "mq.id.efllength", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, "ID EFL Length", HFILL }},
        { &hf_mq_id_ief2       , {"IniErrFlg2", "mq.id.inierrflg2", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, "ID Initial Error Flags 2", HFILL }},
        { &hf_mq_id_Reserved1  , {"Reserved1.", "mq.id.reserved1", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, "ID Reserved 1", HFILL }},
        { &hf_mq_id_HdrCprsLst , {"HdrCprsLst", "mq.id.hdrcprslst", FT_BYTES, BASE_NONE, NULL, 0x0, "ID Hdr Cprs Lst", HFILL }},
        { &hf_mq_id_MsgCprsLst , {"MsgCprsLst", "mq.id.msgcprslst", FT_BYTES, BASE_NONE, NULL, 0x0, "ID Msg Cprs Lst", HFILL }},
        { &hf_mq_id_Reserved2  , {"Reserved2.", "mq.id.reserved2", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, "ID Reserved 2", HFILL }},
        { &hf_mq_id_SSLKeyRst  , {"SSLKeyRst.", "mq.id.sslkeyrst", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "ID SSL Key Reset", HFILL }},
        { &hf_mq_id_ConvBySkt  , {"ConvBySkt.", "mq.id.convbyskt", FT_INT32, BASE_DEC, NULL, 0x0, "ID Conv Per Socket", HFILL }},
        { &hf_mq_id_icf3       , {"CapFlag3..", "mq.id.idflags3", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, "ID Capability flags 3", HFILL }},
        { &hf_mq_id_Eicf3      , {"ECapFlag3.", "mq.id.ideflags3", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, "ID E Capability flags 3", HFILL }},
        { &hf_mq_id_Reserved3  , {"Reserved3.", "mq.id.reserved3", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, "ID Reserved 3", HFILL }},
        { &hf_mq_id_ProcessId  , {"ProcessId.", "mq.id.processid", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "ID Process Identifier", HFILL }},
        { &hf_mq_id_ThreadId   , {"ThreadId..", "mq.id.threadid", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "ID Thread Identifier", HFILL }},
        { &hf_mq_id_TraceId    , {"TraceId...", "mq.id.traceid", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "ID Trace Identifier", HFILL }},
        { &hf_mq_id_ProdId     , {"ProdId....", "mq.id.prodid", FT_STRINGZ, BASE_NONE, NULL, 0x0, "ID Product Identifier", HFILL }},
        { &hf_mq_id_mqmid      , {"MQM ID....", "mq.id.mqmid", FT_STRINGZ, BASE_NONE, NULL, 0x0, "ID MQM ID", HFILL }},

        { &hf_mq_id_icf1_msgseq  , {"Message sequence", "mq.id.icf.msgseq"  , FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_ICF1_MSG_SEQ, "ID ICF Message sequence", HFILL }},
        { &hf_mq_id_icf1_convcap , {"Conversion capable", "mq.id.icf.convcap" , FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_ICF1_CONVERSION_CAPABLE, "ID ICF Conversion capable", HFILL }},
        { &hf_mq_id_icf1_splitmsg, {"Split messages", "mq.id.icf.splitmsg", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_ICF1_SPLIT_MESSAGE, "ID ICF Split message", HFILL }},
        { &hf_mq_id_icf1_RqstInit, {"Request Initiation", "mq.id.icf.rqstinit", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_ICF1_REQUEST_INITIATION, "ID ICF Request Initiation", HFILL }},
        { &hf_mq_id_icf1_RqstSecu, {"Request Security", "mq.id.icf.rqstsecu", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_ICF1_REQUEST_SECURITY, "ID ICF Request Security", HFILL }},
        { &hf_mq_id_icf1_mqreq   , {"MQ request", "mq.id.icf.mqreq"   , FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_ICF1_MQREQUEST, "ID ICF MQ request", HFILL }},
        { &hf_mq_id_icf1_svrsec  , {"Srvr Con security", "mq.id.icf.svrsec"  , FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_ICF1_SVRCONN_SECURITY, "ID ICF Server connection security", HFILL }},
        { &hf_mq_id_icf1_runtime , {"Runtime applic", "mq.id.icf.runtime" , FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_ICF1_RUNTIME, "ID ICF Runtime application", HFILL }},

        { &hf_mq_id_icf2_CanDstLst, {"DistListCapable", "mq.id.icf2.distlistcap"   , FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_ICF2_DIST_LIST_CAPABLE, "ID ICF2 Distribution List Capable", HFILL }},
        { &hf_mq_id_icf2_FstMsgReq, {"Fast Msg Reqrd", "mq.id.icf2.fastmsgrqrd"   , FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_ICF2_FAST_MESSAGES_REQUIRED, "ID ICF2 Fast Message Required", HFILL }},
        { &hf_mq_id_icf2_RespConv , {"RspndrConversion", "mq.id.icf2.respndrconvers", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_ICF2_RESPONDER_CONVERSION, "ID ICF2 Responder Conversion", HFILL }},
        { &hf_mq_id_icf2_XARequest, {"XARequest", "mq.id.icf2.xarequest"     , FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_ICF2_XAREQUEST, "ID ICF2 XA Request", HFILL }},
        { &hf_mq_id_icf2_XARunTApp, {"XARunTypApp", "mq.id.icf2.xaruntypapp"   , FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_ICF2_XARUNTIME_APP, "ID ICF2 XA Runtime App", HFILL }},
        { &hf_mq_id_icf2_SPIRqst  , {"SPIRequest", "mq.id.icf2.spirequest"    , FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_ICF2_SPIREQUEST, "ID ICF2 SPI Request", HFILL }},
        { &hf_mq_id_icf2_DualUOW  , {"DualUOW", "mq.id.icf2.dualuow"       , FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_ICF2_DUAL_UOW, "ID ICF2 Dual UOW", HFILL }},
        { &hf_mq_id_icf2_CanTrcRte, {"Trace Rte Capab", "mq.id.icf2.cantraceroute" , FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_ICF2_TRACE_ROUTE_CAPABLE, "ID ICF2 Trace Route Capable", HFILL }},

        { &hf_mq_id_icf3_CanMsgPrp, {"Msg Property Cap", "mq.id.icf.msgprpcap", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_ICF3_MSG_PROP_CAPABLE, "ID ICF3 Message PropertyCapable", HFILL }},
        { &hf_mq_id_icf3_Unknown02, {"Unknownx02", "mq.id.icf.unknown02", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_ICF3_UNKNOWNX02, "ID ICF3 Unknown Falg x02", HFILL }},

        { &hf_mq_id_ief1_ccsid  , {"Invalid CCSID", "mq.id.ief1.ccsid", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_IEF1_CCSID, "ID invalid CCSID", HFILL }},
        { &hf_mq_id_ief1_enc    , {"Invalid encoding", "mq.id.ief1.enc", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_IEF1_ENCODING, "ID invalid encoding", HFILL }},
        { &hf_mq_id_ief1_mxtrsz , {"Invalid Max Trans Size", "mq.id.ief1.mxtrsz", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_IEF1_MAX_TRANSMISSION_SIZE, "ID invalid maximum transmission size", HFILL }},
        { &hf_mq_id_ief1_fap    , {"Invalid FAP level", "mq.id.ief1.fap", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_IEF1_FAP_LEVEL, "ID invalid FAP level", HFILL }},
        { &hf_mq_id_ief1_mxmsgsz, {"Invalid message size", "mq.id.ief1.mxmsgsz", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_IEF1_MAX_MSG_SIZE, "ID invalid message size", HFILL }},
        { &hf_mq_id_ief1_mxmsgpb, {"Invalid Max Msg batch", "mq.id.ief1.mxmsgpb", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_IEF1_MAX_MSG_PER_BATCH, "ID maximum message per batch", HFILL }},
        { &hf_mq_id_ief1_seqwrap, {"Invalid Seq Wrap Value", "mq.id.ief1.seqwrap", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_IEF1_SEQ_WRAP_VALUE, "ID invalid sequence wrap value", HFILL }},
        { &hf_mq_id_ief1_hbint  , {"Invalid HB interval", "mq.id.ief1.hbint", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_IEF1_HEARTBEAT_INTERVAL, "ID invalid heartbeat interval", HFILL }},

        { &hf_mq_id_ief2_HdrCmpLst, {"Invalid HDR CompLst", "mq.id.ief2.hdrcomplst", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_IEF2_HDRCOMPLIST, "ID invalid Header Compression List", HFILL }},
        { &hf_mq_id_ief2_MsgCmpLst, {"Invalid Msg CompLst", "mq.id.ief2.msgcomplst", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_IEF2_MSGCOMPLIST, "ID invalid Message Compression List", HFILL }},
        { &hf_mq_id_ief2_SSLReset , {"Invalid SSL Reset", "mq.id.ief2.sslreset"  , FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_IEF2_SSL_RESET  , "ID invalid SSL Reset", HFILL }},

        { &hf_mq_uid_StructID  , {"Structid", "mq.uid.structid", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_mq_uid_userid    , {"User ID.", "mq.uid.userid", FT_STRINGZ, BASE_NONE, NULL, 0x0, "UID structid", HFILL }},
        { &hf_mq_uid_password  , {"Password", "mq.uid.password", FT_STRINGZ, BASE_NONE, NULL, 0x0, "UID password", HFILL }},
        { &hf_mq_uid_longuserid, {"Long UID", "mq.uid.longuserid", FT_STRINGZ, BASE_NONE, NULL, 0x0, "UID long user id", HFILL }},

        { &hf_mq_sidlen        , {"SID Len.", "mq.uid.sidlen", FT_UINT8, BASE_DEC, NULL, 0x0, "Sid Len", HFILL }},
        { &hf_mq_sidtyp        , {"SIDType.", "mq.uid.sidtyp", FT_UINT8, BASE_DEC, VALS(GET_VALSV(sidtype)), 0x0, "Sid Typ", HFILL }},
        { &hf_mq_securityid    , {"SecurID.", "mq.uid.securityid", FT_BYTES, BASE_NONE, NULL, 0x0, "Security ID", HFILL }},

        { &hf_mq_conn_QMgr     , {"QMgr....", "mq.conn.qm", FT_STRINGZ, BASE_NONE, NULL, 0x0, "CONN queue manager", HFILL }},
        { &hf_mq_conn_appname  , {"ApplName", "mq.conn.appname", FT_STRINGZ, BASE_NONE, NULL, 0x0, "CONN application name", HFILL }},
        { &hf_mq_conn_apptype  , {"ApplType", "mq.conn.apptype", FT_INT32, BASE_DEC, VALS(GET_VALSV(mqat)), 0x0, "CONN application type", HFILL }},
        { &hf_mq_conn_acttoken , {"AccntTok", "mq.conn.acttoken", FT_BYTES, BASE_NONE, NULL, 0x0, "CONN accounting token", HFILL }},
        { &hf_mq_conn_version  , {"Version.", "mq.conn.version", FT_UINT32, BASE_DEC, VALS(mq_conn_version_vals), 0x0, "CONN version", HFILL }},
        { &hf_mq_conn_options  , {"Options.", "mq.conn.options", FT_UINT32, BASE_HEX, NULL, 0x0, "CONN options", HFILL }},

        { &hf_mq_fcno_StructID , {"StructId.", "mq.fcno.structid", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_mq_fcno_unknown00, {"unknown00", "mq.fcno.unknown00", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "FCNO unknown00", HFILL }},
        { &hf_mq_fcno_unknown01, {"unknown01", "mq.fcno.unknown01", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "FCNO unknown01", HFILL }},
        { &hf_mq_fcno_unknown02, {"unknown02", "mq.fcno.unknown02", FT_BYTES, BASE_NONE, NULL, 0x0, "FCNO unknown02", HFILL }},
        { &hf_mq_fcno_msgid    , {"msgid....", "mq.fcno.msgid", FT_STRINGZ, BASE_NONE, NULL, 0x0, "FCNO Msg ID", HFILL }},
        { &hf_mq_fcno_mqmid    , {"MqmId....", "mq.fcno.mqmid", FT_STRINGZ, BASE_NONE, NULL, 0x0, "FCNO Mqm ID", HFILL }},

        { &hf_mq_inq_nbsel     , {"Selector count..", "mq.inq.nbsel", FT_UINT32, BASE_DEC, NULL, 0x0, "INQ Selector count", HFILL }},
        { &hf_mq_inq_nbint     , {"Integer count...", "mq.inq.nbint", FT_UINT32, BASE_DEC, NULL, 0x0, "INQ Integer count", HFILL }},
        { &hf_mq_inq_charlen   , {"Character length", "mq.inq.charlen", FT_UINT32, BASE_DEC, NULL, 0x0, "INQ Character length", HFILL }},
        { &hf_mq_inq_sel       , {"Selector........", "mq.inq.sel", FT_UINT32, BASE_DEC, VALS(GET_VALSV(selector)), 0x0, "INQ Selector", HFILL }},
        { &hf_mq_inq_intvalue  , {"Integer value...", "mq.inq.intvalue", FT_UINT32, BASE_DEC, NULL, 0x0, "INQ Integer value", HFILL }},
        { &hf_mq_inq_charvalues, {"Char values.....", "mq.inq.charvalues", FT_STRINGZ, BASE_NONE, NULL, 0x0, "INQ Character values", HFILL }},

        { &hf_mq_spi_verb      , {"SPI Verb", "mq.spi.verb", FT_UINT32, BASE_DEC, VALS(GET_VALSV(spi_verbs)), 0x0, NULL, HFILL }},
        { &hf_mq_spi_version   , {"Version", "mq.spi.version", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Version", HFILL }},
        { &hf_mq_spi_length    , {"Max reply size", "mq.spi.replength", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Max reply size", HFILL }},

        { &hf_mq_spi_base_StructID, {"SPI Structid", "mq.spib.structid", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_mq_spi_base_version , {"Version", "mq.spib.version", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Base Version", HFILL }},
        { &hf_mq_spi_base_length  , {"Length", "mq.spib.length", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Base Length", HFILL }},

        { &hf_mq_spi_spqo_nbverb  , {"Number of verbs", "mq.spqo.nbverb", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Query Output Number of verbs", HFILL }},
        { &hf_mq_spi_spqo_verbid  , {"Verb", "mq.spqo.verb", FT_UINT32, BASE_DEC, VALS(GET_VALSV(spi_verbs)), 0x0, "SPI Query Output VerbId", HFILL }},
        { &hf_mq_spi_spqo_maxiover, {"Max InOut Version", "mq.spqo.maxiov", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Query Output Max InOut Version", HFILL }},
        { &hf_mq_spi_spqo_maxinver, {"Max In Version", "mq.spqo.maxiv", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Query Output Max In Version", HFILL }},
        { &hf_mq_spi_spqo_maxouver, {"Max Out Version", "mq.spqo.maxov", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Query Output Max Out Version", HFILL }},
        { &hf_mq_spi_spqo_flags   , {"Flags", "mq.spqo.flags", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Query Output flags", HFILL }},

        { &hf_mq_spi_spai_mode    , {"Mode", "mq.spai.mode", FT_UINT32, BASE_DEC, VALS(GET_VALSV(spi_activate)), 0x0, "SPI Activate Input mode", HFILL }},
        { &hf_mq_spi_spai_unknown1, {"Unknown1", "mq.spai.unknown1", FT_STRINGZ, BASE_NONE, NULL, 0x0, "SPI Activate Input unknown1", HFILL }},
        { &hf_mq_spi_spai_unknown2, {"Unknown2", "mq.spai.unknown2", FT_STRINGZ, BASE_NONE, NULL, 0x0, "SPI Activate Input unknown2", HFILL }},
        { &hf_mq_spi_spai_msgid   , {"Message Id", "mq.spai.msgid", FT_STRINGZ, BASE_NONE, NULL, 0x0, "SPI Activate Input message id", HFILL }},
        { &hf_mq_spi_spgi_batchsz , {"Batch size", "mq.spgi.batchsize", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Get Input batch size", HFILL }},
        { &hf_mq_spi_spgi_batchint, {"Batch interval", "mq.spgi.batchint", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Get Input batch interval", HFILL }},
        { &hf_mq_spi_spgi_maxmsgsz, {"Max message size", "mq.spgi.maxmsgsize", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Get Input max message size", HFILL }},

        { &hf_mq_spi_spgo_options , {"Options", "mq.spgo.options", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Get Output options", HFILL }},
        { &hf_mq_spi_spgo_size    , {"Size", "mq.spgo.size", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Get Output size", HFILL }},
        { &hf_mq_spi_opt_blank    , {"Blank padded", "mq.spi.options.blank", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_SPI_OPTIONS_BLANK_PADDED, "SPI Options blank padded", HFILL }},
        { &hf_mq_spi_opt_syncp    , {"Syncpoint", "mq.spi.options.sync", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_SPI_OPTIONS_SYNCPOINT, "SPI Options syncpoint", HFILL }},
        { &hf_mq_spi_opt_deferred , {"Deferred", "mq.spi.options.deferred", FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQ_SPI_OPTIONS_DEFERRED, "SPI Options deferred", HFILL }},

        { &hf_mq_put_length       , {"Data length", "mq.put.length", FT_UINT32, BASE_DEC, NULL, 0x0, "PUT Data length", HFILL }},

        { &hf_mq_close_options    , {"Options", "mq.close.options", FT_UINT32, BASE_HEX, NULL, 0x0, "CLOSE options", HFILL }},
        { &hf_mq_close_options_DELETE      , {"DELETE", "mq.close.options.Delete", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQCO_DELETE, "CLOSE options DELETE", HFILL }},
        { &hf_mq_close_options_DELETE_PURGE, {"DELETE_PURGE", "mq.close.options.DeletePurge", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQCO_DELETE_PURGE, "CLOSE options DELETE_PURGE", HFILL }},
        { &hf_mq_close_options_KEEP_SUB    , {"KEEPSUB", "mq.close.options.KeepSub", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQCO_KEEP_SUB, "CLOSE options KEEP_SUB", HFILL }},
        { &hf_mq_close_options_REMOVE_SUB  , {"REMOVE_SUB", "mq.close.options.RemoveSub", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQCO_REMOVE_SUB, "CLOSE options REMOVE_SUB", HFILL }},
        { &hf_mq_close_options_QUIESCE     , {"QUIESCE", "mq.close.options.Quiesce", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQCO_QUIESCE, "CLOSE options QUIESCE", HFILL }},

        { &hf_mq_open_options     , {"Options", "mq.open.options", FT_UINT32, BASE_HEX, NULL, 0x0, "OPEN options", HFILL }},
        { &hf_mq_open_options_INPUT_AS_Q_DEF , {"INPUT_AS_Q_DEF", "mq.open.options.InputAsQDef", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_INPUT_AS_Q_DEF, "OPEN options INPUT_AS_Q_DEF", HFILL }},
        { &hf_mq_open_options_INPUT_SHARED   , {"INPUT_SHARED", "mq.open.options.InputShared", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_INPUT_SHARED, "OPEN options INPUT_SHARED", HFILL }},
        { &hf_mq_open_options_INPUT_EXCLUSIVE, {"INPUT_EXCLUSIVE", "mq.open.options.InputExclusive", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_INPUT_EXCLUSIVE, "OPEN options INPUT_EXCLUSIVE", HFILL }},
        { &hf_mq_open_options_BROWSE         , {"BROWSE", "mq.open.options.Browse", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_BROWSE, "OPEN options BROWSE", HFILL }},
        { &hf_mq_open_options_OUTPUT         , {"OUTPUT", "mq.open.options.Output", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_OUTPUT, "OPEN options OUTPUT", HFILL }},
        { &hf_mq_open_options_INQUIRE        , {"INQUIRE", "mq.open.options.Inquire", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_INQUIRE, "OPEN options INQUIRE", HFILL }},
        { &hf_mq_open_options_SET            , {"SET", "mq.open.options.Set", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_SET, "OPEN options SET", HFILL }},
        { &hf_mq_open_options_SAVE_ALL_CTX   , {"SAVE_ALL_CONTEXT", "mq.open.options.SaveAllContext", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_SAVE_ALL_CONTEXT, "OPEN options SAVE_ALL_CONTEXT", HFILL }},
        { &hf_mq_open_options_PASS_IDENT_CTX , {"PASS_IDENTITY_CONTEXT", "mq.open.options.PassIdentityContext", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_PASS_IDENTITY_CONTEXT, "OPEN options PASS_IDENTITY_CONTEXT", HFILL }},
        { &hf_mq_open_options_PASS_ALL_CTX   , {"PASS_ALL_CONTEXT", "mq.open.options.PassAllContext", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_PASS_ALL_CONTEXT, "OPEN options PASS_ALL_CONTEXT", HFILL }},
        { &hf_mq_open_options_SET_IDENT_CTX  , {"SET_IDENTITY_CONTEXT", "mq.open.options.SetIdentityContext", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_SET_IDENTITY_CONTEXT, "OPEN options SET_IDENTITY_CONTEXT", HFILL }},
        { &hf_mq_open_options_SET_ALL_CONTEXT, {"SET_ALL_CONTEXT", "mq.open.options.SetAllContext", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_SET_ALL_CONTEXT, "OPEN options SET_ALL_CONTEXT", HFILL }},
        { &hf_mq_open_options_ALT_USER_AUTH  , {"ALTERNATE_USER_AUTHORITY", "mq.open.options.AlternateUserAuthority", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_ALTERNATE_USER_AUTHORITY, "OPEN options ALTERNATE_USER_AUTHORITY", HFILL }},
        { &hf_mq_open_options_FAIL_IF_QUIESC , {"FAIL_IF_QUIESCING", "mq.open.options.FailIfQuiescing", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_FAIL_IF_QUIESCING, "OPEN options FAIL_IF_QUIESCING", HFILL }},
        { &hf_mq_open_options_BIND_ON_OPEN   , {"BIND_ON_OPEN", "mq.open.options.BindOnOpen", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_BIND_ON_OPEN, "OPEN options BIND_ON_OPEN", HFILL }},
        { &hf_mq_open_options_BIND_NOT_FIXED , {"BIND_NOT_FIXED", "mq.open.options.BindNotFixed", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_BIND_NOT_FIXED, "OPEN options BIND_NOT_FIXED", HFILL }},
        { &hf_mq_open_options_RESOLVE_NAMES  , {"RESOLVE_NAMES", "mq.open.options.ResolveNames", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_RESOLVE_NAMES, "OPEN options RESOLVE_NAMES", HFILL }},
        { &hf_mq_open_options_CO_OP          , {"CO_OP", "mq.open.options.CoOp", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_CO_OP, "OPEN options CO_OP", HFILL }},
        { &hf_mq_open_options_RESOLVE_LOCAL_Q, {"RESOLVE_LOCAL_Q", "mq.open.options.ResolveLocalQueueOrTopic", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_RESOLVE_LOCAL_Q, "OPEN options RESOLVE_LOCAL_Q", HFILL }},
        { &hf_mq_open_options_NO_READ_AHEAD  , {"NO_READ_AHEAD", "mq.open.options.NoReadAhead", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_NO_READ_AHEAD, "OPEN options NO_READ_AHEAD", HFILL }},
        { &hf_mq_open_options_READ_AHEAD     , {"READ_AHEAD", "mq.open.options.ReadAhead", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_READ_AHEAD, "OPEN options READ_AHEAD", HFILL }},
        { &hf_mq_open_options_NO_MULTICAST   , {"NO_MULTICAST", "mq.open.options.NoMulticast", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_NO_MULTICAST, "OPEN options NO_MULTICAST", HFILL }},
        { &hf_mq_open_options_BIND_ON_GROUP  , {"BIND_ON_GROUP", "mq.open.options.BindOnGroup", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQOO_BIND_ON_GROUP, "OPEN options BIND_ON_GROUP", HFILL }},

        { &hf_mq_fopa_StructID, {"StructId", "mq.fopa.structid", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_mq_fopa_version , {"Version.", "mq.fopa.version", FT_UINT32, BASE_DEC, NULL, 0x0, "FOPA Version", HFILL }},
        { &hf_mq_fopa_length  , {"Length..", "mq.fopa.length", FT_UINT32, BASE_DEC, NULL, 0x0, "FOPA Length", HFILL }},
        { &hf_mq_fopa_unknown1, {"Unknown1", "mq.fopa.unknown1", FT_UINT32, BASE_HEX, NULL, 0x0, "FOPA unknown1", HFILL }},
        { &hf_mq_fopa_unknown2, {"Unknown2", "mq.fopa.unknown2", FT_UINT32, BASE_HEX, NULL, 0x0, "FOPA unknown2", HFILL }},
        { &hf_mq_fopa_unknown3, {"Unknown3", "mq.fopa.unknown3", FT_STRINGZ, BASE_NONE, NULL, 0x0, "FOPA unknown3", HFILL }},
        { &hf_mq_fopa_qprotect, {"qprotect", "mq.fopa.qprotect", FT_STRINGZ, BASE_NONE, NULL, 0x0, "FOPA queue protection", HFILL }},
        { &hf_mq_fopa_unknown4, {"Unknown4", "mq.fopa.unknown4", FT_UINT32, BASE_HEX, NULL, 0x0, "FOPA unknown4", HFILL }},
        { &hf_mq_fopa_unknown5, {"Unknown5", "mq.fopa.unknown5", FT_UINT32, BASE_HEX, NULL, 0x0, "FOPA unknown5", HFILL }},

        { &hf_mq_msgreq_version  , {"version..", "mq.msgreq.version"  , FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "MSGREQ version", HFILL }},
        { &hf_mq_msgreq_handle   , {"handle...", "mq.msgreq.handle"   , FT_UINT32, BASE_HEX, NULL, 0x0, "MSGREQ handle", HFILL }},
        { &hf_mq_msgreq_RecvBytes, {"RecvBytes", "mq.msgreq.unknown1" , FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "MSGREQ Received Bytes", HFILL }},
        { &hf_mq_msgreq_RqstBytes, {"RqstBytes", "mq.msgreq.rqstbytes", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "MSGREQ Requesed Bytes", HFILL }},
        { &hf_mq_msgreq_MaxMsgLen, {"MaxMsgLen", "mq.msgreq.maxmsglen", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "MSGREQ Maximum Msg Length", HFILL }},
        { &hf_mq_msgreq_WaitIntrv, {"WaitIntrv", "mq.msgreq.waitintrv", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "MSGREQ Wait Interval", HFILL }},
        { &hf_mq_msgreq_QueStatus, {"QueStatus", "mq.msgreq.questatus", FT_UINT32, BASE_HEX    , NULL, 0x0, "MSGREQ Queue Status", HFILL }},
        { &hf_mq_msgreq_RqstFlags, {"RqstFlags", "mq.msgreq.rqstflags", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "MSGREQ Request Flags", HFILL }},
        { &hf_mq_msgreq_GlbMsgIdx, {"GlbMsgIdx", "mq.msgreq.glbmsgidx", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "MSGREQ Global Message Index", HFILL }},
        { &hf_mq_msgreq_SelectIdx, {"SelectIdx", "mq.msgreq.selectIdx", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, "MSGREQ Selection Index", HFILL }},
        { &hf_mq_msgreq_MQMDVers , {"MQMDVers.", "mq.msgreq.mqmdvers" , FT_UINT16, BASE_HEX_DEC, NULL, 0x0, "MSGREQ MQMD Version", HFILL }},
        { &hf_mq_msgreq_ccsid    , {"CCSID....", "mq.msgreq.ccsid"    , FT_INT32 , BASE_DEC | BASE_RANGE_STRING, RVALS(&GET_VALRV(ccsid)), 0x0, "MSGREQ ccsid", HFILL }},
        { &hf_mq_msgreq_encoding , {"Encoding.", "mq.msgreq.encoding" , FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "MSGREQ encoding", HFILL }},
        { &hf_mq_msgreq_MsgSeqNum, {"MsgSeqNum", "mq.msgreq.msgseqnum", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "MSGREQ Message Sequence Number", HFILL }},
        { &hf_mq_msgreq_offset   , {"Offset...", "mq.msgreq.offset"   , FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "MSGREQ Offset", HFILL }},
        { &hf_mq_msgreq_mtchMsgId, {"mtchMsgId", "mq.msgreq.mtchMsgId", FT_BYTES , BASE_NONE   , NULL, 0x0, "MSGREQ match MsgID", HFILL }},
        { &hf_mq_msgreq_mtchCorId, {"mtchCorID", "mq.msgreq.mtchcorid", FT_BYTES , BASE_NONE   , NULL, 0x0, "MSGREQ match Correlation Id", HFILL }},
        { &hf_mq_msgreq_mtchGrpid, {"mtchGrpID", "mq.msgreq.mtchgrpid", FT_BYTES , BASE_NONE   , NULL, 0x0, "MSGREQ match Group ID", HFILL }},
        { &hf_mq_msgreq_mtchMsgTk, {"mtchMsgTk", "mq.msgreq.mtchmsgtk", FT_BYTES , BASE_NONE   , NULL, 0x0, "MSGREQ match Message Token", HFILL }},

        { &hf_mq_msgasy_version  , {"version..", "mq.msgasy.version"  , FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "MSGASYNC version", HFILL }},
        { &hf_mq_msgasy_handle   , {"handle...", "mq.msgasy.handle"   , FT_UINT32, BASE_HEX, NULL, 0x0, "MSGASYNC handle", HFILL }},
        { &hf_mq_msgasy_MsgIndex , {"MsgIndex.", "mq.msgasy.msgindex" , FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "MSGASYNC Message Index", HFILL }},
        { &hf_mq_msgasy_GlbMsgIdx, {"GlbMsgIdx", "mq.msgasy.glbmsgidx", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "MSGASYNC Global Message Index", HFILL }},
        { &hf_mq_msgasy_SegLength, {"SegLength", "mq.msgasy.seglength", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "MSGASYNC Segment Length", HFILL }},
        { &hf_mq_msgasy_SegmIndex, {"SegmIndex", "mq.msgasy.segmindex", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, "MSGASYNC Segment Index", HFILL }},
        { &hf_mq_msgasy_SeleIndex, {"SeleIndex", "mq.msgasy.seleindex", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, "MSGASYNC Selection Index", HFILL }},
        { &hf_mq_msgasy_ReasonCod, {"ReasonCod", "mq.msgasy.reasoncod", FT_UINT32, BASE_HEX    , NULL, 0x0, "MSGASYNC Reason Code", HFILL }},
        { &hf_mq_msgasy_ActMsgLen, {"ActMsgLen", "mq.msgasy.actmsglen", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "MSGASYNC Actual Message Length", HFILL }},
        { &hf_mq_msgasy_TotMsgLen, {"TotMsgLen", "mq.msgasy.totmsglen", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "MSGASYNC Total Message Length", HFILL }},
        { &hf_mq_msgasy_MsgToken , {"MsgToken.", "mq.msgasy.msgtoken" , FT_BYTES , BASE_NONE   , NULL, 0x0, "MSGASYNC Mesasage Token", HFILL }},
        { &hf_mq_msgasy_Status   , {"status...", "mq.msgasy.status"   , FT_UINT16, BASE_HEX    , NULL, 0x0, "MSGASYNC Status", HFILL }},
        { &hf_mq_msgasy_resolQNLn, {"resolQNLn", "mq.msgasy.resolqnln", FT_UINT8 , BASE_DEC    , NULL, 0x0, "MSGASYNC Resolved Queue Name Length", HFILL }},
        { &hf_mq_msgasy_resolQNme, {"resolQNme", "mq.msgasy.resolqnme", FT_STRINGZ, BASE_NONE  , NULL, 0x0, "MSGASYNC Resolved Queue Name", HFILL }},
        { &hf_mq_msgasy_padding  , {"Padding..", "mq.msgasy.padding"  , FT_BYTES , BASE_NONE   , NULL, 0x0, "MSGASYNC Padding", HFILL }},

        { &hf_mq_notif_vers     , {"version.", "mq.notif.vers"  , FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "NOTIFICATION version", HFILL }},
        { &hf_mq_notif_handle   , {"handle..", "mq.notif.handle", FT_UINT32, BASE_HEX    , NULL, 0x0, "NOTIFICATION handle", HFILL }},
        { &hf_mq_notif_code     , {"code....", "mq.notif.code"  , FT_UINT32, BASE_HEX_DEC, VALS(GET_VALSV(notifcode)), 0x0, "NOTIFICATION code", HFILL }},
        { &hf_mq_notif_value    , {"value...", "mq.notif.value" , FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "NOTIFICATION MQRC", HFILL }},

        { &hf_mq_ping_length    , {"Length", "mq.ping.length", FT_UINT32, BASE_DEC, NULL, 0x0, "PING length", HFILL }},
        { &hf_mq_ping_buffer    , {"Buffer", "mq.ping.buffer", FT_BYTES, BASE_NONE, NULL, 0x0, "PING buffer", HFILL }},

        { &hf_mq_reset_length   , {"Length", "mq.reset.length", FT_UINT32, BASE_DEC, NULL, 0x0, "RESET length", HFILL }},
        { &hf_mq_reset_seqnum   , {"SeqNum", "mq.reset.seqnum", FT_UINT32, BASE_DEC, NULL, 0x0, "RESET sequence number", HFILL }},

        { &hf_mq_status_length  , {"Length", "mq.status.length", FT_UINT32, BASE_DEC, NULL, 0x0, "STATUS length", HFILL }},
        { &hf_mq_status_code    , {"Code..", "mq.status.code"  , FT_UINT32, BASE_DEC, VALS(GET_VALSV(status)), 0x0, "STATUS code", HFILL }},
        { &hf_mq_status_value   , {"Value.", "mq.status.value" , FT_UINT32, BASE_DEC, NULL, 0x0, "STATUS value", HFILL }},

        { &hf_mq_od_StructID    , {"StructID.........", "mq.od.structid", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_mq_od_version     , {"version..........", "mq.od.version", FT_UINT32, BASE_DEC, NULL, 0x0, "OD version", HFILL }},
        { &hf_mq_od_objecttype  , {"ObjType..........", "mq.od.objtype", FT_UINT32, BASE_DEC, VALS(GET_VALSV(objtype)), 0x0, "OD object type", HFILL }},
        { &hf_mq_od_objectname  , {"ObjName..........", "mq.od.objname", FT_STRINGZ, BASE_NONE, NULL, 0x0, "OD object name", HFILL }},
        { &hf_mq_od_objqmgrname , {"ObjQMgr..........", "mq.od.objqmgrname", FT_STRINGZ, BASE_NONE, NULL, 0x0, "OD object queue manager name", HFILL }},
        { &hf_mq_od_dynqname    , {"DynQName.........", "mq.od.dynqname", FT_STRINGZ, BASE_NONE, NULL, 0x0, "OD dynamic queue name", HFILL }},
        { &hf_mq_od_altuserid   , {"AltUserID........", "mq.od.altuserid", FT_STRINGZ, BASE_NONE, NULL, 0x0, "OD alternate userid", HFILL }},
        { &hf_mq_od_recspresent , {"NbrRecord........", "mq.od.nbrrec", FT_UINT32, BASE_DEC, NULL, 0x0, "OD number of records", HFILL }},
        { &hf_mq_od_knowndstcnt , {"Known Dest Count.", "mq.od.kdestcount", FT_UINT32, BASE_DEC, NULL, 0x0, "OD known destination count", HFILL }},
        { &hf_mq_od_unknowdstcnt, {"Unknown Dest Cnt.", "mq.od.udestcount", FT_UINT32, BASE_DEC, NULL, 0x0, "OD unknown destination count", HFILL }},
        { &hf_mq_od_invaldstcnt , {"Invalid Dest Cnt.", "mq.od.idestcount", FT_UINT32, BASE_DEC, NULL, 0x0, "OD invalid destination count", HFILL }},
        { &hf_mq_od_objrecofs   , {"Offset of 1st OR.", "mq.od.offsetor", FT_UINT32, BASE_DEC, NULL, 0x0, "OD offset of first OR", HFILL }},
        { &hf_mq_od_resprecofs  , {"Offset of 1st RR.", "mq.od.offsetrr", FT_UINT32, BASE_DEC, NULL, 0x0, "OD offset of first RR", HFILL }},
        { &hf_mq_od_objrecptr   , {"Addr   of 1st OR.", "mq.od.addror", FT_UINT32, BASE_HEX, NULL, 0x0, "OD address of first OR", HFILL }},
        { &hf_mq_od_resprecptr  , {"Addr   of 1st RR.", "mq.od.addrrr", FT_UINT32, BASE_HEX, NULL, 0x0, "OD address of first RR", HFILL }},
        { &hf_mq_od_altsecurid  , {"Alt security id..", "mq.od.altsecid", FT_STRINGZ, BASE_NONE, NULL, 0x0, "OD alternate security id", HFILL }},
        { &hf_mq_od_resolvqname , {"Resolved Q Name..", "mq.od.resolvq", FT_STRINGZ, BASE_NONE, NULL, 0x0, "OD resolved queue name", HFILL }},
        { &hf_mq_od_resolvqmgrnm, {"Resolved QMgrName", "mq.od.resolvqmgr", FT_STRINGZ, BASE_NONE, NULL, 0x0, "OD resolved queue manager name", HFILL }},
        { &hf_mq_od_resolvobjtyp, {"Resolv Obj Type..", "mq.od.resolvedobjtype", FT_UINT32, BASE_DEC, VALS(GET_VALSV(objtype)), 0x0, "OD resolved object type", HFILL }},

        { &hf_mq_or_objname     , {"Object name...", "mq.or.objname", FT_STRINGZ, BASE_NONE, NULL, 0x0, "OR object name", HFILL }},
        { &hf_mq_or_objqmgrname , {"Object QMgr Nm", "mq.or.objqmgrname", FT_STRINGZ, BASE_NONE, NULL, 0x0, "OR object queue manager name", HFILL }},

        { &hf_mq_rr_compcode    , {"Comp Code", "mq.rr.completioncode", FT_UINT32, BASE_DEC, NULL, 0x0, "OR completion code", HFILL }},
        { &hf_mq_rr_reascode    , {"Reas Code", "mq.rr.reasoncode", FT_UINT32, BASE_DEC, NULL, 0x0, "OR reason code", HFILL }},

        { &hf_mq_pmr_msgid      , {"Message Id", "mq.pmr.msgid", FT_BYTES, BASE_NONE, NULL, 0x0, "PMR Message Id", HFILL }},
        { &hf_mq_pmr_correlid   , {"Correlation Id", "mq.pmr.correlid", FT_BYTES, BASE_NONE, NULL, 0x0, "PMR Correlation Id", HFILL }},
        { &hf_mq_pmr_groupid    , {"GroupId", "mq.pmr.groupid", FT_BYTES, BASE_NONE, NULL, 0x0, "PMR GroupId", HFILL }},
        { &hf_mq_pmr_feedback   , {"Feedback", "mq.pmr.feedback", FT_UINT32, BASE_DEC, NULL, 0x0, "PMR Feedback", HFILL }},
        { &hf_mq_pmr_acttoken   , {"Accounting token", "mq.pmr.acttoken", FT_BYTES, BASE_NONE, NULL, 0x0, "PMR accounting token", HFILL }},

        { &hf_mq_md_StructID    , {"StructID.", "mq.md.structid", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_mq_md_version     , {"Version..", "mq.md.version", FT_UINT32, BASE_DEC, NULL, 0x0, "MD version", HFILL }},
        { &hf_mq_md_report      , {"Report...", "mq.md.report", FT_UINT32, BASE_DEC, NULL, 0x0, "MD report", HFILL }},
        { &hf_mq_md_msgtype     , {"Msg Type.", "mq.md.msgtype", FT_UINT32, BASE_DEC, NULL, 0x0, "MD message type", HFILL }},
        { &hf_mq_md_expiry      , {"Expiry  .", "mq.md.expiry", FT_INT32, BASE_DEC, NULL, 0x0, "MD expiry", HFILL }},
        { &hf_mq_md_feedback    , {"Feedback.", "mq.md.feedback", FT_UINT32, BASE_DEC, NULL, 0x0, "MD feedback", HFILL }},
        { &hf_mq_md_encoding    , {"Encoding.", "mq.md.encoding", FT_UINT32, BASE_DEC, NULL, 0x0, "MD encoding", HFILL }},
        { &hf_mq_md_ccsid       , {"CCSID....", "mq.md.ccsid", FT_INT32, BASE_DEC | BASE_RANGE_STRING, RVALS(&GET_VALRV(ccsid)), 0x0, "MD character set", HFILL }},
        { &hf_mq_md_format      , {"Format...", "mq.md.format", FT_STRINGZ, BASE_NONE, NULL, 0x0, "MD format", HFILL }},
        { &hf_mq_md_priority    , {"Priority.", "mq.md.priority", FT_INT32, BASE_DEC, NULL, 0x0, "MD priority", HFILL }},
        { &hf_mq_md_persistence , {"Persist..", "mq.md.persistence", FT_UINT32, BASE_DEC, NULL, 0x0, "MD persistence", HFILL }},
        { &hf_mq_md_msgid       , {"Msg ID...", "mq.md.msgid", FT_BYTES, BASE_NONE, NULL, 0x0, "MD Message Id", HFILL }},
        { &hf_mq_md_correlid    , {"CorrelID.", "mq.md.correlid", FT_BYTES, BASE_NONE, NULL, 0x0, "MD Correlation Id", HFILL }},
        { &hf_mq_md_backoutcnt  , {"BackoCnt.", "mq.md.backount", FT_UINT32, BASE_DEC, NULL, 0x0, "MD Backout count", HFILL }},
        { &hf_mq_md_replytoq    , {"ReplyToQ.", "mq.md.replytoq", FT_STRINGZ, BASE_NONE, NULL, 0x0, "MD ReplyTo queue", HFILL }},
        { &hf_mq_md_replytoqmgr , {"RepToQMgr", "mq.md.replytoqmgr", FT_STRINGZ, BASE_NONE, NULL, 0x0, "MD ReplyTo queue manager", HFILL }},
        { &hf_mq_md_userid      , {"UserId...", "mq.md.userid", FT_STRINGZ, BASE_NONE, NULL, 0x0, "MD UserId", HFILL }},
        { &hf_mq_md_acttoken    , {"AccntTok.", "mq.md.acttoken", FT_BYTES, BASE_NONE, NULL, 0x0, "MD accounting token", HFILL }},
        { &hf_mq_md_appliddata  , {"AppIdData", "mq.md.appldata", FT_STRINGZ, BASE_NONE, NULL, 0x0, "MD Put applicationId data", HFILL }},
        { &hf_mq_md_putappltype , {"PutAppTyp", "mq.md.appltype", FT_INT32, BASE_DEC, VALS(GET_VALSV(mqat)), 0x0, "MD Put application type", HFILL }},
        { &hf_mq_md_putapplname , {"PutAppNme", "mq.md.applname", FT_STRINGZ, BASE_NONE, NULL, 0x0, "MD Put application name", HFILL }},
        { &hf_mq_md_putdate     , {"PutDatGMT", "mq.md.date", FT_STRINGZ, BASE_NONE, NULL, 0x0, "MD Put date", HFILL }},
        { &hf_mq_md_puttime     , {"PutTimGMT", "mq.md.time", FT_STRINGZ, BASE_NONE, NULL, 0x0, "MD Put time", HFILL }},
        { &hf_mq_md_apporigdata , {"AppOriDat", "mq.md.origdata", FT_STRINGZ, BASE_NONE, NULL, 0x0, "MD Application original data", HFILL }},
        { &hf_mq_md_groupid     , {"GroupId..", "mq.md.groupid", FT_BYTES, BASE_NONE, NULL, 0x0, "MD GroupId", HFILL }},
        { &hf_mq_md_msgseqnumber, {"MsgSeqNum", "mq.md.msgseqnumber", FT_UINT32, BASE_DEC, NULL, 0x0, "MD Message sequence number", HFILL }},
        { &hf_mq_md_offset      , {"Offset...", "mq.md.offset", FT_UINT32, BASE_DEC, NULL, 0x0, "MD Offset", HFILL }},
        { &hf_mq_md_msgflags    , {"Msg flags", "mq.md.msgflags", FT_UINT32, BASE_HEX, NULL, 0x0, "MD Message flags", HFILL }},
        { &hf_mq_md_origlen     , {"Orig len.", "mq.md.origlength", FT_INT32, BASE_DEC, NULL, 0x0, "MD Original length", HFILL }},

        { &hf_mq_dlh_StructID   , {"StructID.", "mq.dlh.structid", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_mq_dlh_version    , {"Version..", "mq.dlh.version", FT_UINT32, BASE_DEC, NULL, 0x0, "DLH version", HFILL }},
        { &hf_mq_dlh_reason     , {"Reason...", "mq.dlh.reason", FT_UINT32, BASE_DEC, NULL, 0x0, "DLH reason", HFILL }},
        { &hf_mq_dlh_destq      , {"Dest Q...", "mq.dlh.destq", FT_STRINGZ, BASE_NONE, NULL, 0x0, "DLH destination queue", HFILL }},
        { &hf_mq_dlh_destqmgr   , {"DestQMgr.", "mq.dlh.destqmgr", FT_STRINGZ, BASE_NONE, NULL, 0x0, "DLH destination queue manager", HFILL }},
        { &hf_mq_dlh_encoding   , {"Encoding.", "mq.dlh.encoding", FT_UINT32, BASE_DEC, NULL, 0x0, "DLH encoding", HFILL }},
        { &hf_mq_dlh_ccsid      , {"CCSID....", "mq.dlh.ccsid", FT_INT32, BASE_DEC | BASE_RANGE_STRING, RVALS(&GET_VALRV(ccsid)), 0x0, "DLH character set", HFILL }},
        { &hf_mq_dlh_format     , {"Format...", "mq.dlh.format", FT_STRINGZ, BASE_NONE, NULL, 0x0, "DLH format", HFILL }},
        { &hf_mq_dlh_putappltype, {"PutAppTyp", "mq.dlh.putappltype", FT_INT32, BASE_DEC, VALS(GET_VALSV(mqat)), 0x0, "DLH put application type", HFILL }},
        { &hf_mq_dlh_putapplname, {"PutAppNme", "mq.dlh.putapplname", FT_STRINGZ, BASE_NONE, NULL, 0x0, "DLH put application name", HFILL }},
        { &hf_mq_dlh_putdate    , {"PutDatGMT", "mq.dlh.putdate", FT_STRINGZ, BASE_NONE, NULL, 0x0, "DLH put date", HFILL }},
        { &hf_mq_dlh_puttime    , {"PutTimGMT", "mq.dlh.puttime", FT_STRINGZ, BASE_NONE, NULL, 0x0, "DLH put time", HFILL }},

        { &hf_mq_gmo_StructID   , {"StructID.", "mq.gmo.structid", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_mq_gmo_version    , {"Version..", "mq.gmo.version", FT_UINT32, BASE_DEC, NULL, 0x0, "GMO version", HFILL }},
        { &hf_mq_gmo_options    , {"GetMsgOpt", "mq.gmo.getmsgopt", FT_UINT32, BASE_HEX, NULL, 0x0, "GMO Get Message Options", HFILL }},

        { &hf_mq_gmo_options_PROPERTIES_COMPATIBILITY, {"PROPERTIES_COMPATIBILITY", "mq.gmo.options.PROPERTIES_COMPATIBILITY", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_PROPERTIES_COMPATIBILITY, "GMO options PROPERTIES_COMPATIBILITY", HFILL }},
        { &hf_mq_gmo_options_PROPERTIES_IN_HANDLE    , {"PROPERTIES_IN_HANDLE", "mq.gmo.options.PROPERTIES_IN_HANDLE", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_PROPERTIES_IN_HANDLE , "GMO options PROPERTIES_IN_HANDLE", HFILL }},
        { &hf_mq_gmo_options_NO_PROPERTIES           , {"NO_PROPERTIES", "mq.gmo.options.NO_PROPERTIES", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_NO_PROPERTIES , "GMO options NO_PROPERTIES", HFILL }},
        { &hf_mq_gmo_options_PROPERTIES_FORCE_MQRFH2 , {"PROPERTIES_FORCE_MQRFH2", "mq.gmo.options.PROPERTIES_FORCE_MQRFH2", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_PROPERTIES_FORCE_MQRFH2 , "GMO options PROPERTIES_FORCE_MQRFH2", HFILL }},
        { &hf_mq_gmo_options_UNMARKED_BROWSE_MSG     , {"UNMARKED_BROWSE_MSG", "mq.gmo.options.UNMARKED_BROWSE_MSG", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_UNMARKED_BROWSE_MSG , "GMO options UNMARKED_BROWSE_MSG", HFILL }},
        { &hf_mq_gmo_options_UNMARK_BROWSE_HANDLE    , {"UNMARK_BROWSE_HANDLE", "mq.gmo.options.UNMARK_BROWSE_HANDLE", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_UNMARK_BROWSE_HANDLE , "GMO options UNMARK_BROWSE_HANDLE", HFILL }},
        { &hf_mq_gmo_options_UNMARK_BROWSE_CO_OP     , {"UNMARK_BROWSE_CO_OP", "mq.gmo.options.UNMARK_BROWSE_CO_OP", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_UNMARK_BROWSE_CO_OP , "GMO options UNMARK_BROWSE_CO_OP", HFILL }},
        { &hf_mq_gmo_options_MARK_BROWSE_CO_OP       , {"MARK_BROWSE_CO_OP", "mq.gmo.options.MARK_BROWSE_CO_OP", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_MARK_BROWSE_CO_OP , "GMO options MARK_BROWSE_CO_OP", HFILL }},
        { &hf_mq_gmo_options_MARK_BROWSE_HANDLE      , {"MARK_BROWSE_HANDLE", "mq.gmo.options.MARK_BROWSE_HANDLE", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_MARK_BROWSE_HANDLE , "GMO options MARK_BROWSE_HANDLE", HFILL }},
        { &hf_mq_gmo_options_ALL_SEGMENTS_AVAILABLE  , {"ALL_SEGMENTS_AVAILABLE", "mq.gmo.options.ALL_SEGMENTS_AVAILABLE", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_ALL_SEGMENTS_AVAILABLE , "GMO options ALL_SEGMENTS_AVAILABLE", HFILL }},
        { &hf_mq_gmo_options_ALL_MSGS_AVAILABLE      , {"ALL_MSGS_AVAILABLE", "mq.gmo.options.ALL_MSGS_AVAILABLE", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_ALL_MSGS_AVAILABLE , "GMO options ALL_MSGS_AVAILABLE", HFILL }},
        { &hf_mq_gmo_options_COMPLETE_MSG            , {"COMPLETE_MSG", "mq.gmo.options.COMPLETE_MSG", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_COMPLETE_MSG , "GMO options COMPLETE_MSG", HFILL }},
        { &hf_mq_gmo_options_LOGICAL_ORDER           , {"LOGICAL_ORDER", "mq.gmo.options.LOGICAL_ORDER", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_LOGICAL_ORDER , "GMO options LOGICAL_ORDER", HFILL }},
        { &hf_mq_gmo_options_CONVERT                 , {"CONVERT", "mq.gmo.options.CONVERT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_CONVERT , "GMO options CONVERT", HFILL }},
        { &hf_mq_gmo_options_FAIL_IF_QUIESCING       , {"FAIL_IF_QUIESCING", "mq.gmo.options.FAIL_IF_QUIESCING", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_FAIL_IF_QUIESCING , "GMO options FAIL_IF_QUIESCING", HFILL }},
        { &hf_mq_gmo_options_SYNCPOINT_IF_PERSISTENT , {"SYNCPOINT_IF_PERSISTENT", "mq.gmo.options.SYNCPOINT_IF_PERSISTENT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_SYNCPOINT_IF_PERSISTENT , "GMO options SYNCPOINT_IF_PERSISTENT", HFILL }},
        { &hf_mq_gmo_options_BROWSE_MSG_UNDER_CURSOR , {"BROWSE_MSG_UNDER_CURSOR", "mq.gmo.options.BROWSE_MSG_UNDER_CURSOR", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_BROWSE_MSG_UNDER_CURSOR , "GMO options BROWSE_MSG_UNDER_CURSOR", HFILL }},
        { &hf_mq_gmo_options_UNLOCK                  , {"UNLOCK", "mq.gmo.options.UNLOCK", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_UNLOCK , "GMO options UNLOCK", HFILL }},
        { &hf_mq_gmo_options_LOCK                    , {"LOCK", "mq.gmo.options.LOCK", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_LOCK , "GMO options LOCK", HFILL }},
        { &hf_mq_gmo_options_MSG_UNDER_CURSOR        , {"MSG_UNDER_CURSOR", "mq.gmo.options.MSG_UNDER_CURSOR", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_MSG_UNDER_CURSOR , "GMO options MSG_UNDER_CURSOR", HFILL }},
        { &hf_mq_gmo_options_MARK_SKIP_BACKOUT       , {"MARK_SKIP_BACKOUT", "mq.gmo.options.MARK_SKIP_BACKOUT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_MARK_SKIP_BACKOUT , "GMO options MARK_SKIP_BACKOUT", HFILL }},
        { &hf_mq_gmo_options_ACCEPT_TRUNCATED_MSG    , {"ACCEPT_TRUNCATED_MSG", "mq.gmo.options.ACCEPT_TRUNCATED_MSG", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_ACCEPT_TRUNCATED_MSG , "GMO options ACCEPT_TRUNCATED_MSG", HFILL }},
        { &hf_mq_gmo_options_BROWSE_NEXT             , {"BROWSE_NEXT", "mq.gmo.options.BROWSE_NEXT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_BROWSE_NEXT , "GMO options BROWSE_NEXT", HFILL }},
        { &hf_mq_gmo_options_BROWSE_FIRST            , {"BROWSE_FIRST", "mq.gmo.options.BROWSE_FIRST", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_BROWSE_FIRST , "GMO options BROWSE_FIRST", HFILL }},
        { &hf_mq_gmo_options_SET_SIGNAL              , {"SET_SIGNAL", "mq.gmo.options.SET_SIGNAL", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_SET_SIGNAL , "GMO options SET_SIGNAL", HFILL }},
        { &hf_mq_gmo_options_NO_SYNCPOINT            , {"NO_SYNCPOINT", "mq.gmo.options.NO_SYNCPOINT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_NO_SYNCPOINT , "GMO options NO_SYNCPOINT", HFILL }},
        { &hf_mq_gmo_options_SYNCPOINT               , {"SYNCPOINT", "mq.gmo.options.SYNCPOINT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_SYNCPOINT , "GMO options SYNCPOINT", HFILL }},
        { &hf_mq_gmo_options_WAIT                    , {"WAIT", "mq.gmo.options.WAIT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQGMO_WAIT , "GMO options WAIT", HFILL }},

        { &hf_mq_gmo_waitinterval, {"WaitIntv.", "mq.gmo.waitint", FT_INT32, BASE_DEC, NULL, 0x0, "GMO wait interval", HFILL }},
        { &hf_mq_gmo_signal1     , {"Signal 1.", "mq.gmo.signal1", FT_UINT32, BASE_HEX, NULL, 0x0, "GMO signal 1", HFILL }},
        { &hf_mq_gmo_signal2     , {"Signal 2.", "mq.gmo.signal2", FT_UINT32, BASE_HEX, NULL, 0x0, "GMO signal 2", HFILL }},
        { &hf_mq_gmo_resolvqname , {"ResQName.", "mq.gmo.resolvq", FT_STRINGZ, BASE_NONE, NULL, 0x0, "GMO resolved queue name", HFILL }},
        { &hf_mq_gmo_matchoptions, {"MatchOpt.", "mq.gmo.matchopt", FT_UINT32, BASE_HEX, NULL, 0x0, "GMO match options", HFILL }},

        { &hf_mq_gmo_matchoptions_MATCH_MSG_TOKEN     , {"MATCH_MSG_TOKEN", "mq.gmo.matchoptions.MATCH_MSG_TOKEN", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQMO_MATCH_MSG_TOKEN , "GMO matchoptions MATCH_MSG_TOKEN", HFILL }},
        { &hf_mq_gmo_matchoptions_MATCH_OFFSET        , {"MATCH_OFFSET", "mq.gmo.matchoptions.MATCH_OFFSET", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQMO_MATCH_OFFSET , "GMO matchoptions MATCH_OFFSET", HFILL }},
        { &hf_mq_gmo_matchoptions_MATCH_MSG_SEQ_NUMBER, {"MATCH_MSG_SEQ_NUMBER", "mq.gmo.matchoptions.MATCH_MSG_SEQ_NUMBER", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQMO_MATCH_MSG_SEQ_NUMBER, "GMO matchoptions MATCH_MSG_SEQ_NUMBER", HFILL }},
        { &hf_mq_gmo_matchoptions_MATCH_GROUP_ID      , {"MATCH_GROUP_ID", "mq.gmo.matchoptions.MATCH_GROUP_ID", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQMO_MATCH_GROUP_ID , "GMO matchoptions MATCH_GROUP_ID", HFILL }},
        { &hf_mq_gmo_matchoptions_MATCH_CORREL_ID     , {"MATCH_CORREL_ID", "mq.gmo.matchoptions.MATCH_CORREL_ID", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQMO_MATCH_CORREL_ID , "GMO matchoptions MATCH_CORREL_ID", HFILL }},
        { &hf_mq_gmo_matchoptions_MATCH_MSG_ID        , {"MATCH_MSG_ID", "mq.gmo.matchoptions.MATCH_MSG_ID", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQMO_MATCH_MSG_ID , "GMO matchoptions MATCH_MSG_ID", HFILL }},

        { &hf_mq_gmo_groupstatus , {"GrpStatus", "mq.gmo.grpstat", FT_UINT8, BASE_HEX, NULL, 0x0, "GMO group status", HFILL }},
        { &hf_mq_gmo_segmstatus  , {"SegStatus", "mq.gmo.sgmtstat", FT_UINT8, BASE_HEX, NULL, 0x0, "GMO segment status", HFILL }},
        { &hf_mq_gmo_segmentation, {"Segmentat", "mq.gmo.segmentation", FT_UINT8, BASE_HEX, NULL, 0x0, "GMO segmentation", HFILL }},
        { &hf_mq_gmo_reserved    , {"Reserved.", "mq.gmo.reserved", FT_UINT8, BASE_HEX, NULL, 0x0, "GMO reserved", HFILL }},
        { &hf_mq_gmo_msgtoken    , {"MsgToken.", "mq.gmo.msgtoken", FT_BYTES, BASE_NONE, NULL, 0x0, "GMO message token", HFILL }},
        { &hf_mq_gmo_returnedlen , {"RtnLength", "mq.gmo.retlen", FT_INT32, BASE_DEC, NULL, 0x0, "GMO returned length", HFILL }},

        { &hf_mq_lpoo_StructID      , {"StructID......", "mq.lpoo.structid", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_mq_lpoo_version       , {"Version.......", "mq.lpoo.version", FT_UINT32, BASE_DEC, NULL, 0x0, "LPOO version", HFILL }},
        { &hf_mq_lpoo_options       , {"Options.......", "mq.lpoo.options", FT_UINT32, BASE_HEX, NULL, 0x0, "LPOO options", HFILL }},
        { &hf_mq_lpoo_lpiopts       , {"LpiOpts.......", "mq.lpoo.lpioopts", FT_UINT32, BASE_HEX, NULL, 0x0, "LPOO Lpi Options", HFILL }},

        { &hf_mq_lpoo_lpiopts_SAVE_USER_CTXT    , {"SAVE_USER_CTXT", "mq.lpoo.opts.SAVE_USER_CTXT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_LPOO_SAVE_USER_CTXT, "LPOO options SAVE_USER_CTXT", HFILL }},
        { &hf_mq_lpoo_lpiopts_SAVE_ORIGIN_CTXT  , {"SAVE_ORIGIN_CTXT", "mq.lpoo.opts.SAVE_ORIGIN_CTXT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_LPOO_SAVE_ORIGIN_CTXT, "LPOO options SAVE_ORIGIN_CTXT", HFILL }},
        { &hf_mq_lpoo_lpiopts_SAVE_IDENTITY_CTXT, {"SAVE_IDENTITY_CTXT", "mq.lpoo.opts.SAVE_IDENTITY_CTXT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_LPOO_SAVE_IDENTITY_CTXT, "LPOO options SAVE_IDENTITY_CTXT", HFILL }},

        { &hf_mq_lpoo_defpersist    , {"DefPersitence.", "mq.lpoo.defpersist", FT_UINT32, BASE_HEX, NULL, 0x0, "LPOO Default Persitence", HFILL }},
        { &hf_mq_lpoo_defputresptype, {"DefPutRespType", "mq.lpoo.defputresptype", FT_UINT32, BASE_HEX, NULL, 0x0, "LPOO Default Put Response Type", HFILL }},
        { &hf_mq_lpoo_defreadahead  , {"DefReadAHead..", "mq.lpoo.defreadahead", FT_UINT32, BASE_HEX, NULL, 0x0, "LPOO Default Read AHead", HFILL }},

        { &hf_mq_lpoo_qprotect      , {"qprotect......", "mq.lpoo.qprotect", FT_STRINGZ, BASE_NONE, NULL, 0x0, "LPOO queue protection", HFILL }},
        { &hf_mq_lpoo_unknown6      , {"Unknown6......", "mq.lpoo.unknown6", FT_UINT32, BASE_HEX, NULL, 0x0, "LPOO unknown6", HFILL }},
        { &hf_mq_lpoo_xtradata      , {"ExtraData.....", "mq.lpoo.extradata", FT_UINT32, BASE_DEC, NULL, 0x0, "LPOO Extra Data", HFILL }},

        { &hf_mq_pmo_StructID    , {"StructID.", "mq.pmo.structid", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_mq_pmo_version     , {"Version..", "mq.pmo.version", FT_UINT32, BASE_DEC, NULL, 0x0, "PMO version", HFILL }},
        { &hf_mq_pmo_options     , {"Options..", "mq.pmo.options", FT_UINT32, BASE_HEX, NULL, 0x0, "PMO options", HFILL }},
        { &hf_mq_pmo_options_NOT_OWN_SUBS            , {"NOT_OWN_SUBS", "mq.pmo.options.NOT_OWN_SUBS", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_NOT_OWN_SUBS , "PMO options NOT_OWN_SUBS", HFILL }},
        { &hf_mq_pmo_options_SUPPRESS_REPLYTO        , {"SUPPRESS_REPLYTO", "mq.pmo.options.SUPPRESS_REPLYTO", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_SUPPRESS_REPLYTO , "PMO options SUPPRESS_REPLYTO", HFILL }},
        { &hf_mq_pmo_options_SCOPE_QMGR              , {"SCOPE_QMGR", "mq.pmo.options.SCOPE_QMGR", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_SCOPE_QMGR , "PMO options SCOPE_QMGR", HFILL }},
        { &hf_mq_pmo_options_MD_FOR_OUTPUT_ONLY      , {"MD_FOR_OUTPUT_ONLY", "mq.pmo.options.MD_FOR_OUTPUT_ONLY", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_MD_FOR_OUTPUT_ONLY , "PMO options MD_FOR_OUTPUT_ONLY", HFILL }},
        { &hf_mq_pmo_options_RETAIN                  , {"RETAIN", "mq.pmo.options.RETAIN", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_RETAIN , "PMO options RETAIN", HFILL }},
        { &hf_mq_pmo_options_WARN_IF_NO_SUBS_MATCHED , {"WARN_IF_NO_SUBS_MATCHED", "mq.pmo.options.WARN_IF_NO_SUBS_MATCHED", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_WARN_IF_NO_SUBS_MATCHED , "PMO options WARN_IF_NO_SUBS_MATCHED", HFILL }},
        { &hf_mq_pmo_options_RESOLVE_LOCAL_Q         , {"RESOLVE_LOCAL_Q", "mq.pmo.options.RESOLVE_LOCAL_Q", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_RESOLVE_LOCAL_Q , "PMO options RESOLVE_LOCAL_Q", HFILL }},
        { &hf_mq_pmo_options_SYNC_RESPONSE           , {"SYNC_RESPONSE", "mq.pmo.options.SYNC_RESPONSE", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_SYNC_RESPONSE , "PMO options SYNC_RESPONSE", HFILL }},
        { &hf_mq_pmo_options_ASYNC_RESPONSE          , {"ASYNC_RESPONSE", "mq.pmo.options.ASYNC_RESPONSE", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_ASYNC_RESPONSE , "PMO options ASYNC_RESPONSE", HFILL }},
        { &hf_mq_pmo_options_LOGICAL_ORDER           , {"LOGICAL_ORDER", "mq.pmo.options.LOGICAL_ORDER", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_LOGICAL_ORDER , "PMO options LOGICAL_ORDER", HFILL }},
        { &hf_mq_pmo_options_NO_CONTEXT              , {"NO_CONTEXT", "mq.pmo.options.NO_CONTEXT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_NO_CONTEXT , "PMO options NO_CONTEXT", HFILL }},
        { &hf_mq_pmo_options_FAIL_IF_QUIESCING       , {"FAIL_IF_QUIESCING", "mq.pmo.options.FAIL_IF_QUIESCING", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_FAIL_IF_QUIESCING , "PMO options FAIL_IF_QUIESCING", HFILL }},
        { &hf_mq_pmo_options_ALTERNATE_USER_AUTHORITY, {"ALTERNATE_USER_AUTHORITY", "mq.pmo.options.ALTERNATE_USER_AUTHORITY", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_ALTERNATE_USER_AUTHORITY , "PMO options ALTERNATE_USER_AUTHORITY", HFILL }},
        { &hf_mq_pmo_options_SET_ALL_CONTEXT         , {"SET_ALL_CONTEXT", "mq.pmo.options.SET_ALL_CONTEXT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_SET_ALL_CONTEXT , "PMO options SET_ALL_CONTEXT", HFILL }},
        { &hf_mq_pmo_options_SET_IDENTITY_CONTEXT    , {"SET_IDENTITY_CONTEXT", "mq.pmo.options.SET_IDENTITY_CONTEXT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_SET_IDENTITY_CONTEXT , "PMO options SET_IDENTITY_CONTEXT", HFILL }},
        { &hf_mq_pmo_options_PASS_ALL_CONTEXT        , {"PASS_ALL_CONTEXT", "mq.pmo.options.PASS_ALL_CONTEXT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_PASS_ALL_CONTEXT , "PMO options PASS_ALL_CONTEXT", HFILL }},
        { &hf_mq_pmo_options_PASS_IDENTITY_CONTEXT   , {"PASS_IDENTITY_CONTEXT", "mq.pmo.options.PASS_IDENTITY_CONTEXT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_PASS_IDENTITY_CONTEXT , "PMO options PASS_IDENTITY_CONTEXT", HFILL }},
        { &hf_mq_pmo_options_NEW_CORREL_ID           , {"NEW_CORREL_ID", "mq.pmo.options.NEW_CORREL_ID", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_NEW_CORREL_ID , "PMO options NEW_CORREL_ID", HFILL }},
        { &hf_mq_pmo_options_NEW_MSG_ID              , {"NEW_MSG_ID", "mq.pmo.options.NEW_MSG_ID", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_NEW_MSG_ID , "PMO options NEW_MSG_ID", HFILL }},
        { &hf_mq_pmo_options_DEFAULT_CONTEXT         , {"DEFAULT_CONTEXT", "mq.pmo.options.DEFAULT_CONTEXT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_DEFAULT_CONTEXT , "PMO options DEFAULT_CONTEXT", HFILL }},
        { &hf_mq_pmo_options_NO_SYNCPOINT            , {"NO_SYNCPOINT", "mq.pmo.options.NO_SYNCPOINT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_NO_SYNCPOINT , "PMO options NO_SYNCPOINT", HFILL }},
        { &hf_mq_pmo_options_SYNCPOINT               , {"SYNCPOINT", "mq.pmo.options.SYNCPOINT", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQPMO_SYNCPOINT , "PMO options SYNCPOINT", HFILL }},

        { &hf_mq_pmo_timeout     , {"Timeout..", "mq.pmo.timeout", FT_INT32, BASE_DEC, NULL, 0x0, "PMO time out", HFILL }},
        { &hf_mq_pmo_context     , {"Context..", "mq.pmo.context", FT_UINT32, BASE_HEX, NULL, 0x0, "PMO context", HFILL }},
        { &hf_mq_pmo_knowndstcnt , {"KnDstCnt.", "mq.pmo.kdstcount", FT_UINT32, BASE_DEC, NULL, 0x0, "PMO known destination count", HFILL }},
        { &hf_mq_pmo_unkndstcnt  , {"UkDstCnt.", "mq.pmo.udestcount", FT_UINT32, BASE_DEC, NULL, 0x0, "PMO unknown destination count", HFILL }},
        { &hf_mq_pmo_invaldstcnt , {"InDstCnt.", "mq.pmo.idestcount", FT_UINT32, BASE_DEC, NULL, 0x0, "PMO invalid destination count", HFILL }},
        { &hf_mq_pmo_resolvqname , {"ResQName.", "mq.pmo.resolvq", FT_STRINGZ, BASE_NONE, NULL, 0x0, "PMO resolved queue name", HFILL }},
        { &hf_mq_pmo_resolvqmgr  , {"ResQMgr..", "mq.pmo.resolvqmgr", FT_STRINGZ, BASE_NONE, NULL, 0x0, "PMO resolved queue manager name", HFILL }},
        { &hf_mq_pmo_recspresent , {"NumRecs..", "mq.pmo.nbrrec", FT_UINT32, BASE_DEC, NULL, 0x0, "PMO number of records", HFILL }},
        { &hf_mq_pmo_putmsgrecfld, {"PMR Flag.", "mq.pmo.flagspmr", FT_UINT32, BASE_HEX, NULL, 0x0, "PMO flags PMR fields", HFILL }},
        { &hf_mq_pmo_putmsgrecofs, {"Ofs1stPMR", "mq.pmo.offsetpmr", FT_UINT32, BASE_DEC, NULL, 0x0, "PMO offset of first PMR", HFILL }},
        { &hf_mq_pmo_resprecofs  , {"Off1stRR.", "mq.pmo.offsetrr", FT_UINT32, BASE_DEC, NULL, 0x0, "PMO offset of first RR", HFILL }},
        { &hf_mq_pmo_putmsgrecptr, {"Adr1stPMR", "mq.pmo.addrrec", FT_UINT32, BASE_HEX, NULL, 0x0, "PMO address of first record", HFILL }},
        { &hf_mq_pmo_resprecptr  , {"Adr1stRR.", "mq.pmo.addrres", FT_UINT32, BASE_HEX, NULL, 0x0, "PMO address of first response record", HFILL }},

        { &hf_mq_xa_length        , {"Length.......", "mq.xa.length", FT_UINT32, BASE_DEC, NULL, 0x0, "XA Length", HFILL }},
        { &hf_mq_xa_returnvalue   , {"Return value.", "mq.xa.returnvalue", FT_INT32, BASE_DEC, VALS(mq_xaer_vals), 0x0, "XA Return Value", HFILL }},
        { &hf_mq_xa_tmflags       , {"TransMgrFlags", "mq.xa.tmflags", FT_UINT32, BASE_HEX, NULL, 0x0, "XA Transaction Manager Flags", HFILL }},
        { &hf_mq_xa_rmid          , {"ResourceMgrID", "mq.xa.rmid", FT_UINT32, BASE_DEC, NULL, 0x0, "XA Resource Manager ID", HFILL }},
        { &hf_mq_xa_count         , {"Number of Xid", "mq.xa.nbxid", FT_UINT32, BASE_DEC, NULL, 0x0, "XA Number of Xid", HFILL }},
        { &hf_mq_xa_tmflags_join      , {"JOIN", "mq.xa.tmflags.join", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_XA_TMJOIN, "XA TM Flags JOIN", HFILL }},
        { &hf_mq_xa_tmflags_endrscan  , {"ENDRSCAN", "mq.xa.tmflags.endrscan", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_XA_TMENDRSCAN, "XA TM Flags ENDRSCAN", HFILL }},
        { &hf_mq_xa_tmflags_startrscan, {"STARTRSCAN", "mq.xa.tmflags.startrscan", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_XA_TMSTARTRSCAN, "XA TM Flags STARTRSCAN", HFILL }},
        { &hf_mq_xa_tmflags_suspend   , {"SUSPEND", "mq.xa.tmflags.suspend", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_XA_TMSUSPEND, "XA TM Flags SUSPEND", HFILL }},
        { &hf_mq_xa_tmflags_success   , {"SUCCESS", "mq.xa.tmflags.success", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_XA_TMSUCCESS, "XA TM Flags SUCCESS", HFILL }},
        { &hf_mq_xa_tmflags_resume    , {"RESUME", "mq.xa.tmflags.resume", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_XA_TMRESUME, "XA TM Flags RESUME", HFILL }},
        { &hf_mq_xa_tmflags_fail      , {"FAIL", "mq.xa.tmflags.fail", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_XA_TMFAIL, "XA TM Flags FAIL", HFILL }},
        { &hf_mq_xa_tmflags_onephase  , {"ONEPHASE", "mq.xa.tmflags.onephase", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_XA_TMONEPHASE, "XA TM Flags ONEPHASE", HFILL }},

        { &hf_mq_xa_xid_formatid  , {"Format ID....", "mq.xa.xid.formatid", FT_INT32, BASE_DEC, NULL, 0x0, "XA Xid Format ID", HFILL }},
        { &hf_mq_xa_xid_glbxid_len, {"GlbTransIDLen", "mq.xa.xid.gxidl", FT_UINT8, BASE_DEC, NULL, 0x0, "XA Xid Global TransactionId Length", HFILL }},
        { &hf_mq_xa_xid_brq_length, {"BranchQualLen", "mq.xa.xid.bql", FT_UINT8, BASE_DEC, NULL, 0x0, "XA Xid Branch Qualifier Length", HFILL }},
        { &hf_mq_xa_xid_globalxid , {"GlbTransactID", "mq.xa.xid.gxid", FT_BYTES, BASE_NONE, NULL, 0x0, "XA Xid Global TransactionId", HFILL }},
        { &hf_mq_xa_xid_brq       , {"BranchQualif.", "mq.xa.xid.bq", FT_BYTES, BASE_NONE, NULL, 0x0, "XA Xid Branch Qualifier", HFILL }},
        { &hf_mq_xa_xainfo_length , {"Length.......", "mq.xa.xainfo.length", FT_UINT8, BASE_DEC, NULL, 0x0, "XA XA_info Length", HFILL }},
        { &hf_mq_xa_xainfo_value  , {"Value........", "mq.xa.xainfo.value", FT_STRINGZ, BASE_NONE, NULL, 0x0, "XA XA_info Value", HFILL }},

        { &hf_mq_charv_vsptr      , {"VLStr Addr.", "mq.charv.vsptr", FT_UINT32, BASE_HEX, NULL, 0x0, "VS Address", HFILL }},
        { &hf_mq_charv_vsoffset   , {"VLStr Offs.", "mq.charv.vsoffset", FT_UINT32, BASE_DEC, NULL, 0x0, "VS Offset", HFILL }},
        { &hf_mq_charv_vsbufsize  , {"VLStr BufSz", "mq.charv.vsbufsize", FT_UINT32, BASE_DEC, NULL, 0x0, "VS BufSize", HFILL }},
        { &hf_mq_charv_vslength   , {"VLStr Len..", "mq.charv.vslength", FT_UINT32, BASE_DEC, NULL, 0x0, "VS Length", HFILL }},
        { &hf_mq_charv_vsccsid    , {"VLStr Ccsid", "mq.charv.vsccsid", FT_INT32, BASE_DEC, NULL, 0x0, "VS CCSID", HFILL }},
        { &hf_mq_charv_vsvalue    , {"VLStr Value", "mq.charv.vsvalue", FT_STRINGZ, BASE_NONE, NULL, 0x0, "VS value", HFILL }},

        { &hf_mq_head_StructID   , {"Structid", "mq.head.structid", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Header structid", HFILL }},
        { &hf_mq_head_version    , {"version.", "mq.head.version", FT_UINT32, BASE_DEC, NULL, 0x0, "Header version", HFILL }},
        { &hf_mq_head_length     , {"Length..", "mq.head.length", FT_UINT32, BASE_DEC, NULL, 0x0, "Header length", HFILL }},
        { &hf_mq_head_encoding   , {"Encoding", "mq.head.encoding", FT_UINT32, BASE_DEC, NULL, 0x0, "Header encoding", HFILL }},
        { &hf_mq_head_ccsid      , {"CCSID...", "mq.head.ccsid", FT_INT32, BASE_DEC | BASE_RANGE_STRING, RVALS(&GET_VALRV(ccsid)), 0x0, "Header character set", HFILL }},
        { &hf_mq_head_format     , {"Format..", "mq.head.format", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Header format", HFILL }},

        { &hf_mq_head_flags      , {"Flags...", "mq.head.flags", FT_UINT32, BASE_HEX, NULL, 0x0, "Header flags", HFILL }},
        { &hf_mq_head_struct     , {"Struct..", "mq.head.struct", FT_BYTES, BASE_NONE, NULL, 0x0, "Header struct", HFILL }},

        { &hf_mq_dh_flags_newmsgid, {"NEW_MSG_IDS", "mq.dh.flags.newmsgid", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQIIH_CM0_REQUEST_RESPONSE, "MQ DH Flags MQDHF_NEW_MSG_IDS", HFILL }},

        { &hf_mq_dh_putmsgrecfld, {"Flags PMR", "mq.dh.flagspmr", FT_UINT32, BASE_DEC, NULL, 0x0, "DH flags PMR", HFILL }},
        { &hf_mq_dh_recspresent , {"NumOfRecs", "mq.dh.nbrrec", FT_UINT32, BASE_DEC, NULL, 0x0, "DH number of records", HFILL }},
        { &hf_mq_dh_objrecofs   , {"Ofs1stOR.", "mq.dh.offsetor", FT_UINT32, BASE_DEC, NULL, 0x0, "DH offset of first OR", HFILL }},
        { &hf_mq_dh_putmsgrecofs, {"Ofs1stPMR", "mq.dh.offsetpmr", FT_UINT32, BASE_DEC, NULL, 0x0, "DH offset of first PMR", HFILL }},

        { &hf_mq_iih_flags_cmqrqstresp , {"CMO_RQST_RESP", "mq.iih.flags.cmqrqstresp" , FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQIIH_CM0_REQUEST_RESPONSE, "MQ IIH Flags CM0_REQUEST_RESPONSE", HFILL }},
        { &hf_mq_iih_flags_ignorepurg  , {"IGNORE_PURG..", "mq.iih.flags.ignorepurg"  , FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQIIH_IGNORE_PURG, "MQ IIH Flags IGNORE_PURG", HFILL }},
        { &hf_mq_iih_flags_replyfmtnone, {"REPL_FMT_NONE", "mq.iih.flags.replyfmtnone", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQIIH_REPLY_FORMAT_NONE, "MQ IIH Flags REPLY_FORMAT_NONE", HFILL }},
        { &hf_mq_iih_flags_passexpir   , {"PASS_EXPIR...", "mq.iih.flags.passexpir"   , FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQIIH_PASS_EXPIRATION, "MQ IIH Flags PASS_EXPIRATION", HFILL }},

        { &hf_mq_iih_ltermoverride, {"LTerm Override", "mq.iih.ltermoverrid" , FT_STRINGZ, BASE_NONE, NULL, 0x0, "Logical Terminal Override", HFILL }},
        { &hf_mq_iih_mfsmapname   , {"MFS Map Name..", "mq.iih.mfsmapname"   , FT_STRINGZ, BASE_NONE, NULL, 0x0, "MFS Map Name", HFILL }},
        { &hf_mq_iih_replytofmt   , {"ReplyToFormat.", "mq.iih.replytofmt"   , FT_STRINGZ, BASE_NONE, NULL, 0x0, "Reply To Format", HFILL }},
        { &hf_mq_iih_authenticator, {"Authenticator.", "mq.iih.authenticator", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Password or Passcode", HFILL }},
        { &hf_mq_iih_transinstid  , {"TransInstIdent", "mq.iih.transinstid"  , FT_BYTES,   BASE_NONE, NULL, 0x0, "Transaction Instance Identifier", HFILL }},
        { &hf_mq_iih_transstate   , {"TransactState.", "mq.iih.transstate"   , FT_STRINGZ, BASE_NONE, NULL, 0x0, "Transaction State", HFILL }},
        { &hf_mq_iih_commimode    , {"Commit Mode...", "mq.iih.commimode"    , FT_STRINGZ, BASE_NONE, NULL, 0x0, "Commit Mode", HFILL }},
        { &hf_mq_iih_securityscope, {"SecurityScope.", "mq.iih.securityscope", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Security Scope", HFILL }},
        { &hf_mq_iih_reserved     , {"Reserved......", "mq.iih.reserved"     , FT_STRINGZ, BASE_NONE, NULL, 0x0, "Reserved", HFILL }},

        { &hf_mq_cih_flags_synconret   , {"SYNC_ON_RETURN", "mq.iih.flags.synconret"   , FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQCIH_SYNC_ON_RETURN, "MQ CIH Flags IGNORE_PURG", HFILL }},
        { &hf_mq_cih_flags_replywonulls, {"REPLY_WO_NULLS", "mq.iih.flags.replywonulls", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQCIH_REPLY_WITHOUT_NULLS, "MQ CIH Flags REPLY_WITHOUT_NULLS", HFILL }},
        { &hf_mq_cih_flags_passexpir   , {"PASS_EXPIR....", "mq.iih.flags.passexpir"   , FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQCIH_PASS_EXPIRATION, "MQ CIH Flags PASS_EXPIRATION", HFILL }},

        { &hf_mq_cih_returncode   , {"ReturnCode...", "mq.cih.returncode"   , FT_UINT32 , BASE_HEX_DEC, NULL, 0x0, "Return Code", HFILL }},
        { &hf_mq_cih_compcode     , {"ComplCode....", "mq.cih.compcode"     , FT_UINT32 , BASE_HEX_DEC, NULL, 0x0, "Completion Code", HFILL }},
        { &hf_mq_cih_reasoncode   , {"ReasonCode...", "mq.cih.reasoncode"   , FT_UINT32 , BASE_HEX_DEC, NULL, 0x0, "Reason Code", HFILL }},
        { &hf_mq_cih_uowcontrols  , {"UOWControls..", "mq.cih.uowcontrols"  , FT_UINT32 , BASE_HEX_DEC, VALS(GET_VALSV(UOWControls)), 0x0, "Unit Of Work Controls", HFILL }},
        { &hf_mq_cih_getwaitintv  , {"GetWaitIntv..", "mq.cih.getwaitintv"  , FT_INT32  , BASE_DEC | BASE_RANGE_STRING, RVALS(&GET_VALRV(WaitIntv)), 0x0, "Get Wait Interval", HFILL }},
        { &hf_mq_cih_linktype     , {"LinkType.....", "mq.cih.linktype"     , FT_UINT32 , BASE_DEC , VALS(GET_VALSV(LinkType)), 0x0, "LinkType", HFILL }},
        { &hf_mq_cih_outdatalen   , {"OutDataLen...", "mq.cih.outdatalen"   , FT_INT32  , BASE_DEC | BASE_RANGE_STRING, RVALS(&GET_VALRV(OutDataLen)), 0x0, "Output Data Len", HFILL }},
        { &hf_mq_cih_facilkeeptime, {"FacilKeepTime", "mq.cih.facilkeeptime", FT_UINT32 , BASE_DEC , NULL, 0x0, "Facility Keep Time", HFILL }},
        { &hf_mq_cih_adsdescriptor, {"ADSDescriptor", "mq.cih.adsdescr"     , FT_UINT32 , BASE_DEC , VALS(GET_VALSV(ADSDescr)), 0x0, "ADS Descriptor", HFILL }},
        { &hf_mq_cih_converstask  , {"ConversTask..", "mq.cih.converstask"  , FT_UINT32 , BASE_DEC , VALS(GET_VALSV(ConvTaskOpt)), 0x0, "Conversational Task", HFILL }},
        { &hf_mq_cih_taskendstatus, {"TaskEndStatus", "mq.cih.taskendstatus", FT_UINT32 , BASE_DEC , VALS(GET_VALSV(TaskEndStatus)), 0x0, "Status at End of Task", HFILL }},
        { &hf_mq_cih_bridgefactokn, {"BridgeFacTokn", "mq.cih.bridgefactokn", FT_BYTES  , BASE_NONE, NULL, 0x0, "Bridge facility token", HFILL }},
        { &hf_mq_cih_function     , {"Function.....", "mq.cih.function"     , FT_STRINGZ, BASE_NONE, NULL, 0x0, "MQ call name or CICS EIBFN function", HFILL }},
        { &hf_mq_cih_abendcode    , {"AbendCode....", "mq.cih.abendcode"    , FT_STRINGZ, BASE_NONE, NULL, 0x0, "Abend Code", HFILL }},
        { &hf_mq_cih_authenticator, {"Authenticator", "mq.cih.authenticator", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Password or Passcode", HFILL }},
        { &hf_mq_cih_reserved     , {"Reserved.....", "mq.cih.reserved"     , FT_STRINGZ, BASE_NONE, NULL, 0x0, "Reserved", HFILL }},
        { &hf_mq_cih_replytofmt   , {"ReplyToFormat", "mq.cih.replytofmt"   , FT_STRINGZ, BASE_NONE, NULL, 0x0, "Reply To Format", HFILL }},
        { &hf_mq_cih_remotesysid  , {"RemoteSysId..", "mq.cih.remotesysid"  , FT_STRINGZ, BASE_NONE, NULL, 0x0, "Remote System Id", HFILL }},
        { &hf_mq_cih_remotetransid, {"RemoteTransId", "mq.cih.remotetransid", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Remote Transaction Id", HFILL }},
        { &hf_mq_cih_transactionid, {"TransactionId", "mq.cih.transactionid", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Transaction to attach", HFILL }},
        { &hf_mq_cih_facilitylike , {"FacilityLike.", "mq.cih.facilitylike" , FT_STRINGZ, BASE_NONE, NULL, 0x0, "Terminal emulated attributes", HFILL }},
        { &hf_mq_cih_attentionid  , {"AttentionID..", "mq.cih.attentionid"  , FT_STRINGZ, BASE_NONE, NULL, 0x0, "Attention Id (AID) Key", HFILL }},
        { &hf_mq_cih_startcode    , {"StartCode....", "mq.cih.startcode"    , FT_STRINGZ, BASE_NONE, NULL, 0x0, "Transaction Start Code", HFILL }},
        { &hf_mq_cih_cancelcode   , {"CancelCode...", "mq.cih.cancelcode"   , FT_STRINGZ, BASE_NONE, NULL, 0x0, "Abend transaction code", HFILL }},
        { &hf_mq_cih_nexttransid  , {"NextTransId..", "mq.cih.nexttransid"  , FT_STRINGZ, BASE_NONE, NULL, 0x0, "Next transaction to attach", HFILL }},
        { &hf_mq_cih_reserved2    , {"Reserved3....", "mq.cih.reserved2"    , FT_STRINGZ, BASE_NONE, NULL, 0x0, "Reserved 2", HFILL }},
        { &hf_mq_cih_reserved3    , {"Reserved3....", "mq.cih.reserved3"    , FT_STRINGZ, BASE_NONE, NULL, 0x0, "Reserved 3", HFILL }},
        { &hf_mq_cih_cursorpos    , {"CursorPos....", "mq.cih.cursorpos"    , FT_UINT32 , BASE_DEC_HEX, NULL, 0x0, "Cursor Posiution", HFILL }},
        { &hf_mq_cih_erroroffset  , {"ErrorOffset..", "mq.cih.erroroffset"  , FT_UINT32 , BASE_DEC_HEX, NULL, 0x0, "Offset of error in message", HFILL }},
        { &hf_mq_cih_inputitem    , {"InputItem....", "mq.cih.inputitem"    , FT_UINT32 , BASE_DEC_HEX, NULL, 0x0, "Input Item", HFILL }},
        { &hf_mq_cih_reserved4    , {"Reserved4....", "mq.cih.reserved4"    , FT_STRINGZ, BASE_NONE, NULL, 0x0, "Reserved 4", HFILL }},

        { &hf_mq_rmh_flags_last   , {"LAST", "mq.rmh.flags.last", FT_BOOLEAN, 32, TFS(&tfs_set_notset), MQ_MQRMHF_LAST, "MQ RMH LAST", HFILL }},

        { &hf_mq_rmh_objecttype   , {"ObjectType...", "mq.rmh.objecttype"   , FT_STRINGZ, BASE_NONE, NULL, 0x0, "Object Type", HFILL }},
        { &hf_mq_rmh_objectinstid , {"ObjectInstId.", "mq.rmh.objectinstid" , FT_BYTES  , BASE_NONE, NULL, 0x0, "Object Instance Identifier", HFILL }},
        { &hf_mq_rmh_srcenvlen    , {"SrcEnvLen....", "mq.rmh.srcenvlen"    , FT_UINT32 , BASE_DEC , NULL, 0x0, "Length of source environment data", HFILL }},
        { &hf_mq_rmh_srcenvofs    , {"SrcEnvOfs....", "mq.rmh.srcenvofs"    , FT_UINT32 , BASE_DEC_HEX, NULL, 0x0, "Offset of source environment data", HFILL }},
        { &hf_mq_rmh_srcnamelen   , {"SrcNameLen...", "mq.rmh.srcnamelen"   , FT_UINT32 , BASE_DEC , NULL, 0x0, "Length of source object name", HFILL }},
        { &hf_mq_rmh_srcnameofs   , {"SrcNameOfs...", "mq.rmh.srcnameofs"   , FT_UINT32 , BASE_DEC_HEX, NULL, 0x0, "Offset of source object name", HFILL }},
        { &hf_mq_rmh_dstenvlen    , {"DstEnvLen....", "mq.rmh.dstenvlen"    , FT_UINT32 , BASE_DEC , NULL, 0x0, "Length of destination environment data", HFILL }},
        { &hf_mq_rmh_dstenvofs    , {"DstEnvOfs....", "mq.rmh.dstenvofs"    , FT_UINT32 , BASE_DEC_HEX, NULL, 0x0, "Offset of destination environment data", HFILL }},
        { &hf_mq_rmh_dstnamelen   , {"DstNameLen...", "mq.rmh.dstnamelen"   , FT_UINT32 , BASE_DEC , NULL, 0x0, "Length of destination object name", HFILL }},
        { &hf_mq_rmh_dstnameofs   , {"DstNameOfs...", "mq.rmh.dstnameofs"   , FT_UINT32 , BASE_DEC  | BASE_HEX, NULL, 0x0, "Offset of destination object name", HFILL }},
        { &hf_mq_rmh_datalogiclen , {"DataLogicLen.", "mq.rmh.datalogiclen" , FT_UINT32 , BASE_DEC , NULL, 0x0, "Length of bulk data", HFILL }},
        { &hf_mq_rmh_datalogicofsl, {"DataLogicOfsL", "mq.rmh.datalogicofsl", FT_UINT32 , BASE_DEC_HEX, NULL, 0x0, "Low offset of bulk data", HFILL }},
        { &hf_mq_rmh_datalogicofsh, {"DataLogicOfsH", "mq.rmh.datalogicofsh", FT_UINT32 , BASE_DEC_HEX, NULL, 0x0, "High offset of bulk data", HFILL }},

        { &hf_mq_wih_servicename  , {"ServiceName..", "mq.wih.servicename"  , FT_STRINGZ, BASE_NONE, NULL, 0x0, "Service Name", HFILL }},
        { &hf_mq_wih_servicestep  , {"ServiceStep..", "mq.wih.servicestep"  , FT_STRINGZ, BASE_NONE, NULL, 0x0, "Service Step Name", HFILL }},
        { &hf_mq_wih_msgtoken     , {"MsgToken.....", "mq.wih.msgtoken"     , FT_BYTES  , BASE_NONE, NULL, 0x0, "Message Token", HFILL }},
        { &hf_mq_wih_reserved     , {"Resereved....", "mq.wih.reserved"     , FT_STRINGZ, BASE_NONE, NULL, 0x0, "Resereved", HFILL }},
    };

    static gint *ett[] =
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
        &ett_mq_id_icf1,
        &ett_mq_id_icf2,
        &ett_mq_id_icf3,
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
        &ett_mq_pmo,
        &ett_mq_pmo_option,
        &ett_mq_fcno,
        &ett_mq_fopa,
        &ett_mq_lpoo,
        &ett_mq_lpoo_options,
        &ett_mq_lpoo_lpiopts,
        &ett_mq_head,
        &ett_mq_head_flags,
        &ett_mq_xa,
        &ett_mq_xa_tmflags,
        &ett_mq_xa_xid,
        &ett_mq_xa_info,
        &ett_mq_charv,
        &ett_mq_reaasemb
    };

    module_t *mq_module;

    proto_mq = proto_register_protocol("WebSphere MQ", "MQ", "mq");
    proto_register_field_array(proto_mq, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_heur_dissector_list("mq", &mq_heur_subdissector_list);
    register_init_routine(mq_init);

    mq_module = prefs_register_protocol(proto_mq, NULL);
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

    mq_tcp_handle = new_create_dissector_handle(dissect_mq_tcp, proto_mq);
    mq_spx_handle = create_dissector_handle(dissect_mq_spx, proto_mq);

    dissector_add_for_decode_as("tcp.port", mq_tcp_handle);
    heur_dissector_add("tcp",     dissect_mq_heur_tcp, proto_mq);
    heur_dissector_add("netbios", dissect_mq_heur_netbios, proto_mq);
    heur_dissector_add("http",    dissect_mq_heur_http, proto_mq);
    dissector_add_uint("spx.socket", MQ_SOCKET_SPX, mq_spx_handle);
    data_handle  = find_dissector("data");
    mqpcf_handle = find_dissector("mqpcf");
}

/*
 * Editor modelines - http://www.wireshark.org/tools/modelines.html
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
