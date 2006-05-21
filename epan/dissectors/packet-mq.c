/* packet-mq.c
 * Routines for IBM WebSphere MQ packet dissection
 *
 * metatech <metatech@flashmail.com>
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

/*  WebSphere MQ in a nutshell
*
*   IBM WebSphere MQ (formerly IBM MQSeries) is an asynchronous proprietary messaging middleware that is based on message queues.
*   MQ can run on more than 35 platforms, amongst which UNIX, Windows and mainframes.
*   MQ can be transported on top of TCP, UDP, HTTP, NetBIOS, SPX, SNA LU 6.2, DECnet.
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
*   MQ API documentation is called "WebSphere MQ Application Programming Reference"
*
*   Possible structures combinations :
*	TSH [ ID ^ UID ^ CONN ^ INQ ^ OD ]
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/conversation.h>
#include <epan/reassemble.h>
#include <epan/prefs.h>
#include "packet-tcp.h"
#include "packet-mq.h"

static int proto_mq = -1;
static int hf_mq_tsh_structid = -1;
static int hf_mq_tsh_packetlength = -1;
static int hf_mq_tsh_byteorder = -1;
static int hf_mq_tsh_opcode = -1;
static int hf_mq_tsh_controlflags = -1;
static int hf_mq_tsh_reserved = -1;
static int hf_mq_tsh_luwid = -1;
static int hf_mq_tsh_encoding = -1;
static int hf_mq_tsh_ccsid = -1;
static int hf_mq_tsh_padding = -1;
static int hf_mq_tsh_tcf_confirmreq = -1;
static int hf_mq_tsh_tcf_error = -1;
static int hf_mq_tsh_tcf_reqclose = -1;
static int hf_mq_tsh_tcf_closechann = -1;
static int hf_mq_tsh_tcf_first = -1;
static int hf_mq_tsh_tcf_last = -1;
static int hf_mq_tsh_tcf_reqacc = -1;
static int hf_mq_tsh_tcf_dlq = -1;
static int hf_mq_api_replylength = -1;
static int hf_mq_api_completioncode = -1;
static int hf_mq_api_reasoncode = -1;
static int hf_mq_api_objecthandle = -1;
static int hf_mq_msh_structid = -1;
static int hf_mq_msh_seqnum = -1;
static int hf_mq_msh_datalength = -1;
static int hf_mq_msh_unknown1 = -1;
static int hf_mq_msh_msglength = -1;
static int hf_mq_xqh_structid = -1;
static int hf_mq_xqh_version = -1;
static int hf_mq_xqh_remoteq = -1;
static int hf_mq_xqh_remoteqmgr = -1;
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
static int hf_mq_id_capflags = -1;
static int hf_mq_id_unknown5 = -1;
static int hf_mq_id_ccsid = -1;
static int hf_mq_id_queuemanager = -1;
static int hf_mq_id_heartbeatinterval = -1;
static int hf_mq_id_unknown6 = -1;
static int hf_mq_id_icf_msgseq = -1;
static int hf_mq_id_icf_convcap = -1;
static int hf_mq_id_icf_splitmsg = -1;
static int hf_mq_id_icf_mqreq = -1;
static int hf_mq_id_icf_svrsec = -1;
static int hf_mq_id_icf_runtime = -1;
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
static int hf_mq_conn_appname = -1;
static int hf_mq_conn_apptype = -1;
static int hf_mq_conn_acttoken = -1;
static int hf_mq_conn_version = -1;
static int hf_mq_conn_options = -1;
static int hf_mq_inq_nbsel = -1;
static int hf_mq_inq_nbint = -1;
static int hf_mq_inq_charlen = -1;
static int hf_mq_inq_sel = -1;
static int hf_mq_inq_intvalue = -1;
static int hf_mq_inq_charvalues = -1;
static int hf_mq_spi_verb = -1;
static int hf_mq_spi_version = -1;
static int hf_mq_spi_length = -1;
static int hf_mq_spi_base_structid = -1;
static int hf_mq_spi_base_version = -1;
static int hf_mq_spi_base_length = -1;
static int hf_mq_spi_spqo_nbverb = -1;
static int hf_mq_spi_spqo_verbid = -1;
static int hf_mq_spi_spqo_maxinoutversion = -1;
static int hf_mq_spi_spqo_maxinversion = -1;
static int hf_mq_spi_spqo_maxoutversion = -1;
static int hf_mq_spi_spqo_flags = -1;
static int hf_mq_spi_spai_mode = -1;
static int hf_mq_spi_spai_unknown1 = -1;
static int hf_mq_spi_spai_unknown2 = -1;
static int hf_mq_spi_spai_msgid = -1;
static int hf_mq_spi_spgi_batchsize = -1;
static int hf_mq_spi_spgi_batchint = -1;
static int hf_mq_spi_spgi_maxmsgsize = -1;
static int hf_mq_spi_spgo_options = -1;
static int hf_mq_spi_spgo_size = -1;
static int hf_mq_spi_options_blank = -1;
static int hf_mq_spi_options_syncpoint = -1;
static int hf_mq_spi_options_deferred = -1;
static int hf_mq_put_length = -1;
static int hf_mq_open_options = -1;
static int hf_mq_ping_length = -1;
static int hf_mq_ping_buffer = -1;
static int hf_mq_reset_length = -1;
static int hf_mq_reset_seqnum = -1;
static int hf_mq_status_length = -1;
static int hf_mq_status_code = -1;
static int hf_mq_status_value = -1;
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
static int hf_mq_or_objname= -1;
static int hf_mq_or_objqmgrname = -1;
static int hf_mq_rr_completioncode = -1;
static int hf_mq_rr_reasoncode = -1;
static int hf_mq_pmr_msgid = -1;
static int hf_mq_pmr_correlid = -1;
static int hf_mq_pmr_groupid = -1;
static int hf_mq_pmr_feedback = -1;
static int hf_mq_pmr_acttoken = -1;
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
static int hf_mq_md_hidden_lastformat = -1;
static int hf_mq_dlh_structid = -1;
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
static int hf_mq_dh_putmsgrecfields = -1;
static int hf_mq_dh_recspresent = -1;
static int hf_mq_dh_objectrecoffset = -1;
static int hf_mq_dh_putmsgrecoffset = -1;
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
static int hf_mq_head_structid = -1;
static int hf_mq_head_version = -1;
static int hf_mq_head_length = -1;
static int hf_mq_head_encoding = -1;
static int hf_mq_head_ccsid = -1;
static int hf_mq_head_format = -1;
static int hf_mq_head_flags = -1;
static int hf_mq_head_struct = -1;
static int hf_mq_xa_length = -1;
static int hf_mq_xa_returnvalue = -1;
static int hf_mq_xa_tmflags = -1;
static int hf_mq_xa_rmid = -1;
static int hf_mq_xa_count = -1;
static int hf_mq_xa_tmflags_join = -1;
static int hf_mq_xa_tmflags_endrscan = -1;
static int hf_mq_xa_tmflags_startrscan = -1;
static int hf_mq_xa_tmflags_suspend = -1;
static int hf_mq_xa_tmflags_success = -1;
static int hf_mq_xa_tmflags_resume = -1;
static int hf_mq_xa_tmflags_fail = -1;
static int hf_mq_xa_tmflags_onephase = -1;
static int hf_mq_xa_xid_formatid = -1;
static int hf_mq_xa_xid_globalxid_length = -1;
static int hf_mq_xa_xid_brq_length = -1;
static int hf_mq_xa_xid_globalxid = -1;
static int hf_mq_xa_xid_brq = -1;
static int hf_mq_xa_xainfo_length = -1;
static int hf_mq_xa_xainfo_value = -1;

static gint ett_mq = -1;
static gint ett_mq_tsh = -1;
static gint ett_mq_tsh_tcf = -1;
static gint ett_mq_api = -1;
static gint ett_mq_msh = -1;
static gint ett_mq_xqh = -1;
static gint ett_mq_id = -1;
static gint ett_mq_id_icf = -1;
static gint ett_mq_id_ief = -1;
static gint ett_mq_uid = -1;
static gint ett_mq_conn = -1;
static gint ett_mq_inq = -1;
static gint ett_mq_spi = -1;
static gint ett_mq_spi_base = -1; /* Factorisation of common SPI items */
static gint ett_mq_spi_options = -1;
static gint ett_mq_put = -1;
static gint ett_mq_open = -1;
static gint ett_mq_ping = -1;
static gint ett_mq_reset = -1;
static gint ett_mq_status = -1;
static gint ett_mq_od = -1;
static gint ett_mq_or = -1;
static gint ett_mq_rr = -1;
static gint ett_mq_pmr = -1;
static gint ett_mq_md = -1;
static gint ett_mq_mde = -1;
static gint ett_mq_dlh = -1;
static gint ett_mq_dh = -1;
static gint ett_mq_gmo = -1;
static gint ett_mq_pmo = -1;
static gint ett_mq_head = -1; /* Factorisation of common Header structure items (DH, MDE, CIH, IIH, RFH, RMH, WIH */
static gint ett_mq_xa = -1;
static gint ett_mq_xa_tmflags = -1;
static gint ett_mq_xa_xid = -1;
static gint ett_mq_xa_info = -1;

static dissector_handle_t mq_tcp_handle;
static dissector_handle_t mq_spx_handle;
static dissector_handle_t data_handle;

static heur_dissector_list_t mq_heur_subdissector_list;

static gboolean mq_desegment = TRUE;
static gboolean mq_reassembly = TRUE;

static GHashTable *mq_fragment_table = NULL;
static GHashTable *mq_reassembled_table = NULL;


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
#define MQ_STRUCTID_TSH           0x54534820
#define MQ_STRUCTID_UID           0x55494420
#define MQ_STRUCTID_WIH           0x57494820
#define MQ_STRUCTID_XQH           0x58514820
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
#define MQ_STRUCTID_TSH_EBCDIC    0xE3E2C840 
#define MQ_STRUCTID_UID_EBCDIC    0xE4C9C440
#define MQ_STRUCTID_WIH_EBCDIC    0xE6C9C840
#define MQ_STRUCTID_XQH_EBCDIC    0xE7D8C840

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

#define MQ_SPI_QUERY              0x01
#define MQ_SPI_PUT                0x02
#define MQ_SPI_GET                0x03
#define MQ_SPI_ACTIVATE           0x04

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

#define MQ_ICF_MSG_SEQ            0x01
#define MQ_ICF_CONVERSION_CAPABLE 0x02
#define MQ_ICF_SPLIT_MESSAGE      0x04
#define MQ_ICF_MQREQUEST          0x20
#define MQ_ICF_SVRCONN_SECURITY   0x40
#define MQ_ICF_RUNTIME            0x80

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

#define MQ_CONN_VERSION        0x01
#define MQ_CONNX_VERSION       0x03

#define MQ_STATUS_E_REMOTE_CHANNEL_NOT_FOUND   0x01 
#define MQ_STATUS_E_BAD_REMOTE_CHANNEL_TYPE    0x02 
#define MQ_STATUS_E_REMOTE_QM_UNAVAILABLE      0x03 
#define MQ_STATUS_E_MSG_SEQUENCE_ERROR         0x04 
#define MQ_STATUS_E_REMOTE_QM_TERMINATING      0x05 
#define MQ_STATUS_E_MSG_NOT_RECEIVED           0x06 
#define MQ_STATUS_I_CHANNEL_CLOSED             0x07 
#define MQ_STATUS_I_DISCINTERVAL_EXPIRED       0x08 
#define MQ_STATUS_E_REMOTE_PROTOCOL_ERROR      0x0A 
#define MQ_STATUS_E_BIND_FAILED                0x14 
#define MQ_STATUS_E_MSGWRAP_DIFFERENT          0x15 
#define MQ_STATUS_E_REMOTE_CHANNEL_UNAVAILABLE 0x16 
#define MQ_STATUS_E_TERMINATED_BY_REMOTE_EXIT  0x17 
#define MQ_STATUS_E_SSL_REMOTE_BAD_CIPHER      0x18 

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
#define MQ_TEXT_TSH   "Transmission Segment Header"
#define MQ_TEXT_API   "API Header"
#define MQ_TEXT_ID    "Initial Data"
#define MQ_TEXT_UID   "User Id Data"
#define MQ_TEXT_MSH   "Message Segment Header"
#define MQ_TEXT_CONN  "MQCONN"
#define MQ_TEXT_INQ   "MQINQ/MQSET"
#define MQ_TEXT_PUT   "MQPUT/MQGET"
#define MQ_TEXT_OPEN  "MQOPEN/MQCLOSE"
#define MQ_TEXT_PING  "PING"
#define MQ_TEXT_RESET "RESET"
#define MQ_TEXT_STAT  "STATUS"
#define MQ_TEXT_SPI   "SPI"
#define MQ_TEXT_XA    "XA"
#define MQ_TEXT_XID   "Xid"
#define MQ_TEXT_XINF  "XA_info"

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


static const value_string mq_opcode_vals[] = {
  { MQ_TST_INITIAL,           "INITIAL_DATA" },
  { MQ_TST_RESYNC,            "RESYNC_DATA" },
  { MQ_TST_RESET,             "RESET_DATA" },
  { MQ_TST_MESSAGE,           "MESSAGE_DATA" },
  { MQ_TST_STATUS,            "STATUS_DATA" },
  { MQ_TST_SECURITY,          "SECURITY_DATA" },
  { MQ_TST_PING,              "PING_DATA" },
  { MQ_TST_USERID,            "USERID_DATA" },
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
  { MQ_TST_SPI,               "SPI" },
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
  { 0,          NULL }
};

static const value_string mq_spi_verbs_vals[] = {
  { MQ_SPI_QUERY,      "QUERY" },
  { MQ_SPI_PUT,        "PUT" },
  { MQ_SPI_GET,        "GET" },
  { MQ_SPI_ACTIVATE,   "ACTIVATE" },
  { 0,          NULL }
};

static const value_string mq_spi_activate_vals[] = {
  { MQ_SPI_ACTIVATE_ENABLE,      "ENABLE" },
  { MQ_SPI_ACTIVATE_DISABLE,     "DISABLE" },
  { 0,          NULL }
};

static const value_string mq_status_vals[] = {
  { MQ_STATUS_E_REMOTE_CHANNEL_NOT_FOUND,    "REMOTE_CHANNEL_NOT_FOUND" },
  { MQ_STATUS_E_BAD_REMOTE_CHANNEL_TYPE,     "BAD_REMOTE_CHANNEL_TYPE" },
  { MQ_STATUS_E_REMOTE_QM_UNAVAILABLE,       "REMOTE_QM_UNAVAILABLE" },
  { MQ_STATUS_E_MSG_SEQUENCE_ERROR,          "MSG_SEQUENCE_ERROR" },
  { MQ_STATUS_E_REMOTE_QM_TERMINATING,       "REMOTE_QM_TERMINATING" },
  { MQ_STATUS_E_MSG_NOT_RECEIVED,            "MSG_NOT_RECEIVED" },
  { MQ_STATUS_I_CHANNEL_CLOSED,              "CHANNEL_CLOSED" },
  { MQ_STATUS_I_DISCINTERVAL_EXPIRED,        "DISCINTERVAL_EXPIRED" },
  { MQ_STATUS_E_REMOTE_PROTOCOL_ERROR,       "REMOTE_PROTOCOL_ERROR" },
  { MQ_STATUS_E_BIND_FAILED,                 "BIND_FAILED" },
  { MQ_STATUS_E_MSGWRAP_DIFFERENT,           "MSGWRAP_DIFFERENT" },
  { MQ_STATUS_E_REMOTE_CHANNEL_UNAVAILABLE,  "REMOTE_CHANNEL_UNAVAILABLE" },
  { MQ_STATUS_E_TERMINATED_BY_REMOTE_EXIT,   "TERMINATED_BY_REMOTE_EXIT" },
  { MQ_STATUS_E_SSL_REMOTE_BAD_CIPHER,       "SSL_REMOTE_BAD_CIPHER" },
  { 0,          NULL }
};

static const value_string mq_xaer_vals[] = {
  { MQ_XA_RBROLLBACK,         "XA_RBROLLBACK" },
  { MQ_XA_RBCOMMFAIL,         "XA_RBCOMMFAIL" },
  { MQ_XA_RBDEADLOCK,         "XA_RBDEADLOCK" },
  { MQ_XA_RBINTEGRITY,        "XA_RBINTEGRITY" },
  { MQ_XA_RBOTHER,            "XA_RBOTHER" },
  { MQ_XA_RBPROTO,            "XA_RBPROTO" },
  { MQ_XA_RBTIMEOUT,          "XA_RBTIMEOUT" },
  { MQ_XA_RBTRANSIENT,        "XA_RBTRANSIENT" },
  { MQ_XA_NOMIGRATE,          "XA_NOMIGRATE" },
  { MQ_XA_HEURHAZ,            "XA_HEURHAZ" },
  { MQ_XA_HEURCOM,            "XA_HEURCOM" },
  { MQ_XA_HEURRB,             "XA_HEURRB" },
  { MQ_XA_HEURMIX,            "XA_HEURMIX" },
  { MQ_XA_RETRY,              "XA_RETRY" },
  { MQ_XA_RDONLY,             "XA_RDONLY" },
  { MQ_XA_OK,                 "XA_OK" },
  { (guint32)MQ_XAER_ASYNC,   "XAER_ASYNC" },
  { (guint32)MQ_XAER_RMERR,   "XAER_RMERR" },
  { (guint32)MQ_XAER_NOTA,    "XAER_NOTA" },
  { (guint32)MQ_XAER_INVAL,   "XAER_INVAL" },
  { (guint32)MQ_XAER_PROTO,   "XAER_PROTO" },
  { (guint32)MQ_XAER_RMFAIL,  "XAER_RMFAIL" },
  { (guint32)MQ_XAER_DUPID,   "XAER_DUPID" },
  { (guint32)MQ_XAER_OUTSIDE, "XAER_OUTSIDE" },
  { 0,          NULL }
};

static const value_string mq_structid_vals[] = {
  { MQ_STRUCTID_CIH,         MQ_TEXT_CIH },
  { MQ_STRUCTID_DH,          MQ_TEXT_DH },
  { MQ_STRUCTID_DLH,         MQ_TEXT_DLH },
  { MQ_STRUCTID_GMO,         MQ_TEXT_GMO },
  { MQ_STRUCTID_ID,          MQ_TEXT_ID },
  { MQ_STRUCTID_IIH,         MQ_TEXT_IIH },
  { MQ_STRUCTID_MD,          MQ_TEXT_MD },
  { MQ_STRUCTID_MDE,         MQ_TEXT_MDE },
  { MQ_STRUCTID_MSH,         MQ_TEXT_MSH },
  { MQ_STRUCTID_OD,          MQ_TEXT_OD },
  { MQ_STRUCTID_PMO,         MQ_TEXT_PMO },
  { MQ_STRUCTID_RMH,         MQ_TEXT_RMH },
  { MQ_STRUCTID_TM,          MQ_TEXT_TM },
  { MQ_STRUCTID_TMC2,        MQ_TEXT_TMC2 },
  { MQ_STRUCTID_TSH,         MQ_TEXT_TSH },
  { MQ_STRUCTID_UID,         MQ_TEXT_UID },
  { MQ_STRUCTID_WIH,         MQ_TEXT_WIH },
  { MQ_STRUCTID_XQH,         MQ_TEXT_XQH },
  { MQ_STRUCTID_CIH_EBCDIC,  MQ_TEXT_CIH },
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
  { MQ_STRUCTID_TM_EBCDIC,   MQ_TEXT_TM },
  { MQ_STRUCTID_TMC2_EBCDIC, MQ_TEXT_TMC2 },
  { MQ_STRUCTID_TSH_EBCDIC,  MQ_TEXT_TSH },
  { MQ_STRUCTID_UID_EBCDIC,  MQ_TEXT_UID },
  { MQ_STRUCTID_WIH_EBCDIC,  MQ_TEXT_WIH },
  { MQ_STRUCTID_XQH_EBCDIC,  MQ_TEXT_XQH },
  { 0,          NULL }
};

static const value_string mq_byteorder_vals[] = {
  { MQ_LITTLE_ENDIAN,  "Little endian" },
  { MQ_BIG_ENDIAN,     "Big endian" },
  { 0,          NULL }
};

static const value_string mq_conn_version_vals[] = {
  { MQ_CONN_VERSION,   "MQCONN" },
  { MQ_CONNX_VERSION,  "MQCONNX" },
  { 0,          NULL }
};

struct mq_msg_properties {
	gint iOffsetEncoding;     /* Message encoding */
	gint iOffsetCcsid;        /* Message character set */
	gint iOffsetFormat;       /* Message format */
};

static guint32 tvb_get_guint32_endian(tvbuff_t *a_tvb, gint a_iOffset, gboolean a_bLittleEndian)
{
	guint32 iResult;
	if (a_bLittleEndian)
		iResult = tvb_get_letohl(a_tvb, a_iOffset);
	else
		iResult =  tvb_get_ntohl(a_tvb, a_iOffset);
	return iResult;
}

/* This routine truncates the string at the first blank space */
static gint strip_trailing_blanks(guint8* a_string, gint a_size)
{
	gint i = 0;
	if (a_string != NULL)
	{
		for (i = 0; i < a_size; i++)
		{
			if (a_string[i] == ' ' || a_string[i] == '\0') 
			{
				a_string[i] = '\0';
				break;
			}
		}
	}
	return i;
}

static gint
dissect_mq_md(tvbuff_t *tvb, proto_tree *tree, gboolean bLittleEndian, gint offset, struct mq_msg_properties* tMsgProps)
{
	proto_tree	*mq_tree = NULL;
	guint32 structId;
	gint iSizeMD = 0;

	if (tvb_length_remaining(tvb, offset) >= 4)
	{
		structId = tvb_get_ntohl(tvb, offset);
		if ((structId == MQ_STRUCTID_MD || structId == MQ_STRUCTID_MD_EBCDIC) && tvb_length_remaining(tvb, offset) >= 8)
		{
			guint32 iVersionMD = 0;
			iVersionMD = tvb_get_guint32_endian(tvb, offset + 4, bLittleEndian);
			/* Compute length according to version */
			switch (iVersionMD) 
			{
				case 1: iSizeMD = 324; break;
				case 2: iSizeMD = 364; break;
			}

			if (iSizeMD != 0 && tvb_length_remaining(tvb, offset) >= iSizeMD)
			{
				tMsgProps->iOffsetEncoding = offset + 24;
				tMsgProps->iOffsetCcsid    = offset + 28;
				tMsgProps->iOffsetFormat   = offset + 32;
				if (tree)
				{
					proto_item	*ti = NULL;
					ti = proto_tree_add_text(tree, tvb, offset, iSizeMD, MQ_TEXT_MD);
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
	
					if (iVersionMD >= 2)
					{
						proto_tree_add_item(mq_tree, hf_mq_md_groupid, tvb, offset + 324, 24, FALSE);
						proto_tree_add_item(mq_tree, hf_mq_md_msgseqnumber, tvb, offset + 348, 4, bLittleEndian);
						proto_tree_add_item(mq_tree, hf_mq_md_offset, tvb, offset + 352, 4, bLittleEndian);
						proto_tree_add_item(mq_tree, hf_mq_md_msgflags, tvb, offset + 356, 4, bLittleEndian);
						proto_tree_add_item(mq_tree, hf_mq_md_originallength, tvb, offset + 360, 4, bLittleEndian);
					}
				}
			}
		}
	}
	return iSizeMD;
}


static gint
dissect_mq_or(tvbuff_t *tvb, proto_tree *tree, gint offset, gint iNbrRecords, gint offsetOR)
{
	proto_tree	*mq_tree = NULL;
	proto_item	*ti = NULL;
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
					ti = proto_tree_add_text(tree, tvb, offset + iOffsetOR, 96, MQ_TEXT_OR);
					mq_tree = proto_item_add_subtree(ti, ett_mq_or);
					proto_tree_add_item(mq_tree, hf_mq_or_objname, tvb, offset + iOffsetOR, 48, FALSE);
					proto_tree_add_item(mq_tree, hf_mq_or_objqmgrname, tvb, offset + iOffsetOR + 48, 48, FALSE);
					iOffsetOR += 96;
				}
			}
		}
		else iSizeOR = 0;
	}
	return iSizeOR;
}

static gint
dissect_mq_rr(tvbuff_t *tvb, proto_tree *tree, gboolean bLittleEndian, gint offset, gint iNbrRecords, gint offsetRR)
{
	proto_tree	*mq_tree = NULL;
	proto_item	*ti = NULL;
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
					ti = proto_tree_add_text(tree, tvb, offset + iOffsetRR, 8, MQ_TEXT_RR);
					mq_tree = proto_item_add_subtree(ti, ett_mq_rr);
					proto_tree_add_item(mq_tree, hf_mq_rr_completioncode, tvb, offset + iOffsetRR, 4, bLittleEndian);
					proto_tree_add_item(mq_tree, hf_mq_rr_reasoncode, tvb, offset + iOffsetRR + 4, 4, bLittleEndian);
					iOffsetRR += 8;
				}
			}
		}
		else iSizeRR = 0;
	}
	return iSizeRR;
}

static gint
dissect_mq_pmr(tvbuff_t *tvb, proto_tree *tree, gboolean bLittleEndian, gint offset, gint iNbrRecords, gint offsetPMR, guint32 recFlags)
{
	proto_tree	*mq_tree = NULL;
	proto_item	*ti = NULL;
	gint iSizePMR1 = 0;
	gint iSizePMR = 0;

	iSizePMR1 =  ((((recFlags & MQ_PMRF_MSG_ID) != 0) * 24)
					+(((recFlags & MQ_PMRF_CORREL_ID) != 0) * 24)
					+(((recFlags & MQ_PMRF_GROUP_ID) != 0) * 24)
					+(((recFlags & MQ_PMRF_FEEDBACK) != 0) * 4)
					+(((recFlags & MQ_PMRF_ACCOUNTING_TOKEN) != 0) * 32));
	if (offsetPMR != 0)
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
					ti = proto_tree_add_text(tree, tvb, offset + iOffsetPMR, iSizePMR1, MQ_TEXT_PMR);
					mq_tree = proto_item_add_subtree(ti, ett_mq_pmr);
					if ((recFlags & MQ_PMRF_MSG_ID) != 0)
					{
						proto_tree_add_item(mq_tree, hf_mq_pmr_msgid, tvb, offset + iOffsetPMR, 24, bLittleEndian);
						iOffsetPMR += 24;
					}
					if ((recFlags & MQ_PMRF_CORREL_ID) != 0)
					{
						proto_tree_add_item(mq_tree, hf_mq_pmr_correlid, tvb, offset + iOffsetPMR, 24, bLittleEndian);
						iOffsetPMR += 24;
					}
					if ((recFlags & MQ_PMRF_GROUP_ID) != 0)
					{
						proto_tree_add_item(mq_tree, hf_mq_pmr_groupid, tvb, offset + iOffsetPMR, 24, bLittleEndian);
						iOffsetPMR += 24;
					}
					if ((recFlags & MQ_PMRF_FEEDBACK) != 0)
					{
						proto_tree_add_item(mq_tree, hf_mq_pmr_feedback, tvb, offset + iOffsetPMR, 4, bLittleEndian);
						iOffsetPMR += 4;
					}
					if ((recFlags & MQ_PMRF_ACCOUNTING_TOKEN) != 0)
					{
						proto_tree_add_item(mq_tree, hf_mq_pmr_acttoken, tvb, offset + iOffsetPMR, 32, bLittleEndian);
						iOffsetPMR += 32;
					}
				}
			}
		}
		else iSizePMR = 0;
	}
	return iSizePMR;
}

static gint
dissect_mq_gmo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean bLittleEndian, gint offset)
{
	proto_tree	*mq_tree = NULL;
	proto_item	*ti = NULL;
	guint32 structId;
	gint iSizeGMO = 0;

	if (tvb_length_remaining(tvb, offset) >= 4)
	{
		structId = tvb_get_ntohl(tvb, offset);
		if ((structId == MQ_STRUCTID_GMO || structId == MQ_STRUCTID_GMO_EBCDIC) && tvb_length_remaining(tvb, offset) >= 8)
		{
			guint32 iVersionGMO = 0;
			iVersionGMO = tvb_get_guint32_endian(tvb, offset + 4, bLittleEndian);
			/* Compute length according to version */
			switch (iVersionGMO) 
			{
				case 1: iSizeGMO = 72; break;
				case 2: iSizeGMO = 80; break;
				case 3: iSizeGMO = 100; break;
			}

			if (iSizeGMO != 0 && tvb_length_remaining(tvb, offset) >= iSizeGMO)
			{
				if (check_col(pinfo->cinfo, COL_INFO)) 
				{
					guint8* sQueue;
					sQueue = tvb_get_ephemeral_string(tvb, offset + 24, 48);
					if (strip_trailing_blanks(sQueue, 48) != 0)
					{
						col_append_fstr(pinfo->cinfo, COL_INFO, " Q=%s", sQueue);
					}
				}
	
				if (tree)
				{
					ti = proto_tree_add_text(tree, tvb, offset, iSizeGMO, MQ_TEXT_GMO);
					mq_tree = proto_item_add_subtree(ti, ett_mq_gmo);
	
					proto_tree_add_item(mq_tree, hf_mq_gmo_structid, tvb, offset, 4, FALSE);
					proto_tree_add_item(mq_tree, hf_mq_gmo_version, tvb, offset + 4, 4, bLittleEndian);
					proto_tree_add_item(mq_tree, hf_mq_gmo_options, tvb, offset + 8, 4, bLittleEndian);
					proto_tree_add_item(mq_tree, hf_mq_gmo_waitinterval, tvb, offset + 12, 4, bLittleEndian);
					proto_tree_add_item(mq_tree, hf_mq_gmo_signal1, tvb, offset + 16, 4, bLittleEndian);
					proto_tree_add_item(mq_tree, hf_mq_gmo_signal2, tvb, offset + 20, 4, bLittleEndian);
					proto_tree_add_item(mq_tree, hf_mq_gmo_resolvedqname, tvb, offset + 24, 48, FALSE);
	
					if (iVersionGMO >= 2)
					{
						proto_tree_add_item(mq_tree, hf_mq_gmo_matchoptions, tvb, offset + 72, 4, FALSE);
						proto_tree_add_item(mq_tree, hf_mq_gmo_groupstatus, tvb, offset + 76, 1, FALSE);
						proto_tree_add_item(mq_tree, hf_mq_gmo_segmentstatus, tvb, offset + 77, 1, FALSE);
						proto_tree_add_item(mq_tree, hf_mq_gmo_segmentation, tvb, offset + 78, 1, FALSE);
						proto_tree_add_item(mq_tree, hf_mq_gmo_reserved, tvb, offset + 79, 1, FALSE);
					}
	
					if (iVersionGMO >= 3)
					{
						proto_tree_add_item(mq_tree, hf_mq_gmo_msgtoken, tvb, offset + 80, 16, FALSE);
						proto_tree_add_item(mq_tree, hf_mq_gmo_returnedlength, tvb, offset + 96, 4, bLittleEndian);
					}
				}
			}
		}
	}
	return iSizeGMO;
}

static gint
dissect_mq_pmo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean bLittleEndian, gint offset, gint* iDistributionListSize)
{
	proto_tree	*mq_tree = NULL;
	proto_item	*ti = NULL;
	guint32 structId;
	gint iSizePMO = 0;

	if (tvb_length_remaining(tvb, offset) >= 4)
	{
		structId = tvb_get_ntohl(tvb, offset);
		if ((structId == MQ_STRUCTID_PMO || structId == MQ_STRUCTID_PMO_EBCDIC) && tvb_length_remaining(tvb, offset) >= 8)
		{
			guint32 iVersionPMO = 0;
			iVersionPMO = tvb_get_guint32_endian(tvb, offset + 4, bLittleEndian);
			/* Compute length according to version */
			switch (iVersionPMO) 
			{
				case 1: iSizePMO = 128; break;
				case 2: iSizePMO = 152;break;
			}

			if (iSizePMO != 0 && tvb_length_remaining(tvb, offset) >= iSizePMO)
			{
				gint iNbrRecords = 0;
				guint32 iRecFlags = 0;
				if (iVersionPMO >= 2)
				{
					iNbrRecords = tvb_get_guint32_endian(tvb, offset + 128, bLittleEndian);
					iRecFlags = tvb_get_guint32_endian(tvb, offset + 132, bLittleEndian);
				}
	
				if (check_col(pinfo->cinfo, COL_INFO)) 
				{
					guint8* sQueue;
					sQueue = tvb_get_ephemeral_string(tvb, offset + 32, 48);
					if (strip_trailing_blanks(sQueue, 48) != 0)
					{
						col_append_fstr(pinfo->cinfo, COL_INFO, " Q=%s", sQueue);
					}
				}
	
				if (tree)
				{
					ti = proto_tree_add_text(tree, tvb, offset, iSizePMO, MQ_TEXT_PMO);
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
	
					if (iVersionPMO >= 2)
					{
						proto_tree_add_item(mq_tree, hf_mq_pmo_recspresent, tvb, offset + 128, 4, bLittleEndian);
						proto_tree_add_item(mq_tree, hf_mq_pmo_putmsgrecfields, tvb, offset + 132, 4, bLittleEndian);
						proto_tree_add_item(mq_tree, hf_mq_pmo_putmsgrecoffset, tvb, offset + 136, 4, bLittleEndian);
						proto_tree_add_item(mq_tree, hf_mq_pmo_responserecoffset, tvb, offset + 140, 4, bLittleEndian);
						proto_tree_add_item(mq_tree, hf_mq_pmo_putmsgrecptr, tvb, offset + 144, 4, bLittleEndian);
						proto_tree_add_item(mq_tree, hf_mq_pmo_responserecptr, tvb, offset + 148, 4, bLittleEndian);
					}
	
				}
				if (iNbrRecords > 0)
				{
					gint iOffsetPMR = 0;
					gint iOffsetRR = 0;
					gint iSizePMRRR = 0;
	
					*iDistributionListSize = iNbrRecords;
					iOffsetPMR = tvb_get_guint32_endian(tvb, offset + 136, bLittleEndian);
					iOffsetRR = tvb_get_guint32_endian(tvb, offset + 140, bLittleEndian);
					if ((iSizePMRRR = dissect_mq_pmr(tvb, tree, bLittleEndian, offset + iSizePMO, iNbrRecords, iOffsetPMR, iRecFlags)) != 0)
						iSizePMO += iSizePMRRR;
					if ((iSizePMRRR = dissect_mq_rr(tvb, tree, bLittleEndian, offset + iSizePMO, iNbrRecords, iOffsetRR)) != 0)
						iSizePMO += iSizePMRRR;
				}
			}
		}
	}
	return iSizePMO;
}

static gint
dissect_mq_xid(tvbuff_t *tvb, proto_tree *tree, gboolean bLittleEndian, gint offset)
{
	proto_tree	*mq_tree = NULL;
	proto_item	*ti = NULL;
	gint iSizeXid = 0;
	if (tvb_length_remaining(tvb, offset) >= 6)
	{
		guint8 iXidLength = 0;
		guint8 iBqLength = 0;
		iXidLength = tvb_get_guint8(tvb, offset + 4);
		iBqLength = tvb_get_guint8(tvb, offset + 5);
		iSizeXid = 6 + iXidLength + iBqLength;
		
		if (tvb_length_remaining(tvb, offset) >= iSizeXid) 
		{
			if (tree)
			{
				ti = proto_tree_add_text(tree, tvb, offset, iSizeXid, MQ_TEXT_XID);
				mq_tree = proto_item_add_subtree(ti, ett_mq_xa_xid);
	
				proto_tree_add_item(mq_tree, hf_mq_xa_xid_formatid, tvb, offset, 4, bLittleEndian);
				proto_tree_add_item(mq_tree, hf_mq_xa_xid_globalxid_length, tvb, offset + 4, 1, FALSE);
				proto_tree_add_item(mq_tree, hf_mq_xa_xid_brq_length, tvb, offset + 5, 1, FALSE);
				proto_tree_add_item(mq_tree, hf_mq_xa_xid_globalxid, tvb, offset + 6, iXidLength, FALSE);
				proto_tree_add_item(mq_tree, hf_mq_xa_xid_brq, tvb, offset + 6 + iXidLength, iBqLength, FALSE);								
			}
			iSizeXid += (4 - (iSizeXid % 4)) % 4; /* Pad for alignment with 4 byte word boundary */
			if (tvb_length_remaining(tvb, offset) < iSizeXid) iSizeXid = 0;
		}
		else iSizeXid = 0;	
	}
	return iSizeXid;
}

static void
dissect_mq_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*mq_tree = NULL;
	proto_tree	*mqroot_tree = NULL;
	proto_item	*ti = NULL;
	gint offset = 0;
	guint32 structId = MQ_STRUCTID_NULL;
	guint8 opcode;
	guint32 iSegmentLength = 0;
	guint32 iSizePayload = 0;
	gint iSizeMD = 0;
	gboolean bLittleEndian = FALSE;
	gboolean bPayload = FALSE;
	gboolean bEBCDIC = FALSE;
	gint iDistributionListSize = 0;
	struct mq_msg_properties tMsgProps;
	static gint iPreviousFrameNumber = -1;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) col_set_str(pinfo->cinfo, COL_PROTOCOL, "MQ");	  
	if (check_col(pinfo->cinfo, COL_INFO))
	{
		/* This is a trick to know whether this is the first PDU in this packet or not */	
		if (iPreviousFrameNumber != (gint) pinfo->fd->num)
			col_clear(pinfo->cinfo, COL_INFO);	  
		else
			col_append_str(pinfo->cinfo, COL_INFO, " | ");
	}
	iPreviousFrameNumber = pinfo->fd->num;
	if (tvb_length(tvb) >= 4)
	{
		structId = tvb_get_ntohl(tvb, offset);
		if ((structId == MQ_STRUCTID_TSH || structId == MQ_STRUCTID_TSH_EBCDIC) && tvb_length_remaining(tvb, offset) >= 28)
		{
			/* An MQ packet always starts with this structure*/
			gint iSizeTSH = 28;
			guint8 iControlFlags = 0;
			if (structId == MQ_STRUCTID_TSH_EBCDIC) bEBCDIC = TRUE;
			opcode = tvb_get_guint8(tvb, offset + 9);
			bLittleEndian = (tvb_get_guint8(tvb, offset + 8) == MQ_LITTLE_ENDIAN ? TRUE : FALSE);
			iSegmentLength = tvb_get_ntohl(tvb, offset + 4);
			iControlFlags = tvb_get_guint8(tvb, offset + 10);

			if (check_col(pinfo->cinfo, COL_INFO)) 
			{
				col_append_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(opcode, mq_opcode_vals, "Unknown (0x%02x)"));
			}

			if (tree)
			{
				ti = proto_tree_add_item(tree, proto_mq, tvb, offset, -1, FALSE);
				proto_item_append_text(ti, " (%s)", val_to_str(opcode, mq_opcode_vals, "Unknown (0x%02x)"));
				if (bEBCDIC == TRUE) proto_item_append_text(ti, " (EBCDIC)");
				mqroot_tree = proto_item_add_subtree(ti, ett_mq);

				ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSizeTSH, MQ_TEXT_TSH);
				mq_tree = proto_item_add_subtree(ti, ett_mq_tsh);

				proto_tree_add_item(mq_tree, hf_mq_tsh_structid, tvb, offset + 0, 4, FALSE);
				proto_tree_add_item(mq_tree, hf_mq_tsh_packetlength, tvb, offset + 4, 4, FALSE);

				proto_tree_add_item(mq_tree, hf_mq_tsh_byteorder, tvb, offset + 8, 1, FALSE);

				proto_tree_add_item(mq_tree, hf_mq_tsh_opcode, tvb, offset + 9, 1, FALSE);

				/* Control flags */
				{
					proto_tree	*mq_tree_sub = NULL;

					ti = proto_tree_add_item(mq_tree, hf_mq_tsh_controlflags, tvb, offset + 10, 1, FALSE);
					mq_tree_sub = proto_item_add_subtree(ti, ett_mq_tsh_tcf);

					proto_tree_add_boolean(mq_tree_sub, hf_mq_tsh_tcf_dlq, tvb, offset + 10, 1, iControlFlags);
					proto_tree_add_boolean(mq_tree_sub, hf_mq_tsh_tcf_reqacc, tvb, offset + 10, 1, iControlFlags);
					proto_tree_add_boolean(mq_tree_sub, hf_mq_tsh_tcf_last, tvb, offset + 10, 1, iControlFlags);
					proto_tree_add_boolean(mq_tree_sub, hf_mq_tsh_tcf_first, tvb, offset + 10, 1, iControlFlags);
					proto_tree_add_boolean(mq_tree_sub, hf_mq_tsh_tcf_closechann, tvb, offset + 10, 1, iControlFlags);
					proto_tree_add_boolean(mq_tree_sub, hf_mq_tsh_tcf_reqclose, tvb, offset + 10, 1, iControlFlags);
					proto_tree_add_boolean(mq_tree_sub, hf_mq_tsh_tcf_error, tvb, offset + 10, 1, iControlFlags);
					proto_tree_add_boolean(mq_tree_sub, hf_mq_tsh_tcf_confirmreq, tvb, offset + 10, 1, iControlFlags);
				}

				proto_tree_add_item(mq_tree, hf_mq_tsh_reserved, tvb, offset + 11, 1, FALSE);
				proto_tree_add_item(mq_tree, hf_mq_tsh_luwid, tvb, offset + 12, 8, FALSE);
				proto_tree_add_item(mq_tree, hf_mq_tsh_encoding, tvb, offset + 20, 4, bLittleEndian);
				proto_tree_add_item(mq_tree, hf_mq_tsh_ccsid, tvb, offset + 24, 2, bLittleEndian);
				proto_tree_add_item(mq_tree, hf_mq_tsh_padding, tvb, offset + 26, 2, FALSE);	
			}
			offset += iSizeTSH;

			/* Now dissect the embedded structures */
			if (tvb_length_remaining(tvb, offset) >= 4) 
			{
				structId = tvb_get_ntohl(tvb, offset);
				if (((iControlFlags & MQ_TCF_FIRST) != 0) || opcode < 0x80)
				{
					/* First MQ segment (opcodes below 0x80 never span several TSH) */
					gint iSizeAPI = 16;
					if (opcode >= 0x80 && opcode <= 0x9F && tvb_length_remaining(tvb, offset) >= 16)
					{
						guint32 iReturnCode = 0;
						iReturnCode = tvb_get_guint32_endian(tvb, offset + 8, bLittleEndian);
						if (check_col(pinfo->cinfo, COL_INFO)) 
						{
							if (iReturnCode != 0)
								col_append_fstr(pinfo->cinfo, COL_INFO, " [RC=%d]", iReturnCode);
						}

						if (tree)
						{
							ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSizeAPI, MQ_TEXT_API);
							mq_tree = proto_item_add_subtree(ti, ett_mq_api);
	
							proto_tree_add_item(mq_tree, hf_mq_api_replylength, tvb, offset, 4, FALSE);
							proto_tree_add_item(mq_tree, hf_mq_api_completioncode, tvb, offset + 4, 4, bLittleEndian);
							proto_tree_add_item(mq_tree, hf_mq_api_reasoncode, tvb, offset + 8, 4, bLittleEndian);
							proto_tree_add_item(mq_tree, hf_mq_api_objecthandle, tvb, offset + 12, 4, bLittleEndian);
						}
						offset += iSizeAPI;
						structId = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
					}
					if ((structId == MQ_STRUCTID_MSH || structId == MQ_STRUCTID_MSH_EBCDIC) && tvb_length_remaining(tvb, offset) >= 20)
					{
						gint iSizeMSH = 20;
						iSizePayload = tvb_get_guint32_endian(tvb, offset + 16, bLittleEndian);
						bPayload = TRUE;
						if (tree)
						{
							ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSizeMSH, MQ_TEXT_MSH);
							mq_tree = proto_item_add_subtree(ti, ett_mq_msh);
	
							proto_tree_add_item(mq_tree, hf_mq_msh_structid, tvb, offset + 0, 4, FALSE);
							proto_tree_add_item(mq_tree, hf_mq_msh_seqnum, tvb, offset + 4, 4, bLittleEndian);
							proto_tree_add_item(mq_tree, hf_mq_msh_datalength, tvb, offset + 8, 4, bLittleEndian);
							proto_tree_add_item(mq_tree, hf_mq_msh_unknown1, tvb, offset + 12, 4, bLittleEndian);
							proto_tree_add_item(mq_tree, hf_mq_msh_msglength, tvb, offset + 16, 4, bLittleEndian);
						}
						offset += iSizeMSH;
					}
					else if (opcode == MQ_TST_STATUS && tvb_length_remaining(tvb, offset) >= 8)
					{
						/* Some status are 28 bytes long and some are 36 bytes long */
						guint32 iStatus = 0;
						gint iStatusLength = 0;
						iStatus = tvb_get_guint32_endian(tvb, offset + 4, bLittleEndian);
						iStatusLength = tvb_get_guint32_endian(tvb, offset, bLittleEndian);

						if (tvb_length_remaining(tvb, offset) >= iStatusLength)
						{
							if (check_col(pinfo->cinfo, COL_INFO)) 
							{
								if (iStatus != 0)
									col_append_fstr(pinfo->cinfo, COL_INFO, ": Code=%s", val_to_str(iStatus, mq_status_vals, "Unknown (0x%08x)"));
							}
							if (tree)
							{
								ti = proto_tree_add_text(mqroot_tree, tvb, offset, 8, MQ_TEXT_STAT);
								mq_tree = proto_item_add_subtree(ti, ett_mq_status);
		
								proto_tree_add_item(mq_tree, hf_mq_status_length, tvb, offset, 4, bLittleEndian);
								proto_tree_add_item(mq_tree, hf_mq_status_code, tvb, offset + 4, 4, bLittleEndian);
								
								if (iStatusLength >= 12)
									proto_tree_add_item(mq_tree, hf_mq_status_value, tvb, offset + 8, 4, bLittleEndian);
							}
							offset += iStatusLength;
						}
					}
					else if (opcode == MQ_TST_PING && tvb_length_remaining(tvb, offset) > 4)
					{
						if (tree)
						{
							ti = proto_tree_add_text(mqroot_tree, tvb, offset, -1, MQ_TEXT_PING);
							mq_tree = proto_item_add_subtree(ti, ett_mq_ping);
	
							proto_tree_add_item(mq_tree, hf_mq_ping_length, tvb, offset, 4, bLittleEndian);
							proto_tree_add_item(mq_tree, hf_mq_ping_buffer, tvb, offset + 4, -1, FALSE);
						}
						offset = tvb_length(tvb);
					}
					else if (opcode == MQ_TST_RESET && tvb_length_remaining(tvb, offset) >= 8)
					{
						if (tree)
						{
							ti = proto_tree_add_text(mqroot_tree, tvb, offset, -1, MQ_TEXT_RESET);
							mq_tree = proto_item_add_subtree(ti, ett_mq_reset);
	
							proto_tree_add_item(mq_tree, hf_mq_reset_length, tvb, offset, 4, bLittleEndian);
							proto_tree_add_item(mq_tree, hf_mq_reset_seqnum, tvb, offset + 4, 4, bLittleEndian);
						}
						offset = tvb_length(tvb);
					}
					else if (opcode == MQ_TST_MQCONN && tvb_length_remaining(tvb, offset) > 0)
					{
						gint iSizeCONN = 0;
						/*iSizeCONN = ((iVersionID == 4 || iVersionID == 6) ? 120 : 112);*/ /* guess */
						/* The iVersionID is available in the previous ID segment, we should keep a state 
						 * Instead we rely on the segment length announced in the TSH */
						/* The MQCONN structure is special because it does not start with a structid */
						iSizeCONN = iSegmentLength - iSizeTSH - iSizeAPI;
						if (iSizeCONN != 112 && iSizeCONN != 120) iSizeCONN = 0;
	
						if (iSizeCONN != 0 && tvb_length_remaining(tvb, offset) >= iSizeCONN)
						{
							if (check_col(pinfo->cinfo, COL_INFO)) 
							{
								guint8* sApplicationName;
								guint8* sQueueManager;
								sApplicationName = tvb_get_ephemeral_string(tvb, offset + 48, 28);
								if (strip_trailing_blanks(sApplicationName, 28) != 0)
								{
									col_append_fstr(pinfo->cinfo, COL_INFO, ": App=%s", sApplicationName);
								}
								sQueueManager = tvb_get_ephemeral_string(tvb, offset, 48);
								if (strip_trailing_blanks(sQueueManager, 48) != 0)
								{
									col_append_fstr(pinfo->cinfo, COL_INFO, " QM=%s", sQueueManager);
								}
							}
		
		
							if (tree)
							{
								ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSizeCONN, MQ_TEXT_CONN);
								mq_tree = proto_item_add_subtree(ti, ett_mq_conn);
		
								proto_tree_add_item(mq_tree, hf_mq_conn_queuemanager, tvb, offset, 48, FALSE);
								proto_tree_add_item(mq_tree, hf_mq_conn_appname, tvb, offset + 48, 28, FALSE);
								proto_tree_add_item(mq_tree, hf_mq_conn_apptype, tvb, offset + 76, 4, bLittleEndian);
								proto_tree_add_item(mq_tree, hf_mq_conn_acttoken, tvb, offset + 80, 32, FALSE);
	
								if (iSizeCONN >= 120)
								{
									proto_tree_add_item(mq_tree, hf_mq_conn_version, tvb, offset + 112, 4, bLittleEndian);
									proto_tree_add_item(mq_tree, hf_mq_conn_options, tvb, offset + 116, 4, bLittleEndian);
								}
							}	
							offset += iSizeCONN;
						}
					}
					else if ((opcode == MQ_TST_MQINQ || opcode == MQ_TST_MQINQ_REPLY || opcode == MQ_TST_MQSET) && tvb_length_remaining(tvb, offset) >= 12)
					{
						/* The MQINQ/MQSET structure is special because it does not start with a structid */
						gint iNbSelectors = 0;
						gint iNbIntegers = 0;
						gint iCharLen = 0;
						gint iOffsetINQ = 0;
						gint iSelector = 0;
	
						iNbSelectors = tvb_get_guint32_endian(tvb, offset, bLittleEndian);
						iNbIntegers = tvb_get_guint32_endian(tvb, offset + 4, bLittleEndian);
						iCharLen = tvb_get_guint32_endian(tvb, offset + 8, bLittleEndian);
	
						if (tree)
						{
							ti = proto_tree_add_text(mqroot_tree, tvb, offset, -1, MQ_TEXT_INQ);
							mq_tree = proto_item_add_subtree(ti, ett_mq_inq);
	
							proto_tree_add_item(mq_tree, hf_mq_inq_nbsel, tvb, offset, 4, bLittleEndian);
							proto_tree_add_item(mq_tree, hf_mq_inq_nbint, tvb, offset + 4, 4, bLittleEndian);
							proto_tree_add_item(mq_tree, hf_mq_inq_charlen, tvb, offset + 8, 4, bLittleEndian);
						}
						iOffsetINQ = 12; 
						if (tvb_length_remaining(tvb, offset + iOffsetINQ) >= iNbSelectors * 4)
						{
							if (tree)
							{
								for (iSelector = 0; iSelector < iNbSelectors; iSelector++)
								{
									proto_tree_add_item(mq_tree, hf_mq_inq_sel, tvb, offset + iOffsetINQ + iSelector * 4, 4, bLittleEndian);
								}
							}
							iOffsetINQ += iNbSelectors * 4;
							if (opcode == MQ_TST_MQINQ_REPLY || opcode == MQ_TST_MQSET)
							{
								gint iSizeINQValues = 0;
								iSizeINQValues = iNbIntegers * 4 + iCharLen;
								if (tvb_length_remaining(tvb, offset + iOffsetINQ) >= iSizeINQValues)
								{
									gint iInteger = 0;
									if (tree)
									{
										for (iInteger = 0; iInteger < iNbIntegers; iInteger++)
										{
											proto_tree_add_item(mq_tree, hf_mq_inq_intvalue, tvb, offset + iOffsetINQ + iInteger * 4, 4, bLittleEndian);
										}
									}
									iOffsetINQ += iNbIntegers * 4;
									if (iCharLen != 0)
									{
										if (tree)
										{
											proto_tree_add_item(mq_tree, hf_mq_inq_charvalues, tvb, offset + iOffsetINQ, iCharLen, FALSE);
										}
									}
								}
							}
						}
						offset += tvb_length(tvb);
					}
					else if ((opcode == MQ_TST_SPI || opcode == MQ_TST_SPI_REPLY) && tvb_length_remaining(tvb, offset) >= 12)
					{
						gint iOffsetSPI = 0;
						guint32 iSpiVerb = 0;
	
						iSpiVerb = tvb_get_guint32_endian(tvb, offset, bLittleEndian);
						if (check_col(pinfo->cinfo, COL_INFO)) 
						{
							col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", val_to_str(iSpiVerb, mq_spi_verbs_vals, "Unknown (0x%08x)"));
						}
	
						if (tree)
						{
							ti = proto_tree_add_text(mqroot_tree, tvb, offset, 12, MQ_TEXT_SPI);
							mq_tree = proto_item_add_subtree(ti, ett_mq_spi);
	
							proto_tree_add_item(mq_tree, hf_mq_spi_verb, tvb, offset, 4, bLittleEndian);
							proto_tree_add_item(mq_tree, hf_mq_spi_version, tvb, offset + 4, 4, bLittleEndian);
							proto_tree_add_item(mq_tree, hf_mq_spi_length, tvb, offset + 8, 4, bLittleEndian);
						}
	
						offset += 12;
						structId = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
						if ((structId == MQ_STRUCTID_SPQU || structId == MQ_STRUCTID_SPAU_EBCDIC
							|| structId == MQ_STRUCTID_SPPU || structId == MQ_STRUCTID_SPPU_EBCDIC
							|| structId == MQ_STRUCTID_SPGU || structId == MQ_STRUCTID_SPGU_EBCDIC
							|| structId == MQ_STRUCTID_SPAU || structId == MQ_STRUCTID_SPAU_EBCDIC)
							&& tvb_length_remaining(tvb, offset) >= 12)
						{
							gint iSizeSPIMD = 0;
							if (tree)
							{
								guint8* sStructId;
								sStructId = tvb_get_ephemeral_string(tvb, offset, 4);
								ti = proto_tree_add_text(mqroot_tree, tvb, offset, 12, (const char*)sStructId);
								mq_tree = proto_item_add_subtree(ti, ett_mq_spi_base);
	
								proto_tree_add_item(mq_tree, hf_mq_spi_base_structid, tvb, offset, 4, FALSE);
								proto_tree_add_item(mq_tree, hf_mq_spi_base_version, tvb, offset + 4, 4, bLittleEndian);
								proto_tree_add_item(mq_tree, hf_mq_spi_base_length, tvb, offset + 8, 4, bLittleEndian);
							}
							offset += 12;
							structId = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
	
							if ((iSizeSPIMD = dissect_mq_md(tvb, mqroot_tree, bLittleEndian, offset, &tMsgProps)) != 0)
							{
								gint iSizeGMO = 0;
								gint iSizePMO = 0;
								offset += iSizeSPIMD;
	
								if ((iSizeGMO = dissect_mq_gmo(tvb, pinfo, mqroot_tree, bLittleEndian, offset)) != 0)
								{
									offset += iSizeGMO;
								}
								else if ((iSizePMO = dissect_mq_pmo(tvb, pinfo, mqroot_tree, bLittleEndian, offset, &iDistributionListSize)) != 0)
								{
									offset += iSizePMO;
								}
								structId = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
							}
	
							if ((structId == MQ_STRUCTID_SPQO || structId == MQ_STRUCTID_SPQO_EBCDIC
								|| structId == MQ_STRUCTID_SPQI || structId == MQ_STRUCTID_SPQI_EBCDIC
								|| structId == MQ_STRUCTID_SPPO || structId == MQ_STRUCTID_SPPO_EBCDIC
								|| structId == MQ_STRUCTID_SPPI || structId == MQ_STRUCTID_SPPI_EBCDIC
								|| structId == MQ_STRUCTID_SPGO || structId == MQ_STRUCTID_SPGO_EBCDIC
								|| structId == MQ_STRUCTID_SPGI || structId == MQ_STRUCTID_SPGI_EBCDIC
								|| structId == MQ_STRUCTID_SPAO || structId == MQ_STRUCTID_SPAO_EBCDIC
								|| structId == MQ_STRUCTID_SPAI || structId == MQ_STRUCTID_SPAI_EBCDIC) 
								&& tvb_length_remaining(tvb, offset) >= 12)
							{
								if (tree)
								{
									/* Dissect the common part of these structures */
									guint8* sStructId;
									sStructId = tvb_get_ephemeral_string(tvb, offset, 4);
									ti = proto_tree_add_text(mqroot_tree, tvb, offset, -1, "%s", (const char*)sStructId);
									mq_tree = proto_item_add_subtree(ti, ett_mq_spi_base);
	
									proto_tree_add_item(mq_tree, hf_mq_spi_base_structid, tvb, offset, 4, FALSE);
									proto_tree_add_item(mq_tree, hf_mq_spi_base_version, tvb, offset + 4, 4, bLittleEndian);
									proto_tree_add_item(mq_tree, hf_mq_spi_base_length, tvb, offset + 8, 4, bLittleEndian);
								}
	
								if (structId == MQ_STRUCTID_SPQO && tvb_length_remaining(tvb, offset) >= 16)
								{
									if (tree)
									{
										gint iVerbNumber = 0;
										proto_tree_add_item(mq_tree, hf_mq_spi_spqo_nbverb, tvb, offset + 12, 4, bLittleEndian);
										iVerbNumber = tvb_get_guint32_endian(tvb, offset + 12, bLittleEndian);
	
										if (tvb_length_remaining(tvb, offset) >= iVerbNumber * 20 + 16)
										{
											gint iVerb = 0;
											iOffsetSPI = offset + 16;									 
											for (iVerb = 0; iVerb < iVerbNumber; iVerb++)
											{
												proto_tree_add_item(mq_tree, hf_mq_spi_spqo_verbid, tvb, iOffsetSPI, 4, bLittleEndian);
												proto_tree_add_item(mq_tree, hf_mq_spi_spqo_maxinoutversion, tvb, iOffsetSPI + 4, 4, bLittleEndian);
												proto_tree_add_item(mq_tree, hf_mq_spi_spqo_maxinversion, tvb, iOffsetSPI + 8, 4, bLittleEndian);
												proto_tree_add_item(mq_tree, hf_mq_spi_spqo_maxoutversion, tvb, iOffsetSPI + 12, 4, bLittleEndian);
												proto_tree_add_item(mq_tree, hf_mq_spi_spqo_flags, tvb, iOffsetSPI + 16, 4, bLittleEndian);
												iOffsetSPI += 20;
											}
											offset += iVerbNumber * 20 + 16;
										}
									}
								}
								else if (structId == MQ_STRUCTID_SPAI && tvb_length_remaining(tvb, offset) >= 136)
								{
									if (tree)
									{
										proto_tree_add_item(mq_tree, hf_mq_spi_spai_mode, tvb, offset + 12, 4, bLittleEndian);
										proto_tree_add_item(mq_tree, hf_mq_spi_spai_unknown1, tvb, offset + 16, 48, bLittleEndian);
										proto_tree_add_item(mq_tree, hf_mq_spi_spai_unknown2, tvb, offset + 64, 48, bLittleEndian);
										proto_tree_add_item(mq_tree, hf_mq_spi_spai_msgid, tvb, offset + 112, 24, bLittleEndian);
									}
									offset += 136;
								}
								else if (structId == MQ_STRUCTID_SPGI && tvb_length_remaining(tvb, offset) >= 24)
								{
									if (tree)
									{
										proto_tree_add_item(mq_tree, hf_mq_spi_spgi_batchsize, tvb, offset + 12, 4, bLittleEndian);
										proto_tree_add_item(mq_tree, hf_mq_spi_spgi_batchint, tvb, offset + 16, 4, bLittleEndian);
										proto_tree_add_item(mq_tree, hf_mq_spi_spgi_maxmsgsize, tvb, offset + 20, 4, bLittleEndian);
									}
									offset += 24;
								}
								else if ((structId == MQ_STRUCTID_SPGO || structId == MQ_STRUCTID_SPPI) && tvb_length_remaining(tvb, offset) >= 20)
								{
									if (tree)
									{
										/* Options flags */
										{
											proto_tree	*mq_tree_sub = NULL;
											gint iOptionsFlags;
	
											ti = proto_tree_add_item(mq_tree, hf_mq_spi_spgo_options, tvb, offset + 12, 4, bLittleEndian);
											mq_tree_sub = proto_item_add_subtree(ti, ett_mq_spi_options);
											iOptionsFlags = tvb_get_guint32_endian(tvb, offset + 12, bLittleEndian);
	
											proto_tree_add_boolean(mq_tree_sub, hf_mq_spi_options_deferred, tvb, offset + 12, 4, iOptionsFlags);
											proto_tree_add_boolean(mq_tree_sub, hf_mq_spi_options_syncpoint, tvb, offset + 12, 4, iOptionsFlags);
											proto_tree_add_boolean(mq_tree_sub, hf_mq_spi_options_blank, tvb, offset + 12, 4, iOptionsFlags);
										}
										proto_tree_add_item(mq_tree, hf_mq_spi_spgo_size, tvb, offset + 16, 4, bLittleEndian);
									}
									iSizePayload = tvb_get_guint32_endian(tvb, offset + 16, bLittleEndian);
									offset += 20;
									bPayload = TRUE;
								}
								else
								{
									offset += 12;
								}
								structId = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
							}
						}
					}
					else if ((opcode >= 0xA0 && opcode <= 0xB9) && tvb_length_remaining(tvb, offset) >= 16)
					{
						/* The XA structures are special because they do not start with a structid */					
						if (tree)
						{
							ti = proto_tree_add_text(mqroot_tree, tvb, offset, 16, "%s (%s)", MQ_TEXT_XA, val_to_str(opcode, mq_opcode_vals, "Unknown (0x%02x)"));
							mq_tree = proto_item_add_subtree(ti, ett_mq_xa);
	
							proto_tree_add_item(mq_tree, hf_mq_xa_length, tvb, offset, 4, FALSE);
							proto_tree_add_item(mq_tree, hf_mq_xa_returnvalue, tvb, offset + 4, 4, bLittleEndian);
	
							/* Transaction Manager flags */
							{
								proto_tree	*mq_tree_sub = NULL;
								guint32 iTMFlags;
			
								ti = proto_tree_add_item(mq_tree, hf_mq_xa_tmflags, tvb, offset + 8, 4, bLittleEndian);
								mq_tree_sub = proto_item_add_subtree(ti, ett_mq_xa_tmflags);
								iTMFlags = tvb_get_guint32_endian(tvb, offset + 8, bLittleEndian);
	
								proto_tree_add_boolean(mq_tree_sub, hf_mq_xa_tmflags_onephase, tvb, offset + 8, 4, iTMFlags);
								proto_tree_add_boolean(mq_tree_sub, hf_mq_xa_tmflags_fail, tvb, offset + 8, 4, iTMFlags);
								proto_tree_add_boolean(mq_tree_sub, hf_mq_xa_tmflags_resume, tvb, offset + 8, 4, iTMFlags);
								proto_tree_add_boolean(mq_tree_sub, hf_mq_xa_tmflags_success, tvb, offset + 8, 4, iTMFlags);
								proto_tree_add_boolean(mq_tree_sub, hf_mq_xa_tmflags_suspend, tvb, offset + 8, 4, iTMFlags);
								proto_tree_add_boolean(mq_tree_sub, hf_mq_xa_tmflags_startrscan, tvb, offset + 8, 4, iTMFlags);
								proto_tree_add_boolean(mq_tree_sub, hf_mq_xa_tmflags_endrscan, tvb, offset + 8, 4, iTMFlags);
								proto_tree_add_boolean(mq_tree_sub, hf_mq_xa_tmflags_join, tvb, offset + 8, 4, iTMFlags);
							}
	
							proto_tree_add_item(mq_tree, hf_mq_xa_rmid, tvb, offset + 12, 4, bLittleEndian);
						}
						offset += 16;
						if (opcode == MQ_TST_XA_START || opcode == MQ_TST_XA_END || opcode == MQ_TST_XA_PREPARE
							|| opcode == MQ_TST_XA_COMMIT || opcode == MQ_TST_XA_ROLLBACK || opcode == MQ_TST_XA_FORGET
							|| opcode == MQ_TST_XA_COMPLETE)
						{
							gint iSizeXid = 0;
							if ((iSizeXid = dissect_mq_xid(tvb, mqroot_tree, bLittleEndian, offset)) != 0)
								offset += iSizeXid;
						}
						else if ((opcode == MQ_TST_XA_OPEN || opcode == MQ_TST_XA_CLOSE)
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
	
									proto_tree_add_item(mq_tree, hf_mq_xa_xainfo_length, tvb, offset, 1, FALSE);
									proto_tree_add_item(mq_tree, hf_mq_xa_xainfo_value, tvb, offset + 1, iXAInfoLength, FALSE);
								}
							}
							offset += 1 + iXAInfoLength;
						}
						else if ((opcode == MQ_TST_XA_RECOVER || opcode == MQ_TST_XA_RECOVER_REPLY)
							&& tvb_length_remaining(tvb, offset) >= 4)
						{
							gint iNbXid = 0;
							iNbXid = tvb_get_guint32_endian(tvb, offset, bLittleEndian);
							if (tree)
							{
								proto_tree_add_item(mq_tree, hf_mq_xa_count, tvb, offset, 4, bLittleEndian);
							}
							offset += 4;
							if (opcode == MQ_TST_XA_RECOVER_REPLY)
							{
								gint iXid = 0;
								for (iXid = 0; iXid < iNbXid; iXid++)
								{
									gint iSizeXid = 0;
									if ((iSizeXid = dissect_mq_xid(tvb, mqroot_tree, bLittleEndian, offset)) != 0)
										offset += iSizeXid;
									else
										break;									
								}
							}
						}
					}
					else if ((structId == MQ_STRUCTID_ID || structId == MQ_STRUCTID_ID_EBCDIC) && tvb_length_remaining(tvb, offset) >= 5)
					{
						guint8 iVersionID = 0;
						gint iSizeID = 0;
						iVersionID = tvb_get_guint8(tvb, offset + 4);
						iSizeID = (iVersionID < 4 ? 44 : 104); /* guess */
						/* actually 102 but must be aligned to multiple of 4 */
	
						if (iSizeID != 0 && tvb_length_remaining(tvb, offset) >= iSizeID)
						{
							if (check_col(pinfo->cinfo, COL_INFO)) 
							{
								guint8* sChannel;
								sChannel = tvb_get_ephemeral_string(tvb, offset + 24, 20);
								if (strip_trailing_blanks(sChannel, 20) != 0)
								{
									col_append_fstr(pinfo->cinfo, COL_INFO, ": CHL=%s", sChannel);
								}
							}
		
							if (tree)
							{
								ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSizeID, MQ_TEXT_ID);
								mq_tree = proto_item_add_subtree(ti, ett_mq_id);
		
								proto_tree_add_item(mq_tree, hf_mq_id_structid, tvb, offset, 4, FALSE);
								proto_tree_add_item(mq_tree, hf_mq_id_level, tvb, offset + 4, 1, FALSE);
		
								/* ID flags */
								{
									proto_tree	*mq_tree_sub = NULL;
									guint8 iIDFlags;
		
									ti = proto_tree_add_item(mq_tree, hf_mq_id_flags, tvb, offset + 5, 1, FALSE);
									mq_tree_sub = proto_item_add_subtree(ti, ett_mq_id_icf);
									iIDFlags = tvb_get_guint8(tvb, offset + 5);
		
									proto_tree_add_boolean(mq_tree_sub, hf_mq_id_icf_runtime, tvb, offset + 5, 1, iIDFlags);
									proto_tree_add_boolean(mq_tree_sub, hf_mq_id_icf_svrsec, tvb, offset + 5, 1, iIDFlags);
									proto_tree_add_boolean(mq_tree_sub, hf_mq_id_icf_mqreq, tvb, offset + 5, 1, iIDFlags);
									proto_tree_add_boolean(mq_tree_sub, hf_mq_id_icf_splitmsg, tvb, offset + 5, 1, iIDFlags);
									proto_tree_add_boolean(mq_tree_sub, hf_mq_id_icf_convcap, tvb, offset + 5, 1, iIDFlags);
									proto_tree_add_boolean(mq_tree_sub, hf_mq_id_icf_msgseq, tvb, offset + 5, 1, iIDFlags);
								}
		
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
		
							if (iVersionID >= 4)
							{
								if (check_col(pinfo->cinfo, COL_INFO)) 
								{
									guint8* sQueueManager;
									sQueueManager = tvb_get_ephemeral_string(tvb, offset + 48, 48);
									if (strip_trailing_blanks(sQueueManager,48) != 0)
									{
										col_append_fstr(pinfo->cinfo, COL_INFO, " QM=%s", sQueueManager);
									}
								}
		
								if (tree)
								{
									proto_tree_add_item(mq_tree, hf_mq_id_capflags, tvb, offset + 44, 1, FALSE);
									proto_tree_add_item(mq_tree, hf_mq_id_unknown5, tvb, offset + 45, 1, FALSE);
									proto_tree_add_item(mq_tree, hf_mq_id_ccsid, tvb, offset + 46, 2, bLittleEndian);
									proto_tree_add_item(mq_tree, hf_mq_id_queuemanager, tvb, offset + 48, 48, FALSE);
									proto_tree_add_item(mq_tree, hf_mq_id_heartbeatinterval, tvb, offset + 96, 4, bLittleEndian);
								}
		
							}
							offset += iSizeID;
						}
					}
					else if ((structId == MQ_STRUCTID_UID || structId == MQ_STRUCTID_UID_EBCDIC) && tvb_length_remaining(tvb, offset) > 0)
					{
						gint iSizeUID = 0;
						/* iSizeUID = (iVersionID < 5 ? 28 : 132);  guess */
						/* The iVersionID is available in the previous ID segment, we should keep a state *
						 * Instead we rely on the segment length announced in the TSH */
						iSizeUID = iSegmentLength - iSizeTSH;
						if (iSizeUID != 28 && iSizeUID != 132) iSizeUID = 0;
	
						if (iSizeUID != 0 && tvb_length_remaining(tvb, offset) >= iSizeUID)
						{
							if (check_col(pinfo->cinfo, COL_INFO)) 
							{
								guint8* sUserId;
								sUserId = tvb_get_ephemeral_string(tvb, offset + 4, 12);
								if (strip_trailing_blanks(sUserId, 12) != 0)
								{
									col_append_fstr(pinfo->cinfo, COL_INFO, ": User=%s", sUserId);
								}
							}
		
							if (tree)
							{
								ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSizeUID, MQ_TEXT_UID);
								mq_tree = proto_item_add_subtree(ti, ett_mq_uid);
		
								proto_tree_add_item(mq_tree, hf_mq_uid_structid, tvb, offset, 4, FALSE);
								proto_tree_add_item(mq_tree, hf_mq_uid_userid, tvb, offset + 4, 12, FALSE);
								proto_tree_add_item(mq_tree, hf_mq_uid_password, tvb, offset + 16, 12, FALSE);
							}
		
							if (iSizeUID == 132)
							{
								if (tree)
								{
									proto_tree_add_item(mq_tree, hf_mq_uid_longuserid, tvb, offset + 28, 64, FALSE);
									proto_tree_add_item(mq_tree, hf_mq_uid_securityid, tvb, offset + 92, 40, FALSE);
								}
							}
							offset += iSizeUID;
						}
					}
					if ((structId == MQ_STRUCTID_OD || structId == MQ_STRUCTID_OD_EBCDIC) && tvb_length_remaining(tvb, offset) >= 8)
					{
						/* The OD struct can be present in several messages at different levels */
						gint iSizeOD = 0;
						guint32 iVersionOD = 0;
						iVersionOD = tvb_get_guint32_endian(tvb, offset + 4, bLittleEndian);
						/* Compute length according to version */
						switch (iVersionOD) 
						{
							case 1: iSizeOD = 168; break;
							case 2: iSizeOD = 200; break;
							case 3: iSizeOD = 336; break;
						}
						
						if (iSizeOD != 0 && tvb_length_remaining(tvb, offset) >= iSizeOD)
						{
							gint iNbrRecords = 0;
							if (iVersionOD >= 2)
								iNbrRecords = tvb_get_guint32_endian(tvb, offset + 168, bLittleEndian);
		
							if (check_col(pinfo->cinfo, COL_INFO)) 
							{
								guint8* sQueue;
								sQueue = tvb_get_ephemeral_string(tvb, offset + 12, 48);
								if (strip_trailing_blanks(sQueue,48) != 0)
								{
									col_append_fstr(pinfo->cinfo, COL_INFO, " Obj=%s", sQueue);
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
		
								if (iVersionOD >= 2)
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
		
								if (iVersionOD >= 3)
								{
									proto_tree_add_item(mq_tree, hf_mq_od_alternatesecurityid, tvb, offset + 200, 40, FALSE);
									proto_tree_add_item(mq_tree, hf_mq_od_resolvedqname, tvb, offset + 240, 48, FALSE);
									proto_tree_add_item(mq_tree, hf_mq_od_resolvedqmgrname, tvb, offset + 288, 48, FALSE);
								}
		
							}
							offset += iSizeOD;
		
							if (iNbrRecords > 0)
							{
								gint iOffsetOR = 0;
								gint iOffsetRR = 0;
								gint iSizeORRR = 0;
		
								iDistributionListSize = iNbrRecords;
								iOffsetOR = tvb_get_guint32_endian(tvb, offset - iSizeOD + 184, bLittleEndian);
								iOffsetRR = tvb_get_guint32_endian(tvb, offset - iSizeOD + 188, bLittleEndian);
								if ((iSizeORRR = dissect_mq_or(tvb, mqroot_tree, offset, iNbrRecords, iOffsetOR)) != 0)
									offset += iSizeORRR;
								if ((iSizeORRR = dissect_mq_rr(tvb, mqroot_tree, bLittleEndian, offset, iNbrRecords, iOffsetRR)) != 0)
									offset += iSizeORRR;
							}
						}
						structId = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
					}
					if ((opcode == MQ_TST_MQOPEN || opcode == MQ_TST_MQCLOSE 
						|| opcode == MQ_TST_MQOPEN_REPLY || opcode == MQ_TST_MQCLOSE_REPLY) 
						&& tvb_length_remaining(tvb, offset) >= 4)
					{
						if (tree)
						{
							ti = proto_tree_add_text(mqroot_tree, tvb, offset, 4, MQ_TEXT_OPEN);
							mq_tree = proto_item_add_subtree(ti, ett_mq_open);
							proto_tree_add_item(mq_tree, hf_mq_open_options, tvb, offset, 4, bLittleEndian);
						}
						offset += 4;
						structId = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
					}
					if ((iSizeMD = dissect_mq_md(tvb, mqroot_tree, bLittleEndian, offset, &tMsgProps)) != 0)
					{
						gint iSizeGMO = 0;
						gint iSizePMO = 0;
						offset += iSizeMD;
	
						if ((iSizeGMO = dissect_mq_gmo(tvb, pinfo, mqroot_tree, bLittleEndian, offset)) != 0)
						{
							offset += iSizeGMO;
							bPayload = TRUE;
						}
						else if ((iSizePMO = dissect_mq_pmo(tvb, pinfo, mqroot_tree, bLittleEndian, offset, &iDistributionListSize)) != 0)
						{
							offset += iSizePMO;
							bPayload = TRUE;
						}
						if (tvb_length_remaining(tvb, offset) >= 4)
						{
							if (bPayload == TRUE)
							{
								iSizePayload = tvb_get_guint32_endian(tvb, offset, bLittleEndian);
								if (tree)
								{
									ti = proto_tree_add_text(mqroot_tree, tvb, offset, 4, MQ_TEXT_PUT);
									mq_tree = proto_item_add_subtree(ti, ett_mq_put);
									proto_tree_add_item(mq_tree, hf_mq_put_length, tvb, offset, 4, bLittleEndian);
								}
								offset += 4;
							}
						}
					}
					if (iDistributionListSize > 0)
					{
						if (check_col(pinfo->cinfo, COL_INFO)) 
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
								gint iSizeMD = 0;
								structId = tvb_get_ntohl(tvb, offset);
	
								if ((structId == MQ_STRUCTID_XQH || structId == MQ_STRUCTID_XQH_EBCDIC) && tvb_length_remaining(tvb, offset) >= 104)
								{
									/* if MD.format == MQXMIT */
									gint iSizeXQH = 104;
									if (tree)
									{
										ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSizeXQH, MQ_TEXT_XQH);
										mq_tree = proto_item_add_subtree(ti, ett_mq_xqh);
	
										proto_tree_add_item(mq_tree, hf_mq_xqh_structid, tvb, offset, 4, FALSE);
										proto_tree_add_item(mq_tree, hf_mq_xqh_version, tvb, offset + 4, 4, bLittleEndian);
										proto_tree_add_item(mq_tree, hf_mq_xqh_remoteq, tvb, offset + 8, 48, FALSE);
										proto_tree_add_item(mq_tree, hf_mq_xqh_remoteqmgr, tvb, offset + 56, 48, FALSE);
									}
									offset += iSizeXQH;
									iHeadersLength += iSizeXQH;
	
									if ((iSizeMD = dissect_mq_md(tvb, mqroot_tree, bLittleEndian, offset, &tMsgProps)) != 0)
									{
										offset += iSizeMD;
										iHeadersLength += iSizeMD;
									}
	
									structId = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
								}
								if ((structId == MQ_STRUCTID_DH || structId == MQ_STRUCTID_DH_EBCDIC) && tvb_length_remaining(tvb, offset) >= 48)
								{
									/* if MD.format == MQHDIST */
									gint iSizeDH = 48;
									gint iNbrRecords = 0;
									guint32 iRecFlags = 0;
	
									iNbrRecords = tvb_get_guint32_endian(tvb, offset + 36, bLittleEndian);
									iRecFlags = tvb_get_guint32_endian(tvb, offset + 32, bLittleEndian);
									tMsgProps.iOffsetEncoding = offset + 12;
									tMsgProps.iOffsetCcsid    = offset + 16;
									tMsgProps.iOffsetFormat   = offset + 20;

									if (tree)
									{
										ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSizeDH, MQ_TEXT_DH);
										mq_tree = proto_item_add_subtree(ti, ett_mq_dh);
	
										proto_tree_add_item(mq_tree, hf_mq_head_structid, tvb, offset, 4, FALSE);
										proto_tree_add_item(mq_tree, hf_mq_head_version, tvb, offset + 4, 4, bLittleEndian);
										proto_tree_add_item(mq_tree, hf_mq_head_length, tvb, offset + 8, 4, bLittleEndian);
										proto_tree_add_item(mq_tree, hf_mq_head_encoding, tvb, offset + 12, 4, bLittleEndian);
										proto_tree_add_item(mq_tree, hf_mq_head_ccsid, tvb, offset + 16, 4, bLittleEndian);
										proto_tree_add_item(mq_tree, hf_mq_head_format, tvb, offset + 20, 8, FALSE);
										proto_tree_add_item(mq_tree, hf_mq_head_flags, tvb, offset + 28, 4, bLittleEndian);
										proto_tree_add_item(mq_tree, hf_mq_dh_putmsgrecfields, tvb, offset + 32, 4, bLittleEndian);
										proto_tree_add_item(mq_tree, hf_mq_dh_recspresent, tvb, offset + 36, 4, bLittleEndian);
										proto_tree_add_item(mq_tree, hf_mq_dh_objectrecoffset , tvb, offset + 40, 4, bLittleEndian);
										proto_tree_add_item(mq_tree, hf_mq_dh_putmsgrecoffset, tvb, offset + 44, 4, bLittleEndian);
									}
									offset += iSizeDH;
									iHeadersLength += iSizeDH;
	
									if (iNbrRecords > 0)
									{
										gint iOffsetOR = 0;
										gint iOffsetPMR = 0;
										gint iSizeORPMR = 0;
	
										iOffsetOR = tvb_get_guint32_endian(tvb, offset - iSizeDH + 40, bLittleEndian);
										iOffsetPMR = tvb_get_guint32_endian(tvb, offset - iSizeDH + 44, bLittleEndian);
										if ((iSizeORPMR = dissect_mq_or(tvb, mqroot_tree, offset, iNbrRecords, iOffsetOR)) != 0)
										{
											offset += iSizeORPMR;
											iHeadersLength += iSizeORPMR;
										}
										if ((iSizeORPMR = dissect_mq_pmr(tvb, mqroot_tree, bLittleEndian, offset, iNbrRecords, iOffsetPMR, iRecFlags)) != 0)
										{
											offset += iSizeORPMR;
											iHeadersLength += iSizeORPMR;
										}
									}
	
									structId = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
								}
								if ((structId == MQ_STRUCTID_DLH || structId == MQ_STRUCTID_DLH_EBCDIC) && tvb_length_remaining(tvb, offset) >= 172)
								{
									/* if MD.format == MQDEAD */
									gint iSizeDLH = 172;
									tMsgProps.iOffsetEncoding = offset + 108;
									tMsgProps.iOffsetCcsid    = offset + 112;
									tMsgProps.iOffsetFormat   = offset + 116;
									if (tree)
									{
										ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSizeDLH, MQ_TEXT_DLH);
										mq_tree = proto_item_add_subtree(ti, ett_mq_dlh);
	
										proto_tree_add_item(mq_tree, hf_mq_dlh_structid, tvb, offset, 4, FALSE);
										proto_tree_add_item(mq_tree, hf_mq_dlh_version, tvb, offset + 4, 4, bLittleEndian);
										proto_tree_add_item(mq_tree, hf_mq_dlh_reason, tvb, offset + 8, 4, bLittleEndian);
										proto_tree_add_item(mq_tree, hf_mq_dlh_destq, tvb, offset + 12, 48, FALSE);
										proto_tree_add_item(mq_tree, hf_mq_dlh_destqmgr, tvb, offset + 60, 48, FALSE);
										proto_tree_add_item(mq_tree, hf_mq_dlh_encoding, tvb, offset + 108, 4, bLittleEndian);
										proto_tree_add_item(mq_tree, hf_mq_dlh_ccsid, tvb, offset + 112, 4, bLittleEndian);
										proto_tree_add_item(mq_tree, hf_mq_dlh_format, tvb, offset + 116, 8, FALSE);
										proto_tree_add_item(mq_tree, hf_mq_dlh_putappltype, tvb, offset + 124, 4, bLittleEndian);
										proto_tree_add_item(mq_tree, hf_mq_dlh_putapplname, tvb, offset + 128, 28, FALSE);
										proto_tree_add_item(mq_tree, hf_mq_dlh_putdate, tvb, offset + 156, 8, FALSE);
										proto_tree_add_item(mq_tree, hf_mq_dlh_puttime, tvb, offset + 164, 8, FALSE);
									}
									offset += iSizeDLH;
									iHeadersLength += iSizeDLH;
									structId = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
								}
								if ((structId == MQ_STRUCTID_MDE || structId == MQ_STRUCTID_MDE_EBCDIC) && tvb_length_remaining(tvb, offset) >= 72)
								{
									/* if MD.format == MQHMDE */
									gint iSizeMDE = 72;
									tMsgProps.iOffsetEncoding = offset + 12;
									tMsgProps.iOffsetCcsid    = offset + 16;
									tMsgProps.iOffsetFormat   = offset + 20;
									if (tree)
									{
										ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSizeMDE, MQ_TEXT_MDE);
										mq_tree = proto_item_add_subtree(ti, ett_mq_mde);
	
										proto_tree_add_item(mq_tree, hf_mq_head_structid, tvb, offset, 4, FALSE);
										proto_tree_add_item(mq_tree, hf_mq_head_version, tvb, offset + 4, 4, bLittleEndian);
										proto_tree_add_item(mq_tree, hf_mq_head_length, tvb, offset + 8, 4, bLittleEndian);
										proto_tree_add_item(mq_tree, hf_mq_head_encoding, tvb, offset + 12, 4, bLittleEndian);
										proto_tree_add_item(mq_tree, hf_mq_head_ccsid, tvb, offset + 16, 4, bLittleEndian);
										proto_tree_add_item(mq_tree, hf_mq_head_format, tvb, offset + 20, 8, FALSE);
										proto_tree_add_item(mq_tree, hf_mq_head_flags, tvb, offset + 28, 4, bLittleEndian);
										proto_tree_add_item(mq_tree, hf_mq_md_groupid, tvb, offset + 32, 24, FALSE);
										proto_tree_add_item(mq_tree, hf_mq_md_msgseqnumber, tvb, offset + 56, 4, bLittleEndian);
										proto_tree_add_item(mq_tree, hf_mq_md_offset, tvb, offset + 60, 4, bLittleEndian);
										proto_tree_add_item(mq_tree, hf_mq_md_msgflags, tvb, offset + 64, 4, bLittleEndian);
										proto_tree_add_item(mq_tree, hf_mq_md_originallength, tvb, offset + 68, 4, bLittleEndian);
									}
									offset += iSizeMDE;
									iHeadersLength += iSizeMDE;
									structId = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
								}
								if ((structId == MQ_STRUCTID_CIH || structId == MQ_STRUCTID_CIH_EBCDIC
									|| structId == MQ_STRUCTID_IIH || structId == MQ_STRUCTID_IIH_EBCDIC
									|| structId == MQ_STRUCTID_RFH || structId == MQ_STRUCTID_RFH_EBCDIC
									|| structId == MQ_STRUCTID_RMH || structId == MQ_STRUCTID_RMH_EBCDIC
									|| structId == MQ_STRUCTID_WIH || structId == MQ_STRUCTID_WIH_EBCDIC)
								 		&& tvb_length_remaining(tvb, offset) >= 12)
								{
									/* Dissect the generic part of the other pre-defined headers */
									/* We assume that only one such header is present */
									gint iSizeHeader = 0;
									iSizeHeader = tvb_get_guint32_endian(tvb, offset + 8, bLittleEndian);
	
								 	if (tvb_length_remaining(tvb, offset) >= iSizeHeader)
								 	{
										tMsgProps.iOffsetEncoding = offset + 12;
										tMsgProps.iOffsetCcsid    = offset + 16;
										tMsgProps.iOffsetFormat   = offset + 20;
								 		if (tree)
										{
											ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSizeHeader, val_to_str(structId, mq_structid_vals, "Unknown (0x%08x)"));
											mq_tree = proto_item_add_subtree(ti, ett_mq_head);
	
											proto_tree_add_item(mq_tree, hf_mq_head_structid, tvb, offset, 4, FALSE);
											proto_tree_add_item(mq_tree, hf_mq_head_version, tvb, offset + 4, 4, bLittleEndian);
											proto_tree_add_item(mq_tree, hf_mq_head_length, tvb, offset + 8, 4, bLittleEndian);
											proto_tree_add_item(mq_tree, hf_mq_head_encoding, tvb, offset + 12, 4, bLittleEndian);
											proto_tree_add_item(mq_tree, hf_mq_head_ccsid, tvb, offset + 16, 4, bLittleEndian);
											proto_tree_add_item(mq_tree, hf_mq_head_format, tvb, offset + 20, 8, FALSE);
											proto_tree_add_item(mq_tree, hf_mq_head_flags, tvb, offset + 28, 4, bLittleEndian);
											proto_tree_add_item(mq_tree, hf_mq_head_struct, tvb, offset + 32, iSizeHeader - 32, bLittleEndian);
	
										}
										offset += iSizeHeader;
										iHeadersLength += iSizeHeader;
										structId = (tvb_length_remaining(tvb, offset) >= 4) ? tvb_get_ntohl(tvb, offset) : MQ_STRUCTID_NULL;
									}
								}
							}
	
							if (tMsgProps.iOffsetFormat != 0)
							{
									guint8* sFormat = NULL;
									sFormat = tvb_get_ephemeral_string(tvb, tMsgProps.iOffsetFormat, 8);
									if (strip_trailing_blanks(sFormat, 8) == 0)	sFormat = (guint8*)g_strdup("MQNONE");
									if (check_col(pinfo->cinfo, COL_INFO)) 
									{
										col_append_fstr(pinfo->cinfo, COL_INFO, " Fmt=%s", sFormat);
									}
									if (tree)
									{
										proto_tree_add_string_hidden(tree, hf_mq_md_hidden_lastformat, tvb, tMsgProps.iOffsetFormat, 8, (const char*)sFormat);
									}
							}
							if (check_col(pinfo->cinfo, COL_INFO)) 
							{
								col_append_fstr(pinfo->cinfo, COL_INFO, " (%d bytes)", iSizePayload - iHeadersLength);
							}
	
							{
								/* Call subdissector for the payload */
								tvbuff_t* next_tvb = NULL;
								struct mqinfo mqinfo;
								/* Format, encoding and character set are "data type" information, not subprotocol information */
								mqinfo.encoding = tvb_get_guint32_endian(tvb, tMsgProps.iOffsetEncoding, bLittleEndian);
								mqinfo.ccsid    = tvb_get_guint32_endian(tvb, tMsgProps.iOffsetCcsid, bLittleEndian);
								tvb_memcpy(tvb, mqinfo.format, tMsgProps.iOffsetFormat, 8);
								pinfo->private_data = &mqinfo;
								next_tvb = tvb_new_subset(tvb, offset, -1, -1);
								if (!dissector_try_heuristic(mq_heur_subdissector_list, next_tvb, pinfo, tree))
									call_dissector(data_handle, next_tvb, pinfo, tree);
							}
						}
						offset = tvb_length(tvb);
					}
					/* After all recognised structures have been dissected, process remaining structure*/
					if (tvb_length_remaining(tvb, offset) >= 4)
					{
						structId = tvb_get_ntohl(tvb, offset);
						if (tree)
						{
							proto_tree_add_text(mqroot_tree, tvb, offset, -1, val_to_str(structId, mq_structid_vals, "Unknown (0x%08x)"));
						}
					}
				}
				else
				{
					/* This is a MQ segment continuation (if MQ reassembly is not enabled) */
					if (check_col(pinfo->cinfo, COL_INFO)) col_append_str(pinfo->cinfo, COL_INFO, " [Unreassembled MQ]");
					call_dissector(data_handle, tvb_new_subset(tvb, offset, -1, -1), pinfo, tree);
				}
			}
		}
		else
		{
			/* This packet is a TCP continuation of a segment (if desegmentation is not enabled) */
			if (check_col(pinfo->cinfo, COL_INFO)) col_append_str(pinfo->cinfo, COL_INFO, " [Undesegmented]");
			if (tree)
			{
				proto_tree_add_item(tree, proto_mq, tvb, offset, -1, FALSE);
			}
			call_dissector(data_handle, tvb_new_subset(tvb, offset, -1, -1), pinfo, tree);
		}
	}
}


static void
reassemble_mq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	/* Reassembly of the MQ messages that span several PDU (several TSH) */
	/* Typically a TCP PDU is 1460 bytes and a MQ PDU is 32766 bytes */
	if (tvb_length(tvb) >= 28)
	{
		guint32 structId;
		structId = tvb_get_ntohl(tvb, 0);

		if (structId == MQ_STRUCTID_TSH || structId == MQ_STRUCTID_TSH_EBCDIC) 
		{
			guint8 iControlFlags = 0;
			guint32 iSegmentLength = 0;
			guint32 iBeginLength = 0;
			guint8 opcode;
			gboolean bFirstSegment; 
			gboolean bLastSegment;
			opcode = tvb_get_guint8(tvb, 9);
			iControlFlags = tvb_get_guint8(tvb, 10);
			iSegmentLength = tvb_get_ntohl(tvb, 4);
			bFirstSegment = ((iControlFlags & MQ_TCF_FIRST) != 0);
			bLastSegment = ((iControlFlags & MQ_TCF_LAST) != 0);

			if (opcode > 0x80 && !(bFirstSegment && bLastSegment)) 
			{
				/* Optimisation : only fragmented segments go through the reassembly process */
				if (mq_reassembly)
				{
					tvbuff_t* next_tvb;
					fragment_data* fd_head;
					guint32 iConnectionId = (pinfo->srcport + pinfo->destport);
					if (opcode > 0x80 && !bFirstSegment) iBeginLength = 28;
					fd_head = fragment_add_seq_next(tvb, iBeginLength, pinfo, iConnectionId, mq_fragment_table, mq_reassembled_table, iSegmentLength - iBeginLength, !bLastSegment);
					if (fd_head != NULL && pinfo->fd->num == fd_head->reassembled_in) 
					{
						/* Reassembly finished */
						if (fd_head->next != NULL) 
						{
							/* 2 or more fragments */
							next_tvb = tvb_new_real_data(fd_head->data, fd_head->len, fd_head->len);
							tvb_set_child_real_data_tvbuff(tvb, next_tvb);
							add_new_data_source(pinfo, next_tvb, "Reassembled MQ");
						}
						else
						{
							/* Only 1 fragment */
							next_tvb = tvb;
						}
						dissect_mq_pdu(next_tvb, pinfo, tree);
						return;
					}
					else
					{
						/* Reassembly in progress */
						if (check_col(pinfo->cinfo, COL_PROTOCOL)) col_set_str(pinfo->cinfo, COL_PROTOCOL, "MQ");	  
						if (check_col(pinfo->cinfo, COL_INFO)) col_add_fstr(pinfo->cinfo, COL_INFO, "%s [Reassembled MQ]", val_to_str(opcode, mq_opcode_vals, "Unknown (0x%02x)"));
						if (tree)
						{
							proto_item* ti = NULL;
							ti = proto_tree_add_item(tree, proto_mq, tvb, 0, -1, FALSE);
							proto_item_append_text(ti, " (%s) [Reassembled MQ]", val_to_str(opcode, mq_opcode_vals, "Unknown (0x%02x)"));
						}
						return;
					}				
				}
				else
				{
					dissect_mq_pdu(tvb, pinfo, tree);
					if (bFirstSegment)
					{
						/* MQ segment is the first of a unreassembled series */
						if (check_col(pinfo->cinfo, COL_INFO)) col_append_str(pinfo->cinfo, COL_INFO, " [Unreassembled MQ]");
					}
					return;					
				}
			}
			/* Reassembly not enabled or non-fragmented message */
			dissect_mq_pdu(tvb, pinfo, tree);
			return;
		}
	}
}

static guint
get_mq_pdu_len(tvbuff_t *tvb, int offset)
{
	if (tvb_length_remaining(tvb, offset) >= 8)
	{
		if ((tvb_get_ntohl(tvb, 0) == MQ_STRUCTID_TSH || tvb_get_ntohl(tvb, 0) == MQ_STRUCTID_TSH_EBCDIC)) 
			return tvb_get_ntohl(tvb, offset + 4);
	}
	return 0;
}

static void
dissect_mq_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tcp_dissect_pdus(tvb, pinfo, tree, mq_desegment, 28, get_mq_pdu_len, reassemble_mq);
}

static void
dissect_mq_spx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	/* Since SPX has no standard desegmentation, MQ cannot be performed as well */
	dissect_mq_pdu(tvb, pinfo, tree);
}

static gboolean
dissect_mq_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint iProto)
{
	if (tvb_length(tvb) >= 28)
	{
		guint32 structId;
		guint8 cEndian;
		structId = tvb_get_ntohl(tvb, 0);
		cEndian = tvb_get_guint8(tvb, 8);

		if ((structId == MQ_STRUCTID_TSH || structId == MQ_STRUCTID_TSH_EBCDIC) 
			&& (cEndian == MQ_LITTLE_ENDIAN || cEndian == MQ_BIG_ENDIAN))
		{
			/* Register this dissector for this conversation */
			conversation_t  *conversation = NULL;
			conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
			if (conversation == NULL) 
			{
				conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
			}
			if (iProto == MQ_XPT_TCP) conversation_set_dissector(conversation, mq_tcp_handle); 

			/* Dissect the packet */
			reassemble_mq(tvb, pinfo, tree);
			return TRUE;
		}
	}
	return FALSE;
}

static gboolean
dissect_mq_heur_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	return dissect_mq_heur(tvb, pinfo, tree, MQ_XPT_TCP);
}

static gboolean
dissect_mq_heur_netbios(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	return dissect_mq_heur(tvb, pinfo, tree, MQ_XPT_NETBIOS);
}

static gboolean
dissect_mq_heur_http(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	return dissect_mq_heur(tvb, pinfo, tree, MQ_XPT_HTTP);
}

static void
mq_init(void)
{
	fragment_table_init(&mq_fragment_table);
	reassembled_table_init(&mq_reassembled_table);
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

    { &hf_mq_tsh_reserved,
      { "Reserved", "mq.tsh.reserved", FT_UINT8, BASE_HEX, NULL, 0x0, "TSH Reserved", HFILL }},
      
    { &hf_mq_tsh_luwid,
      { "Logical unit of work identifier", "mq.tsh.luwid", FT_BYTES, BASE_HEX, NULL, 0x0, "TSH logical unit of work identifier", HFILL }},
      
    { &hf_mq_tsh_encoding,
      { "Encoding", "mq.tsh.encoding", FT_UINT32, BASE_DEC, NULL, 0x0, "TSH Encoding", HFILL }},

    { &hf_mq_tsh_ccsid,
      { "Character set", "mq.tsh.ccsid", FT_UINT16, BASE_DEC, NULL, 0x0, "TSH CCSID", HFILL }},
      
    { &hf_mq_tsh_padding,
      { "Padding", "mq.tsh.padding", FT_UINT16, BASE_HEX, NULL, 0x0, "TSH Padding", HFILL }},

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

    { &hf_mq_tsh_tcf_reqacc,
      { "Request accepted", "mq.tsh.tcf.reqacc", FT_BOOLEAN, 8, TFS(&flags_set_truth), MQ_TCF_REQUEST_ACCEPTED, "TSH TCF Request accepted", HFILL }},

    { &hf_mq_tsh_tcf_dlq,
      { "DLQ used", "mq.tsh.tcf.dlq", FT_BOOLEAN, 8, TFS(&flags_set_truth), MQ_TCF_DLQ_USED, "TSH TCF DLQ used", HFILL }},

    { &hf_mq_api_replylength,
      { "Reply length", "mq.api.replylength", FT_UINT32, BASE_DEC, NULL, 0x0, "API Reply length", HFILL }},

    { &hf_mq_api_completioncode,
      { "Completion code", "mq.api.completioncode", FT_UINT32, BASE_DEC, NULL, 0x0, "API Completion code", HFILL }},

    { &hf_mq_api_reasoncode,
      { "Reason code", "mq.api.reasoncode", FT_UINT32, BASE_DEC, NULL, 0x0, "API Reason code", HFILL }},

    { &hf_mq_api_objecthandle,
      { "Object handle", "mq.api.hobj", FT_UINT32, BASE_HEX, NULL, 0x0, "API Object handle", HFILL }},

    { &hf_mq_id_icf_msgseq,
      { "Message sequence", "mq.id.icf.msgseq", FT_BOOLEAN, 8, TFS(&flags_set_truth), MQ_ICF_MSG_SEQ, "ID ICF Message sequence", HFILL }},

    { &hf_mq_id_icf_convcap,
      { "Conversion capable", "mq.id.icf.convcap", FT_BOOLEAN, 8, TFS(&flags_set_truth), MQ_ICF_CONVERSION_CAPABLE, "ID ICF Conversion capable", HFILL }},

    { &hf_mq_id_icf_splitmsg,
      { "Split messages", "mq.id.icf.splitmsg", FT_BOOLEAN, 8, TFS(&flags_set_truth), MQ_ICF_SPLIT_MESSAGE, "ID ICF Split message", HFILL }},

    { &hf_mq_id_icf_mqreq,
      { "MQ request", "mq.id.icf.mqreq", FT_BOOLEAN, 8, TFS(&flags_set_truth), MQ_ICF_MQREQUEST, "ID ICF MQ request", HFILL }},

    { &hf_mq_id_icf_svrsec,
      { "Server connection security", "mq.id.icf.svrsec", FT_BOOLEAN, 8, TFS(&flags_set_truth), MQ_ICF_SVRCONN_SECURITY, "ID ICF Server connection security", HFILL }},

    { &hf_mq_id_icf_runtime,
      { "Runtime application", "mq.id.icf.runtime", FT_BOOLEAN, 8, TFS(&flags_set_truth), MQ_ICF_RUNTIME, "ID ICF Runtime application", HFILL }},

    { &hf_mq_msh_structid,
      { "MSH structid", "mq.msh.structid", FT_STRINGZ, BASE_DEC, NULL, 0x0, "MSH structid", HFILL }},

    { &hf_mq_msh_seqnum,
      { "Sequence number", "mq.msh.seqnum", FT_UINT32, BASE_DEC, NULL, 0x0, "MSH sequence number", HFILL }},

    { &hf_mq_msh_datalength,
      { "Buffer length", "mq.msh.buflength", FT_UINT32, BASE_DEC, NULL, 0x0, "MSH buffer length", HFILL }},

    { &hf_mq_msh_unknown1,
      { "Unknown1", "mq.msh.unknown1", FT_UINT32, BASE_HEX, NULL, 0x0, "MSH unknown1", HFILL }},

    { &hf_mq_msh_msglength,
      { "Message length", "mq.msh.msglength", FT_UINT32, BASE_DEC, NULL, 0x0, "MSH message length", HFILL }},

    { &hf_mq_xqh_structid,
      { "XQH structid", "mq.xqh.structid", FT_STRINGZ, BASE_DEC, NULL, 0x0, "XQH structid", HFILL }},

    { &hf_mq_xqh_version,
      { "Version", "mq.xqh.version", FT_UINT32, BASE_DEC, NULL, 0x0, "XQH version", HFILL }},

    { &hf_mq_xqh_remoteq,
      { "Remote queue", "mq.xqh.remoteq", FT_STRINGZ, BASE_DEC, NULL, 0x0, "XQH remote queue", HFILL }},

    { &hf_mq_xqh_remoteqmgr,
      { "Remote queue manager", "mq.xqh.remoteqmgr", FT_STRINGZ, BASE_DEC, NULL, 0x0, "XQH remote queue manager", HFILL }},

    { &hf_mq_id_structid,
      { "ID structid", "mq.id.structid", FT_STRINGZ, BASE_DEC, NULL, 0x0, "ID structid", HFILL }},

    { &hf_mq_id_level,
      { "FAP level", "mq.id.level", FT_UINT8, BASE_DEC, NULL, 0x0, "ID Formats And Protocols level", HFILL }},

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
      { "Sequence wrap value", "mq.id.seqwrap", FT_UINT32, BASE_DEC, NULL, 0x0, "ID seq wrap value", HFILL }},

    { &hf_mq_id_channel,
      { "Channel name", "mq.id.channelname", FT_STRINGZ, BASE_HEX, NULL, 0x0, "ID channel name", HFILL }},

    { &hf_mq_id_capflags,
      { "Capability flags", "mq.id.capflags", FT_UINT8, BASE_HEX, NULL, 0x0, "ID Capability flags", HFILL }},

    { &hf_mq_id_unknown5,
      { "Unknown5", "mq.id.unknown5", FT_UINT8, BASE_HEX, NULL, 0x0, "ID unknown5", HFILL }},

    { &hf_mq_id_ccsid,
      { "Character set", "mq.id.ccsid", FT_UINT16, BASE_DEC, NULL, 0x0, "ID character set", HFILL }},

    { &hf_mq_id_queuemanager,
      { "Queue manager", "mq.id.qm", FT_STRINGZ, BASE_HEX, NULL, 0x0, "ID Queue manager", HFILL }},

    { &hf_mq_id_heartbeatinterval,
      { "Heartbeat interval", "mq.id.hbint", FT_UINT32, BASE_DEC, NULL, 0x0, "ID Heartbeat interval", HFILL }},

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

    { &hf_mq_conn_appname,
      { "Application name", "mq.conn.appname", FT_STRINGZ, BASE_HEX, NULL, 0x0, "CONN application name", HFILL }},

    { &hf_mq_conn_apptype,
      { "Application type", "mq.conn.apptype", FT_INT32, BASE_DEC, NULL, 0x0, "CONN application type", HFILL }},

    { &hf_mq_conn_acttoken,
      { "Accounting token", "mq.conn.acttoken", FT_BYTES, BASE_HEX, NULL, 0x0, "CONN accounting token", HFILL }},

    { &hf_mq_conn_version,
      { "Version", "mq.conn.version", FT_UINT32, BASE_DEC, VALS(mq_conn_version_vals), 0x0, "CONN version", HFILL }},

    { &hf_mq_conn_options,
      { "Options", "mq.conn.options", FT_UINT32, BASE_HEX, NULL, 0x0, "CONN options", HFILL }},

    { &hf_mq_inq_nbsel,
      { "Selector count", "mq.inq.nbsel", FT_UINT32, BASE_DEC, NULL, 0x0, "INQ Selector count", HFILL }},

    { &hf_mq_inq_nbint,
      { "Integer count", "mq.inq.nbint", FT_UINT32, BASE_DEC, NULL, 0x0, "INQ Integer count", HFILL }},

    { &hf_mq_inq_charlen,
      { "Character length", "mq.inq.charlen", FT_UINT32, BASE_DEC, NULL, 0x0, "INQ Character length", HFILL }},

    { &hf_mq_inq_sel,
      { "Selector", "mq.inq.sel", FT_UINT32, BASE_DEC, NULL, 0x0, "INQ Selector", HFILL }},

    { &hf_mq_inq_intvalue,
      { "Integer value", "mq.inq.intvalue", FT_UINT32, BASE_DEC, NULL, 0x0, "INQ Integer value", HFILL }},

    { &hf_mq_inq_charvalues,
      { "Char values", "mq.inq.charvalues", FT_STRINGZ, BASE_HEX, NULL, 0x0, "INQ Character values", HFILL }},

    { &hf_mq_spi_verb,
      { "SPI Verb", "mq.spi.verb", FT_UINT32, BASE_DEC, VALS(mq_spi_verbs_vals), 0x0, "SPI Verb", HFILL }},

    { &hf_mq_spi_version,
      { "Version", "mq.spi.version", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Version", HFILL }},

    { &hf_mq_spi_length,
      { "Max reply size", "mq.spi.replength", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Max reply size", HFILL }},

    { &hf_mq_spi_base_structid,
      { "SPI Structid", "mq.spib.structid", FT_STRINGZ, BASE_DEC, NULL, 0x0, "SPI Base structid", HFILL }},

    { &hf_mq_spi_base_version,
      { "Version", "mq.spib.version", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Base Version", HFILL }},

    { &hf_mq_spi_base_length,
      { "Length", "mq.spib.length", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Base Length", HFILL }},

    { &hf_mq_spi_spqo_nbverb,
      { "Number of verbs", "mq.spqo.nbverb", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Query Output Number of verbs", HFILL }},

    { &hf_mq_spi_spqo_verbid,
      { "Verb", "mq.spqo.verb", FT_UINT32, BASE_DEC, VALS(mq_spi_verbs_vals), 0x0, "SPI Query Output VerbId", HFILL }},

    { &hf_mq_spi_spqo_maxinoutversion,
      { "Max InOut Version", "mq.spqo.maxiov", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Query Output Max InOut Version", HFILL }},

    { &hf_mq_spi_spqo_maxinversion,
      { "Max In Version", "mq.spqo.maxiv", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Query Output Max In Version", HFILL }},

    { &hf_mq_spi_spqo_maxoutversion,
      { "Max Out Version", "mq.spqo.maxov", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Query Output Max Out Version", HFILL }},

    { &hf_mq_spi_spqo_flags,
      { "Flags", "mq.spqo.flags", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Query Output flags", HFILL }},

    { &hf_mq_spi_spai_mode,
      { "Mode", "mq.spai.mode", FT_UINT32, BASE_DEC, VALS(mq_spi_activate_vals), 0x0, "SPI Activate Input mode", HFILL }},

    { &hf_mq_spi_spai_unknown1,
      { "Unknown1", "mq.spai.unknown1", FT_STRINGZ, BASE_DEC, NULL, 0x0, "SPI Activate Input unknown1", HFILL }},

    { &hf_mq_spi_spai_unknown2,
      { "Unknown2", "mq.spai.unknown2", FT_STRINGZ, BASE_DEC, NULL, 0x0, "SPI Activate Input unknown2", HFILL }},

    { &hf_mq_spi_spai_msgid,
      { "Message Id", "mq.spai.msgid", FT_STRINGZ, BASE_DEC, NULL, 0x0, "SPI Activate Input message id", HFILL }},

    { &hf_mq_spi_spgi_batchsize,
      { "Batch size", "mq.spgi.batchsize", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Get Input batch size", HFILL }},

    { &hf_mq_spi_spgi_batchint,
      { "Batch interval", "mq.spgi.batchint", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Get Input batch interval", HFILL }},

    { &hf_mq_spi_spgi_maxmsgsize,
      { "Max message size", "mq.spgi.maxmsgsize", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Get Input max message size", HFILL }},

    { &hf_mq_spi_spgo_options,
      { "Options", "mq.spgo.options", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Get Output options", HFILL }},

    { &hf_mq_spi_spgo_size,
      { "Size", "mq.spgo.size", FT_UINT32, BASE_DEC, NULL, 0x0, "SPI Get Output size", HFILL }},

    { &hf_mq_spi_options_blank,
      { "Blank padded", "mq.spi.options.blank", FT_BOOLEAN, 8, TFS(&flags_set_truth), MQ_SPI_OPTIONS_BLANK_PADDED, "SPI Options blank padded", HFILL }},

    { &hf_mq_spi_options_syncpoint,
      { "Syncpoint", "mq.spi.options.sync", FT_BOOLEAN, 8, TFS(&flags_set_truth), MQ_SPI_OPTIONS_SYNCPOINT, "SPI Options syncpoint", HFILL }},

    { &hf_mq_spi_options_deferred,
      { "Deferred", "mq.spi.options.deferred", FT_BOOLEAN, 8, TFS(&flags_set_truth), MQ_SPI_OPTIONS_DEFERRED, "SPI Options deferred", HFILL }},

    { &hf_mq_put_length,
      { "Data length", "mq.put.length", FT_UINT32, BASE_DEC, NULL, 0x0, "PUT Data length", HFILL }},

    { &hf_mq_open_options,
      { "Options", "mq.open.options", FT_UINT32, BASE_DEC, NULL, 0x0, "OPEN options", HFILL }},

    { &hf_mq_ping_length,
      { "Length", "mq.ping.length", FT_UINT32, BASE_DEC, NULL, 0x0, "PING length", HFILL }},

    { &hf_mq_ping_buffer,
      { "Buffer", "mq.ping.buffer", FT_BYTES, BASE_DEC, NULL, 0x0, "PING buffer", HFILL }},

    { &hf_mq_reset_length,
      { "Length", "mq.ping.length", FT_UINT32, BASE_DEC, NULL, 0x0, "RESET length", HFILL }},

    { &hf_mq_reset_seqnum,
      { "Sequence number", "mq.ping.seqnum", FT_UINT32, BASE_DEC, NULL, 0x0, "RESET sequence number", HFILL }},

    { &hf_mq_status_length,
      { "Length", "mq.status.length", FT_UINT32, BASE_DEC, NULL, 0x0, "STATUS length", HFILL }},

    { &hf_mq_status_code,
      { "Code", "mq.status.code", FT_UINT32, BASE_DEC, VALS(mq_status_vals), 0x0, "STATUS code", HFILL }},

    { &hf_mq_status_value,
      { "Value", "mq.status.value", FT_UINT32, BASE_DEC, NULL, 0x0, "STATUS value", HFILL }},

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
      { "Offset of first OR", "mq.od.offsetor", FT_UINT32, BASE_DEC, NULL, 0x0, "OD offset of first OR", HFILL }},

    { &hf_mq_od_responserecoffset,
      { "Offset of first RR", "mq.od.offsetrr", FT_UINT32, BASE_DEC, NULL, 0x0, "OD offset of first RR", HFILL }},

    { &hf_mq_od_objectrecptr,
      { "Address of first OR", "mq.od.addror", FT_UINT32, BASE_HEX, NULL, 0x0, "OD address of first OR", HFILL }},

    { &hf_mq_od_responserecptr,
      { "Address of first RR", "mq.od.addrrr", FT_UINT32, BASE_HEX, NULL, 0x0, "OD address of first RR", HFILL }},

    { &hf_mq_od_alternatesecurityid,
      { "Alternate security id", "mq.od.altsecid", FT_STRINGZ, BASE_HEX, NULL, 0x0, "OD alternate security id", HFILL }},

    { &hf_mq_od_resolvedqname,
      { "Resolved queue name", "mq.od.resolvq", FT_STRINGZ, BASE_HEX, NULL, 0x0, "OD resolved queue name", HFILL }},

    { &hf_mq_od_resolvedqmgrname,
      { "Resolved queue manager name", "mq.od.resolvqmgr", FT_STRINGZ, BASE_HEX, NULL, 0x0, "OD resolved queue manager name", HFILL }},

    { &hf_mq_or_objname,
      { "Object name", "mq.od.objname", FT_STRINGZ, BASE_HEX, NULL, 0x0, "OR object name", HFILL }},

    { &hf_mq_or_objqmgrname,
      { "Object queue manager name", "mq.od.objqmgrname", FT_STRINGZ, BASE_HEX, NULL, 0x0, "OR object queue manager name", HFILL }},

    { &hf_mq_rr_completioncode,
      { "Completion code", "mq.rr.completioncode", FT_UINT32, BASE_DEC, NULL, 0x0, "OR completion code", HFILL }},

    { &hf_mq_rr_reasoncode,
      { "Reason code", "mq.rr.reasoncode", FT_UINT32, BASE_DEC, NULL, 0x0, "OR reason code", HFILL }},

    { &hf_mq_pmr_msgid,
      { "Message Id", "mq.pmr.msgid", FT_BYTES, BASE_DEC, NULL, 0x0, "PMR Message Id", HFILL }},

    { &hf_mq_pmr_correlid,
      { "Correlation Id", "mq.pmr.correlid", FT_BYTES, BASE_DEC, NULL, 0x0, "PMR Correlation Id", HFILL }},

    { &hf_mq_pmr_groupid,
      { "GroupId", "mq.pmr.groupid", FT_BYTES, BASE_DEC, NULL, 0x0, "PMR GroupId", HFILL }},

    { &hf_mq_pmr_feedback,
      { "Feedback", "mq.pmr.feedback", FT_UINT32, BASE_DEC, NULL, 0x0, "PMR Feedback", HFILL }},

    { &hf_mq_pmr_acttoken,
      { "Accounting token", "mq.pmr.acttoken", FT_BYTES, BASE_DEC, NULL, 0x0, "PMR accounting token", HFILL }},

    { &hf_mq_md_structid,
      { "MD structid", "mq.md.structid", FT_STRINGZ, BASE_DEC, NULL, 0x0, "MD structid", HFILL }},

    { &hf_mq_md_version,
      { "Version", "mq.md.version", FT_UINT32, BASE_DEC, NULL, 0x0, "MD version", HFILL }},

    { &hf_mq_md_report,
      { "Report", "mq.md.report", FT_UINT32, BASE_DEC, NULL, 0x0, "MD report", HFILL }},

    { &hf_mq_md_msgtype,
      { "Message type", "mq.md.msgtype", FT_UINT32, BASE_DEC, NULL, 0x0, "MD message type", HFILL }},

    { &hf_mq_md_expiry,
      { "Expiry", "mq.md.expiry", FT_INT32, BASE_DEC, NULL, 0x0, "MD expiry", HFILL }},

    { &hf_mq_md_feedback,
      { "Feedback", "mq.md.feedback", FT_UINT32, BASE_DEC, NULL, 0x0, "MD feedback", HFILL }},

    { &hf_mq_md_encoding,
      { "Encoding", "mq.md.encoding", FT_UINT32, BASE_DEC, NULL, 0x0, "MD encoding", HFILL }},

    { &hf_mq_md_ccsid,
      { "Character set", "mq.md.ccsid", FT_INT32, BASE_DEC, NULL, 0x0, "MD character set", HFILL }},

    { &hf_mq_md_format,
      { "Format", "mq.md.format", FT_STRINGZ, BASE_DEC, NULL, 0x0, "MD format", HFILL }},

    { &hf_mq_md_priority,
      { "Priority", "mq.md.priority", FT_INT32, BASE_DEC, NULL, 0x0, "MD priority", HFILL }},

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
      { "Put Application Type", "mq.md.appltype", FT_INT32, BASE_DEC, NULL, 0x0, "MD Put application type", HFILL }},

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
      { "Original length", "mq.md.origdata", FT_INT32, BASE_DEC, NULL, 0x0, "MD Original length", HFILL }},

    { &hf_mq_md_hidden_lastformat,
      { "Last format", "mq.md.lastformat", FT_STRINGZ, BASE_DEC, NULL, 0x0, "MD Last format", HFILL }},

    { &hf_mq_dlh_structid,
      { "DLH structid", "mq.dlh.structid", FT_STRINGZ, BASE_DEC, NULL, 0x0, "DLH structid", HFILL }},

    { &hf_mq_dlh_version,
      { "Version", "mq.dlh.version", FT_UINT32, BASE_DEC, NULL, 0x0, "DLH version", HFILL }},

    { &hf_mq_dlh_reason,
      { "Reason", "mq.dlh.reason", FT_UINT32, BASE_DEC, NULL, 0x0, "DLH reason", HFILL }},

    { &hf_mq_dlh_destq,
      { "Destination queue", "mq.dlh.destq", FT_STRINGZ, BASE_DEC, NULL, 0x0, "DLH destination queue", HFILL }},

    { &hf_mq_dlh_destqmgr,
      { "Destination queue manager", "mq.dlh.destqmgr", FT_STRINGZ, BASE_DEC, NULL, 0x0, "DLH destination queue manager", HFILL }},

    { &hf_mq_dlh_encoding,
      { "Encoding", "mq.dlh.encoding", FT_UINT32, BASE_DEC, NULL, 0x0, "DLH encoding", HFILL }},

    { &hf_mq_dlh_ccsid,
      { "Character set", "mq.dlh.ccsid", FT_INT32, BASE_DEC, NULL, 0x0, "DLH character set", HFILL }},

    { &hf_mq_dlh_format,
      { "Format", "mq.dlh.format", FT_STRINGZ, BASE_DEC, NULL, 0x0, "DLH format", HFILL }},

    { &hf_mq_dlh_putappltype,
      { "Put application type", "mq.dlh.putappltype", FT_INT32, BASE_DEC, NULL, 0x0, "DLH put application type", HFILL }},

    { &hf_mq_dlh_putapplname,
      { "Put application name", "mq.dlh.putapplname", FT_STRINGZ, BASE_DEC, NULL, 0x0, "DLH put application name", HFILL }},

    { &hf_mq_dlh_putdate,
      { "Put date", "mq.dlh.putdate", FT_STRINGZ, BASE_DEC, NULL, 0x0, "DLH put date", HFILL }},

    { &hf_mq_dlh_puttime,
      { "Put time", "mq.dlh.puttime", FT_STRINGZ, BASE_DEC, NULL, 0x0, "DLH put time", HFILL }},

    { &hf_mq_dh_putmsgrecfields,
      { "Flags PMR", "mq.dh.flagspmr", FT_UINT32, BASE_DEC, NULL, 0x0, "DH flags PMR", HFILL }},

    { &hf_mq_dh_recspresent,
      { "Number of records", "mq.dh.nbrrec", FT_UINT32, BASE_DEC, NULL, 0x0, "DH number of records", HFILL }},

    { &hf_mq_dh_objectrecoffset,
      { "Offset of first OR", "mq.dh.offsetor", FT_UINT32, BASE_DEC, NULL, 0x0, "DH offset of first OR", HFILL }},

    { &hf_mq_dh_putmsgrecoffset,
      { "Offset of first PMR", "mq.dh.offsetpmr", FT_UINT32, BASE_DEC, NULL, 0x0, "DH offset of first PMR", HFILL }},

    { &hf_mq_gmo_structid,
      { "GMO structid", "mq.gmo.structid", FT_STRINGZ, BASE_DEC, NULL, 0x0, "GMO structid", HFILL }},

    { &hf_mq_gmo_version,
      { "Version", "mq.gmo.version", FT_UINT32, BASE_DEC, NULL, 0x0, "GMO version", HFILL }},

    { &hf_mq_gmo_options,
      { "Options", "mq.gmo.options", FT_UINT32, BASE_HEX, NULL, 0x0, "GMO options", HFILL }},

    { &hf_mq_gmo_waitinterval,
      { "Wait Interval", "mq.gmo.waitint", FT_INT32, BASE_DEC, NULL, 0x0, "GMO wait interval", HFILL }},

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
      { "Returned length", "mq.gmo.retlen", FT_INT32, BASE_DEC, NULL, 0x0, "GMO returned length", HFILL }},

    { &hf_mq_pmo_structid,
      { "PMO structid", "mq.pmo.structid", FT_STRINGZ, BASE_DEC, NULL, 0x0, "PMO structid", HFILL }},

    { &hf_mq_pmo_version,
      { "Version", "mq.pmo.structid", FT_UINT32, BASE_DEC, NULL, 0x0, "PMO version", HFILL }},

    { &hf_mq_pmo_options,
      { "Options", "mq.pmo.options", FT_UINT32, BASE_HEX, NULL, 0x0, "PMO options", HFILL }},

    { &hf_mq_pmo_timeout,
      { "Timeout", "mq.pmo.timeout", FT_INT32, BASE_DEC, NULL, 0x0, "PMO time out", HFILL }},

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
      { "Offset of first PMR", "mq.pmo.offsetpmr", FT_UINT32, BASE_DEC, NULL, 0x0, "PMO offset of first PMR", HFILL }},

    { &hf_mq_pmo_responserecoffset,
      { "Offset of first RR", "mq.pmo.offsetrr", FT_UINT32, BASE_DEC, NULL, 0x0, "PMO offset of first RR", HFILL }},

    { &hf_mq_pmo_putmsgrecptr,
      { "Address of first record", "mq.pmo.addrrec", FT_UINT32, BASE_HEX, NULL, 0x0, "PMO address of first record", HFILL }},

    { &hf_mq_pmo_responserecptr,
      { "Address of first response record", "mq.pmo.addrres", FT_UINT32, BASE_HEX, NULL, 0x0, "PMO address of first response record", HFILL }},

    { &hf_mq_head_structid,
      { "Structid", "mq.head.structid", FT_STRINGZ, BASE_DEC, NULL, 0x0, "Header structid", HFILL }},

    { &hf_mq_head_version,
      { "Structid", "mq.head.version", FT_UINT32, BASE_DEC, NULL, 0x0, "Header version", HFILL }},

    { &hf_mq_head_length,
      { "Length", "mq.head.length", FT_UINT32, BASE_DEC, NULL, 0x0, "Header length", HFILL }},

    { &hf_mq_head_encoding,
      { "Encoding", "mq.head.encoding", FT_UINT32, BASE_DEC, NULL, 0x0, "Header encoding", HFILL }},

    { &hf_mq_head_ccsid,
      { "Character set", "mq.head.ccsid", FT_INT32, BASE_DEC, NULL, 0x0, "Header character set", HFILL }},

    { &hf_mq_head_format,
      { "Format", "mq.head.format", FT_STRINGZ, BASE_DEC, NULL, 0x0, "Header format", HFILL }},

    { &hf_mq_head_flags,
      { "Flags", "mq.head.flags", FT_UINT32, BASE_DEC, NULL, 0x0, "Header flags", HFILL }},

    { &hf_mq_head_struct,
      { "Struct", "mq.head.struct", FT_BYTES, BASE_HEX, NULL, 0x0, "Header struct", HFILL }},

    { &hf_mq_xa_length,
      { "Length", "mq.xa.length", FT_UINT32, BASE_DEC, NULL, 0x0, "XA Length", HFILL }},

    { &hf_mq_xa_returnvalue,
      { "Return value", "mq.xa.returnvalue", FT_INT32, BASE_DEC, VALS(mq_xaer_vals), 0x0, "XA Return Value", HFILL }},

    { &hf_mq_xa_tmflags,
      { "Transaction Manager Flags", "mq.xa.tmflags", FT_UINT32, BASE_HEX, NULL, 0x0, "XA Transaction Manager Flags", HFILL }},

    { &hf_mq_xa_rmid,
      { "Resource manager ID", "mq.xa.rmid", FT_UINT32, BASE_DEC, NULL, 0x0, "XA Resource Manager ID", HFILL }},

    { &hf_mq_xa_count,
      { "Number of Xid", "mq.xa.nbxid", FT_UINT32, BASE_DEC, NULL, 0x0, "XA Number of Xid", HFILL }},

    { &hf_mq_xa_tmflags_join,
      { "JOIN", "mq.xa.tmflags.join", FT_BOOLEAN, 32, TFS(&flags_set_truth), MQ_XA_TMJOIN, "XA TM Flags JOIN", HFILL }},

    { &hf_mq_xa_tmflags_endrscan,
      { "ENDRSCAN", "mq.xa.tmflags.endrscan", FT_BOOLEAN, 32, TFS(&flags_set_truth), MQ_XA_TMENDRSCAN, "XA TM Flags ENDRSCAN", HFILL }},

    { &hf_mq_xa_tmflags_startrscan,
      { "STARTRSCAN", "mq.xa.tmflags.startrscan", FT_BOOLEAN, 32, TFS(&flags_set_truth), MQ_XA_TMSTARTRSCAN, "XA TM Flags STARTRSCAN", HFILL }},

    { &hf_mq_xa_tmflags_suspend,
      { "SUSPEND", "mq.xa.tmflags.suspend", FT_BOOLEAN, 32, TFS(&flags_set_truth), MQ_XA_TMSUSPEND, "XA TM Flags SUSPEND", HFILL }},

    { &hf_mq_xa_tmflags_success,
      { "SUCCESS", "mq.xa.tmflags.success", FT_BOOLEAN, 32, TFS(&flags_set_truth), MQ_XA_TMSUCCESS, "XA TM Flags SUCCESS", HFILL }},

    { &hf_mq_xa_tmflags_resume,
      { "RESUME", "mq.xa.tmflags.resume", FT_BOOLEAN, 32, TFS(&flags_set_truth), MQ_XA_TMRESUME, "XA TM Flags RESUME", HFILL }},

    { &hf_mq_xa_tmflags_fail,
      { "FAIL", "mq.xa.tmflags.fail", FT_BOOLEAN, 32, TFS(&flags_set_truth), MQ_XA_TMFAIL, "XA TM Flags FAIL", HFILL }},

    { &hf_mq_xa_tmflags_onephase,
      { "ONEPHASE", "mq.xa.tmflags.onephase", FT_BOOLEAN, 32, TFS(&flags_set_truth), MQ_XA_TMONEPHASE, "XA TM Flags ONEPHASE", HFILL }},

    { &hf_mq_xa_xid_formatid,
      { "Format ID", "mq.xa.xid.formatid", FT_INT32, BASE_DEC, NULL, 0x0, "XA Xid Format ID", HFILL }},

    { &hf_mq_xa_xid_globalxid_length,
      { "Global TransactionId Length", "mq.xa.xid.gxidl", FT_UINT8, BASE_DEC, NULL, 0x0, "XA Xid Global TransactionId Length", HFILL }},

    { &hf_mq_xa_xid_brq_length,
      { "Branch Qualifier Length", "mq.xa.xid.bql", FT_UINT8, BASE_DEC, NULL, 0x0, "XA Xid Branch Qualifier Length", HFILL }},

    { &hf_mq_xa_xid_globalxid,
      { "Global TransactionId", "mq.xa.xid.gxid", FT_BYTES, BASE_DEC, NULL, 0x0, "XA Xid Global TransactionId", HFILL }},

    { &hf_mq_xa_xid_brq,
      { "Branch Qualifier", "mq.xa.xid.bq", FT_BYTES, BASE_DEC, NULL, 0x0, "XA Xid Branch Qualifier", HFILL }},

    { &hf_mq_xa_xainfo_length,
      { "Length", "mq.xa.xainfo.length", FT_UINT8, BASE_DEC, NULL, 0x0, "XA XA_info Length", HFILL }},

    { &hf_mq_xa_xainfo_value,
      { "Value", "mq.xa.xainfo.value", FT_STRINGZ, BASE_DEC, NULL, 0x0, "XA XA_info Value", HFILL }}

  };
  static gint *ett[] = {
    &ett_mq,
    &ett_mq_tsh,
    &ett_mq_tsh_tcf,
    &ett_mq_api,
    &ett_mq_msh,
    &ett_mq_xqh,
    &ett_mq_id,
    &ett_mq_id_icf,
    &ett_mq_id_ief,
    &ett_mq_uid,
    &ett_mq_conn,
    &ett_mq_inq,
    &ett_mq_spi,
    &ett_mq_spi_base,
    &ett_mq_spi_options,
    &ett_mq_put,
    &ett_mq_open,
    &ett_mq_ping,
    &ett_mq_reset,
    &ett_mq_status,
    &ett_mq_od,
    &ett_mq_or,
    &ett_mq_rr,
    &ett_mq_pmr,
    &ett_mq_md,
    &ett_mq_mde,
    &ett_mq_dlh,
    &ett_mq_dh,
    &ett_mq_gmo,
    &ett_mq_pmo,
    &ett_mq_head,
    &ett_mq_xa,
    &ett_mq_xa_tmflags,
    &ett_mq_xa_xid,
    &ett_mq_xa_info,
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

void
proto_reg_handoff_mq(void)
{
	/*  Unlike some protocol (HTTP, POP3, ...) that clearly map to a standard
	*  class of applications (web browser, e-mail client, ...) and have a very well
	*  known port number, the MQ applications are most often specific to a business application */

	mq_tcp_handle = create_dissector_handle(dissect_mq_tcp, proto_mq);
	mq_spx_handle = create_dissector_handle(dissect_mq_spx, proto_mq);

	dissector_add_handle("tcp.port", mq_tcp_handle);
	heur_dissector_add("tcp", dissect_mq_heur_tcp, proto_mq);
	heur_dissector_add("netbios", dissect_mq_heur_netbios, proto_mq);
	heur_dissector_add("http", dissect_mq_heur_http, proto_mq);
	dissector_add("spx.socket", MQ_SOCKET_SPX, mq_spx_handle);
	data_handle = find_dissector("data");

}
