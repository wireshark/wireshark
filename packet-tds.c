/* packet-tds.c
 * Routines for TDS NetLib dissection
 * Copyright 2000-2002, Brian Bruns <camber@ais.org>
 * Copyright 2002, Steve Langasek <vorlon@netexpress.net>
 *
 * $Id: packet-tds.c,v 1.20 2003/12/27 02:17:22 guy Exp $
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

/*
 * The NETLIB protocol is a small blocking protocol designed to allow TDS
 * to be placed within different transports (TCP, DECNet, IPX/SPX).  A
 * NETLIB packet starts with an eight byte header containing:
 *
 *	a one-byte packet type field;
 *
 *	a one-byte status field;
 *
 *	a two-byte big-endian size field giving the size of the packet,
 *	including the header;
 *
 *	a two-byte big-endian channel number, used when multiple sessions
 *	are being multiplexed on a single connection;
 *
 *	a one-byte packet number, giving "the frame number of a multiplexed
 *	message, modulo 256";
 *
 *	a one-byte window, which is the number of frames to be sent
 *	before an acknowledgment message is received.
 *
 * followed by payload whose size is the value in the size field minus
 * 8.
 *
 * Microsoft Network Monitor 2.x dissects the 4 byte field (and indicates
 * that the one-byte last packet indicator also contains other bits).
 *
 * The TDS protocol consists of a number of protocol data units (PDUs) that
 * appear to be assembled from NETLIB packets, in the form of zero or more
 * NETLIB packets with the last packet indicator clear and a final NETLIB
 * packet with the last packet indicator set.  The type of the TDS PDU is
 * specified by the packet type field of the NETLIB header (presumably that
 * field has the same value for all NETLIB packets that make up a TDS PDU).
 *
 * The "server response" PDU consists of a sequence of multiple items, each
 * one beginning with a one byte type field at the start of the PDU.  Some
 * items are fixed length, some are variable length with a two byte size
 * field following the item type, and then there is TDS_ROW_TOKEN in which
 * size is determined by analyzing the result set returned from the server.
 * This in effect means that we are hopelessly lost if we haven't seen the
 * result set.  Also, TDS 4/5 is byte order negotiable, which is specified
 * in the login packet.  We can attempt to determine it later on, but not
 * with 100% accuracy.
 *
 * Some preliminary documentation on the packet format can be found at
 * http://www.freetds.org/tds.html
 *
 * Some more information can be found in
 * http://download.nai.com/products/media/sniffer/support/sdos/sybase.pdf
 *
 * Much of this code was originally developed for the FreeTDS project.
 * http://www.freetds.org
 */

/*
 * Excerpts from Brian's posting to ethereal-dev:
 *
 * The TDS Protocol is actually a protocol within a protocol.  On the outside
 * there is netlib which is not so much a encapsulation as a blocking of the
 * data, typically to 512 or 4096 bytes.  Between this are the protocol data
 * units for TDS.  Netlib packets may be split over real packets, multiple
 * netlib packets may appear in single real packets.  TDS PDUs may be split
 * over netlib packets (and real packets) and most certainly can appear
 * multiple times within a netlib packet.
 *
 * Because of this, I abandoned my earlier attempt at making two dissectors,
 * one for netlib and one for TDS. Counterintuitively, a single dissector
 * turned out to be simpler than splitting it up.
 *
 * Here are some of the (hefty) limitations of the current code
 *
 * . We currently do not handle netlib headers that cross packet boundaries.
 *   This should be an easy fix.
 * . I probably could have used the packet reassembly stuff, but I started
 *   this at version 0.8.20, so c'est la vie. It wouldn't have covered the
 *   netlib stuff anyway, so no big loss.
 * . The older two layer version of the code dissected the PDU's, but the new
 *   version does not yet, it only labels the names. I need an elegant way to
 *   deal with dissecting data crossing (netlib and tcp) packet boundries.  I
 *   think I have one, but ran out of time to do it.
 * . It will only work on little endian platforms.  Or rather I should say,
 *   the client that was captured must be little endian.  TDS 7.0/8.0 is
 *   always LE; for TDS 4.2/5.0 look in the code for tvb_get_le*() functions,
 *   there are fields in the login packet which determine byte order.
 * . result sets that span netlib packets are not working
 * . TDS 7 and 4.2 result sets are not working yet
 *
 * All that said, the code does deal gracefully with different boudary
 * conditions and what remains are the easier bits, IMHO.
 *
 * XXX - "real packets" means "TCP segments", for TCP.
 *
 * XXX - is it *REALLY* true that you can have more than one TDS PDU (as
 * opposed to more than one server response item) per NETLIB packet?  Or is
 * all the data in a NETLIB packet put into a single TDS PDU?  If so, then
 * we can reassemble NETLIB packets using the standard TCP desegmentation
 * code, and can reassemble TDS PDUs using "fragment_add_seq_check()",
 * and more cleanly separate the NETLIB and TDS dissectors (although the
 * "is this NETLIB" heuristic would have to look at TDS information past
 * the NETLIB header, in order to make the heuristic strong enough not
 * to get too many false positives; note that the heuristic should reject
 * any putative NETLIB packet with a length field with a value < 8).
 *
 * That would substantially clean the dissector up, eliminating most of
 * the per-packet data (we might still need information to handle
 * TDS_ROW_TOKEN), getting rid of the stuff to handle data split across
 * TCP segment boundaries in favor of simple reassembly code, and
 * fixing some otherwise nasty-looking crashing bugs.
 *
 * NOTE: we assume that all the data in a NETLIB packet *can* be put into
 * a single TDS PTU, so that we have separate reassembly of NETLIB
 * packets and TDS PDUs; it seems to work, and it really did clean stuff
 * up and fix crashes.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/conversation.h>

#include "packet-smb-common.h"
#include "packet-frame.h"
#include "reassemble.h"
#include "prefs.h"

#define TDS_QUERY_PKT        1
#define TDS_LOGIN_PKT        2
#define TDS_RPC_PKT          3
#define TDS_RESP_PKT         4
#define TDS_RAW_PKT          5
#define TDS_CANCEL_PKT       6
#define TDS_BULK_DATA_PKT    7
#define TDS_OPEN_CHN_PKT     8
#define TDS_CLOSE_CHN_PKT    9
#define TDS_RES_ERROR_PKT   10
#define TDS_LOG_CHN_ACK_PKT 11
#define TDS_ECHO_PKT        12
#define TDS_LOGOUT_CHN_PKT  13
#define TDS_QUERY5_PKT      15  /* or "Normal tokenized request or response */
#define TDS_LOGIN7_PKT      16	/* or "Urgent tokenized request or response */
#define TDS_XXX7_PKT        18	/* seen in one capture */

#define is_valid_tds_type(x) ((x) >= TDS_QUERY_PKT && (x) <= TDS_XXX7_PKT)

/* The following constants are imported more or less directly from FreeTDS */

#define TDS5_DYN_TOKEN      231  /* 0xE7    TDS 5.0 only              */
#define TDS5_DYNRES_TOKEN   236  /* 0xEC    TDS 5.0 only              */
#define TDS5_DYN3_TOKEN     215  /* 0xD7    TDS 5.0 only              */
#define TDS_LANG_TOKEN       33  /* 0x21    TDS 5.0 only              */
#define TDS_CLOSE_TOKEN     113  /* 0x71    TDS 5.0 only? ct_close()  */
#define TDS_RET_STAT_TOKEN  121  /* 0x79                              */
#define TDS_124_TOKEN       124  /* 0x7C    TDS 4.2 only - TDS_PROCID */
#define TDS7_RESULT_TOKEN   129  /* 0x81    TDS 7.0 only              */
#define TDS_COL_NAME_TOKEN  160  /* 0xA0    TDS 4.2 only              */
#define TDS_COL_INFO_TOKEN  161  /* 0xA1    TDS 4.2 only - TDS_COLFMT */
/*#define  TDS_TABNAME   164 */
/*#define  TDS_COL_INFO   165 */
#define TDS_167_TOKEN       167  /* 0xA7                              */
#define TDS_168_TOKEN       168  /* 0xA8                              */
#define TDS_ORDER_BY_TOKEN  169  /* 0xA9    TDS_ORDER                 */
#define TDS_ERR_TOKEN       170  /* 0xAA                              */
#define TDS_MSG_TOKEN       171  /* 0xAB                              */
#define TDS_PARAM_TOKEN     172  /* 0xAC    RETURNVALUE?              */
#define TDS_LOGIN_ACK_TOKEN 173  /* 0xAD                              */
#define TDS_174_TOKEN       174  /* 0xAE    TDS_CONTROL               */
#define TDS_ROW_TOKEN       209  /* 0xD1                              */
#define TDS_CMP_ROW_TOKEN   211  /* 0xD3                              */
#define TDS_CAP_TOKEN       226  /* 0xE2                              */
#define TDS_ENV_CHG_TOKEN   227  /* 0xE3                              */
#define TDS_EED_TOKEN       229  /* 0xE5                              */
#define TDS_AUTH_TOKEN      237  /* 0xED                              */
#define TDS_RESULT_TOKEN    238  /* 0xEE                              */
#define TDS_DONE_TOKEN      253  /* 0xFD    TDS_DONE                  */
#define TDS_DONEPROC_TOKEN  254  /* 0xFE    TDS_DONEPROC              */
#define TDS_DONEINPROC_TOKEN 255  /* 0xFF    TDS_DONEINPROC            */

#define SYBCHAR      47   /* 0x2F */
#define SYBVARCHAR   39   /* 0x27 */
#define SYBINTN      38   /* 0x26 */
#define SYBINT1      48   /* 0x30 */
#define SYBINT2      52   /* 0x34 */
#define SYBINT4      56   /* 0x38 */
#define SYBINT8     127   /* 0x7F */
#define SYBFLT8      62   /* 0x3E */
#define SYBDATETIME  61   /* 0x3D */
#define SYBBIT       50   /* 0x32 */
#define SYBTEXT      35   /* 0x23 */
#define SYBNTEXT     99   /* 0x63 */
#define SYBIMAGE     34   /* 0x22 */
#define SYBMONEY4    122  /* 0x7A */
#define SYBMONEY     60   /* 0x3C */
#define SYBDATETIME4 58   /* 0x3A */
#define SYBREAL      59   /* 0x3B */
#define SYBBINARY    45   /* 0x2D */
#define SYBVOID      31   /* 0x1F */
#define SYBVARBINARY 37   /* 0x25 */
#define SYBNVARCHAR  103  /* 0x67 */
#define SYBBITN      104  /* 0x68 */
#define SYBNUMERIC   108  /* 0x6C */
#define SYBDECIMAL   106  /* 0x6A */
#define SYBFLTN      109  /* 0x6D */
#define SYBMONEYN    110  /* 0x6E */
#define SYBDATETIMN  111  /* 0x6F */
#define XSYBCHAR     167  /* 0xA7 */
#define XSYBVARCHAR  175  /* 0xAF */
#define XSYBNVARCHAR 231  /* 0xE7 */
#define XSYBNCHAR    239  /* 0xEF */
#define SYBUNIQUE    0x24
#define SYBVARIANT   0x62

#define is_fixed_coltype(x) (x==SYBINT1    || \
                        x==SYBINT2      || \
                        x==SYBINT4      || \
                        x==SYBINT8      || \
                        x==SYBREAL       || \
                        x==SYBFLT8      || \
                        x==SYBDATETIME  || \
                        x==SYBDATETIME4 || \
                        x==SYBBIT       || \
                        x==SYBMONEY     || \
                        x==SYBMONEY4    || \
                        x==SYBUNIQUE)

/* Initialize the protocol and registered fields */
static int proto_tds = -1;
static int hf_tds_type = -1;
static int hf_tds_status = -1;
static int hf_tds_size = -1;
static int hf_tds_channel = -1;
static int hf_tds_packet_number = -1;
static int hf_tds_window = -1;
static int hf_tds_reassembled_in = -1;
static int hf_tds_fragments = -1;
static int hf_tds_fragment = -1;
static int hf_tds_fragment_overlap = -1;
static int hf_tds_fragment_overlap_conflict = -1;
static int hf_tds_fragment_multiple_tails = -1;
static int hf_tds_fragment_too_long_fragment = -1;
static int hf_tds_fragment_error = -1;

static int hf_tds7_login_total_size = -1;
static int hf_tds7_version = -1;
static int hf_tds7_packet_size = -1;
static int hf_tds7_client_version = -1;
static int hf_tds7_client_pid = -1;
static int hf_tds7_connection_id = -1;
static int hf_tds7_option_flags1 = -1;
static int hf_tds7_option_flags2 = -1;
static int hf_tds7_sql_type_flags = -1;
static int hf_tds7_reserved_flags = -1;
static int hf_tds7_time_zone = -1;
static int hf_tds7_collation = -1;

/* Initialize the subtree pointers */
static gint ett_tds = -1;
static gint ett_tds_fragments = -1;
static gint ett_tds_fragment = -1;
static gint ett_tds_token = -1;
static gint ett_tds7_login = -1;
static gint ett_tds7_hdr = -1;

/* Desegmentation of Netlib buffers crossing TCP segment boundaries. */
static gboolean tds_desegment = TRUE;

static const fragment_items tds_frag_items = {
	&ett_tds_fragment,
	&ett_tds_fragments,
	&hf_tds_fragments,
	&hf_tds_fragment,
	&hf_tds_fragment_overlap,
	&hf_tds_fragment_overlap_conflict,
	&hf_tds_fragment_multiple_tails,
	&hf_tds_fragment_too_long_fragment,
	&hf_tds_fragment_error,
	&hf_tds_reassembled_in,
	"fragments"
};

/* Tables for reassembly of fragments. */
static GHashTable *tds_fragment_table = NULL;
static GHashTable *tds_reassembled_table = NULL;

/* defragmentation of multi-buffer TDS PDUs */
static gboolean tds_defragment = TRUE;

static dissector_handle_t tds_tcp_handle;
static dissector_handle_t ntlmssp_handle;
static dissector_handle_t data_handle;

/* These correspond to the netlib packet type field */
static const value_string packet_type_names[] = {
	{TDS_QUERY_PKT,  "Query Packet"},
	{TDS_LOGIN_PKT,  "Login Packet"},
	{TDS_RPC_PKT,    "Remote Procedure Call Packet"},
	{TDS_RESP_PKT,   "Response Packet"},
	{TDS_CANCEL_PKT, "Cancel Packet"},
	{TDS_QUERY5_PKT, "TDS5 Query Packet"},
	{TDS_LOGIN7_PKT, "TDS7/8 Login Packet"},
	{0, NULL},
};

/* The status field */

#define is_valid_tds_status(x) ((x) <= STATUS_EVENT_NOTIFICATION)

#define STATUS_NOT_LAST_BUFFER		0x00
#define STATUS_LAST_BUFFER		0x01
#define STATUS_ATTN_REQUEST_ACK		0x02
#define STATUS_ATTN_REQUEST		0x03
#define STATUS_EVENT_NOTIFICATION	0x04

static const value_string status_names[] = {
	{STATUS_NOT_LAST_BUFFER,    "Not last buffer"},
	{STATUS_LAST_BUFFER,        "Last buffer in request or response"},
	{STATUS_ATTN_REQUEST_ACK,   "Acknowledgment of last attention request"},
	{STATUS_ATTN_REQUEST,       "Attention request"},
	{STATUS_EVENT_NOTIFICATION, "Event notification"},
	{0, NULL},
};

/* The one byte token at the start of each TDS PDU */
static const value_string token_names[] = {
	{TDS5_DYN_TOKEN, "Dynamic SQL"},
	{TDS5_DYNRES_TOKEN, "Dynamic Results"},
	{TDS5_DYN3_TOKEN, "Dynamic (Unknown)"},
	{TDS_LANG_TOKEN, "Language"},
	{TDS_CLOSE_TOKEN, "Close Connection"},
	{TDS_RET_STAT_TOKEN, "Return Status"},
	{TDS_124_TOKEN, "Proc ID"},
	{TDS7_RESULT_TOKEN, "Results"},
	{TDS_COL_NAME_TOKEN, "Column Names"},
	{TDS_COL_INFO_TOKEN, "Column Info"},
	{TDS_167_TOKEN, "Unknown (167)"},
	{TDS_168_TOKEN, "Unknown (168)"},
	{TDS_ORDER_BY_TOKEN, "Order By"},
	{TDS_ERR_TOKEN, "Error Message"},
	{TDS_MSG_TOKEN, "Info Message"},
	{TDS_PARAM_TOKEN, "Paramater"},
	{TDS_LOGIN_ACK_TOKEN, "Login Acknowledgement"},
	{TDS_174_TOKEN, "Unknown (174)"},
	{TDS_ROW_TOKEN, "Row"},
	{TDS_CMP_ROW_TOKEN, "Compute Row"},
	{TDS_CAP_TOKEN, "Capabilities"},
	{TDS_ENV_CHG_TOKEN, "Environment Change"},
	{TDS_EED_TOKEN, "Extended Error"},
	{TDS_AUTH_TOKEN, "Authentication"},
	{TDS_RESULT_TOKEN, "Results"},
	{TDS_DONE_TOKEN, "Done"},
	{TDS_DONEPROC_TOKEN, "Done Proc"},
	{TDS_DONEINPROC_TOKEN, "Done In Proc"},
	{0, NULL},
};

static const value_string env_chg_names[] = {
        {1, "Database"},
        {2, "Language"},
        {3, "Sort Order"},
        {4, "Blocksize"},
        {5, "Unicode Locale ID"},
        {6, "Unicode Comparison Style"},
        {0, NULL},
};

static const value_string login_field_names[] = {
        {0, "Client Name"},
        {1, "Username"},
        {2, "Password"},
        {3, "App Name"},
        {4, "Server Name"},
        {5, "Unknown1"},
        {6, "Library Name"},
        {7, "Locale"},
        {8, "Unknown2"},
        {0, NULL},
};


#define MAX_COLUMNS 256

/*
 * This is where we store the column information to be used in decoding the
 * TDS_ROW_TOKEN tokens.
 */
struct _tds_col {
     gchar name[256];
     guint16 utype;
     guint8 ctype;
     guint csize;
};

struct _netlib_data {
	guint num_cols;
	struct _tds_col *columns[MAX_COLUMNS];
};

struct tds7_login_packet_hdr {
	guint32	total_packet_size;
	guint32 tds_version;
	guint32 packet_size;
	guint32 client_version;
	guint32 client_pid;
	guint32	connection_id;
	guint8  option_flags1;
	guint8	option_flags2;
	guint8	sql_type_flags;
	guint8	reserved_flags;
	guint32	time_zone;
	guint32	collation;
};

/* all the standard memory management stuff */
#define tds_column_length (sizeof(struct _tds_col))
#define tds_column_init_count 10

static GMemChunk *tds_column = NULL;

/* support routines */
static void
dissect_tds_ntlmssp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    guint offset, guint length)
{
	tvbuff_t *ntlmssp_tvb;

	ntlmssp_tvb = tvb_new_subset(tvb, offset, length, length);
	call_dissector(ntlmssp_handle, ntlmssp_tvb, pinfo, tree);
}

static void
dissect_tds7_login(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset, i, offset2, len;
	gboolean is_unicode = TRUE;
	char *val;

	proto_item *login_hdr;
	proto_tree *login_tree;
	proto_item *header_hdr;
	proto_tree *header_tree;
	proto_item *length_hdr;
	proto_tree *length_tree;
	
	struct tds7_login_packet_hdr td7hdr;
	gint length_remaining;


	/* create display subtree for the protocol */
	offset = 0;
	login_hdr = proto_tree_add_text(tree, tvb, offset, -1, "TDS7 Login Packet");
	login_tree = proto_item_add_subtree(login_hdr, ett_tds7_login);
	header_hdr = proto_tree_add_text(login_tree, tvb, offset, 36, "Login Packet Header");
	header_tree = proto_item_add_subtree(header_hdr, ett_tds7_hdr);
	
	td7hdr.total_packet_size = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(header_tree, hf_tds7_login_total_size, tvb, offset, sizeof(td7hdr.total_packet_size), td7hdr.total_packet_size);
	offset += sizeof(td7hdr.total_packet_size);
	
	td7hdr.tds_version = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint(header_tree, hf_tds7_version, tvb, offset, sizeof(td7hdr.tds_version), td7hdr.tds_version);
	offset += sizeof(td7hdr.tds_version);
	
	td7hdr.packet_size = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint(header_tree, hf_tds7_packet_size, tvb, offset, sizeof(td7hdr.packet_size), td7hdr.packet_size);
	offset += sizeof(td7hdr.packet_size);
	
	td7hdr.client_version = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint(header_tree, hf_tds7_client_version, tvb, offset, sizeof(td7hdr.client_version), td7hdr.client_version);
        offset += sizeof(td7hdr.client_version);
	
	td7hdr.client_pid = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(header_tree, hf_tds7_client_pid, tvb, offset, sizeof(td7hdr.client_pid), td7hdr.client_pid);
        offset += sizeof(td7hdr.client_pid);

	td7hdr.connection_id= tvb_get_letohl(tvb, offset);
        proto_tree_add_uint(header_tree, hf_tds7_connection_id, tvb, offset, sizeof(td7hdr.connection_id), td7hdr.connection_id);
        offset += sizeof(td7hdr.connection_id);
	
	td7hdr.option_flags1 = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(header_tree, hf_tds7_option_flags1, tvb, offset, sizeof(td7hdr.option_flags1), td7hdr.option_flags1);
	offset += sizeof(td7hdr.option_flags1);
	
	td7hdr.option_flags2 = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(header_tree, hf_tds7_option_flags2, tvb, offset, sizeof(td7hdr.option_flags2), td7hdr.option_flags2);
        offset += sizeof(td7hdr.option_flags2);

	td7hdr.sql_type_flags = tvb_get_guint8(tvb, offset);	
	proto_tree_add_uint(header_tree, hf_tds7_sql_type_flags, tvb, offset, sizeof(td7hdr.sql_type_flags), td7hdr.sql_type_flags);
	offset += sizeof(td7hdr.sql_type_flags);

	td7hdr.reserved_flags = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(header_tree, hf_tds7_reserved_flags, tvb, offset, sizeof(td7hdr.reserved_flags), td7hdr.reserved_flags);
	offset += sizeof(td7hdr.reserved_flags);
	
	td7hdr.time_zone = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint(header_tree, hf_tds7_time_zone, tvb, offset, sizeof(td7hdr.time_zone), td7hdr.time_zone);
	offset += sizeof(td7hdr.time_zone);

	td7hdr.collation = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint(header_tree, hf_tds7_collation, tvb, offset, sizeof(td7hdr.collation), td7hdr.collation);
	offset += sizeof(td7hdr.collation);

	length_hdr = proto_tree_add_text(login_tree, tvb, offset, 50, "Lengths and offsets");
        length_tree = proto_item_add_subtree(length_hdr, ett_tds7_hdr);

	for (i = 0; i < 9; i++) {
		offset2 = tvb_get_letohs(tvb, offset + i*4);
		len = tvb_get_letohs(tvb, offset + i*4 + 2);
		proto_tree_add_text(length_tree, tvb, offset + i*4, 2,
		    "%s offset: %u",
		    val_to_str(i, login_field_names, "Unknown"),
		    offset2);
		proto_tree_add_text(length_tree, tvb, offset + i*4 + 2, 2,
			"%s length: %u",
			val_to_str(i, login_field_names, "Unknown"),
			len);
		if (len != 0) {
			if (is_unicode == TRUE) {
				val = tvb_fake_unicode(tvb, offset2, len,
				    TRUE);
				len *= 2;
			} else
				val = tvb_get_string(tvb, offset2, len);
			proto_tree_add_text(login_tree, tvb, offset2, len,
				"%s: %s",
				val_to_str(i, login_field_names, "Unknown"),
				val);
			g_free(val);
		}
	}

	length_remaining = tvb_reported_length_remaining(tvb, offset2 + len);
	if (length_remaining > 0) {
		dissect_tds_ntlmssp(tvb, pinfo, login_tree, offset2 + len,
		    length_remaining);
	}
}

static int get_size_by_coltype(int servertype)
{
   switch(servertype)
   {
      case SYBINT1:        return 1;  break;
      case SYBINT2:        return 2;  break;
      case SYBINT4:        return 4;  break;
      case SYBINT8:        return 8;  break;
      case SYBREAL:        return 4;  break;
      case SYBFLT8:        return 8;  break;
      case SYBDATETIME:    return 8;  break;
      case SYBDATETIME4:   return 4;  break;
      case SYBBIT:         return 1;  break;
      case SYBBITN:        return 1;  break;
      case SYBMONEY:       return 8;  break;
      case SYBMONEY4:      return 4;  break;
      case SYBUNIQUE:      return 16; break;
      default:             return -1; break;
   }
}
static int tds_is_fixed_token(int token)
{
     switch (token) {
          case TDS_DONE_TOKEN:
          case TDS_DONEPROC_TOKEN:
          case TDS_DONEINPROC_TOKEN:
          case TDS_RET_STAT_TOKEN:
               return 1;
          default:
               return 0;
     }
}
static int tds_get_token_size(int token)
{
     switch(token) {
          case TDS_DONE_TOKEN:
          case TDS_DONEPROC_TOKEN:
          case TDS_DONEINPROC_TOKEN:
               return 8;
          case TDS_RET_STAT_TOKEN:
               return 4;
          case TDS_124_TOKEN:
               return 8;
          default:
               return 0;
     }
}

# if 0
/*
 * data_to_string should take column data and turn it into something we can
 * display on the tree.
 */
static char *data_to_string(void *data, guint col_type, guint col_size)
{
   static char  result[256];
   guint i;

   switch(col_type) {
      case SYBVARCHAR:
         /* strncpy(result, (char *)data, col_size); */
	 for (i=0;i<col_size && i<(256-1);i++)
		if (!isprint(((char *)data)[i])) result[i]='.';
		else result[i]=((char *)data)[i];
         result[i] = '\0';
         break;
      case SYBINT2:
         sprintf(result, "%d", *(short *)data);
         break;
      case SYBINT4:
         sprintf(result, "%d", *(int *)data);
         break;
      default:
         sprintf(result, "Unexpected column_type %d", col_type);
         break;
   }
   return result;
}
#endif

/*
 * Since rows are special PDUs in that they are not fixed and lack a size field,
 * the length must be computed using the column information seen in the result
 * PDU. This function does just that.
 */
static size_t
tds_get_row_size(tvbuff_t *tvb, struct _netlib_data *nl_data, guint offset)
{
	guint cur, i, csize;

	cur = offset;
	for (i = 0; i < nl_data->num_cols; i++) {
		if (!is_fixed_coltype(nl_data->columns[i]->ctype)) {
			csize = tvb_get_guint8(tvb, cur);
			cur++;
		} else
			csize = get_size_by_coltype(nl_data->columns[i]->ctype);
		cur += csize;
	}

	return (cur - offset + 1);
}

/*
 * Read the results token and store the relevant information in the
 * _netlib_data structure for later use (see tds_get_row_size).
 */
static gboolean
read_results_tds5(tvbuff_t *tvb, struct _netlib_data *nl_data, guint offset)
{
	guint len, name_len;
	guint cur;
	guint i;

	len = tvb_get_letohs(tvb, offset+1);
	cur = offset + 3;

	/*
	 * This would be the logical place to check for little/big endianess
	 * if we didn't see the login packet.
	 */
	nl_data->num_cols = tvb_get_letohs(tvb, cur);
	if (nl_data->num_cols > MAX_COLUMNS) {
		nl_data->num_cols = 0;
		return FALSE;
	}

	cur += 2;

	for (i = 0; i < nl_data->num_cols; i++) {
		nl_data->columns[i] = g_mem_chunk_alloc(tds_column);
		name_len = tvb_get_guint8(tvb,cur);
		cur ++;
		cur += name_len;

		cur++; /* unknown */

		nl_data->columns[i]->utype = tvb_get_letohs(tvb, cur);
		cur += 2;

		cur += 2; /* unknown */

		nl_data->columns[i]->ctype = tvb_get_guint8(tvb,cur);
		cur++;

		if (!is_fixed_coltype(nl_data->columns[i]->ctype)) {
			nl_data->columns[i]->csize = tvb_get_guint8(tvb,cur);
			cur ++;
		} else {
			nl_data->columns[i]->csize =
			    get_size_by_coltype(nl_data->columns[i]->ctype);
		}
		cur++; /* unknown */
	}
	return TRUE;
}

/*
 * If the packet type from the netlib header is a login packet, then dig into
 * the packet to see if this is a supported TDS version and verify the otherwise
 * weak heuristics of the netlib check.
 */
static gboolean
netlib_check_login_pkt(tvbuff_t *tvb, guint offset, packet_info *pinfo, guint8 type)
{
	guint tds_major, bytes_avail;

	bytes_avail = tvb_length(tvb) - offset;
	/*
	 * we have two login packet styles, one for TDS 4.2 and 5.0
	 */
	if (type==TDS_LOGIN_PKT) {
		/* Use major version number to validate TDS 4/5 login
		 * packet */

		/* Login packet is first in stream and should not be fragmented...
		 * if it is we are screwed */
		if (bytes_avail < 467) return FALSE;
		tds_major = tvb_get_guint8(tvb, 466);
		if (tds_major != 4 && tds_major != 5) {
			return FALSE;
		}
	/*
	 * and one added by Microsoft in SQL Server 7
	 */
	} else if (type==TDS_LOGIN7_PKT) {
		if (bytes_avail < 16) return FALSE;
		tds_major = tvb_get_guint8(tvb, 15);
		if (tds_major != 0x70 && tds_major != 0x80) {
			return FALSE;
		}
	} else if (type==TDS_QUERY5_PKT) {
		if (bytes_avail < 9) return FALSE;
		/* if this is a TDS 5.0 query check the token */
		if (tvb_get_guint8(tvb, 8) != TDS_LANG_TOKEN) {
			return FALSE;
		}
	/* check if it is MS SQL default port */
	} else if (pinfo->srcport != 1433 &&
		pinfo->destport != 1433) {
		/* otherwise, we can not ensure this is netlib */
		/* beyond a reasonable doubt.                  */
          		return FALSE;
	}
	return TRUE;
}

static void
dissect_tds_env_chg(tvbuff_t *tvb, guint offset, guint token_sz,
    proto_tree *tree)
{
	guint8 env_type;
	guint old_len, new_len, old_len_offset;
	char *new_val = NULL, *old_val = NULL;
	guint32 string_offset;
	gboolean is_unicode = FALSE;

	env_type = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 1, "Type: %u (%s)", env_type,
		val_to_str(env_type, env_chg_names, "Unknown"));

	new_len = tvb_get_guint8(tvb, offset+1);
	old_len_offset = offset + new_len + 2;
	old_len = tvb_get_guint8(tvb, old_len_offset);

	/*
	 * If our lengths plus the lengths of the type and the lengths
	 * don't add up to the token size, it must be UCS2.
	 */
	if (old_len + new_len + 3 != token_sz) {
		is_unicode = TRUE;
		old_len_offset = offset + (new_len * 2) + 2;
		old_len = tvb_get_guint8(tvb, old_len_offset);
	}

	proto_tree_add_text(tree, tvb, offset + 1, 1, "New Value Length: %u",
	    new_len);
	if (new_len) {
		string_offset = offset + 2;
		if (is_unicode == TRUE) {
			new_val = tvb_fake_unicode(tvb, string_offset,
			    new_len, TRUE);
			new_len *= 2;
		} else
			new_val = tvb_get_string(tvb, string_offset, new_len);
		proto_tree_add_text(tree, tvb, string_offset, new_len,
		    "New Value: %s", new_val);
		g_free(new_val);
	}

	proto_tree_add_text(tree, tvb, old_len_offset, 1, "Old Value Length: %u",
	    old_len);
	if (old_len) {
		string_offset = old_len_offset + 1;
		if (is_unicode == TRUE) {
			old_val = tvb_fake_unicode(tvb, string_offset,
			    old_len, TRUE);
			old_len *= 2;
		} else
			old_val = tvb_get_string(tvb, string_offset, old_len);
		proto_tree_add_text(tree, tvb, string_offset, old_len,
		    "Old Value: %s", old_val);
		g_free(old_val);
	 }
}

static void
dissect_tds_rpc(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset = 0;
	guint len;
	const char *val;

	/*
	 * RPC name.
	 * XXX - how can we determine whether this is ASCII or Unicode?
	 */
	len = tvb_get_letohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "RPC Name Length: %u", len);
	offset += 2;
	if (len != 0) {
		val = tvb_fake_unicode(tvb, offset, len, TRUE);
		len *= 2;
		proto_tree_add_text(tree, tvb, offset, len, "RPC Name: %s",
		    val);
		offset += len;
	}
	
	proto_tree_add_text(tree, tvb, offset, -1, "Unknown data");
}

static void
dissect_tds_resp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	proto_item *token_item;
	proto_tree *token_tree;
	guint pos, token_sz = 0;
	guint8 token;
	struct _netlib_data nl_data;
	gint length_remaining;

	memset(&nl_data, '\0', sizeof nl_data);

	/*
	 * Until we reach the end of the packet, read tokens.
	 */
	pos = offset;
	while (tvb_reported_length_remaining(tvb, pos) > 0) {
		/* our token */
		token = tvb_get_guint8(tvb, pos);

		if (tds_is_fixed_token(token)) {
			token_sz = tds_get_token_size(token) + 1;
		} else if (token == TDS_ROW_TOKEN) {
			/*
			 * Rows are special; they have no size field and
			 * aren't fixed length.
			 */
			token_sz = tds_get_row_size(tvb, &nl_data, pos + 1);
		} else
			token_sz = tvb_get_letohs(tvb, pos + 1) + 3;

		length_remaining = tvb_ensure_length_remaining(tvb, pos);
		if (token_sz > (guint)length_remaining)
			token_sz = (guint)length_remaining;

		token_item = proto_tree_add_text(tree, tvb, pos, token_sz,
                    "Token 0x%02x %s", token,
                    val_to_str(token, token_names, "Unknown Token Type"));
		token_tree = proto_item_add_subtree(token_item, ett_tds_token);

		/*
		 * If it's a variable token, put the length field in here
		 * instead of replicating this for each token subdissector.
		 */
		if (!tds_is_fixed_token(token) && token != TDS_ROW_TOKEN) {
			proto_tree_add_text(token_tree, tvb, pos+1, 2,
			    "Length: %u", tvb_get_letohs(tvb, pos+1));
		}

		switch (token) {

		case TDS_RESULT_TOKEN:
			/*
			 * If it's a result token, we need to stash the
			 * column info.
			 */
			read_results_tds5(tvb, &nl_data, pos);
			break;

		case TDS_ENV_CHG_TOKEN:
			dissect_tds_env_chg(tvb, pos + 3, token_sz - 3,
			    token_tree);
			break;

		case TDS_AUTH_TOKEN:
			dissect_tds_ntlmssp(tvb, pinfo, token_tree, pos + 3,
			    token_sz - 3);
			break;
		}

		/* and step to the end of the token, rinse, lather, repeat */
		pos += token_sz;
	}
}

static void
dissect_netlib_buffer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	proto_item *tds_item = NULL;
	proto_tree *tds_tree = NULL;
	guint8 type;
	guint8 status;
	guint16 size;
	guint16 channel;
	guint8 packet_number;
	gboolean save_fragmented;
	int len;
	fragment_data *fd_head;
	tvbuff_t *next_tvb;

	if (tree) {
		/* create display subtree for the protocol */
		tds_item = proto_tree_add_item(tree, proto_tds, tvb, offset, -1,
		    FALSE);

		tds_tree = proto_item_add_subtree(tds_item, ett_tds);
	}
	type = tvb_get_guint8(tvb, offset);
	if (tree) {
		proto_tree_add_uint(tds_tree, hf_tds_type, tvb, offset, 1,
		    type);
	}
	status = tvb_get_guint8(tvb, offset + 1);
	if (tree) {
		proto_tree_add_uint(tds_tree, hf_tds_status, tvb, offset + 1, 1,
		    status);
	}
	size = tvb_get_ntohs(tvb, offset + 2);
	if (tree) {
		proto_tree_add_uint(tds_tree, hf_tds_size, tvb, offset + 2, 2,
			size);
	}
	channel = tvb_get_ntohs(tvb, offset + 4);
	if (tree) {
		proto_tree_add_uint(tds_tree, hf_tds_channel, tvb, offset + 4, 2,
			channel);
	}
	packet_number = tvb_get_guint8(tvb, offset + 6);
	if (tree) {
		proto_tree_add_uint(tds_tree, hf_tds_packet_number, tvb, offset + 6, 1,
			packet_number);
		proto_tree_add_item(tds_tree, hf_tds_window, tvb, offset + 7, 1,
			FALSE);
	}
	offset += 8;	/* skip Netlib header */

	/*
	 * Deal with fragmentation.
	 */
	save_fragmented = pinfo->fragmented;
	if (tds_defragment &&
	    (packet_number != 1 || status == STATUS_NOT_LAST_BUFFER)) {
		if (status == STATUS_NOT_LAST_BUFFER) {
			if (check_col(pinfo->cinfo, COL_INFO))
				col_append_str(pinfo->cinfo, COL_INFO,
				    " (Not last buffer)");
		}
		len = tvb_reported_length_remaining(tvb, offset);
		/*
		 * XXX - I've seen captures that start with a login
		 * packet with a sequence number of 2.
		 */
		fd_head = fragment_add_seq_check(tvb, offset, pinfo, channel,
		    tds_fragment_table, tds_reassembled_table,
		    packet_number - 1, len, status == STATUS_NOT_LAST_BUFFER);
		next_tvb = process_reassembled_data(tvb, offset, pinfo,
		    "Reassembled TDS", fd_head, &tds_frag_items, NULL,
		    tds_tree);
	} else {
		/*
		 * If this isn't the last buffer, just show it as a fragment.
		 * (XXX - it'd be nice to dissect it if it's the first
		 * buffer, but we'd need to do reassembly in order to
		 * discover that.)
		 *
		 * If this is the last buffer, dissect it.
		 * (XXX - it'd be nice to show it as a fragment if it's part
		 * of a fragmented message, but we'd need to do reassembly
		 * in order to discover that.)
		 */
		if (status == STATUS_NOT_LAST_BUFFER)
			next_tvb = NULL;
		else {
			next_tvb = tvb_new_subset(tvb, offset, -1, -1);
		}
	}
	if (next_tvb != NULL) {
		switch (type) {

		case TDS_RPC_PKT:
			dissect_tds_rpc(next_tvb, pinfo, tds_tree);
			break;

		case TDS_RESP_PKT:
			dissect_tds_resp(next_tvb, pinfo, tds_tree);
			break;

		case TDS_LOGIN7_PKT:
			dissect_tds7_login(next_tvb, pinfo, tds_tree);
			break;

		default:
			proto_tree_add_text(tds_tree, next_tvb, 0, -1,
			    "TDS Packet");
			break;
		}
	} else {
		next_tvb = tvb_new_subset (tvb, offset, -1, -1);
		call_dissector(data_handle, next_tvb, pinfo, tds_tree);
	}
}

static void
dissect_tds_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	volatile gboolean first_time = TRUE;
	volatile int offset = 0;
	guint length_remaining;
	guint8 type;
	guint16 plen;
	guint length;
	tvbuff_t *next_tvb;
	proto_item *tds_item = NULL;
	proto_tree *tds_tree = NULL;

	while (tvb_reported_length_remaining(tvb, offset) != 0) {
		length_remaining = tvb_ensure_length_remaining(tvb, offset);

		/*
		 * Can we do reassembly?
		 */
		if (tds_desegment && pinfo->can_desegment) {
			/*
			 * Yes - is the fixed-length part of the PDU
			 * split across segment boundaries?
			 */
			if (length_remaining < 8) {
				/*
				 * Yes.  Tell the TCP dissector where the
				 * data for this message starts in the data
				 * it handed us, and how many more bytes we
				 * need, and return.
				 */
				pinfo->desegment_offset = offset;
				pinfo->desegment_len = 8 - length_remaining;
				return;
			}
		}

		type = tvb_get_guint8(tvb, offset);

		/*
		 * Get the length of the PDU.
		 */
		plen = tvb_get_ntohs(tvb, offset + 2);
		if (plen < 8) {
			/*
			 * The length is less than the header length.
			 * Put in the type, status, and length, and
			 * report the length as bogus.
			 */
			if (tree) {
				/* create display subtree for the protocol */
				tds_item = proto_tree_add_item(tree, proto_tds,
				    tvb, offset, -1, FALSE);

				tds_tree = proto_item_add_subtree(tds_item,
				    ett_tds);
				proto_tree_add_uint(tds_tree, hf_tds_type, tvb,
				    offset, 1, type);
				proto_tree_add_item(tds_tree, hf_tds_status,
				    tvb, offset + 1, 1, FALSE);
				proto_tree_add_uint_format(tds_tree,
				    hf_tds_size, tvb, offset + 2, 2, plen,
				    "Size: %u (bogus, should be >= 8)", plen);
			}

			/*
			 * Give up - we can't dissect any more of this
			 * data.
			 */
			break;
		}

		/*
		 * Can we do reassembly?
		 */
		if (tds_desegment && pinfo->can_desegment) {
			/*
			 * Yes - is the PDU split across segment boundaries?
			 */
			if (length_remaining < plen) {
				/*
				 * Yes.  Tell the TCP dissector where the
				 * data for this message starts in the data
				 * it handed us, and how many more bytes we
				 * need, and return.
				 */
				pinfo->desegment_offset = offset;
				pinfo->desegment_len = plen - length_remaining;
				return;
			}
		}

		if (first_time) {
			if (check_col(pinfo->cinfo, COL_PROTOCOL))
				col_set_str(pinfo->cinfo, COL_PROTOCOL, "TDS");

			/*
			 * Set the packet description based on its TDS packet
			 * type.
			 */
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_add_str(pinfo->cinfo, COL_INFO,
				    val_to_str(type, packet_type_names,
				      "Unknown Packet Type: %u"));
			}
			first_time = FALSE;
		}

		/*
		 * Construct a tvbuff containing the amount of the payload
		 * we have available.  Make its reported length the amount
		 * of data in the PDU.
		 *
		 * XXX - if reassembly isn't enabled. the subdissector will
		 * throw a BoundsError exception, rather than a
		 * ReportedBoundsError exception.  We really want a tvbuff
		 * where the length is "length", the reported length is
		 * "plen", and the "if the snapshot length were infinite"
		 * length is the minimum of the reported length of the tvbuff
		 * handed to us and "plen", with a new type of exception
		 * thrown if the offset is within the reported length but
		 * beyond that third length, with that exception getting the
		 * "Unreassembled Packet" error.
		 */
		length = length_remaining;
		if (length > plen)
			length = plen;
		next_tvb = tvb_new_subset(tvb, offset, length, plen);

		/*
		 * Dissect the Netlib buffer.
		 *
		 * Catch the ReportedBoundsError exception; if this
		 * particular Netlib buffer happens to get a
		 * ReportedBoundsError exception, that doesn't mean
		 * that we should stop dissecting PDUs within this frame
		 * or chunk of reassembled data.
		 *
		 * If it gets a BoundsError, we can stop, as there's nothing
		 * more to see, so we just re-throw it.
		 */
		TRY {
			dissect_netlib_buffer(next_tvb, pinfo, tree);
		}
		CATCH(BoundsError) {
			RETHROW;
		}
		CATCH(ReportedBoundsError) {
			show_reported_bounds_error(tvb, pinfo, tree);
		}
		ENDTRY;

		/*
		 * Step to the next Netlib buffer.
		 */
		offset += plen;
	}
}

static gboolean
dissect_tds_tcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	guint8 type;
	guint8 status;
	guint16 plen;
	conversation_t *conv;

	/*
	 * If we don't have even enough data for a Netlib header,
	 * just say it's not TDS.
	 */
	if (!tvb_bytes_exist(tvb, offset, 8))
		return FALSE;

	/*
	 * Quickly scan all the data we have in order to see if
	 * everything in it looks like Netlib traffic.
	 */
	while (tvb_bytes_exist(tvb, offset, 1)) {
		/*
		 * Check the type field.
		 */
		type = tvb_get_guint8(tvb, offset);
		if (!is_valid_tds_type(type))
			return FALSE;

		/*
		 * Check the status field, if it's present.
		 */
		if (!tvb_bytes_exist(tvb, offset + 1, 1))
			break;
		status = tvb_get_guint8(tvb, offset + 1);
		if (!is_valid_tds_status(status))
			return FALSE;

		/*
		 * Get the length of the PDU.
		 */
		if (!tvb_bytes_exist(tvb, offset + 2, 2))
			break;
		plen = tvb_get_ntohs(tvb, offset + 2);
		if (plen < 8) {
			/*
			 * The length is less than the header length.
			 * That's bogus.
			 */
			return FALSE;
		}

		/*
		 * If we're at the beginning of the segment, check the
		 * payload if it's a login packet.
		 */
		if (offset == 0) {
			if (!netlib_check_login_pkt(tvb, offset, pinfo, type))
				return FALSE;
		}

		/*
		 * Step to the next Netlib buffer.
		 */
		offset += plen;
	}

	/*
	 * OK, it passes the test; assume the rest of this conversation
	 * is TDS.
	 */
	conv = find_conversation(&pinfo->src, &pinfo->dst, pinfo->ptype,
            pinfo->srcport, pinfo->destport, 0);
        if (conv == NULL) {
        	/*
        	 * No conversation exists yet - create one.
        	 */
		conv = conversation_new(&pinfo->src, &pinfo->dst,
		    pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
	}
	conversation_set_dissector(conv, tds_tcp_handle);

	/*
	 * Now dissect it as TDS.
	 */
	dissect_tds_tcp(tvb, pinfo, tree);
	return TRUE;
}

static void
tds_init(void)
{
	/*
	 * Initialize the fragment and reassembly tables.
	 */
	fragment_table_init(&tds_fragment_table);
	reassembled_table_init(&tds_reassembled_table);

	/*
	 * Reinitialize the chunks of data for remembering row
	 * information.
	 */
        if (tds_column)
                g_mem_chunk_destroy(tds_column);

        tds_column = g_mem_chunk_new("tds_column", tds_column_length,
                tds_column_init_count * tds_column_length,
                G_ALLOC_AND_FREE);
}

/* Register the protocol with Ethereal */

/* this format is required because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_netlib(void)
{
	static hf_register_info hf[] = {
		{ &hf_tds_type,
			{ "Type",           "tds.type",
			FT_UINT8, BASE_HEX, VALS(packet_type_names), 0x0,
			"Packet Type", HFILL }
		},
		{ &hf_tds_status,
			{ "Status",         "tds.status",
			FT_UINT8, BASE_DEC, VALS(status_names), 0x0,
			"Frame status", HFILL }
		},
		{ &hf_tds_size,
			{ "Size",           "tds.size",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Packet Size", HFILL }
		},
		{ &hf_tds_channel,
			{ "Channel",        "tds.channel",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Channel Number", HFILL }
		},
		{ &hf_tds_packet_number,
			{ "Packet Number",  "tds.packet_number",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Packet Number", HFILL }
		},
		{ &hf_tds_window,
			{ "Window",         "tds.window",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Window", HFILL }
		},
		{ &hf_tds_fragment_overlap,
			{ "Segment overlap",	"tds.fragment.overlap",
			FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"Fragment overlaps with other fragments", HFILL }
		},
		{ &hf_tds_fragment_overlap_conflict,
			{ "Conflicting data in fragment overlap", "tds.fragment.overlap.conflict",
			FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"Overlapping fragments contained conflicting data", HFILL }
		},
		{ &hf_tds_fragment_multiple_tails,
			{ "Multiple tail fragments found", "tds.fragment.multipletails",
			FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"Several tails were found when defragmenting the packet", HFILL }
		},
		{ &hf_tds_fragment_too_long_fragment,
			{ "Segment too long",	"tds.fragment.toolongfragment",
			FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"Segment contained data past end of packet", HFILL }
		},
		{ &hf_tds_fragment_error,
			{ "Defragmentation error",	"tds.fragment.error",
			FT_FRAMENUM, BASE_NONE, NULL, 0x0,
			"Defragmentation error due to illegal fragments", HFILL }
		},
		{ &hf_tds_fragment,
			{ "TDS Fragment",	"tds.fragment",
			FT_FRAMENUM, BASE_NONE, NULL, 0x0,
			"TDS Fragment", HFILL }
		},
		{ &hf_tds_fragments,
			{ "TDS Fragments",	"tds.fragments",
			FT_NONE, BASE_NONE, NULL, 0x0,
			"TDS Fragments", HFILL }
		},
		{ &hf_tds_reassembled_in,
			{ "Reassembled TDS in frame", "tds.reassembled_in",
			FT_FRAMENUM, BASE_NONE, NULL, 0x0,
			"This TDS packet is reassembled in this frame", HFILL }
		},
		{ &hf_tds7_login_total_size,
			{ "Total Packet Length", "tds7login.total_len",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"TDS7 Login Packet total packet length", HFILL }
		},
		{ &hf_tds7_version,
                        { "TDS version", "tds7login.version",
                        FT_UINT32, BASE_HEX, NULL, 0x0,
                        "TDS version", HFILL }
                },
		{ &hf_tds7_packet_size,
                        { "Packet Size", "tds7login.packet_size",
                        FT_UINT32, BASE_DEC, NULL, 0x0,
                        "Packet size", HFILL }
                },
		{ &hf_tds7_client_version,
                        { "Client version", "tds7login.client_version",
                        FT_UINT32, BASE_DEC, NULL, 0x0,
                        "Client version", HFILL }
                },
		{ &hf_tds7_client_pid,
                        { "Client PID", "tds7login.client_pid",
                        FT_UINT32, BASE_DEC, NULL, 0x0,
                        "Client PID", HFILL }
                },
		{ &hf_tds7_connection_id,
                        { "Connection ID", "tds7login.connection_id",
                        FT_UINT32, BASE_DEC, NULL, 0x0,
                        "Connection ID", HFILL }
                },
		{ &hf_tds7_option_flags1,
                        { "Option Flags 1", "tds7login.option_flags1",
                        FT_UINT8, BASE_HEX, NULL, 0x0,
                        "Option Flags 1", HFILL }
                },
		{ &hf_tds7_option_flags2,
                        { "Option Flags 2", "tds7login.option_flags2",
                        FT_UINT8, BASE_HEX, NULL, 0x0,
                        "Option Flags 2", HFILL }
                },
		{ &hf_tds7_sql_type_flags,
                        { "SQL Type Flags", "tds7login.sql_type_flags",
                        FT_UINT8, BASE_HEX, NULL, 0x0,
                        "SQL Type Flags", HFILL }
                },
		{ &hf_tds7_reserved_flags,
                        { "Reserved Flags", "tds7login.reserved_flags",
                        FT_UINT8, BASE_HEX, NULL, 0x0,
                        "reserved flags", HFILL }
                },
		{ &hf_tds7_time_zone,
                        { "Time Zone", "tds7login.time_zone",
                        FT_UINT32, BASE_HEX, NULL, 0x0,
                        "Time Zone", HFILL }
                },
		{ &hf_tds7_collation,
                        { "Collation", "tds7login.collation",
                        FT_UINT32, BASE_HEX, NULL, 0x0,
                        "Collation", HFILL }
                },
	};
	static gint *ett[] = {
		&ett_tds,
		&ett_tds_fragments,
		&ett_tds_fragment,
		&ett_tds_token,
		&ett_tds7_login,
		&ett_tds7_hdr,
	};
	module_t *tds_module;

/* Register the protocol name and description */
	proto_tds = proto_register_protocol("Tabular Data Stream",
	    "TDS", "tds");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_tds, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	tds_tcp_handle = create_dissector_handle(dissect_tds_tcp, proto_tds);

	tds_module = prefs_register_protocol(proto_tds, NULL);
	prefs_register_bool_preference(tds_module, "desegment_buffers",
	    "Desegment all TDS buffers spanning multiple TCP segments",
	    "Whether the TDS dissector should desegment all TDS buffers spanning multiple TCP segments",
	    &tds_desegment);
	prefs_register_bool_preference(tds_module, "defragment",
	    "Defragment all TDS messages with multiple buffers",
	    "Whether the TDS dissector should defragment all messages spanning multiple Netlib buffers",
	    &tds_defragment);

	register_init_routine(tds_init);
}

/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_tds(void)
{
	/* dissector_add("tcp.port", 1433, dissect_tds,
	    proto_tds); */
	heur_dissector_add("tcp", dissect_tds_tcp_heur, proto_tds);

	ntlmssp_handle = find_dissector("ntlmssp");
	data_handle = find_dissector("data");
}
