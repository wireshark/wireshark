/* packet-tds.c
 * Routines for TDS NetLib dissection
 * Copyright 2000-2002, Brian Bruns <camber@ais.org>
 * Copyright 2002, Steve Langasek <vorlon@netexpress.net>
 *
 * $Id: packet-tds.c,v 1.5 2002/11/17 21:47:41 gerald Exp $
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
 * to be placed within different transports (TCP, DECNet, IPX/SPX).  It
 * consist of an eight byte header containing a two byte size field, a last
 * packet indicator, a one byte packet type field, and a 4 byte field used in
 * RPC communications whose purpose is unknown (it is most likely a conversation
 * number to multiplex multiple conversations over a single socket).
 *
 * The TDS protocol consists of a number of protocol data units (PDUs) marked
 * by a one byte field at the start of the PDU.  Some PDUs are fixed length
 * some are variable length with a two byte size field following the type, and
 * then there is TDS_ROW_TOKEN in which size is determined by analyzing the
 * result set returned from the server. This in effect means that we are
 * hopelessly lost if we haven't seen the result set.  Also, TDS 4/5 is byte
 * order negotiable, which is specified in the login packet.  We can attempt to
 * determine it later on, but not with 100% accuracy.
 *
 * Some preliminary documentation on the packet format can be found at
 * http://www.freetds.org/tds.html
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <glib.h>

#include "epan/packet.h"
#include "epan/conversation.h"

#include "packet-smb-common.h"

#define TDS_QUERY_PKT  0x01
#define TDS_LOGIN_PKT  0x02
#define TDS_RESP_PKT   0x04
#define TDS_CANCEL_PKT 0x06
#define TDS_QUERY5_PKT 0x0f
#define TDS_LOGIN7_PKT 0x10

#define is_valid_tds_type(x) \
	(x==TDS_QUERY_PKT || \
	x==TDS_LOGIN_PKT || \
	x==TDS_RESP_PKT || \
	x==TDS_QUERY5_PKT || \
	x==TDS_QUERY5_PKT || \
	x==TDS_LOGIN7_PKT)

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
static int hf_netlib_size = -1;
static int hf_netlib_type = -1;
static int hf_netlib_last = -1;

/* Initialize the subtree pointers */
static gint ett_netlib = -1;
static gint ett_tds = -1;
static gint ett_tds_pdu = -1;
static gint ett_tds7_login = -1;
static gint ett_tds7_hdr = -1;

static heur_dissector_list_t netlib_heur_subdissector_list;

static dissector_handle_t ntlmssp_handle = NULL;

/* These correspond to the netlib packet type field */
static const value_string packet_type_names[] = {
	{TDS_QUERY_PKT, "Query Packet"},
	{TDS_LOGIN_PKT, "Login Packet"},
	{TDS_RESP_PKT, "Response Packet"},
	{TDS_CANCEL_PKT, "Cancel Packet"},
	{TDS_QUERY5_PKT, "TDS5 Query Packet"},
	{TDS_LOGIN7_PKT, "TDS7/8 Login Packet"},
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
#define REM_BUF_SIZE 4096

/*
 * this is where we store the column information to be used in decoding the
 * TDS_ROW_TOKEN PDU's
 */
struct _tds_col {
     gchar name[256];
     guint16 utype;
     guint8 ctype;
     guint csize;
};

/*
 * The first time ethereal decodes a stream it calls each packet in order.
 * We use this structure to pass data from the dissection of one packet to
 * the next.  After the initial dissection, this structure is largely unused.
 */
struct _conv_data {
	guint netlib_unread_bytes;
	guint num_cols;
	struct _tds_col *columns[MAX_COLUMNS];
	guint tds_bytes_left;
	guint8 tds_remainder[REM_BUF_SIZE];
};

/*
 * Now on the first dissection of a packet copy the global (_conv_data)
 * to the packet data so that we may retrieve out of order later.
 */
struct _packet_data {
	guint netlib_unread_bytes;
	guint num_cols;
	struct _tds_col *columns[MAX_COLUMNS];
	guint tds_bytes_left;
	guint8 tds_remainder[REM_BUF_SIZE];
};

/*
 * and finally a place for netlib packets within tcp packets
 */
struct _netlib_data {
	guint8 packet_type;
	guint8 packet_last;
	guint16 packet_size;
	guint netlib_unread_bytes;
	guint num_cols;
	struct _tds_col *columns[MAX_COLUMNS];
	guint tds_bytes_left;
	guint8 tds_remainder[REM_BUF_SIZE];
};

/* all the standard memory management stuff */
#define netlib_win_length (sizeof(struct _conv_data))
#define netlib_packet_length (sizeof(struct _packet_data))
#define tds_column_length (sizeof(struct _tds_col))

#define netlib_win_init_count 4
#define netlib_packet_init_count 10
#define tds_column_init_count 10

static GMemChunk *netlib_window = NULL;
static GMemChunk *netlib_pdata = NULL;
static GMemChunk *tds_column = NULL;

static void netlib_reinit(void);

/* support routines */
static void dissect_tds_ntlmssp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint length)
{
	tvbuff_t *ntlmssp_tvb = NULL;

	ntlmssp_tvb = tvb_new_subset(tvb, offset, length, length);

	add_new_data_source(pinfo, ntlmssp_tvb, "NTLMSSP Data");
	call_dissector(ntlmssp_handle, ntlmssp_tvb, pinfo, tree);
}

static void dissect_tds7_login(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint length)
{
	guint offset, i, offset2, len;
	guint16 bc;
	gboolean is_unicode = TRUE;
	const char *val;

	proto_item *login_hdr;
	proto_tree *login_tree;
	proto_item *header_hdr;
	proto_tree *header_tree;

	tvbuff_t *tds7_tvb;

	length -= 8;

	tds7_tvb = tvb_new_subset(tvb, 8, length, length);
	offset = 36;

	/* create display subtree for the protocol */
	login_hdr = proto_tree_add_text(tree, tds7_tvb, 0, length,
		"TDS7 Login Packet");
	login_tree = proto_item_add_subtree(login_hdr, ett_tds7_login);

	header_hdr = proto_tree_add_text(login_tree, tds7_tvb, offset, 50, "Login Packet Header");
	header_tree = proto_item_add_subtree(header_hdr, ett_tds7_hdr);
	for (i = 0; i < 9; i++) {
		offset2 = tvb_get_letohs(tds7_tvb, offset + i*4);
		len = tvb_get_letohs(tds7_tvb, offset + i*4 + 2);
		proto_tree_add_text(header_tree, tds7_tvb, offset + i*4, 2,
			"%s offset: %d",val_to_str(i,login_field_names,"Unknown"),
			offset2);
		proto_tree_add_text(header_tree, tds7_tvb, offset + i*4 + 2, 2,
			"%s length: %d",val_to_str(i,login_field_names,"Unknown"),
			len);
		if (len > 0) {
			if (is_unicode == TRUE)
				len *= 2;
			val = get_unicode_or_ascii_string(tds7_tvb, &offset2,
				is_unicode, &len, TRUE, TRUE, &bc);
			proto_tree_add_text(login_tree, tds7_tvb, offset2, len,
				"%s: %s", val_to_str(i, login_field_names, "Unknown"), val);
		}
	}

	if (offset2 + len < length) {
		dissect_tds_ntlmssp(tds7_tvb, pinfo, login_tree, offset2 + len, length - offset2);
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
 * This function computes the number of bytes remaining from a PDU started in
 * the previous netlib packet.
 * XXX - needs some more PDU types added.
 */
static int
get_skip_count(tvbuff_t *tvb, guint offset, struct _netlib_data *nl_data, guint last_byte)
{
guint8 token;
guint i;
int csize;
unsigned int cur;
const guint8 *buf;
int switched = 0;

     /* none leftover? none to skip */
     if (!nl_data->tds_bytes_left)
          return 0;

     token = nl_data->tds_remainder[0];
     switch (token) {
          case TDS_ROW_TOKEN:
               buf = nl_data->tds_remainder;
               cur = 1;
               for (i = 0; i < nl_data->num_cols; i++) {
                    if (! is_fixed_coltype(nl_data->columns[i]->ctype)) {
                         if (!switched && cur >= nl_data->tds_bytes_left) {
                              switched = 1;
                              cur = cur - nl_data->tds_bytes_left;
                              buf = tvb_get_ptr(tvb, offset, tvb_length(tvb)-offset);
                         }
                         csize = buf[cur];
                         cur ++;
                    } else {
                         csize = get_size_by_coltype(nl_data->columns[i]->ctype);
                    }
/* printf("2value %d %d %d %s\n", i, cur, csize, data_to_string(&buf[cur], nl_data->columns[i]->ctype, csize));  */
                    cur += csize;
                    if (switched && cur > last_byte - offset)
			return -1;
               }
               return cur;
               break;
          default:
#ifdef DEBUG
               printf("unhandled case for token %d\n",token);
#else
		;
#endif
     }
     return 0;
}

/*
 * Since rows are special PDUs in that they are not fixed and lack a size field,
 * the length must be computed using the column information seen in the result
 * PDU. This function does just that.
 */
static size_t
tds_get_row_size(tvbuff_t *tvb, struct _netlib_data *nl_data, guint offset, guint last_byte)
{
guint cur, i, csize;

     cur = offset;
     for (i=0;i<nl_data->num_cols;i++) {
          if (! is_fixed_coltype(nl_data->columns[i]->ctype)) {
               if (cur>=last_byte) return 0;
               csize = tvb_get_guint8(tvb,cur);
               cur ++;
          } else {
               csize = get_size_by_coltype(nl_data->columns[i]->ctype);
          }
          cur += csize;
     }
     if (cur>last_byte) return 0;

     return (cur - offset + 1);
}
/*
 * read the results PDU and store the relevent information in the _netlib_data
 * structure for later use (see tds_get_row_size)
 * XXX - assumes that result token will be entirely contained within packet
 * boundary
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
	 * This would be the logical place to check for little/big endianess if we
	 * didn't see the login packet.
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

		cur ++; /* unknown */

		nl_data->columns[i]->utype = tvb_get_letohs(tvb, cur);
		cur += 2;

		cur += 2; /* unknown */

		nl_data->columns[i]->ctype = tvb_get_guint8(tvb,cur);
		cur ++;

		if (!is_fixed_coltype(nl_data->columns[i]->ctype)) {
			nl_data->columns[i]->csize = tvb_get_guint8(tvb,cur);
			cur ++;
		} else {
			nl_data->columns[i]->csize = get_size_by_coltype(nl_data->columns[i]->ctype);
		}
		cur ++; /* unknown */
	}
	return TRUE;
}
/*
 * This function copies information about data crossing the netlib packet
 * boundary from _netlib_data to _conv_data it is called at the end of packet
 * dissection during the first decoding.
 */
void
store_conv_data(packet_info *pinfo, struct _netlib_data *nl_data)
{
	conversation_t *conv;
	struct _conv_data *conv_data;

	/* check for an existing conversation */
	conv = find_conversation (&pinfo->src, &pinfo->dst, pinfo->ptype,
		pinfo->srcport, pinfo->destport, 0);

	conv_data = conversation_get_proto_data(conv,proto_tds);
	/* first packet seen ? */
	if (!conv_data) {
		conv_data = g_mem_chunk_alloc(netlib_window);
	}
	conv_data->netlib_unread_bytes = nl_data->netlib_unread_bytes;
        conv_data->num_cols = nl_data->num_cols;
        memcpy(conv_data->columns, nl_data->columns, sizeof(struct _tds_col *) * MAX_COLUMNS);
        conv_data->tds_bytes_left = nl_data->tds_bytes_left;
        memcpy(conv_data->tds_remainder, nl_data->tds_remainder, REM_BUF_SIZE);

	conversation_add_proto_data(conv,proto_tds, conv_data);
}
/*
 * This function copies information about data crossing the netlib packet
 * boundary from _netlib_data to _pkt_data it is called after load_nelib_data
 * during packet dissection when the packet has not previously been seen.
 */
void
store_pkt_data(packet_info *pinfo, struct _netlib_data *nl_data)
{
	struct _packet_data *p_data;

	p_data = p_get_proto_data(pinfo->fd, proto_tds);

	/* only store it the first time through */
	if (p_data) {
		return;
	}

	p_data = g_mem_chunk_alloc(netlib_pdata);

	/* copy the data */
	p_data->netlib_unread_bytes = nl_data->netlib_unread_bytes;
        p_data->num_cols = nl_data->num_cols;
        memcpy(p_data->columns, nl_data->columns, sizeof(struct _tds_col *) * MAX_COLUMNS);
        p_data->tds_bytes_left = nl_data->tds_bytes_left;
        memcpy(p_data->tds_remainder, nl_data->tds_remainder, REM_BUF_SIZE);

	/* stash it */
	p_add_proto_data( pinfo->fd, proto_tds, (void*)p_data);
}
/* load conversation data into packet_data */
void
load_packet_data(packet_info *pinfo, struct _packet_data *pkt_data)
{
	conversation_t *conv;
	struct _conv_data *conv_data;

	/* check for an existing conversation */
	conv = find_conversation (&pinfo->src, &pinfo->dst, pinfo->ptype,
		pinfo->srcport, pinfo->destport, 0);

	conv_data = conversation_get_proto_data(conv,proto_tds);
	/* first packet seen ? */
	if (!conv_data) {
		/* just zero it */
		memset(pkt_data, 0, sizeof(struct _packet_data));
		return;
	}
	pkt_data->netlib_unread_bytes = conv_data->netlib_unread_bytes;
        pkt_data->num_cols = conv_data->num_cols;
        memcpy(pkt_data->columns, conv_data->columns, sizeof(struct _tds_col *) * MAX_COLUMNS);
        pkt_data->tds_bytes_left = conv_data->tds_bytes_left;
        memcpy(pkt_data->tds_remainder, conv_data->tds_remainder, REM_BUF_SIZE);

}
/* load packet data into netlib_data */
void
load_netlib_data(packet_info *pinfo, struct _netlib_data *nl_data)
{
	struct _packet_data *pkt_data;

	pkt_data = p_get_proto_data(pinfo->fd, proto_tds);
	/* wtf? */
	if (!pkt_data) {
		return;
	}
	nl_data->netlib_unread_bytes = pkt_data->netlib_unread_bytes;
        nl_data->num_cols = pkt_data->num_cols;
        memcpy(nl_data->columns, pkt_data->columns, sizeof(struct _tds_col *) * MAX_COLUMNS);
        nl_data->tds_bytes_left = pkt_data->tds_bytes_left;
        memcpy(nl_data->tds_remainder, pkt_data->tds_remainder, REM_BUF_SIZE);
}


/*
 * read the eight byte netlib header, write the interesting parts into
 * netlib_data, and return false if this is illegal (for heuristics)
 */
static gboolean
netlib_read_header(tvbuff_t *tvb, guint offset, struct _netlib_data *nl_data)
{
	nl_data->packet_type = tvb_get_guint8( tvb, offset);
	nl_data->packet_last = tvb_get_guint8( tvb, offset+1);
	nl_data->packet_size = tvb_get_ntohs( tvb, offset+2);

	/* do validity checks on header fields */

	if (!is_valid_tds_type(nl_data->packet_type)) {
		return FALSE;
	}
	/* Valid values are 0 and 1 */
	if (nl_data->packet_last > 1) {
		return FALSE;
	}
	if (nl_data->packet_size == 0) {
		return FALSE;
	}
	/*
	if (tvb_length(tvb) != nl_data->packet_size) {
		return FALSE;
	}
	*/
	return TRUE;
}

/*
 * If the packet type from the netlib header is a login packet, then dig into
 * the packet to see if this is a supported TDS version and verify the otherwise
 * weak heuristics of the netlib check.
 */
static gboolean
netlib_check_login_pkt(tvbuff_t *tvb, guint offset, packet_info *pinfo, struct _netlib_data *nl_data)
{
	guint tds_major, bytes_avail;

	bytes_avail = tvb_length(tvb) - offset;

	/*
	 * we have two login packet styles, one for TDS 4.2 and 5.0
	 */
	if (nl_data->packet_type==TDS_LOGIN_PKT) {
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
	} else if (nl_data->packet_type==TDS_LOGIN7_PKT) {
		if (bytes_avail < 16) return FALSE;
		tds_major = tvb_get_guint8(tvb, 15);
		if (tds_major != 0x70 && tds_major != 0x80) {
			return FALSE;
		}
	} else if (nl_data->packet_type==TDS_QUERY5_PKT) {
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
	} else {
	}
	return TRUE;
}

static gboolean
dissect_tds_env_chg(tvbuff_t *tvb, struct _netlib_data *nl_data _U_, guint offset, guint last_byte _U_, proto_tree *tree)
{
guint8 env_type;
guint packet_len;
guint old_len, new_len, old_len_offset;
const char *new_val = NULL, *old_val = NULL;
guint32 string_offset;
guint16 bc;
gboolean is_unicode = FALSE;

	/* FIXME: if we have to take a negative offset, isn't that
	   defeating the purpose? */
	packet_len = tvb_get_letohs(tvb, offset - 2);

	env_type = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 1, "Type: %d (%s)", env_type,
		val_to_str(env_type, env_chg_names, "Unknown"));

	new_len = tvb_get_guint8(tvb, offset+1);
	old_len_offset = offset + new_len + 2;
	old_len = tvb_get_guint8(tvb, old_len_offset);

	/* If our lengths don't add up to the packet length, it must be UCS2. */
	if (old_len + new_len + 3 != packet_len) {
		is_unicode = TRUE;
		old_len_offset = offset + (new_len * 2) + 2;
		old_len = tvb_get_guint8(tvb, old_len_offset);
	}

	proto_tree_add_text(tree, tvb, offset + 1, 1, "New Value Length: %d", new_len);
	if (new_len) {
		if (is_unicode == TRUE) {
			new_len *= 2;
		}
		string_offset = offset + 2;
		new_val = get_unicode_or_ascii_string(tvb, &string_offset,
		                            is_unicode, &new_len,
		                            TRUE, TRUE, &bc);

		proto_tree_add_text(tree, tvb, string_offset, new_len, "New Value: %s", new_val);
	}

	proto_tree_add_text(tree, tvb, old_len_offset, 1, "Old Value Length: %d", old_len);
	if (old_len) {
		if (is_unicode == TRUE) {
			old_len *= 2;
		}
		string_offset = old_len_offset + 1;
		old_val = get_unicode_or_ascii_string(tvb, &string_offset,
		                            is_unicode, &old_len,
		                            TRUE, TRUE, &bc);

		proto_tree_add_text(tree, tvb, string_offset, old_len, "Old Value: %s", old_val);
	 }

	 return TRUE;
}

/* note that dissect_tds is called only for TDS_RESP_PKT netlib packets */
static void
dissect_tds(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, struct _netlib_data *nl_data, guint offset)
{
proto_item *ti;
proto_item *tds_hdr;
proto_tree *tds_tree;
guint last_byte, end_of_pkt;
guint pos, token_sz = 0;
guint8 token;
gint skip_count;
proto_tree *pdu_tree;

	/*
	 * if we have unprocessed bytes from the previous dissection then we deal
	 * those first.
	 */
	if (nl_data->netlib_unread_bytes) {
		end_of_pkt = nl_data->netlib_unread_bytes;
	} else {
		/*
		 * otherwise the end of the packet is where we are now plus the
		 * packet_size minus the 8 header bytes.
		 */
		end_of_pkt = offset + nl_data->packet_size - 8;
	}

	/*
	 * the last byte to dissect is the end of the netlib packet or the end of
	 * the tcp packet (tvb buffer) which ever comes first
	 */
	last_byte = tvb_length(tvb) > end_of_pkt ? end_of_pkt : tvb_length(tvb);

	/* create an item to make a TDS tree out of */
	tds_hdr = proto_tree_add_text(tree, tvb, offset, last_byte - offset,
		"TDS Data");
	tds_tree = proto_item_add_subtree(tds_hdr, ett_tds);

	/* is there the second half of a PDU here ? */
	if (nl_data->tds_bytes_left > 0) {
		/* XXX - should be calling dissection here */
		skip_count = get_skip_count(tvb, offset, nl_data, last_byte);

		/*
		 * we started with left overs and the data continues to the end of
		 * this packet.  Just add it on, and skip to the next packet
		 */
		if (skip_count == -1) {
			token = nl_data->tds_remainder[0];
			token_sz = last_byte - offset;
			ti = proto_tree_add_text(tds_tree, tvb, offset, token_sz,
                    		"Token 0x%02x %s (continued)",  token, val_to_str(token, token_names,
                		"Unknown Token Type"));
			tvb_memcpy( tvb, &nl_data->tds_remainder[nl_data->tds_bytes_left],
				offset, token_sz);
			nl_data->tds_bytes_left += token_sz;
			nl_data->netlib_unread_bytes = 0;
			return;
		}

		/* show something in the tree for this data */
		token = nl_data->tds_remainder[0];
		ti = proto_tree_add_text(tds_tree, tvb, offset, skip_count,
                   	"Token 0x%02x %s (continued)",  token, val_to_str(token, token_names,
                	"Unknown Token Type"));
		offset += skip_count;
	}

	/* Ok, all done with the fragments, start clean */
	nl_data->tds_bytes_left = 0;
	nl_data->netlib_unread_bytes = 0;

	/* until we reach the end of the netlib packet or this buffer, read PDUs */
	pos = offset;
	while (pos < last_byte) {
		/* our PDU token */
		token = tvb_get_guint8(tvb, pos);

		if (tds_is_fixed_token(token)) {
			token_sz = tds_get_token_size(token) + 1;
		/* rows are special, they have no size field and aren't fixed length */
		} else if (token == TDS_ROW_TOKEN) {

			token_sz = tds_get_row_size(tvb, nl_data, pos + 1, last_byte);

			if (! token_sz) {
				/*
				 * partial row, set size to end of packet and stash
				 * the top half for the next packet dissection
				 */
				token_sz = last_byte - pos;
				nl_data->tds_bytes_left = token_sz;
				tvb_memcpy(tvb, nl_data->tds_remainder, pos, token_sz);
			}

		} else {
			token_sz = tvb_get_letohs(tvb, pos+1) + 3;
		}

		ti = proto_tree_add_text(tds_tree, tvb, pos, token_sz,
                    "Token 0x%02x %s",  token, val_to_str(token, token_names,
                "Unknown Token Type"));
		pdu_tree = proto_item_add_subtree(ti, ett_tds_pdu);

		/* if it's a variable token do it here instead of replicating this
		 * for each subdissector */
		if (! tds_is_fixed_token(token) && token != TDS_ROW_TOKEN) {
			proto_tree_add_text(pdu_tree, tvb, pos+1, 2,
			"Length: %d", tvb_get_letohs(tvb, pos+1));
		}


		/* XXX - call subdissector here */
		switch (token) {
			/* if it's a result token we need to stash the column info */
			case TDS_RESULT_TOKEN:
				read_results_tds5(tvb, nl_data, pos);
			break;
			case TDS_ENV_CHG_TOKEN:
				dissect_tds_env_chg(tvb, nl_data, pos + 3, last_byte, pdu_tree);
			break;
			case TDS_AUTH_TOKEN:
				dissect_tds_ntlmssp(tvb, pinfo, pdu_tree, pos + 3, last_byte - pos - 3);
			break;
		}

		/* and step to the end of the PDU, rinse, lather, repeat */
		pos += token_sz;

	}

}
static void
dissect_netlib_hdr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, struct _netlib_data *nl_data, guint offset)
{
	proto_item *netlib_hdr;
	proto_tree *netlib_tree;
	guint bytes_remaining, bytes_avail;

	bytes_remaining = tvb_length(tvb) - offset;
	bytes_avail = bytes_remaining > nl_data->packet_size ?
		nl_data->packet_size : bytes_remaining;


	/* In the interest of speed, if "tree" is NULL, don't do any work not
	 * necessary to generate protocol tree items. */
	if (tree) {

		/* create display subtree for the protocol */
		netlib_hdr = proto_tree_add_text(tree, tvb, offset, bytes_avail,
                    "Netlib Header");

		netlib_tree = proto_item_add_subtree(netlib_hdr, ett_netlib);
		proto_tree_add_text(netlib_tree, tvb, offset, 1, "Packet Type: %02x %s",
			nl_data->packet_type, val_to_str(nl_data->packet_type,
			packet_type_names, "Unknown Packet Type"));
		proto_tree_add_uint(netlib_tree, hf_netlib_last, tvb, offset+1, 1,
			nl_data->packet_last);
		proto_tree_add_uint(netlib_tree, hf_netlib_size, tvb, offset+2, 2,
			nl_data->packet_size);
	}
}

/* Code to actually dissect the packets */
static gboolean
dissect_netlib(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

/* Set up structures needed to add the protocol subtree and manage it */
	conversation_t *conv;
	struct _netlib_data nl_data;
	struct _packet_data *p_data;
	guint offset = 0;
	guint bytes_remaining;

	p_data = p_get_proto_data(pinfo->fd, proto_tds);

        /* check for an existing conversation */
        conv = find_conversation (&pinfo->src, &pinfo->dst, pinfo->ptype,
                pinfo->srcport, pinfo->destport, 0);

	/*
	 * we don't know if this is our packet yet, so do nothing if we don't have
	 * a conversation.
	 */
	if (conv) {

		/* only copy from conv_data to p_data if we've never seen this before */
	        if (!p_data) {
       		       	p_data = g_mem_chunk_alloc(netlib_pdata);
			load_packet_data(pinfo, p_data);
       			p_add_proto_data( pinfo->fd, proto_tds, (void*)p_data);
		}
		offset = p_data->netlib_unread_bytes;
	}

#ifdef DEBUG
		printf("offset = %d\n", offset);
#endif

	load_netlib_data(pinfo, &nl_data);

	/*
	 * if offset is > 0 then we have undecoded data at the front of the
	 * packet.  Call the TDS dissector on it.
 	 */
	if (nl_data.packet_type == TDS_RESP_PKT && offset > 0) {
		dissect_tds(tvb, pinfo, tree, &nl_data, 0);
	}

	bytes_remaining = tvb_length(tvb) - offset;

	while (bytes_remaining > 0) {

		/*
		 * if packet is less than 8 characters, its not a
		 * netlib packet
		 * XXX - This is not entirely correct...fix.
		 */
		if (bytes_remaining < 8) {
			return FALSE;
		}

		/* read header fields and check their validity */
		if (!netlib_read_header(tvb, offset, &nl_data))
			return FALSE;

		/* If we don't have a conversation is this a TDS stream? */
		if (conv == NULL) {
			if (!netlib_check_login_pkt(tvb, offset, pinfo, &nl_data)) {
				return FALSE;
			}
			/* first packet checks out, create a conversation */
			conv = conversation_new (&pinfo->src, &pinfo->dst,
				pinfo->ptype, pinfo->srcport, pinfo->destport,
				0);
		}

		/* dissect the header */
		dissect_netlib_hdr(tvb, pinfo, tree, &nl_data, offset);

		/* if this is a response packet decode it further */
		if (nl_data.packet_type == TDS_RESP_PKT) {
			dissect_tds(tvb, pinfo, tree, &nl_data, offset+8);
		} else if (nl_data.packet_type == TDS_LOGIN7_PKT) {
			dissect_tds7_login(tvb, pinfo, tree, nl_data.packet_size);
		} else {
			/* we don't want to track left overs for non-response packets */
			nl_data.tds_bytes_left = 0;
		}

		/* now all the checking is done, we are a TDS stream */
		offset += nl_data.packet_size;

		bytes_remaining = tvb_length(tvb) - offset;
	}
	nl_data.netlib_unread_bytes = offset - tvb_length(tvb);

	/*
	 * copy carry over data to the conversation buffer, to retrieve at beginning
         * of next packet
	 */
	store_conv_data(pinfo, &nl_data);

/* Make entries in Protocol column and Info column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "TDS");


	/* set the packet description based on its TDS packet type */
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
                        val_to_str(nl_data.packet_type, packet_type_names,
				"Unknown Packet Type: %u"));
	}


	return TRUE;
}


/* Register the protocol with Ethereal */

/* this format is required because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_netlib(void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_netlib_size,
			{ "Size",           "netlib.size",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Packet Size", HFILL }
		},
		{ &hf_netlib_type,
			{ "Type",           "netlib.type",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"Packet Type", HFILL }
		},
		{ &hf_netlib_last,
			{ "Last Packet",           "netlib.last",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Last Packet Indicator", HFILL }
		},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_netlib,
		&ett_tds,
		&ett_tds_pdu,
		&ett_tds7_login,
		&ett_tds7_hdr,
	};

/* Register the protocol name and description */
	proto_tds = proto_register_protocol("Tabular Data Stream",
	    "TDS", "tds");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_tds, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_init_routine(&netlib_reinit);

	register_heur_dissector_list("netlib", &netlib_heur_subdissector_list);
}

static void netlib_reinit( void){

/* Do the cleanup work when a new pass through the packet list is       */
/* performed. re-initialize the  memory chunks.                         */

/* mostly ripped from packet-wcp.c -- bsb */

        if (netlib_window)
                g_mem_chunk_destroy(netlib_window);

        netlib_window = g_mem_chunk_new("netlib_window", netlib_win_length,
                netlib_win_init_count * netlib_win_length,
                G_ALLOC_AND_FREE);

        if (netlib_pdata)
                g_mem_chunk_destroy(netlib_pdata);

        netlib_pdata = g_mem_chunk_new("netlib_pdata", netlib_packet_length,
                netlib_packet_init_count * netlib_packet_length,
                G_ALLOC_AND_FREE);

        if (tds_column)
                g_mem_chunk_destroy(tds_column);

        tds_column = g_mem_chunk_new("tds_column", tds_column_length,
                tds_column_init_count * tds_column_length,
                G_ALLOC_AND_FREE);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_netlib(void)
{
	/* dissector_add("tcp.port", 1433, dissect_netlib,
	    proto_netlib); */
	heur_dissector_add ("tcp", dissect_netlib, proto_tds);

	ntlmssp_handle = find_dissector("ntlmssp");
}


