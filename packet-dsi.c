/* packet-dsi.c
 * Routines for dsi packet dissection
 * Copyright 2001, Randy McEoin <rmceoin@pe.com>
 *
 * $Id: packet-dsi.c,v 1.2 2001/06/18 02:17:46 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c
 *
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>
#include "packet.h"
#include "strutil.h"
#include "conversation.h"

/* The information in this module (DSI) comes from:

  AFP 2.1 & 2.2.pdf contained in AppleShare_IP_6.3_SDK
  available from http://www.apple.com

  The netatalk source code by Wesley Craig & Adrian Sun

 * What a Data Stream Interface packet looks like:
 * 0                               32
 * |-------------------------------|
 * |flags  |command| requestID     |
 * |-------------------------------|
 * |error code/enclosed data offset|
 * |-------------------------------|
 * |total data length              |
 * |-------------------------------|
 * |reserved field                 |
 * |-------------------------------|
*/

static int proto_dsi = -1;
static int hf_dsi_flags = -1;
static int hf_dsi_command = -1;
static int hf_dsi_requestid = -1;
static int hf_dsi_code = -1;
static int hf_dsi_length = -1;
static int hf_dsi_reserved = -1;

static gint ett_dsi = -1;

#define TCP_PORT_DSI			548

/* DSI flags */
#define DSIFL_REQUEST    0x00
#define DSIFL_REPLY      0x01
#define DSIFL_MAX        0x01

/* DSI Commands */
#define DSIFUNC_CLOSE   1       /* DSICloseSession */
#define DSIFUNC_CMD     2       /* DSICommand */
#define DSIFUNC_STAT    3       /* DSIGetStatus */
#define DSIFUNC_OPEN    4       /* DSIOpenSession */
#define DSIFUNC_TICKLE  5       /* DSITickle */
#define DSIFUNC_WRITE   6       /* DSIWrite */
#define DSIFUNC_ATTN    8       /* DSIAttention */
#define DSIFUNC_MAX     8       /* largest command */

static const value_string flag_vals[] = {
  {DSIFL_REQUEST,	"Request" },
  {DSIFL_REPLY,		"Reply" },
  {0,			NULL } };

static const value_string func_vals[] = {
  {DSIFUNC_CLOSE,	"CloseSession" },
  {DSIFUNC_CMD,		"Command" },
  {DSIFUNC_STAT,	"GetStatus" },
  {DSIFUNC_OPEN,	"OpenSession" },
  {DSIFUNC_TICKLE,	"Tickle" },
  {DSIFUNC_WRITE,	"Write" },
  {DSIFUNC_ATTN,	"Attention" },
  {0,			NULL } };


static GMemChunk *vals = NULL;

typedef struct {
	int	state;
	guint8	flags,command;
	guint16	requestid;
	guint32	code;
	guint32	length;		/* total length of this DSI request/reply */
	guint32	reserved;
	guint32	seen;		/* bytes seen so far */
}hash_entry_t;

enum {NONE,FIRSTDATA,MOREDATA,DONE};

#define hash_init_count 20
#define hash_val_length (sizeof(hash_entry_t))

static guint32 last_abs_sec = 0;
static guint32 last_abs_usec= 0;
static guint32 highest_num = 0;

/* Hash functions */
gint  dsi_equal (gconstpointer v, gconstpointer v2);
guint dsi_hash  (gconstpointer v);
 
static guint dsi_packet_init_count = 200;

typedef struct {
	guint32	packetnum;
} dsi_request_key;
 
typedef struct {
	guint8	flags;
	guint8	command;
	guint16	requestid;
	guint32	length;
	guint32	seen;		/* bytes seen so far, including this packet */
} dsi_request_val;
 
static GHashTable *dsi_request_hash = NULL;
static GMemChunk *dsi_request_keys = NULL;
static GMemChunk *dsi_request_records = NULL;

/* Hash Functions */
gint  dsi_equal (gconstpointer v, gconstpointer v2)
{
	dsi_request_key *val1 = (dsi_request_key*)v;
	dsi_request_key *val2 = (dsi_request_key*)v2;

	if (val1->packetnum == val2->packetnum) {
		return 1;
	}
	return 0;
}

guint dsi_hash  (gconstpointer v)
{
        dsi_request_key *dsi_key = (dsi_request_key*)v;
        return GPOINTER_TO_UINT(dsi_key->packetnum);
}

void
dsi_hash_insert(guint32 packetnum, guint8 flags, guint8 command,
	guint16 requestid, guint32 length, guint32 seen)
{
	dsi_request_val         *request_val;
	dsi_request_key         *request_key;

	/* Now remember info about this continuation packet */

	request_key = g_mem_chunk_alloc(dsi_request_keys);
	request_key->packetnum = packetnum;

	request_val = g_mem_chunk_alloc(dsi_request_records);
	request_val->flags = flags;
	request_val->command = command;
	request_val->requestid = requestid;
	request_val->length = length;
	request_val->seen = seen;

	g_hash_table_insert(dsi_request_hash, request_key, request_val);
}

/* Returns TRUE or FALSE. If TRUE, the record was found */

gboolean
dsi_hash_lookup(guint32 packetnum, guint8 *flags, guint8 *command,
                guint16 *requestid, guint32 *length, guint32 *seen)
{
	dsi_request_val         *request_val;
	dsi_request_key         request_key;

	request_key.packetnum = packetnum;

	request_val = (dsi_request_val*)
		g_hash_table_lookup(dsi_request_hash, &request_key);

	if (request_val) {
		*flags		= request_val->flags;
		*command	= request_val->command;
		*requestid	= request_val->requestid;
		*length		= request_val->length;
		*seen		= request_val->seen;
		return TRUE;
	}
	else {
		return FALSE;
	}
}

/* The state_machine remembers information about continuation packets */
/* returns TRUE if it found a previously known continuation packet */
gboolean
dsi_state_machine( hash_entry_t *hash_info, tvbuff_t *tvb, packet_info *pinfo,
	int offset)
{
	frame_data *fd;
	guint32	data_here;
	guint8	flags,command;
	guint16	requestid;
	guint32	length;
	guint32	seen;
	gboolean found_hash;

	fd=pinfo->fd;

	found_hash=dsi_hash_lookup(fd->num, &flags, &command, &requestid,
		&length, &seen);
	if (found_hash==TRUE)
	{
		hash_info->flags = flags;
		hash_info->command = command;
		hash_info->requestid = requestid;
		hash_info->length = length;
		hash_info->seen = seen;
		return TRUE;
	}

	/* is this sequentially the next packet? */
	if (highest_num > fd->num)
	{
		hash_info->state = NONE;
		return FALSE;
	}

	highest_num = fd->num;

	if ((hash_info->state == NONE) || (hash_info->state == DONE))
	{
		hash_info->state = NONE;
		hash_info->length = tvb_get_ntohl(tvb, offset+8);
		data_here = tvb_length_remaining(tvb, offset+16);
		if (data_here < hash_info->length)
		{
			hash_info->flags = tvb_get_guint8(tvb, offset);
			hash_info->command = tvb_get_guint8(tvb, offset+1);
			hash_info->requestid = tvb_get_ntohs(tvb, offset+2);
			hash_info->code = tvb_get_ntohl(tvb, offset+4);
			hash_info->reserved = tvb_get_ntohl(tvb, offset+12);
			hash_info->seen = data_here;
			hash_info->state = FIRSTDATA;
		}
		return FALSE;
	}


	if (hash_info->state == FIRSTDATA)
		hash_info->state = MOREDATA;

	/* we must be receiving more data */
	data_here = tvb_length_remaining(tvb, offset);
	hash_info->seen += data_here;
	if (hash_info->seen >= hash_info->length)
		hash_info->state = DONE;

	dsi_hash_insert(fd->num, hash_info->flags,
		hash_info->command, hash_info->requestid,
		hash_info->length,hash_info->seen);

	return FALSE;
}

static void
dissect_dsi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        proto_tree      *dsi_tree;
	proto_item	*ti;
	conversation_t	*conversation;
	hash_entry_t	*hash_info;
	gint		offset = 0;
	gboolean	prev_cont;	/* TRUE if a previously known
					* continuation packet */
	char		cont_str[256];

	gchar	*flag_str;
	gchar	*func_str;
	guint8	dsi_flags,dsi_command;
	guint16 dsi_requestid;
	guint32 dsi_code;
	guint32 dsi_length;
	guint32 dsi_reserved;
 
	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_set_str(pinfo->fd, COL_PROTOCOL, "DSI");
	if (check_col(pinfo->fd, COL_INFO))
		col_clear(pinfo->fd, COL_INFO);

	conversation = find_conversation(&pinfo->src, &pinfo->dst, PT_TCP,
		pinfo->srcport, pinfo->destport, 0);
	if (conversation == NULL) {
		hash_info = g_mem_chunk_alloc(vals);
		hash_info->state = NONE;
		conversation = conversation_new(&pinfo->src, &pinfo->dst,
			pinfo->ptype, pinfo->srcport, pinfo->destport,
			hash_info, 0);

		conversation_set_dissector(conversation, dissect_dsi);
	}else
	{
		hash_info = conversation->data;
	}

	prev_cont=dsi_state_machine( hash_info, tvb, pinfo, offset);

	if ((hash_info->state == NONE) && (prev_cont!=TRUE))
	{
		dsi_flags = tvb_get_guint8(tvb, offset);
		dsi_command = tvb_get_guint8(tvb, offset+1);
		dsi_requestid = tvb_get_ntohs(tvb, offset+2);
		dsi_code = tvb_get_ntohl(tvb, offset+4);
		dsi_length = tvb_get_ntohl(tvb, offset+8);
		dsi_reserved = tvb_get_ntohl(tvb, offset+12);
	}else
	{
		dsi_flags = hash_info->flags;
		dsi_command = hash_info->command;
		dsi_requestid = hash_info->requestid;
		dsi_code = hash_info->code;
		dsi_length = hash_info->length;
		dsi_reserved = hash_info->reserved;
	}

	if (check_col(pinfo->fd, COL_INFO)) {
		if ((func_str = match_strval(dsi_command, func_vals)))
		{
			flag_str = match_strval(dsi_flags, flag_vals);
			if ((hash_info->state == MOREDATA) ||
				(hash_info->state == DONE) ||
				(prev_cont == TRUE))
			{
				sprintf(cont_str,"Continued: %d/%d",
					hash_info->seen,hash_info->length);
			}else
			{
				cont_str[0]=0;
			}
			col_add_fstr(pinfo->fd, COL_INFO, "%s %s (%d) %s",
				flag_str,func_str,dsi_requestid,
				cont_str);
		}
	}


	if (tree)
	{
		ti = proto_tree_add_item(tree, proto_dsi, tvb, offset,
		    tvb_length_remaining(tvb, offset), FALSE);
		dsi_tree = proto_item_add_subtree(ti, ett_dsi);

		if (prev_cont == TRUE)
		{
			proto_tree_add_uint(dsi_tree, hf_dsi_requestid, tvb,
				0, 0, dsi_requestid);
			dissect_data(tvb, 0, pinfo, dsi_tree);
		}else
		{
			proto_tree_add_uint(dsi_tree, hf_dsi_flags, tvb,
				offset, 1, dsi_flags);
			proto_tree_add_uint(dsi_tree, hf_dsi_command, tvb,
				offset+1, 1, dsi_command);
			proto_tree_add_uint(dsi_tree, hf_dsi_requestid, tvb,
				offset+2, 2, dsi_requestid);
			proto_tree_add_uint(dsi_tree, hf_dsi_code, tvb,
				offset+4, 4, dsi_code);
			proto_tree_add_uint_format(dsi_tree, hf_dsi_length, tvb,
				offset+8, 4, dsi_length,
				"Length: %d bytes", dsi_length);
			proto_tree_add_uint(dsi_tree, hf_dsi_reserved, tvb,
				offset+12, 4, dsi_reserved);
			dissect_data(tvb, 16, pinfo, dsi_tree);
		}

	}
}

static void dsi_reinit( void){                                              

	last_abs_sec = 0;
	last_abs_usec= 0;
	highest_num = 0;

	if (vals)
		g_mem_chunk_destroy(vals);
	if (dsi_request_hash)
		g_hash_table_destroy(dsi_request_hash);
	if (dsi_request_keys)
		g_mem_chunk_destroy(dsi_request_keys);
	if (dsi_request_records)
		g_mem_chunk_destroy(dsi_request_records);

	dsi_request_hash = g_hash_table_new(dsi_hash, dsi_equal);

	dsi_request_keys = g_mem_chunk_new("dsi_request_keys",
		sizeof(dsi_request_key),
		dsi_packet_init_count * sizeof(dsi_request_key),
		G_ALLOC_AND_FREE);
	dsi_request_records = g_mem_chunk_new("dsi_request_records",
		sizeof(dsi_request_val),
		dsi_packet_init_count * sizeof(dsi_request_val),
		G_ALLOC_AND_FREE);

	vals = g_mem_chunk_new("dsi_vals", hash_val_length,
		hash_init_count * hash_val_length,
		G_ALLOC_AND_FREE);
}

void
proto_register_dsi(void)
{

  static hf_register_info hf[] = {
    { &hf_dsi_flags,
      { "Flags",            "dsi.flags",
	FT_UINT8, BASE_HEX, VALS(flag_vals), 0x0,
      	"Indicates request or reply.", HFILL }},

    { &hf_dsi_command,
      { "Command",           "dsi.command",
	FT_UINT8, BASE_DEC, VALS(func_vals), 0x0,
      	"Represents a DSI command.", HFILL }},

    { &hf_dsi_requestid,
      { "Request ID",           "dsi.requestid",
	FT_UINT16, BASE_DEC, NULL, 0x0,
      	"Keeps track of which request this is.  Replies must match a Request.  IDs must be generated in sequential order.", HFILL }},

    { &hf_dsi_code,
      { "Code",           "dsi.code",
	FT_UINT32, BASE_HEX, NULL, 0x0,
      	"In Reply packets this is an error code.  In Request Write packets this is a data offset.", HFILL }},

    { &hf_dsi_length,
      { "Length",           "dsi.length",
	FT_UINT32, BASE_DEC, NULL, 0x0,
      	"Total length of the data that follows the DSI header.", HFILL }},

    { &hf_dsi_reserved,
      { "Reserved",           "dsi.reserved",
	FT_UINT32, BASE_HEX, NULL, 0x0,
      	"Reserved for future use.  Should be set to zero.", HFILL }},

  };
  static gint *ett[] = {
    &ett_dsi,
  };

  proto_dsi = proto_register_protocol("Data Stream Interface", "DSI", "dsi");
  proto_register_field_array(proto_dsi, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_init_routine( &dsi_reinit);
}

void
proto_reg_handoff_dsi(void)
{
  dissector_add("tcp.port", TCP_PORT_DSI, dissect_dsi, proto_dsi);
}
