/* packet-ncp.c
 * Routines for NetWare Core Protocol
 * Gilbert Ramirez <gram@verdict.uthscsa.edu>
 *
 * $Id: packet-ncp.c,v 1.11 1999/05/10 20:51:36 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
 * Copyright 1998 Gerald Combs
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>
#include "packet.h"
#include "packet-ipx.h"
#include "packet-ncp.h"

static void
dissect_ncp_request(const u_char *pd, int offset, frame_data *fd, proto_tree *ncp_tree, proto_tree *tree);

static void
dissect_ncp_reply(const u_char *pd, int offset, frame_data *fd, proto_tree *ncp_tree, proto_tree *tree);

static struct ncp2222_record *
ncp2222_find(guint8 func, guint8 subfunc);

struct svc_record;

static int
svc_record_byte_count(struct svc_record *sr);

/* Hash functions */
gint  ncp_equal (const gpointer v, const gpointer v2);
guint ncp_hash  (const gpointer v);


/* The information in this module comes from:
	NetWare LAN Analysis, Second Edition
	Laura A. Chappell and Dan E. Hakes
	(c) 1994 Novell, Inc.
	Novell Press, San Jose.
	ISBN: 0-7821-1362-1

  And from the ncpfs source code by Volker Lendecke

  And:
	Programmer's Guide to the NetWare Core Protocol
	Steve Conner & Diane Conner
	(c) 1996 by Steve Conner & Diane Conner
	Published by Annabooks, San Diego, California
        ISBN: 0-929392-31-0

*/

struct ncp_common_header {
	guint16	type;
	guint8	sequence;
	guint8	conn_low;
	guint8	task;
	guint8	conn_high;
};
struct ncp_request_header {
	guint16	type;
	guint8	sequence;
	guint8	conn_low;
	guint8	task;
	guint8	conn_high;
	guint8	function;
	guint16	length;
	guint8	subfunc;
};

struct ncp_reply_header {
	guint16	type;
	guint8	sequence;
	guint8	conn_low;
	guint8	task;
	guint8	conn_high;
	guint8	completion_code;
	guint8	connection_state;
};


static value_string request_reply_values[] = {
	{ 0x1111, "Create a service connection" },
	{ 0x2222, "Service request" },
	{ 0x3333, "Service reply" },
	{ 0x5555, "Destroy service connection" },
	{ 0x7777, "Burst mode transfer" },
	{ 0x9999, "Request being processed" },
	{ 0x0000, NULL }
};

enum ntype { nend, nbyte, nhex, nbelong, nbeshort, ndata, nbytevar,
	ndatetime, nasciiz };

typedef struct svc_record {
	enum ntype	type;
	guint8		length;
	gchar		*description;
} svc_record;

typedef struct ncp2222_record {
	guint8		func;
	guint8		subfunc;
	guint8		submask;
	gchar		*funcname;

	svc_record	*req;
	gchar		*req_summ;
	guint8		req_summ_var1;
	guint8		req_summ_var2;
	guint8		req_summ_var3;

	svc_record	*rep;
	gchar		*rep_summ;
	guint8		rep_summ_var1;
	guint8		rep_summ_var2;
	guint8		rep_summ_var3;
} ncp2222_record;

/* Service Queue Job REQUEST */
static svc_record ncp_17_7C_C[] = {
		{ nbelong,	4,	"The queue the job resides in" },
		{ nbeshort,	2,	"Job Type" },
		{ nend,		0,	NULL }
};
/* Service Queue Job REPLY */
static svc_record ncp_17_7C_R[] = {
		{ nbelong,	4,	"Client station number" },
		{ nbelong,	4,	"Task Number" },
		{ nbelong,	4,	"User" },
		{ nbelong,	4,	"Server specifed to service queue entry" },
		{ ndatetime,6,	"Earliest time to execute" },
		{ ndatetime,6,	"When job entered queue" },
		{ nbelong,	4,	"Job Number" },
		{ nbeshort,	2,	"Job Type" },
		{ nbeshort,	2,	"Job Position" },
		{ nbeshort,	2,	"Current status of job" },
		{ nasciiz,	14,	"Name of file" },
		{ nbelong,	4,	"File handle" },
		{ nbelong,	4,	"Client station number" },
		{ nbelong,	4,	"Task number" },
		{ nbelong,	4,	"Job server" },
		{ nend,		0,	NULL }
};

/* Read from a file REQUEST */
static svc_record ncp_48_00_C[] = {
		{ nbyte, 	1,	"Unknown" },
		{ nhex,		6,	"File Handle" },
		{ nbelong,	4,	"Byte offset within file" },
		{ nbeshort,	2,	"Maximum data bytes to return" },
		{ nend,		0,	NULL }
};
/* RESPONSE */
static svc_record ncp_48_00_R[] = {
		{ nbeshort,	2,	"Data bytes returned" },
		{ nbytevar,	1,	"Padding" },
		{ ndata,	0,	NULL }
};

#define SUBFUNC	0xff
#define NOSUB	0x00

static ncp2222_record ncp2222[] = {

{ 0x17, 0x7C, SUBFUNC, "Service Queue Job",
	ncp_17_7C_C, "", -1, -1, -1, 
	ncp_17_7C_R, "", -1, -1, -1
},

{ 0x48, 0x00, NOSUB, "Read from a file",
	ncp_48_00_C, "F=%s Read %d at %d", 1, 2, 3, 
	ncp_48_00_R, "%d bytes read", 0, -1, -1
},

{ 0x00, 0x00, NOSUB, NULL,
	NULL, NULL, -1, -1, -1,
	NULL, NULL, -1, -1, -1
}

};

/* NCP packets come in request/reply pairs. The request packets tell the type
 * of NCP request and give a sequence ID. The response, unfortunately, only
 * identifies itself via the sequence ID; you have to know what type of NCP
 * request the request packet contained in order to successfully parse the NCP
 * response. A global method for doing this does not exist in ethereal yet
 * (NFS also requires it), so for now the NCP section will keep its own hash
 * table keeping track of NCP packet types.
 *
 * The key representing the unique NCP request is composed of 3 variables:
 *
 * ServerIPXNetwork.Connection.SequenceNumber
 *     4 bytes        2 bytes      1 byte
 *     guint32        guint16      guint8     (all are host order)
 *
 * This assumes that all NCP connection is between a client and server.
 * Servers can be identified by having a 00:00:00:00:00:01 IPX Node address.
 * We have to let the IPX layer pass us the ServerIPXNetwork via a global
 * variable (nw_server_address). In the future, if we decode NCP over TCP/UDP,
 * then nw_server_address will represent the IP address of the server, which
 * conveniently, is also 4 bytes long.
 *
 * The value stored in the hash table is the ncp_request_val pointer. This
 * struct tells us the NCP type and gives the ncp2222_record pointer, if
 * ncp_type == 0x2222.
 */
guint32 nw_server_address = 0; /* set by IPX layer */
guint16 nw_connection = 0; /* set by dissect_ncp */
guint8  nw_sequence = 0; /* set by dissect_ncp */
guint16 nw_ncp_type = 0; /* set by dissect_ncp */

struct ncp_request_key {
	guint32	nw_server_address;
	guint16	nw_connection;
	guint8	nw_sequence;
};

struct ncp_request_val {
	guint32					ncp_type;
	struct ncp2222_record*	ncp_record;
};

GHashTable *ncp_request_hash = NULL;
GMemChunk *ncp_request_records = NULL;

/* Hash Functions */
gint  ncp_equal (const gpointer v, const gpointer v2)
{
	return memcmp(v, v2, 7);
}

guint ncp_hash  (const gpointer v)
{
	struct ncp_request_key	*ncp_key = (struct ncp_request_key*)v;

	return ncp_key->nw_server_address +
			((guint32) ncp_key->nw_connection << 16) +
			ncp_key->nw_sequence;
}

void
ncp_init_protocol(void)
{
	if (ncp_request_hash)
		g_hash_table_destroy(ncp_request_hash);
	if (ncp_request_records)
		g_mem_chunk_destroy(ncp_request_records);

	ncp_request_hash = g_hash_table_new(ncp_hash, ncp_equal);
	ncp_request_records = g_mem_chunk_new("ncp_request_records",
			sizeof(struct ncp_request_val), 50 * sizeof(struct ncp_request_val),
			G_ALLOC_AND_FREE);
}

static struct ncp2222_record *
ncp2222_find(guint8 func, guint8 subfunc)
{
	struct ncp2222_record *ncp_record, *retval = NULL;

	ncp_record = ncp2222;

	while(ncp_record->func != 0) {
		if (ncp_record->func == func &&
			ncp_record->subfunc == (subfunc & ncp_record->submask)) {
			retval = ncp_record;
			break;
		}
		ncp_record++;
	}

	return retval;
}

static int
svc_record_byte_count(svc_record *sr)
{
	svc_record *rec = sr;
	int byte_count = 0;

	while (rec->type != nend && rec->type != ndata) {
		byte_count += rec->length;
		rec++;
	}

	return byte_count;
}

void
dissect_ncp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
	int max_data) {

	proto_tree	*ncp_tree = NULL;
	proto_item	*ti;
	int		ncp_hdr_length = 0;
	struct ncp_common_header	header;

	memcpy(&header, &pd[offset], sizeof(header));
	header.type = ntohs(header.type);

	if (header.type == 0x1111 ||
			header.type == 0x2222 ||
			header.type == 0x5555 ||
			header.type == 0x7777) {
		ncp_hdr_length = 7;
	}
	else if (header.type == 0x3333 || header.type == 0x9999) {
		ncp_hdr_length = 8;
	}

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "NCP");
	nw_connection = (header.conn_high << 16) + header.conn_low;
	nw_sequence = header.sequence;
	nw_ncp_type = header.type;

	if (tree) {
		ti = proto_tree_add_item(tree, offset, END_OF_FRAME,
			"NetWare Core Protocol");
		ncp_tree = proto_tree_new();
		proto_item_add_subtree(ti, ncp_tree, ETT_NCP);

		proto_tree_add_item(ncp_tree, offset,      2,
			"Type: %s", val_to_str( header.type,
			request_reply_values, "Unknown (%04X)"));

		proto_tree_add_item(ncp_tree, offset+2,    1,
			"Sequence Number: %d", header.sequence);

		proto_tree_add_item(ncp_tree, offset+3,    3,
			"Connection Number: %d", nw_connection);

		proto_tree_add_item(ncp_tree, offset+4,    1,
			"Task Number: %d", header.task);
	}

	/* Note how I use ncp_tree *and* tree in my args for ncp request/reply */
	if (ncp_hdr_length == 7)
		dissect_ncp_request(pd, offset, fd, ncp_tree, tree);
	else if (ncp_hdr_length == 8)
		dissect_ncp_reply(pd, offset, fd, ncp_tree, tree);
	else
		dissect_data(pd, offset, fd, tree);
}

void
dissect_ncp_request(const u_char *pd, int offset, frame_data *fd, proto_tree *ncp_tree, proto_tree *tree) {

	struct ncp_request_header	request;
	struct ncp2222_record		*ncp_request;
	gchar						*description = "Unknown";
	struct ncp_request_val		*request_val;
	struct ncp_request_key		request_key;

	/*memcpy(&request, &pd[offset], sizeof(request));*/
	request.function = pd[offset+6];
	request.subfunc = pd[offset+9];

	ncp_request = ncp2222_find(request.function, request.subfunc);

	if (ncp_request)
		description = ncp_request->funcname;

	if (check_col(fd, COL_INFO))
		col_add_fstr(fd, COL_INFO, "C %s", description);

	if (ncp_tree) {
		proto_tree_add_item(ncp_tree, offset+6, 1, "Function Code: 0x%02X (%s)",
			request.function, description);
		if (ncp_request) {
			offset += 10 + svc_record_byte_count(ncp_request->req);
			dissect_data(pd, offset, fd, tree);
		}
	}
	else { /* ! tree */
		request_val = g_mem_chunk_alloc(ncp_request_records);
		request_val->ncp_type = nw_ncp_type;
		request_val->ncp_record = ncp2222_find(request.function, request.subfunc);
		request_key.nw_server_address = nw_server_address;
		request_key.nw_connection = nw_connection;
		request_key.nw_sequence = nw_sequence;

		g_hash_table_insert(ncp_request_hash, &request_key, request_val);
	}

}

void
dissect_ncp_reply(const u_char *pd, int offset, frame_data *fd, proto_tree *ncp_tree, proto_tree *tree) {
	struct ncp_reply_header		reply;
	struct ncp2222_record		*ncp_request = NULL;
	struct ncp_request_val		*request_val;
	struct ncp_request_key		request_key;
	gchar						*description = "Unknown";

	memcpy(&reply, &pd[offset], sizeof(reply));

	/* find the record telling us the request made that caused this reply */
	request_key.nw_server_address = nw_server_address;
	request_key.nw_connection = nw_connection;
	request_key.nw_sequence = nw_sequence;

	request_val = (struct ncp_request_val*)
	g_hash_table_lookup(ncp_request_hash, &request_key);

	if (request_val)
		ncp_request = request_val->ncp_record;

	if (ncp_request)
		description = ncp_request->funcname;

	if (check_col(fd, COL_INFO))
		col_add_fstr(fd, COL_INFO, "R %s", description);

	if (ncp_tree) {
		proto_tree_add_item(ncp_tree, offset+6,    1,
			"Completion Code: %d", reply.completion_code);

		proto_tree_add_item(ncp_tree, offset+7,    1,
			"Connection Status: %d", reply.connection_state);
		offset += 8;
		dissect_data(pd, offset, fd, tree);
	}

}
