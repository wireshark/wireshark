/* packet-ncp.c
 * Routines for NetWare Core Protocol
 * Gilbert Ramirez <gram@verdict.uthscsa.edu>
 *
 * $Id: packet-ncp.c,v 1.20 1999/10/17 14:09:35 deniel Exp $
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

#undef DEBUG_NCP_HASH

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

static int proto_ncp = -1;
static int hf_ncp_type = -1;
static int hf_ncp_seq = -1;
static int hf_ncp_connection = -1;
static int hf_ncp_task = -1;

struct svc_record;

static void
dissect_ncp_request(const u_char *pd, int offset, frame_data *fd, proto_tree *ncp_tree, proto_tree *tree);

static void
dissect_ncp_reply(const u_char *pd, int offset, frame_data *fd, proto_tree *ncp_tree, proto_tree *tree);

static struct ncp2222_record *
ncp2222_find(guint8 func, guint8 subfunc);

static void
parse_ncp_svc_fields(const u_char *pd, proto_tree *ncp_tree, int offset,
	struct svc_record *svc);


/* Hash functions */
gint  ncp_equal (gconstpointer v, gconstpointer v2);
guint ncp_hash  (gconstpointer v);

int ncp_packet_init_count = 200;

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

/* Every NCP packet has this common header */
struct ncp_common_header {
	guint16	type;
	guint8	sequence;
	guint8	conn_low;
	guint8	task;
	guint8	conn_high;
};

/* NCP request packets */
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

/* NCP reply packets */
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

/* These are the field types in an NCP packet */
enum ntype {
	nend,		/* end of the NCP field list */
	nbyte,		/* one byte of data */
	nhex,		/* bytes to be shown as hex digits */
	nbelong,	/* 4-byte big-endian long int */
	nbeshort,	/* 2-byte big-endian short int */
	ndata,		/* unstructured data */
	nbytevar,	/* a variable number of bytes */
	ndatetime,	/* date-time stamp */
	nasciile,	/* length-encoded ASCII string. First byte is length */
	nasciiz		/* null-terminated string of ASCII characters */
};

/* These are the broad families that the different NCP request types belong
 * to.
 */
enum nfamily {
		NCP_UNKNOWN_SERVICE,	/* unknown or n/a */
		NCP_QUEUE_SERVICES,		/* print queues */
		NCP_FILE_SERVICES,		/* file serving */
		NCP_BINDERY_SERVICES,	/* bindery database */
		NCP_CONNECTION_SERVICES, /* communication */
};

/* I had to put this function prototype after the enum nfamily declaration */
static char*
ncp_completion_code(guint8 ccode, enum nfamily family);


/* Information on the NCP field */
typedef struct svc_record {
	enum ntype	type;
	guint8		length;	/* max-length for variable-sized fields */
	gchar		*description;
} svc_record;

typedef struct ncp2222_record {
	guint8		func;
	guint8		subfunc;
	guint8		submask;	/* Does this function have subfunctions?
					 * SUBFUNC or NOSUB */
	gchar		*funcname;

	svc_record	*req;
	svc_record	*rep;
	enum nfamily	family;

} ncp2222_record;


/* ------------------------------------------------------------ */

/* Get Bindery Object ID REQUEST */
static svc_record ncp_17_35_C[] = {
		{ nbeshort,	2,	"Object Type: 0x%04x" },
		{ nasciile,	48,	"Object Name: %.*s" },
		{ nend,		0,	NULL }
};
/* Get Bindery Object ID REPLY has no fields*/


/* Service Queue Job REQUEST */
static svc_record ncp_17_7C_C[] = {
		{ nbelong,	4,	"The queue the job resides in" },
		{ nbeshort,	2,	"Job Type" },
		{ nend,		0,	NULL }
};
/* Service Queue Job REPLY */
static svc_record ncp_17_7C_R[] = {
		{ nbelong,	4,	"Client station number: %d" },
		{ nbelong,	4,	"Task Number: %d" },
		{ nbelong,	4,	"User: %d" },
		{ nbelong,	4,	"Server specifed to service queue entry: %08X" },
		{ ndatetime,	6,	"Earliest time to execute" },
		{ ndatetime,	6,	"When job entered queue" },
		{ nbelong,	4,	"Job Number" },
		{ nbeshort,	2,	"Job Type" },
		{ nbeshort,	2,	"Job Position" },
		{ nbeshort,	2,	"Current status of job: 0x%02x" },
		{ nasciiz,	14,	"Name of file" },
		{ nbelong,	4,	"File handle" },
		{ nbelong,	4,	"Client station number" },
		{ nbelong,	4,	"Task number" },
		{ nbelong,	4,	"Job server" },
		{ nend,		0,	NULL }
};



/* Negotiate Buffer Size REQUEST */
static svc_record ncp_21_00_C[] = {
		{ nbeshort,	2,	"Caller's maximum packet size: %d bytes" },
		{ nend,		0,	NULL }
};
/* Negotiate Buffer Size RESPONSE */
static svc_record ncp_21_00_R[] = {
		{ nbeshort,	2,	"Packet size decided upon by file server: %d bytes" },
		{ nend,		0,	NULL }
};


/* Close File REQUEST */
static svc_record ncp_42_00_C[] = {
		{ nhex,		6,	"File Handle: 02x:02x:02x:02x:02x:02x"},
		{ nend,		0,	NULL }
};
/* Close File RESPONSE */
static svc_record ncp_42_00_R[] = {
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

/* ------------------------------------------------------------ */
/* Any svc_record that has no fields is not created.
 *  Store a NULL in the ncp2222_record instead */

#define SUBFUNC	0xff
#define NOSUB	0x00

static ncp2222_record ncp2222[] = {

{ 0x17, 0x35, SUBFUNC, "Get Bindery Object ID",
	ncp_17_35_C, NULL, NCP_BINDERY_SERVICES
},

{ 0x17, 0x7C, SUBFUNC, "Service Queue Job",
	ncp_17_7C_C, ncp_17_7C_R, NCP_QUEUE_SERVICES
},

{ 0x18, 0x00, NOSUB, "End of Job",
	NULL, NULL, NCP_CONNECTION_SERVICES
},

{ 0x19, 0x00, NOSUB, "Logout",
	NULL, NULL, NCP_CONNECTION_SERVICES
},

{ 0x21, 0x00, NOSUB, "Negotiate Buffer Size",
	ncp_21_00_C, ncp_21_00_R, NCP_CONNECTION_SERVICES
},

{ 0x42, 0x00, NOSUB, "Close File",
	ncp_42_00_C, ncp_42_00_R, NCP_FILE_SERVICES
},

{ 0x48, 0x00, NOSUB, "Read from a file",
	ncp_48_00_C, ncp_48_00_R, NCP_FILE_SERVICES
},

{ 0x00, 0x00, NOSUB, NULL,
	NULL, NULL, NCP_UNKNOWN_SERVICE
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
GMemChunk *ncp_request_keys = NULL;
GMemChunk *ncp_request_records = NULL;

/* Hash Functions */
gint  ncp_equal (gconstpointer v, gconstpointer v2)
{
	struct ncp_request_key	*val1 = (struct ncp_request_key*)v;
	struct ncp_request_key	*val2 = (struct ncp_request_key*)v2;

	#if defined(DEBUG_NCP_HASH)
	printf("Comparing %08X:%d:%d and %08X:%d:%d\n",
		val1->nw_server_address, val1->nw_connection, val1->nw_sequence,
		val2->nw_server_address, val2->nw_connection, val2->nw_sequence);
	#endif

	if (val1->nw_server_address == val2->nw_server_address &&
		val1->nw_connection == val2->nw_connection &&
		val1->nw_sequence   == val2->nw_sequence ) {
		return 1;
	}
	return 0;
}

guint ncp_hash  (gconstpointer v)
{
	struct ncp_request_key	*ncp_key = (struct ncp_request_key*)v;
#if defined(DEBUG_NCP_HASH)
	printf("hash calculated as %d\n", ncp_key->nw_server_address +
			((guint32) ncp_key->nw_connection << 16) +
			ncp_key->nw_sequence);
#endif
	return ncp_key->nw_server_address +
			((guint32) ncp_key->nw_connection << 16) +
			ncp_key->nw_sequence;
}

/* Initializes the hash table and the mem_chunk area each time a new
 * file is loaded or re-loaded in ethereal */
void
ncp_init_protocol(void)
{
	#if defined(DEBUG_NCP_HASH)
	printf("Initializing NCP hashtable and mem_chunk area\n");
	#endif
	if (ncp_request_hash)
		g_hash_table_destroy(ncp_request_hash);
	if (ncp_request_keys)
		g_mem_chunk_destroy(ncp_request_keys);
	if (ncp_request_records)
		g_mem_chunk_destroy(ncp_request_records);

	ncp_request_hash = g_hash_table_new(ncp_hash, ncp_equal);
	ncp_request_keys = g_mem_chunk_new("ncp_request_keys",
			sizeof(struct ncp_request_key),
			ncp_packet_init_count * sizeof(struct ncp_request_key), G_ALLOC_AND_FREE);
	ncp_request_records = g_mem_chunk_new("ncp_request_records",
			sizeof(struct ncp_request_val),
			ncp_packet_init_count * sizeof(struct ncp_request_val), G_ALLOC_AND_FREE);
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

void
dissect_ncp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

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
		ti = proto_tree_add_item(tree, proto_ncp, offset, END_OF_FRAME, NULL);
		ncp_tree = proto_item_add_subtree(ti, ETT_NCP);

		proto_tree_add_item_format(ncp_tree, hf_ncp_type, 
					   offset,      2,
					   header.type,
					   "Type: %s", 
					   val_to_str( header.type,
						       request_reply_values,
						       "Unknown (%04X)"));

		proto_tree_add_item(ncp_tree, hf_ncp_seq, 
				    offset+2,    1, header.sequence);

		proto_tree_add_item(ncp_tree, hf_ncp_connection,
				    offset+3,    3, nw_connection);

		proto_tree_add_item(ncp_tree, hf_ncp_task, 
				    offset+4,    1, header.task);
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
dissect_ncp_request(const u_char *pd, int offset, frame_data *fd,
	proto_tree *ncp_tree, proto_tree *tree) {

	struct ncp_request_header	request;
	struct ncp2222_record		*ncp_request;
	gchar				*description = "";
	struct ncp_request_val		*request_val;
	struct ncp_request_key		*request_key;
	proto_tree			*field_tree = NULL;
	proto_item			*ti = NULL;

	/*memcpy(&request, &pd[offset], sizeof(request));*/
	request.function = pd[offset+6];
	request.subfunc = pd[offset+9];

	ncp_request = ncp2222_find(request.function, request.subfunc);

	if (ncp_request)
		description = ncp_request->funcname;

	if (check_col(fd, COL_INFO)) {
		if (description[0]) {
			col_add_fstr(fd, COL_INFO, "C %s", description);
		}
		else {
			col_add_fstr(fd, COL_INFO, "C Unknown Function %02X/%02X",
				request.function, request.subfunc);
		}
	}

	if (ncp_tree) {
		proto_tree_add_text(ncp_tree, offset+6, 1,
			"Function Code: 0x%02X (%s)",
			request.function, description);

	 	if (ncp_request) {

			if (ncp_request->submask == SUBFUNC) {
				proto_tree_add_text(ncp_tree, offset+7, 2,
					"Packet Length: %d bytes", pntohs(&pd[offset+7]));
				proto_tree_add_text(ncp_tree, offset+9, 1,
					"Subfunction Code: 0x%02x", pd[offset+9]);
				offset += 7 + 3;
			}
			else {
				offset += 7;
			}

			if (ncp_request->req) {
				ti = proto_tree_add_text(ncp_tree, offset, END_OF_FRAME,
				"NCP Request Packet");
				field_tree = proto_item_add_subtree(ti, ETT_NCP_REQUEST_FIELDS);

				parse_ncp_svc_fields(pd, field_tree, offset, ncp_request->req);
			}
		}
	}
	else { /* ! tree */
		request_key = g_mem_chunk_alloc(ncp_request_keys);
		request_key->nw_server_address = nw_server_address;
		request_key->nw_connection = nw_connection;
		request_key->nw_sequence = nw_sequence;

		request_val = g_mem_chunk_alloc(ncp_request_records);
		request_val->ncp_type = nw_ncp_type;
		request_val->ncp_record = ncp2222_find(request.function, request.subfunc);

		g_hash_table_insert(ncp_request_hash, request_key, request_val);
		#if defined(DEBUG_NCP_HASH)
		printf("Inserted server %08X connection %d sequence %d (val=%08X)\n",
			nw_server_address, nw_connection, nw_sequence, request_val);
		#endif
	}

}

void
dissect_ncp_reply(const u_char *pd, int offset, frame_data *fd,
	proto_tree *ncp_tree, proto_tree *tree) {

	struct ncp_reply_header		reply;
	struct ncp2222_record		*ncp_request = NULL;
	struct ncp_request_val		*request_val;
	struct ncp_request_key		request_key;
	proto_tree			*field_tree = NULL;
	proto_item			*ti = NULL;

	memcpy(&reply, &pd[offset], sizeof(reply));

	/* find the record telling us the request made that caused this reply */
	request_key.nw_server_address = nw_server_address;
	request_key.nw_connection = nw_connection;
	request_key.nw_sequence = nw_sequence;

	request_val = (struct ncp_request_val*)
		g_hash_table_lookup(ncp_request_hash, &request_key);

	#if defined(DEBUG_NCP_HASH)
	printf("Looking for server %08X connection %d sequence %d (retval=%08X)\n",
		nw_server_address, nw_connection, nw_sequence, request_val);
	#endif

	if (request_val)
		ncp_request = request_val->ncp_record;

	if (check_col(fd, COL_INFO)) {
		if (reply.completion_code == 0) {
			col_add_fstr(fd, COL_INFO, "R OK");
		}
		else {
			col_add_fstr(fd, COL_INFO, "R Not OK");
		}
	}

	if (ncp_tree) {
		/* A completion code of 0 always means OK. Other values have different
		 * meanings */
		if (ncp_request) {
			proto_tree_add_text(ncp_tree, offset+6,    1,
				"Completion Code: 0x%02x (%s)", reply.completion_code,
				ncp_completion_code(reply.completion_code, ncp_request->family));
		}
		else {
			proto_tree_add_text(ncp_tree, offset+6,    1,
				"Completion Code: 0x%02x (%s)", reply.completion_code,
				reply.completion_code == 0 ? "OK" : "Unknown");
		}

		proto_tree_add_text(ncp_tree, offset+7,    1,
			"Connection Status: %d", reply.connection_state);

		if (ncp_request) {

			if (ncp_request->rep) {
				ti = proto_tree_add_text(ncp_tree, offset+8, END_OF_FRAME,
				"NCP Reply Packet");
				field_tree = proto_item_add_subtree(ti, ETT_NCP_REPLY_FIELDS);

				parse_ncp_svc_fields(pd, field_tree, offset+8, ncp_request->rep);
			}
		}
	}

}

/* Populates the protocol tree with information about the svc_record fields */
static void
parse_ncp_svc_fields(const u_char *pd, proto_tree *ncp_tree, int offset,
	struct svc_record *svc)
{
	struct svc_record *rec = svc;
	int field_offset = offset;
	int field_length = 0;

	while (rec->type != nend) {
		switch(rec->type) {
			case nbeshort:
				field_length = 2;
				proto_tree_add_text(ncp_tree, field_offset,
					field_length, rec->description, pntohs(&pd[field_offset]));
				break;

			case nasciile:
				field_length = pd[field_offset];
				proto_tree_add_text(ncp_tree, field_offset,
					field_length + 1, rec->description, field_length,
					&pd[field_offset+1]);
				break;

			case nhex:
				field_length = rec->length;
				proto_tree_add_text(ncp_tree, field_offset,
					field_length, rec->description);
				break;	

			 default:
				; /* nothing */
				break;
		}
		field_offset += field_length;
		rec++;
	}	
}

static char*
ncp_completion_code(guint8 ccode, enum nfamily family)
{
		char	*text;

#define NCP_CCODE_MIN 0x7e
#define NCP_CCODE_MAX 0xff

	/* From Appendix C of "Programmer's Guide to NetWare Core Protocol" */
	static char	*ccode_text[] = {
		/* 7e */ "NCP boundary check failed",
		/* 7f */ "Unknown",
		/* 80 */ "Lock fail. The file is already open",
		/* 81 */ "A file handle could not be allocated by the file server",
		/* 82 */ "Unauthorized to open file",
		/* 83 */ "Unable to read/write the volume. Possible bad sector on the file server",
		/* 84 */ "Unauthorized to create the file",
		/* 85 */ "",
		/* 86 */ "Unknown",
		/* 87 */ "An unexpected character was encountered in the filename",
		/* 88 */ "FileHandle is not valid",
		/* 89 */ "Unauthorized to search this directory",
		/* 8a */ "Unauthorized to delete a file in this directory",
		/* 8b */ "Unauthorized to rename a file in this directory",
		/* 8c */ "Unauthorized to modify a file in this directory",
		/* 8d */ "Some of the affected files are in use by another client",
		/* 8e */ "All of the affected files are in use by another client",
		/* 8f */ "Some of the affected file are read only",
		/* 90 */ "",
		/* 91 */ "Some of the affected files already exist",
		/* 92 */ "All of the affected files already exist",
		/* 93 */ "Unauthorized to read from this file",
		/* 94 */ "Unauthorized to write to this file",
		/* 95 */ "The affected file is detached",
		/* 96 */ "The file server has run out of memory to service this request",
		/* 97 */ "Unknown",
		/* 98 */ "The affected volume is not mounted",
		/* 99 */ "The file server has run out of directory space on the affected volume",
		/* 9a */ "The request attempted to rename the affected file to another volume",
		/* 9b */ "DirHandle is not associated with a valid directory path",
		/* 9c */ "",
		/* 9d */ "A directory handle was not available for allocation",
		/* 9e */ "The filename does not conform to a legal name for this name space",
		/* 9f */ "The request attempted to delete a directory that is in use by another client",
		/* a0 */ "The request attempted to delete a directory that is not empty",
		/* a1 */ "An unrecoverable error occurred on the affected directory",
		/* a2 */ "The request attempted to read from a file region that is physically locked",
		/* a3 */ "Unknown",
		/* a4 */ "Unknown",
		/* a5 */ "Unknown",
		/* a6 */ "Unknown",
		/* a7 */ "Unknown",
		/* a8 */ "Unknown",
		/* a9 */ "Unknown",
		/* aa */ "Unknown",
		/* ab */ "Unknown",
		/* ac */ "Unknown",
		/* ad */ "Unknown",
		/* ae */ "Unknown",
		/* af */ "Unknown",
		/* b0 */ "Unknown",
		/* b1 */ "Unknown",
		/* b2 */ "Unknown",
		/* b3 */ "Unknown",
		/* b4 */ "Unknown",
		/* b5 */ "Unknown",
		/* b6 */ "Unknown",
		/* b7 */ "Unknown",
		/* b8 */ "Unknown",
		/* b9 */ "Unknown",
		/* ba */ "Unknown",
		/* bb */ "Unknown",
		/* bc */ "Unknown",
		/* bd */ "Unknown",
		/* be */ "Unknown",
		/* bf */ "Requests for this name space are not valid on this volume",
		/* c0 */ "Unauthorized to retrieve accounting data",
		/* c1 */ "The 'account balance' property does not exist",
		/* c2 */ "The object has exceeded its credit limit",
		/* c3 */ "Too many holds have been placed against this account",
		/* c4 */ "The account for this bindery object has been disabled",
		/* c5 */ "Access to the account has been denied because of intruder detections",
		/* c6 */ "The caller does not have operator privileges",
		/* c7 */ "Unknown",
		/* c8 */ "Unknown",
		/* c9 */ "Unknown",
		/* ca */ "Unknown",
		/* cb */ "Unknown",
		/* cc */ "Unknown",
		/* cd */ "Unknown",
		/* ce */ "Unknown",
		/* cf */ "Unknown",
		/* d0 */ "Queue error",
		/* d1 */ "The queue associated with Object ID does not exist",
		/* d2 */ "A queue server is not associated with the selected queue",
		/* d3 */ "No queue rights",
		/* d4 */ "The queue associated with Object ID is full and cannot accept another request",
		/* d5 */ "The job associated with Job Number does not exist in this queue",
		/* d6 */ "",
		/* d7 */ "",
		/* d8 */ "Queue not active",
		/* d9 */ "",
		/* da */ "",
		/* db */ "",
		/* dc */ "Unknown",
		/* dd */ "Unknown",
		/* de */ "Attempted to login to the file server with an incorrect password",
		/* df */ "Attempted to login to the file server with a password that has expired",
		/* e0 */ "Unknown",
		/* e1 */ "Unknown",
		/* e2 */ "Unknown",
		/* e3 */ "Unknown",
		/* e4 */ "Unknown",
		/* e5 */ "Unknown",
		/* e6 */ "Unknown",
		/* e7 */ "No disk track",
		/* e8 */ "",
		/* e9 */ "Unknown",
		/* ea */ "The bindery object is not a member of this set",
		/* eb */ "The property is not a set property",
		/* ec */ "The set property does not exist",
		/* ed */ "The property already exists",
		/* ee */ "The bindery object already exists",
		/* ef */ "Illegal characters in Object Name field",
		/* f0 */ "A wildcard was detected in a field that does not support wildcards",
		/* f1 */ "The client does not have the rights to access this bindery objecs",
		/* f2 */ "Unauthorized to read from this object",
		/* f3 */ "Unauthorized to rename this object",
		/* f4 */ "Unauthorized to delete this object",
		/* f5 */ "Unauthorized to create this object",
		/* f6 */ "Unauthorized to delete the property of this object",
		/* f7 */ "Unauthorized to create this property",
		/* f8 */ "Unauthorized to write to this property",
		/* f9 */ "Unauthorized to read this property",
		/* fa */ "Temporary remap error",
		/* fb */ "",
		/* fc */ "",
		/* fd */ "",
		/* fe */ "",
		/* ff */ ""
	};

	switch (ccode) {
		case 0:
			return "OK";
			break;

		case 3:
			return "Client not accepting messages";
			break;
	}

	if (ccode >= NCP_CCODE_MIN && ccode <= NCP_CCODE_MAX) {
		text = ccode_text[ccode - NCP_CCODE_MIN];
		/* If there really is text, return it */
		if (text[0] != 0)
			return text;
	}
	else {
		return "Unknown";
	}

	/* We have a completion code with multiple translations. We'll use the
	 * nfamily that this request type belongs to to give the right
	 * translation.
	 */
	switch (ccode) {

		case 0xfc:
			switch(family) {
				case NCP_QUEUE_SERVICES:
					return "The message queue cannot accept another message";
					break;
				case NCP_BINDERY_SERVICES:
					return "The specified bindery object does not exist";
					break;
				default:
					return "Unknown";
					break;
			}
			break;

		default:
			return "I don't know how to parse this completion code. Please send this packet trace to Gilbert Ramirez <gram@xiexie.org> for analysis";
	}
}

void
proto_register_ncp(void)
{

  static hf_register_info hf[] = {
    { &hf_ncp_type,
      { "Type",			"ncp.type",
	FT_UINT16, BASE_HEX, NULL, 0x0,
	"NCP message type" }},
    { &hf_ncp_seq,
      { "Sequence Number",     	"ncp.seq",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"" }},
    { &hf_ncp_connection,
      { "Connection Number",    "ncp.connection",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"" }},
    { &hf_ncp_task,
      { "Task Number",     	"ncp.task",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"" }}
  };

  proto_ncp = proto_register_protocol("NetWare Core Protocol", "ncp");
  proto_register_field_array(proto_ncp, hf, array_length(hf));

}
