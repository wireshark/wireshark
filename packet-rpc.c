/* packet-rpc.c
 * Routines for rpc dissection
 * Copyright 1999, Uwe Girlich <Uwe.Girlich@philosys.de>
 * 
 * $Id: packet-rpc.c,v 1.29 2000/04/04 06:46:27 guy Exp $
 * 
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 * 
 * Copied from packet-smb.c
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

#include <glib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "packet.h"
#include "conversation.h"
#include "packet-rpc.h"


#define RPC_RM_FRAGLEN  0x7fffffffL

static struct true_false_string yesno = { "Yes", "No" };


static const value_string rpc_msg_type[3] = {
	{ RPC_CALL, "Call" },
	{ RPC_REPLY, "Reply" },
	{ 0, NULL }
};

static const value_string rpc_reply_state[3] = {
	{ MSG_ACCEPTED, "accepted" },
	{ MSG_DENIED, "denied" },
	{ 0, NULL }
};

const value_string rpc_auth_flavor[] = {
	{ AUTH_NULL, "AUTH_NULL" },
	{ AUTH_UNIX, "AUTH_UNIX" },
	{ AUTH_SHORT, "AUTH_SHORT" },
	{ AUTH_DES, "AUTH_DES" },
	{ 0, NULL }
};

static const value_string rpc_accept_state[6] = {
	{ SUCCESS, "RPC executed successfully" },
	{ PROG_UNAVAIL, "remote hasn't exported program" },
	{ PROG_MISMATCH, "remote can't support version #" },
	{ PROC_UNAVAIL, "program can't support procedure" },
	{ GARBAGE_ARGS, "procedure can't decode params" },
	{ 0, NULL }
};

static const value_string rpc_reject_state[3] = {
	{ RPC_MISMATCH, "RPC_MISMATCH" },
	{ AUTH_ERROR, "AUTH_ERROR" },
	{ 0, NULL }
};

static const value_string rpc_auth_state[6] = {
	{ AUTH_BADCRED, "bad credential (seal broken)" },
	{ AUTH_REJECTEDCRED, "client must begin new session" },
	{ AUTH_BADVERF, "bad verifier (seal broken)" },
	{ AUTH_REJECTEDVERF, "verifier expired or replayed" },
	{ AUTH_TOOWEAK, "rejected for security reasons" },
	{ 0, NULL }
};


/* the protocol number */
static int proto_rpc = -1;
static int hf_rpc_lastfrag = -1;
static int hf_rpc_fraglen = -1;
static int hf_rpc_xid = -1;
static int hf_rpc_msgtype = -1;
static int hf_rpc_version = -1;
static int hf_rpc_version_min = -1;
static int hf_rpc_version_max = -1;
static int hf_rpc_program = -1;
static int hf_rpc_programversion = -1;
static int hf_rpc_programversion_min = -1;
static int hf_rpc_programversion_max = -1;
static int hf_rpc_procedure = -1;
static int hf_rpc_auth_flavor = -1;
static int hf_rpc_auth_length = -1;
static int hf_rpc_auth_machinename = -1;
static int hf_rpc_auth_stamp = -1;
static int hf_rpc_auth_uid = -1;
static int hf_rpc_auth_gid = -1;
static int hf_rpc_state_accept = -1;
static int hf_rpc_state_reply = -1;
static int hf_rpc_state_reject = -1;
static int hf_rpc_state_auth = -1;
static int hf_rpc_dup = -1;
static int hf_rpc_call_dup = -1;
static int hf_rpc_reply_dup = -1;
static int hf_rpc_value_follows = -1;

static gint ett_rpc = -1;
static gint ett_rpc_string = -1;
static gint ett_rpc_cred = -1;
static gint ett_rpc_verf = -1;
static gint ett_rpc_gids = -1;

/* Hash table with info on RPC program numbers */
static GHashTable *rpc_progs;

/* Hash table with info on RPC procedure numbers */
static GHashTable *rpc_procs;


/***********************************/
/* Hash array with procedure names */
/***********************************/

/* compare 2 keys */
gint
rpc_proc_equal(gconstpointer k1, gconstpointer k2)
{
	rpc_proc_info_key* key1 = (rpc_proc_info_key*) k1;
	rpc_proc_info_key* key2 = (rpc_proc_info_key*) k2;

	return ((key1->prog == key2->prog && 
		key1->vers == key2->vers &&
		key1->proc == key2->proc) ?
	TRUE : FALSE);
}

/* calculate a hash key */
guint
rpc_proc_hash(gconstpointer k)
{
	rpc_proc_info_key* key = (rpc_proc_info_key*) k;

	return (key->prog ^ (key->vers<<16) ^ (key->proc<<24));
}


/* insert some entries */
void
rpc_init_proc_table(guint prog, guint vers, const vsff *proc_table)
{
	const vsff *proc;

	for (proc = proc_table ; proc->strptr!=NULL; proc++) {
		rpc_proc_info_key *key;
		rpc_proc_info_value *value;

		key = (rpc_proc_info_key *) g_malloc(sizeof(rpc_proc_info_key));
		key->prog = prog;
		key->vers = vers;
		key->proc = proc->value;

		value = (rpc_proc_info_value *) g_malloc(sizeof(rpc_proc_info_value));
		value->name = proc->strptr;
		value->dissect_call = proc->dissect_call;
		value->dissect_reply = proc->dissect_reply;

		g_hash_table_insert(rpc_procs,key,value);
	}
}

/*----------------------------------------*/
/* end of Hash array with procedure names */
/*----------------------------------------*/


/*********************************/
/* Hash array with program names */
/*********************************/

/* compare 2 keys */
gint
rpc_prog_equal(gconstpointer k1, gconstpointer k2)
{
	rpc_prog_info_key* key1 = (rpc_prog_info_key*) k1;
	rpc_prog_info_key* key2 = (rpc_prog_info_key*) k2;

	return ((key1->prog == key2->prog) ?
	TRUE : FALSE);
}


/* calculate a hash key */
guint
rpc_prog_hash(gconstpointer k)
{
	rpc_prog_info_key* key = (rpc_prog_info_key*) k;

	return (key->prog);
}


void
rpc_init_prog(int proto, guint32 prog, int ett)
{
	rpc_prog_info_key *key;
	rpc_prog_info_value *value;
	char *uc_progname = NULL, *lc_progname = NULL;

	key = (rpc_prog_info_key *) g_malloc(sizeof(rpc_prog_info_key));
	key->prog = prog;

	value = (rpc_prog_info_value *) g_malloc(sizeof(rpc_prog_info_value));
	value->proto = proto;
	value->ett = ett;

	lc_progname = proto_registrar_get_abbrev(proto);
	if ( lc_progname )
	{
		int i;
		uc_progname = strdup(lc_progname);
		for (i=0; i<strlen(uc_progname); i++)
		{
			uc_progname[i] = toupper(uc_progname[i]);
		}
	}
	value->progname = uc_progname;

	g_hash_table_insert(rpc_progs,key,value);
}

/*	return the name associated with a previously registered program. This
	should probably eventually be expanded to use the rpc YP/NIS map
	so that it can give names for programs not handled by ethereal */
char *rpc_prog_name(guint32 prog)
{
	char *progname = NULL;
	rpc_prog_info_key       rpc_prog_key;
	rpc_prog_info_value     *rpc_prog;

	rpc_prog_key.prog = prog;
	if ((rpc_prog = g_hash_table_lookup(rpc_progs,&rpc_prog_key)) == NULL) {
		progname = "Unknown";
	}
	else {
		progname = rpc_prog->progname;
	}
	return progname;
}


/*--------------------------------------*/
/* end of Hash array with program names */
/*--------------------------------------*/

/* static array, first quick implementation, I'll switch over to GList soon */ 
rpc_call_info rpc_call_table[RPC_CALL_TABLE_LENGTH];
guint32 rpc_call_index = 0;
guint32 rpc_call_firstfree = 0;

void
rpc_call_insert(rpc_call_info *call)
{
	/* some space left? */
	if (rpc_call_firstfree<RPC_CALL_TABLE_LENGTH) {
		/* some space left */
		/* take the first free entry */
		rpc_call_index = rpc_call_firstfree;
		/* increase this limit */
		rpc_call_firstfree++;
		/* rpc_call_firstfree may now be RPC_CALL_TABLE_LENGTH */
	}
	else {
		/* no space left */
		/* the next entry, with wrap around */
		rpc_call_index = (rpc_call_index+1) % rpc_call_firstfree;
	}
		
	/* put the entry in */
	memcpy(&rpc_call_table[rpc_call_index],call,sizeof(*call));
	return;
}


rpc_call_info*
rpc_call_lookup(rpc_call_info *call)
{
	int i;

	i = rpc_call_index;
	do {
		if (
			rpc_call_table[i].xid == call->xid &&
			rpc_call_table[i].conversation == call->conversation
		) {
			return &rpc_call_table[i];
		}
		if (rpc_call_firstfree) {
			/* decrement by one, go to rpc_call_firstfree-1 
			   at the start of the list */
			i = (i-1+rpc_call_firstfree) % rpc_call_firstfree;
		}
	} while (i!=rpc_call_index);
	return NULL;
}


unsigned int
rpc_roundup(unsigned int a)
{
	unsigned int mod = a % 4;
	return a + ((mod)? 4-mod : 0);
}


int
dissect_rpc_bool(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
int hfindex)
{
	guint32 value;

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	value = EXTRACT_UINT(pd, offset+0);
	if (tree)
		proto_tree_add_item(tree, hfindex, offset, 4, value);
	offset += 4;

	return offset;
}


int
dissect_rpc_uint32(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
char* name, char* type)
{
	guint32 value;

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	value = EXTRACT_UINT(pd, offset+0);

	if (tree) {
		proto_tree_add_text(tree, offset, 4,
		"%s: %u", name, value);
	}

	offset += 4;
	return offset;
}


int
dissect_rpc_uint64(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
char* name, char* type)
{
	guint32 value_low;
	guint32 value_high;

	if (!BYTES_ARE_IN_FRAME(offset,8)) return offset;
	value_high = EXTRACT_UINT(pd, offset+0);
	value_low = EXTRACT_UINT(pd, offset+4);

	if (tree) {
		if (value_high)
			proto_tree_add_text(tree, offset, 8,
				"%s: 0x%x%08x", name, value_high, value_low);
		else
			proto_tree_add_text(tree, offset, 8,
				"%s: %u", name, value_low);
	}

	offset += 8;
	return offset;
}


static int
dissect_rpc_opaque_data(const u_char *pd, int offset, frame_data *fd,
    proto_tree *tree, int hfindex, gboolean string_data,
    char **string_buffer_ret)
{
	proto_item *string_item = NULL;
	proto_tree *string_tree = NULL;
	int old_offset = offset;

	int length_truncated = 0;

	int string_truncated = 0;
	guint32 string_length = 0;
	guint32 string_length_full;
	guint32 string_length_packet;
	guint32 string_length_copy = 0;

	int fill_truncated = 0;
	guint32 fill_length  = 0;
	guint32 fill_length_packet  = 0;
	guint32 fill_length_copy  = 0;

	char *string_buffer = NULL;
	char *string_buffer_print = NULL;

	if (BYTES_ARE_IN_FRAME(offset,4)) {
		string_length = EXTRACT_UINT(pd,offset+0);
		string_length_full = rpc_roundup(string_length);
		string_length_packet = pi.captured_len - (offset + 4);
		if (string_length_packet < string_length) {
			/* truncated string */
			string_truncated = 1;
			string_length_copy = string_length_packet;
			fill_truncated = 2;
			fill_length = 0;
			fill_length_packet = 0;
			fill_length_copy = 0;
		}
		else {
			/* full string data */
			string_truncated = 0;
			string_length_copy = string_length;
			fill_length = string_length_full - string_length;
			fill_length_packet = pi.captured_len - (offset + 4 + string_length);
			if (fill_length_packet < fill_length) {
				/* truncated fill bytes */
				fill_length_copy = fill_length_packet;
				fill_truncated = 1;
			}
			else {
				/* full fill bytes */
				fill_length_copy = fill_length;
				fill_truncated = 0;
			}
		}
		string_buffer = (char*)g_malloc(string_length_copy + 
			(string_data ? 1 : 0));
		memcpy(string_buffer,pd+offset+4,string_length_copy);
		if (string_data)
			string_buffer[string_length_copy] = '\0';

		/* calculate a nice printable string */
		if (string_length) {
			if (string_length != string_length_copy) {
				if (string_data) {
					/* alloc maximum data area */
					string_buffer_print = (char*)g_malloc(string_length_copy + 12 + 1);
					/* copy over the data */
					memcpy(string_buffer_print,string_buffer,string_length_copy);
					/* append a 0 byte for sure printing */
					string_buffer_print[string_length_copy] = '\0';
					/* append <TRUNCATED> */
					/* This way, we get the TRUNCATED even
					   in the case of totally wrong packets,
					   where \0 are inside the string.
					   TRUNCATED will appear at the
					   first \0 or at the end (where we 
					   put the securing \0).
					*/
					strcat(string_buffer_print,"<TRUNCATED>");
				}
				else {
					string_buffer_print = g_strdup("<DATA><TRUNCATED>");
				}
			}
			else {
				if (string_data) {
					string_buffer_print = g_strdup(string_buffer);
				}
				else {
					string_buffer_print = g_strdup("<DATA>");
				}
			}
		}
		else {
			string_buffer_print = g_strdup("<EMPTY>");
		}
	}
	else {
		length_truncated = 1;
		string_truncated = 2;
		fill_truncated = 2;
		string_buffer = g_strdup("");
		string_buffer_print = g_strdup("<TRUNCATED>");
	}

	if (tree) {
		string_item = proto_tree_add_text(tree,offset+0, END_OF_FRAME,
			"%s: %s", proto_registrar_get_name(hfindex), string_buffer_print);
		if (string_data) {
			proto_tree_add_item_hidden(tree, hfindex, offset+4,
				string_length_copy, string_buffer);
		}
		if (string_item) {
			string_tree = proto_item_add_subtree(string_item, ett_rpc_string);
		}
	}
	if (length_truncated) {
		if (string_tree)
			proto_tree_add_text(string_tree,
				offset,pi.captured_len-offset,
				"length: <TRUNCATED>");
		offset = pi.captured_len;
	} else {
		if (string_tree)
			proto_tree_add_text(string_tree,offset+0,4,
				"length: %u", string_length);
		offset += 4;

		if (string_tree)
			proto_tree_add_text(string_tree,offset,string_length_copy,
				"contents: %s", string_buffer_print);
		offset += string_length_copy;
		if (fill_length) {
			if (string_tree) {
				if (fill_truncated) {
					proto_tree_add_text(string_tree,
					offset,fill_length_copy,
					"fill bytes: opaque data<TRUNCATED>");
				}
				else {
					proto_tree_add_text(string_tree,
					offset,fill_length_copy,
					"fill bytes: opaque data");
				}
			}
			offset += fill_length_copy;
		}
	}
	
	if (string_item) {
		proto_item_set_len(string_item, offset - old_offset);
	}

	if (string_buffer       != NULL) g_free (string_buffer      );
	if (string_buffer_print != NULL) {
		if (string_buffer_ret != NULL)
			*string_buffer_ret = string_buffer_print;
		else
			g_free (string_buffer_print);
	}
	return offset;
}


int
dissect_rpc_string(const u_char *pd, int offset, frame_data *fd,
    proto_tree *tree, int hfindex, char **string_buffer_ret)
{
	offset = dissect_rpc_opaque_data(pd, offset, fd, tree, hfindex, TRUE,
	    string_buffer_ret);

	return offset;
}


int
dissect_rpc_data(const u_char *pd, int offset, frame_data *fd,
    proto_tree *tree, int hfindex)
{
	offset = dissect_rpc_opaque_data(pd, offset, fd, tree, hfindex, FALSE,
	    NULL);

	return offset;
}


int
dissect_rpc_list(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, dissect_function_t *rpc_list_dissector)
{
	guint32 value_follows;

	while (1) {
		if (!BYTES_ARE_IN_FRAME(offset,4)) break;
		value_follows = EXTRACT_UINT(pd, offset+0);
		proto_tree_add_item(tree,hf_rpc_value_follows,
			offset+0, 4, value_follows);
		offset += 4;
		if (value_follows == 1) {
			offset = rpc_list_dissector(pd, offset, fd, tree);
		}
		else {
			break;
		}
	}

	return offset;
}


void
dissect_rpc_auth( const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
        guint flavor;
        guint length;
        guint length_full;

	/* both checks are made outside */
	/* if (!BYTES_ARE_IN_FRAME(offset,8)) return; */
	flavor = EXTRACT_UINT(pd,offset+0);
	length = EXTRACT_UINT(pd,offset+4);
	length_full = rpc_roundup(length);
	/* if (!BYTES_ARE_IN_FRAME(offset+8,full_length)) return; */

	if (tree) {
		proto_tree_add_item(tree, hf_rpc_auth_flavor, offset+0, 4,
			flavor);
		proto_tree_add_item(tree, hf_rpc_auth_length, offset+4, 4,
			length);
	}

	offset += 8;

	switch (flavor) {
		case AUTH_UNIX: {
			guint stamp;
			guint uid;
			guint gid;
			guint gids_count;
			guint gids_i;
			guint gids_entry;
			proto_item *gitem;
			proto_tree *gtree = NULL;

			if (!BYTES_ARE_IN_FRAME(offset,4)) return;
			stamp = EXTRACT_UINT(pd,offset+0);
			if (tree)
				proto_tree_add_item(tree, hf_rpc_auth_stamp,
					offset+0, 4, stamp);
			offset += 4;

			offset = dissect_rpc_string(pd,offset,fd,
				tree,hf_rpc_auth_machinename,NULL);

			if (!BYTES_ARE_IN_FRAME(offset,4)) return;
			uid = EXTRACT_UINT(pd,offset+0);
			if (tree)
				proto_tree_add_item(tree, hf_rpc_auth_uid,
					offset+0, 4, uid);
			offset += 4;

			if (!BYTES_ARE_IN_FRAME(offset,4)) return;
			gid = EXTRACT_UINT(pd,offset+0);
			if (tree)
				proto_tree_add_item(tree, hf_rpc_auth_gid,
					offset+0, 4, gid);
			offset += 4;

			if (!BYTES_ARE_IN_FRAME(offset,4)) return;
			gids_count = EXTRACT_UINT(pd,offset+0);
			if (tree) {
				gitem = proto_tree_add_text(tree, offset, 4+gids_count*4,
				"Auxiliary GIDs");
				gtree = proto_item_add_subtree(gitem, ett_rpc_gids);
			}
			offset += 4;
			if (!BYTES_ARE_IN_FRAME(offset,4*gids_count)) return;
			for (gids_i = 0 ; gids_i < gids_count ; gids_i++) {
				gids_entry = EXTRACT_UINT(pd,offset+0);
				if (gtree)
				proto_tree_add_item(gtree, hf_rpc_auth_gid,
					offset, 4, gids_entry);
				offset+=4;
			}
			/* how can I NOW change the gitem to print a list with
				the first 16 gids? */
		}
		break;
		/*
		case AUTH_SHORT:

		break;
		*/
		/* I have no tcpdump file with such a packet to verify the
			info from the RFC 1050 */
		/*
		case AUTH_DES:

		break;
		*/
		default:
			if (length_full) {
				if (tree)
				proto_tree_add_text(tree,offset,
				length_full, "opaque data");
			}
	}
}

int
dissect_rpc_cred( const u_char *pd, int offset, frame_data *fd, proto_tree *tree )
{
	guint length;
	guint length_full;
	proto_item *citem;
	proto_tree *ctree;

	if (!BYTES_ARE_IN_FRAME(offset,8)) return offset;
	length = EXTRACT_UINT(pd,offset+4);
	length_full = rpc_roundup(length);
	if (!BYTES_ARE_IN_FRAME(offset+8,length_full)) return offset;

	if (tree) {
		citem = proto_tree_add_text(tree, offset, 8+length_full,
			"Credentials");
		ctree = proto_item_add_subtree(citem, ett_rpc_cred);
		dissect_rpc_auth(pd, offset, fd, ctree);
	}
	offset += 8 + length_full;

	return offset;
}


int
dissect_rpc_verf( const u_char *pd, int offset, frame_data *fd, proto_tree *tree )
{
	unsigned int length;
	unsigned int length_full;
	proto_item *vitem;
	proto_tree *vtree;

	if (!BYTES_ARE_IN_FRAME(offset,8)) return offset;
	length = EXTRACT_UINT(pd,offset+4);
	length_full = rpc_roundup(length);
	if (!BYTES_ARE_IN_FRAME(offset+8,length_full)) return offset;

	if (tree) {
		vitem = proto_tree_add_text(tree, offset, 8+length_full,
			"Verifier");
		vtree = proto_item_add_subtree(vitem, ett_rpc_verf);
		dissect_rpc_auth(pd, offset, fd, vtree);
	}
	offset += 8 + length_full;

	return offset;
}


gboolean
dissect_rpc( const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	guint32	msg_type;
	rpc_call_info rpc_key;
	rpc_call_info *rpc_call = NULL;
	rpc_prog_info_value *rpc_prog = NULL;
	rpc_prog_info_key rpc_prog_key;

	unsigned int xid;
	unsigned int rpcvers;
	unsigned int prog = 0;
	unsigned int vers = 0;
	unsigned int proc = 0;
	int	proto = 0;
	int	ett = 0;

	unsigned int reply_state;
	unsigned int accept_state;
	unsigned int reject_state;

	char *msg_type_name = NULL;
	char *progname;
	char *procname = NULL;
	static char procname_static[20];

	unsigned int vers_low;
	unsigned int vers_high;

	unsigned int auth_state;

	proto_item *rpc_item=NULL;
	proto_tree *rpc_tree = NULL;

	proto_item *pitem=NULL;
	proto_tree *ptree = NULL;
	int offset_old = offset;

	int use_rm = 0;
	guint32 rpc_rm = 0;

	rpc_call_info	rpc_call_msg;
	rpc_proc_info_key	key;
	rpc_proc_info_value	*value = NULL;
	conversation_t* conversation;
	static address null_address = { AT_NONE, 0, NULL };

	dissect_function_t *dissect_function = NULL;

	/* TCP uses record marking */
	use_rm = (pi.ptype == PT_TCP);

	/* the first 4 bytes are special in "record marking  mode" */
	if (use_rm) {
		if (!BYTES_ARE_IN_FRAME(offset,4))
			return FALSE;
		rpc_rm = EXTRACT_UINT(pd,offset);
		offset += 4;
	}

	/*
	 * Check to see whether this looks like an RPC call or reply.
	 */
	if (!BYTES_ARE_IN_FRAME(offset,8)) {
		/* Captured data in packet isn't enough to let us tell. */
		return FALSE;
	}

	/* both directions need at least this */
	msg_type = EXTRACT_UINT(pd,offset+4);

	switch (msg_type) {

	case RPC_CALL:
		/* check for RPC call */
		if (!BYTES_ARE_IN_FRAME(offset,16)) {
			/* Captured data in packet isn't enough to let us
			   tell. */
			return FALSE;
		}

		/* XID can be anything, we don't check it.
		   We already have the message type.
		   Check whether an RPC version number of 2 is in the
		   location where it would be, and that an RPC program
		   number we know about is in the locaton where it would be. */
		rpc_prog_key.prog = EXTRACT_UINT(pd,offset+12);
		if (EXTRACT_UINT(pd,offset+8) != 2 ||
		    ((rpc_prog = g_hash_table_lookup(rpc_progs, &rpc_prog_key))
		       == NULL)) {
			/* They're not, so it's probably not an RPC call. */
			return FALSE;
		}
		break;

	case RPC_REPLY:
		/* Check for RPC reply.  A reply must match a call that
		   we've seen, and the reply must be sent to the same
		   port and address that the call came from, and must
		   come from the port to which the call was sent.  (We
		   don't worry about the address to which the call was
		   sent and from which the reply was sent, because there's
		   no guarantee that the reply will come from the address
		   to which the call was sent.) */
		conversation = find_conversation(&null_address, &pi.dst,
		    pi.ptype, pi.srcport, pi.destport);
		if (conversation == NULL) {
			/* We haven't seen an RPC call for that conversation,
			   so we can't check for a reply to that call. */
			return FALSE;
		}

		/* The XIDs of the call and reply must match. */
		rpc_key.xid = EXTRACT_UINT(pd,offset+0);
		rpc_key.conversation = conversation;
		if ((rpc_call = rpc_call_lookup(&rpc_key)) == NULL) {
			/* The XID doesn't match a call from that
			   conversation, so it's probably not an RPC reply. */
			return FALSE;
		}
		break;

	default:
		/* The putative message type field contains neither
		   RPC_CALL nor RPC_REPLY, so it's not an RPC call or
		   reply. */
		return FALSE;
	}

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "RPC");

	if (tree) {
		rpc_item = proto_tree_add_item(tree, proto_rpc, offset, END_OF_FRAME, NULL);
		if (rpc_item) {
			rpc_tree = proto_item_add_subtree(rpc_item, ett_rpc);
		}
	}

	if (use_rm && rpc_tree) {
		proto_tree_add_item(rpc_tree,hf_rpc_lastfrag,
			offset-4, 4, (rpc_rm >> 31) & 0x1);
		proto_tree_add_item(rpc_tree,hf_rpc_fraglen,
			offset-4, 4, rpc_rm & RPC_RM_FRAGLEN);
	}

	xid      = EXTRACT_UINT(pd,offset+0);
	if (rpc_tree) {
		proto_tree_add_uint_format(rpc_tree,hf_rpc_xid,
			offset+0, 4, xid, "XID: 0x%x (%u)", xid, xid);
	}

	msg_type_name = val_to_str(msg_type,rpc_msg_type,"%u");
	if (rpc_tree) {
		proto_tree_add_item(rpc_tree, hf_rpc_msgtype,
			offset+4, 4, msg_type);
	}

	offset += 8;

	if (msg_type==RPC_CALL) {
		/* we know already the proto-entry, the ETT-const,
		   and "rpc_prog" */
		proto = rpc_prog->proto;
		ett = rpc_prog->ett;
		progname = rpc_prog->progname;

		rpcvers = EXTRACT_UINT(pd,offset+0);
		if (rpc_tree) {
			proto_tree_add_item(rpc_tree,
				hf_rpc_version, offset+0, 4, rpcvers);
		}

		prog = EXTRACT_UINT(pd,offset+4);
		
		if (rpc_tree) {
			proto_tree_add_uint_format(rpc_tree,
				hf_rpc_program, offset+4, 4, prog,
				"Program: %s (%u)", progname, prog);
		}
		
		if (check_col(fd, COL_PROTOCOL)) {
			/* Set the protocol name to the underlying
			   program name. */
			col_add_fstr(fd, COL_PROTOCOL, "%s", progname);
		}

		if (!BYTES_ARE_IN_FRAME(offset+8,4))
			return TRUE;
		vers = EXTRACT_UINT(pd,offset+8);
		if (rpc_tree) {
			proto_tree_add_item(rpc_tree,
				hf_rpc_programversion, offset+8, 4, vers);
		}

		if (!BYTES_ARE_IN_FRAME(offset+12,4))
			return TRUE;
		proc = EXTRACT_UINT(pd,offset+12);

		key.prog = prog;
		key.vers = vers;
		key.proc = proc;

		value = g_hash_table_lookup(rpc_procs,&key);
		if (value != NULL) {
			dissect_function = value->dissect_call;
			procname = value->name;
		}
		else {
			/* happens only with strange program versions or
			   non-existing dissectors */
			dissect_function = NULL;
			sprintf(procname_static, "proc-%u", proc);
			procname = procname_static;
		}
		if (rpc_tree) {
			proto_tree_add_uint_format(rpc_tree,
				hf_rpc_procedure, offset+12, 4, proc,
				"Procedure: %s (%u)", procname, proc);
		}

		if (check_col(fd, COL_INFO)) {
			col_add_fstr(fd, COL_INFO,"V%u %s %s XID 0x%x",
				vers,
				procname,
				msg_type_name,
				xid);
		}

		/* Keep track of the address and port whence the call came,
		   and the port to which the call is being sent, so that
		   we can match up calls wityh replies.  (We don't worry
		   about the address to which the call was sent and from
		   which the reply was sent, because there's no
		   guarantee that the reply will come from the address
		   to which the call was sent.) */
		conversation = find_conversation(&pi.src, &null_address,
		    pi.ptype, pi.srcport, pi.destport);
		if (conversation == NULL) {
			/* It's not part of any conversation - create a new one. */
			conversation = conversation_new(&pi.src, &null_address,
			    pi.ptype, pi.srcport, pi.destport, NULL);
		}

		/* prepare the key data */
		rpc_call_msg.xid = xid;
		rpc_call_msg.conversation = conversation;

		/* look up the request */
		if (rpc_call_lookup(&rpc_call_msg)) {
			/* duplicate request */
			if (check_col(fd, COL_INFO)) {
				col_append_fstr(fd, COL_INFO, " dup XID 0x%x", xid);
				if (rpc_tree) {
					proto_tree_add_item_hidden(rpc_tree,
						hf_rpc_dup, 0,0, xid);
					proto_tree_add_item_hidden(rpc_tree,
						hf_rpc_call_dup, 0,0, xid);
				}
			}
		}
		else {
			/* prepare the value data */
			rpc_call_msg.replies = 0;
			rpc_call_msg.prog = prog;
			rpc_call_msg.vers = vers;
			rpc_call_msg.proc = proc;
			rpc_call_msg.proc_info = value;
			/* store it */
			rpc_call_insert(&rpc_call_msg);
		}

		offset += 16;

		offset = dissect_rpc_cred(pd, offset, fd, rpc_tree);
		offset = dissect_rpc_verf(pd, offset, fd, rpc_tree);

		/* go to the next dissector */
		/* goto dissect_rpc_prog; */

	} /* end of RPC call */
	else if (msg_type == RPC_REPLY)
	{
		/* we know already the type from the calling routine,
		   and we already have "rpc_call" set above. */
		prog = rpc_call->prog;
		vers = rpc_call->vers;
		proc = rpc_call->proc;
		if (rpc_call->proc_info != NULL) {
			dissect_function = rpc_call->proc_info->dissect_reply;
			if (rpc_call->proc_info->name != NULL) {
				procname = rpc_call->proc_info->name;
			}
			else {
				sprintf(procname_static, "proc-%u", proc);
				procname = procname_static;
			}
		}
		else {
			dissect_function = NULL;
			sprintf(procname_static, "proc-%u", proc);
			procname = procname_static;
		}
		rpc_call->replies++;

		rpc_prog_key.prog = prog;
		if ((rpc_prog = g_hash_table_lookup(rpc_progs,&rpc_prog_key)) == NULL) {
			proto = 0;
			ett = 0;
			progname = "Unknown";
		}
		else {
			proto = rpc_prog->proto;
			ett = rpc_prog->ett;
			progname = rpc_prog->progname;

			if (check_col(fd, COL_PROTOCOL)) {
				/* Set the protocol name to the underlying
				   program name. */
				col_add_fstr(fd, COL_PROTOCOL, "%s",
				    progname);
			}
		}

		if (check_col(fd, COL_INFO)) {
			col_add_fstr(fd, COL_INFO,"V%u %s %s XID 0x%x",
				vers,
				procname,
				msg_type_name,
				xid);
		}

		if (rpc_tree) {
			proto_tree_add_uint_format(rpc_tree,
				hf_rpc_program, 0, 0, prog,
				"Program: %s (%u)", progname, prog);
			proto_tree_add_item(rpc_tree,
				hf_rpc_programversion, 0, 0, vers);
			proto_tree_add_uint_format(rpc_tree,
				hf_rpc_procedure, 0, 0, proc,
				"Procedure: %s (%u)", procname, proc);
		}

		if (rpc_call->replies>1) {
			if (check_col(fd, COL_INFO)) {
				col_append_fstr(fd, COL_INFO, " dup XID 0x%x", xid);
				if (rpc_tree) {
					proto_tree_add_item_hidden(rpc_tree,
						hf_rpc_dup, 0,0, xid);
					proto_tree_add_item_hidden(rpc_tree,
						hf_rpc_reply_dup, 0,0, xid);
				}
			}
		}

		if (!BYTES_ARE_IN_FRAME(offset,4))
			return TRUE;
		reply_state = EXTRACT_UINT(pd,offset+0);
		if (rpc_tree) {
			proto_tree_add_item(rpc_tree, hf_rpc_state_reply,
				offset+0, 4, reply_state);
		}
		offset += 4;

		if (reply_state == MSG_ACCEPTED) {
			offset = dissect_rpc_verf(pd, offset, fd, rpc_tree);
			if (!BYTES_ARE_IN_FRAME(offset,4))
				return TRUE;
			accept_state = EXTRACT_UINT(pd,offset+0);
			if (rpc_tree) {
				proto_tree_add_item(rpc_tree, hf_rpc_state_accept,
					offset+0, 4, accept_state);
			}
			offset += 4;
			switch (accept_state) {
				case SUCCESS:
					/* now goto the lower protocol */
					goto dissect_rpc_prog;
				break;
				case PROG_MISMATCH:
					if (!BYTES_ARE_IN_FRAME(offset,8))
						return TRUE;
					vers_low = EXTRACT_UINT(pd,offset+0);
					vers_high = EXTRACT_UINT(pd,offset+4);
					if (rpc_tree) {
						proto_tree_add_item(rpc_tree,
							hf_rpc_programversion_min,
							offset+0, 4, vers_low);
						proto_tree_add_item(rpc_tree,
							hf_rpc_programversion_max,
							offset+4, 4, vers_high);
					}
					offset += 8;
				break;
				default:
					/* void */
				break;
			}
		} else if (reply_state == MSG_DENIED) {
			if (!BYTES_ARE_IN_FRAME(offset,4))
				return TRUE;
			reject_state = EXTRACT_UINT(pd,offset+0);
			if (rpc_tree) {
				proto_tree_add_item(rpc_tree,
					hf_rpc_state_reject, offset+0, 4,
					reject_state);
			}
			offset += 4;

			if (reject_state==RPC_MISMATCH) {
				if (!BYTES_ARE_IN_FRAME(offset,8))
					return TRUE;
				vers_low = EXTRACT_UINT(pd,offset+0);
				vers_high = EXTRACT_UINT(pd,offset+4);
				if (rpc_tree) {
					proto_tree_add_item(rpc_tree,
						hf_rpc_version_min,
						offset+0, 4, vers_low);
					proto_tree_add_item(rpc_tree,
						hf_rpc_version_max,
						offset+4, 4, vers_high);
				}
				offset += 8;
			} else if (reject_state==AUTH_ERROR) {
				if (!BYTES_ARE_IN_FRAME(offset,4))
					return TRUE;
				auth_state = EXTRACT_UINT(pd,offset+0);
				if (rpc_tree) {
					proto_tree_add_item(rpc_tree,
						hf_rpc_state_auth, offset+0, 4,
						auth_state);
				}
				offset += 4;
			}
		} 
	} /* end of RPC reply */

dissect_rpc_prog:
	/* I know, goto is evil but it works as it is. */

	/* now we know, that RPC was shorter */
	if (rpc_item) {
		proto_item_set_len(rpc_item, offset - offset_old);
	}

	/* create here the program specific sub-tree */
	if (tree) {
		pitem = proto_tree_add_item(tree, proto, offset, END_OF_FRAME);
		if (pitem) {
			ptree = proto_item_add_subtree(pitem, ett);
		}

		if (ptree) {
			proto_tree_add_item(ptree,
				hf_rpc_programversion, 0, 0, vers);
			proto_tree_add_uint_format(ptree,
				hf_rpc_procedure, 0, 0, proc,
				"Procedure: %s (%u)", procname, proc);
		}
	}

	/* call a specific dissection */
	if (dissect_function != NULL) {
		offset = dissect_function(pd, offset, fd, ptree);
	}

	/* dissect any remaining bytes (incomplete dissection) as pure data in
	   the ptree */
	dissect_data(pd, offset, fd, ptree);

	return TRUE;
}


/* Discard any state we've saved. */
static void
rpc_init_protocol(void)
{
	memset(rpc_call_table, '\0', sizeof rpc_call_table);
	rpc_call_index = 0;
	rpc_call_firstfree = 0;
}


/* will be called once from register.c at startup time */
void
proto_register_rpc(void)
{
	static hf_register_info hf[] = {
		{ &hf_rpc_lastfrag, {
			"Last Fragment", "rpc.lastfrag", FT_BOOLEAN, BASE_NONE,
			&yesno, 0, "Last Fragment" }},
		{ &hf_rpc_fraglen, {
			"Fragment Length", "rpc.fraglen", FT_UINT32, BASE_DEC,
			NULL, 0, "Fragment Length" }},
		{ &hf_rpc_xid, {
			"XID", "rpc.xid", FT_UINT32, BASE_HEX,
			NULL, 0, "XID" }},
		{ &hf_rpc_msgtype, {
			"Message Type", "rpc.msgtyp", FT_UINT32, BASE_DEC,
			VALS(rpc_msg_type), 0, "Message Type" }},
		{ &hf_rpc_state_reply, {
			"Reply State", "rpc.replystat", FT_UINT32, BASE_DEC,
			VALS(rpc_reply_state), 0, "Reply State" }},
		{ &hf_rpc_state_accept, {
			"Accept State", "rpc.state_accept", FT_UINT32, BASE_DEC,
			VALS(rpc_accept_state), 0, "Accept State" }},
		{ &hf_rpc_state_reject, {
			"Reject State", "rpc.state_reject", FT_UINT32, BASE_DEC,
			VALS(rpc_reject_state), 0, "Reject State" }},
		{ &hf_rpc_state_auth, {
			"Auth State", "rpc.state_auth", FT_UINT32, BASE_DEC,
			VALS(rpc_auth_state), 0, "Auth State" }},
		{ &hf_rpc_version, {
			"RPC Version", "rpc.version", FT_UINT32, BASE_DEC,
			NULL, 0, "RPC Version" }},
		{ &hf_rpc_version_min, {
			"RPC Version (Minimum)", "rpc.version.min", FT_UINT32, 
			BASE_DEC, NULL, 0, "Program Version (Minimum)" }},
		{ &hf_rpc_version_max, {
			"RPC Version (Maximum)", "rpc.version.max", FT_UINT32, 
			BASE_DEC, NULL, 0, "RPC Version (Maximum)" }},
		{ &hf_rpc_program, {
			"Program", "rpc.program", FT_UINT32, BASE_DEC,
			NULL, 0, "Program" }},
		{ &hf_rpc_programversion, {
			"Program Version", "rpc.programversion", FT_UINT32, 
			BASE_DEC, NULL, 0, "Program Version" }},
		{ &hf_rpc_programversion_min, {
			"Program Version (Minimum)", "rpc.programversion.min", FT_UINT32, 
			BASE_DEC, NULL, 0, "Program Version (Minimum)" }},
		{ &hf_rpc_programversion_max, {
			"Program Version (Maximum)", "rpc.programversion.max", FT_UINT32, 
			BASE_DEC, NULL, 0, "Program Version (Maximum)" }},
		{ &hf_rpc_procedure, {
			"Procedure", "rpc.procedure", FT_UINT32, BASE_DEC,
			NULL, 0, "Procedure" }},
		{ &hf_rpc_auth_flavor, {
			"Flavor", "rpc.auth.flavor", FT_UINT32, BASE_DEC,
			VALS(rpc_auth_flavor), 0, "Flavor" }},
		{ &hf_rpc_auth_length, {
			"Length", "rpc.auth.length", FT_UINT32, BASE_DEC,
			NULL, 0, "Length" }},
		{ &hf_rpc_auth_stamp, {
			"Stamp", "rpc.auth.stamp", FT_UINT32, BASE_HEX,
			NULL, 0, "Stamp" }},
		{ &hf_rpc_auth_uid, {
			"UID", "rpc.auth.uid", FT_UINT32, BASE_DEC,
			NULL, 0, "UID" }},
		{ &hf_rpc_auth_gid, {
			"GID", "rpc.auth.gid", FT_UINT32, BASE_DEC,
			NULL, 0, "GID" }},
		{ &hf_rpc_auth_machinename, {
			"Machine Name", "rpc.auth.machinename", FT_STRING, 
			BASE_DEC, NULL, 0, "Machine Name" }},
		{ &hf_rpc_dup, {
			"Duplicate Transaction", "rpc.dup", FT_UINT32, BASE_DEC,
			NULL, 0, "Duplicate Transaction" }},
		{ &hf_rpc_call_dup, {
			"Duplicate Call", "rpc.call.dup", FT_UINT32, BASE_DEC,
			NULL, 0, "Duplicate Call" }},
		{ &hf_rpc_reply_dup, {
			"Duplicate Reply", "rpc.reply.dup", FT_UINT32, BASE_DEC,
			NULL, 0, "Duplicate Reply" }},
		{ &hf_rpc_value_follows, {
			"Value Follows", "rpc.value_follows", FT_BOOLEAN, BASE_NONE,
			&yesno, 0, "Value Follows" }}
	};
	static gint *ett[] = {
		&ett_rpc,
		&ett_rpc_string,
		&ett_rpc_cred,
		&ett_rpc_verf,
		&ett_rpc_gids,
	};

	proto_rpc = proto_register_protocol("Remote Procedure Call", "rpc");
	proto_register_field_array(proto_rpc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_init_routine(&rpc_init_protocol);

	/*
	 * Init the hash tables.  Dissectors for RPC protocols must
	 * have a "handoff registration" routine that registers the
	 * protocol with RPC; they must not do it in their protocol
	 * registration routine, as their protocol registration
	 * routine might be called before this routine is called and
	 * thus might be called before the hash tables are initialized,
	 * but it's guaranteed that all protocol registration routines
	 * will be called before any handoff registration routines
	 * are called.
	 */
	rpc_progs = g_hash_table_new(rpc_prog_hash, rpc_prog_equal);
	rpc_procs = g_hash_table_new(rpc_proc_hash, rpc_proc_equal);
}
