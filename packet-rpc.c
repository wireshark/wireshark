/* packet-rpc.c
 * Routines for rpc dissection
 * Copyright 1999, Uwe Girlich <Uwe.Girlich@philosys.de>
 * 
 * $Id: packet-rpc.c,v 1.3 1999/11/05 07:16:23 guy Exp $
 * 
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
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
#include "packet.h"
#include "conversation.h"
#include "packet-rpc.h"


const value_string rpc_msg_type[3] = {
	{ RPC_CALL, "Call" },
	{ RPC_REPLY, "Reply" },
	{ 0, NULL }
};

const value_string rpc_reply_state[3] = {
	{ MSG_ACCEPTED, "accepted" },
	{ MSG_DENIED, "denied" },
	{ 0, NULL }
};

const value_string rpc_auth_flavor[5] = {
	{ AUTH_NULL, "AUTH_NULL" },
	{ AUTH_UNIX, "AUTH_UNIX" },
	{ AUTH_SHORT, "AUTH_SHORT" },
	{ AUTH_DES, "AUTH_DES" },
	{ 0, NULL }
};

const value_string rpc_accept_state[6] = {
	{ SUCCESS, "RPC executed successfully" },
	{ PROG_UNAVAIL, "remote hasn't exported program" },
	{ PROG_MISMATCH, "remote can't support version #" },
	{ PROC_UNAVAIL, "program can't support procedure" },
	{ GARBAGE_ARGS, "procedure can't decode params" },
	{ 0, NULL }
};

const value_string rpc_reject_state[3] = {
	{ RPC_MISMATCH, "RPC_MISMATCH" },
	{ AUTH_ERROR, "AUTH_ERROR" },
	{ 0, NULL }
};

const value_string rpc_auth_state[6] = {
	{ AUTH_BADCRED, "bad credential (seal broken)" },
	{ AUTH_REJECTEDCRED, "client must begin new session" },
	{ AUTH_BADVERF, "bad verifier (seal broken)" },
	{ AUTH_REJECTEDVERF, "verifier expired or replayed" },
	{ AUTH_TOOWEAK, "rejected for security reasons" },
	{ 0, NULL }
};


/* the protocol number */
static int proto_rpc = -1;


/* Hash table with info on RPC program numbers */
GHashTable *rpc_progs;

/* Hash table with info on RPC procedure numbers */
GHashTable *rpc_procs;


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

	key = (rpc_prog_info_key *) g_malloc(sizeof(rpc_prog_info_key));
	key->prog = prog;

	value = (rpc_prog_info_value *) g_malloc(sizeof(rpc_prog_info_value));
	value->proto = proto;
	value->ett = ett;
	value->progname = proto_registrar_get_abbrev(proto);

	g_hash_table_insert(rpc_progs,key,value);
}

/*--------------------------------------*/
/* end of Hash array with program names */
/*--------------------------------------*/


/* Placeholder for future dissectors.
It should vanish, if they are finally present. Up to this point, this
minimal variant serves as a detector for RPC services and can even find
request/reply pairs. */

#define	BOOT_PROGRAM	100026
#define	MNT_PROGRAM	100005
#define	NLM_PROGRAM	100021
#define PMAP_PROGRAM	100000
#define STAT_PROGRAM	100024
#define YPBIND_PROGRAM	100007
#define YPSERV_PROGRAM	100004

static int proto_boot = -1;
static int proto_mnt = -1;
static int proto_nlm = -1;
static int proto_pmap = -1;
static int proto_stat = -1;
static int proto_ypbind = -1;
static int proto_ypserv = -1;

void init_incomplete_dissect(void)
{
	proto_boot = proto_register_protocol("Bootparameters", "BOOT");
	rpc_init_prog(proto_boot, BOOT_PROGRAM, ETT_BOOT);

	proto_mnt = proto_register_protocol("Mount", "MNT");
	rpc_init_prog(proto_mnt, MNT_PROGRAM, ETT_MNT);

	proto_nlm = proto_register_protocol("Network Lock Manager", "NLM");
	rpc_init_prog(proto_nlm, NLM_PROGRAM, ETT_NLM);

	proto_pmap = proto_register_protocol("Portmapper", "PMAP");
	rpc_init_prog(proto_pmap, PMAP_PROGRAM, ETT_PMAP);

	proto_stat = proto_register_protocol("Status", "STAT");
	rpc_init_prog(proto_stat, STAT_PROGRAM, ETT_STAT);

	proto_ypbind = proto_register_protocol("Yellow Page Bind", "YPBINB");
	rpc_init_prog(proto_ypbind, YPBIND_PROGRAM, ETT_YPBIND);

	proto_ypserv = proto_register_protocol("Yellow Page Server", "YPSERV");
	rpc_init_prog(proto_ypserv, YPSERV_PROGRAM, ETT_YPSERV);
}


/*
 * Init the hash tables. It will be called from ethereal_proto_init().
 * ethereal_proto_init() calls later proto_init(), which calls 
 * register_all_protocols().
 * The proto_register_<some rpc program> functions use these hash tables
 * here, so we need this order!
 */
void
init_dissect_rpc()
{
	rpc_progs = g_hash_table_new(rpc_prog_hash, rpc_prog_equal);
	rpc_procs = g_hash_table_new(rpc_proc_hash, rpc_proc_equal);
}

 
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
roundup(unsigned int a)
{
	unsigned int mod = a % 4;
	return a + ((mod)? 4-mod : 0);
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
		"%s (%s): %u", name, type, value);
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
				"%s (%s): %x%08x", name, type, value_high, value_low);
		else
			proto_tree_add_text(tree, offset, 8,
				"%s (%s): %u", name, type, value_low);
	}

	offset += 8;
	return offset;
}



/* arbitrary limit */
#define RPC_STRING_MAXBUF 1024

int
dissect_rpc_string(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name)
{
	proto_item *string_item;
	proto_tree *string_tree = NULL;

	guint32 string_length;
	guint32 string_fill;
	guint32 string_length_full;
	char string_buffer[RPC_STRING_MAXBUF];

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	string_length = EXTRACT_UINT(pd,offset+0);
	string_length_full = roundup(string_length);
	string_fill = string_length_full - string_length;
	if (!BYTES_ARE_IN_FRAME(offset+4,string_length_full)) return offset;
	if (string_length>=sizeof(string_buffer)) return offset;
	memcpy(string_buffer,pd+offset+4,string_length);
	string_buffer[string_length] = '\0';
	if (tree) {
		string_item = proto_tree_add_text(tree,offset+0,
			4+string_length_full,
			"%s: %s", name, string_buffer);
		if (string_item) {
			string_tree = proto_item_add_subtree(string_item, ETT_RPC_STRING);
		}
	}
	if (string_tree) {
		proto_tree_add_text(string_tree,offset+0,4,
			"length: %u", string_length);
		proto_tree_add_text(string_tree,offset+4,string_length,
			"text: %s", string_buffer);
		if (string_fill)
			proto_tree_add_text(string_tree,offset+4+string_length,string_fill,
				"fill bytes: opaque data");
	}

	offset += 4 + string_length_full;
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
	length_full = roundup(length);
	/* if (!BYTES_ARE_IN_FRAME(offset+8,full_length)) return; */

	if (tree) {
		proto_tree_add_text(tree,offset+0,4,
		"Flavor: %s (%u)", val_to_str(flavor,rpc_auth_flavor,"Unknown"),flavor);
		proto_tree_add_text(tree,offset+4,4,
			"Length: %u", length);
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
				proto_tree_add_text(tree,offset+0,4,
					"stamp: 0x%08x", stamp);
			offset += 4;

			offset = dissect_rpc_string(pd,offset,fd,tree,"machinename");

			if (!BYTES_ARE_IN_FRAME(offset,4)) return;
			uid = EXTRACT_UINT(pd,offset+0);
			if (tree)
				proto_tree_add_text(tree,offset+0,4,
					"uid: %u", uid);
			offset += 4;

			if (!BYTES_ARE_IN_FRAME(offset,4)) return;
			gid = EXTRACT_UINT(pd,offset+0);
			if (tree)
				proto_tree_add_text(tree,offset+0,4,
					"gid: %u", gid);
			offset += 4;

			if (!BYTES_ARE_IN_FRAME(offset,4)) return;
			gids_count = EXTRACT_UINT(pd,offset+0);
			if (tree) {
				gitem = proto_tree_add_text(tree, offset, 4+gids_count*4,
				"gids");
				gtree = proto_item_add_subtree(gitem, ETT_RPC_GIDS);
			}
			offset += 4;
			if (!BYTES_ARE_IN_FRAME(offset,4*gids_count)) return;
			for (gids_i = 0 ; gids_i < gids_count ; gids_i++) {
				gids_entry = EXTRACT_UINT(pd,offset+0);
				if (gtree)
				proto_tree_add_text(gtree, offset, 4, 
					"%u", gids_entry);
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
	length_full = roundup(length);
	if (!BYTES_ARE_IN_FRAME(offset+8,length_full)) return offset;

	if (tree) {
		citem = proto_tree_add_text(tree, offset, 8+length_full,
			"Credentials");
		ctree = proto_item_add_subtree(citem, ETT_RPC_CRED);
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
	length_full = roundup(length);
	if (!BYTES_ARE_IN_FRAME(offset+8,length_full)) return offset;

	if (tree) {
		vitem = proto_tree_add_text(tree, offset, 8+length_full,
			"Verifier");
		vtree = proto_item_add_subtree(vitem, ETT_RPC_VERF);
		dissect_rpc_auth(pd, offset, fd, vtree);
	}
	offset += 8 + length_full;

	return offset;
}


void
dissect_rpc( const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
		guint32	msg_type, void* info)
{
	unsigned int xid;
	unsigned int rpcvers;
	unsigned int prog;
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

	rpc_call_info	rpc_call_msg;
	rpc_proc_info_key	key;
	rpc_proc_info_value	*value = NULL;
	conversation_t* conversation;

	/* the last parameter can be either of these two types */
	rpc_call_info	*rpc_call;
	rpc_prog_info_key	rpc_prog_key;
	rpc_prog_info_value	*rpc_prog;

	dissect_function_t *dissect_function = NULL;

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "RPC");

	if (tree) {
		rpc_item = proto_tree_add_item(tree, proto_rpc, offset, END_OF_FRAME, NULL);
		if (rpc_item) {
			rpc_tree = proto_item_add_subtree(rpc_item, ETT_RPC);
		}
	}

	xid      = EXTRACT_UINT(pd,offset+0);
	if (rpc_tree) {
		proto_tree_add_text(rpc_tree,offset+0,4,
			"XID: 0x%x (%u)", xid, xid);
	}

	/* we should better compare this with the argument?! */
	msg_type = EXTRACT_UINT(pd,offset+4);
	msg_type_name = val_to_str(msg_type,rpc_msg_type,"%u");
	if (rpc_tree) {
		proto_tree_add_text(rpc_tree,offset+4,4,
			"msg_type: %s (%u)",
			msg_type_name, msg_type);
	}

	offset += 8;

	if (msg_type==RPC_CALL) {
		/* we know already the proto-entry and the ETT-const */
		rpc_prog = (rpc_prog_info_value*)info;
		proto = rpc_prog->proto;
		ett = rpc_prog->ett;
		progname = rpc_prog->progname;

		rpcvers = EXTRACT_UINT(pd,offset+0);
		if (rpc_tree) {
			proto_tree_add_text(rpc_tree,offset+0,4,
				"RPC Version: %u", rpcvers);
		}

		prog = EXTRACT_UINT(pd,offset+4);
		
		if (rpc_tree) {
			proto_tree_add_text(rpc_tree,offset+4,4,
				"Program: %s (%u)", progname, prog);
		}
		
		if (check_col(fd, COL_PROTOCOL)) {
			/* Set the protocol name to the underlying
			   program name. */
			col_add_fstr(fd, COL_PROTOCOL, "%s", progname);
		}

		if (!BYTES_ARE_IN_FRAME(offset+8,4)) return;
		vers = EXTRACT_UINT(pd,offset+8);
		if (rpc_tree) {
			proto_tree_add_text(rpc_tree,offset+8,4,
				"Program Version: %u",vers);
		}

		if (!BYTES_ARE_IN_FRAME(offset+12,4)) return;
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
			proto_tree_add_text(rpc_tree,offset+12,4,
				"Procedure: %s (%u)", procname, proc);
		}

		if (check_col(fd, COL_INFO)) {
			col_add_fstr(fd, COL_INFO,"V%u %s %s XID 0x%x",
				vers,
				procname,
				msg_type_name,
				xid);
		}

		conversation = find_conversation(&pi.src, &pi.dst, pi.ptype,
			pi.srcport, pi.destport);
		if (conversation == NULL) {
			/* It's not part of any conversation - create a new one. */
			conversation = conversation_new(&pi.src, &pi.dst, pi.ptype,
				pi.srcport, pi.destport, NULL);
		}

		/* prepare the key data */
		rpc_call_msg.xid = xid;
		rpc_call_msg.conversation = conversation;

		/* look up the request */
		if (rpc_call_lookup(&rpc_call_msg)) {
			/* duplicate request */
			if (check_col(fd, COL_INFO)) {
				col_append_fstr(fd, COL_INFO, " dup XID 0x%x", xid);
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
		/* we know already the type from the calling routine */
		rpc_call = (rpc_call_info*)info;
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
			proto_tree_add_text(rpc_tree,0,0,
				"Program: %s (%u)", 
				progname, prog);
			proto_tree_add_text(rpc_tree,0,0,
				"Program Version: %u", vers);
			proto_tree_add_text(rpc_tree,0,0,
				"Procedure: %s (%u)", procname, proc);
		}

		if (rpc_call->replies>1) {
			if (check_col(fd, COL_INFO)) {
				col_append_fstr(fd, COL_INFO, " dup XID 0x%x", xid);
			}
		}

		if (!BYTES_ARE_IN_FRAME(offset,4)) return;
		reply_state = EXTRACT_UINT(pd,offset+0);
		if (rpc_tree) {
			proto_tree_add_text(rpc_tree,offset+0, 4,
				"Reply State: %s (%u)",
				val_to_str(reply_state,rpc_reply_state,"Unknown"),
				reply_state);
		}
		offset += 4;

		if (reply_state == MSG_ACCEPTED) {
			offset = dissect_rpc_verf(pd, offset, fd, rpc_tree);
			if (!BYTES_ARE_IN_FRAME(offset,4)) return;
			accept_state = EXTRACT_UINT(pd,offset+0);
			if (rpc_tree) {
				proto_tree_add_text(rpc_tree,offset+0, 4,
					"Accept State: %s (%u)", 
					val_to_str(accept_state,rpc_accept_state,"Unknown"),
					accept_state);
			}
			offset += 4;
			switch (accept_state) {
				case SUCCESS:
					/* now goto the lower protocol */
					goto dissect_rpc_prog;
				break;
				case PROG_MISMATCH:
					if (!BYTES_ARE_IN_FRAME(offset,8)) return;
					vers_low = EXTRACT_UINT(pd,offset+0);
					vers_high = EXTRACT_UINT(pd,offset+4);
					if (rpc_tree) {
						proto_tree_add_text(rpc_tree,
							offset+0, 4,
							"min. Program Version: %u",
							vers_low);
						proto_tree_add_text(rpc_tree,
							offset+4, 4,
							"max. Program Version: %u",
							vers_high);
					}
					offset += 8;
				break;
				default:
					/* void */
				break;
			}
		} else if (reply_state == MSG_DENIED) {
			if (!BYTES_ARE_IN_FRAME(offset,4)) return;
			reject_state = EXTRACT_UINT(pd,offset+0);
			if (rpc_tree) {
				proto_tree_add_text(rpc_tree, offset+0, 4,
					"Reject State: %s (%u)",
					val_to_str(reject_state,rpc_reject_state,"Unknown"),
					reject_state);
			}
			offset += 4;

			if (reject_state==RPC_MISMATCH) {
				if (!BYTES_ARE_IN_FRAME(offset,8)) return;
				vers_low = EXTRACT_UINT(pd,offset+0);
				vers_high = EXTRACT_UINT(pd,offset+4);
				if (rpc_tree) {
					proto_tree_add_text(rpc_tree,
						offset+0, 4,
						"min. RPC Version: %u",
						vers_low);
					proto_tree_add_text(rpc_tree,
						offset+4, 4,
						"max. RPC Version: %u",
						vers_high);
				}
				offset += 8;
			} else if (reject_state==AUTH_ERROR) {
				if (!BYTES_ARE_IN_FRAME(offset,4)) return;
				auth_state = EXTRACT_UINT(pd,offset+0);
				if (rpc_tree) {
					proto_tree_add_text(rpc_tree,
						offset+0, 4,
						"Authentication error: %s (%u)",
						val_to_str(auth_state,rpc_auth_state,"Unknown"),
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
		if (pitem)
			ptree = proto_item_add_subtree(pitem, ett);
		}

	/* call a specific dissection */
	if (dissect_function != NULL) {
		offset = dissect_function(pd, offset, fd, ptree);
	}

	/* dissect any remaining bytes (incomplete dissection) as pure data in
	   the ptree */
	dissect_data(pd, offset, fd, ptree);
}

/* will be called from file.c on every new file open */
void
rpc_init_protocol(void)
{
	rpc_call_index = 0;
	rpc_call_firstfree = 0;
}


/* will be called once from register.c at startup time */
void
proto_register_rpc(void)
{
	proto_rpc = proto_register_protocol("Remote Procedure Call", "rpc");

	/* please remove this, if all specific dissectors are ready */
	init_incomplete_dissect();
}

