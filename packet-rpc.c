/* packet-rpc.c
 * Routines for rpc dissection
 * Copyright 1999, Uwe Girlich <Uwe.Girlich@philosys.de>
 * 
 * $Id: packet-rpc.c,v 1.44 2000/11/21 14:58:07 girlich Exp $
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

/*
 * See:
 *
 *	RFC 1831, "RPC: Remote Procedure Call Protocol Specification
 *	Version 2";
 *
 *	RFC 1832, "XDR: External Data Representation Standard";
 *
 *	RFC 2203, "RPCSEC_GSS Protocol Specification".
 *
 * See also
 *
 *	RFC 2695, "Authentication Mechanisms for ONC RPC"
 *
 *	although we don't currently dissec AUTH_DES or AUTH_KERB.
 */

#define RPC_RM_FRAGLEN  0x7fffffffL

static struct true_false_string yesno = { "Yes", "No" };


static const value_string rpc_msg_type[] = {
	{ RPC_CALL, "Call" },
	{ RPC_REPLY, "Reply" },
	{ 0, NULL }
};

static const value_string rpc_reply_state[] = {
	{ MSG_ACCEPTED, "accepted" },
	{ MSG_DENIED, "denied" },
	{ 0, NULL }
};

const value_string rpc_auth_flavor[] = {
	{ AUTH_NULL, "AUTH_NULL" },
	{ AUTH_UNIX, "AUTH_UNIX" },
	{ AUTH_SHORT, "AUTH_SHORT" },
	{ AUTH_DES, "AUTH_DES" },
	{ RPCSEC_GSS, "RPCSEC_GSS" },
	{ 0, NULL }
};

static const value_string rpc_authgss_proc[] = {
	{ RPCSEC_GSS_DATA, "RPCSEC_GSS_DATA" },
	{ RPCSEC_GSS_INIT, "RPCSEC_GSS_INIT" },
	{ RPCSEC_GSS_CONTINUE_INIT, "RPCSEC_GSS_CONTINUE_INIT" },
	{ RPCSEC_GSS_DESTROY, "RPCSEC_GSS_DESTROY" },
	{ 0, NULL }
};

static const value_string rpc_authgss_svc[] = {
	{ RPCSEC_GSS_SVC_NONE, "rpcsec_gss_svc_none" },
	{ RPCSEC_GSS_SVC_INTEGRITY, "rpcsec_gss_svc_integrity" },
	{ RPCSEC_GSS_SVC_PRIVACY, "rpcsec_gss_svc_privacy" },
	{ 0, NULL }
};

static const value_string rpc_accept_state[] = {
	{ SUCCESS, "RPC executed successfully" },
	{ PROG_UNAVAIL, "remote hasn't exported program" },
	{ PROG_MISMATCH, "remote can't support version #" },
	{ PROC_UNAVAIL, "program can't support procedure" },
	{ GARBAGE_ARGS, "procedure can't decode params" },
	{ 0, NULL }
};

static const value_string rpc_reject_state[] = {
	{ RPC_MISMATCH, "RPC_MISMATCH" },
	{ AUTH_ERROR, "AUTH_ERROR" },
	{ 0, NULL }
};

static const value_string rpc_auth_state[] = {
	{ AUTH_BADCRED, "bad credential (seal broken)" },
	{ AUTH_REJECTEDCRED, "client must begin new session" },
	{ AUTH_BADVERF, "bad verifier (seal broken)" },
	{ AUTH_REJECTEDVERF, "verifier expired or replayed" },
	{ AUTH_TOOWEAK, "rejected for security reasons" },
	{ RPCSEC_GSSCREDPROB, "GSS credential problem" },
	{ RPCSEC_GSSCTXPROB, "GSS context problem" },
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
static int hf_rpc_authgss_v = -1;
static int hf_rpc_authgss_proc = -1;
static int hf_rpc_authgss_seq = -1;
static int hf_rpc_authgss_svc = -1;
static int hf_rpc_authgss_ctx = -1;
static int hf_rpc_authgss_major = -1;
static int hf_rpc_authgss_minor = -1;
static int hf_rpc_authgss_window = -1;
static int hf_rpc_authgss_token = -1;
static int hf_rpc_authgss_data_length = -1;
static int hf_rpc_authgss_data = -1;
static int hf_rpc_authgss_checksum = -1;
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
static gint ett_rpc_gss_data = -1;

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
typedef struct _rpc_call_info {
	guint32	xid;
	conversation_t *conversation;
	guint32	req_num;	/* frame number of first request seen */
	guint32	rep_num;	/* frame number of first reply seen */
	guint32	prog;
	guint32	vers;
	guint32	proc;
	guint32 flavor;
	guint32 gss_proc;
	guint32 gss_svc;
	rpc_proc_info_value*	proc_info;
} rpc_call_info;

#define RPC_CALL_TABLE_LENGTH 1000

rpc_call_info rpc_call_table[RPC_CALL_TABLE_LENGTH];
guint32 rpc_call_index = 0;
guint32 rpc_call_firstfree = 0;

static void
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


static rpc_call_info*
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
		proto_tree_add_boolean(tree, hfindex, NullTVB, offset, 4, value);
	offset += 4;

	return offset;
}


int
dissect_rpc_bool_tvb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
int hfindex, int offset)
{
	if (tree)
		proto_tree_add_item(tree, hfindex, tvb, offset, 4, FALSE);
	return offset + 4;
}


int
dissect_rpc_uint32(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
char* name)
{
	guint32 value;

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	value = EXTRACT_UINT(pd, offset+0);

	if (tree) {
		proto_tree_add_text(tree, NullTVB, offset, 4,
		"%s: %u", name, value);
	}

	offset += 4;
	return offset;
}


int
dissect_rpc_uint32_tvb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
int hfindex, int offset)
{
	if (tree)
		proto_tree_add_item(tree, hfindex, tvb, offset, 4, FALSE);
	return offset + 4;
}


int
dissect_rpc_uint64(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
char* name)
{
	guint32 value_low;
	guint32 value_high;

	if (!BYTES_ARE_IN_FRAME(offset,8)) return offset;
	value_high = EXTRACT_UINT(pd, offset+0);
	value_low = EXTRACT_UINT(pd, offset+4);

	if (tree) {
		if (value_high)
			proto_tree_add_text(tree, NullTVB, offset, 8,
				"%s: 0x%x%08x", name, value_high, value_low);
		else
			proto_tree_add_text(tree, NullTVB, offset, 8,
				"%s: %u", name, value_low);
	}

	offset += 8;
	return offset;
}


int
dissect_rpc_uint64_tvb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
int hfindex, int offset)
{
	guint32 value_low;
	guint32 value_high;

	value_high = tvb_get_ntohl(tvb, offset + 0);
	value_low  = tvb_get_ntohl(tvb, offset + 4);

	if (tree) {
		if (value_high)
			proto_tree_add_text(tree, tvb, offset, 8,
				"%s: 0x%x%08x", proto_registrar_get_name(hfindex), value_high, value_low);
		else
			proto_tree_add_uint(tree, hfindex, tvb, offset, 8, value_low);
	}

	return offset + 8;
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
		string_item = proto_tree_add_text(tree, NullTVB,offset+0, END_OF_FRAME,
			"%s: %s", proto_registrar_get_name(hfindex), string_buffer_print);
		if (string_data) {
			proto_tree_add_string_hidden(tree, hfindex, NullTVB, offset+4,
				string_length_copy, string_buffer);
		}
		if (string_item) {
			string_tree = proto_item_add_subtree(string_item, ett_rpc_string);
		}
	}
	if (length_truncated) {
		if (string_tree)
			proto_tree_add_text(string_tree, NullTVB,
				offset,pi.captured_len-offset,
				"length: <TRUNCATED>");
		offset = pi.captured_len;
	} else {
		if (string_tree)
			proto_tree_add_text(string_tree, NullTVB,offset+0,4,
				"length: %u", string_length);
		offset += 4;

		if (string_tree)
			proto_tree_add_text(string_tree, NullTVB,offset,string_length_copy,
				"contents: %s", string_buffer_print);
		offset += string_length_copy;
		if (fill_length) {
			if (string_tree) {
				if (fill_truncated) {
					proto_tree_add_text(string_tree, NullTVB,
					offset,fill_length_copy,
					"fill bytes: opaque data<TRUNCATED>");
				}
				else {
					proto_tree_add_text(string_tree, NullTVB,
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
dissect_rpc_string_tvb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int hfindex, int offset, char **string_buffer_ret)
{
	const guint8 *pd;
	int compat_offset;
	int compat_offset_new;

	tvb_compat(tvb, &pd, &compat_offset);
	compat_offset += offset;
	
	compat_offset_new = dissect_rpc_string(pd, compat_offset, pinfo->fd,
				tree, hfindex, string_buffer_ret);
	offset += (compat_offset_new - compat_offset);
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
dissect_rpc_data_tvb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int hfindex, int offset)
{
	const guint8 *pd;
	int compat_offset;
	int compat_offset_new;

	tvb_compat(tvb, &pd, &compat_offset);
	compat_offset += offset;
	
	compat_offset_new = dissect_rpc_data(pd, compat_offset, pinfo->fd,
				tree, hfindex);
	offset += (compat_offset_new - compat_offset);
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
		proto_tree_add_boolean(tree,hf_rpc_value_follows, NullTVB,
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

static int
dissect_rpc_authunix_cred(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset)
{
	guint stamp;
	guint uid;
	guint gid;
	guint gids_count;
	guint gids_i;
	guint gids_entry;
	proto_item *gitem;
	proto_tree *gtree = NULL;

	if (!tvb_bytes_exist(tvb,offset,4)) return offset;
	stamp = tvb_get_ntohl(tvb,offset+0);
	if (tree)
		proto_tree_add_uint(tree, hf_rpc_auth_stamp, tvb,
			offset+0, 4, stamp);
	offset += 4;

	offset = dissect_rpc_string_tvb(tvb, pinfo, tree,
			hf_rpc_auth_machinename, offset, NULL);

	if (!tvb_bytes_exist(tvb,offset,4)) return offset;
	uid = tvb_get_ntohl(tvb,offset+0);
	if (tree)
		proto_tree_add_uint(tree, hf_rpc_auth_uid, tvb,
			offset+0, 4, uid);
	offset += 4;

	if (!tvb_bytes_exist(tvb,offset,4)) return offset;
	gid = tvb_get_ntohl(tvb,offset+0);
	if (tree)
		proto_tree_add_uint(tree, hf_rpc_auth_gid, tvb,
			offset+0, 4, gid);
	offset += 4;

	if (!tvb_bytes_exist(tvb,offset,4)) return offset;
	gids_count = tvb_get_ntohl(tvb,offset+0);
	if (tree) {
		gitem = proto_tree_add_text(tree, tvb,
			offset, 4+gids_count*4, "Auxiliary GIDs");
		gtree = proto_item_add_subtree(gitem, ett_rpc_gids);
	}
	offset += 4;
	
	if (!tvb_bytes_exist(tvb,offset,4*gids_count)) return offset;
	for (gids_i = 0 ; gids_i < gids_count ; gids_i++) {
		gids_entry = tvb_get_ntohl(tvb,offset+0);
		if (gtree)
		proto_tree_add_uint(gtree, hf_rpc_auth_gid, tvb,
			offset, 4, gids_entry);
		offset+=4;
	}
	/* how can I NOW change the gitem to print a list with
		the first 16 gids? */

	return offset;
}

static int
dissect_rpc_authgss_cred(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset)
{
	guint agc_v;
	guint agc_proc;
	guint agc_seq;
	guint agc_svc;

	if (!tvb_bytes_exist(tvb,offset,4)) return offset;
	agc_v = tvb_get_ntohl(tvb, offset+0);
	if (tree)
		proto_tree_add_uint(tree, hf_rpc_authgss_v,
				    tvb, offset+0, 4, agc_v);
	offset += 4;
	
	if (!tvb_bytes_exist(tvb,offset,4)) return offset;
	agc_proc = tvb_get_ntohl(tvb, offset+0);
	if (tree)
		proto_tree_add_uint(tree, hf_rpc_authgss_proc,
				    tvb, offset+0, 4, agc_proc);
	offset += 4;
	
	if (!tvb_bytes_exist(tvb,offset,4)) return offset;
	agc_seq = tvb_get_ntohl(tvb, offset+0);
	if (tree)
		proto_tree_add_uint(tree, hf_rpc_authgss_seq,
				    tvb, offset+0, 4, agc_seq);
	offset += 4;
	
	if (!tvb_bytes_exist(tvb,offset,4)) return offset;
	agc_svc = tvb_get_ntohl(tvb, offset+0);
	if (tree)
		proto_tree_add_uint(tree, hf_rpc_authgss_svc,
				    tvb, offset+0, 4, agc_svc);
	offset += 4;
	
	offset = dissect_rpc_data_tvb(tvb, pinfo, tree, hf_rpc_authgss_ctx,
			offset);
	
	return offset;
}

static int
dissect_rpc_cred(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset)
{
	guint flavor;
	guint length;

	proto_item *citem;
	proto_tree *ctree;

	if (!tvb_bytes_exist(tvb, offset,8)) return offset;
	flavor = tvb_get_ntohl(tvb,offset+0);
	length = tvb_get_ntohl(tvb,offset+4);
	length = rpc_roundup(length);
	if (!tvb_bytes_exist(tvb,offset+8,length)) return offset;

	if (tree) {
		citem = proto_tree_add_text(tree, tvb, offset,
					    8+length, "Credentials");
		ctree = proto_item_add_subtree(citem, ett_rpc_cred);
		proto_tree_add_uint(ctree, hf_rpc_auth_flavor, tvb,
				    offset+0, 4, flavor);
		proto_tree_add_uint(ctree, hf_rpc_auth_length, tvb,
				    offset+4, 4, length);

		switch (flavor) {
		case AUTH_UNIX:
			dissect_rpc_authunix_cred(tvb, pinfo, ctree, offset+8);
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
		case RPCSEC_GSS:
			dissect_rpc_authgss_cred(tvb, pinfo, ctree, offset+8);
			break;
		default:
			if (length)
				proto_tree_add_text(ctree, tvb, offset+8,
						    length,"opaque data");
		break;
		}
	}
	offset += 8 + length;

	return offset;
}

static int
dissect_rpc_verf(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset)
{
	guint flavor;
	guint length;
	
	proto_item *vitem;
	proto_tree *vtree;

	if (!tvb_bytes_exist(tvb,offset,8)) return offset;
	flavor = tvb_get_ntohl(tvb,offset+0);
	length = tvb_get_ntohl(tvb,offset+4);
	length = rpc_roundup(length);
	if (!tvb_bytes_exist(tvb,offset+8,length)) return offset;

	if (tree) {
		vitem = proto_tree_add_text(tree, tvb, offset,
					    8+length, "Verifier");
		vtree = proto_item_add_subtree(vitem, ett_rpc_verf);
		proto_tree_add_uint(vtree, hf_rpc_auth_flavor, tvb,
				    offset+0, 4, flavor);

		switch (flavor) {
		case AUTH_UNIX:
			proto_tree_add_uint(vtree, hf_rpc_auth_length, tvb,
					    offset+4, 4, length);
			dissect_rpc_authunix_cred(tvb, pinfo, vtree, offset+8);
			break;
		case RPCSEC_GSS:
			dissect_rpc_data_tvb(tvb, pinfo, vtree,
				hf_rpc_authgss_checksum, offset+4);
			break;
		default:
			proto_tree_add_uint(vtree, hf_rpc_auth_length, tvb,
					    offset+4, 4, length);
			if (length)
				proto_tree_add_text(vtree, tvb, offset+8,
						    length, "opaque data");
			break;
		}
	}
	offset += 8 + length;

	return offset;
}

static int
dissect_rpc_authgss_initarg(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset)
{
	offset = dissect_rpc_data_tvb(tvb, pinfo, tree, hf_rpc_authgss_token,
			offset);
	return offset;
}

static int
dissect_rpc_authgss_initres(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset)
{
	int major, minor, window;
	
	offset = dissect_rpc_data_tvb(tvb, pinfo, tree, hf_rpc_authgss_ctx,
			offset);
	
	if (!tvb_bytes_exist(tvb,offset,4)) return offset;
	major = tvb_get_ntohl(tvb,offset+0);
	if (tree)
		proto_tree_add_uint(tree, hf_rpc_authgss_major, tvb,
				    offset+0, 4, major);
	offset += 4;

	if (!tvb_bytes_exist(tvb,offset,4)) return offset;
	minor = tvb_get_ntohl(tvb,offset+0);
	if (tree)
		proto_tree_add_uint(tree, hf_rpc_authgss_minor, tvb,
				    offset+0, 4, minor);
	offset += 4;

	if (!tvb_bytes_exist(tvb,offset,4)) return offset;
	window = tvb_get_ntohl(tvb,offset+0);
	if (tree)
		proto_tree_add_uint(tree, hf_rpc_authgss_window, tvb,
				    offset+0, 4, window);
	offset += 4;

	offset = dissect_rpc_data_tvb(tvb, pinfo, tree, hf_rpc_authgss_token,
			offset);

	return offset;
}


static int
call_dissect_function(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, dissect_function_t* dissect_function)
{
	if (dissect_function != NULL) {
		tvbuff_t *next_tvb;
		const guint8 *next_pd;
		int next_offset;
		int offset_diff;

		/* make a new tvbuff subset */
		next_tvb = tvb_new_subset(tvb, offset, -1, -1);

		/* make a new pd,offset pair */
		tvb_compat(next_tvb, &next_pd, &next_offset);

		/* with this difference we can switch to/from old offsets */
		offset_diff = next_offset - offset;

		/* call the dissector for the next level */
		next_offset = dissect_function(next_pd, next_offset,
					pinfo->fd, tree);

		/* correct the tvb offset */
		offset = next_offset - offset_diff;
	}

	return offset;
}


static int
dissect_rpc_authgss_integ_data(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int offset, dissect_function_t* dissect_function)
{
	guint32 length, seq;
	
	proto_item *gitem;
	proto_tree *gtree;

	if (!tvb_bytes_exist(tvb, offset, 8)) return offset;
	length = tvb_get_ntohl(tvb, offset+0);
	length = rpc_roundup(length);
	seq = tvb_get_ntohl(tvb, offset+4);

	if (tree) {
		gitem = proto_tree_add_text(tree, tvb, offset,
					    4+length, "GSS Data");
		gtree = proto_item_add_subtree(gitem, ett_rpc_gss_data);
		proto_tree_add_uint(gtree, hf_rpc_authgss_data_length,
				    tvb, offset+0, 4, length);
		proto_tree_add_uint(gtree, hf_rpc_authgss_seq,
				    tvb, offset+4, 4, seq);
		if (dissect_function != NULL)
			/* offset = */
			call_dissect_function(tvb, pinfo, gtree,
				offset, dissect_function);
	}
	offset += 8 + length;
	offset = dissect_rpc_data_tvb(tvb, pinfo, tree, hf_rpc_authgss_checksum,
			offset);
	return offset;
}


static int
dissect_rpc_authgss_priv_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	offset = dissect_rpc_data_tvb(tvb, pinfo, tree, hf_rpc_authgss_data,
			offset);
	return offset;
}


gboolean
dissect_rpc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
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
	unsigned int flavor = 0;
	unsigned int gss_proc = 0;
	unsigned int gss_svc = 0;
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

	if (!proto_is_protocol_enabled(proto_rpc))
	  return FALSE;

	/* TCP uses record marking */
	use_rm = (pi.ptype == PT_TCP);

	/* the first 4 bytes are special in "record marking  mode" */
	if (use_rm) {
		if (!tvb_bytes_exist(tvb, offset, 4))
			return FALSE;
		rpc_rm = tvb_get_ntohl(tvb, offset);
		offset += 4;
	}

	/*
	 * Check to see whether this looks like an RPC call or reply.
	 */
	if (!tvb_bytes_exist(tvb, offset, 8)) {
		/* Captured data in packet isn't enough to let us tell. */
		return FALSE;
	}

	/* both directions need at least this */
	msg_type = tvb_get_ntohl(tvb, offset + 4);

	switch (msg_type) {

	case RPC_CALL:
		/* check for RPC call */
		if (!tvb_bytes_exist(tvb, offset, 16)) {
			/* Captured data in packet isn't enough to let us
			   tell. */
			return FALSE;
		}

		/* XID can be anything, we don't check it.
		   We already have the message type.
		   Check whether an RPC version number of 2 is in the
		   location where it would be, and that an RPC program
		   number we know about is in the locaton where it would be. */
		rpc_prog_key.prog = tvb_get_ntohl(tvb, offset + 12);
		if (tvb_get_ntohl(tvb, offset + 8) != 2 ||
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
		    pi.ptype, pi.srcport, pi.destport, 0);
		if (conversation == NULL) {
			/* We haven't seen an RPC call for that conversation,
			   so we can't check for a reply to that call. */
			return FALSE;
		}

		/* The XIDs of the call and reply must match. */
		rpc_key.xid = tvb_get_ntohl(tvb, offset + 0);
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

	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_set_str(pinfo->fd, COL_PROTOCOL, "RPC");

	if (tree) {
		rpc_item = proto_tree_add_item(tree, proto_rpc, tvb, 0,
				tvb_length(tvb), FALSE);
		if (rpc_item) {
			rpc_tree = proto_item_add_subtree(rpc_item, ett_rpc);
		}
	}

	if (use_rm && rpc_tree) {
		proto_tree_add_boolean(rpc_tree,hf_rpc_lastfrag, tvb,
			offset-4, 4, (rpc_rm >> 31) & 0x1);
		proto_tree_add_uint(rpc_tree,hf_rpc_fraglen, tvb,
			offset-4, 4, rpc_rm & RPC_RM_FRAGLEN);
	}

	xid      = tvb_get_ntohl(tvb, offset + 0);
	if (rpc_tree) {
		proto_tree_add_uint_format(rpc_tree,hf_rpc_xid, tvb,
			offset+0, 4, xid, "XID: 0x%x (%u)", xid, xid);
	}

	msg_type_name = val_to_str(msg_type,rpc_msg_type,"%u");
	if (rpc_tree) {
		proto_tree_add_uint(rpc_tree, hf_rpc_msgtype, tvb,
			offset+4, 4, msg_type);
	}

	offset += 8;

	if (msg_type==RPC_CALL) {
		/* we know already the proto-entry, the ETT-const,
		   and "rpc_prog" */
		proto = rpc_prog->proto;
		ett = rpc_prog->ett;
		progname = rpc_prog->progname;

		rpcvers = tvb_get_ntohl(tvb, offset + 0);
		if (rpc_tree) {
			proto_tree_add_uint(rpc_tree,
				hf_rpc_version, tvb, offset+0, 4, rpcvers);
		}

		prog = tvb_get_ntohl(tvb, offset + 4);
		
		if (rpc_tree) {
			proto_tree_add_uint_format(rpc_tree,
				hf_rpc_program, tvb, offset+4, 4, prog,
				"Program: %s (%u)", progname, prog);
		}
		
		if (check_col(pinfo->fd, COL_PROTOCOL)) {
			/* Set the protocol name to the underlying
			   program name. */
			col_add_fstr(pinfo->fd, COL_PROTOCOL, "%s", progname);
		}

		if (!tvb_bytes_exist(tvb, offset+8,4))
			return TRUE;
		vers = tvb_get_ntohl(tvb, offset+8);
		if (rpc_tree) {
			proto_tree_add_uint(rpc_tree,
				hf_rpc_programversion, tvb, offset+8, 4, vers);
		}

		if (!tvb_bytes_exist(tvb, offset+12,4))
			return TRUE;
		proc = tvb_get_ntohl(tvb, offset+12);

		/* Check for RPCSEC_GSS */
		if (proc == 0 && tvb_bytes_exist(tvb, offset+16,28)) {
			flavor = tvb_get_ntohl(tvb, offset+16);
			if (flavor == RPCSEC_GSS) {
				gss_proc = tvb_get_ntohl(tvb, offset+28);
				gss_svc = tvb_get_ntohl(tvb, offset+34);
			}
		}
		key.prog = prog;
		key.vers = vers;
		key.proc = proc;

		if ((value = g_hash_table_lookup(rpc_procs,&key)) != NULL) {
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
				hf_rpc_procedure, tvb, offset+12, 4, proc,
				"Procedure: %s (%u)", procname, proc);
		}

		if (check_col(pinfo->fd, COL_INFO)) {
			col_add_fstr(pinfo->fd, COL_INFO,"V%u %s %s XID 0x%x",
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
		    pi.ptype, pi.srcport, pi.destport, 0);
		if (conversation == NULL) {
			/* It's not part of any conversation - create a new one. */
			conversation = conversation_new(&pi.src, &null_address,
			    pi.ptype, pi.srcport, pi.destport, NULL, 0);
		}

		/* prepare the key data */
		rpc_call_msg.xid = xid;
		rpc_call_msg.conversation = conversation;

		/* look up the request */
		if ((rpc_call = rpc_call_lookup(&rpc_call_msg)) != NULL) {
			/* We've seen a request with this XID, with the same
			   source and destination, before - but was it
			   *this* request? */
			if (pinfo->fd->num != rpc_call->req_num) {
				/* No, so it's a duplicate request.
				   Mark it as such. */
				if (check_col(pinfo->fd, COL_INFO)) {
					col_append_fstr(pinfo->fd, COL_INFO,
						" dup XID 0x%x", xid);
					if (rpc_tree) {
						proto_tree_add_uint_hidden(rpc_tree,
							hf_rpc_dup, tvb, 0,0, xid);
						proto_tree_add_uint_hidden(rpc_tree,
							hf_rpc_call_dup, tvb, 0,0, xid);
					}
				}
			}
		}
		else {
			/* Prepare the value data.
			   "req_num" and "rep_num" are frame numbers;
			   frame numbers are 1-origin, so we use 0
			   to mean "we don't yet know in which frame
			   the reply for this call appears". */
			rpc_call_msg.req_num = pinfo->fd->num;
			rpc_call_msg.rep_num = 0;
			rpc_call_msg.prog = prog;
			rpc_call_msg.vers = vers;
			rpc_call_msg.proc = proc;
			rpc_call_msg.flavor = flavor;
			rpc_call_msg.gss_proc = gss_proc;
			rpc_call_msg.gss_svc = gss_svc;
			rpc_call_msg.proc_info = value;
			/* store it */
			rpc_call_insert(&rpc_call_msg);
		}

		offset += 16;

		offset = dissect_rpc_cred(tvb, pinfo, rpc_tree, offset);
		offset = dissect_rpc_verf(tvb, pinfo, rpc_tree, offset);

		/* go to the next dissector */

	} /* end of RPC call */
	else if (msg_type == RPC_REPLY)
	{
		/* we know already the type from the calling routine,
		   and we already have "rpc_call" set above. */
		prog = rpc_call->prog;
		vers = rpc_call->vers;
		proc = rpc_call->proc;
		flavor = rpc_call->flavor;
		gss_proc = rpc_call->gss_proc;
		gss_svc = rpc_call->gss_svc;

		/* Indicate the frame to which this is a reply. */
		proto_tree_add_text(rpc_tree, tvb, 0, 0,
		    "This is a reply to a request starting in frame %u",
		    rpc_call->req_num);

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

			if (check_col(pinfo->fd, COL_PROTOCOL)) {
				/* Set the protocol name to the underlying
				   program name. */
				col_add_fstr(pinfo->fd, COL_PROTOCOL, "%s",
				    progname);
			}
		}

		if (check_col(pinfo->fd, COL_INFO)) {
			col_add_fstr(pinfo->fd, COL_INFO,"V%u %s %s XID 0x%x",
				vers,
				procname,
				msg_type_name,
				xid);
		}

		if (rpc_tree) {
			proto_tree_add_uint_format(rpc_tree,
				hf_rpc_program, tvb, 0, 0, prog,
				"Program: %s (%u)", progname, prog);
			proto_tree_add_uint(rpc_tree,
				hf_rpc_programversion, tvb, 0, 0, vers);
			proto_tree_add_uint_format(rpc_tree,
				hf_rpc_procedure, tvb, 0, 0, proc,
				"Procedure: %s (%u)", procname, proc);
		}

		if (rpc_call->rep_num == 0) {
			/* We have not yet seen a reply to that call, so
			   this must be the first reply; remember its
			   frame number. */
			rpc_call->rep_num = pinfo->fd->num;
		} else {
			/* We have seen a reply to this call - but was it
			   *this* reply? */
			if (rpc_call->rep_num != pinfo->fd->num) {
				/* No, so it's a duplicate reply.
				   Mark it as such. */
				if (check_col(pinfo->fd, COL_INFO)) {
					col_append_fstr(pinfo->fd, COL_INFO,
						" dup XID 0x%x", xid);
					if (rpc_tree) {
						proto_tree_add_uint_hidden(rpc_tree,
							hf_rpc_dup, tvb, 0,0, xid);
						proto_tree_add_uint_hidden(rpc_tree,
							hf_rpc_reply_dup, tvb, 0,0, xid);
					}
				}
			}
		}

		if (!tvb_bytes_exist(tvb, offset,4))
			return TRUE;
		reply_state = tvb_get_ntohl(tvb,offset+0);
		if (rpc_tree) {
			proto_tree_add_uint(rpc_tree, hf_rpc_state_reply, tvb,
				offset+0, 4, reply_state);
		}
		offset += 4;

		if (reply_state == MSG_ACCEPTED) {
			offset = dissect_rpc_verf(tvb, pinfo, rpc_tree, offset);
			if (!tvb_bytes_exist(tvb, offset,4))
				return TRUE;
			accept_state = tvb_get_ntohl(tvb,offset+0);
			if (rpc_tree) {
				proto_tree_add_uint(rpc_tree, hf_rpc_state_accept, tvb,
					offset+0, 4, accept_state);
			}
			offset += 4;
			switch (accept_state) {
				case SUCCESS:
					/* go to the next dissector */
				break;
				case PROG_MISMATCH:
					if (!tvb_bytes_exist(tvb,offset,8))
						return TRUE;
					vers_low = tvb_get_ntohl(tvb,offset+0);
					vers_high = tvb_get_ntohl(tvb,offset+4);
					if (rpc_tree) {
						proto_tree_add_uint(rpc_tree,
							hf_rpc_programversion_min,
							tvb, offset+0, 4, vers_low);
						proto_tree_add_uint(rpc_tree,
							hf_rpc_programversion_max,
							tvb, offset+4, 4, vers_high);
					}
					offset += 8;
				break;
				default:
					/* void */
				break;
			}
		} else if (reply_state == MSG_DENIED) {
			if (!tvb_bytes_exist(tvb,offset,4))
				return TRUE;
			reject_state = tvb_get_ntohl(tvb,offset+0);
			if (rpc_tree) {
				proto_tree_add_uint(rpc_tree,
					hf_rpc_state_reject, tvb, offset+0, 4,
					reject_state);
			}
			offset += 4;

			if (reject_state==RPC_MISMATCH) {
				if (!tvb_bytes_exist(tvb,offset,8))
					return TRUE;
				vers_low = tvb_get_ntohl(tvb,offset+0);
				vers_high = tvb_get_ntohl(tvb,offset+4);
				if (rpc_tree) {
					proto_tree_add_uint(rpc_tree,
						hf_rpc_version_min,
						tvb, offset+0, 4, vers_low);
					proto_tree_add_uint(rpc_tree,
						hf_rpc_version_max,
						tvb, offset+4, 4, vers_high);
				}
				offset += 8;
			} else if (reject_state==AUTH_ERROR) {
				if (!tvb_bytes_exist(tvb,offset,4))
					return TRUE;
				auth_state = tvb_get_ntohl(tvb,offset+0);
				if (rpc_tree) {
					proto_tree_add_uint(rpc_tree,
						hf_rpc_state_auth, tvb, offset+0, 4,
						auth_state);
				}
				offset += 4;
			}
		} 
	} /* end of RPC reply */

	/* now we know, that RPC was shorter */
	if (rpc_item) {
		proto_item_set_len(rpc_item, offset - offset_old);
	}

	/* create here the program specific sub-tree */
	if (tree) {
		pitem = proto_tree_add_item(tree, proto, tvb,
				offset, tvb_length(tvb) - offset, FALSE);
		if (pitem) {
			ptree = proto_item_add_subtree(pitem, ett);
		}

		if (ptree) {
			proto_tree_add_uint(ptree,
				hf_rpc_programversion, NullTVB, 0, 0, vers);
			proto_tree_add_uint_format(ptree,
				hf_rpc_procedure, NullTVB, 0, 0, proc,
				"Procedure: %s (%u)", procname, proc);
		}
	}

	if (!proto_is_protocol_enabled(proto)) {
		dissect_function = NULL;
	}

	/* RPCSEC_GSS processing. */
	if (flavor == RPCSEC_GSS) {
		switch (gss_proc) {
		case RPCSEC_GSS_INIT:
		case RPCSEC_GSS_CONTINUE_INIT:
			if (msg_type == RPC_CALL) {
				offset = dissect_rpc_authgss_initarg(tvb,
					pinfo, ptree, offset);
			}
			else {
				offset = dissect_rpc_authgss_initres(tvb,
					pinfo, ptree, offset);
			}
			break;
		case RPCSEC_GSS_DATA:
			if (gss_svc == RPCSEC_GSS_SVC_NONE) {
				offset = call_dissect_function(tvb, 
						pinfo, ptree, offset, 
						dissect_function);
			}
			else if (gss_svc == RPCSEC_GSS_SVC_INTEGRITY) {
				offset = dissect_rpc_authgss_integ_data(tvb,
						pinfo, ptree, offset,
						dissect_function);
			}
			else if (gss_svc == RPCSEC_GSS_SVC_PRIVACY) {
				offset = dissect_rpc_authgss_priv_data(tvb,
						pinfo, ptree, offset);
			}
			break;
		default:
			dissect_function = NULL;
			break;
		}
	}
	else {
		offset=call_dissect_function(tvb, pinfo, ptree, offset,
				dissect_function);
	}

	/* dissect any remaining bytes (incomplete dissection) as pure data in
	   the ptree */
	dissect_data(tvb, offset, pinfo, ptree);

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
		{ &hf_rpc_authgss_v, {
			"GSS Version", "rpc.authgss.version", FT_UINT32,
			BASE_DEC, NULL, 0, "GSS Version" }},
		{ &hf_rpc_authgss_proc, {
			"GSS Procedure", "rpc.authgss.procedure", FT_UINT32,
			BASE_DEC, VALS(rpc_authgss_proc), 0, "GSS Procedure" }},
		{ &hf_rpc_authgss_seq, {
			"GSS Sequence Number", "rpc.authgss.seqnum", FT_UINT32,
			BASE_DEC, NULL, 0, "GSS Sequence Number" }},
		{ &hf_rpc_authgss_svc, {
			"GSS Service", "rpc.authgss.service", FT_UINT32,
			BASE_DEC, VALS(rpc_authgss_svc), 0, "GSS Service" }},
		{ &hf_rpc_authgss_ctx, {
			"GSS Context", "rpc.authgss.context", FT_BYTES,
			BASE_HEX, NULL, 0, "GSS Context" }},
		{ &hf_rpc_authgss_major, {
			"GSS Major Status", "rpc.authgss.major", FT_UINT32,
			BASE_DEC, NULL, 0, "GSS Major Status" }},
		{ &hf_rpc_authgss_minor, {
			"GSS Minor Status", "rpc.authgss.minor", FT_UINT32,
			BASE_DEC, NULL, 0, "GSS Minor Status" }},
		{ &hf_rpc_authgss_window, {
			"GSS Sequence Window", "rpc.authgss.window", FT_UINT32,
			BASE_DEC, NULL, 0, "GSS Sequence Window" }},
		{ &hf_rpc_authgss_token, {
			"GSS Token", "rpc.authgss.token", FT_BYTES,
			BASE_HEX, NULL, 0, "GSS Token" }},
		{ &hf_rpc_authgss_data_length, {
			"Length", "rpc.authgss.data.length", FT_UINT32,
			BASE_DEC, NULL, 0, "Length" }},
		{ &hf_rpc_authgss_data, {
			"GSS Data", "rpc.authgss.data", FT_BYTES,
			BASE_HEX, NULL, 0, "GSS Data" }},
		{ &hf_rpc_authgss_checksum, {
			"GSS Checksum", "rpc.authgss.checksum", FT_BYTES,
			BASE_HEX, NULL, 0, "GSS Checksum" }},
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


void
proto_reg_handoff_rpc(void)
{
	heur_dissector_add("tcp", dissect_rpc);
	heur_dissector_add("udp", dissect_rpc);
}


