/* packet-rpc.c
 * Routines for rpc dissection
 * Copyright 1999, Uwe Girlich <Uwe.Girlich@philosys.de>
 * 
 * $Id: packet-rpc.c,v 1.73 2001/10/29 20:49:28 guy Exp $
 * 
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
#include "prefs.h"

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
 *	although we don't currently dissect AUTH_DES or AUTH_KERB.
 */

#define RPC_RM_FRAGLEN  0x7fffffffL

/* desegmentation of RPC over TCP */
static gboolean rpc_desegment = TRUE;

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

value_string rpc_authgss_svc[] = {
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

static const value_string rpc_authdes_namekind[] = {
	{ AUTHDES_NAMEKIND_FULLNAME, "ADN_FULLNAME" },
	{ AUTHDES_NAMEKIND_NICKNAME, "ADN_NICKNAME" },
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
static int hf_rpc_authdes_namekind = -1;
static int hf_rpc_authdes_netname = -1;
static int hf_rpc_authdes_convkey = -1;
static int hf_rpc_authdes_window = -1;
static int hf_rpc_authdes_nickname = -1;
static int hf_rpc_authdes_timestamp = -1;
static int hf_rpc_authdes_windowverf = -1;
static int hf_rpc_authdes_timeverf = -1;
static int hf_rpc_state_accept = -1;
static int hf_rpc_state_reply = -1;
static int hf_rpc_state_reject = -1;
static int hf_rpc_state_auth = -1;
static int hf_rpc_dup = -1;
static int hf_rpc_call_dup = -1;
static int hf_rpc_reply_dup = -1;
static int hf_rpc_value_follows = -1;
static int hf_rpc_array_len = -1;

static gint ett_rpc = -1;
static gint ett_rpc_string = -1;
static gint ett_rpc_cred = -1;
static gint ett_rpc_verf = -1;
static gint ett_rpc_gids = -1;
static gint ett_rpc_gss_data = -1;
static gint ett_rpc_array = -1;

/* Hash table with info on RPC program numbers */
static GHashTable *rpc_progs;

/* Hash table with info on RPC procedure numbers */
static GHashTable *rpc_procs;

typedef struct _rpc_proc_info_key {
	guint32	prog;
	guint32	vers;
	guint32	proc;
} rpc_proc_info_key;

typedef struct _rpc_proc_info_value {
	gchar		*name;
	dissect_function_t *dissect_call;
	dissect_function_t *dissect_reply;
} rpc_proc_info_value;

typedef struct _rpc_prog_info_key {
	guint32 prog;
} rpc_prog_info_key;

typedef struct _rpc_prog_info_value {
	int proto;
	int ett;
	char* progname;
} rpc_prog_info_value;

static void dissect_rpc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_rpc_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

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

/*	return the name associated with a previously registered procedure. */
char *rpc_proc_name(guint32 prog, guint32 vers, guint32 proc)
{
	rpc_proc_info_key key;
	rpc_proc_info_value *value;
	char *procname;
	static char procname_static[20];

	key.prog = prog;
	key.vers = vers;
	key.proc = proc;

	if ((value = g_hash_table_lookup(rpc_procs,&key)) != NULL)
		procname = value->name;
	else {
		/* happens only with strange program versions or
		   non-existing dissectors */
		sprintf(procname_static, "proc-%u", key.proc);
		procname = procname_static;
	}
	return procname;
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
	value->progname = proto_get_protocol_short_name(proto);

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

typedef struct _rpc_call_info_key {
	guint32	xid;
	conversation_t *conversation;
} rpc_call_info_key;

static GMemChunk *rpc_call_info_key_chunk;

typedef enum {
	FLAVOR_UNKNOWN,		/* authentication flavor unknown */
	FLAVOR_NOT_GSSAPI,	/* flavor isn't GSSAPI */
	FLAVOR_GSSAPI_NO_INFO,	/* flavor is GSSAPI, procedure & service unknown */
	FLAVOR_GSSAPI		/* flavor is GSSAPI, procedure & service known */
} flavor_t;

typedef struct _rpc_call_info_value {
	guint32	req_num;	/* frame number of first request seen */
	guint32	rep_num;	/* frame number of first reply seen */
	guint32	prog;
	guint32	vers;
	guint32	proc;
	flavor_t flavor;
	guint32 gss_proc;
	guint32 gss_svc;
	rpc_proc_info_value*	proc_info;
} rpc_call_info_value;

static GMemChunk *rpc_call_info_value_chunk;

static GHashTable *rpc_calls;

static GHashTable *rpc_indir_calls;

/* compare 2 keys */
gint
rpc_call_equal(gconstpointer k1, gconstpointer k2)
{
	rpc_call_info_key* key1 = (rpc_call_info_key*) k1;
	rpc_call_info_key* key2 = (rpc_call_info_key*) k2;

	return (key1->xid == key2->xid &&
	    key1->conversation == key2->conversation);
}


/* calculate a hash key */
guint
rpc_call_hash(gconstpointer k)
{
	rpc_call_info_key* key = (rpc_call_info_key*) k;

	return key->xid + (guint32)(key->conversation);
}


unsigned int
rpc_roundup(unsigned int a)
{
	unsigned int mod = a % 4;
	return a + ((mod)? 4-mod : 0);
}


int
dissect_rpc_bool(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
int hfindex, int offset)
{
	if (tree)
		proto_tree_add_item(tree, hfindex, tvb, offset, 4, FALSE);
	return offset + 4;
}


int
dissect_rpc_uint32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
int hfindex, int offset)
{
	if (tree)
		proto_tree_add_item(tree, hfindex, tvb, offset, 4, FALSE);
	return offset + 4;
}


int
dissect_rpc_uint64(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
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
dissect_rpc_opaque_data(tvbuff_t *tvb, int offset, packet_info *pinfo,
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

	string_length = tvb_get_ntohl(tvb,offset+0);
	string_length_full = rpc_roundup(string_length);
	/* XXX - just let the tvbuff stuff throw an exception? */
	string_length_packet = tvb_length_remaining(tvb, offset + 4);
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
		/* XXX - just let the tvbuff stuff throw an exception? */
		fill_length_packet = tvb_length_remaining(tvb,
		    offset + 4 + string_length);
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
	tvb_memcpy(tvb,string_buffer,offset+4,string_length_copy);
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

	if (tree) {
		string_item = proto_tree_add_text(tree, tvb,offset+0, tvb_length_remaining(tvb, offset),
			"%s: %s", proto_registrar_get_name(hfindex), string_buffer_print);
		if (string_data) {
			proto_tree_add_string_hidden(tree, hfindex, tvb, offset+4,
				string_length_copy, string_buffer);
		}
		if (string_item) {
			string_tree = proto_item_add_subtree(string_item, ett_rpc_string);
		}
	}
	if (length_truncated) {
		if (string_tree)
			proto_tree_add_text(string_tree, tvb,
				offset, tvb_length_remaining(tvb, offset),
				"length: <TRUNCATED>");
		offset = tvb_length(tvb);
	} else {
		if (string_tree)
			proto_tree_add_text(string_tree, tvb,offset+0,4,
				"length: %u", string_length);
		offset += 4;

		if (string_tree) {
			if (string_data) {
				proto_tree_add_string_format(string_tree,
				    hfindex, tvb, offset, string_length_copy,
					string_buffer_print, 
					"contents: %s", string_buffer_print);
			} else {
				proto_tree_add_bytes_format(string_tree,
				    hfindex, tvb, offset, string_length_copy,
					string_buffer_print, 
					"contents: %s", string_buffer_print);
			}
		}
		offset += string_length_copy;
		if (fill_length) {
			if (string_tree) {
				if (fill_truncated) {
					proto_tree_add_text(string_tree, tvb,
					offset,fill_length_copy,
					"fill bytes: opaque data<TRUNCATED>");
				}
				else {
					proto_tree_add_text(string_tree, tvb,
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
dissect_rpc_string(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int hfindex, int offset, char **string_buffer_ret)
{
	offset = dissect_rpc_opaque_data(tvb, offset, pinfo, tree,
	    hfindex, TRUE, string_buffer_ret);
	return offset;
}


int
dissect_rpc_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int hfindex, int offset)
{
	offset = dissect_rpc_opaque_data(tvb, offset, pinfo, tree, hfindex,
	    FALSE, NULL);

	return offset;
}


int
dissect_rpc_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	int offset, dissect_function_t *rpc_list_dissector)
{
	guint32 value_follows;

	while (1) {
		value_follows = tvb_get_ntohl(tvb, offset+0);
		proto_tree_add_boolean(tree,hf_rpc_value_follows, tvb,
			offset+0, 4, value_follows);
		offset += 4;
		if (value_follows == 1) {
			offset = rpc_list_dissector(tvb, offset, pinfo, tree);
		}
		else {
			break;
		}
	}

	return offset;
}

int
dissect_rpc_array(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	int offset, dissect_function_t *rpc_array_dissector,
	int hfindex)
{
	proto_item* lock_item;
	proto_tree* lock_tree;
	guint32	num;
	int old_offset = offset;

	num = tvb_get_ntohl(tvb, offset);

	if( num == 0 ){
		proto_tree_add_none_format(tree, hfindex, tvb, offset, 4,
			"no values");
		offset += 4;

		return offset;
	}

	lock_item = proto_tree_add_item(tree, hfindex, tvb, offset,
			0, FALSE);

	lock_tree = proto_item_add_subtree(lock_item, ett_rpc_array); 	

	offset = dissect_rpc_uint32(tvb, pinfo, lock_tree,
			hf_rpc_array_len, offset);

	while (num--) {
		offset = rpc_array_dissector(tvb, offset, pinfo, lock_tree);
	}

	proto_item_set_len(lock_item, offset-old_offset);
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

	stamp = tvb_get_ntohl(tvb,offset+0);
	if (tree)
		proto_tree_add_uint(tree, hf_rpc_auth_stamp, tvb,
			offset+0, 4, stamp);
	offset += 4;

	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_rpc_auth_machinename, offset, NULL);

	uid = tvb_get_ntohl(tvb,offset+0);
	if (tree)
		proto_tree_add_uint(tree, hf_rpc_auth_uid, tvb,
			offset+0, 4, uid);
	offset += 4;

	gid = tvb_get_ntohl(tvb,offset+0);
	if (tree)
		proto_tree_add_uint(tree, hf_rpc_auth_gid, tvb,
			offset+0, 4, gid);
	offset += 4;

	gids_count = tvb_get_ntohl(tvb,offset+0);
	if (tree) {
		gitem = proto_tree_add_text(tree, tvb,
			offset, 4+gids_count*4, "Auxiliary GIDs");
		gtree = proto_item_add_subtree(gitem, ett_rpc_gids);
	}
	offset += 4;
	
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

	agc_v = tvb_get_ntohl(tvb, offset+0);
	if (tree)
		proto_tree_add_uint(tree, hf_rpc_authgss_v,
				    tvb, offset+0, 4, agc_v);
	offset += 4;
	
	agc_proc = tvb_get_ntohl(tvb, offset+0);
	if (tree)
		proto_tree_add_uint(tree, hf_rpc_authgss_proc,
				    tvb, offset+0, 4, agc_proc);
	offset += 4;
	
	agc_seq = tvb_get_ntohl(tvb, offset+0);
	if (tree)
		proto_tree_add_uint(tree, hf_rpc_authgss_seq,
				    tvb, offset+0, 4, agc_seq);
	offset += 4;
	
	agc_svc = tvb_get_ntohl(tvb, offset+0);
	if (tree)
		proto_tree_add_uint(tree, hf_rpc_authgss_svc,
				    tvb, offset+0, 4, agc_svc);
	offset += 4;
	
	offset = dissect_rpc_data(tvb, pinfo, tree, hf_rpc_authgss_ctx,
			offset);
	
	return offset;
}

int
dissect_rpc_authdes_desblock(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
int hfindex, int offset)
{
	guint32 value_low;
	guint32 value_high;

	value_high = tvb_get_ntohl(tvb, offset + 0);
	value_low  = tvb_get_ntohl(tvb, offset + 4);

	if (tree) {
		proto_tree_add_text(tree, tvb, offset, 8,
			"%s: 0x%x%08x", proto_registrar_get_name(hfindex), value_high, 
			value_low);
	}

	return offset + 8;
}

static int
dissect_rpc_authdes_cred(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset)
{
	guint adc_namekind;
	guint window = 0;
	guint nickname = 0;

	adc_namekind = tvb_get_ntohl(tvb, offset+0);
	if (tree)
		proto_tree_add_uint(tree, hf_rpc_authdes_namekind,
				    tvb, offset+0, 4, adc_namekind);
	offset += 4;

	switch(adc_namekind)
	{
	case AUTHDES_NAMEKIND_FULLNAME:
		offset = dissect_rpc_string(tvb, pinfo, tree, 
			hf_rpc_authdes_netname, offset, NULL);
		offset = dissect_rpc_authdes_desblock(tvb, pinfo, tree,
			hf_rpc_authdes_convkey, offset);
		window = tvb_get_ntohl(tvb, offset+0);
		proto_tree_add_uint(tree, hf_rpc_authdes_window, tvb, offset+0, 4,
			window);
		offset += 4;
		break;

	case AUTHDES_NAMEKIND_NICKNAME:
		nickname = tvb_get_ntohl(tvb, offset+0);
		proto_tree_add_uint(tree, hf_rpc_authdes_nickname, tvb, offset+0, 4,
			window);
		offset += 4;
		break;
	}

	return offset;
}

static int
dissect_rpc_cred(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset)
{
	guint flavor;
	guint length;

	proto_item *citem;
	proto_tree *ctree;

	flavor = tvb_get_ntohl(tvb,offset+0);
	length = tvb_get_ntohl(tvb,offset+4);
	length = rpc_roundup(length);

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
		case AUTH_DES:
			dissect_rpc_authdes_cred(tvb, pinfo, ctree, offset+8);
			break;
			
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

/* AUTH_DES verifiers are asymmetrical, so we need to know what type of
 * verifier we're decoding (CALL or REPLY).
 */
static int
dissect_rpc_verf(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, int msg_type)
{
	guint flavor;
	guint length;
	
	proto_item *vitem;
	proto_tree *vtree;

	flavor = tvb_get_ntohl(tvb,offset+0);
	length = tvb_get_ntohl(tvb,offset+4);
	length = rpc_roundup(length);

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
		case AUTH_DES:
			proto_tree_add_uint(vtree, hf_rpc_auth_length, tvb,
				offset+4, 4, length);

			if (msg_type == RPC_CALL)
			{
				guint window;

				dissect_rpc_authdes_desblock(tvb, pinfo, vtree,
					hf_rpc_authdes_timestamp, offset+8);
				window = tvb_get_ntohl(tvb, offset+16);
				proto_tree_add_uint(vtree, hf_rpc_authdes_windowverf, tvb, 
					offset+16, 4, window);
			}
			else
			{
				/* must be an RPC_REPLY */
				guint nickname;

				dissect_rpc_authdes_desblock(tvb, pinfo, vtree,
					hf_rpc_authdes_timeverf, offset+8);
				nickname = tvb_get_ntohl(tvb, offset+16);
				proto_tree_add_uint(vtree, hf_rpc_authdes_nickname, tvb, 
				 	offset+16, 4, nickname);
			}
			break;
		case RPCSEC_GSS:
			dissect_rpc_data(tvb, pinfo, vtree,
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
	offset = dissect_rpc_data(tvb, pinfo, tree, hf_rpc_authgss_token,
			offset);
	return offset;
}

static int
dissect_rpc_authgss_initres(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset)
{
	int major, minor, window;
	
	offset = dissect_rpc_data(tvb, pinfo, tree, hf_rpc_authgss_ctx,
			offset);
	
	major = tvb_get_ntohl(tvb,offset+0);
	if (tree)
		proto_tree_add_uint(tree, hf_rpc_authgss_major, tvb,
				    offset+0, 4, major);
	offset += 4;

	minor = tvb_get_ntohl(tvb,offset+0);
	if (tree)
		proto_tree_add_uint(tree, hf_rpc_authgss_minor, tvb,
				    offset+0, 4, minor);
	offset += 4;

	window = tvb_get_ntohl(tvb,offset+0);
	if (tree)
		proto_tree_add_uint(tree, hf_rpc_authgss_window, tvb,
				    offset+0, 4, window);
	offset += 4;

	offset = dissect_rpc_data(tvb, pinfo, tree, hf_rpc_authgss_token,
			offset);

	return offset;
}


static int
call_dissect_function(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	int offset, dissect_function_t* dissect_function, const char *progname)
{
	const char *saved_proto;

	if (dissect_function != NULL) {
		/* set the current protocol name */
		saved_proto = pinfo->current_proto;
		if (progname != NULL)
			pinfo->current_proto = progname;

		/* call the dissector for the next level */
		offset = dissect_function(tvb, offset, pinfo, tree);

		/* restore the protocol name */
		pinfo->current_proto = saved_proto;
	}

	return offset;
}


static int
dissect_rpc_authgss_integ_data(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int offset,
	dissect_function_t* dissect_function,
	const char *progname)
{
	guint32 length, seq;
	
	proto_item *gitem;
	proto_tree *gtree = NULL;

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
	}
	offset += 8;

	if (dissect_function != NULL) {
		/* offset = */
		call_dissect_function(tvb, pinfo, gtree, offset,
				      dissect_function, progname);
	}
	offset += length - 4;
	offset = dissect_rpc_data(tvb, pinfo, tree, hf_rpc_authgss_checksum,
			offset);
	return offset;
}


static int
dissect_rpc_authgss_priv_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	offset = dissect_rpc_data(tvb, pinfo, tree, hf_rpc_authgss_data,
			offset);
	return offset;
}

/*
 * Dissect the arguments to an indirect call; used by the portmapper/RPCBIND
 * dissector.
 *
 * Record this call in a hash table, similar to the hash table for
 * direct calls, so we can find it when dissecting an indirect call reply.
 */
int
dissect_rpc_indir_call(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int offset, int args_id, guint32 prog, guint32 vers, guint32 proc)
{
	conversation_t* conversation;
	static address null_address = { AT_NONE, 0, NULL };
	rpc_proc_info_key key;
	rpc_proc_info_value *value;
	rpc_call_info_value *rpc_call;
	rpc_call_info_key rpc_call_key;
	rpc_call_info_key *new_rpc_call_key;
	dissect_function_t *dissect_function = NULL;

	key.prog = prog;
	key.vers = vers;
	key.proc = proc;
	if ((value = g_hash_table_lookup(rpc_procs,&key)) != NULL) {
		dissect_function = value->dissect_call;

		/* Keep track of the address and port whence the call came,
		   and the port to which the call is being sent, so that
		   we can match up calls with replies.

		   If the transport is connection-oriented (we check, for
		   now, only for "pinfo->ptype" of PT_TCP), we take
		   into account the address from which the call was sent
		   and the address to which the call was sent, because
		   the addresses of the two endpoints should be the same
		   for all calls and replies.

		   If the transport is connectionless, we don't worry
		   about the address to which the call was sent and from
		   which the reply was sent, because there's no
		   guarantee that the reply will come from the address
		   to which the call was sent. */
		if (pinfo->ptype == PT_TCP) {
			conversation = find_conversation(&pinfo->src,
			    &pinfo->dst, pinfo->ptype, pinfo->srcport,
			    pinfo->destport, 0);
		} else {
			/*
			 * XXX - can we just use NO_ADDR_B?  Unfortunately,
			 * you currently still have to pass a non-null
			 * pointer for the second address argument even
			 * if you do that.
			 */
			conversation = find_conversation(&pinfo->src,
			    &null_address, pinfo->ptype, pinfo->srcport,
			    pinfo->destport, 0);
		}
		if (conversation == NULL) {
			/* It's not part of any conversation - create a new
			   one.

			   XXX - this should never happen, as we should've
			   created a conversation for it in the RPC
			   dissector. */
			if (pinfo->ptype == PT_TCP) {
				conversation = conversation_new(&pinfo->src,
				    &pinfo->dst, pinfo->ptype, pinfo->srcport,
				    pinfo->destport, 0);
			} else {
				conversation = conversation_new(&pinfo->src,
				    &null_address, pinfo->ptype, pinfo->srcport,
				    pinfo->destport, 0);
			}
		}

		/* Make the dissector for this conversation the non-heuristic
		   RPC dissector. */
		conversation_set_dissector(conversation,
		    (pinfo->ptype == PT_TCP) ? dissect_rpc_tcp : dissect_rpc);

		/* Prepare the key data.

		   Dissectors for RPC procedure calls and replies shouldn't
		   create new tvbuffs, and we don't create one ourselves,
		   so we should have been handed the tvbuff for this RPC call;
		   as such, the XID is at offset 0 in this tvbuff. */
		rpc_call_key.xid = tvb_get_ntohl(tvb, 0);
		rpc_call_key.conversation = conversation;

		/* look up the request */
		rpc_call = g_hash_table_lookup(rpc_indir_calls, &rpc_call_key);
		if (rpc_call == NULL) {
			/* We didn't find it; create a new entry.
			   Prepare the value data.
			   Not all of it is needed for handling indirect
			   calls, so we set a bunch of items to 0. */
			new_rpc_call_key = g_mem_chunk_alloc(rpc_call_info_key_chunk);
			*new_rpc_call_key = rpc_call_key;
			rpc_call = g_mem_chunk_alloc(rpc_call_info_value_chunk);
			rpc_call->req_num = 0;
			rpc_call->rep_num = 0;
			rpc_call->prog = prog;
			rpc_call->vers = vers;
			rpc_call->proc = proc;

			/*
			 * XXX - what about RPCSEC_GSS?
			 * Do we have to worry about it?
			 */
			rpc_call->flavor = FLAVOR_NOT_GSSAPI;
			rpc_call->gss_proc = 0;
			rpc_call->gss_svc = 0;
			rpc_call->proc_info = value;
			/* store it */
			g_hash_table_insert(rpc_indir_calls, new_rpc_call_key,
			    rpc_call);
		}
	}
	else {
		/* We don't know the procedure.
		   Happens only with strange program versions or
		   non-existing dissectors.
		   Just show the arguments as opaque data. */
		offset = dissect_rpc_data(tvb, pinfo, tree, args_id,
		    offset);
		return offset;
	}

	if ( tree )
	{
		proto_tree_add_text(tree, tvb, offset, 4,
			"Argument length: %u",
			tvb_get_ntohl(tvb, offset));
	}
	offset += 4;

	/* Dissect the arguments */
	offset = call_dissect_function(tvb, pinfo, tree, offset,
			dissect_function, NULL);
	return offset;
}

/*
 * Dissect the results in an indirect reply; used by the portmapper/RPCBIND
 * dissector.
 */
int
dissect_rpc_indir_reply(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int offset, int result_id, int prog_id, int vers_id, int proc_id)
{
	conversation_t* conversation;
	static address null_address = { AT_NONE, 0, NULL };
	rpc_call_info_key rpc_call_key;
	rpc_call_info_value *rpc_call;
	char *procname = NULL;
	char procname_static[20];
	dissect_function_t *dissect_function = NULL;

	/* Look for the matching call in the hash table of indirect
	   calls.  A reply must match a call that we've seen, and the
	   reply must be sent to the same port and address that the
	   call came from, and must come from the port to which the
	   call was sent.

	   If the transport is connection-oriented (we check, for
	   now, only for "pinfo->ptype" of PT_TCP), we take
	   into account the address from which the call was sent
	   and the address to which the call was sent, because
	   the addresses of the two endpoints should be the same
	   for all calls and replies.

	   If the transport is connectionless, we don't worry
	   about the address to which the call was sent and from
	   which the reply was sent, because there's no
	   guarantee that the reply will come from the address
	   to which the call was sent. */
	if (pinfo->ptype == PT_TCP) {
		conversation = find_conversation(&pinfo->src, &pinfo->dst,
		    pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
	} else {
		/*
		 * XXX - can we just use NO_ADDR_B?  Unfortunately,
		 * you currently still have to pass a non-null
		 * pointer for the second address argument even
		 * if you do that.
		 */
		conversation = find_conversation(&null_address, &pinfo->dst,
		    pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
	}
	if (conversation == NULL) {
		/* We haven't seen an RPC call for that conversation,
		   so we can't check for a reply to that call.
		   Just show the reply stuff as opaque data. */
		offset = dissect_rpc_data(tvb, pinfo, tree, result_id,
		    offset);
		return offset;
	}

	/* The XIDs of the call and reply must match. */
	rpc_call_key.xid = tvb_get_ntohl(tvb, 0);
	rpc_call_key.conversation = conversation;
	rpc_call = g_hash_table_lookup(rpc_indir_calls, &rpc_call_key);
	if (rpc_call == NULL) {
		/* The XID doesn't match a call from that
		   conversation, so it's probably not an RPC reply.
		   Just show the reply stuff as opaque data. */
		offset = dissect_rpc_data(tvb, pinfo, tree, result_id,
		    offset);
		return offset;
	}

	if (rpc_call->proc_info != NULL) {
		dissect_function = rpc_call->proc_info->dissect_reply;
		if (rpc_call->proc_info->name != NULL) {
			procname = rpc_call->proc_info->name;
		}
		else {
			sprintf(procname_static, "proc-%u", rpc_call->proc);
			procname = procname_static;
		}
	}
	else {
#if 0
		dissect_function = NULL;
#endif
		sprintf(procname_static, "proc-%u", rpc_call->proc);
		procname = procname_static;
	}

	if ( tree )
	{
		/* Put the program, version, and procedure into the tree. */
		proto_tree_add_uint_format(tree, prog_id, tvb,
			0, 0, rpc_call->prog, "Program: %s (%u)",
			rpc_prog_name(rpc_call->prog), rpc_call->prog);
		proto_tree_add_uint(tree, vers_id, tvb, 0, 0, rpc_call->vers);
		proto_tree_add_uint_format(tree, proc_id, tvb,
			0, 0, rpc_call->proc, "Procedure: %s (%u)",
			procname, rpc_call->proc);
	}

	if (dissect_function == NULL) {
		/* We don't know how to dissect the reply procedure.
		   Just show the reply stuff as opaque data. */
		offset = dissect_rpc_data(tvb, pinfo, tree, result_id,
		    offset);
		return offset;
	}

	if (tree) {
		/* Put the length of the reply value into the tree. */
		proto_tree_add_text(tree, tvb, offset, 4,
			"Argument length: %u",
			tvb_get_ntohl(tvb, offset));
	}
	offset += 4;

	/* Dissect the return value */
	offset = call_dissect_function(tvb, pinfo, tree, offset,
			dissect_function, NULL);
	return offset;
}

/*
 * Just mark this as a continuation of an earlier packet.
 */
static void
dissect_rpc_continuation(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *rpc_item;
	proto_tree *rpc_tree;

	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_set_str(pinfo->fd, COL_PROTOCOL, "RPC");
	if (check_col(pinfo->fd, COL_INFO))
		col_set_str(pinfo->fd, COL_INFO, "Continuation");

	if (tree) {
		rpc_item = proto_tree_add_item(tree, proto_rpc, tvb, 0,
				tvb_length(tvb), FALSE);
		rpc_tree = proto_item_add_subtree(rpc_item, ett_rpc);
		proto_tree_add_text(rpc_tree, tvb, 0, tvb_length(tvb),
		    "Continuation data");
	}
}

static gboolean
dissect_rpc_message(tvbuff_t *tvb, int offset, packet_info *pinfo,
    proto_tree *tree, gboolean use_rm, guint32 rpc_rm)
{
	guint32	msg_type;
	rpc_call_info_key rpc_call_key;
	rpc_call_info_value *rpc_call = NULL;
	rpc_prog_info_value *rpc_prog = NULL;
	rpc_prog_info_key rpc_prog_key;

	unsigned int xid;
	unsigned int rpcvers;
	unsigned int prog = 0;
	unsigned int vers = 0;
	unsigned int proc = 0;
	flavor_t flavor = FLAVOR_UNKNOWN;
	unsigned int gss_proc = 0;
	unsigned int gss_svc = 0;
	int	proto = 0;
	int	ett = 0;

	unsigned int reply_state;
	unsigned int accept_state;
	unsigned int reject_state;

	char *msg_type_name = NULL;
	char *progname = NULL;
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

	rpc_call_info_key	*new_rpc_call_key;
	rpc_proc_info_key	key;
	rpc_proc_info_value	*value = NULL;
	conversation_t* conversation;
	static address null_address = { AT_NONE, 0, NULL };

	dissect_function_t *dissect_function = NULL;

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
		   come from the port to which the call was sent.

		   If the transport is connection-oriented (we check, for
		   now, only for "pinfo->ptype" of PT_TCP), we take
		   into account the address from which the call was sent
		   and the address to which the call was sent, because
		   the addresses of the two endpoints should be the same
		   for all calls and replies.

		   If the transport is connectionless, we don't worry
		   about the address to which the call was sent and from
		   which the reply was sent, because there's no
		   guarantee that the reply will come from the address
		   to which the call was sent. */
		if (pinfo->ptype == PT_TCP) {
			conversation = find_conversation(&pinfo->src,
			    &pinfo->dst, pinfo->ptype, pinfo->srcport,
			    pinfo->destport, 0);
		} else {
			/*
			 * XXX - can we just use NO_ADDR_B?  Unfortunately,
			 * you currently still have to pass a non-null
			 * pointer for the second address argument even
			 * if you do that.
			 */
			conversation = find_conversation(&null_address,
			    &pinfo->dst, pinfo->ptype, pinfo->srcport,
			    pinfo->destport, 0);
		}
		if (conversation == NULL) {
			/* We haven't seen an RPC call for that conversation,
			   so we can't check for a reply to that call. */
			return FALSE;
		}

		/* The XIDs of the call and reply must match. */
		rpc_call_key.xid = tvb_get_ntohl(tvb, offset + 0);
		rpc_call_key.conversation = conversation;
		rpc_call = g_hash_table_lookup(rpc_calls, &rpc_call_key);
		if (rpc_call == NULL) {
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
	if (check_col(pinfo->fd, COL_INFO))
		col_clear(pinfo->fd, COL_INFO);

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

	switch (msg_type) {

	case RPC_CALL:
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
			col_set_str(pinfo->fd, COL_PROTOCOL, progname);
		}

		vers = tvb_get_ntohl(tvb, offset+8);
		if (rpc_tree) {
			proto_tree_add_uint(rpc_tree,
				hf_rpc_programversion, tvb, offset+8, 4, vers);
		}

		proc = tvb_get_ntohl(tvb, offset+12);

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
#if 0
			dissect_function = NULL;
#endif
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

		/* Check for RPCSEC_GSS */
		if (tvb_bytes_exist(tvb, offset+16, 4)) {
			switch (tvb_get_ntohl(tvb, offset+16)) {

			case RPCSEC_GSS:
				/*
				 * It's GSS-API authentication...
				 */
				if (tvb_bytes_exist(tvb, offset+28, 8)) {
					/*
					 * ...and we have the procedure
					 * and service information for it.
					 */
					flavor = FLAVOR_GSSAPI;
					gss_proc = tvb_get_ntohl(tvb, offset+28);
					gss_svc = tvb_get_ntohl(tvb, offset+36);
				} else {
					/*
					 * ...but the procedure and service
					 * information isn't available.
					 */
					flavor = FLAVOR_GSSAPI_NO_INFO;
				}
				break;

			default:
				/*
				 * It's not GSS-API authentication.
				 */
				flavor = FLAVOR_NOT_GSSAPI;
				break;
			}
		}

		/* Keep track of the address and port whence the call came,
		   and the port to which the call is being sent, so that
		   we can match up calls with replies.

		   If the transport is connection-oriented (we check, for
		   now, only for "pinfo->ptype" of PT_TCP), we take
		   into account the address from which the call was sent
		   and the address to which the call was sent, because
		   the addresses of the two endpoints should be the same
		   for all calls and replies.

		   If the transport is connectionless, we don't worry
		   about the address to which the call was sent and from
		   which the reply was sent, because there's no
		   guarantee that the reply will come from the address
		   to which the call was sent. */
		if (pinfo->ptype == PT_TCP) {
			conversation = find_conversation(&pinfo->src,
			    &pinfo->dst, pinfo->ptype, pinfo->srcport,
			    pinfo->destport, 0);
		} else {
			/*
			 * XXX - can we just use NO_ADDR_B?  Unfortunately,
			 * you currently still have to pass a non-null
			 * pointer for the second address argument even
			 * if you do that.
			 */
			conversation = find_conversation(&pinfo->src,
			    &null_address, pinfo->ptype, pinfo->srcport,
			    pinfo->destport, 0);
		}
		if (conversation == NULL) {
			/* It's not part of any conversation - create a new
			   one. */
			if (pinfo->ptype == PT_TCP) {
				conversation = conversation_new(&pinfo->src,
				    &pinfo->dst, pinfo->ptype, pinfo->srcport,
				    pinfo->destport, 0);
			} else {
				conversation = conversation_new(&pinfo->src,
				    &null_address, pinfo->ptype, pinfo->srcport,
				    pinfo->destport, 0);
			}
		}

		/* Make the dissector for this conversation the non-heuristic
		   RPC dissector. */
		conversation_set_dissector(conversation,
		    (pinfo->ptype == PT_TCP) ? dissect_rpc_tcp : dissect_rpc);

		/* prepare the key data */
		rpc_call_key.xid = xid;
		rpc_call_key.conversation = conversation;

		/* look up the request */
		rpc_call = g_hash_table_lookup(rpc_calls, &rpc_call_key);
		if (rpc_call != NULL) {
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
			new_rpc_call_key = g_mem_chunk_alloc(rpc_call_info_key_chunk);
			*new_rpc_call_key = rpc_call_key;
			rpc_call = g_mem_chunk_alloc(rpc_call_info_value_chunk);
			rpc_call->req_num = pinfo->fd->num;
			rpc_call->rep_num = 0;
			rpc_call->prog = prog;
			rpc_call->vers = vers;
			rpc_call->proc = proc;
			rpc_call->flavor = flavor;
			rpc_call->gss_proc = gss_proc;
			rpc_call->gss_svc = gss_svc;
			rpc_call->proc_info = value;
			/* store it */
			g_hash_table_insert(rpc_calls, new_rpc_call_key,
			    rpc_call);
		}

		offset += 16;

		offset = dissect_rpc_cred(tvb, pinfo, rpc_tree, offset);
		offset = dissect_rpc_verf(tvb, pinfo, rpc_tree, offset, msg_type);

		/* go to the next dissector */

		break;	/* end of RPC call */

	case RPC_REPLY:
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
		    "This is a reply to a request in frame %u",
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
#if 0
			dissect_function = NULL;
#endif
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
				col_set_str(pinfo->fd, COL_PROTOCOL, progname);
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

		reply_state = tvb_get_ntohl(tvb,offset+0);
		if (rpc_tree) {
			proto_tree_add_uint(rpc_tree, hf_rpc_state_reply, tvb,
				offset+0, 4, reply_state);
		}
		offset += 4;

		if (reply_state == MSG_ACCEPTED) {
			offset = dissect_rpc_verf(tvb, pinfo, rpc_tree, offset, msg_type);
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
			reject_state = tvb_get_ntohl(tvb,offset+0);
			if (rpc_tree) {
				proto_tree_add_uint(rpc_tree,
					hf_rpc_state_reject, tvb, offset+0, 4,
					reject_state);
			}
			offset += 4;

			if (reject_state==RPC_MISMATCH) {
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
				auth_state = tvb_get_ntohl(tvb,offset+0);
				if (rpc_tree) {
					proto_tree_add_uint(rpc_tree,
						hf_rpc_state_auth, tvb, offset+0, 4,
						auth_state);
				}
				offset += 4;
			}
		} 
		break; /* end of RPC reply */

	default:
		/*
		 * The switch statement at the top returned if
		 * this was neither an RPC call nor a reply.
		 */
		g_assert_not_reached();
	}

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
				hf_rpc_programversion, tvb, 0, 0, vers);
			proto_tree_add_uint_format(ptree,
				hf_rpc_procedure, tvb, 0, 0, proc,
				"Procedure: %s (%u)", procname, proc);
		}
	}

	if (!proto_is_protocol_enabled(proto))
		dissect_function = NULL;

	/*
	 * Handle RPCSEC_GSS specially.
	 */
	switch (flavor) {

	case FLAVOR_UNKNOWN:
		/*
		 * We don't know the authentication flavor, so we can't
		 * dissect the payload.
		 */
		proto_tree_add_text(ptree, tvb, offset, tvb_length_remaining(tvb, offset),
		    "Unknown authentication flavor - cannot dissect");
		return TRUE;

	case FLAVOR_NOT_GSSAPI:
		/*
		 * It's not GSS-API authentication.  Just dissect the
		 * payload.
		 */
		offset = call_dissect_function(tvb, pinfo, ptree, offset,
				dissect_function, progname);
		break;

	case FLAVOR_GSSAPI_NO_INFO:
		/*
		 * It's GSS-API authentication, but we don't have the
		 * procedure and service information, so we can't dissect
		 * the payload.
		 */
		proto_tree_add_text(ptree, tvb, offset, tvb_length_remaining(tvb, offset),
		    "GSS-API authentication, but procedure and service unknown - cannot dissect");
		return TRUE;

	case FLAVOR_GSSAPI:
		/*
		 * It's GSS-API authentication, and we have the procedure
		 * and service information; process the GSS-API stuff,
		 * and process the payload if there is any.
		 */
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
						dissect_function,
						progname);
			}
			else if (gss_svc == RPCSEC_GSS_SVC_INTEGRITY) {
				offset = dissect_rpc_authgss_integ_data(tvb,
						pinfo, ptree, offset,
						dissect_function,
						progname);
			}
			else if (gss_svc == RPCSEC_GSS_SVC_PRIVACY) {
				offset = dissect_rpc_authgss_priv_data(tvb,
						pinfo, ptree, offset);
			}
			break;

		default:
			break;
		}
	}

	/* dissect any remaining bytes (incomplete dissection) as pure data in
	   the ptree */
	dissect_data(tvb, offset, pinfo, ptree);

	return TRUE;
}

static gboolean
dissect_rpc_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	return dissect_rpc_message(tvb, 0, pinfo, tree, FALSE, 0);
}

static void
dissect_rpc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if (!dissect_rpc_message(tvb, 0, pinfo, tree, FALSE, 0))
		dissect_rpc_continuation(tvb, pinfo, tree);
}

/*
 * Can return:
 *
 *	NEED_MORE_DATA, if we don't have enough data to dissect anything;
 *
 *	IS_RPC, if we dissected at least one message in its entirety
 *	as RPC;
 *
 *	IS_NOT_RPC, if we found no RPC message.
 */
typedef enum {
	NEED_MORE_DATA,
	IS_RPC,
	IS_NOT_RPC
} rpc_tcp_return_t;

static rpc_tcp_return_t
dissect_rpc_tcp_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    gboolean is_heur)
{
	int offset = 0;
	guint32 rpc_rm;
	gboolean saw_rpc = FALSE;
	gint32 len, seglen;
	gint tvb_len, tvb_reported_len;
	tvbuff_t *msg_tvb;

	while (tvb_reported_length_remaining(tvb, offset) != 0) {
		/*
		 * XXX - we need to handle records that don't have the "last
		 * fragment" bit set, and reassemble fragments.
		 */

		/* the first 4 bytes are special in "record marking mode" */
		if (!tvb_bytes_exist(tvb, offset, 4)) {
			/*
			 * XXX - we should somehow arrange to handle
			 * a record mark split across TCP segments.
			 */
			return saw_rpc ? IS_RPC : IS_NOT_RPC;
		}
		rpc_rm = tvb_get_ntohl(tvb, offset);

		len = rpc_rm&RPC_RM_FRAGLEN;

		/*
		 * XXX - reject fragments bigger than 2 megabytes.
		 * This is arbitrary, but should at least prevent
		 * some crashes from either packets with really
		 * large RPC-over-TCP fragments or from stuff that's
		 * not really RPC.
		 */
		if (len > 2*1024*1024)
			return saw_rpc ? IS_RPC : IS_NOT_RPC;
		if (rpc_desegment) {
			seglen = tvb_length_remaining(tvb, offset + 4);

			if (len > seglen && pinfo->can_desegment) {
				/*
				 * This frame doesn't have all of the
				 * data for this message, but we can do
				 * reassembly on it.
				 *
				 * If this is a heuristic dissector, just
				 * return IS_NOT_RPC - we don't want to try
				 * to get more data, as that's too likely
				 * to cause us to misidentify this as
				 * RPC.
				 *
				 * If this isn't a heuristic dissector,
				 * we've already identified this conversation
				 * as containing RPC data, as we saw RPC
				 * data in previous frames.  Try to get
				 * more data.
				 */
				if (is_heur)
					return IS_NOT_RPC;
				else {
					pinfo->desegment_offset = offset;
					pinfo->desegment_len = len - seglen;
					return NEED_MORE_DATA;
				}
			}
		}
		len += 4;	/* include record mark */
		tvb_len = tvb_length_remaining(tvb, offset);
		tvb_reported_len = tvb_reported_length_remaining(tvb, offset);
		if (tvb_len > len)
			tvb_len = len;
		if (tvb_reported_len > len)
			tvb_reported_len = len;
		msg_tvb = tvb_new_subset(tvb, offset, tvb_len,
		    tvb_reported_len);
		if (!dissect_rpc_message(msg_tvb, 4, pinfo, tree,
		    TRUE, rpc_rm))
			break;
		offset += len;
		saw_rpc = TRUE;
	}
	return saw_rpc ? IS_RPC : IS_NOT_RPC;
}

static gboolean
dissect_rpc_tcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	switch (dissect_rpc_tcp_common(tvb, pinfo, tree, TRUE)) {

	case IS_RPC:
		return TRUE;

	case IS_NOT_RPC:
		return FALSE;

	default:
		/* "Can't happen" */
		g_assert_not_reached();
		return FALSE;
	}
}

static void
dissect_rpc_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if (dissect_rpc_tcp_common(tvb, pinfo, tree, FALSE) == IS_NOT_RPC)
		dissect_rpc_continuation(tvb, pinfo, tree);
}

/* Discard any state we've saved. */
static void
rpc_init_protocol(void)
{
	if (rpc_calls != NULL)
		g_hash_table_destroy(rpc_calls);
	if (rpc_indir_calls != NULL)
		g_hash_table_destroy(rpc_indir_calls);
	if (rpc_call_info_key_chunk != NULL)
		g_mem_chunk_destroy(rpc_call_info_key_chunk);
	if (rpc_call_info_value_chunk != NULL)
		g_mem_chunk_destroy(rpc_call_info_value_chunk);

	rpc_calls = g_hash_table_new(rpc_call_hash, rpc_call_equal);
	rpc_indir_calls = g_hash_table_new(rpc_call_hash, rpc_call_equal);
	rpc_call_info_key_chunk = g_mem_chunk_new("call_info_key_chunk",
	    sizeof(rpc_call_info_key),
	    200 * sizeof(rpc_call_info_key),
	    G_ALLOC_ONLY);
	rpc_call_info_value_chunk = g_mem_chunk_new("call_info_value_chunk",
	    sizeof(rpc_call_info_value),
	    200 * sizeof(rpc_call_info_value),
	    G_ALLOC_ONLY);
}

/* will be called once from register.c at startup time */
void
proto_register_rpc(void)
{
	static hf_register_info hf[] = {
		{ &hf_rpc_lastfrag, {
			"Last Fragment", "rpc.lastfrag", FT_BOOLEAN, BASE_NONE,
			&yesno, 0, "Last Fragment", HFILL }},
		{ &hf_rpc_fraglen, {
			"Fragment Length", "rpc.fraglen", FT_UINT32, BASE_DEC,
			NULL, 0, "Fragment Length", HFILL }},
		{ &hf_rpc_xid, {
			"XID", "rpc.xid", FT_UINT32, BASE_HEX,
			NULL, 0, "XID", HFILL }},
		{ &hf_rpc_msgtype, {
			"Message Type", "rpc.msgtyp", FT_UINT32, BASE_DEC,
			VALS(rpc_msg_type), 0, "Message Type", HFILL }},
		{ &hf_rpc_state_reply, {
			"Reply State", "rpc.replystat", FT_UINT32, BASE_DEC,
			VALS(rpc_reply_state), 0, "Reply State", HFILL }},
		{ &hf_rpc_state_accept, {
			"Accept State", "rpc.state_accept", FT_UINT32, BASE_DEC,
			VALS(rpc_accept_state), 0, "Accept State", HFILL }},
		{ &hf_rpc_state_reject, {
			"Reject State", "rpc.state_reject", FT_UINT32, BASE_DEC,
			VALS(rpc_reject_state), 0, "Reject State", HFILL }},
		{ &hf_rpc_state_auth, {
			"Auth State", "rpc.state_auth", FT_UINT32, BASE_DEC,
			VALS(rpc_auth_state), 0, "Auth State", HFILL }},
		{ &hf_rpc_version, {
			"RPC Version", "rpc.version", FT_UINT32, BASE_DEC,
			NULL, 0, "RPC Version", HFILL }},
		{ &hf_rpc_version_min, {
			"RPC Version (Minimum)", "rpc.version.min", FT_UINT32, 
			BASE_DEC, NULL, 0, "Program Version (Minimum)", HFILL }},
		{ &hf_rpc_version_max, {
			"RPC Version (Maximum)", "rpc.version.max", FT_UINT32, 
			BASE_DEC, NULL, 0, "RPC Version (Maximum)", HFILL }},
		{ &hf_rpc_program, {
			"Program", "rpc.program", FT_UINT32, BASE_DEC,
			NULL, 0, "Program", HFILL }},
		{ &hf_rpc_programversion, {
			"Program Version", "rpc.programversion", FT_UINT32, 
			BASE_DEC, NULL, 0, "Program Version", HFILL }},
		{ &hf_rpc_programversion_min, {
			"Program Version (Minimum)", "rpc.programversion.min", FT_UINT32, 
			BASE_DEC, NULL, 0, "Program Version (Minimum)", HFILL }},
		{ &hf_rpc_programversion_max, {
			"Program Version (Maximum)", "rpc.programversion.max", FT_UINT32, 
			BASE_DEC, NULL, 0, "Program Version (Maximum)", HFILL }},
		{ &hf_rpc_procedure, {
			"Procedure", "rpc.procedure", FT_UINT32, BASE_DEC,
			NULL, 0, "Procedure", HFILL }},
		{ &hf_rpc_auth_flavor, {
			"Flavor", "rpc.auth.flavor", FT_UINT32, BASE_DEC,
			VALS(rpc_auth_flavor), 0, "Flavor", HFILL }},
		{ &hf_rpc_auth_length, {
			"Length", "rpc.auth.length", FT_UINT32, BASE_DEC,
			NULL, 0, "Length", HFILL }},
		{ &hf_rpc_auth_stamp, {
			"Stamp", "rpc.auth.stamp", FT_UINT32, BASE_HEX,
			NULL, 0, "Stamp", HFILL }},
		{ &hf_rpc_auth_uid, {
			"UID", "rpc.auth.uid", FT_UINT32, BASE_DEC,
			NULL, 0, "UID", HFILL }},
		{ &hf_rpc_auth_gid, {
			"GID", "rpc.auth.gid", FT_UINT32, BASE_DEC,
			NULL, 0, "GID", HFILL }},
		{ &hf_rpc_authgss_v, {
			"GSS Version", "rpc.authgss.version", FT_UINT32,
			BASE_DEC, NULL, 0, "GSS Version", HFILL }},
		{ &hf_rpc_authgss_proc, {
			"GSS Procedure", "rpc.authgss.procedure", FT_UINT32,
			BASE_DEC, VALS(rpc_authgss_proc), 0, "GSS Procedure", HFILL }},
		{ &hf_rpc_authgss_seq, {
			"GSS Sequence Number", "rpc.authgss.seqnum", FT_UINT32,
			BASE_DEC, NULL, 0, "GSS Sequence Number", HFILL }},
		{ &hf_rpc_authgss_svc, {
			"GSS Service", "rpc.authgss.service", FT_UINT32,
			BASE_DEC, VALS(rpc_authgss_svc), 0, "GSS Service", HFILL }},
		{ &hf_rpc_authgss_ctx, {
			"GSS Context", "rpc.authgss.context", FT_BYTES,
			BASE_HEX, NULL, 0, "GSS Context", HFILL }},
		{ &hf_rpc_authgss_major, {
			"GSS Major Status", "rpc.authgss.major", FT_UINT32,
			BASE_DEC, NULL, 0, "GSS Major Status", HFILL }},
		{ &hf_rpc_authgss_minor, {
			"GSS Minor Status", "rpc.authgss.minor", FT_UINT32,
			BASE_DEC, NULL, 0, "GSS Minor Status", HFILL }},
		{ &hf_rpc_authgss_window, {
			"GSS Sequence Window", "rpc.authgss.window", FT_UINT32,
			BASE_DEC, NULL, 0, "GSS Sequence Window", HFILL }},
		{ &hf_rpc_authgss_token, {
			"GSS Token", "rpc.authgss.token", FT_BYTES,
			BASE_HEX, NULL, 0, "GSS Token", HFILL }},
		{ &hf_rpc_authgss_data_length, {
			"Length", "rpc.authgss.data.length", FT_UINT32,
			BASE_DEC, NULL, 0, "Length", HFILL }},
		{ &hf_rpc_authgss_data, {
			"GSS Data", "rpc.authgss.data", FT_BYTES,
			BASE_HEX, NULL, 0, "GSS Data", HFILL }},
		{ &hf_rpc_authgss_checksum, {
			"GSS Checksum", "rpc.authgss.checksum", FT_BYTES,
			BASE_HEX, NULL, 0, "GSS Checksum", HFILL }},
		{ &hf_rpc_authdes_namekind, {
			"Namekind", "rpc.authdes.namekind", FT_UINT32, BASE_DEC,
			VALS(rpc_authdes_namekind), 0, "Namekind", HFILL }},
		{ &hf_rpc_authdes_netname, {
			"Netname", "rpc.authdes.netname", FT_STRING,
			BASE_DEC, NULL, 0, "Netname", HFILL }},
		{ &hf_rpc_authdes_convkey, {
			"Conversation Key (encrypted)", "rpc.authdes.convkey", FT_UINT32,
			BASE_HEX, NULL, 0, "Conversation Key (encrypted)", HFILL }},
		{ &hf_rpc_authdes_window, {
			"Window (encrypted)", "rpc.authdes.window", FT_UINT32,
			BASE_HEX, NULL, 0, "Windows (encrypted)", HFILL }},
		{ &hf_rpc_authdes_nickname, {
			"Nickname", "rpc.authdes.nickname", FT_UINT32, 
			BASE_HEX, NULL, 0, "Nickname", HFILL }},
		{ &hf_rpc_authdes_timestamp, {
			"Timestamp (encrypted)", "rpc.authdes.timestamp", FT_UINT32,
			BASE_HEX, NULL, 0, "Timestamp (encrypted)", HFILL }},
		{ &hf_rpc_authdes_windowverf, {
			"Window verifier (encrypted)", "rpc.authdes.windowverf", FT_UINT32,
			BASE_HEX, NULL, 0, "Window verifier (encrypted)", HFILL }},
		{ &hf_rpc_authdes_timeverf, {
			"Timestamp verifier (encrypted)", "rpc.authdes.timeverf", FT_UINT32,
			BASE_HEX, NULL, 0, "Timestamp verifier (encrypted)", HFILL }},
		{ &hf_rpc_auth_machinename, {
			"Machine Name", "rpc.auth.machinename", FT_STRING, 
			BASE_DEC, NULL, 0, "Machine Name", HFILL }},
		{ &hf_rpc_dup, {
			"Duplicate Transaction", "rpc.dup", FT_UINT32, BASE_DEC,
			NULL, 0, "Duplicate Transaction", HFILL }},
		{ &hf_rpc_call_dup, {
			"Duplicate Call", "rpc.call.dup", FT_UINT32, BASE_DEC,
			NULL, 0, "Duplicate Call", HFILL }},
		{ &hf_rpc_reply_dup, {
			"Duplicate Reply", "rpc.reply.dup", FT_UINT32, BASE_DEC,
			NULL, 0, "Duplicate Reply", HFILL }},
		{ &hf_rpc_value_follows, {
			"Value Follows", "rpc.value_follows", FT_BOOLEAN, BASE_NONE,
			&yesno, 0, "Value Follows", HFILL }},
		{ &hf_rpc_array_len, {
			"num", "rpc.array.len", FT_UINT32, BASE_DEC,
			NULL, 0, "Length of RPC array", HFILL }},
	};
	static gint *ett[] = {
		&ett_rpc,
		&ett_rpc_string,
		&ett_rpc_cred,
		&ett_rpc_verf,
		&ett_rpc_gids,
		&ett_rpc_gss_data,
		&ett_rpc_array,
	};
	module_t *rpc_module;

	proto_rpc = proto_register_protocol("Remote Procedure Call",
	    "RPC", "rpc");
	proto_register_field_array(proto_rpc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_init_routine(&rpc_init_protocol);
	rpc_module = prefs_register_protocol(proto_rpc, NULL);
	prefs_register_bool_preference(rpc_module, "desegment_rpc_over_tcp",
		"Desegment all RPC over TCP commands",
		"Whether the RPC dissector should desegment all RPC over TCP commands",
		&rpc_desegment);

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
	heur_dissector_add("tcp", dissect_rpc_tcp_heur, proto_rpc);
	heur_dissector_add("udp", dissect_rpc_heur, proto_rpc);
}
