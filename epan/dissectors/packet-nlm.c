/* packet-nlm.c
 * Routines for nlm dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-mount.c
 *
 * 2001-JAN  Ronnie Sahlberg <See AUTHORS for email>
 *  Updates to version 1 of the protocol.
 *  Added version 3 of the protocol.
 *  Added version 4 of the protocol.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


#include "config.h"

#include "packet-nfs.h"
#include "packet-nlm.h"
#include <epan/prefs.h>

void proto_register_nlm(void);
void proto_reg_handoff_nlm(void);

/*
 * NFS Lock Manager protocol specs can only be found in actual
 * implementations or in the nice book:
 * Brent Callaghan: "NFS Illustrated", Addison-Wesley, ISBN 0-201-32570-5
 * which I use here as reference (BC).
 *
 * They can also be found if you go to
 *
 *	http://www.opengroup.org/publications/catalog/c702.htm
 *
 * and follow the links to the HTML version of the document.
 */

static int proto_nlm = -1;
static int hf_nlm_procedure_v1 = -1;
static int hf_nlm_procedure_v2 = -1;
static int hf_nlm_procedure_v3 = -1;
static int hf_nlm_procedure_v4 = -1;
static int hf_nlm_cookie = -1;
static int hf_nlm_block = -1;
static int hf_nlm_exclusive = -1;
static int hf_nlm_lock = -1;
static int hf_nlm_lock_caller_name = -1;
static int hf_nlm_lock_owner = -1;
static int hf_nlm_lock_svid = -1;
static int hf_nlm_lock_l_offset = -1;
static int hf_nlm_lock_l_offset64 = -1;
static int hf_nlm_lock_l_len = -1;
static int hf_nlm_lock_l_len64 = -1;
static int hf_nlm_reclaim = -1;
static int hf_nlm_stat = -1;
static int hf_nlm_state = -1;
static int hf_nlm_test_stat = -1;
static int hf_nlm_test_stat_stat = -1;
static int hf_nlm_holder = -1;
static int hf_nlm_share = -1;
static int hf_nlm_share_mode = -1;
static int hf_nlm_share_access = -1;
static int hf_nlm_share_name = -1;
static int hf_nlm_sequence = -1;
static int hf_nlm_request_in = -1;
static int hf_nlm_reply_in = -1;
static int hf_nlm_time = -1;

static gint ett_nlm = -1;
static gint ett_nlm_lock = -1;



/*
 * stuff to match MSG and RES packets for async NLM
 */

static gboolean nlm_match_msgres = FALSE;
static GHashTable *nlm_msg_res_unmatched = NULL;
static GHashTable *nlm_msg_res_matched = NULL;

/* XXX 	when matching the packets we should really check the conversation (only address
	NOT ports) and command type as well. I am lazy and thinks the cookie itself is
	good enough for now
*/
typedef struct _nlm_msg_res_unmatched_data {
	int req_frame;
	nstime_t ns;
	int cookie_len;
	const guint8 *cookie;
} nlm_msg_res_unmatched_data;

typedef struct _nlm_msg_res_matched_data {
	int req_frame;
	int rep_frame;
	nstime_t ns;
} nlm_msg_res_matched_data;

static void
nlm_msg_res_unmatched_value_destroy(gpointer value)
{
	nlm_msg_res_unmatched_data *umd = (nlm_msg_res_unmatched_data *)value;

	wmem_free(NULL, (gpointer)umd->cookie);
	g_free(umd);
}

static guint
nlm_msg_res_unmatched_hash(gconstpointer k)
{
	const nlm_msg_res_unmatched_data *umd = (const nlm_msg_res_unmatched_data *)k;
	guint8 hash=0;
	int i;

	for(i=0;i<umd->cookie_len;i++){
		hash^=umd->cookie[i];
	}

	return hash;
}
static guint
nlm_msg_res_matched_hash(gconstpointer k)
{
	guint hash = GPOINTER_TO_UINT(k);

	return hash;
}

static gint
nlm_msg_res_unmatched_equal(gconstpointer k1, gconstpointer k2)
{
	const nlm_msg_res_unmatched_data *umd1 = (const nlm_msg_res_unmatched_data *)k1;
	const nlm_msg_res_unmatched_data *umd2 = (const nlm_msg_res_unmatched_data *)k2;

	if(umd1->cookie_len!=umd2->cookie_len){
		return 0;
	}

	return( memcmp(umd1->cookie, umd2->cookie, umd1->cookie_len) == 0);
}
static gint
nlm_msg_res_matched_equal(gconstpointer k1, gconstpointer k2)
{
	guint mk1 = GPOINTER_TO_UINT(k1);
	guint mk2 = GPOINTER_TO_UINT(k2);

	return( mk1==mk2 );
}

static void
nlm_msg_res_match_init(void)
{
	nlm_msg_res_unmatched =
		g_hash_table_new_full(nlm_msg_res_unmatched_hash,
		nlm_msg_res_unmatched_equal,
		NULL, nlm_msg_res_unmatched_value_destroy);
	nlm_msg_res_matched = g_hash_table_new_full(nlm_msg_res_matched_hash,
		nlm_msg_res_matched_equal, NULL, (GDestroyNotify)g_free);
}

static void
nlm_msg_res_match_cleanup(void)
{
	g_hash_table_destroy(nlm_msg_res_unmatched);
	g_hash_table_destroy(nlm_msg_res_matched);
}

static void
nlm_print_msgres_reply(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb)
{
	nlm_msg_res_matched_data *md;

	md=(nlm_msg_res_matched_data *)g_hash_table_lookup(nlm_msg_res_matched, GINT_TO_POINTER(pinfo->num));
	if(md){
		nstime_t ns;
		proto_tree_add_uint(tree, hf_nlm_request_in, tvb, 0, 0, md->req_frame);
		nstime_delta(&ns, &pinfo->abs_ts, &md->ns);
		proto_tree_add_time(tree, hf_nlm_time, tvb, 0, 0, &ns);
	}
}

static void
nlm_print_msgres_request(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb)
{
	nlm_msg_res_matched_data *md;

	md=(nlm_msg_res_matched_data *)g_hash_table_lookup(nlm_msg_res_matched, GINT_TO_POINTER(pinfo->num));
	if(md){
		proto_tree_add_uint(tree, hf_nlm_reply_in, tvb, 0, 0, md->rep_frame);
	}
}
static void
nlm_match_fhandle_reply(packet_info *pinfo, proto_tree *tree)
{
	nlm_msg_res_matched_data *md;

	md=(nlm_msg_res_matched_data *)g_hash_table_lookup(nlm_msg_res_matched, GINT_TO_POINTER(pinfo->num));
	if(md && md->rep_frame){
		dissect_fhandle_hidden(pinfo,
				tree, md->req_frame);
	}
}
static void
nlm_match_fhandle_request(packet_info *pinfo, proto_tree *tree)
{
	nlm_msg_res_matched_data *md;

	md=(nlm_msg_res_matched_data *)g_hash_table_lookup(nlm_msg_res_matched, GINT_TO_POINTER(pinfo->num));
	if(md && md->rep_frame){
		dissect_fhandle_hidden(pinfo,
				tree, md->rep_frame);
	}
}

static void
nlm_register_unmatched_res(packet_info *pinfo, tvbuff_t *tvb, int offset)
{
	nlm_msg_res_unmatched_data umd;
	nlm_msg_res_unmatched_data *old_umd;

	umd.cookie_len=tvb_get_ntohl(tvb, offset);
	umd.cookie=tvb_get_ptr(tvb, offset+4, -1);

	/* have we seen this cookie before? */
	old_umd=(nlm_msg_res_unmatched_data *)g_hash_table_lookup(nlm_msg_res_unmatched, (gconstpointer)&umd);
	if(old_umd){
		nlm_msg_res_matched_data *md_req, *md_rep;

		md_req=(nlm_msg_res_matched_data *)g_malloc(sizeof(nlm_msg_res_matched_data));
		md_req->req_frame=old_umd->req_frame;
		md_req->rep_frame=pinfo->num;
		md_req->ns=old_umd->ns;
		md_rep=(nlm_msg_res_matched_data *)g_memdup(md_req, sizeof(nlm_msg_res_matched_data));
		g_hash_table_insert(nlm_msg_res_matched, GINT_TO_POINTER(md_req->req_frame), (gpointer)md_req);
		g_hash_table_insert(nlm_msg_res_matched, GINT_TO_POINTER(md_rep->rep_frame), (gpointer)md_rep);

		g_hash_table_remove(nlm_msg_res_unmatched, (gconstpointer)old_umd);
	}
}

static void
nlm_register_unmatched_msg(packet_info *pinfo, tvbuff_t *tvb, int offset)
{
	nlm_msg_res_unmatched_data *umd;
	nlm_msg_res_unmatched_data *old_umd;

	/* allocate and build the unmatched structure for this request */
	umd=(nlm_msg_res_unmatched_data *)g_malloc(sizeof(nlm_msg_res_unmatched_data));
	umd->req_frame=pinfo->num;
	umd->ns=pinfo->abs_ts;
	umd->cookie_len=tvb_get_ntohl(tvb, offset);
	umd->cookie=(const guint8 *)tvb_memdup(NULL, tvb, offset+4, umd->cookie_len);

	/* remove any old duplicates */
	old_umd=(nlm_msg_res_unmatched_data *)g_hash_table_lookup(nlm_msg_res_unmatched, (gconstpointer)umd);
	if(old_umd){
		g_hash_table_remove(nlm_msg_res_unmatched, (gconstpointer)old_umd);
	}

	/* add new one */
	g_hash_table_insert(nlm_msg_res_unmatched, (gpointer)umd, (gpointer)umd);
}




static const value_string names_nlm_stats[] =
{
	/* NLM_GRANTED is the function number 5 and the state code 0.
	 * So we use for the state the postfix _S.
	 */
#define NLM_GRANTED_S		0
		{	NLM_GRANTED_S,	"NLM_GRANTED"	},
#define NLM_DENIED		1
		{	NLM_DENIED,	"NLM_DENIED"	},
#define NLM_DENIED_NOLOCKS	2
		{	NLM_DENIED_NOLOCKS,	"NLM_DENIED_NOLOCKS"	},
#define NLM_BLOCKED		3
		{	NLM_BLOCKED,	"NLM_BLOCKED"		},
#define NLM_DENIED_GRACE_PERIOD	4
		{	NLM_DENIED_GRACE_PERIOD,	"NLM_DENIED_GRACE_PERIOD"	},
#define NLM_DEADLCK		5
		{	NLM_DEADLCK,	"NLM_DEADLCK"	},
#define NLM_ROFS		6
		{	NLM_ROFS,	"NLM_ROFS"	},
#define NLM_STALE_FH		7
		{	NLM_STALE_FH,	"NLM_STALE_FH"	},
#define NLM_BIG			8
		{	NLM_BIG,	"NLM_BIG"	},
#define NLM_FAILED		9
		{	NLM_FAILED,	"NLM_FAILED"	},
		{	0,		NULL		}
};


static const value_string names_fsh_mode[] =
{
#define FSM_DN	0
		{	FSM_DN,		"deny none"	},
#define FSM_DR	1
		{	FSM_DR,		"deny read"	},
#define FSM_DW	2
		{	FSM_DW,		"deny write"	},
#define FSM_DRW	3
		{	FSM_DRW,	"deny read/write"	},

		{	0,		NULL	}
};


static const value_string names_fsh_access[] =
{
#define FSA_NONE	0
		{	FSA_NONE,	"no access"	},
#define FSA_R	1
		{	FSA_R,		"read-only"	},
#define FSA_W	2
		{	FSA_W,		"write-only"	},
#define FSA_RW	3
		{	FSA_RW,		"read/write"	},
		{	0,		NULL	}
};






/* **************************** */
/* generic dissecting functions */
/* **************************** */
static int
dissect_lock(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int version, int offset, rpc_call_info_value* civ)
{
	proto_item* lock_item = NULL;
	proto_tree* lock_tree = NULL;
	guint32 fh_hash, svid, start_offset=0, end_offset=0;

	if (tree) {
		lock_item = proto_tree_add_item(tree, hf_nlm_lock, tvb,
				offset, -1, ENC_NA);
		if (lock_item)
			lock_tree = proto_item_add_subtree(lock_item, ett_nlm_lock);
	}

	offset = dissect_rpc_string(tvb,lock_tree,
			hf_nlm_lock_caller_name, offset, NULL);
	offset = dissect_nfs3_fh(tvb, offset, pinfo, lock_tree, "fh", &fh_hash, civ);
	col_append_fstr(pinfo->cinfo, COL_INFO, " FH:0x%08x", fh_hash);

	offset = dissect_rpc_data(tvb, lock_tree, hf_nlm_lock_owner, offset);

	svid = tvb_get_ntohl(tvb, offset);
	offset = dissect_rpc_uint32(tvb, lock_tree, hf_nlm_lock_svid, offset);
	col_append_fstr(pinfo->cinfo, COL_INFO, " svid:%d", svid);

	if (version == 4) {
		start_offset = tvb_get_ntohl(tvb, offset);
		offset = dissect_rpc_uint64(tvb, lock_tree, hf_nlm_lock_l_offset64, offset);
		end_offset = tvb_get_ntohl(tvb, offset);
		offset = dissect_rpc_uint64(tvb, lock_tree, hf_nlm_lock_l_len64, offset);
	}
	else {
		start_offset = tvb_get_ntohl(tvb, offset);
		offset = dissect_rpc_uint32(tvb, lock_tree, hf_nlm_lock_l_offset, offset);
		end_offset = tvb_get_ntohl(tvb, offset);
		offset = dissect_rpc_uint32(tvb, lock_tree, hf_nlm_lock_l_len, offset);
	}

	col_append_fstr(pinfo->cinfo, COL_INFO, " pos:%d-%d", start_offset, end_offset);

	return offset;
}


static int
dissect_nlm_test(tvbuff_t *tvb, int offset, packet_info *pinfo,
		 proto_tree *tree, int version, rpc_call_info_value* rpc_call)
{
	if(nlm_match_msgres){
		if(rpc_call->proc==6){	/* NLM_TEST_MSG */
			if( (!pinfo->fd->flags.visited) ){
				nlm_register_unmatched_msg(pinfo, tvb, offset);
			} else {
				nlm_print_msgres_request(pinfo, tree, tvb);
			}
			/* for the fhandle matching that finds both request and
			   response packet */
			if(nfs_fhandle_reqrep_matching){
				nlm_match_fhandle_request(pinfo, tree);
			}
		}
	}

	offset = dissect_rpc_data(tvb, tree, hf_nlm_cookie, offset);
	dissect_rpc_bool(tvb, tree, hf_nlm_exclusive, offset);
	offset += 4;
	offset = dissect_lock(tvb, pinfo, tree, version, offset, rpc_call);
	return offset;
}

static int
dissect_nlm_lock(tvbuff_t *tvb, int offset, packet_info *pinfo,
		 proto_tree *tree,int version, rpc_call_info_value* rpc_call)
{
	if(nlm_match_msgres){
		if(rpc_call->proc==7){	/* NLM_LOCK_MSG */
			if( (!pinfo->fd->flags.visited) ){
				nlm_register_unmatched_msg(pinfo, tvb, offset);
			} else {
				nlm_print_msgres_request(pinfo, tree, tvb);
			}
			/* for the fhandle matching that finds both request and
			   response packet */
			if(nfs_fhandle_reqrep_matching){
				nlm_match_fhandle_request(pinfo, tree);
			}
		}
	}

	offset = dissect_rpc_data(tvb, tree, hf_nlm_cookie, offset);
	offset = dissect_rpc_bool(tvb, tree, hf_nlm_block, offset);
	offset = dissect_rpc_bool(tvb, tree, hf_nlm_exclusive, offset);
	offset = dissect_lock(tvb, pinfo, tree, version, offset, rpc_call);
	offset = dissect_rpc_bool(tvb, tree, hf_nlm_reclaim, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_nlm_state, offset);
	return offset;
}

static int
dissect_nlm_cancel(tvbuff_t *tvb, int offset, packet_info *pinfo,
		   proto_tree *tree,int version, rpc_call_info_value* rpc_call)
{
	if(nlm_match_msgres){
		if(rpc_call->proc==8){	/* NLM_CANCEL_MSG */
			if( (!pinfo->fd->flags.visited) ){
				nlm_register_unmatched_msg(pinfo, tvb, offset);
			} else {
				nlm_print_msgres_request(pinfo, tree, tvb);
			}
			/* for the fhandle matching that finds both request and
			   response packet */
			if(nfs_fhandle_reqrep_matching){
				nlm_match_fhandle_request(pinfo, tree);
			}
		}
	}

	offset = dissect_rpc_data(tvb, tree, hf_nlm_cookie, offset);
	offset = dissect_rpc_bool(tvb, tree, hf_nlm_block, offset);
	offset = dissect_rpc_bool(tvb, tree, hf_nlm_exclusive, offset);
	offset = dissect_lock(tvb, pinfo, tree, version, offset, rpc_call);
	return offset;
}

static int
dissect_nlm_unlock(tvbuff_t *tvb, int offset, packet_info *pinfo,
		   proto_tree *tree,int version, rpc_call_info_value* rpc_call)
{
	if(nlm_match_msgres){
		if(rpc_call->proc==9){	/* NLM_UNLOCK_MSG */
			if( (!pinfo->fd->flags.visited) ){
				nlm_register_unmatched_msg(pinfo, tvb, offset);
			} else {
				nlm_print_msgres_request(pinfo, tree, tvb);
			}
			/* for the fhandle matching that finds both request and
			   response packet */
			if(nfs_fhandle_reqrep_matching){
				nlm_match_fhandle_request(pinfo, tree);
			}
		}
	}

	offset = dissect_rpc_data(tvb, tree, hf_nlm_cookie, offset);
	offset = dissect_lock(tvb, pinfo, tree, version, offset, rpc_call);
	return offset;
}

static int
dissect_nlm_granted(tvbuff_t *tvb, int offset, packet_info *pinfo,
		    proto_tree *tree,int version, rpc_call_info_value* rpc_call)
{
	if(nlm_match_msgres){
		if(rpc_call->proc==10){	/* NLM_GRANTED_MSG */
			if( (!pinfo->fd->flags.visited) ){
				nlm_register_unmatched_msg(pinfo, tvb, offset);
			} else {
				nlm_print_msgres_request(pinfo, tree, tvb);
			}
			/* for the fhandle matching that finds both request and
			   response packet */
			if(nfs_fhandle_reqrep_matching){
				nlm_match_fhandle_request(pinfo, tree);
			}
		}
	}

	offset = dissect_rpc_data(tvb, tree, hf_nlm_cookie, offset);
	offset = dissect_rpc_bool(tvb, tree, hf_nlm_exclusive, offset);
	offset = dissect_lock(tvb, pinfo, tree, version, offset, rpc_call);
	return offset;
}


static int
dissect_nlm_test_res(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		     proto_tree *tree, int version, rpc_call_info_value *rpc_call)
{
	proto_item* lock_item = NULL;
	proto_tree* lock_tree = NULL;

	if(nlm_match_msgres){
		if(rpc_call->proc==11){	/* NLM_TEST_RES */
			if( (!pinfo->fd->flags.visited) ){
				nlm_register_unmatched_res(pinfo, tvb, offset);
			} else {
				nlm_print_msgres_reply(pinfo, tree, tvb);
			}
			/* for the fhandle matching that finds both request and
			   response packet */
			if(nfs_fhandle_reqrep_matching){
				nlm_match_fhandle_reply(pinfo, tree);
			}
		}
	}

	offset = dissect_rpc_data(tvb, tree, hf_nlm_cookie, offset);

	if (tree) {
		lock_item = proto_tree_add_item(tree, hf_nlm_test_stat, tvb,
				offset, -1, ENC_NA);
		lock_tree = proto_item_add_subtree(lock_item, ett_nlm_lock);
	}

	offset = dissect_rpc_uint32(tvb, lock_tree, hf_nlm_test_stat_stat,
	    offset);

	/* last structure is optional, only supplied for stat==1 (LOCKED) */
	if(tvb_reported_length_remaining(tvb, offset) == 0){
		return offset;
	}

	if (tree) {
		lock_item = proto_tree_add_item(lock_tree, hf_nlm_holder, tvb,
				offset, -1, ENC_NA);
		if (lock_item)
			lock_tree = proto_item_add_subtree(lock_item,
				ett_nlm_lock);
	}

	offset = dissect_rpc_bool(tvb, lock_tree, hf_nlm_exclusive,
	    offset);
	offset = dissect_rpc_uint32(tvb, lock_tree, hf_nlm_lock_svid,
	    offset);
	offset = dissect_rpc_data(tvb, lock_tree, hf_nlm_lock_owner,
	    offset);

	if (version == 4) {
		offset = dissect_rpc_uint64(tvb, lock_tree,
		    hf_nlm_lock_l_offset64, offset);
		offset = dissect_rpc_uint64(tvb, lock_tree,
		    hf_nlm_lock_l_len64, offset);
	}
	else {
		offset = dissect_rpc_uint32(tvb, lock_tree,
		    hf_nlm_lock_l_offset, offset);
		offset = dissect_rpc_uint32(tvb, lock_tree,
		    hf_nlm_lock_l_len, offset);
	}

	return offset;
}


static int
dissect_nlm_share(tvbuff_t *tvb, int offset, packet_info *pinfo,
		  proto_tree *tree,int version _U_, rpc_call_info_value* civ)
{
	proto_item* lock_item = NULL;
	proto_tree* lock_tree = NULL;
	guint32 fh_hash;

	offset = dissect_rpc_data(tvb, tree, hf_nlm_cookie, offset);

	if (tree) {
		lock_item = proto_tree_add_item(tree, hf_nlm_share, tvb,
				offset, -1, ENC_NA);
		if (lock_item)
			lock_tree = proto_item_add_subtree(lock_item,
				ett_nlm_lock);
	}

	offset = dissect_rpc_string(tvb,lock_tree,
			hf_nlm_lock_caller_name, offset, NULL);

	offset = dissect_nfs3_fh(tvb, offset, pinfo, lock_tree, "fh", &fh_hash, civ);
	col_append_fstr(pinfo->cinfo, COL_INFO, " FH:0x%08x", fh_hash);

	offset = dissect_rpc_data(tvb, lock_tree, hf_nlm_lock_owner, offset);

	offset = dissect_rpc_uint32(tvb, lock_tree, hf_nlm_share_mode, offset);
	offset = dissect_rpc_uint32(tvb, lock_tree, hf_nlm_share_access, offset);


	offset = dissect_rpc_bool(tvb, tree, hf_nlm_reclaim, offset);
	return offset;
}

static int
dissect_nlm_shareres(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		     proto_tree *tree, int version _U_)
{
	guint32 nlm_stat;

	offset = dissect_rpc_data(tvb, tree, hf_nlm_cookie, offset);
	nlm_stat = tvb_get_ntohl(tvb, offset);
	if (nlm_stat) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
		    val_to_str(nlm_stat, names_nlm_stats, "Unknown Status (%u)"));
	}
	offset = dissect_rpc_uint32(tvb, tree, hf_nlm_stat, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_nlm_sequence, offset);
	return offset;
}

static int
dissect_nlm_freeall(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		    proto_tree *tree,int version _U_)
{
	offset = dissect_rpc_string(tvb,tree,
			hf_nlm_share_name, offset, NULL);

	offset = dissect_rpc_uint32(tvb, tree, hf_nlm_state, offset);

	return offset;
}


/* RPC functions */


/* This function is identical for all NLM protocol versions (1-4)*/
static int
dissect_nlm_gen_reply(tvbuff_t *tvb, packet_info *pinfo _U_,
		      proto_tree *tree, void* data)
{
	guint32 nlm_stat;
	int offset = 0;

	if(nlm_match_msgres){
		rpc_call_info_value *rpc_call=(rpc_call_info_value *)data;
		if((rpc_call->proc==12)  /* NLM_LOCK_RES */
		|| (rpc_call->proc==13)  /* NLM_CANCEL_RES */
		|| (rpc_call->proc==14)  /* NLM_UNLOCK_RES */
		|| (rpc_call->proc==15) ){	/* NLM_GRENTED_RES */
			if( (!pinfo->fd->flags.visited) ){
				nlm_register_unmatched_res(pinfo, tvb, offset);
			} else {
				nlm_print_msgres_reply(pinfo, tree, tvb);
			}
			/* for the fhandle matching that finds both request and
			   response packet */
			if(nfs_fhandle_reqrep_matching){
				nlm_match_fhandle_reply(pinfo, tree);
			}
		}
	}

	offset = dissect_rpc_data(tvb, tree, hf_nlm_cookie, offset);

	nlm_stat = tvb_get_ntohl(tvb, offset);
	if (nlm_stat) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
		    val_to_str(nlm_stat, names_nlm_stats, "Unknown Status (%u)"));
	}
	offset = dissect_rpc_uint32(tvb, tree, hf_nlm_stat, offset);
	return offset;
}

static int
dissect_nlm1_test(tvbuff_t *tvb, packet_info *pinfo,
		  proto_tree *tree, void* data)
{
	return dissect_nlm_test(tvb,0,pinfo,tree,1,(rpc_call_info_value*)data);
}

static int
dissect_nlm4_test(tvbuff_t *tvb, packet_info *pinfo,
		  proto_tree *tree, void* data)
{
	return dissect_nlm_test(tvb,0,pinfo,tree,4,(rpc_call_info_value*)data);
}


static int
dissect_nlm1_lock(tvbuff_t *tvb, packet_info *pinfo,
		  proto_tree *tree, void* data)
{
	return dissect_nlm_lock(tvb,0,pinfo,tree,1,(rpc_call_info_value*)data);
}

static int
dissect_nlm4_lock(tvbuff_t *tvb, packet_info *pinfo,
		  proto_tree *tree, void* data)
{
	return dissect_nlm_lock(tvb,0,pinfo,tree,4,(rpc_call_info_value*)data);
}


static int
dissect_nlm1_cancel(tvbuff_t *tvb, packet_info *pinfo,
		    proto_tree *tree, void* data)
{
	return dissect_nlm_cancel(tvb,0,pinfo,tree,1,(rpc_call_info_value*)data);
}

static int
dissect_nlm4_cancel(tvbuff_t *tvb, packet_info *pinfo,
		    proto_tree *tree, void* data)
{
	return dissect_nlm_cancel(tvb,0,pinfo,tree,4,(rpc_call_info_value*)data);
}


static int
dissect_nlm1_unlock(tvbuff_t *tvb, packet_info *pinfo,
		    proto_tree *tree, void* data)
{
	return dissect_nlm_unlock(tvb,0,pinfo,tree,1,(rpc_call_info_value*)data);
}

static int
dissect_nlm4_unlock(tvbuff_t *tvb, packet_info *pinfo,
		    proto_tree *tree, void* data)
{
	return dissect_nlm_unlock(tvb,0,pinfo,tree,4,(rpc_call_info_value*)data);
}


static int
dissect_nlm1_granted(tvbuff_t *tvb, packet_info *pinfo,
		     proto_tree *tree, void* data)
{
	return dissect_nlm_granted(tvb,0,pinfo,tree,1,(rpc_call_info_value*)data);
}

static int
dissect_nlm4_granted(tvbuff_t *tvb, packet_info *pinfo,
		     proto_tree *tree, void* data)
{
	return dissect_nlm_granted(tvb,0,pinfo,tree,4,(rpc_call_info_value*)data);
}


static int
dissect_nlm1_test_res(tvbuff_t *tvb, packet_info *pinfo,
		      proto_tree *tree, void* data)
{
	return dissect_nlm_test_res(tvb,0,pinfo,tree,1,(rpc_call_info_value*)data);
}

static int
dissect_nlm4_test_res(tvbuff_t *tvb, packet_info *pinfo,
		      proto_tree *tree, void* data)
{
	return dissect_nlm_test_res(tvb,0,pinfo,tree,4,(rpc_call_info_value*)data);
}

static int
dissect_nlm3_share(tvbuff_t *tvb, packet_info *pinfo,
		   proto_tree *tree, void* data _U_)
{
	return dissect_nlm_share(tvb,0,pinfo,tree,3,(rpc_call_info_value*)data);
}

static int
dissect_nlm4_share(tvbuff_t *tvb, packet_info *pinfo,
		   proto_tree *tree, void* data _U_)
{
	return dissect_nlm_share(tvb,0,pinfo,tree,4,(rpc_call_info_value*)data);
}

static int
dissect_nlm3_shareres(tvbuff_t *tvb, packet_info *pinfo,
		      proto_tree *tree, void* data _U_)
{
	return dissect_nlm_shareres(tvb,0,pinfo,tree,3);
}

static int
dissect_nlm4_shareres(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	return dissect_nlm_shareres(tvb,0,pinfo,tree,4);
}

static int
dissect_nlm3_freeall(tvbuff_t *tvb, packet_info *pinfo,
		     proto_tree *tree, void* data _U_)
{
	return dissect_nlm_freeall(tvb,0,pinfo,tree,3);
}

static int
dissect_nlm4_freeall(tvbuff_t *tvb, packet_info *pinfo,
		     proto_tree *tree, void* data _U_)
{
	return dissect_nlm_freeall(tvb,0,pinfo,tree,4);
}




/* proc number, "proc name", dissect_request, dissect_reply */
/* NLM protocol version 1 */
static const vsff nlm1_proc[] = {
	{ NLM_NULL,		"NULL",
		dissect_rpc_void,		dissect_rpc_void },
	{ NLM_TEST,		"TEST",
		dissect_nlm1_test,		dissect_nlm1_test_res },
	{ NLM_LOCK,		"LOCK",
		dissect_nlm1_lock,		dissect_nlm_gen_reply },
	{ NLM_CANCEL,		"CANCEL",
		dissect_nlm1_cancel,		dissect_nlm_gen_reply },
	{ NLM_UNLOCK,		"UNLOCK",
		dissect_nlm1_unlock,		dissect_nlm_gen_reply },
	{ NLM_GRANTED,		"GRANTED",
		dissect_nlm1_granted,		dissect_nlm_gen_reply },
	{ NLM_TEST_MSG,		"TEST_MSG",
		dissect_nlm1_test,		dissect_rpc_void },
	{ NLM_LOCK_MSG,		"LOCK_MSG",
		dissect_nlm1_lock,		dissect_rpc_void },
	{ NLM_CANCEL_MSG,	"CANCEL_MSG",
		dissect_nlm1_cancel,		dissect_rpc_void },
	{ NLM_UNLOCK_MSG,	"UNLOCK_MSG",
		dissect_nlm1_unlock,		dissect_rpc_void },
	{ NLM_GRANTED_MSG,	"GRANTED_MSG",
		dissect_nlm1_granted,		dissect_rpc_void },
	{ NLM_TEST_RES,		"TEST_RES",
		dissect_nlm1_test_res,		dissect_rpc_void },
	{ NLM_LOCK_RES,		"LOCK_RES",
		dissect_nlm_gen_reply,		dissect_rpc_void },
	{ NLM_CANCEL_RES,	"CANCEL_RES",
		dissect_nlm_gen_reply,		dissect_rpc_void },
	{ NLM_UNLOCK_RES,	"UNLOCK_RES",
		dissect_nlm_gen_reply,		dissect_rpc_void },
	{ NLM_GRANTED_RES,	"GRANTED_RES",
		dissect_nlm_gen_reply,		dissect_rpc_void },
	{ 0,			NULL,
		NULL,				NULL }
};
static const value_string nlm1_proc_vals[] = {
	{ NLM_NULL,		"NULL" },
	{ NLM_TEST,		"TEST" },
	{ NLM_LOCK,		"LOCK" },
	{ NLM_CANCEL,		"CANCEL" },
	{ NLM_UNLOCK,		"UNLOCK" },
	{ NLM_GRANTED,		"GRANTED" },
	{ NLM_TEST_MSG,		"TEST_MSG" },
	{ NLM_LOCK_MSG,		"LOCK_MSG" },
	{ NLM_CANCEL_MSG,	"CANCEL_MSG" },
	{ NLM_UNLOCK_MSG,	"UNLOCK_MSG" },
	{ NLM_GRANTED_MSG,	"GRANTED_MSG" },
	{ NLM_TEST_RES,		"TEST_RES" },
	{ NLM_LOCK_RES,		"LOCK_RES" },
	{ NLM_CANCEL_RES,	"CANCEL_RES" },
	{ NLM_UNLOCK_RES,	"UNLOCK_RES" },
	{ NLM_GRANTED_RES,	"GRANTED_RES" },
	{ 0,			NULL }
};
/* end of NLM protocol version 1 */

/* NLM protocol version 2 */
static const vsff nlm2_proc[] = {
	{ NLM_NULL,		"NULL",
		dissect_rpc_void,		dissect_rpc_void },
	{ NLM_TEST,		"TEST",
		dissect_nlm1_test,		dissect_nlm1_test_res },
	{ NLM_LOCK,		"LOCK",
		dissect_nlm1_lock,		dissect_nlm_gen_reply },
	{ NLM_CANCEL,		"CANCEL",
		dissect_nlm1_cancel,		dissect_nlm_gen_reply },
	{ NLM_UNLOCK,		"UNLOCK",
		dissect_nlm1_unlock,		dissect_nlm_gen_reply },
	{ NLM_GRANTED,		"GRANTED",
		dissect_nlm1_granted,		dissect_nlm_gen_reply },
	{ NLM_TEST_MSG,		"TEST_MSG",
		dissect_nlm1_test,		dissect_rpc_void },
	{ NLM_LOCK_MSG,		"LOCK_MSG",
		dissect_nlm1_lock,		dissect_rpc_void },
	{ NLM_CANCEL_MSG,	"CANCEL_MSG",
		dissect_nlm1_cancel,		dissect_rpc_void },
	{ NLM_UNLOCK_MSG,	"UNLOCK_MSG",
		dissect_nlm1_unlock,		dissect_rpc_void },
	{ NLM_GRANTED_MSG,	"GRANTED_MSG",
		dissect_nlm1_granted,		dissect_rpc_void },
	{ NLM_TEST_RES,		"TEST_RES",
		dissect_nlm1_test_res,		dissect_rpc_void },
	{ NLM_LOCK_RES,		"LOCK_RES",
		dissect_nlm_gen_reply,		dissect_rpc_void },
	{ NLM_CANCEL_RES,	"CANCEL_RES",
		dissect_nlm_gen_reply,		dissect_rpc_void },
	{ NLM_UNLOCK_RES,	"UNLOCK_RES",
		dissect_nlm_gen_reply,		dissect_rpc_void },
	{ NLM_GRANTED_RES,	"GRANTED_RES",
		dissect_nlm_gen_reply,		dissect_rpc_void },
	{ 0,			NULL,
		NULL,				NULL }
};
static const value_string nlm2_proc_vals[] = {
	{ NLM_NULL,		"NULL" },
	{ NLM_TEST,		"TEST" },
	{ NLM_LOCK,		"LOCK" },
	{ NLM_CANCEL,		"CANCEL" },
	{ NLM_UNLOCK,		"UNLOCK" },
	{ NLM_GRANTED,		"GRANTED" },
	{ NLM_TEST_MSG,		"TEST_MSG" },
	{ NLM_LOCK_MSG,		"LOCK_MSG" },
	{ NLM_CANCEL_MSG,	"CANCEL_MSG" },
	{ NLM_UNLOCK_MSG,	"UNLOCK_MSG" },
	{ NLM_GRANTED_MSG,	"GRANTED_MSG" },
	{ NLM_TEST_RES,		"TEST_RES" },
	{ NLM_LOCK_RES,		"LOCK_RES" },
	{ NLM_CANCEL_RES,	"CANCEL_RES" },
	{ NLM_UNLOCK_RES,	"UNLOCK_RES" },
	{ NLM_GRANTED_RES,	"GRANTED_RES" },
	{ 0,			NULL }
};
/* end of NLM protocol version 2 */

/* NLM protocol version 3 */
static const vsff nlm3_proc[] = {
	{ NLM_NULL,		"NULL",
		dissect_rpc_void,		dissect_rpc_void },
	{ NLM_TEST,		"TEST",
		dissect_nlm1_test,		dissect_nlm1_test_res },
	{ NLM_LOCK,		"LOCK",
		dissect_nlm1_lock,		dissect_nlm_gen_reply },
	{ NLM_CANCEL,		"CANCEL",
		dissect_nlm1_cancel,		dissect_nlm_gen_reply },
	{ NLM_UNLOCK,		"UNLOCK",
		dissect_nlm1_unlock,		dissect_nlm_gen_reply },
	{ NLM_GRANTED,		"GRANTED",
		dissect_nlm1_granted,		dissect_nlm_gen_reply },
	{ NLM_TEST_MSG,		"TEST_MSG",
		dissect_nlm1_test,		dissect_rpc_void },
	{ NLM_LOCK_MSG,		"LOCK_MSG",
		dissect_nlm1_lock,		dissect_rpc_void },
	{ NLM_CANCEL_MSG,	"CANCEL_MSG",
		dissect_nlm1_cancel,		dissect_rpc_void },
	{ NLM_UNLOCK_MSG,	"UNLOCK_MSG",
		dissect_nlm1_unlock,		dissect_rpc_void },
	{ NLM_GRANTED_MSG,	"GRANTED_MSG",
		dissect_nlm1_granted,		dissect_rpc_void },
	{ NLM_TEST_RES,		"TEST_RES",
		dissect_nlm1_test_res,		dissect_rpc_void },
	{ NLM_LOCK_RES,		"LOCK_RES",
		dissect_nlm_gen_reply,		dissect_rpc_void },
	{ NLM_CANCEL_RES,	"CANCEL_RES",
		dissect_nlm_gen_reply,		dissect_rpc_void },
	{ NLM_UNLOCK_RES,	"UNLOCK_RES",
		dissect_nlm_gen_reply,		dissect_rpc_void },
	{ NLM_GRANTED_RES,	"GRANTED_RES",
		dissect_nlm_gen_reply,		dissect_rpc_void },
	{ NLM_SHARE,		"SHARE",
		dissect_nlm3_share,		dissect_nlm3_shareres },
	{ NLM_UNSHARE,		"UNSHARE",
		dissect_nlm3_share,		dissect_nlm3_shareres },
	{ NLM_NM_LOCK,		"NM_LOCK",
		dissect_nlm1_lock,		dissect_nlm_gen_reply },
	{ NLM_FREE_ALL,		"FREE_ALL",
		dissect_nlm3_freeall,		dissect_rpc_void },
	{ 0,			NULL,
		NULL,				NULL }
};
static const value_string nlm3_proc_vals[] = {
	{ NLM_NULL,		"NULL" },
	{ NLM_TEST,		"TEST" },
	{ NLM_LOCK,		"LOCK" },
	{ NLM_CANCEL,		"CANCEL" },
	{ NLM_UNLOCK,		"UNLOCK" },
	{ NLM_GRANTED,		"GRANTED" },
	{ NLM_TEST_MSG,		"TEST_MSG" },
	{ NLM_LOCK_MSG,		"LOCK_MSG" },
	{ NLM_CANCEL_MSG,	"CANCEL_MSG" },
	{ NLM_UNLOCK_MSG,	"UNLOCK_MSG" },
	{ NLM_GRANTED_MSG,	"GRANTED_MSG" },
	{ NLM_TEST_RES,		"TEST_RES" },
	{ NLM_LOCK_RES,		"LOCK_RES" },
	{ NLM_CANCEL_RES,	"CANCEL_RES" },
	{ NLM_UNLOCK_RES,	"UNLOCK_RES" },
	{ NLM_GRANTED_RES,	"GRANTED_RES" },
	{ NLM_SHARE,		"SHARE" },
	{ NLM_UNSHARE,		"UNSHARE" },
	{ NLM_NM_LOCK,		"NM_LOCK" },
	{ NLM_FREE_ALL,		"FREE_ALL" },
	{ 0,			NULL }
};
/* end of NLM protocol version 3 */


/* NLM protocol version 4 */
static const vsff nlm4_proc[] = {
	{ NLM_NULL,		"NULL",
		dissect_rpc_void,		dissect_rpc_void },
	{ NLM_TEST,		"TEST",
		dissect_nlm4_test,		dissect_nlm4_test_res },
	{ NLM_LOCK,		"LOCK",
		dissect_nlm4_lock,		dissect_nlm_gen_reply },
	{ NLM_CANCEL,		"CANCEL",
		dissect_nlm4_cancel,		dissect_nlm_gen_reply },
	{ NLM_UNLOCK,		"UNLOCK",
		dissect_nlm4_unlock,	 	dissect_nlm_gen_reply },
	{ NLM_GRANTED,		"GRANTED",
		dissect_nlm4_granted,		dissect_nlm_gen_reply },
	{ NLM_TEST_MSG,		"TEST_MSG",
		dissect_nlm4_test,		dissect_rpc_void },
	{ NLM_LOCK_MSG,		"LOCK_MSG",
		dissect_nlm4_lock,		dissect_rpc_void },
	{ NLM_CANCEL_MSG,	"CANCEL_MSG",
		dissect_nlm4_cancel,		dissect_rpc_void },
	{ NLM_UNLOCK_MSG,	"UNLOCK_MSG",
		dissect_nlm4_unlock,		dissect_rpc_void },
	{ NLM_GRANTED_MSG,	"GRANTED_MSG",
		dissect_nlm4_granted,		dissect_rpc_void },
	{ NLM_TEST_RES,		"TEST_RES",
		dissect_nlm4_test_res,		dissect_rpc_void },
	{ NLM_LOCK_RES,		"LOCK_RES",
		dissect_nlm_gen_reply,		dissect_rpc_void },
	{ NLM_CANCEL_RES,	"CANCEL_RES",
		dissect_nlm_gen_reply,		dissect_rpc_void },
	{ NLM_UNLOCK_RES,	"UNLOCK_RES",
		dissect_nlm_gen_reply,		dissect_rpc_void },
	{ NLM_GRANTED_RES,	"GRANTED_RES",
		dissect_nlm_gen_reply,		dissect_rpc_void },
	{ NLM_SHARE,		"SHARE",
		dissect_nlm4_share,		dissect_nlm4_shareres },
	{ NLM_UNSHARE,		"UNSHARE",
		dissect_nlm4_share,		dissect_nlm4_shareres },
	{ NLM_NM_LOCK,		"NM_LOCK",
		dissect_nlm4_lock,		dissect_nlm_gen_reply },
	{ NLM_FREE_ALL,		"FREE_ALL",
		dissect_nlm4_freeall,		dissect_rpc_void },
	{ 0,			NULL,
		NULL,				NULL }
};
static const value_string nlm4_proc_vals[] = {
	{ NLM_NULL,		"NULL" },
	{ NLM_TEST,		"TEST" },
	{ NLM_LOCK,		"LOCK" },
	{ NLM_CANCEL,		"CANCEL" },
	{ NLM_UNLOCK,		"UNLOCK" },
	{ NLM_GRANTED,		"GRANTED" },
	{ NLM_TEST_MSG,		"TEST_MSG" },
	{ NLM_LOCK_MSG,		"LOCK_MSG" },
	{ NLM_CANCEL_MSG,	"CANCEL_MSG" },
	{ NLM_UNLOCK_MSG,	"UNLOCK_MSG" },
	{ NLM_GRANTED_MSG,	"GRANTED_MSG" },
	{ NLM_TEST_RES,		"TEST_RES" },
	{ NLM_LOCK_RES,		"LOCK_RES" },
	{ NLM_CANCEL_RES,	"CANCEL_RES" },
	{ NLM_UNLOCK_RES,	"UNLOCK_RES" },
	{ NLM_GRANTED_RES,	"GRANTED_RES" },
	{ NLM_SHARE,		"SHARE" },
	{ NLM_UNSHARE,		"UNSHARE" },
	{ NLM_NM_LOCK,		"NM_LOCK" },
	{ NLM_FREE_ALL,		"FREE_ALL" },
	{ 0,			NULL }
};
/* end of NLM protocol version 4 */

static const rpc_prog_vers_info nlm_vers_info[] = {
	{ 1, nlm1_proc, &hf_nlm_procedure_v1 },
	{ 2, nlm2_proc, &hf_nlm_procedure_v2 },
	{ 3, nlm3_proc, &hf_nlm_procedure_v3 },
	{ 4, nlm4_proc, &hf_nlm_procedure_v4 },
};

void
proto_register_nlm(void)
{
	static hf_register_info hf[] = {
		{ &hf_nlm_procedure_v1, {
			"V1 Procedure", "nlm.procedure_v1", FT_UINT32, BASE_DEC,
			VALS(nlm1_proc_vals), 0, NULL, HFILL }},
		{ &hf_nlm_procedure_v2, {
			"V2 Procedure", "nlm.procedure_v2", FT_UINT32, BASE_DEC,
			VALS(nlm2_proc_vals), 0, NULL, HFILL }},
		{ &hf_nlm_procedure_v3, {
			"V3 Procedure", "nlm.procedure_v3", FT_UINT32, BASE_DEC,
			VALS(nlm3_proc_vals), 0, NULL, HFILL }},
		{ &hf_nlm_procedure_v4, {
			"V4 Procedure", "nlm.procedure_v4", FT_UINT32, BASE_DEC,
			VALS(nlm4_proc_vals), 0, NULL, HFILL }},
		{ &hf_nlm_cookie, {
			"cookie", "nlm.cookie", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_nlm_block, {
			"block", "nlm.block", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},
		{ &hf_nlm_exclusive, {
			"exclusive", "nlm.exclusive", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},
		{ &hf_nlm_lock, {
			"lock", "nlm.lock", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_nlm_lock_caller_name, {
			"caller_name", "nlm.lock.caller_name", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_nlm_lock_owner, {
			"owner", "nlm.lock.owner", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_nlm_lock_svid, {
			"svid", "nlm.lock.svid", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_nlm_lock_l_offset64, {
			"l_offset", "nlm.lock.l_offset64", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_nlm_lock_l_offset, {
			"l_offset", "nlm.lock.l_offset", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_nlm_lock_l_len64, {
			"l_len", "nlm.lock.l_len64", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_nlm_lock_l_len, {
			"l_len", "nlm.lock.l_len", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_nlm_reclaim, {
			"reclaim", "nlm.reclaim", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},
		{ &hf_nlm_state, {
			"state", "nlm.state", FT_UINT32, BASE_DEC,
			NULL, 0, "STATD state", HFILL }},
		{ &hf_nlm_stat, {
			"stat", "nlm.stat", FT_UINT32, BASE_DEC,
			VALS(names_nlm_stats), 0, NULL, HFILL }},
		{ &hf_nlm_test_stat, {
			"test_stat", "nlm.test_stat", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_nlm_test_stat_stat, {
			"stat", "nlm.test_stat.stat", FT_UINT32, BASE_DEC,
			VALS(names_nlm_stats), 0, NULL, HFILL }},
		{ &hf_nlm_holder, {
			"holder", "nlm.holder", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_nlm_share, {
			"share", "nlm.share", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_nlm_share_mode, {
			"mode", "nlm.share.mode", FT_UINT32, BASE_DEC,
			VALS(names_fsh_mode), 0, NULL, HFILL }},
		{ &hf_nlm_share_access, {
			"access", "nlm.share.access", FT_UINT32, BASE_DEC,
			VALS(names_fsh_access), 0, NULL, HFILL }},
		{ &hf_nlm_share_name, {
			"name", "nlm.share.name", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_nlm_sequence, {
			"sequence", "nlm.sequence", FT_INT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_nlm_request_in, {
			"Request MSG in", "nlm.msg_in", FT_UINT32, BASE_DEC,
			NULL, 0, "The RES packet is a response to the MSG in this packet", HFILL }},
		{ &hf_nlm_reply_in, {
			"Reply RES in", "nlm.res_in", FT_UINT32, BASE_DEC,
			NULL, 0, "The response to this MSG packet is in this packet", HFILL }},
		{ &hf_nlm_time, {
			"Time from request", "nlm.time", FT_RELATIVE_TIME, BASE_NONE,
			NULL, 0, "Time between Request and Reply for async NLM calls", HFILL }},

		};

	static gint *ett[] = {
		&ett_nlm,
		&ett_nlm_lock,
	};
	module_t *nlm_module;

	proto_nlm = proto_register_protocol("Network Lock Manager Protocol",
	    "NLM", "nlm");
	proto_register_field_array(proto_nlm, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	nlm_module = prefs_register_protocol(proto_nlm, NULL);
	prefs_register_bool_preference(nlm_module, "msg_res_matching",
		"Match MSG/RES packets for async NLM",
		"Whether the dissector will track and match MSG and RES calls for asynchronous NLM",
		&nlm_match_msgres);
	register_init_routine(nlm_msg_res_match_init);
	register_cleanup_routine(nlm_msg_res_match_cleanup);
}

void
proto_reg_handoff_nlm(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_nlm, NLM_PROGRAM, ett_nlm,
	    G_N_ELEMENTS(nlm_vers_info), nlm_vers_info);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
