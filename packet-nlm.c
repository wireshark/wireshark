/* packet-nlm.c
 * Routines for nlm dissection
 *
 * $Id: packet-nlm.c,v 1.10 2001/01/03 06:55:30 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-mount.c
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
#include "config.h"
#endif


#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif


#include "packet-rpc.h"
#include "packet-nfs.h"
#include "packet-nlm.h"

/*
 * NFS Lock Manager protocol specs can only be found in actual
 * implementations or in the nice book:
 * Brent Callaghan: "NFS Illustrated", Addison-Wesley, ISBN 0-201-32570-5
 * which I use here as reference (BC).
 */

static int proto_nlm = -1;

static int hf_nlm_cookie = -1;
static int hf_nlm_block = -1;
static int hf_nlm_exclusive = -1;
static int hf_nlm_lock = -1;
static int hf_nlm_lock_caller_name = -1;
static int hf_nlm_lock_owner = -1;
static int hf_nlm_lock_svid = -1;
static int hf_nlm_lock_l_offset = -1;
static int hf_nlm_lock_l_len = -1;
static int hf_nlm_reclaim = -1;
static int hf_nlm_state = -1;

static gint ett_nlm = -1;
static gint ett_nlm_lock = -1;


const value_string names_nlm_state[] =
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


/* generic dissecting functions */

static int
dissect_nlm_lock(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int version, int offset)
{
	proto_item* lock_item = NULL;
	proto_tree* lock_tree = NULL;
	const guint8 *pd;
	int compat_offset;

	tvb_compat(tvb, &pd, &compat_offset);

	if (tree) {
		lock_item = proto_tree_add_item(tree, hf_nlm_lock, tvb,
				offset, tvb_length_remaining(tvb, offset), FALSE);
		if (lock_item)
			lock_tree = proto_item_add_subtree(lock_item, ett_nlm_lock);
	}

	offset = dissect_rpc_string_tvb(tvb,pinfo,lock_tree,
			hf_nlm_lock_caller_name, offset, NULL);
	offset = dissect_nfs_fh3(pd, compat_offset+offset, pinfo->fd, lock_tree,"fh") - compat_offset;

	offset = dissect_rpc_data_tvb(tvb, pinfo, lock_tree, hf_nlm_lock_owner, offset);

	offset = dissect_rpc_uint32_tvb(tvb, pinfo, lock_tree, hf_nlm_lock_svid, offset);

	if (version == 4) {
		offset = dissect_rpc_uint64_tvb(tvb, pinfo, lock_tree, hf_nlm_lock_l_offset, offset);
		offset = dissect_rpc_uint64_tvb(tvb, pinfo, lock_tree, hf_nlm_lock_l_len, offset);
	}
	else {
		offset = dissect_rpc_uint32_tvb(tvb, pinfo, lock_tree, hf_nlm_lock_l_offset, offset);
		offset = dissect_rpc_uint32_tvb(tvb, pinfo, lock_tree, hf_nlm_lock_l_len, offset);
	}

	return offset;
}


/* RPC functions */

#if 0
static int
dissect_nlm1_lock_call(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
#else
int
dissect_nlm1_lock_call(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	tvbuff_t *tvb = tvb_create_from_top(offset);
	packet_info *pinfo = &pi;
#endif
	int noffset;

	noffset = dissect_rpc_data_tvb(tvb, pinfo, tree, hf_nlm_cookie, 0);
	noffset = dissect_rpc_bool_tvb(tvb, pinfo, tree, hf_nlm_block, noffset);
	noffset = dissect_rpc_bool_tvb(tvb, pinfo, tree, hf_nlm_exclusive, noffset);
	noffset = dissect_nlm_lock(tvb, pinfo, tree, 1, noffset);
	noffset = dissect_rpc_bool_tvb(tvb, pinfo, tree, hf_nlm_reclaim, noffset);
	noffset = dissect_rpc_uint32_tvb(tvb, pinfo, tree, hf_nlm_state, noffset);
	return tvb_raw_offset(tvb) + noffset;
}


#if 0
static int
dissect_nlm1_unlock_call(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
#else
int
dissect_nlm1_unlock_call(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	tvbuff_t *tvb = tvb_create_from_top(offset);
	packet_info *pinfo = &pi;
#endif
	int noffset;

	noffset = dissect_rpc_data_tvb(tvb, pinfo, tree, hf_nlm_cookie, 0);
	noffset = dissect_nlm_lock(tvb, pinfo, tree, 1, noffset);
	return tvb_raw_offset(tvb) + noffset;
}


#if 0
static int
dissect_nlm1_gen_reply(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
#else
int
dissect_nlm1_gen_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	tvbuff_t *tvb = tvb_create_from_top(offset);
	packet_info *pinfo = &pi;
#endif
	int noffset;

	noffset = dissect_rpc_data_tvb(tvb, pinfo, tree, hf_nlm_cookie, 0);
	noffset = dissect_rpc_uint32_tvb(tvb, pinfo, tree, hf_nlm_state, noffset);
	return tvb_raw_offset(tvb) + noffset;
}


/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: take the generic one. */
/* NLM protocol version 1 */
const vsff nlm1_proc[] = {
	{ NLM_NULL,		"NULL",		/* OK */
	NULL,				NULL },
	{ NLM_TEST,		"TEST",
	NULL,				NULL },
	{ NLM_LOCK,		"LOCK",		/* OK */
	dissect_nlm1_lock_call,		dissect_nlm1_gen_reply },
	{ NLM_CANCEL,		"CANCEL",
	NULL,				dissect_nlm1_gen_reply },
	{ NLM_UNLOCK,		"UNLOCK",	/* OK */
	dissect_nlm1_unlock_call,	dissect_nlm1_gen_reply },
	{ NLM_GRANTED,		"GRANTED",
	NULL,				NULL },
	{ NLM_TEST_MSG,		"TEST_MSG",
	NULL,				NULL },
	{ NLM_LOCK_MSG,		"LOCK_MSG",	/* OK */
	dissect_nlm1_lock_call,		NULL },
	{ NLM_CANCEL_MSG,	"CANCEL_MSG",
	NULL,				NULL },
	{ NLM_UNLOCK_MSG,	"UNLOCK_MSG",	/* OK */
	dissect_nlm1_unlock_call,	NULL },
	{ NLM_GRANTED_MSG,	"GRANTED_MSG",
	NULL,				dissect_nlm1_gen_reply },
	{ NLM_TEST_RES,		"TEST_RES",
	NULL,				NULL },
	{ NLM_LOCK_RES,		"LOCK_RES",	/* OK */
	dissect_nlm1_gen_reply,		NULL },
	{ NLM_CANCEL_RES,	"CANCEL_RES",	/* OK */
	dissect_nlm1_gen_reply,		NULL },
	{ NLM_UNLOCK_RES,	"UNLOCK_RES",	/* OK */
	dissect_nlm1_gen_reply,		NULL },
	{ NLM_GRANTED_RES,	"GRANTED_RES",	/* OK */
	dissect_nlm1_gen_reply,		NULL },
	{ 0,			NULL,		NULL,	NULL }
};
/* end of NLM protocol version 1 */

/* NLM protocol version 2 */
const vsff nlm2_proc[] = {
	{ NLM_NULL,		"NULL",		NULL,	NULL },
	{ NLM_TEST,		"TEST",		NULL,	NULL },
	{ NLM_LOCK,		"LOCK",		NULL,	NULL },
	{ NLM_CANCEL,		"CANCEL",	NULL,	NULL },
	{ NLM_UNLOCK,		"UNLOCK",	NULL,	NULL },
	{ NLM_GRANTED,		"GRANTED",	NULL,	NULL },
	{ NLM_TEST_MSG,		"TEST_MSG",	NULL,	NULL },
	{ NLM_LOCK_MSG,		"LOCK_MSG",	NULL,	NULL },
	{ NLM_CANCEL_MSG,	"CANCEL_MSG",	NULL,	NULL },
	{ NLM_UNLOCK_MSG,	"UNLOCK_MSG",	NULL,	NULL },
	{ NLM_GRANTED_MSG,	"GRANTED_MSG",	NULL,	NULL },
	{ NLM_TEST_RES,		"TEST_RES",	NULL,	NULL },
	{ NLM_LOCK_RES,		"LOCK_RES",	NULL,	NULL },
	{ NLM_CANCEL_RES,	"CANCEL_RES",	NULL,	NULL },
	{ NLM_UNLOCK_RES,	"UNLOCK_RES",	NULL,	NULL },
	{ NLM_GRANTED_RES,	"GRANTED_RES",	NULL,	NULL },
	{ 0,			NULL,		NULL,	NULL }
};
/* end of NLM protocol version 2 */

/* NLM protocol version 3 */
const vsff nlm3_proc[] = {
	{ NLM_NULL,		"NULL",		NULL,	NULL },
	{ NLM_TEST,		"TEST",		NULL,	NULL },
	{ NLM_LOCK,		"LOCK",		NULL,	NULL },
	{ NLM_CANCEL,		"CANCEL",	NULL,	NULL },
	{ NLM_UNLOCK,		"UNLOCK",	NULL,	NULL },
	{ NLM_GRANTED,		"GRANTED",	NULL,	NULL },
	{ NLM_TEST_MSG,		"TEST_MSG",	NULL,	NULL },
	{ NLM_LOCK_MSG,		"LOCK_MSG",	NULL,	NULL },
	{ NLM_CANCEL_MSG,	"CANCEL_MSG",	NULL,	NULL },
	{ NLM_UNLOCK_MSG,	"UNLOCK_MSG",	NULL,	NULL },
	{ NLM_GRANTED_MSG,	"GRANTED_MSG",	NULL,	NULL },
	{ NLM_TEST_RES,		"TEST_RES",	NULL,	NULL },
	{ NLM_LOCK_RES,		"LOCK_RES",	NULL,	NULL },
	{ NLM_CANCEL_RES,	"CANCEL_RES",	NULL,	NULL },
	{ NLM_UNLOCK_RES,	"UNLOCK_RES",	NULL,	NULL },
	{ NLM_GRANTED_RES,	"GRANTED_RES",	NULL,	NULL },
	{ NLM_SHARE,		"SHARE",	NULL,	NULL },
	{ NLM_UNSHARE,		"UNSHARE",	NULL,	NULL },
	{ NLM_NM_LOCK,		"NM_LOCK",	NULL,	NULL },
	{ NLM_FREE_ALL,		"FREE_ALL",	NULL,	NULL },
	{ 0,			NULL,		NULL,	NULL }
};
/* end of NLM protocol version 3 */


#if 0
static int
dissect_nlm4_test_call(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
#else
int
dissect_nlm4_test_call(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	tvbuff_t *tvb = tvb_create_from_top(offset);
	packet_info *pinfo = &pi;
#endif
	int noffset;

	noffset = dissect_rpc_data_tvb(tvb, pinfo, tree, hf_nlm_cookie, 0);
	dissect_rpc_bool_tvb(tvb, pinfo, tree, hf_nlm_exclusive, noffset);
	noffset += 4;
	noffset = dissect_nlm_lock(tvb, pinfo, tree, 4, noffset);

	return tvb_raw_offset(tvb) + noffset;
}


/* NLM protocol version 4 */
const vsff nlm4_proc[] = {
	{ NLM_NULL,		"NULL",		NULL,	NULL },
	{ NLM_TEST,		"TEST",		dissect_nlm4_test_call,	NULL },
	{ NLM_LOCK,		"LOCK",		NULL,	NULL },
	{ NLM_CANCEL,		"CANCEL",	NULL,	NULL },
	{ NLM_UNLOCK,		"UNLOCK",	NULL,	NULL },
	{ NLM_GRANTED,		"GRANTED",	NULL,	NULL },
	{ NLM_TEST_MSG,		"TEST_MSG",	NULL,	NULL },
	{ NLM_LOCK_MSG,		"LOCK_MSG",	NULL,	NULL },
	{ NLM_CANCEL_MSG,	"CANCEL_MSG",	NULL,	NULL },
	{ NLM_UNLOCK_MSG,	"UNLOCK_MSG",	NULL,	NULL },
	{ NLM_GRANTED_MSG,	"GRANTED_MSG",	NULL,	NULL },
	{ NLM_TEST_RES,		"TEST_RES",	NULL,	NULL },
	{ NLM_LOCK_RES,		"LOCK_RES",	NULL,	NULL },
	{ NLM_CANCEL_RES,	"CANCEL_RES",	NULL,	NULL },
	{ NLM_UNLOCK_RES,	"UNLOCK_RES",	NULL,	NULL },
	{ NLM_GRANTED_RES,	"GRANTED_RES",	NULL,	NULL },
	{ NLM_SHARE,		"SHARE",	NULL,	NULL },
	{ NLM_UNSHARE,		"UNSHARE",	NULL,	NULL },
	{ NLM_NM_LOCK,		"NM_LOCK",	NULL,	NULL },
	{ NLM_FREE_ALL,		"FREE_ALL",	NULL,	NULL },
	{ 0,			NULL,		NULL,	NULL }
};
/* end of NLM protocol version 4 */


static struct true_false_string yesno = { "Yes", "No" };


void
proto_register_nlm(void)
{
	static hf_register_info hf[] = {
		{ &hf_nlm_cookie, {
			"cookie", "nlm.cookie", FT_STRING, BASE_DEC,
			NULL, 0, "cookie" }},
		{ &hf_nlm_block, {
			"block", "nlm.block", FT_BOOLEAN, BASE_NONE,
			&yesno, 0, "block" }},
		{ &hf_nlm_exclusive, {
			"exclusive", "nlm.exclusive", FT_BOOLEAN, BASE_NONE,
			&yesno, 0, "exclusive" }},
		{ &hf_nlm_lock, {
			"lock", "nlm.lock", FT_NONE, 0,
			NULL, 0, "lock" }},
		{ &hf_nlm_lock_caller_name, {
			"caller_name", "nlm.lock.caller_name", FT_STRING, BASE_NONE,
			NULL, 0, "caller_name" }},
		{ &hf_nlm_lock_owner, {
			"owner", "nlm.lock.owner", FT_STRING, BASE_DEC,
			NULL, 0, "owner" }},
		{ &hf_nlm_lock_svid, {
			"svid", "nlm.lock.svid", FT_UINT32, BASE_DEC,
			NULL, 0, "svid" }},
		{ &hf_nlm_lock_l_offset, {
			"l_offset", "nlm.lock.l_offset", FT_UINT32, BASE_DEC,
			NULL, 0, "l_offset" }},
		{ &hf_nlm_lock_l_len, {
			"l_len", "nlm.lock.l_len", FT_UINT32, BASE_DEC,
			NULL, 0, "l_len" }},
		{ &hf_nlm_reclaim, {
			"reclaim", "nlm.reclaim", FT_BOOLEAN, BASE_NONE,
			&yesno, 0, "reclaim" }},
		{ &hf_nlm_state, {
			"state", "nlm.state", FT_UINT32, BASE_DEC,
			VALS(names_nlm_state), 0, "state" }},
		};

	static gint *ett[] = {
		&ett_nlm,
		&ett_nlm_lock,
	};

	proto_nlm = proto_register_protocol("Network Lock Manager Protocol",
	    "NLM", "nlm");
	proto_register_field_array(proto_nlm, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_nlm(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_nlm, NLM_PROGRAM, ett_nlm);
	/* Register the procedure tables */
	rpc_init_proc_table(NLM_PROGRAM, 1, nlm1_proc);
	rpc_init_proc_table(NLM_PROGRAM, 2, nlm2_proc);
	rpc_init_proc_table(NLM_PROGRAM, 3, nlm3_proc);
	rpc_init_proc_table(NLM_PROGRAM, 4, nlm4_proc);
}
