/* packet-dcerpc-nt.c
 * Routines for DCERPC over SMB packet disassembly
 * Copyright 2001-2003, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-dcerpc-nt.c,v 1.77 2003/07/01 00:59:43 guy Exp $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"
#include "smb.h"
#include "packet-smb-common.h" /* for dissect_smb_64bit_time() */

/*
 * This file contains helper routines that are used by the DCERPC over SMB
 * dissectors for ethereal.
 */

/*
 * Used by several dissectors.
 */
const value_string platform_id_vals[] = {
	{ 300, "DOS" },
	{ 400, "OS/2" },
	{ 500, "Windows NT" },
	{ 600, "OSF" },
	{ 700, "VMS" },
	{ 0,   NULL }
};

/* Parse some common RPC structures */

gint ett_nt_unicode_string = -1; /* FIXME: make static */

/* Dissect a counted string as a callback to dissect_ndr_pointer_cb() */

static int hf_nt_cs_len = -1;
static int hf_nt_cs_size = -1;

int
dissect_ndr_counted_string_cb(tvbuff_t *tvb, int offset,
			      packet_info *pinfo, proto_tree *tree,
			      char *drep, int hf_index,
			      dcerpc_callback_fnct_t *callback,
			      void *callback_args)
{
	dcerpc_info *di = pinfo->private_data;
	guint16 len, size;

        /* Structure starts with short, but is aligned for longs */

	ALIGN_TO_4_BYTES;

	if (di->conformant_run)
		return offset;
	
	/* 
           struct {
               short len;
               short size;
               [size_is(size/2), length_is(len/2), ptr] unsigned short *string;
           } UNICODE_STRING;

         */

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
			hf_nt_cs_len, &len);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
			hf_nt_cs_size, &size);	

	offset = dissect_ndr_pointer_cb(tvb, offset, pinfo, tree, drep,
			dissect_ndr_wchar_cvstring, NDR_POINTER_UNIQUE,
			"Character Array", hf_index, callback, callback_args);

	return offset;
}

static gint ett_nt_counted_string = -1;

static int
dissect_ndr_counted_string_helper(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  char *drep, int hf_index, int levels,
				  gboolean add_subtree)
{
	proto_item *item;
	proto_tree *subtree = tree;

	if (add_subtree) {

		item = proto_tree_add_text(
			tree, tvb, offset, 0, 
			proto_registrar_get_name(hf_index));

		subtree = proto_item_add_subtree(item, ett_nt_counted_string);
	}

	/*
	 * Add 2 levels, so that the string gets attached to the
	 * "Character Array" top-level item and to the top-level item
	 * added above.
	 */
	return dissect_ndr_counted_string_cb(
		tvb, offset, pinfo, subtree, drep, hf_index,
		cb_wstr_postprocess, GINT_TO_POINTER(2 + levels));
}

/* Dissect a counted string in-line. */

int
dissect_ndr_counted_string(tvbuff_t *tvb, int offset,
			   packet_info *pinfo, proto_tree *tree,
			   char *drep, int hf_index, int levels)
{
	return dissect_ndr_counted_string_helper(
		tvb, offset, pinfo, tree, drep, hf_index, levels, TRUE);
}

/* Dissect a counted string as a callback to dissect_ndr_pointer().
   This doesn't add a adds a proto item and subtreee for the string as
   the pointer dissection already creates one. */

int
dissect_ndr_counted_string_ptr(tvbuff_t *tvb, int offset,
			       packet_info *pinfo, proto_tree *tree,
			       char *drep)
{
	dcerpc_info *di = pinfo->private_data;

	return dissect_ndr_counted_string_helper(
		tvb, offset, pinfo, tree, drep, di->hf_index, 0, FALSE);
}

/* Dissect a counted byte_array as a callback to dissect_ndr_pointer_cb() */

static gint ett_nt_counted_byte_array = -1;

/* Dissect a counted byte array in-line. */

int
dissect_ndr_counted_byte_array_cb(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  char *drep, int hf_index,
				  dcerpc_callback_fnct_t *callback,
				  void *callback_args)
{
	dcerpc_info *di = pinfo->private_data;
	proto_item *item;
	proto_tree *subtree;
	guint16 len, size;

        /* Structure starts with short, but is aligned for longs */

	ALIGN_TO_4_BYTES;

	if (di->conformant_run)
		return offset;

	item = proto_tree_add_text(tree, tvb, offset, 0, 
		proto_registrar_get_name(hf_index));

	subtree = proto_item_add_subtree(item, ett_nt_counted_byte_array);
	
	/* 
           struct {
               short len;
               short size;
               [size_is(size), length_is(len), ptr] unsigned char *string;
           } WHATEVER_THIS_IS_CALLED;

         */

	offset = dissect_ndr_uint16(tvb, offset, pinfo, subtree, drep,
			hf_nt_cs_len, &len);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, subtree, drep,
			hf_nt_cs_size, &size);	

	offset = dissect_ndr_pointer_cb(tvb, offset, pinfo, subtree, drep,
			dissect_ndr_char_cvstring, NDR_POINTER_UNIQUE,
			"Byte Array", hf_index, callback, callback_args);

	return offset;
}

int
dissect_ndr_counted_byte_array(tvbuff_t *tvb, int offset,
			       packet_info *pinfo, proto_tree *tree,
			       char *drep, int hf_index)
{
	return dissect_ndr_counted_byte_array_cb(
		tvb, offset, pinfo, tree, drep, hf_index, NULL, NULL);
}

/* This function is used to dissect a DCERPC encoded 64 bit time value.
   XXX it should be fixed both here and in dissect_smb_64bit_time so
   it can handle both BIG and LITTLE endian encodings
 */
int
dissect_ndr_nt_NTTIME (tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep _U_, int hf_index)
{
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	ALIGN_TO_4_BYTES;

	offset = dissect_smb_64bit_time(tvb, tree, offset, hf_index);
	return offset;
}

/* Define this symbol to display warnings about request/response and
   policy handle hash table collisions.  This happens when a packet with
   the same conversation, smb fid and dcerpc call id occurs.  I think this
   is due to a bug in the dcerpc/smb fragment reassembly code. */

#undef DEBUG_HASH_COLL

/*
 * Policy handle hashing.
 *
 * We hash based on the policy handle value; the items in the hash table
 * are lists of policy handle information about one or more policy
 * handles with that value.  We have multiple values in case a given
 * policy handle is opened in frame N, closed in frame M, and re-opened
 * in frame O, where N < M < O.
 *
 * XXX - we really should also use a DCE RPC conversation/session handle
 * of some sort, in case two separate sessions have the same handle
 * value.  A transport-layer conversation might not be sufficient, as you
 * might, for example, have multiple pipes in a single SMB connection,
 * and you might have the same handle opened and closed separately on
 * those two pipes.
 *
 * The policy handle information has "first frame" and "last frame"
 * information; the entry should be used when dissecting a given frame
 * only if that frame is within the interval [first frame,last frame].
 * The list is sorted by "first frame".
 *
 * This doesn't handle the case of a handle being opened in frame N and
 * re-opened in frame M, where N < M, with no intervening close, but I'm
 * not sure anything can handle that if it's within the same DCE RPC
 * session (if it's not, the conversation/session handle would fix that).
 */

typedef struct {
	guint8 policy_hnd[20];
} pol_hash_key;

typedef struct pol_value {
	struct pol_value *next;          /* Next entry in hash bucket */
	guint32 open_frame, close_frame; /* Frame numbers for open/close */
	guint32 first_frame;             /* First frame in which this instance was seen */
	guint32 last_frame;              /* Last frame in which this instance was seen */
	char *name;			 /* Name of policy handle */
} pol_value;

typedef struct {
	pol_value *list;                 /* List of policy handle entries */
} pol_hash_value;

#define POL_HASH_INIT_COUNT 100

static GHashTable *pol_hash;
static GMemChunk *pol_hash_key_chunk;
static GMemChunk *pol_value_chunk;
static GMemChunk *pol_hash_value_chunk;

/* Hash function */

static guint pol_hash_fn(gconstpointer k)
{
	const pol_hash_key *key = (const pol_hash_key *)k;

	/* Bytes 4-7 of the policy handle are a timestamp so should make a
	   reasonable hash value */

	return key->policy_hnd[4] + (key->policy_hnd[5] << 8) +
		(key->policy_hnd[6] << 16) + (key->policy_hnd[7] << 24);
}

/* Return true if a policy handle is all zeros */

static gboolean is_null_pol(e_ctx_hnd *policy_hnd)
{
	static guint8 null_policy_hnd[20];

	return memcmp(policy_hnd, null_policy_hnd, 20) == 0;
}

/* Hash compare function */

static gint pol_hash_compare(gconstpointer k1, gconstpointer k2)
{
	const pol_hash_key *key1 = (const pol_hash_key *)k1;
	const pol_hash_key *key2 = (const pol_hash_key *)k2;

	return memcmp(key1->policy_hnd, key2->policy_hnd,
		      sizeof(key1->policy_hnd)) == 0;
}

/*
 * Look up the instance of a policy handle value in whose range of frames
 * the specified frame falls.
 */
static pol_value *find_pol_handle(e_ctx_hnd *policy_hnd, guint32 frame,
				  pol_hash_value **valuep)
{
	pol_hash_key key;
	pol_value *pol;

	memcpy(&key.policy_hnd, policy_hnd, sizeof(key.policy_hnd));
	if ((*valuep = g_hash_table_lookup(pol_hash, &key))) {
		/*
		 * Look for the first value such that both:
		 *
		 *	1) the first frame in which it was seen is
		 *	   <= the specified frame;
		 *
		 *	2) the last frame in which it was seen is
		 *	   either unknown (meaning we haven't yet
		 *	   seen a close or another open of the
		 *	   same handle, which is assumed to imply
		 *	   an intervening close that wasn't captured)
		 *	   or is >= the specified frame.
		 *
		 * If there's more than one such frame, that's the
		 * case where a handle is opened in frame N and
		 * reopened in frame M, with no intervening close;
		 * there is no right answer for that, so the instance
		 * opened in frame N is as right as anything else.
		 */
		for (pol = (*valuep)->list; pol != NULL; pol = pol->next) {
			if (pol->first_frame <= frame &&
			    (pol->last_frame == 0 ||
			     pol->last_frame >= frame))
				break;	/* found one */
		}
		return pol;
	} else {
		/*
		 * The handle isn't in the hash table.
		 */
		return NULL;
	}
}

static void add_pol_handle(e_ctx_hnd *policy_hnd, guint32 frame,
			   pol_value *pol, pol_hash_value *value)
{
	pol_hash_key *key;
	pol_value *polprev, *polnext;

	if (value == NULL) {
		/*
		 * There's no hash value; create one, put the new
		 * value at the beginning of its policy handle list,
		 * and put the hash value in the policy handle hash
		 * table.
		 */
		value = g_mem_chunk_alloc(pol_hash_value_chunk);
		value->list = pol;
		pol->next = NULL;
		key = g_mem_chunk_alloc(pol_hash_key_chunk);
		memcpy(&key->policy_hnd, policy_hnd, sizeof(key->policy_hnd));
		g_hash_table_insert(pol_hash, key, value);
	} else {
		/*
		 * Put the new value in the hash value's policy handle
		 * list so that it's sorted by the first frame in
		 * which it appeared.
		 *
		 * Search for the first entry whose first frame number
		 * is greater than the current frame number, if any.
		 */
		for (polnext = value->list, polprev = NULL;
		    polnext != NULL && polnext->first_frame <= frame;
		    polprev = polnext, polnext = polnext->next)
			;

		/*
		 * "polprev" points to the entry in the list after
		 * which we should put the new entry; if it's null,
		 * that means we should put it at the beginning of
		 * the list.
		 */
		if (polprev == NULL)
			value->list = pol;
		else
			polprev->next = pol;
		
		/*
		 * "polnext" points to the entry in the list before
		 * which we should put the new entry; if it's null,
		 * that means we should put it at the end of the list.
		 */
		pol->next = polnext;
	}
}

/* Store the open and close frame numbers of a policy handle */

void dcerpc_smb_store_pol_pkts(e_ctx_hnd *policy_hnd, packet_info *pinfo,
			       gboolean is_open, gboolean is_close)
{
	pol_hash_value *value;
	pol_value *pol;

	/*
	 * By the time the first pass is done, the policy handle database
	 * has been completely constructed.  If we've already seen this
	 * frame, there's nothing to do.
	 */
	if (pinfo->fd->flags.visited)
		return;

	if (is_null_pol(policy_hnd))
		return;

	/* Look up existing value */
	pol = find_pol_handle(policy_hnd, pinfo->fd->num, &value);

	if (pol != NULL) {
		/*
		 * Update the existing value as appropriate.
		 */
		if (is_open) {
			/*
			 * This is an open; we assume that we missed
			 * a close of this handle, so we set its
			 * "last frame" value and act as if we didn't
			 * see it.
			 *
			 * XXX - note that we might be called twice for
			 * the same operation (see "dissect_pipe_dcerpc()",
			 * which calls the DCE RPC dissector twice), so we
			 * must first check to see if this is a handle we
			 * just filled in.
			 *
			 * We check whether this handle's "first frame"
			 * frame number is this frame and its "last frame
			 * is 0; if so, this is presumably a duplicate call,
			 * and we don't do an implicit close.
			 */
			if (pol->first_frame == pinfo->fd->num &&
			    pol->last_frame == 0)
				return;
			pol->last_frame = pinfo->fd->num;
			pol = NULL;
		} else {
			if (is_close) {
				pol->close_frame = pinfo->fd->num;
				pol->last_frame = pinfo->fd->num;
			}
			return;
		}
	}

	/* Create a new value */

	pol = g_mem_chunk_alloc(pol_value_chunk);

	pol->open_frame = is_open ? pinfo->fd->num : 0;
	pol->close_frame = is_close ? pinfo->fd->num : 0;
	pol->first_frame = pinfo->fd->num;
	pol->last_frame = pol->close_frame;	/* if 0, unknown; if non-0, known */

	pol->name = NULL;

	add_pol_handle(policy_hnd, pinfo->fd->num, pol, value);
}

/* Store a text string with a policy handle */

void dcerpc_smb_store_pol_name(e_ctx_hnd *policy_hnd, packet_info *pinfo,
			       char *name)
{
	pol_hash_value *value;
	pol_value *pol;

	/*
	 * By the time the first pass is done, the policy handle database
	 * has been completely constructed.  If we've already seen this
	 * frame, there's nothing to do.
	 */
	if (pinfo->fd->flags.visited)
		return;

	if (is_null_pol(policy_hnd))
		return;

	/* Look up existing value */
	pol = find_pol_handle(policy_hnd, pinfo->fd->num, &value);

	if (pol != NULL) {
		/*
		 * This is the first pass; update the existing
		 * value as appropriate.
		 */
		if (pol->name && name) {
#ifdef DEBUG_HASH_COLL
			if (strcmp(pol->name, name) != 0)
				g_warning("dcerpc_smb: pol_hash name collision %s/%s\n", value->name, name);
#endif
			free(pol->name);
		}

		pol->name = strdup(name);

		return;
	}

	/* Create a new value */

	pol = g_mem_chunk_alloc(pol_value_chunk);

	pol->open_frame = 0;
	pol->close_frame = 0;
	pol->first_frame = pinfo->fd->num;
	pol->last_frame = 0;

	if (name)
		pol->name = strdup(name);
	else
		pol->name = strdup("<UNKNOWN>");

	add_pol_handle(policy_hnd, pinfo->fd->num, pol, value);
}

/*
 * Retrieve a policy handle.
 *
 * XXX - should this get an "is_close" argument, and match even closed
 * policy handles if the call is a close, so we can handle retransmitted
 * close operations?
 */

gboolean dcerpc_smb_fetch_pol(e_ctx_hnd *policy_hnd, char **name,
			      guint32 *open_frame, guint32 *close_frame,
			      guint32 cur_frame)
{
	pol_hash_value *value;
	pol_value *pol;

	/* Prevent uninitialised return vars */

	if (name)
		*name = NULL;

	if (open_frame)
		*open_frame = 0;

	if (close_frame)
		*close_frame = 0;

	/* Look up existing value */
	pol = find_pol_handle(policy_hnd, cur_frame, &value);

	if (pol) {
		if (name)
			*name = pol->name;

		if (open_frame)
			*open_frame = pol->open_frame;

		if (close_frame)
			*close_frame = pol->close_frame;
	}

	return pol != NULL;
}

/* Iterator to free a policy handle key/value pair, and all
   the policy handle values to which the hash table value
   points */

static void free_pol_keyvalue(gpointer key _U_, gpointer value_arg,
    gpointer user_data _U_)
{
	pol_hash_value *value = (pol_hash_value *)value_arg;
	pol_value *pol;

	/* Free user data */

	for (pol = value->list; pol != NULL; pol = pol->next) {
		free(pol->name);
		pol->name = NULL;
	}
}

/* Initialise policy handle hash */

static void init_pol_hash(void)
{
	/* Initialise memory chunks */

	if (pol_hash_key_chunk)
		g_mem_chunk_destroy(pol_hash_key_chunk);

	pol_hash_key_chunk = g_mem_chunk_new(
		"Policy handle hash keys", sizeof(pol_hash_key),
		POL_HASH_INIT_COUNT * sizeof(pol_hash_key), G_ALLOC_ONLY);

	if (pol_value_chunk)
		g_mem_chunk_destroy(pol_value_chunk);

	pol_value_chunk = g_mem_chunk_new(
		"Policy handle values", sizeof(pol_value),
		POL_HASH_INIT_COUNT * sizeof(pol_value), G_ALLOC_ONLY);

	if (pol_hash_value_chunk)
		g_mem_chunk_destroy(pol_hash_value_chunk);

	pol_hash_value_chunk = g_mem_chunk_new(
		"Policy handle hash values", sizeof(pol_hash_value),
		POL_HASH_INIT_COUNT * sizeof(pol_hash_value), G_ALLOC_ONLY);

	/* Initialise hash table */

	if (pol_hash) {
		g_hash_table_foreach(pol_hash, free_pol_keyvalue, NULL);
		g_hash_table_destroy(pol_hash);
	}

	pol_hash = g_hash_table_new(pol_hash_fn, pol_hash_compare);
}

/* Dissect a NT status code */

int
dissect_ntstatus(tvbuff_t *tvb, gint offset, packet_info *pinfo,
		 proto_tree *tree, char *drep,
		 int hfindex, guint32 *pdata)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hfindex, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
				val_to_str(status, NT_errors,
					   "Unknown error 0x%08x"));
	if (pdata)
		*pdata = status;

	return offset;
}

/* Dissect a DOS status code */

int
dissect_doserror(tvbuff_t *tvb, gint offset, packet_info *pinfo,
	       proto_tree *tree, char *drep,
	       int hfindex, guint32 *pdata)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hfindex, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
				val_to_str(status, DOS_errors,
					   "Unknown error 0x%08x"));
	if (pdata)
		*pdata = status;

	return offset;
}

/* Dissect a NT policy handle */

static int hf_nt_policy_open_frame = -1;
static int hf_nt_policy_close_frame = -1;

static gint ett_nt_policy_hnd = -1;

int
dissect_nt_policy_hnd(tvbuff_t *tvb, gint offset, packet_info *pinfo,
		      proto_tree *tree, char *drep, int hfindex,
		      e_ctx_hnd *pdata, proto_item **pitem,
		      gboolean is_open, gboolean is_close)
{
	proto_item *item;
	proto_tree *subtree;
	e_ctx_hnd hnd;
	guint32 open_frame = 0, close_frame = 0;
	char *name;
	int old_offset = offset;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*
		 * just a run to handle conformant arrays, no scalars to
		 * dissect - and "dissect_ndr_ctx_hnd()" won't return
		 * a handle, so we can't do the hashing stuff in any
		 * case
		 */
		return offset;
	}

	/* Add to proto tree */

	item = proto_tree_add_text(tree, tvb, offset, sizeof(e_ctx_hnd),
				   "Policy Handle");

	subtree = proto_item_add_subtree(item, ett_nt_policy_hnd);

	offset = dissect_ndr_ctx_hnd(tvb, offset, pinfo, subtree, drep,
				     hfindex, &hnd);

	/*
	 * Create a new entry for this handle if it's not a null handle
	 * and no entry already exists, and, in any case, set the
	 * open, close, first, and last frame information as appropriate.
	 */
	dcerpc_smb_store_pol_pkts(&hnd, pinfo, is_open, is_close);

	/* Insert open/close/name information if known */

	if (dcerpc_smb_fetch_pol(&hnd, &name, &open_frame, &close_frame,
	    pinfo->fd->num)) {

		if (open_frame)
			proto_tree_add_uint(
				subtree, hf_nt_policy_open_frame, tvb,
				old_offset, sizeof(e_ctx_hnd), open_frame);

		if (close_frame)
			proto_tree_add_uint(
				subtree, hf_nt_policy_close_frame, tvb,
				old_offset, sizeof(e_ctx_hnd), close_frame);

		/*
		 * Don't append the handle name if pitem is null; that's
		 * an indication that our caller will do so, as we're
		 * supplying a pointer to the item so that they can do
		 * so.
		 */
		if (name != NULL && pitem == NULL)
			proto_item_append_text(item, ": %s", name);
	}

	if (pdata)
		*pdata = hnd;

	if (pitem)
		*pitem = item;

	return offset;
}

/* Some helper routines to dissect a range of uint8 characters.  I don't
   think these are "official" NDR representations and are probably specific
   to NT so for the moment they're put here instead of in packet-dcerpc.c
   and packet-dcerpc-ndr.c. */

int
dissect_dcerpc_uint8s(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_,
                      proto_tree *tree, char *drep, int hfindex,
		      int length, const guint8 **pdata)
{
    const guint8 *data;

    data = (const guint8 *)tvb_get_ptr(tvb, offset, length);

    if (tree) {
        proto_tree_add_item (tree, hfindex, tvb, offset, length, (drep[0] & 0x10));
    }

    if (pdata)
        *pdata = data;

    return offset + length;
}

int
dissect_ndr_uint8s(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                   proto_tree *tree, char *drep,
                   int hfindex, int length, const guint8 **pdata)
{
    dcerpc_info *di;

    di=pinfo->private_data;
    if(di->conformant_run){
      /* just a run to handle conformant arrays, no scalars to dissect */
      return offset;
    }

    /* no alignment needed */
    return dissect_dcerpc_uint8s(tvb, offset, pinfo,
                                 tree, drep, hfindex, length, pdata);
}

int
dissect_dcerpc_uint16s(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_,
                      proto_tree *tree, char *drep, int hfindex,
		      int length)
{
    if (tree) {
        proto_tree_add_item (tree, hfindex, tvb, offset, length * 2, (drep[0] & 0x10));
    }

    return offset + length * 2;
}

int
dissect_ndr_uint16s(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                   proto_tree *tree, char *drep,
                   int hfindex, int length)
{
    dcerpc_info *di;

    di=pinfo->private_data;
    if(di->conformant_run){
      /* just a run to handle conformant arrays, no scalars to dissect */
      return offset;
    }

    if (offset % 2)
        offset++;

    return dissect_dcerpc_uint16s(tvb, offset, pinfo,
                                 tree, drep, hfindex, length);
}

/*
 * Helper routines for dissecting NDR strings
 */

void cb_wstr_postprocess(packet_info *pinfo, proto_tree *tree _U_,
			proto_item *item, tvbuff_t *tvb, 
			int start_offset, int end_offset,
			void *callback_args)
{
	gint options = GPOINTER_TO_INT(callback_args);
	gint levels = CB_STR_ITEM_LEVELS(options);
	char *s;

	/* Align start_offset on 4-byte boundary. */

	if (start_offset % 4)
		start_offset += 4 - (start_offset % 4);

	/* Get string value */

	if ((end_offset - start_offset) <= 12)
		return;		/* XXX: Use unistr2 dissector instead? */

	/*
	 * XXX - need to handle non-printable characters here.
	 *
	 * XXX - this is typically called after the string has already
	 * been fetched and processed by some other routine; is there
	 * some way we can get that string, rather than duplicating the
	 * efforts of that routine?
	 */
	s = tvb_fake_unicode(
		tvb, start_offset + 12, (end_offset - start_offset - 12) / 2,
		TRUE);

	/* Append string to COL_INFO */

	if (options & CB_STR_COL_INFO) {
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", s);
	}

	/* Append string to upper-level proto_items */

	if (levels > 0 && item && s && s[0]) {
		proto_item_append_text(item, ": %s", s);
		item = item->parent;
		levels--;
		if (levels > 0) {
			proto_item_append_text(item, ": %s", s);
			item = item->parent;
			levels--;
			while (levels > 0) {
				proto_item_append_text(item, " %s", s);
				item = item->parent;
				levels--;
			}
		}
	}

	/* Save string to dcv->private_data */

	if (options & CB_STR_SAVE) {
		dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
		dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
		
		dcv->private_data = g_strdup(s);
	}

	g_free(s);
}

void cb_str_postprocess(packet_info *pinfo, proto_tree *tree _U_,
			proto_item *item, tvbuff_t *tvb, 
			int start_offset, int end_offset,
			void *callback_args)
{
	gint options = GPOINTER_TO_INT(callback_args);
	gint levels = CB_STR_ITEM_LEVELS(options);
	char *s;

	/* Align start_offset on 4-byte boundary. */

	if (start_offset % 4)
		start_offset += 4 - (start_offset % 4);

	/* Get string value */

	if ((end_offset - start_offset) <= 12)
		return;		/* XXX: Use unistr2 dissector instead? */

	/*
	 * XXX - need to handle non-printable characters here.
	 *
	 * XXX - this is typically called after the string has already
	 * been fetched and processed by some other routine; is there
	 * some way we can get that string, rather than duplicating the
	 * efforts of that routine?
	 */
	s = tvb_get_string(
		tvb, start_offset + 12, (end_offset - start_offset - 12) );

	/* Append string to COL_INFO */

	if (options & CB_STR_COL_INFO) {
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", s);
	}

	/* Append string to upper-level proto_items */

	if (levels > 0 && item && s && s[0]) {
		proto_item_append_text(item, ": %s", s);
		item = item->parent;
		levels--;
		if (levels > 0) {
			proto_item_append_text(item, ": %s", s);
			item = item->parent;
			levels--;
			while (levels > 0) {
				proto_item_append_text(item, " %s", s);
				item = item->parent;
				levels--;
			}
		}
	}

	/* Save string to dcv->private_data */

	if (options & CB_STR_SAVE) {
		dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
		dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
		
		dcv->private_data = g_strdup(s);
	}

	g_free(s);
}

/* Dissect a pointer to a NDR string and append the string value to the
   proto_item. */

int dissect_ndr_str_pointer_item(tvbuff_t *tvb, gint offset, 
				 packet_info *pinfo, proto_tree *tree, 
				 char *drep, int type, char *text, 
				 int hf_index, int levels)
{
	return dissect_ndr_pointer_cb(
		tvb, offset, pinfo, tree, drep, 
		dissect_ndr_wchar_cvstring, type, text, hf_index, 
		cb_wstr_postprocess, GINT_TO_POINTER(levels + 1));
}

/*
 * Register ett/hf values and perform DCERPC over SMB specific
 * initialisation.
 */
void dcerpc_smb_init(int proto_dcerpc)
{
	static hf_register_info hf[] = {

		/* String handling */

		{ &hf_nt_cs_size,
		  { "Size", "nt.str.size", FT_UINT16, BASE_DEC,
		    NULL, 0x0, "Size of string in short integers", 
		    HFILL }},
		
		{ &hf_nt_cs_len,
		  { "Length", "nt.str.len", FT_UINT16, BASE_DEC,
		    NULL, 0x0, "Length of string in short integers", 
		    HFILL }},
		
		/* Policy handles */

		{ &hf_nt_policy_open_frame,
		  { "Frame handle opened", "dcerpc.nt.open_frame",
		    FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		    "Frame handle opened", HFILL }},

		{ &hf_nt_policy_close_frame,
		  { "Frame handle closed", "dcerpc.nt.close_frame",
		    FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		    "Frame handle closed", HFILL }},
	};

	static gint *ett[] = {
		&ett_nt_unicode_string,
		&ett_nt_counted_string,
		&ett_nt_counted_byte_array,
		&ett_nt_policy_hnd,
	};

	/* Register ett's and hf's */

	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_dcerpc, hf, array_length(hf));

	/* Initialise policy handle hash */

	init_pol_hash();
}
