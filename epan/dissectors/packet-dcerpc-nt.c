/* TODO:
    dissect_ndr_nt_SID_with_options    see comment.
*/
/* packet-dcerpc-nt.c
 * Routines for DCERPC over SMB packet disassembly
 * Copyright 2001-2003, Tim Potter <tpot@samba.org>
 *
 * $Id$
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

#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/emem.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"
#include "packet-windows-common.h"

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
			      guint8 *drep, int hf_index,
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
				  guint8 *drep, int hf_index, int levels,
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
			   guint8 *drep, int hf_index, int levels)
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
			       guint8 *drep)
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
				  guint8 *drep, int hf_index,
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

static void cb_byte_array_postprocess(packet_info *pinfo, proto_tree *tree _U_,
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

	/* Get byte array value */

	if ((end_offset - start_offset) <= 12)
		return;

	s = tvb_bytes_to_str(
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
}

int
dissect_ndr_counted_byte_array(tvbuff_t *tvb, int offset,
			       packet_info *pinfo, proto_tree *tree,
			       guint8 *drep, int hf_index, int levels)
{
	return dissect_ndr_counted_byte_array_cb(
		tvb, offset, pinfo, tree, drep, hf_index, cb_byte_array_postprocess, GINT_TO_POINTER(2 + levels));
}

/* Dissect a counted ascii string in-line. */
static gint ett_nt_counted_ascii_string = -1;

int
dissect_ndr_counted_ascii_string_cb(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  guint8 *drep, int hf_index,
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

	subtree = proto_item_add_subtree(item, ett_nt_counted_ascii_string);

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
			"Ascii String", hf_index, callback, callback_args);

	return offset;
}

int
dissect_ndr_counted_ascii_string(tvbuff_t *tvb, int offset,
			       packet_info *pinfo, proto_tree *tree,
			       guint8 *drep, int hf_index, int levels)
{
	return dissect_ndr_counted_ascii_string_cb(
		tvb, offset, pinfo, tree, drep, hf_index, cb_str_postprocess, GINT_TO_POINTER(2 + levels));
}

static int hf_nt_guid = -1;

int
dissect_nt_GUID(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			guint8 *drep)
{
	offset=dissect_ndr_uuid_t(tvb, offset, pinfo, tree, drep, hf_nt_guid, NULL);

	return offset;
}

/* This function is used to dissect a DCERPC encoded 64 bit time value.
   XXX it should be fixed both here and in dissect_nt_64bit_time so
   it can handle both BIG and LITTLE endian encodings
 */
int
dissect_ndr_nt_NTTIME (tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			guint8 *drep _U_, int hf_index)
{
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	ALIGN_TO_4_BYTES;

	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_index);
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

static GHashTable *pol_hash = NULL;

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
		value = se_alloc(sizeof(pol_hash_value));
		value->list = pol;
		pol->next = NULL;
		key = se_alloc(sizeof(pol_hash_key));
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

	pol = se_alloc(sizeof(pol_value));

	pol->open_frame = is_open ? pinfo->fd->num : 0;
	pol->close_frame = is_close ? pinfo->fd->num : 0;
	pol->first_frame = pinfo->fd->num;
	pol->last_frame = pol->close_frame;	/* if 0, unknown; if non-0, known */

	pol->name = NULL;

	add_pol_handle(policy_hnd, pinfo->fd->num, pol, value);
}

/* Store a text string with a policy handle */

void dcerpc_smb_store_pol_name(e_ctx_hnd *policy_hnd, packet_info *pinfo,
			       const char *name)
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

	pol = se_alloc(sizeof(pol_value));

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
		 proto_tree *tree, guint8 *drep,
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
	       proto_tree *tree, guint8 *drep,
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

/* this function is used to dissect a "handle".
 * it will keep track of which frame a handle is opened from and in which 
 * frame it is closed.
 * normally, this function would be used for tracking 20 byte policy handles
 * as used in dcerpc  but it has shown VERY useful to also use it for tracking
 * GUIDs such as for the file ids in smb2.
 */
#define HND_TYPE_CTX_HANDLE	0
#define HND_TYPE_GUID		1
static int
dissect_nt_hnd(tvbuff_t *tvb, gint offset, packet_info *pinfo,
		      proto_tree *tree, guint8 *drep, int hfindex,
		      e_ctx_hnd *pdata, proto_item **pitem,
		      gboolean is_open, gboolean is_close, int type)
{
	proto_item *item=NULL;
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

	switch(type){
	case HND_TYPE_CTX_HANDLE:
		item = proto_tree_add_text(tree, tvb, offset, sizeof(e_ctx_hnd),
					   "Policy Handle");

		subtree = proto_item_add_subtree(item, ett_nt_policy_hnd);

		offset = dissect_ndr_ctx_hnd(tvb, offset, pinfo, subtree, drep,
					     hfindex, &hnd);
		break;
	case HND_TYPE_GUID:
		item = proto_tree_add_text(tree, tvb, offset, 16,
					   "GUID handle");

		subtree = proto_item_add_subtree(item, ett_nt_policy_hnd);

		hnd.attributes=0;
		offset=dissect_ndr_uuid_t(tvb, offset, pinfo, subtree, drep, hfindex, &hnd.uuid);
		break;
	}

	/*
	 * Create a new entry for this handle if it's not a null handle
	 * and no entry already exists, and, in any case, set the
	 * open, close, first, and last frame information as appropriate.
	 */
	dcerpc_smb_store_pol_pkts(&hnd, pinfo, is_open, is_close);

	/* Insert open/close/name information if known */

	if (dcerpc_smb_fetch_pol(&hnd, &name, &open_frame, &close_frame,
	    pinfo->fd->num)) {

		if (open_frame) {
			proto_item *item;
			item=proto_tree_add_uint(
				subtree, hf_nt_policy_open_frame, tvb,
				old_offset, sizeof(e_ctx_hnd), open_frame);
			PROTO_ITEM_SET_GENERATED(item);
		}
		if (close_frame) {
			proto_item *item;
			item=proto_tree_add_uint(
				subtree, hf_nt_policy_close_frame, tvb,
				old_offset, sizeof(e_ctx_hnd), close_frame);
			PROTO_ITEM_SET_GENERATED(item);
		}

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


int
dissect_nt_policy_hnd(tvbuff_t *tvb, gint offset, packet_info *pinfo,
		      proto_tree *tree, guint8 *drep, int hfindex,
		      e_ctx_hnd *pdata, proto_item **pitem,
		      gboolean is_open, gboolean is_close)
{
	offset=dissect_nt_hnd(tvb, offset, pinfo,
		      tree, drep, hfindex,
		      pdata, pitem,
		      is_open, is_close, HND_TYPE_CTX_HANDLE);

	return offset;
}

/* this function must be called with   hfindex being HF_GUID */
int
dissect_nt_guid_hnd(tvbuff_t *tvb, gint offset, packet_info *pinfo,
		      proto_tree *tree, guint8 *drep, int hfindex,
		      e_ctx_hnd *pdata, proto_item **pitem,
		      gboolean is_open, gboolean is_close)
{
	offset=dissect_nt_hnd(tvb, offset, pinfo,
		      tree, drep, hfindex,
		      pdata, pitem,
		      is_open, is_close, HND_TYPE_GUID);

	return offset;
}

/* Some helper routines to dissect a range of uint8 characters.  I don't
   think these are "official" NDR representations and are probably specific
   to NT so for the moment they're put here instead of in packet-dcerpc.c
   and packet-dcerpc-ndr.c. */

int
dissect_dcerpc_uint8s(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_,
                      proto_tree *tree, guint8 *drep, int hfindex,
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
                   proto_tree *tree, guint8 *drep,
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
                      proto_tree *tree, guint8 *drep, int hfindex,
		      int length)
{
    if (tree) {
        proto_tree_add_item (tree, hfindex, tvb, offset, length * 2, (drep[0] & 0x10));
    }

    return offset + length * 2;
}

int
dissect_ndr_uint16s(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                   proto_tree *tree, guint8 *drep,
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
	s = tvb_get_ephemeral_faked_unicode(
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

/* FIXME EPHEMERAL need to get rid of the g_strdup() and later g_free() */
		dcv->private_data = g_strdup(s);
	}
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
	s = tvb_get_ephemeral_string(
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
}

/* Dissect a pointer to a NDR string and append the string value to the
   proto_item. */

int dissect_ndr_str_pointer_item(tvbuff_t *tvb, gint offset,
				 packet_info *pinfo, proto_tree *tree,
				 guint8 *drep, int type, const char *text,
				 int hf_index, int levels)
{
	return dissect_ndr_pointer_cb(
		tvb, offset, pinfo, tree, drep,
		dissect_ndr_wchar_cvstring, type, text, hf_index,
		cb_wstr_postprocess, GINT_TO_POINTER(levels + 1));
}

/* SID dissection routines */

static int hf_nt_count = -1;
static int hf_nt_domain_sid = -1;

int
dissect_ndr_nt_SID(tvbuff_t *tvb, int offset, packet_info *pinfo,
		   proto_tree *tree, guint8 *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	char *sid_str=NULL;
	const char *name;

	if(di->hf_index!=-1){
		name=proto_registrar_get_name(di->hf_index);
	} else {
		name="Domain";
	}
	if(di->conformant_run){
		/* just a run to handle conformant arrays, no scalars to dissect */
		return offset;
	}

	/* the SID contains a conformant array, first we must eat
	   the 4-byte max_count before we can hand it off */

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_nt_count, NULL);

	offset = dissect_nt_sid(tvb, offset, tree, name, &sid_str,
				hf_nt_domain_sid);

	/* dcv can be null, for example when this ndr structure is embedded
	 * inside non-dcerpc pdus, i.e. kerberos PAC structure
	 */
	if(dcv){
		dcv->private_data = sid_str;
	}

	return offset;
}

/* same as dissect_ndr_nt_SID() but takes the same options as counted strings
   do to prettify the dissect pane and the COL_INFO summary line
*/
int
dissect_ndr_nt_SID_with_options(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep, guint32 options)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	gint levels = CB_STR_ITEM_LEVELS(options);
	offset=dissect_ndr_nt_SID(tvb, offset, pinfo, tree, drep);

	if(dcv && dcv->private_data){
		char *s=dcv->private_data;
		proto_item *item=(proto_item *)tree;

		if ((options & CB_STR_COL_INFO)&&(!di->conformant_run)) {
			/* kludge, ugly,   but this is called twice for all
			   dcerpc interfaces due to how we chase pointers
			   and putting the sid twice on the summary line
			   looks even worse.
			   Real solution would be to block updates to col_info
			   while we just do a conformance run,   this might
			   have sideeffects so it needs some more thoughts first.
			*/
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
	}

	return offset;
}

static int
dissect_ndr_nt_SID_hf_through_ptr(tvbuff_t *tvb, int offset, packet_info *pinfo,
		   proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_nt_SID(tvb, offset, pinfo, tree, drep);

	return offset;
}

static gint ett_nt_sid_pointer = -1;

int
dissect_ndr_nt_PSID(tvbuff_t *tvb, int offset,
		    packet_info *pinfo, proto_tree *parent_tree,
		    guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"SID pointer:");
		tree = proto_item_add_subtree(item, ett_nt_sid_pointer);
	}

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_nt_SID_hf_through_ptr, NDR_POINTER_UNIQUE,
			"SID pointer", hf_nt_domain_sid);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static const true_false_string tfs_nt_acb_disabled = {
	"Account is DISABLED",
	"Account is NOT disabled"
};
static const true_false_string tfs_nt_acb_homedirreq = {
	"Homedir is REQUIRED",
	"Homedir is NOT required"
};
static const true_false_string tfs_nt_acb_pwnotreq = {
	"Password is NOT required",
	"Password is REQUIRED"
};
static const true_false_string tfs_nt_acb_tempdup = {
	"This is a TEMPORARY DUPLICATE account",
	"This is NOT a temporary duplicate account"
};
static const true_false_string tfs_nt_acb_normal = {
	"This is a NORMAL USER account",
	"This is NOT a normal user account"
};
static const true_false_string tfs_nt_acb_mns = {
	"This is a MNS account",
	"This is NOT a mns account"
};
static const true_false_string tfs_nt_acb_domtrust = {
	"This is a DOMAIN TRUST account",
	"This is NOT a domain trust account"
};
static const true_false_string tfs_nt_acb_wstrust = {
	"This is a WORKSTATION TRUST account",
	"This is NOT a workstation trust account"
};
static const true_false_string tfs_nt_acb_svrtrust = {
	"This is a SERVER TRUST account",
	"This is NOT a server trust account"
};
static const true_false_string tfs_nt_acb_pwnoexp = {
	"Passwords does NOT expire",
	"Password will EXPIRE"
};
static const true_false_string tfs_nt_acb_autolock = {
	"This account has been AUTO LOCKED",
	"This account has NOT been auto locked"
};

static gint ett_nt_acct_ctrl = -1;

static int hf_nt_acct_ctrl = -1;
static int hf_nt_acb_disabled = -1;
static int hf_nt_acb_homedirreq = -1;
static int hf_nt_acb_pwnotreq = -1;
static int hf_nt_acb_tempdup = -1;
static int hf_nt_acb_normal = -1;
static int hf_nt_acb_mns = -1;
static int hf_nt_acb_domtrust = -1;
static int hf_nt_acb_wstrust = -1;
static int hf_nt_acb_svrtrust = -1;
static int hf_nt_acb_pwnoexp = -1;
static int hf_nt_acb_autolock = -1;

int
dissect_ndr_nt_acct_ctrl(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *parent_tree, guint8 *drep)
{
	guint32 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	offset=dissect_ndr_uint32(tvb, offset, pinfo, NULL, drep,
			hf_nt_acct_ctrl, &mask);

	if(parent_tree){
		item = proto_tree_add_uint(parent_tree, hf_nt_acct_ctrl,
			tvb, offset-4, 4, mask);
		tree = proto_item_add_subtree(item, ett_nt_acct_ctrl);
	}

	proto_tree_add_boolean(tree, hf_nt_acb_autolock,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_nt_acb_pwnoexp,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_nt_acb_svrtrust,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_nt_acb_wstrust,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_nt_acb_domtrust,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_nt_acb_mns,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_nt_acb_normal,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_nt_acb_tempdup,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_nt_acb_pwnotreq,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_nt_acb_homedirreq,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_nt_acb_disabled,
		tvb, offset-4, 4, mask);

	return offset;
}

static int hf_logonhours_unknown_char;

static int
dissect_LOGON_HOURS_entry(tvbuff_t *tvb, int offset,
			  packet_info *pinfo, proto_tree *tree,
			  guint8 *drep)
{
	offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep,
			hf_logonhours_unknown_char, NULL);
	return offset;
}

static gint ett_nt_logon_hours_hours = -1;

static int
dissect_LOGON_HOURS_hours(tvbuff_t *tvb, int offset,
			  packet_info *pinfo, proto_tree *parent_tree,
			  guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"LOGON_HOURS:");
		tree = proto_item_add_subtree(item, ett_nt_logon_hours_hours);
	}

	offset = dissect_ndr_ucvarray(tvb, offset, pinfo, tree, drep,
			dissect_LOGON_HOURS_entry);

	proto_item_set_len(item, offset-old_offset);
	return offset;

	return offset;
}

static gint ett_nt_logon_hours = -1;
static int hf_logonhours_divisions = -1;

int
dissect_ndr_nt_LOGON_HOURS(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	ALIGN_TO_4_BYTES;  /* strcture starts with short, but is aligned for longs */

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"LOGON_HOURS:");
		tree = proto_item_add_subtree(item, ett_nt_logon_hours);
	}

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
				hf_logonhours_divisions, NULL);
	/* XXX - is this a bitmask like the "logon hours" field in the
	   Remote API call "NetUserGetInfo()" with an information level
	   of 11? */
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_LOGON_HOURS_hours, NDR_POINTER_UNIQUE,
			"LOGON_HOURS", -1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
dissect_ndr_nt_PSID_no_hf(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *parent_tree,
                             guint8 *drep)
{
	offset=dissect_ndr_nt_PSID(tvb, offset, pinfo, parent_tree, drep);
	return offset;
}

static int
dissect_ndr_nt_PSID_ARRAY_sids (tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			dissect_ndr_nt_PSID_no_hf);

	return offset;
}

static gint ett_nt_sid_array = -1;

int
dissect_ndr_nt_PSID_ARRAY(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	guint32 count;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"SID array:");
		tree = proto_item_add_subtree(item, ett_nt_sid_array);
	}

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_nt_count, &count);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_nt_PSID_ARRAY_sids, NDR_POINTER_UNIQUE,
			"PSID_ARRAY", -1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static gint ett_nt_sid_and_attributes = -1;
static int hf_nt_attrib = -1;

int
dissect_ndr_nt_SID_AND_ATTRIBUTES(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"SID_AND_ATTRIBUTES:");
		tree = proto_item_add_subtree(item, ett_nt_sid_and_attributes);
	}

	offset = dissect_ndr_nt_PSID(tvb, offset, pinfo, tree, drep);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_nt_attrib, NULL);

	return offset;
}

static gint ett_nt_sid_and_attributes_array = -1;

int
dissect_ndr_nt_SID_AND_ATTRIBUTES_ARRAY(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"SID_AND_ATTRIBUTES array:");
		tree = proto_item_add_subtree(item, ett_nt_sid_and_attributes_array);
	}

	/*offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
	  hf_samr_count, &count); */
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			dissect_ndr_nt_SID_AND_ATTRIBUTES);

	proto_item_set_len(item, offset-old_offset);
	return offset;
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

		/* GUIDs */
		{ &hf_nt_guid,
		  { "GUID", "nt.guid", FT_STRING, BASE_NONE,
		    NULL, 0x0, "GUID (uuid for groups?)", HFILL }},

		/* Policy handles */

		{ &hf_nt_policy_open_frame,
		  { "Frame handle opened", "dcerpc.nt.open_frame",
		    FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		    "Frame handle opened", HFILL }},

		{ &hf_nt_policy_close_frame,
		  { "Frame handle closed", "dcerpc.nt.close_frame",
		    FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		    "Frame handle closed", HFILL }},

		/* ACBs */

		{ &hf_nt_acct_ctrl,
		  { "Acct Ctrl", "nt.acct_ctrl", FT_UINT32, BASE_HEX,
		    NULL, 0x0, "Acct CTRL", HFILL }},

		{ &hf_nt_acb_disabled,
		  { "", "nt.acb.disabled", FT_BOOLEAN, 32,
		    TFS(&tfs_nt_acb_disabled), 0x0001,
		    "If this account is enabled or disabled", HFILL }},

		{ &hf_nt_acb_homedirreq,
		  { "", "nt.acb.homedirreq", FT_BOOLEAN, 32,
		    TFS(&tfs_nt_acb_homedirreq), 0x0002,
		    "Is hom,edirs required for this account?", HFILL }},

		{ &hf_nt_acb_pwnotreq,
		  { "", "nt.acb.pwnotreq", FT_BOOLEAN, 32,
		    TFS(&tfs_nt_acb_pwnotreq), 0x0004,
		    "If a password is required for this account?", HFILL }},

		{ &hf_nt_acb_tempdup,
		  { "", "nt.acb.tempdup", FT_BOOLEAN, 32,
		    TFS(&tfs_nt_acb_tempdup), 0x0008,
		    "If this is a temporary duplicate account", HFILL }},

		{ &hf_nt_acb_normal,
		  { "", "nt.acb.normal", FT_BOOLEAN, 32,
		    TFS(&tfs_nt_acb_normal), 0x0010,
		    "If this is a normal user account", HFILL }},

		{ &hf_nt_acb_mns,
		  { "", "nt.acb.mns", FT_BOOLEAN, 32,
		    TFS(&tfs_nt_acb_mns), 0x0020,
		    "MNS logon user account", HFILL }},

		{ &hf_nt_acb_domtrust,
		  { "", "nt.acb.domtrust", FT_BOOLEAN, 32,
		    TFS(&tfs_nt_acb_domtrust), 0x0040,
		    "Interdomain trust account", HFILL }},

		{ &hf_nt_acb_wstrust,
		  { "", "nt.acb.wstrust", FT_BOOLEAN, 32,
		    TFS(&tfs_nt_acb_wstrust), 0x0080,
		    "Workstation trust account", HFILL }},

		{ &hf_nt_acb_svrtrust,
		  { "", "nt.acb.svrtrust", FT_BOOLEAN, 32,
		    TFS(&tfs_nt_acb_svrtrust), 0x0100,
		    "Server trust account", HFILL }},

		{ &hf_nt_acb_pwnoexp,
		  { "", "nt.acb.pwnoexp", FT_BOOLEAN, 32,
		    TFS(&tfs_nt_acb_pwnoexp), 0x0200,
		    "If this account expires or not", HFILL }},

		{ &hf_nt_acb_autolock,
		  { "", "nt.acb.autolock", FT_BOOLEAN, 32,
		    TFS(&tfs_nt_acb_autolock), 0x0400,
		    "If this account has been autolocked", HFILL }},

		/* SIDs */

		{ &hf_nt_domain_sid,
		  { "Domain SID", "nt.domain_sid",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "The Domain SID", HFILL }},

		{ &hf_nt_count,
		  { "Count", "nt.count",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Number of elements in following array", HFILL }},

		/* Logon hours */

		{ &hf_logonhours_divisions,
		  { "Divisions", "logonhours.divisions",
		    FT_UINT16, BASE_DEC, NULL, 0,
		    "Number of divisions for LOGON_HOURS", HFILL }},

		{ &hf_logonhours_unknown_char,
		  { "Unknown char", "nt.unknown.char",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    "Unknown char. If you know what this is, contact "
		    "ethereal developers.", HFILL }},

		/* Misc */

                { &hf_nt_attrib,
		  { "Attributes", "nt.attr",
		    FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
	};

	static gint *ett[] = {
		&ett_nt_unicode_string,
		&ett_nt_counted_string,
		&ett_nt_counted_byte_array,
		&ett_nt_policy_hnd,
                &ett_nt_sid_pointer,
                &ett_nt_acct_ctrl,
                &ett_nt_logon_hours,
                &ett_nt_logon_hours_hours,
                &ett_nt_sid_array,
                &ett_nt_sid_and_attributes_array,
                &ett_nt_sid_and_attributes,
		&ett_nt_counted_ascii_string,
	};

	/* Register ett's and hf's */

	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_dcerpc, hf, array_length(hf));

	/* Initialise policy handle hash */

	register_init_routine(&init_pol_hash);
}
