/* packet-dcerpc-nt.c
 * Routines for DCERPC over SMB packet disassembly
 * Copyright 2001-2003, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-dcerpc-nt.c,v 1.67 2003/02/08 09:41:44 guy Exp $
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
		cb_str_postprocess, GINT_TO_POINTER(2 + levels));
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
dissect_ndr_counted_byte_array(tvbuff_t *tvb, int offset,
			       packet_info *pinfo, proto_tree *tree,
			       char *drep, int hf_index)
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

	offset = dissect_ndr_pointer(tvb, offset, pinfo, subtree, drep,
			dissect_ndr_char_cvstring, NDR_POINTER_UNIQUE,
			"Byte Array", hf_index);

	return offset;
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
 * Policy handle hashing
 */

typedef struct {
	guint8 policy_hnd[20];
} pol_hash_key;

typedef struct {
	guint32 open_frame, close_frame; /* Frame numbers for open/close */
	char *name;			 /* Name of policy handle */
} pol_hash_value;

#define POL_HASH_INIT_COUNT 100

static GHashTable *pol_hash;
static GMemChunk *pol_hash_key_chunk;
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

/* Store the open and close frame numbers of a policy handle */

void dcerpc_smb_store_pol_pkts(e_ctx_hnd *policy_hnd, guint32 open_frame,
			       guint32 close_frame)
{
	pol_hash_key *key;
	pol_hash_value *value;

	if (is_null_pol(policy_hnd) || (open_frame == 0 && close_frame == 0))
		return;

	/* Look up existing value */

	key = g_mem_chunk_alloc(pol_hash_key_chunk);

	memcpy(&key->policy_hnd, policy_hnd, sizeof(key->policy_hnd));

	if ((value = g_hash_table_lookup(pol_hash, key))) {

		/* Update existing value */

		if (open_frame) {
#ifdef DEBUG_HASH_COLL
			if (value->open_frame != open_frame)
				g_warning("dcerpc_smb: pol_hash open frame collision %d/%d\n", value->open_frame, open_frame);
#endif
			value->open_frame = open_frame;
		}

		if (close_frame) {
#ifdef DEBUG_HASH_COLL
			if (value->close_frame != close_frame)
				g_warning("dcerpc_smb: pol_hash close frame collision %d/%d\n", value->close_frame, close_frame);
#endif
			value->close_frame = close_frame;
		}

		return;
	}

	/* Create a new value */

	value = g_mem_chunk_alloc(pol_hash_value_chunk);

	value->open_frame = open_frame;
	value->close_frame = close_frame;

	value->name = NULL;

	g_hash_table_insert(pol_hash, key, value);
}

/* Store a text string with a policy handle */

void dcerpc_smb_store_pol_name(e_ctx_hnd *policy_hnd, char *name)
{
	pol_hash_key *key;
	pol_hash_value *value;

	if (is_null_pol(policy_hnd))
		return;

	/* Look up existing value */

	key = g_mem_chunk_alloc(pol_hash_key_chunk);

	memcpy(&key->policy_hnd, policy_hnd, sizeof(key->policy_hnd));

	if ((value = g_hash_table_lookup(pol_hash, key))) {

		/* Update existing value */

		if (value->name && name) {
#ifdef DEBUG_HASH_COLL
			if (strcmp(value->name, name) != 0)
				g_warning("dcerpc_smb: pol_hash name collision %s/%s\n", value->name, name);
#endif
			free(value->name);
		}

		value->name = strdup(name);

		return;
	}

	/* Create a new value */

	value = g_mem_chunk_alloc(pol_hash_value_chunk);

	value->open_frame = 0;
	value->close_frame = 0;

	if (name)
		value->name = strdup(name);
	else
		value->name = strdup("<UNKNOWN>");

	g_hash_table_insert(pol_hash, key, value);
}

/* Retrieve a policy handle */

gboolean dcerpc_smb_fetch_pol(e_ctx_hnd *policy_hnd, char **name,
			      guint32 *open_frame, guint32 *close_frame)
{
	pol_hash_key key;
	pol_hash_value *value;

	/* Prevent uninitialised return vars */

	if (name)
		*name = NULL;

	if (open_frame)
		*open_frame = 0;

	if (close_frame)
		*close_frame = 0;

	/* Look up existing value */

	memcpy(&key.policy_hnd, policy_hnd, sizeof(key.policy_hnd));

	value = g_hash_table_lookup(pol_hash, &key);

	/* Return name and frame numbers */

	if (value) {
		if (name)
			*name = value->name;

		if (open_frame)
			*open_frame = value->open_frame;

		if (close_frame)
			*close_frame = value->close_frame;
	}

	return value != NULL;
}

/* Iterator to free a policy handle key/value pair */

static void free_pol_keyvalue(gpointer key _U_, gpointer value,
    gpointer user_data _U_)
{
	pol_hash_value *pol_value = (pol_hash_value *)value;

	/* Free user data */

	if (pol_value->name) {
		free(pol_value->name);
		pol_value->name = NULL;
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

/* Check if there is unparsed data remaining in a frame and display an
   error.  I guess this could be made into an exception like the malformed
   frame exception.  For the DCERPC over SMB dissectors a long frame
   indicates a bug in a dissector. */

void dcerpc_smb_check_long_frame(tvbuff_t *tvb, int offset,
				 packet_info *pinfo, proto_tree *tree)
{
	if (tvb_length_remaining(tvb, offset) != 0) {

		proto_tree_add_text(
			tree, tvb, offset, tvb_length_remaining(tvb, offset),
			"[Long frame (%d bytes): SPOOLSS]",
			tvb_length_remaining(tvb, offset));

		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO,
					"[Long frame (%d bytes): SPOOLSS]",
					tvb_length_remaining(tvb, offset));
	}
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
		      e_ctx_hnd *pdata, gboolean is_open, gboolean is_close)
{
	proto_item *item;
	proto_tree *subtree;
	e_ctx_hnd hnd;
	guint32 open_frame = 0, close_frame = 0;
	char *name;
	int old_offset = offset;

	/* Add to proto tree */

	item = proto_tree_add_text(tree, tvb, offset, sizeof(e_ctx_hnd),
				   "Policy Handle");

	subtree = proto_item_add_subtree(item, ett_nt_policy_hnd);

	offset = dissect_ndr_ctx_hnd(tvb, offset, pinfo, subtree, drep,
				     hfindex, &hnd);

	/* Store request/reply information */

	dcerpc_smb_store_pol_pkts(&hnd, 0, is_close ? pinfo->fd->num : 0);
	dcerpc_smb_store_pol_pkts(&hnd, is_open ? pinfo->fd->num: 0, 0);

	/* Insert request/reply information if known */

	if (dcerpc_smb_fetch_pol(&hnd, &name, &open_frame, &close_frame)) {

		if (open_frame)
			proto_tree_add_uint(
				subtree, hf_nt_policy_open_frame, tvb,
				old_offset, sizeof(e_ctx_hnd), open_frame);

		if (close_frame)
			proto_tree_add_uint(
				subtree, hf_nt_policy_close_frame, tvb,
				old_offset, sizeof(e_ctx_hnd), close_frame);

		if (name != NULL)
			proto_item_append_text(item, ": %s", name);
	}

	if (pdata)
		*pdata = hnd;

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

	s = fake_unicode(
		tvb, start_offset + 12, (end_offset - start_offset - 12) / 2);

	/* Append string to COL_INFO */

	if (options & CB_STR_COL_INFO) {
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", s);
	}

	/* Append string to upper-level proto_items */
	if (levels > 0 && item) {
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
		cb_str_postprocess, GINT_TO_POINTER(levels + 1));
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
		  { "Frame handle close", "dcerpc.nt.close_frame",
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
