/* packet-dcerpc-nt.c
 * Routines for DCERPC over SMB packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-dcerpc-nt.c,v 1.19 2002/03/19 22:09:23 guy Exp $
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

/* Align offset to a n-byte boundary */

int prs_align(int offset, int n)
{
	if (offset % n)
		offset += n - (offset % n);
	
	return offset;
}

/* Parse a 8-bit integer */

int prs_uint8(tvbuff_t *tvb, int offset, packet_info *pinfo,
	      proto_tree *tree, guint8 *data, char *name)
{
	guint8 i;
	
	/* No alignment required */

	i = tvb_get_guint8(tvb, offset);
	offset++;

	if (name && tree)
		proto_tree_add_text(tree, tvb, offset - 1, 1, 
				    "%s: %u", name, i);

	if (data)
		*data = i;

	return offset;
}

int prs_uint8s(tvbuff_t *tvb, int offset, packet_info *pinfo,
	       proto_tree *tree, int count, int *data_offset, char *name)
{
	/* No alignment required */

	if (name && tree)
		proto_tree_add_text(tree, tvb, offset, count, "%s", name);

	if (data_offset)
		*data_offset = offset;

	offset += count;

	return offset;
}

/* Parse a 16-bit integer */

int prs_uint16(tvbuff_t *tvb, int offset, packet_info *pinfo,
	       proto_tree *tree, guint16 *data, char *name)
{
	guint16 i;
	
	offset = prs_align(offset, 2);
	
	i = tvb_get_letohs(tvb, offset);
	offset += 2;

	if (name && tree)
		proto_tree_add_text(tree, tvb, offset - 2, 2, 
				    "%s: %u", name, i);
	if (data)
		*data = i;

	return offset;
}

/* Parse a number of uint16's */

int prs_uint16s(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, int count, int *data_offset, char *name)
{
	offset = prs_align(offset, 2);
	
	if (name && tree)
		proto_tree_add_text(tree, tvb, offset, count * 2, 
				    "%s", name);
	if (data_offset)
		*data_offset = offset;

	offset += count * 2;

	return offset;
}

/* Parse a 32-bit integer */

int prs_uint32(tvbuff_t *tvb, int offset, packet_info *pinfo,
	       proto_tree *tree, guint32 *data, char *name)
{
	guint32 i;
	
	offset = prs_align(offset, 4);
	
	i = tvb_get_letohl(tvb, offset);
	offset += 4;

	if (name && tree)
		proto_tree_add_text(tree, tvb, offset - 4, 4, 
				    "%s: %u", name, i);

	if (data)
		*data = i;

	return offset;
}

/* Parse a number of 32-bit integers */

int prs_uint32s(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, int count, int *data_offset, char *name)
{
	offset = prs_align(offset, 4);
	
	if (name && tree)
		proto_tree_add_text(tree, tvb, offset - 4, 4, 
				    "%s", name);
	if (data_offset)
		*data_offset = offset;

	offset += count * 4;

	return offset;
}

/* Parse a NT status code */

int prs_ntstatus(tvbuff_t *tvb, int offset, packet_info *pinfo,
		 proto_tree *tree)
{
	guint32 status;

	offset = prs_uint32(tvb, offset, pinfo, tree, &status, NULL);

	if (tree)
		proto_tree_add_text(tree, tvb, offset - 4, 4, "Status: %s",
				    val_to_str(status, NT_errors, "???"));

	return offset;
}

/*
 * We need to keep track of deferred referrents as they appear in the
 * packet after all the non-pointer objects.
 * to keep track of pointers as they are parsed as scalars and need to be
 * remembered for the next call to the prs function.
 *
 * Pointers are stored in a linked list and pushed in the PARSE_SCALARS
 * section of the prs function and popped in the PARSE_BUFFERS section.  If
 * we try to pop off a referrent that has a different name then we are
 * expecting then something has gone wrong.
 */

#undef DEBUG_PTRS

struct ptr {
	char *name;
	guint32 value;
};

/* Create a new pointer */

static struct ptr *new_ptr(char *name, guint32 value)
{
	struct ptr *p;

	p = g_malloc(sizeof(struct ptr));

	p->name = g_strdup(name);
	p->value = value;

	return p;
}

/* Free a pointer */

static void free_ptr(struct ptr *p)
{
	if (p) {
		g_free(p->name);
		g_free(p);
	}
}

/* Parse a pointer and store it's value in a linked list */

int prs_push_ptr(tvbuff_t *tvb, int offset, packet_info *pinfo,
		 proto_tree *tree, GList **ptr_list, char *name)
{
	struct ptr *p;
	guint32 value;

	offset = prs_uint32(tvb, offset, pinfo, tree, &value, NULL);

	if (name && tree)
		proto_tree_add_text(tree, tvb, offset - 4, 4, 
				    "%s pointer: 0x%08x", name, value);

	p = new_ptr(name, value);

	*ptr_list = g_list_append(*ptr_list, p);

#ifdef DEBUG_PTRS
	fprintf(stderr, "DEBUG_PTRS: pushing %s ptr = 0x%08x, %d ptrs in "
		"list\n", name, value, g_list_length(*ptr_list));
#endif

	return offset;
}

/* Pop a pointer of a given name.  Return it's value. */

guint32 prs_pop_ptr(GList **ptr_list, char *name)
{
	GList *elt;
	struct ptr *p;
	guint32 result;

	g_assert(g_list_length(*ptr_list) != 0);	/* List too short */

	/* Get pointer at head of list */

	elt = g_list_first(*ptr_list);
	p = (struct ptr *)elt->data;
	result = p->value;

#ifdef DEBUG_PTRS
	if (strcmp(p->name, name) != 0) {
		fprintf(stderr, "DEBUG_PTRS: wrong pointer (%s != %s)\n",
			p->name, name);
	}
#endif

	/* Free pointer record */

	*ptr_list = g_list_remove_link(*ptr_list, elt);

#ifdef DEBUG_PTRS
	fprintf(stderr, "DEBUG_PTRS: popping %s ptr = 0x%08x, %d ptrs in "
		"list\n", p->name, p->value, g_list_length(*ptr_list));
#endif

	free_ptr(p);

	return result;
}

/*
 * Parse a UNISTR2 structure 
 *
 * typedef struct {
 *   short length;
 *   short size;
 *   [size_is(size/2)] [length_is(length/2)] [unique] wchar_t *string;
 * } UNICODE_STRING;
 *
 */

/* Convert a string from little-endian unicode to ascii.  At the moment we
   fake it by taking every odd byte.  )-:  The caller must free the
   result returned. */

char *fake_unicode(tvbuff_t *tvb, int offset, int len)
{
	char *buffer;
	int i;
	guint16 character;

	buffer = g_malloc(len + 1);

	/*
	 * Register a cleanup function in case on of our tvbuff accesses
	 * throws an exception. We need to clean up buffer.
	 */
	CLEANUP_PUSH(g_free, buffer);

	for (i = 0; i < len; i++) {
		character = tvb_get_letohs(tvb, offset);
		buffer[i] = character & 0xff;
		offset += 2;
	}

	buffer[len] = 0;

	/*
	 * Pop the cleanup function, but don't free the buffer.
	 */
	CLEANUP_POP;

	return buffer;
}

/* Parse a UNISTR2 structure */

int prs_UNISTR2(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, int flags, char **data, char *name)
{
	guint32 len = 0, unknown = 0, max_len = 0;

	if (flags & PARSE_SCALARS) {
		offset = prs_uint32(tvb, offset, pinfo, tree, &len, "Length");
		offset = prs_uint32(tvb, offset, pinfo, tree, &unknown, 
				    "Offset");
		offset = prs_uint32(tvb, offset, pinfo, tree, &max_len, 
				    "Max length");
	}

	if (flags & PARSE_BUFFERS) {
		int data16_offset;

		offset = prs_uint16s(tvb, offset, pinfo, tree, max_len,
				     &data16_offset, "Buffer");

		if (data)
			*data = fake_unicode(tvb, data16_offset, max_len);
	}

	return offset;
}

/* Parse a policy handle. */

int prs_policy_hnd(tvbuff_t *tvb, int offset, packet_info *pinfo, 
		   proto_tree *tree, const guint8 **data)
{
	const guint8 *data8;

	offset = prs_align(offset, 4);

	proto_tree_add_text(tree, tvb, offset, 20, "Policy Handle: %s", 
                tvb_bytes_to_str(tvb, offset, 20));

	data8 = tvb_get_ptr(tvb, offset, 20);
	
	if (data)
		*data = data8;

	return offset + 20;
}



/* following are a few functions for dissecting common structures used by NT 
   services. These might need to be cleaned up at a later time but at least we get
   them out of the real service dissectors.
*/


/* UNICODE_STRING  BEGIN */
/* functions to dissect a UNICODE_STRING structure, common to many 
   NT services
   struct {
     short len;
     short size;
     [size_is(size/2), length_is(len/2), ptr] unsigned short *string;
   } UNICODE_STRING;

   these variables can be found in packet-dcerpc-samr.c 
*/
extern int hf_nt_str_len;
extern int hf_nt_str_off;
extern int hf_nt_str_max_len;
extern int hf_nt_string_length;
extern int hf_nt_string_size;
extern gint ett_nt_unicode_string;


/* this function will dissect the
     [size_is(size/2), length_is(len/2), ptr] unsigned short *string;
  part of the unicode string

   struct {
     short len;
     short size;
     [size_is(size/2), length_is(len/2), ptr] unsigned short *string;
   } UNICODE_STRING;
  structure used by NT to transmit unicode string values.

  This function also looks at di->levels to see if whoever called us wanted us to append
  the name: string to any higher levels in the tree .
*/
int
dissect_ndr_nt_UNICODE_STRING_str(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree, 
			char *drep)
{
	guint32 len, off, max_len;
	int data16_offset;
	char *text;
	int old_offset;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_nt_str_len, &len);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_nt_str_off, &off);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_nt_str_max_len, &max_len);

	old_offset=offset;
	offset = prs_uint16s(tvb, offset, pinfo, tree, max_len, &data16_offset,
			NULL);
	text = fake_unicode(tvb, data16_offset, max_len);

	proto_tree_add_string(tree, di->hf_index, tvb, old_offset,
		offset-old_offset, text);

	/* need to test di->levels before doing the proto_item_append_text()
	   since netlogon has these objects as top level objects in its representation
	   and trying to append to the tree object in that case will dump core */
	if(tree && (di->levels>-1)){
		proto_item_append_text(tree, ": %s", text);
		if(di->levels>-1){
			tree=tree->parent;
			proto_item_append_text(tree, ": %s", text);
			while(di->levels>0){
				tree=tree->parent;
				proto_item_append_text(tree, " %s", text);
				di->levels--;
			}
		}
	}
	g_free(text);
  	return offset;
}

/* this function will dissect the
   struct {
     short len;
     short size;
     [size_is(size/2), length_is(len/2), ptr] unsigned short *string;
   } UNICODE_STRING;
  structure used by NT to transmit unicode string values.
 
  the function takes one additional parameter, level
  which specifies how many additional levels up in the tree where we should
  append the string.  If unsure, specify levels as 0.
*/
int
dissect_ndr_nt_UNICODE_STRING(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree, 
			char *drep, int hf_index, int levels)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;
	dcerpc_info *di;
	char *name;

	ALIGN_TO_4_BYTES;  /* strcture starts with short, but is aligned for longs */

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	name = proto_registrar_get_name(hf_index);
	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"%s", name);
		tree = proto_item_add_subtree(item, ett_nt_unicode_string);
	}

	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
			hf_nt_string_length, NULL);
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
			hf_nt_string_size, NULL);
	di->levels=1;
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
			name, hf_index, levels);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}
/* UNICODE_STRING  END */

/* functions to dissect a STRING structure, common to many 
   NT services
   struct {
     short len;
     short size;
     [size_is(size), length_is(len), ptr] char *string;
   } STRING;
*/
int
dissect_ndr_nt_STRING_string (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
	guint32 len, off, max_len;
	int text_offset;
	const guint8 *text;
	int old_offset;
	header_field_info *hfi;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_nt_str_len, &len);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_nt_str_off, &off);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_nt_str_max_len, &max_len);

	old_offset=offset;
	hfi = proto_registrar_get_nth(di->hf_index);

	switch(hfi->type){
	case FT_STRING:
		offset = prs_uint8s(tvb, offset, pinfo, tree, max_len,
			&text_offset, NULL);
		text = tvb_get_ptr(tvb, text_offset, max_len);
		proto_tree_add_string_format(tree, di->hf_index, 
			tvb, old_offset, offset-old_offset,
			text, "%s: %s", hfi->name, text);
		break;
	case FT_BYTES:
		text = NULL;
		proto_tree_add_item(tree, di->hf_index, tvb, offset, max_len, FALSE);
		offset += max_len;
		break;
	default:
		text = NULL;
		g_assert_not_reached();
	}

	if(tree && text && (di->levels>-1)){
		proto_item_append_text(tree, ": %s", text);
		if(di->levels>-1){
			tree=tree->parent;
			proto_item_append_text(tree, ": %s", text);
			while(di->levels>0){
				tree=tree->parent;
				proto_item_append_text(tree, " %s", text);
				di->levels--;
			}
		}
	}
  	return offset;
}

int
dissect_ndr_nt_STRING (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *parent_tree, 
                             char *drep, int hf_index, int levels)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;
	dcerpc_info *di;
	char *name;

	ALIGN_TO_4_BYTES;  /* strcture starts with short, but is aligned for longs */

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	name = proto_registrar_get_name(hf_index);
	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"%s", name);
		tree = proto_item_add_subtree(item, ett_nt_unicode_string);
	}

        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_nt_string_length, NULL);
        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_nt_string_size, NULL);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_nt_STRING_string, NDR_POINTER_UNIQUE,
			name, hf_index, levels);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


/* This function is used to dissect a DCERPC encoded 64 bit time value.
   XXX it should be fixed both here and in dissect_smb_64bit_time so
   it can handle both BIG and LITTLE endian encodings 
 */
int
dissect_ndr_nt_NTTIME (tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree, 
			char *drep, int hf_index)
{
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	ALIGN_TO_4_BYTES;

	offset = dissect_smb_64bit_time(tvb, pinfo, tree, offset,
		 hf_index);
	return offset;
}

