/* packet-dcerpc-nt.c
 * Routines for DCERPC over SMB packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-dcerpc-nt.c,v 1.1 2001/12/16 20:17:10 guy Exp $
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
#include "packet.h"
#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"
#include "smb.h"

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
				    "%s: %d", name, i);

	if (data)
		*data = i;

	return offset;
}

int prs_uint8s(tvbuff_t *tvb, int offset, packet_info *pinfo,
	       proto_tree *tree, int count, guint8 **data, char *name)
{
	const guint8 *ptr;
	
	/* No alignment required */

	ptr = tvb_get_ptr(tvb, offset, count);

	if (name && tree)
		proto_tree_add_text(tree, tvb, offset, count, "%s", name);

	if (data)
		*data = (guint8 *)ptr;

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
				    "%s: %d", name, i);
	if (data)
		*data = i;

	return offset;
}

/* Parse a number of uint16's */

int prs_uint16s(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, int count, guint16 **data, char *name)
{
	const guint8 *ptr;
	
	offset = prs_align(offset, 2);
	
	ptr = tvb_get_ptr(tvb, offset, count * 2);

	if (name && tree)
		proto_tree_add_text(tree, tvb, offset, count * 2, 
				    "%s", name);
	if (data)
		*data = (guint16 *)ptr;

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
				    "%s: %d", name, i);

	if (data)
		*data = i;

	return offset;
}

/* Parse a number of 32-bit integers */

int prs_uint32s(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, int count, guint32 **data, char *name)
{
	const guint8 *ptr;
	
	offset = prs_align(offset, 4);
	
	ptr = tvb_get_ptr(tvb, offset, count * 4);

	if (name && tree)
		proto_tree_add_text(tree, tvb, offset - 4, 4, 
				    "%s", name);
	if (data)
		*data = (guint32 *)ptr;

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

static char *fake_unicode(guint16 *data, int len)
{
	char *buffer;
	int i;

	buffer = malloc(len + 1);

	for (i = 0; i < len; i++)
		buffer[i] = data[i] & 0xff;

	buffer[len] = 0;

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
		guint16 *data16;

		offset = prs_uint16s(tvb, offset, pinfo, tree, max_len,
				     &data16, "Buffer");

		if (data)
			*data = fake_unicode(data16, max_len);
	}

	return offset;
}

/* Parse a policy handle. */

int prs_policy_hnd(tvbuff_t *tvb, int offset, packet_info *pinfo, 
		   proto_tree *tree)
{
	offset = prs_align(offset, 4);

	proto_tree_add_text(tree, tvb, offset, 20, "Policy Handle");

	return offset + 20;
}
