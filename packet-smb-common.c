/* packet-smb-common.c
 * Common routines for smb packet dissection
 * Copyright 2000, Jeffrey C. Foster <jfoste@woodward.com>
 *
 * $Id: packet-smb-common.c,v 1.12 2002/06/16 00:39:30 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c
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

#include "packet-smb-common.h"

/*
 * Share type values - used in LANMAN and in SRVSVC.
 *
 * XXX - should we dissect share type values, at least in SRVSVC, as
 * a subtree with bitfields, as the 0x80000000 bit appears to be a
 * hidden bit, with some number of bits at the bottom being the share
 * type?
 *
 * Does LANMAN use that bit?
 */
const value_string share_type_vals[] = {
	{0, "Directory tree"},
	{1, "Printer queue"},
	{2, "Communications device"},
	{3, "IPC"},
	{0x80000000, "Hidden Directory tree"},
	{0x80000001, "Hidden Printer queue"},
	{0x80000002, "Hidden Communications device"},
	{0x80000003, "Hidden IPC"},
	{0, NULL}
};

int display_ms_string(tvbuff_t *tvb, proto_tree *tree, int offset, int hf_index)
{
	char *str;
	int len;

	/* display a string from the tree and return the new offset */

	len = tvb_strnlen(tvb, offset, -1);
	if (len == -1) {
		/*
		 * XXX - throw an exception?
		 */
		len = tvb_length_remaining(tvb, offset);
	}
	str = g_malloc(len+1);
	tvb_memcpy(tvb, (guint8 *)str, offset, len);
	str[len] = '\0';
  	
	proto_tree_add_string(tree, hf_index, tvb, offset, len+1, str);
	
	/*
	 * XXX - "proto_tree_add_string()" mallocates a copy; it'd
	 * be nice not to have it copy the string, but just to
	 * make it the value, avoiding both the copy and the free
	 * on the next line.
	 */
	g_free(str);

	return 	offset+len+1;
}


int display_unicode_string(tvbuff_t *tvb, proto_tree *tree, int offset, int hf_index)
{
	char *str, *p;
	int len;
	int charoffset;
	guint16 character;

	/* display a unicode string from the tree and return new offset */

	/*
	 * Get the length of the string.
	 * XXX - is it a bug or a feature that this will throw an exception
	 * if we don't find the '\0'?  I think it's a feature.
	 */
	len = 0;
	while ((character = tvb_get_letohs(tvb, offset + len)) != '\0')
		len += 2;
	len += 2;	/* count the '\0' too */

	/*
	 * Allocate a buffer for the string; "len" is the length in
	 * bytes, not the length in characters.
	 */
	str = g_malloc(len/2);

	/*
	 * XXX - this assumes the string is just ISO 8859-1; we need
	 * to better handle multiple character sets in Ethereal,
	 * including Unicode/ISO 10646, and multiple encodings of
	 * that character set (UCS-2, UTF-8, etc.).
	 */
	charoffset = offset;
	p = str;
	while ((character = tvb_get_letohs(tvb, charoffset)) != '\0') {
		*p++ = character;
		charoffset += 2;
	}
	*p = '\0';
	  	
	proto_tree_add_string(tree, hf_index, tvb, offset, len, str);

	g_free(str);
	
	return 	offset+len;
}

int
dissect_smb_unknown(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	/* display data as unknown */

	proto_tree_add_text(tree, tvb, offset, -1, "Data (%u bytes)",
	    tvb_reported_length_remaining(tvb, offset));

	return offset+tvb_length_remaining(tvb, offset);
}
