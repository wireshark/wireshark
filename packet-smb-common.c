/* packet-smb-common.c
 * Common routines for smb packet dissection
 * Copyright 2000, Jeffrey C. Foster <jfoste@woodward.com>
 *
 * $Id: packet-smb-common.c,v 1.5 2001/07/08 11:32:02 guy Exp $
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

int display_ms_string(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int hf_index)
{
	const char *str;
	int len;

	/* display a string from the tree and return the new offset */

	/* XXX - should use tvbuff routines to extract string length */
	str = tvb_get_ptr(tvb, offset, 1);
	len = strlen(str);
  	
	proto_tree_add_string(tree, hf_index, tvb, offset, len, str);
	
	return 	offset+len+1;
}


int display_unicode_string(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int hf_index)
{
	/* display a unicode string from the tree and return new offset */

	char Temp[100], *OutPtr;
	const char *InPtr;
	
	/* this will crash if composite tvbuffs are used */
	/* XXX - need tvbuff routine to extract DBCS string lengths */
	InPtr = tvb_get_ptr(tvb, offset, 1);
	OutPtr = Temp;			/* point to temp space */
	
	while ( *InPtr){		/* copy every other byte */ 
		*OutPtr++ = *InPtr;
		InPtr += 2;
	} 
	*OutPtr = 0;			/* terminate out string */	
	  	
	proto_tree_add_string(tree, hf_index, tvb, 
		offset, strlen(Temp)*2+2, Temp);
	
	return 	offset+strlen(Temp)*2+2;
}

int
dissect_smb_unknown(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	/* display data as unknown */

	guint len;

	len = tvb_length_remaining(tvb, offset);
  	
	proto_tree_add_text(tree, tvb, offset, len, "Data (%u bytes)", len);

	return offset+len;
}
