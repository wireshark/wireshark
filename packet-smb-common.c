/* packet-smb-common.c
 * Common routines for smb packet dissection
 * Copyright 2000, Jeffrey C. Foster <jfoste@woodward.com>
 *
 * $Id: packet-smb-common.c,v 1.2 2000/02/14 04:05:53 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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



int display_ms_value( char *Name, int len, const u_char *pd, int offset,
		frame_data *fd, proto_tree *tree)

{/* display an entry from the tree and return the length */

  guint32  Temp32;
  
	if( len == 1)
  		Temp32 = GBYTE(pd, offset);
	else if( len == 2)
  		Temp32 = GSHORT(pd, offset);
	else if( len == 4)
  		Temp32 = GWORD(pd, offset);
  	
/* this is an error if we didn't hit one of those three */
  	else 
		return 0;

	proto_tree_add_text( tree, offset, len, "%s: %u", Name, Temp32);
	
	return len;
}	

int display_ms_string( char *Name, const u_char *pd, int offset,
		frame_data *fd, proto_tree *tree)

{/* display a string from the tree and return the amount to move offset */
  	
	proto_tree_add_text( tree, offset, strlen( &pd[offset]) + 1, "%s: %s ",
			Name, &pd[offset]);
	
	return 	strlen( &pd[offset]) + 1;
}


int display_unicode_string( char *Name, const u_char *pd, int offset,
		frame_data *fd, proto_tree *tree){

/* display a unicode string from the tree and return amount to move offset */

	char Temp[100], *OutPtr;
	const char *InPtr;
	
	InPtr = &pd[ offset];		/* point to unicode string */
	OutPtr = Temp;			/* point to temp space */
	
	while ( *InPtr){		/* copy every other byte */ 
		*OutPtr++ = *InPtr;
		InPtr += 2;
	} 
	*OutPtr = 0;			/* terminate out string */	
	  	
	proto_tree_add_text( tree, offset, strlen( Temp) * 2 + 2, "%s: %s ",
			Name, Temp);
	
	return 	strlen( Temp) * 2 + 2;
}


void
dissect_smb_unknown( const u_char *pd, int offset, frame_data *fd,
		proto_tree *tree){

/* display data as unknown */
  	
    proto_tree_add_text(tree, offset, END_OF_FRAME, "Data (%u bytes)",
                        END_OF_FRAME);

}



void
display_flags( struct flag_array_type *flag_array, int length,
	const u_char *pd, int offset, proto_tree *tree){

/* Display a bit fields using the flag_array information.  		*/
/* See packet-smb-common.h for definition of the flag_array structure 	*/


/*** NOTE: currently only handles values that are 1, 2, or 4 octets wide.*/
/***	This should be expanded to handle any bit width. 		 */

/* NOTE: the last entry must have the mask value = 0, this is the end of */
/*	array flag 							 */


	struct flag_array_type *array_ptr = flag_array;

	guint32 flags;
	
	if ( length == 1) flags = GBYTE( pd, offset);
	if ( length == 2) flags = GSHORT( pd, offset);
	if ( length == 4) flags = GWORD( pd, offset);
		

	while( array_ptr->mask) {
		proto_tree_add_text( tree, offset, 2, "%s%s%s%s",
			decode_boolean_bitfield( flags, array_ptr->mask,
				length * 8, "",""),
			array_ptr->pre_string,
			((flags & array_ptr->mask) ? array_ptr->true_string :
				array_ptr->false_string),
			array_ptr->post_string);
	
		++array_ptr;
	}
}	
