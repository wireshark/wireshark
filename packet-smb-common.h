/* packet-smb-common.h
 * Routines for smb packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id: packet-smb-common.h,v 1.1 2000/02/14 04:02:06 guy Exp $
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <time.h>
#include <string.h>
#include <glib.h>
#include <ctype.h>
#include "packet.h"
#include "conversation.h"
#include "smb.h"
#include "alignment.h"






#define ShortPacketError	proto_tree_add_text(tree, offset, 0, "****FRAME TOO SHORT***"); return;
#define IncAndCheckOffset	if ( ++offset > fd->cap_len) {ShortPacketError;}
#define CheckPacketLength(X) 	if ((offset+X) > fd->cap_len) {ShortPacketError;}

#define MoveAndCheckOffset(X)	{int tmp = X; if (( offset + tmp) > fd->cap_len){ ShortPacketError;} else offset += tmp;}

#define UnknowData 	if (tree) proto_tree_add_text(tree, offset, END_OF_FRAME, "Data (%u bytes)",END_OF_FRAME); 


struct flag_array_type {
	guint32	mask;		/* bit mask to test for bit set 	*/
	char 	*pre_string;	/* string for front of description 	*/
	char 	*true_string;	/* description string if flag is set 	*/
	char 	*false_string;	/* description string if flag is not set */
	char 	*post_string;	/* string for end of description 	*/
};


void display_flags( struct flag_array_type *flag_array, int length,
	const u_char *pd, int offset, proto_tree *tree);


int display_ms_value( char *Name, int len, const u_char *pd, int offset,
		frame_data *fd, proto_tree *tree);
int display_ms_string( char *Name, const u_char *pd, int offset,
		frame_data *fd, proto_tree *tree);
int display_unicode_string( char *Name, const u_char *pd, int offset,
		frame_data *fd, proto_tree *tree);
void dissect_smb_unknown( const u_char *pd, int offset, frame_data *fd,
		proto_tree *tree);
