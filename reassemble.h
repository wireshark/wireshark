/* reassemble.h
 * Declarations of outines for {fragment,segment} reassembly
 *
 * $Id: reassemble.h,v 1.1 2001/06/08 06:27:16 guy Exp $
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

/* make sure that all flags that are set in a fragment entry is also set for
 * the flags field of fd_head !!!
 */

/* only in fd_head: packet is defragmented */
#define FD_DEFRAGMENTED		0x0001

/* there are overlapping fragments */
#define FD_OVERLAP		0x0002

/* overlapping fragments contain different data */ 
#define FD_OVERLAPCONFLICT	0x0004  

/* more than one fragment which indicates end-of data */
#define FD_MULTIPLETAILS	0x0008

/* fragment contains data past the end of the datagram */
#define FD_TOOLONGFRAGMENT	0x0010

typedef struct _fragment_data {
	struct _fragment_data *next;
	guint32 frame;
	guint32	offset;
	guint32	len;
	guint32 datalen; /*Only valid in first item of list */
	guint32 flags;
	unsigned char *data;
} fragment_data;

/*
 * Initialize a fragment table.
 */
void fragment_table_init(GHashTable **fragment_table);

/*
 * Free up all space allocated for fragment keys and data.
 */
void reassemble_init(void);

/*
 * This function adds a new fragment to the fragment hash table.
 * If this is the first fragment seen for this datagram, a new entry
 * is created in the hash table, otherwise this fragment is just added
 * to the linked list of fragments for this packet.
 * The list of fragments for a specific datagram is kept sorted for
 * easier handling.
 *
 * Returns a pointer to the head of the fragment data list if we have all the
 * fragments, NULL otherwise.
 */
fragment_data *fragment_add(tvbuff_t *tvb, int offset, packet_info *pinfo,
    guint32 id, GHashTable *fragment_table, guint32 frag_offset,
    guint32 frag_data_len, gboolean more_frags);
