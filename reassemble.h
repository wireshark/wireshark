/* reassemble.h
 * Declarations of outines for {fragment,segment} reassembly
 *
 * $Id: reassemble.h,v 1.4 2002/02/03 23:28:38 guy Exp $
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

/* fragment data not alloced, fd->data pointing to fd_head->data+fd->offset */
#define FD_NOT_MALLOCED         0x0020

/* this flag is used to request fragment_add to continue the reassembly process */
#define FD_PARTIAL_REASSEMBLY   0x0040

/* fragment offset is indicated by sequence number and not byte offset
   into the defragmented packet */
#define FD_BLOCKSEQUENCE        0x0100

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

/* same as fragment_add() but this one assumes frag_offset is a block
   sequence number. note that frag_offset is 0 for the first fragment. */
fragment_data *fragment_add_seq(tvbuff_t *tvb, int offset, packet_info *pinfo,
    guint32 id, GHashTable *fragment_table, guint32 frag_offset,
    guint32 frag_data_len, gboolean more_frags);

/* to specify how much to reassemble, for fragmentation where last fragment can not be 
 * identified by flags or such.
 * note that for FD_BLOCKSEQUENCE tot_len is the index for the tail fragment.
 * i.e. since the block numbers start at 0, if we specify tot_len==2, that 
 * actually means we want to defragment 3 blocks, block 0, 1 and 2.
 *
 */
void
fragment_set_tot_len(packet_info *pinfo, guint32 id, GHashTable *fragment_table, 
		     guint32 tot_len);
/*
 * This function will set the partial reassembly flag(FD_PARTIAL_REASSEMBLY) for a fh.
 * When this function is called, the fh MUST already exist, i.e.
 * the fh MUST be created by the initial call to fragment_add() before
 * this function is called. Also note that this function MUST be called to indicate 
 * a fh will be extended (increase the already stored data). After calling this function,
 * and if FD_DEFRAGMENTED is set, the reassembly process will be continued.
 */
void
fragment_set_partial_reassembly(packet_info *pinfo, guint32 id, GHashTable *fragment_table);

/* This function is used to check if there is partial or completed reassembly state
 * matching this packet. I.e. Are there reassembly going on or not for this packet?
 */
fragment_data *
fragment_get(packet_info *pinfo, guint32 id, GHashTable *fragment_table);

/* This will free up all resources and delete reassembly state for this PDU.
 * Except if the PDU is completely reassembled, then it would NOT deallocate the
 * buffer holding the reassembled data but instead return the pointer to that
 * buffer.
 * 
 * So, if you call fragment_delete and it returns non-NULL, YOU are responsible to 
 * g_free() that buffer.
 */
unsigned char *
fragment_delete(packet_info *pinfo, guint32 id, GHashTable *fragment_table);


