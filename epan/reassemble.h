/* reassemble.h
 * Declarations of outines for {fragment,segment} reassembly
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
	guint32 reassembled_in;	/* frame where this PDU was reassembled,
				   only valid in the first item of the list
				   and when FD_DEFRAGMENTED is set*/
	guint32 flags;
	unsigned char *data;
} fragment_data;

/*
 * Initialize a fragment table.
 */
extern void fragment_table_init(GHashTable **fragment_table);
extern void dcerpc_fragment_table_init(GHashTable **fragment_table);

/*
 * Initialize a reassembled-packet table.
 */
extern void reassembled_table_init(GHashTable **reassembled_table);

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
extern fragment_data *fragment_add(tvbuff_t *tvb, int offset, packet_info *pinfo,
    guint32 id, GHashTable *fragment_table, guint32 frag_offset,
    guint32 frag_data_len, gboolean more_frags);
extern fragment_data *fragment_add_multiple_ok(tvbuff_t *tvb, int offset,
    packet_info *pinfo, guint32 id, GHashTable *fragment_table,
    guint32 frag_offset, guint32 frag_data_len, gboolean more_frags);

extern fragment_data *fragment_add_check(tvbuff_t *tvb, int offset,
    packet_info *pinfo, guint32 id, GHashTable *fragment_table,
    GHashTable *reassembled_table, guint32 frag_offset,
    guint32 frag_data_len, gboolean more_frags);

/* same as fragment_add() but this one assumes frag_number is a block
   sequence number. note that frag_number is 0 for the first fragment. */
extern fragment_data *fragment_add_seq(tvbuff_t *tvb, int offset, packet_info *pinfo,
    guint32 id, GHashTable *fragment_table, guint32 frag_number,
    guint32 frag_data_len, gboolean more_frags);

extern fragment_data *
fragment_add_dcerpc_dg(tvbuff_t *tvb, int offset, packet_info *pinfo, guint32 id,
	void *act_id,
	GHashTable *fragment_table, guint32 frag_number,
	guint32 frag_data_len, gboolean more_frags);

/*
 * These functions add a new fragment to the fragment hash table.
 * If this is the first fragment seen for this datagram, a new
 * "fragment_data" structure is allocated to refer to the reassembled,
 * packet, and:
 *
 *	in "fragment_add_seq_802_11()", if "more_frags" is false,
 *	the structure is not added to the hash table, and not given
 *	any fragments to refer to, but is just returned;
 *
 *	otherwise, this fragment is added to the linked list of fragments
 *	for this packet, and the "fragment_data" structure is put into
 *	the hash table.
 *
 * Otherwise, this fragment is just added to the linked list of fragments
 * for this packet.
 *
 * If, after processing this fragment, we have all the fragments, they
 * remove that from the fragment hash table if necessary and add it
 * to the table of reassembled fragments, and return a pointer to the
 * head of the fragment list.
 *
 * If this is the first fragment we've seen, and "more_frags" is false,
 * "fragment_add_seq_802_11()" does nothing to the fragment data list,
 * and returns a pointer to the head of that (empty) list.  The other
 * routines return NULL.
 *
 * Otherwise, they return NULL.
 *
 * "fragment_add_seq_check()" and "fragment_add_seq_802_11()" assume
 * frag_number is a block sequence number.
 * The bsn for the first block is 0.
 *
 * "fragment_add_seq_next()" is for protocols with no sequence number,
 * and assumes fragments always appear in sequence.
 */
extern fragment_data *
fragment_add_seq_check(tvbuff_t *tvb, int offset, packet_info *pinfo,
	     guint32 id, GHashTable *fragment_table,
	     GHashTable *reassembled_table, guint32 frag_number,
	     guint32 frag_data_len, gboolean more_frags);

extern fragment_data *
fragment_add_seq_802_11(tvbuff_t *tvb, int offset, packet_info *pinfo,
	     guint32 id, GHashTable *fragment_table,
	     GHashTable *reassembled_table, guint32 frag_number,
	     guint32 frag_data_len, gboolean more_frags);

extern fragment_data *
fragment_add_seq_next(tvbuff_t *tvb, int offset, packet_info *pinfo, guint32 id,
	     GHashTable *fragment_table, GHashTable *reassembled_table,
	     guint32 frag_data_len, gboolean more_frags);

/* to specify how much to reassemble, for fragmentation where last fragment can not be
 * identified by flags or such.
 * note that for FD_BLOCKSEQUENCE tot_len is the index for the tail fragment.
 * i.e. since the block numbers start at 0, if we specify tot_len==2, that
 * actually means we want to defragment 3 blocks, block 0, 1 and 2.
 *
 */
extern void
fragment_set_tot_len(packet_info *pinfo, guint32 id, GHashTable *fragment_table,
		     guint32 tot_len);

/* to resad whatever totlen previously set */
extern guint32
fragment_get_tot_len(packet_info *pinfo, guint32 id, GHashTable *fragment_table);

/*
 * This function will set the partial reassembly flag(FD_PARTIAL_REASSEMBLY) for a fh.
 * When this function is called, the fh MUST already exist, i.e.
 * the fh MUST be created by the initial call to fragment_add() before
 * this function is called. Also note that this function MUST be called to indicate
 * a fh will be extended (increase the already stored data). After calling this function,
 * and if FD_DEFRAGMENTED is set, the reassembly process will be continued.
 */
extern void
fragment_set_partial_reassembly(packet_info *pinfo, guint32 id, GHashTable *fragment_table);

/* This function is used to check if there is partial or completed reassembly state
 * matching this packet. I.e. Are there reassembly going on or not for this packet?
 */
extern fragment_data *
fragment_get(packet_info *pinfo, guint32 id, GHashTable *fragment_table);

/* The same for the reassemble table */
extern fragment_data *
fragment_get_reassembled(packet_info *pinfo, guint32 id, GHashTable *reassembled_table);

/* This will free up all resources and delete reassembly state for this PDU.
 * Except if the PDU is completely reassembled, then it would NOT deallocate the
 * buffer holding the reassembled data but instead return the pointer to that
 * buffer.
 *
 * So, if you call fragment_delete and it returns non-NULL, YOU are responsible to
 * g_free() that buffer.
 */
extern unsigned char *
fragment_delete(packet_info *pinfo, guint32 id, GHashTable *fragment_table);

/* hf_fragment, hf_fragment_error, and hf_reassembled_in should be
   FT_FRAMENUM, the others should be FT_BOOLEAN
*/
typedef struct _fragment_items {
	gint	*ett_fragment;
	gint	*ett_fragments;

	int	*hf_fragments;
	int	*hf_fragment;
	int	*hf_fragment_overlap;
	int	*hf_fragment_overlap_conflict;
	int	*hf_fragment_multiple_tails;
	int	*hf_fragment_too_long_fragment;
	int	*hf_fragment_error;
	int	*hf_reassembled_in;

	const char	*tag;
} fragment_items;

extern tvbuff_t *
process_reassembled_data(tvbuff_t *tvb, int offset, packet_info *pinfo,
    const char *name, fragment_data *fd_head, const fragment_items *fit,
    gboolean *update_col_infop, proto_tree *tree);

extern gboolean
show_fragment_tree(fragment_data *ipfd_head, const fragment_items *fit,
    proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, proto_item **fi);

extern gboolean
show_fragment_seq_tree(fragment_data *ipfd_head, const fragment_items *fit,
    proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, proto_item **fi);
