/* reassemble.h
 * Declarations of outines for {fragment,segment} reassembly
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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

/* fragment data not alloc'ed, fd->data pointing to fd_head->data+fd->offset */
#define FD_NOT_MALLOCED         0x0020

/* this flag is used to request fragment_add to continue the reassembly process */
#define FD_PARTIAL_REASSEMBLY   0x0040

/* fragment offset is indicated by sequence number and not byte offset
   into the defragmented packet */
#define FD_BLOCKSEQUENCE        0x0100

/* if REASSEMBLE_FLAGS_CHECK_DATA_PRESENT is set, and the first fragment is
 * incomplete, this flag is set in the flags word on the fd_head returned.
 *
 * It's all a fudge to preserve historical behaviour.
 */
#define FD_DATA_NOT_PRESENT	0x0200

/* This flag is set in (only) fd_head to denote that datalen has been set to a valid value.
 * It's implied by FD_DEFRAGMENTED (we must know the total length of the
 * datagram if we have defragmented it...)
 */
#define FD_DATALEN_SET		0x0400

typedef struct _fragment_data {
	struct _fragment_data *next;
	guint32 frame;
	guint32	offset;
	guint32	len;
	guint32 datalen; /* Only valid in first item of list and when
                          * flags&FD_DATALEN_SET is set;
                          * number of bytes or (if flags&FD_BLOCKSEQUENCE set)
                          * segments in the datagram */
	guint32 reassembled_in;	/* frame where this PDU was reassembled,
				   only valid in the first item of the list
				   and when FD_DEFRAGMENTED is set*/
	guint32 flags;
	unsigned char *data;
} fragment_data;


/*
 * Flags for fragment_add_seq_*
 */

/* we don't have any sequence numbers - fragments are assumed to appear in
 * order */
#define REASSEMBLE_FLAGS_NO_FRAG_NUMBER		0x0001

/* a special fudge for the 802.11 dissector */
#define REASSEMBLE_FLAGS_802_11_HACK		0x0002

/* causes fragment_add_seq_key to check that all the fragment data is present
 * in the tvb, and if not, do something a bit odd. */
#define REASSEMBLE_FLAGS_CHECK_DATA_PRESENT	0x0004

/* a function for copying hash keys */
typedef void *(*fragment_key_copier)(const void *key);

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
extern fragment_data *fragment_add(tvbuff_t *tvb, const int offset, const packet_info *pinfo,
    const guint32 id, GHashTable *fragment_table, const guint32 frag_offset,
    guint32 const frag_data_len, const gboolean more_frags);
extern fragment_data *fragment_add_multiple_ok(tvbuff_t *tvb, const int offset,
    const packet_info *pinfo, const guint32 id, GHashTable *fragment_table,
    const guint32 frag_offset, const guint32 frag_data_len, const gboolean more_frags);

/*
 * This routine extends fragment_add to use a "reassembled_table".
 *
 * If, after processing this fragment, we have all the fragments, they
 * remove that from the fragment hash table if necessary and add it
 * to the table of reassembled fragments, and return a pointer to the
 * head of the fragment list.
 */
extern fragment_data *fragment_add_check(tvbuff_t *tvb, const int offset,
    const packet_info *pinfo, const guint32 id, GHashTable *fragment_table,
    GHashTable *reassembled_table, const guint32 frag_offset,
    const guint32 frag_data_len, const gboolean more_frags);

/* same as fragment_add() but this one assumes frag_number is a block
   sequence number. note that frag_number is 0 for the first fragment. */

/*
 * These functions add a new fragment to the fragment hash table,
 * assuming that frag_number is a block sequence number (starting from zero for
 * the first fragment of each datagram).
 *
 * If this is the first fragment seen for this datagram, a new
 * "fragment_data" structure is allocated to refer to the reassembled
 * packet, and:
 *
 *	if "more_frags" is false, and either we have no sequence numbers, or
 *	are using the 802.11 hack, it is assumed that this is the only fragment
 *	in the datagram. The structure is not added to the hash
 *	table, and not given any fragments to refer to, but is just returned.
 *
 *      In this latter case reassembly wasn't done (since there was only one
 *      fragment in the packet); dissectors can check the 'next' pointer on the
 *      returned list to see if this case was hit or not.
 *
 * Otherwise, this fragment is just added to the linked list of fragments
 * for this packet; the fragment_data is also added to the fragment hash if
 * necessary.
 *
 * If this packet completes assembly, these functions return the head of the
 * fragment data; otherwise, they return null.
 */

/* "key" should be an arbitrary key used for indexing the fragment hash;
 * "key_copier" is called to copy the key to a more appropriate store before
 * inserting a new entry to the hash.
 */
extern fragment_data *
fragment_add_seq_key(tvbuff_t *tvb, const int offset, const packet_info *pinfo,
                     void *key, fragment_key_copier key_copier,
                     GHashTable *fragment_table, guint32 frag_number,
                     const guint32 frag_data_len, const gboolean more_frags,
                     const guint32 flags);

/* a wrapper for fragment_add_seq_key - uses a key of source, dest and id */
extern fragment_data *fragment_add_seq(tvbuff_t *tvb, const int offset, const packet_info *pinfo,
    const guint32 id, GHashTable *fragment_table, const guint32 frag_number,
    const guint32 frag_data_len, const gboolean more_frags);

/* another wrapper for fragment_add_seq_key - uses a key of source, dest, id
 * and act_id */
extern fragment_data *
fragment_add_dcerpc_dg(tvbuff_t *tvb, const int offset, const packet_info *pinfo, const guint32 id,
	void *act_id,
	GHashTable *fragment_table, const guint32 frag_number,
	const guint32 frag_data_len, const gboolean more_frags);

/*
 * These routines extend fragment_add_seq_key to use a "reassembled_table".
 *
 * If, after processing this fragment, we have all the fragments, they
 * remove that from the fragment hash table if necessary and add it
 * to the table of reassembled fragments, and return a pointer to the
 * head of the fragment list.
 */
extern fragment_data *
fragment_add_seq_check(tvbuff_t *tvb, const int offset,
		       const packet_info *pinfo, const guint32 id,
		       GHashTable *fragment_table,
		       GHashTable *reassembled_table, const guint32 frag_number,
		       const guint32 frag_data_len, const gboolean more_frags);

extern fragment_data *
fragment_add_seq_802_11(tvbuff_t *tvb, const int offset,
			const packet_info *pinfo, const guint32 id,
			GHashTable *fragment_table,
			GHashTable *reassembled_table,
			const guint32 frag_number, const guint32 frag_data_len,
			const gboolean more_frags);

extern fragment_data *
fragment_add_seq_next(tvbuff_t *tvb, const int offset, const packet_info *pinfo,
		      const guint32 id, GHashTable *fragment_table,
		      GHashTable *reassembled_table,
		      const guint32 frag_data_len, const gboolean more_frags);

extern void
fragment_start_seq_check(const packet_info *pinfo, const guint32 id, GHashTable *fragment_table,
			 const guint32 tot_len);

extern fragment_data *
fragment_end_seq_next(const packet_info *pinfo, const guint32 id, GHashTable *fragment_table,
		      GHashTable *reassembled_table);
/* to specify how much to reassemble, for fragmentation where last fragment can not be
 * identified by flags or such.
 * note that for FD_BLOCKSEQUENCE tot_len is the index for the tail fragment.
 * i.e. since the block numbers start at 0, if we specify tot_len==2, that
 * actually means we want to defragment 3 blocks, block 0, 1 and 2.
 *
 */
extern void
fragment_set_tot_len(const packet_info *pinfo, const guint32 id, GHashTable *fragment_table,
		     const guint32 tot_len);

/* to resad whatever totlen previously set */
extern guint32
fragment_get_tot_len(const packet_info *pinfo, const guint32 id, GHashTable *fragment_table);

/*
 * This function will set the partial reassembly flag(FD_PARTIAL_REASSEMBLY) for a fh.
 * When this function is called, the fh MUST already exist, i.e.
 * the fh MUST be created by the initial call to fragment_add() before
 * this function is called. Also note that this function MUST be called to indicate
 * a fh will be extended (increase the already stored data). After calling this function,
 * and if FD_DEFRAGMENTED is set, the reassembly process will be continued.
 */
extern void
fragment_set_partial_reassembly(const packet_info *pinfo, const guint32 id, GHashTable *fragment_table);

/* This function is used to check if there is partial or completed reassembly state
 * matching this packet. I.e. Are there reassembly going on or not for this packet?
 */
extern fragment_data *
fragment_get(const packet_info *pinfo, const guint32 id, GHashTable *fragment_table);

/* The same for the reassemble table */
/* id *must* be the frame number for this to work! */
extern fragment_data *
fragment_get_reassembled(const guint32 id, GHashTable *reassembled_table);

extern fragment_data *
fragment_get_reassembled_id(const packet_info *pinfo, const guint32 id, GHashTable *reassembled_table);

/* This will free up all resources and delete reassembly state for this PDU.
 * Except if the PDU is completely reassembled, then it would NOT deallocate the
 * buffer holding the reassembled data but instead return the pointer to that
 * buffer.
 *
 * So, if you call fragment_delete and it returns non-NULL, YOU are responsible to
 * g_free() that buffer.
 */
extern unsigned char *
fragment_delete(const packet_info *pinfo, const guint32 id, GHashTable *fragment_table);

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
	int     *hf_fragment_count;
	int	*hf_reassembled_in;
	int	*hf_reassembled_length;

	const char	*tag;
} fragment_items;

extern tvbuff_t *
process_reassembled_data(tvbuff_t *tvb, const int offset, packet_info *pinfo,
    const char *name, fragment_data *fd_head, const fragment_items *fit,
    gboolean *update_col_infop, proto_tree *tree);

extern gboolean
show_fragment_tree(fragment_data *ipfd_head, const fragment_items *fit,
    proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, proto_item **fi);

extern gboolean
show_fragment_seq_tree(fragment_data *ipfd_head, const fragment_items *fit,
    proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, proto_item **fi);
