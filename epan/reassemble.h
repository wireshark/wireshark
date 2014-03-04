/* reassemble.h
 * Declarations of outines for {fragment,segment} reassembly
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* make sure that all flags that are set in a fragment entry is also set for
 * the flags field of fd_head !!!
 */

#ifndef REASSEMBLE_H
#define REASSEMBLE_H

#include "ws_symbol_export.h"

/* only in fd_head: packet is defragmented */
#define FD_DEFRAGMENTED		0x0001

/* there are overlapping fragments */
#define FD_OVERLAP		0x0002

/* overlapping fragments contain different data */
#define FD_OVERLAPCONFLICT	0x0004

/* more than one fragment which indicates end-of data */
#define FD_MULTIPLETAILS	0x0008

/* fragment starts before the end of the datagram but extends
   past the end of the datagram */
#define FD_TOOLONGFRAGMENT	0x0010

/* fragment tvb is subset, don't tvb_free() it */
#define FD_SUBSET_TVB           0x0020

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

typedef struct _fragment_item {
	struct _fragment_item *next;
	guint32 frame;	/* XXX - does this apply to reassembly heads? */
	guint32	offset;	/* XXX - does this apply to reassembly heads? */
	guint32	len;	/* XXX - does this apply to reassembly heads? */
	guint32 fragment_nr_offset; /* offset for frame numbering, for sequences, where the
	                             * provided fragment number of the first fragment does
	                             * not start with 0
	                             * XXX - does this apply only to reassembly heads? */
	guint32 datalen; /* Only valid in first item of list and when
                          * flags&FD_DATALEN_SET is set;
                          * number of bytes or (if flags&FD_BLOCKSEQUENCE set)
                          * segments in the datagram */
	guint32 reassembled_in;	/* frame where this PDU was reassembled,
				   only valid in the first item of the list
				   and when FD_DEFRAGMENTED is set*/
	guint32 flags;	/* XXX - do some of these apply only to reassembly
			   heads and others only to fragments within
			   a reassembly? */
	tvbuff_t *tvb_data;

	/*
	 * Null if the reassembly had no error; non-null if it had
	 * an error, in which case it's the string for the error.
	 *
	 * XXX - this is wasted in all but the reassembly head; we
	 * should probably have separate data structures for a
	 * reassembly and for the fragments in a reassembly.
	 */
	const char *error;
} fragment_item, fragment_head;


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

/* a function for creating temporary hash keys */
typedef gpointer (*fragment_temporary_key)(const packet_info *pinfo,
    const guint32 id, const void *data);

/* a function for creating persistent hash keys */
typedef gpointer (*fragment_persistent_key)(const packet_info *pinfo,
    const guint32 id, const void *data);

/*
 * Data structure to keep track of fragments and reassemblies.
 */
typedef struct {
	GHashTable *fragment_table;
	GHashTable *reassembled_table;
	fragment_temporary_key temporary_key_func;
	fragment_persistent_key persistent_key_func;
	GDestroyNotify free_temporary_key_func;		/* temporary key destruction function */
} reassembly_table;

/*
 * Table of functions for a reassembly table.
 */
typedef struct {
	/* Functions for fragment table */
	GHashFunc hash_func;				/* hash function */
	GEqualFunc equal_func;				/* comparison function */
	fragment_temporary_key temporary_key_func;	/* temporary key creation function */
	fragment_persistent_key persistent_key_func;	/* persistent key creation function */
	GDestroyNotify free_temporary_key_func;		/* temporary key destruction function */
	GDestroyNotify free_persistent_key_func;	/* persistent key destruction function */
} reassembly_table_functions;

/*
 * Tables of functions exported for the benefit of dissectors that
 * don't need special items in their keys.
 */
WS_DLL_PUBLIC const reassembly_table_functions
	addresses_reassembly_table_functions;		/* keys have endpoint addresses and an ID */
WS_DLL_PUBLIC const reassembly_table_functions
	addresses_ports_reassembly_table_functions;	/* keys have endpoint addresses and ports and an ID */

/*
 * Initialize/destroy a reassembly table.
 *
 * init: If table doesn't exist: create table;
 *       else: just remove any entries;
 * destroy: remove entries and destroy table;
 */
WS_DLL_PUBLIC void
reassembly_table_init(reassembly_table *table,
		      const reassembly_table_functions *funcs);
WS_DLL_PUBLIC void
reassembly_table_destroy(reassembly_table *table);

/*
 * This function adds a new fragment to the reassembly table
 * If this is the first fragment seen for this datagram, a new entry
 * is created in the table, otherwise this fragment is just added
 * to the linked list of fragments for this packet.
 * The list of fragments for a specific datagram is kept sorted for
 * easier handling.
 *
 * Returns a pointer to the head of the fragment data list if we have all the
 * fragments, NULL otherwise.
 */
WS_DLL_PUBLIC fragment_head *
fragment_add(reassembly_table *table, tvbuff_t *tvb, const int offset,
	     const packet_info *pinfo, const guint32 id, const void *data,
	     const guint32 frag_offset, const guint32 frag_data_len,
	     const gboolean more_frags);
WS_DLL_PUBLIC fragment_head *
fragment_add_multiple_ok(reassembly_table *table, tvbuff_t *tvb,
			 const int offset, const packet_info *pinfo,
			 const guint32 id, const void *data,
			 const guint32 frag_offset,
			 const guint32 frag_data_len,
			 const gboolean more_frags);

/*
 * This routine extends fragment_add to use a "reassembled_table"
 * included in the reassembly table.
 *
 * If, after processing this fragment, we have all the fragments, they
 * remove that from the fragment hash table if necessary and add it
 * to the table of reassembled fragments, and return a pointer to the
 * head of the fragment list.
 */
WS_DLL_PUBLIC fragment_head *
fragment_add_check(reassembly_table *table, tvbuff_t *tvb, const int offset,
		   const packet_info *pinfo, const guint32 id,
		   const void *data, const guint32 frag_offset,
		   const guint32 frag_data_len, const gboolean more_frags);

/* same as fragment_add() but this one assumes frag_number is a block
   sequence number. note that frag_number is 0 for the first fragment. */

/*
 * These functions add a new fragment to the fragment hash table,
 * assuming that frag_number is a block sequence number (starting from zero for
 * the first fragment of each datagram).
 *
 * If this is the first fragment seen for this datagram, a new
 * "fragment_head" structure is allocated to refer to the reassembled
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
 * for this packet; the fragment_item is also added to the fragment hash if
 * necessary.
 *
 * If this packet completes assembly, these functions return the head of the
 * fragment data; otherwise, they return null.
 */
WS_DLL_PUBLIC fragment_head *
fragment_add_seq(reassembly_table *table, tvbuff_t *tvb, const int offset,
		 const packet_info *pinfo, const guint32 id, const void *data,
		 const guint32 frag_number, const guint32 frag_data_len,
		 const gboolean more_frags, const guint32 flags);

/*
 * These routines extend fragment_add_seq to use the "reassembled_table".
 *
 * If, after processing this fragment, we have all the fragments, they
 * remove that from the fragment hash table if necessary and add it
 * to the table of reassembled fragments, and return a pointer to the
 * head of the fragment list.
 */
WS_DLL_PUBLIC fragment_head *
fragment_add_seq_check(reassembly_table *table, tvbuff_t *tvb, const int offset,
		       const packet_info *pinfo, const guint32 id,
		       const void *data,
		       const guint32 frag_number, const guint32 frag_data_len,
		       const gboolean more_frags);

WS_DLL_PUBLIC fragment_head *
fragment_add_seq_802_11(reassembly_table *table, tvbuff_t *tvb,
			const int offset, const packet_info *pinfo,
			const guint32 id, const void *data,
			const guint32 frag_number, const guint32 frag_data_len,
			const gboolean more_frags);

WS_DLL_PUBLIC fragment_head *
fragment_add_seq_next(reassembly_table *table, tvbuff_t *tvb, const int offset,
		      const packet_info *pinfo, const guint32 id,
		      const void *data, const guint32 frag_data_len,
		      const gboolean more_frags);

WS_DLL_PUBLIC void
fragment_start_seq_check(reassembly_table *table, const packet_info *pinfo,
			 const guint32 id, const void *data,
			 const guint32 tot_len);

WS_DLL_PUBLIC fragment_head *
fragment_end_seq_next(reassembly_table *table, const packet_info *pinfo,
		      const guint32 id, const void *data);

/* To specify the offset for the fragment numbering, the first fragment is added with 0, and
 * afterwards this offset is set. All additional calls to off_seq_check will calculate
 * the number in sequence in regards to the offset */
WS_DLL_PUBLIC void
fragment_add_seq_offset(reassembly_table *table, const packet_info *pinfo, const guint32 id,
                    const void *data, const guint32 fragment_offset);

/* to specify how much to reassemble, for fragmentation where last fragment can not be
 * identified by flags or such.
 * note that for FD_BLOCKSEQUENCE tot_len is the index for the tail fragment.
 * i.e. since the block numbers start at 0, if we specify tot_len==2, that
 * actually means we want to defragment 3 blocks, block 0, 1 and 2.
 *
 */
WS_DLL_PUBLIC void
fragment_set_tot_len(reassembly_table *table, const packet_info *pinfo,
		     const guint32 id, const void *data, const guint32 tot_len);

/* to resad whatever totlen previously set */
WS_DLL_PUBLIC guint32
fragment_get_tot_len(reassembly_table *table, const packet_info *pinfo,
		     const guint32 id, const void *data);

/*
 * This function will set the partial reassembly flag(FD_PARTIAL_REASSEMBLY) for a fh.
 * When this function is called, the fh MUST already exist, i.e.
 * the fh MUST be created by the initial call to fragment_add() before
 * this function is called. Also note that this function MUST be called to indicate
 * a fh will be extended (increase the already stored data). After calling this function,
 * and if FD_DEFRAGMENTED is set, the reassembly process will be continued.
 */
WS_DLL_PUBLIC void
fragment_set_partial_reassembly(reassembly_table *table,
				const packet_info *pinfo, const guint32 id,
				const void *data);

/* This function is used to check if there is partial or completed reassembly state
 * matching this packet. I.e. Are there reassembly going on or not for this packet?
 */
WS_DLL_PUBLIC fragment_head *
fragment_get(reassembly_table *table, const packet_info *pinfo,
	     const guint32 id, const void *data);

/* The same for the reassemble table */
/* id *must* be the frame number for this to work! */
WS_DLL_PUBLIC fragment_head *
fragment_get_reassembled(reassembly_table *table, const guint32 id);

WS_DLL_PUBLIC fragment_head *
fragment_get_reassembled_id(reassembly_table *table, const packet_info *pinfo,
			    const guint32 id);

/* This will free up all resources and delete reassembly state for this PDU.
 * Except if the PDU is completely reassembled, then it would NOT deallocate the
 * buffer holding the reassembled data but instead return the TVB
 *
 * So, if you call fragment_delete and it returns non-NULL, YOU are responsible to
 * tvb_free() .
 */
WS_DLL_PUBLIC tvbuff_t *
fragment_delete(reassembly_table *table, const packet_info *pinfo,
		const guint32 id, const void *data);

/* This struct holds references to all the tree and field handles used when
 * displaying the reassembled fragment tree in the packet details view. A
 * dissector will populate this structure with its own tree and field handles
 * and then invoke show_fragement_tree to have those items added to the packet
 * details tree.
 */
typedef struct _fragment_items {
    gint       *ett_fragment;
    gint       *ett_fragments;

    int        *hf_fragments;                  /* FT_NONE     */
    int        *hf_fragment;                   /* FT_FRAMENUM */
    int        *hf_fragment_overlap;           /* FT_BOOLEAN  */
    int        *hf_fragment_overlap_conflict;  /* FT_BOOLEAN  */
    int        *hf_fragment_multiple_tails;    /* FT_BOOLEAN  */
    int        *hf_fragment_too_long_fragment; /* FT_BOOLEAN  */
    int        *hf_fragment_error;             /* FT_FRAMENUM */
    int        *hf_fragment_count;             /* FT_UINT32   */
    int        *hf_reassembled_in;             /* FT_FRAMENUM */
    int        *hf_reassembled_length;         /* FT_UINT32   */
    int        *hf_reassembled_data;           /* FT_BYTES    */

    const char *tag;
} fragment_items;

WS_DLL_PUBLIC tvbuff_t *
process_reassembled_data(tvbuff_t *tvb, const int offset, packet_info *pinfo,
    const char *name, fragment_head *fd_head, const fragment_items *fit,
    gboolean *update_col_infop, proto_tree *tree);

WS_DLL_PUBLIC gboolean
show_fragment_tree(fragment_head *ipfd_head, const fragment_items *fit,
    proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, proto_item **fi);

WS_DLL_PUBLIC gboolean
show_fragment_seq_tree(fragment_head *ipfd_head, const fragment_items *fit,
    proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, proto_item **fi);

#endif
