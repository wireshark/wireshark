/** @file
 * Declarations of routines for {fragment,segment} reassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

/* This flag is set in (only) fd_head to denote that datalen has been set to a valid value.
 * It's implied by FD_DEFRAGMENTED (we must know the total length of the
 * datagram if we have defragmented it...)
 */
#define FD_DATALEN_SET		0x0400

typedef struct _fragment_item {
	struct _fragment_item *next;
	guint32 frame;			/* XXX - does this apply to reassembly heads? */
	guint32	offset;			/* XXX - does this apply to reassembly heads? */
	guint32	len;			/* XXX - does this apply to reassembly heads? */
	guint32 fragment_nr_offset;	/**< offset for frame numbering, for sequences, where the
					 * provided fragment number of the first fragment does
					 * not start with 0
					 * XXX - does this apply only to reassembly heads? */
	guint32 datalen;		/**< When flags&FD_BLOCKSEQUENCE is set, the
					 * index of the last block (segments in
					 * datagram + 1); otherwise the number of
					 * bytes of the full datagram. Only valid in
					 * the first item of the fragments list when
					 * flags&FD_DATALEN is set.*/
	guint32 reassembled_in;		/**< frame where this PDU was reassembled,
					 * only valid in the first item of the list
					 * and when FD_DEFRAGMENTED is set*/
	guint8 reas_in_layer_num;	/**< The current "depth" or layer number in the current frame where reassembly was completed.
					 * Example: in SCTP there can be several data chunks and we want the reassemblied tvb for the final
					 * segment only. */
	guint32 flags;			/**< XXX - do some of these apply only to reassembly
					 * heads and others only to fragments within
					 * a reassembly? */
	tvbuff_t *tvb_data;
	/**
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

/*
 * Flags for fragment_add_seq_single_*
 */

/* we want to age off old packets */
#define REASSEMBLE_FLAGS_AGING  0x0001

/*
 * Generates a fragment identifier based on the given parameters. "data" is an
 * opaque type whose interpretation is up to the caller of fragment_add*
 * functions and the fragment key function (possibly NULL if you do not care).
 *
 * Keys returned by this function are only used within this packet scope.
 */
typedef gpointer (*fragment_temporary_key)(const packet_info *pinfo,
    const guint32 id, const void *data);

/*
 * Like fragment_temporary_key, but used for identifying reassembled fragments
 * which may persist through multiple packets.
 */
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
 * Register a reassembly table. By registering the table with epan, the creation and
 * destruction of the table can be managed by epan and not the dissector.
 */
WS_DLL_PUBLIC void
reassembly_table_register(reassembly_table *table,
		      const reassembly_table_functions *funcs);

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
 * Datagrams (messages) are identified by a key generated by
 * fragment_temporary_key or fragment_persistent_key, based on the "pinfo", "id"
 * and "data" pairs. (This is the sole purpose of "data".)
 *
 * Fragments are identified by "frag_offset".
 *
 * Returns a pointer to the head of the fragment data list if we have all the
 * fragments, NULL otherwise. Note that the reassembled fragments list may have
 * a non-zero fragment offset, the only guarantee is that no gaps exist within
 * the list.
 */
WS_DLL_PUBLIC fragment_head *
fragment_add(reassembly_table *table, tvbuff_t *tvb, const int offset,
	     const packet_info *pinfo, const guint32 id, const void *data,
	     const guint32 frag_offset, const guint32 frag_data_len,
	     const gboolean more_frags);
/*
 * Like fragment_add, except that the fragment may be added to multiple
 * reassembly tables. This is needed when multiple protocol layers try
 * to add the same packet to the reassembly table.
 */
WS_DLL_PUBLIC fragment_head *
fragment_add_multiple_ok(reassembly_table *table, tvbuff_t *tvb,
			 const int offset, const packet_info *pinfo,
			 const guint32 id, const void *data,
			 const guint32 frag_offset,
			 const guint32 frag_data_len,
			 const gboolean more_frags);

/*
 * Like fragment_add, except that the fragment may originate from a frame
 * other than pinfo->num. For use when you are adding an out of order segment
 * that arrived in an earlier frame, so that show_fragment_tree will display
 * the correct fragment numbers.
 *
 * This is for protocols like TCP, where the correct reassembly to add a
 * segment to cannot be determined without processing previous segments
 * in sequence order, including handing them to subdissectors.
 *
 * Note that pinfo is still used to set reassembled_in if we have all the
 * fragments, so that results on subsequent passes can be the same as the
 * first pass.
 */
WS_DLL_PUBLIC fragment_head *
fragment_add_out_of_order(reassembly_table *table, tvbuff_t *tvb,
                          const int offset, const packet_info *pinfo,
                          const guint32 id, const void *data,
                          const guint32 frag_offset,
                          const guint32 frag_data_len,
                          const gboolean more_frags, const guint32 frag_frame);
/*
 * Like fragment_add, but maintains a table for completed reassemblies.
 *
 * If the packet was seen before, return the head of the fully reassembled
 * fragments list (NULL if there was none).
 *
 * Otherwise (if reassembly was not possible before), try to add the new
 * fragment to the fragments table. If reassembly is now possible, remove all
 * (reassembled) fragments from the fragments table and store it as a completed
 * reassembly. The head of this reassembled fragments list is returned.
 *
 * Otherwise (if reassembly is still not possible after adding this fragment),
 * return NULL.
 */
WS_DLL_PUBLIC fragment_head *
fragment_add_check(reassembly_table *table, tvbuff_t *tvb, const int offset,
		   const packet_info *pinfo, const guint32 id,
		   const void *data, const guint32 frag_offset,
		   const guint32 frag_data_len, const gboolean more_frags);

/*
 * Like fragment_add, but fragments have a block sequence number starting from
 * zero (for the first fragment of each datagram). This differs from
 * fragment_add for which the fragment may start at any offset.
 *
 * If this is the first fragment seen for this datagram, a new
 * "fragment_head" structure is allocated to refer to the reassembled
 * packet, and:
 *
 *	if "more_frags" is false, and either we have no sequence numbers, or
 *	are using the 802.11 hack (via fragment_add_seq_802_11), it is assumed that
 *	this is the only fragment in the datagram. The structure is not added to the
 *	hash table, and not given any fragments to refer to, but is just returned.
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
 * Like fragment_add_seq, but maintains a table for completed reassemblies
 * just like fragment_add_check.
 */
WS_DLL_PUBLIC fragment_head *
fragment_add_seq_check(reassembly_table *table, tvbuff_t *tvb, const int offset,
		       const packet_info *pinfo, const guint32 id,
		       const void *data,
		       const guint32 frag_number, const guint32 frag_data_len,
		       const gboolean more_frags);

/*
 * Like fragment_add_seq_check, but immediately returns a fragment list for a
 * new fragment. This is a workaround specific for the 802.11 dissector, do not
 * use it elsewhere.
 */
WS_DLL_PUBLIC fragment_head *
fragment_add_seq_802_11(reassembly_table *table, tvbuff_t *tvb,
			const int offset, const packet_info *pinfo,
			const guint32 id, const void *data,
			const guint32 frag_number, const guint32 frag_data_len,
			const gboolean more_frags);

/*
 * Like fragment_add_seq_check, but without explicit fragment number. Fragments
 * are simply appended until no "more_frags" is false.
 */
WS_DLL_PUBLIC fragment_head *
fragment_add_seq_next(reassembly_table *table, tvbuff_t *tvb, const int offset,
		      const packet_info *pinfo, const guint32 id,
		      const void *data, const guint32 frag_data_len,
		      const gboolean more_frags);

/*
 * Like fragment_add_seq_check, but for protocols like PPP MP with a single
 * sequence number that increments for each fragment, thus acting like the sum
 * of the PDU sequence number and explicit fragment number in other protocols.
 * See Appendix A of RFC 4623 (PWE3 Fragmentation and Reassembly) for a list
 * of protocols that use this style, including PPP MP (RFC 1990), PWE3 MPLS
 * (RFC 4385), L2TPv2 (RFC 2661), L2TPv3 (RFC 3931), ATM, and Frame Relay.
 * It is guaranteed to reassemble a packet split up to "max_frags" in size,
 * but may manage to reassemble more in certain cases.
 */
WS_DLL_PUBLIC fragment_head *
fragment_add_seq_single(reassembly_table *table, tvbuff_t *tvb,
            const int offset, const packet_info *pinfo, const guint32 id,
            const void* data, const guint32 frag_data_len,
            const gboolean first, const gboolean last,
            const guint32 max_frags);

/*
 * A variation on the above that ages off fragments that have not been
 * reassembled. Useful if the sequence number loops to deal with leftover
 * fragments from the beginning of the capture or missing fragments.
 */
WS_DLL_PUBLIC fragment_head *
fragment_add_seq_single_aging(reassembly_table *table, tvbuff_t *tvb,
            const int offset, const packet_info *pinfo, const guint32 id,
            const void* data, const guint32 frag_data_len,
            const gboolean first, const gboolean last,
            const guint32 max_frags, const guint32 max_age);

/*
 * Start a reassembly, expecting "tot_len" as the number of given fragments (not
 * the number of bytes). Data can be added later using fragment_add_seq_check.
 */
WS_DLL_PUBLIC void
fragment_start_seq_check(reassembly_table *table, const packet_info *pinfo,
			 const guint32 id, const void *data,
			 const guint32 tot_len);

/*
 * Mark end of reassembly and returns the reassembled fragment (if completed).
 * Use it when fragments were added with "more_flags" set while you discovered
 * that no more fragments have to be added.
 * XXX rename to fragment_finish as it works also for fragment_add?
 */
WS_DLL_PUBLIC fragment_head *
fragment_end_seq_next(reassembly_table *table, const packet_info *pinfo,
		      const guint32 id, const void *data);

/* To specify the offset for the fragment numbering, the first fragment is added with 0, and
 * afterwards this offset is set. All additional calls to off_seq_check will calculate
 * the number in sequence in regards to the offset */
WS_DLL_PUBLIC void
fragment_add_seq_offset(reassembly_table *table, const packet_info *pinfo, const guint32 id,
                    const void *data, const guint32 fragment_offset);

/*
 * Sets the expected index for the last block (for fragment_add_seq functions)
 * or the expected number of bytes (for fragment_add functions). A reassembly
 * must already have started.
 *
 * Note that for FD_BLOCKSEQUENCE tot_len is the index for the tail fragment.
 * i.e. since the block numbers start at 0, if we specify tot_len==2, that
 * actually means we want to defragment 3 blocks, block 0, 1 and 2.
 */
WS_DLL_PUBLIC void
fragment_set_tot_len(reassembly_table *table, const packet_info *pinfo,
		     const guint32 id, const void *data, const guint32 tot_len);

/*
 * Similar to fragment_set_tot_len, it sets the expected number of bytes (for
 * fragment_add functions) for a previously started reassembly. If the specified
 * length already matches the reassembled length, then nothing will be done.
 *
 * If the fragments were previously reassembled, then this state will be
 * cleared, allowing new fragments to extend the reassembled result again.
 */
void
fragment_reset_tot_len(reassembly_table *table, const packet_info *pinfo,
		       const guint32 id, const void *data, const guint32 tot_len);

/*
 * Truncates the size of an already defragmented reassembly to tot_len,
 * discarding past that point, including splitting any fragments in the
 * middle as necessary. The specified length must be less than or equal
 * to the reassembled length. (If it already matches the reassembled length,
 * then nothing will be done.)
 *
 * Used for continuous streams like TCP, where the length of a segment cannot
 * be determined without first reassembling and handing to a subdissector.
 */
void
fragment_truncate(reassembly_table *table, const packet_info *pinfo,
		       const guint32 id, const void *data, const guint32 tot_len);

/*
 * Return the expected index for the last block (for fragment_add_seq functions)
 * or the expected number of bytes (for fragment_add functions).
 */
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
 * and then invoke show_fragment_tree to have those items added to the packet
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

/* Initialize internal structures
 */
extern void reassembly_tables_init(void);

/* Cleanup internal structures
 */
extern void
reassembly_table_cleanup(void);

#endif
