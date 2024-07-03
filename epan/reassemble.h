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
	uint32_t frame;			/**< frame number where the fragment is from */
	uint32_t	offset;			/**< fragment number for FD_BLOCKSEQUENCE, byte
					 * offset otherwise */
	uint32_t	len;			/**< fragment length */
	uint32_t flags;			/**< XXX - do some of these apply only to reassembly
					 * heads and others only to fragments within
					 * a reassembly? */
	tvbuff_t *tvb_data;
} fragment_item;

typedef struct _fragment_head {
	struct _fragment_item *next;
	struct _fragment_item *first_gap;	/**< pointer to last fragment before first gap.
					 * NULL if there is no fragment starting at offset 0 */
	unsigned ref_count; 		/**< reference count in reassembled_table */
	uint32_t contiguous_len;	/**< contiguous length from head up to first gap */
	uint32_t frame;			/**< maximum of all frame numbers added to reassembly */
	uint32_t	len;			/**< When flags&FD_BLOCKSEQUENCE and FD_DEFRAGMENTED
					 * are set, the number of bytes of the full datagram.
					 * Otherwise not valid. */
	uint32_t fragment_nr_offset;	/**< offset for frame numbering, for sequences, where the
					 * provided fragment number of the first fragment does
					 * not start with 0 */
	uint32_t datalen;		/**< When flags&FD_BLOCKSEQUENCE is set, the
					 * index of the last block (segments in
					 * datagram + 1); otherwise the number of
					 * bytes of the full datagram. Only valid in
					 * the first item of the fragments list when
					 * flags&FD_DATALEN is set.*/
	uint32_t reassembled_in;		/**< frame where this PDU was reassembled,
					 * only valid when FD_DEFRAGMENTED is set */
	uint8_t reas_in_layer_num;	/**< The current "depth" or layer number in the current
					 * frame where reassembly was completed.
					 * Example: in SCTP there can be several data chunks and
					 * we want the reassembled tvb for the final segment only. */
	uint32_t flags;			/**< XXX - do some of these apply only to reassembly
					 * heads and others only to fragments within
					 * a reassembly? */
	tvbuff_t *tvb_data;
	/**
	 * Null if the reassembly had no error; non-null if it had
	 * an error, in which case it's the string for the error.
	 */
	const char *error;
} fragment_head;

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
typedef void * (*fragment_temporary_key)(const packet_info *pinfo,
    const uint32_t id, const void *data);

/*
 * Like fragment_temporary_key, but used for identifying reassembled fragments
 * which may persist through multiple packets.
 */
typedef void * (*fragment_persistent_key)(const packet_info *pinfo,
    const uint32_t id, const void *data);

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
 *
 * @note Reused keys are assumed to refer to the same reassembled message
 * (i.e., retransmission). If the same "id" is used more than once on a
 * connection, then "data" and custom reassembly_table_functions should be
 * used so that the keys hash differently.
 */
WS_DLL_PUBLIC fragment_head *
fragment_add(reassembly_table *table, tvbuff_t *tvb, const int offset,
	     const packet_info *pinfo, const uint32_t id, const void *data,
	     const uint32_t frag_offset, const uint32_t frag_data_len,
	     const bool more_frags);
/*
 * Like fragment_add, except that the fragment may be added to multiple
 * reassembly tables. This is needed when multiple protocol layers try
 * to add the same packet to the reassembly table.
 */
WS_DLL_PUBLIC fragment_head *
fragment_add_multiple_ok(reassembly_table *table, tvbuff_t *tvb,
			 const int offset, const packet_info *pinfo,
			 const uint32_t id, const void *data,
			 const uint32_t frag_offset,
			 const uint32_t frag_data_len,
			 const bool more_frags);

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
                          const uint32_t id, const void *data,
                          const uint32_t frag_offset,
                          const uint32_t frag_data_len,
                          const bool more_frags, const uint32_t frag_frame);
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
 *
 * @note Completed reassemblies are removed from the in-progress table, so
 * key can be reused to begin a new reassembled message. Conversely,
 * dissectors SHOULD NOT call this with a retransmitted fragment of a
 * completed reassembly. Dissectors atop a reliable protocol like TCP
 * may assume that the lower layer dissector handles retransmission,
 * but other dissectors (e.g., atop UDP or Ethernet) will have to handle
 * that situation themselves.
 */
WS_DLL_PUBLIC fragment_head *
fragment_add_check(reassembly_table *table, tvbuff_t *tvb, const int offset,
		   const packet_info *pinfo, const uint32_t id,
		   const void *data, const uint32_t frag_offset,
		   const uint32_t frag_data_len, const bool more_frags);

/*
 * Like fragment_add_check, but handles retransmissions after reassembly.
 *
 * Start new reassembly only if there is no reassembly in progress and there
 * is no completed reassembly reachable from fallback_frame. If there is
 * completed reassembly (reachable from fallback_frame), simply links this
 * packet into the list, updating the flags if necessary (however actual data
 * and reassembled in frame won't be modified).
 */
WS_DLL_PUBLIC fragment_head *
fragment_add_check_with_fallback(reassembly_table *table, tvbuff_t *tvb, const int offset,
		   const packet_info *pinfo, const uint32_t id,
		   const void *data, const uint32_t frag_offset,
		   const uint32_t frag_data_len, const bool more_frags,
		   const uint32_t fallback_frame);

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
 *
 * @note Reused keys are assumed to refer to the same reassembled message
 * (i.e., retransmission). If the same "id" is used more than once on a
 * connection, then "data" and custom reassembly_table_functions should be
 * used so that the keys hash differently.
 */
WS_DLL_PUBLIC fragment_head *
fragment_add_seq(reassembly_table *table, tvbuff_t *tvb, const int offset,
		 const packet_info *pinfo, const uint32_t id, const void *data,
		 const uint32_t frag_number, const uint32_t frag_data_len,
		 const bool more_frags, const uint32_t flags);

/*
 * Like fragment_add_seq, but maintains a table for completed reassemblies
 * just like fragment_add_check.
 *
 * @note Completed reassemblies are removed from the in-progress table, so
 * key can be reused to begin a new reassembled message. Conversely,
 * dissectors SHOULD NOT call this with a retransmitted fragment of a
 * completed reassembly. Dissectors atop a reliable protocol like TCP
 * may assume that the lower layer dissector handles retransmission,
 * but other dissectors (e.g., atop UDP or Ethernet) will have to handle
 * that situation themselves.
 */
WS_DLL_PUBLIC fragment_head *
fragment_add_seq_check(reassembly_table *table, tvbuff_t *tvb, const int offset,
		       const packet_info *pinfo, const uint32_t id,
		       const void *data,
		       const uint32_t frag_number, const uint32_t frag_data_len,
		       const bool more_frags);

/*
 * Like fragment_add_seq_check, but immediately returns a fragment list for a
 * new fragment. This is a workaround specific for the 802.11 dissector, do not
 * use it elsewhere.
 */
WS_DLL_PUBLIC fragment_head *
fragment_add_seq_802_11(reassembly_table *table, tvbuff_t *tvb,
			const int offset, const packet_info *pinfo,
			const uint32_t id, const void *data,
			const uint32_t frag_number, const uint32_t frag_data_len,
			const bool more_frags);

/*
 * Like fragment_add_seq_check, but without explicit fragment number. Fragments
 * are simply appended until no "more_frags" is false.
 *
 * @note Out of order fragments will not be reassembled correctly.
 * Dissectors atop a reliable protocol like TCP may rely on the lower
 * level dissector reordering out or order segments (if the appropriate
 * out of order reassembly preference is enabled), but other dissectors
 * will have to handle out of order fragments themselves, if possible.
 */
WS_DLL_PUBLIC fragment_head *
fragment_add_seq_next(reassembly_table *table, tvbuff_t *tvb, const int offset,
		      const packet_info *pinfo, const uint32_t id,
		      const void *data, const uint32_t frag_data_len,
		      const bool more_frags);

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
            const int offset, const packet_info *pinfo, const uint32_t id,
            const void* data, const uint32_t frag_data_len,
            const bool first, const bool last,
            const uint32_t max_frags);

/*
 * A variation on the above that ages off fragments that have not been
 * reassembled. Useful if the sequence number loops to deal with leftover
 * fragments from the beginning of the capture or missing fragments.
 */
WS_DLL_PUBLIC fragment_head *
fragment_add_seq_single_aging(reassembly_table *table, tvbuff_t *tvb,
            const int offset, const packet_info *pinfo, const uint32_t id,
            const void* data, const uint32_t frag_data_len,
            const bool first, const bool last,
            const uint32_t max_frags, const uint32_t max_age);

/*
 * Start a reassembly, expecting "tot_len" as the number of given fragments (not
 * the number of bytes). Data can be added later using fragment_add_seq_check.
 */
WS_DLL_PUBLIC void
fragment_start_seq_check(reassembly_table *table, const packet_info *pinfo,
			 const uint32_t id, const void *data,
			 const uint32_t tot_len);

/*
 * Mark end of reassembly and returns the reassembled fragment (if completed).
 * Use it when fragments were added with "more_flags" set while you discovered
 * that no more fragments have to be added.
 * This is for fragments added with add_seq_next; it doesn't check for gaps,
 * and doesn't set datalen correctly for the fragment_add family.
 */
WS_DLL_PUBLIC fragment_head *
fragment_end_seq_next(reassembly_table *table, const packet_info *pinfo,
		      const uint32_t id, const void *data);

/* To specify the offset for the fragment numbering, the first fragment is added with 0, and
 * afterwards this offset is set. All additional calls to off_seq_check will calculate
 * the number in sequence in regards to the offset */
WS_DLL_PUBLIC void
fragment_add_seq_offset(reassembly_table *table, const packet_info *pinfo, const uint32_t id,
                    const void *data, const uint32_t fragment_offset);

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
		     const uint32_t id, const void *data, const uint32_t tot_len);

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
		       const uint32_t id, const void *data, const uint32_t tot_len);

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
		       const uint32_t id, const void *data, const uint32_t tot_len);

/*
 * Return the expected index for the last block (for fragment_add_seq functions)
 * or the expected number of bytes (for fragment_add functions).
 */
WS_DLL_PUBLIC uint32_t
fragment_get_tot_len(reassembly_table *table, const packet_info *pinfo,
		     const uint32_t id, const void *data);

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
				const packet_info *pinfo, const uint32_t id,
				const void *data);

/* This function is used to check if there is partial or completed reassembly state
 * matching this packet. I.e. Are there reassembly going on or not for this packet?
 */
WS_DLL_PUBLIC fragment_head *
fragment_get(reassembly_table *table, const packet_info *pinfo,
	     const uint32_t id, const void *data);

/* The same for the reassemble table */
WS_DLL_PUBLIC fragment_head *
fragment_get_reassembled_id(reassembly_table *table, const packet_info *pinfo,
			    const uint32_t id);

/* This will free up all resources and delete reassembly state for this PDU.
 * Except if the PDU is completely reassembled, then it would NOT deallocate the
 * buffer holding the reassembled data but instead return the TVB
 *
 * So, if you call fragment_delete and it returns non-NULL, YOU are responsible to
 * tvb_free() .
 */
WS_DLL_PUBLIC tvbuff_t *
fragment_delete(reassembly_table *table, const packet_info *pinfo,
		const uint32_t id, const void *data);

/* This struct holds references to all the tree and field handles used when
 * displaying the reassembled fragment tree in the packet details view. A
 * dissector will populate this structure with its own tree and field handles
 * and then invoke show_fragment_tree to have those items added to the packet
 * details tree.
 */
typedef struct _fragment_items {
    int        *ett_fragment;
    int        *ett_fragments;

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
    bool *update_col_infop, proto_tree *tree);

WS_DLL_PUBLIC bool
show_fragment_tree(fragment_head *ipfd_head, const fragment_items *fit,
    proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, proto_item **fi);

WS_DLL_PUBLIC bool
show_fragment_seq_tree(fragment_head *ipfd_head, const fragment_items *fit,
    proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, proto_item **fi);

/* Initialize internal structures
 */
extern void reassembly_tables_init(void);

/* Cleanup internal structures
 */
extern void
reassembly_table_cleanup(void);

/* ===================== Streaming data reassembly helper ===================== */
/**
 * Macro to help to define ett or hf items variables for reassembly (especially for streaming reassembly).
 * The statement:
 *
 *     REASSEMBLE_ITEMS_DEFINE(foo_body, "Foo Body");  // in global scope
 *
 * will create global variables:
 *
 *     static int ett_foo_body_fragment;
 *     static int ett_foo_body_fragments;
 *     static int hf_foo_body_fragment;
 *     static int hf_foo_body_fragments;
 *     static int hf_foo_body_fragment_overlap;
 *     ...
 *     static int hf_foo_body_segment;
 *
 *     static const fragment_items foo_body_fragment_items = {
 *         &ett_foo_body_fragment,
 *         &ett_foo_body_fragments,
 *         &hf_foo_body_fragments,
 *         &hf_foo_body_fragment,
 *         &hf_foo_body_fragment_overlap,
 *         ...
 *         "Foo Body fragments"
 *     };
 */
#define REASSEMBLE_ITEMS_DEFINE(var_prefix, name_prefix) \
    static int ett_##var_prefix##_fragment; \
    static int ett_##var_prefix##_fragments; \
    static int hf_##var_prefix##_fragments; \
    static int hf_##var_prefix##_fragment; \
    static int hf_##var_prefix##_fragment_overlap; \
    static int hf_##var_prefix##_fragment_overlap_conflicts; \
    static int hf_##var_prefix##_fragment_multiple_tails; \
    static int hf_##var_prefix##_fragment_too_long_fragment; \
    static int hf_##var_prefix##_fragment_error; \
    static int hf_##var_prefix##_fragment_count; \
    static int hf_##var_prefix##_reassembled_in; \
    static int hf_##var_prefix##_reassembled_length; \
    static int hf_##var_prefix##_reassembled_data; \
    static int hf_##var_prefix##_segment; \
    static const fragment_items var_prefix##_fragment_items = { \
        &ett_##var_prefix##_fragment, \
        &ett_##var_prefix##_fragments, \
        &hf_##var_prefix##_fragments, \
        &hf_##var_prefix##_fragment, \
        &hf_##var_prefix##_fragment_overlap, \
        &hf_##var_prefix##_fragment_overlap_conflicts, \
        &hf_##var_prefix##_fragment_multiple_tails, \
        &hf_##var_prefix##_fragment_too_long_fragment, \
        &hf_##var_prefix##_fragment_error, \
        &hf_##var_prefix##_fragment_count, \
        &hf_##var_prefix##_reassembled_in, \
        &hf_##var_prefix##_reassembled_length, \
        &hf_##var_prefix##_reassembled_data, \
        name_prefix " fragments" \
    }

/**
 * Macro to help to initialize hf (head field) items for reassembly.
 * The statement:
 *
 *     void proto_register_foo(void) {
 *         static hf_register_info hf[] = {
 *             ...
 *             { &hf_proto_foo_payload,
 *                 { "Payload", "foo.payload",
 *                     FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
 *             },
 *
 *             // Add fragments items
 *             REASSEMBLE_INIT_HF_ITEMS(foo_body, "Foo Body", "foo.body"),
 *             ...
 *         };
 *         ...
 *     }
 *
 * will expand like:
 *
 *     void proto_register_foo(void) {
 *         static hf_register_info hf[] = {
 *             ...
 *             { &hf_proto_foo_payload,
 *                 { "Payload", "foo.payload",
 *                     FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
 *             },
 *
 *             // Add fragments items
 *             { &hf_foo_body_fragments, \
 *                 { "Reassembled Foo Body fragments", "foo.body.fragments", \
 * 	                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } \
 *             },
 *             { &hf_foo_body_fragment, \
 *                 { "Foo Body fragment", "foo.body.fragment", \
 * 	                FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } \
 *             },
 *             { &hf_foo_body_fragment_overlap, \
 *                 { "Foo Body fragment overlap", "foo.body.fragment.overlap", \
 *                     FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } \
 *             },
 *             ...
 *         };
 *         ...
 *     }
 */
#define REASSEMBLE_INIT_HF_ITEMS(var_prefix, name_prefix, abbrev_prefix) \
	    { &hf_##var_prefix##_fragments, \
            { "Reassembled " name_prefix " fragments", abbrev_prefix ".fragments", \
                FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } \
        }, \
        { &hf_##var_prefix##_fragment, \
            { name_prefix " fragment", abbrev_prefix ".fragment", \
                FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } \
        }, \
        { &hf_##var_prefix##_fragment_overlap, \
            { name_prefix " fragment overlap", abbrev_prefix ".fragment.overlap", \
                FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } \
        }, \
        { &hf_##var_prefix##_fragment_overlap_conflicts, \
            { name_prefix " fragment overlapping with conflicting data", abbrev_prefix ".fragment.overlap.conflicts", \
                FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } \
        }, \
        { &hf_##var_prefix##_fragment_multiple_tails, \
            { name_prefix " has multiple tail fragments", abbrev_prefix ".fragment.multiple_tails", \
                FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } \
        }, \
        { &hf_##var_prefix##_fragment_too_long_fragment, \
            { name_prefix " fragment too long", abbrev_prefix ".fragment.too_long_fragment", \
                FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } \
        }, \
        { &hf_##var_prefix##_fragment_error, \
            { name_prefix " defragment error", abbrev_prefix ".fragment.error", \
                FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } \
        }, \
        { &hf_##var_prefix##_fragment_count, \
            { name_prefix " fragment count", abbrev_prefix ".fragment.count", \
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } \
        }, \
        { &hf_##var_prefix##_reassembled_in, \
            { "Reassembled in", abbrev_prefix ".reassembled.in", \
                FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } \
        }, \
        { &hf_##var_prefix##_reassembled_length, \
            { "Reassembled length", abbrev_prefix ".reassembled.length", \
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } \
        }, \
        { &hf_##var_prefix##_reassembled_data, \
            { "Reassembled data", abbrev_prefix ".reassembled.data", \
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } \
        }, \
        { &hf_##var_prefix##_segment, \
            { name_prefix " segment", abbrev_prefix ".segment", \
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL} \
        }

/**
 * Macro to help to initialize protocol subtree (ett) items for reassembly.
 * The statement:
 *
 *     void proto_register_foo(void) {
 *         ...
 *         static int* ett[] = {
 *             &ett_foo_abc,
 *             ...
 *             // Add ett items
 *             REASSEMBLE_INIT_ETT_ITEMS(foo_body),
 *             ...
 *         };
 *         ...
 *     }
 *
 * will expand like:
 *
 *     void proto_register_foo(void) {
 *         ...
 *         static int* ett[] = {
 *             &ett_foo_abc,
 *             ...
 *             // Add ett items
 *             &ett_foo_body_fragment,
 *             &ett_foo_body_fragments,
 *             ...
 *         };
 *         ...
 *     }
 */
#define REASSEMBLE_INIT_ETT_ITEMS(var_prefix) \
        &ett_##var_prefix##_fragment, \
        &ett_##var_prefix##_fragments

/** a private structure for keeping streaming reassembly information  */
typedef struct streaming_reassembly_info_t streaming_reassembly_info_t;

/**
 * Allocate a streaming reassembly information in wmem_file_scope.
 */
WS_DLL_PUBLIC streaming_reassembly_info_t*
streaming_reassembly_info_new(void);

/**
 * This function provides a simple way to reassemble the streaming data of a higher level
 * protocol that is not on top of TCP but on another protocol which might be on top of TCP.
 *
 * For example, suppose there are two streaming protocols ProtoA and ProtoB. ProtoA is a protocol on top
 * of TCP. ProtoB is a protocol on top of ProtoA.
 *
 * ProtoA dissector should use tcp_dissect_pdus() or pinfo->can_desegment/desegment_offset/desegment_len
 * to reassemble its own messages on top of TCP. After the PDUs of ProtoA are reassembled, ProtoA dissector
 * can call reassemble_streaming_data_and_call_subdissector() to help ProtoB dissector to reassemble the
 * PDUs of ProtoB. ProtoB needs to use fields pinfo->can_desegment/desegment_offset/desegment_len to tell
 * its requirements about reassembly (to reassemble_streaming_data_and_call_subdissector()).
 *
 * -----            +-- Reassembled ProtoB PDU --+-- Reassembled ProtoB PDU --+-- Reassembled ProtoB PDU --+----------------
 * ProtoB:          | ProtoB header and payload  | ProtoB header and payload  | ProtoB header and payload  |            ...
 *                  +----------------------------+---------+------------------+--------+-------------------+--+-------------
 * -----            ^ >>> Reassemble with reassemble_streaming_data_and_call_subdissector() and pinfo->desegment_len.. <<< ^
 *                  +----------------------------+---------+------------------+--------+-------------------+--+-------------
 *                  |           ProtoA payload1            |      ProtoA payload2      |    ProtoA payload3   |         ...
 *                  +--------------------------------------+---------------------------+----------------------+-------------
 *                  ^                                      ^                           ^                      ^
 *                  |         >>> Do de-chunk <<<          |\   >>> Do de-chunk <<<     \  \ >>> Do de-chunk <<< \
 *                  |                                      |  \                           \    \                    \
 *                  |                                      |    \                           \      \                ...
 *                  |                                      |      \                           \        \                 \
 *         +-------- First Reassembled ProtoA PDU ---------+-- Second Reassembled ProtoA PDU ---+- Third Reassembled Prot...
 * ProtoA: | Header |           ProtoA payload1            | Header |       ProtoA payload2     | Header | ProtoA payload3 .
 *         +--------+----------------------+---------------+--------+---------------------------+--------+-+----------------
 * -----   ^     >>> Reassemble with tcp_dissect_pdus() or pinfo->can_desegment/desegment_offset/desegment_len <<<         ^
 *         +--------+----------------------+---------------+--------+---------------------------+--------+-+----------------
 * TCP:    |          TCP segment          |          TCP segment          |          TCP segment          |            ...
 * -----   +-------------------------------+-------------------------------+-------------------------------+----------------
 *
 * The function reassemble_streaming_data_and_call_subdissector() uses fragment_add() and process_reassembled_data()
 * to complete its reassembly task.
 *
 * The reassemble_streaming_data_and_call_subdissector() will handle many cases. The most complicated one is:
 *
 * +-------------------------------------- Payload of a ProtoA PDU -----------------------------------------------+
 * | EoMSP: end of a multisegment PDU | OmNFP: one or more non-fragment PDUs | BoMSP: begin of a multisegment PDU |
 * +----------------------------------+--------------------------------------+------------------------------------+
 * Note, we use short name 'MSP' for 'Multisegment PDU', and 'NFP' for 'Non-fragment PDU'.
 *
 * In this case, the payload of a ProtoA PDU contains:
 * - EoMSP (Part1): At the begin of the ProtoA payload, there is the last part of a multisegment PDU of ProtoB.
 * - OmNFP (Part2): The middle part of ProtoA payload payload contains one or more non-fragment PDUs of ProtoB.
 * - BoMSP (Part3): At the tail of the ProtoA payload, there is the begin of a new multisegment PDU of ProtoB.
 *
 * All of three parts are optional. For example, one ProtoA payload could contain only EoMSP, OmNFP or BoMSP; or contain
 * EoMSP and OmNFP without BoMSP; or contain EoMSP and BoMSP without OmNFP; or contain OmNFP and BoMSP without
 * EoMSP.
 *
 *           +---- A ProtoB MSP ---+       +-- A ProtoB MSP --+-- A ProtoB MSP --+          +-- A ProtoB MSP --+
 *           |                     |       |                  |                  |          |                  |
 * +- A ProtoA payload -+  +-------+-------+-------+  +-------+-------+  +-------+-------+  +-------+  +-------+  +-------+
 * |  OmNFP  |  BoMSP   |  | EoMSP | OmNFP | BoMSP |  | EoMSP | BoMSP |  | EoMSP | OmNFP |  | BoMSP |  | EoMSP |  | OmNFP |
 * +---------+----------+  +-------+-------+-------+  +-------+-------+  +-------+-------+  +-------+  +-------+  +-------+
 *           |                     |       |                  |                  |          |                  |
 *           +---------------------+       +------------------+------------------+          +------------------+
 *
 * And another case is the entire ProtoA payload is one of middle parts of a multisegment PDU. We call it:
 * - MoMSP: The middle part of a multisegment PDU of ProtoB.
 *
 * Following case shows a multisegment PDU composed of [BoMSP + MoMSP + MoMSP + MoMSP + EoMSP]:
 *
 *                 +------------------ A Multisegment PDU of ProtoB ----------------------+
 *                 |                                                                      |
 * +--- ProtoA payload1 ---+   +- payload2 -+  +- Payload3 -+  +- Payload4 -+   +- ProtoA payload5 -+
 * | EoMSP | OmNFP | BoMSP |   |    MoMSP   |  |    MoMSP   |  |    MoMSP   |   |  EoMSP  |  BoMSP  |
 * +-------+-------+-------+   +------------+  +------------+  +------------+   +---------+---------+
 *                 |                                                                      |
 *                 +----------------------------------------------------------------------+
 *
 * The function reassemble_streaming_data_and_call_subdissector() will handle all of the above cases and manage
 * the information used during the reassembly. The caller (ProtoA dissector) only needs to initialize the relevant
 * variables and pass these variables and its own completed payload to this function.
 *
 * The subdissector (ProtoB dissector) needs to set the pinfo->desegment_len to cooperate with the function
 * reassemble_streaming_data_and_call_subdissector() to complete the reassembly task.
 * The pinfo->desegment_len should be DESEGMENT_ONE_MORE_SEGMENT or contain the estimated number of additional bytes required for completing
 * the current PDU (MSP), and set pinfo->desegment_offset to the offset in the tvbuff at which the dissector will
 * continue processing when next called. Next time the subdissector is called, it will be passed a tvbuff composed
 * of the end of the data from the previous tvbuff together with desegment_len more bytes. If the dissector cannot
 * tell how many more bytes it will need, it should set pinfo->desegment_len to DESEGMENT_ONE_MORE_SEGMENT or additional bytes required for parsing
 * message head. It will then be called again as soon as more data becomes available. Subdissector MUST NOT set the
 * pinfo->desegment_len to DESEGMENT_UNTIL_FIN, we don't support it yet.
 *
 * Note that if the subdissector sets pinfo->desegment_len to additional bytes required for parsing the header of
 * the message rather than the entire message when the length of entire message is unable to be determined, it MUST
 * return the length of the tvb handled by itself (for example, return 0 length if nothing is parsed in MoMSP),
 * otherwise it may cause some unexpected dissecting errors. However, if you want to be compatible with TCP's reassembly
 * method by setting the pinfo->desegment_len, you MUST set the pinfo->desegment_len to DESEGMENT_ONE_MORE_SEGMENT
 * when the entire message length cannot be determined, and return a length other than 0 (such as tvb_captured_length(tvb))
 * when exiting the subdissector dissect function (such as dissect_proto_b()).
 *
 * Following is sample code of ProtoB which on top of ProtoA mentioned above:
 * <code>
 *     // file packet-proto-b.c
 *     ...
 *
 *     static int
 *     dissect_proto_b(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
 *     {
 *         while (offset < tvb_len)
 *         {
 *             if (tvb_len - offset < PROTO_B_MESSAGE_HEAD_LEN) {
 *                 // need at least X bytes for getting a ProtoB message
 *                 if (pinfo->can_desegment) {
 *                     pinfo->desegment_offset = offset;
 *                     // It is strongly recommended to set pinfo->desegment_len to DESEGMENT_ONE_MORE_SEGMENT
 *                     // if the length of entire message is unknown.
 *                     pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
 *                     return tvb_len; // MUST return a length other than 0
 *
 *                     // Or set pinfo->desegment_len to how many additional bytes needed to parse head of
 *                     // a ProtoB message.
 *                     // pinfo->desegment_len = PROTO_B_MESSAGE_HEAD_LEN - (tvb_len - offset);
 *                     // return offset; // But you MUST return the length handled by ProtoB
 *                 }
 *                 ...
 *     	       }
 *             ...
 *             // e.g. length is at offset 4
 *             body_len = (unsigned)tvb_get_ntohl(tvb, offset + 4);
 *
 *             if (tvb_len - offset - PROTO_B_MESSAGE_HEAD_LEN < body_len) {
 *                 // need X bytes for dissecting a ProtoB message
 *                 if (pinfo->can_desegment) {
 *                     pinfo->desegment_offset = offset;
 *                     // calculate how many additional bytes need to parsing body of a ProtoB message
 *                     pinfo->desegment_len = body_len - (tvb_len - offset - PROTO_B_MESSAGE_HEAD_LEN);
 *                     // MUST return a length other than 0, if DESEGMENT_ONE_MORE_SEGMENT is used previously.
 *                     return tvb_len;
 *
 *                     // MUST return the length handled by ProtoB,
 *                     // if 'pinfo->desegment_len = PROTO_B_MESSAGE_HEAD_LEN - (tvb_len - offset);' is used previously.
 *                     // return offset;
 *                 }
 *                 ...
 *             }
 *             ...
 *         }
 *         return tvb_len; // all bytes of this tvb are parsed
 *     }
 * </code>
 *
 * Following is sample code of ProtoA mentioned above:
 * <code>
 *     // file packet-proto-a.c
 *     ...
 *     // reassembly table for streaming chunk mode
 *     static reassembly_table proto_a_streaming_reassembly_table;
 *     ...
 *     // heads for displaying reassembly information
 *     static int hf_msg_fragments;
 *     static int hf_msg_fragment;
 *     static int hf_msg_fragment_overlap;
 *     static int hf_msg_fragment_overlap_conflicts;
 *     static int hf_msg_fragment_multiple_tails;
 *     static int hf_msg_fragment_too_long_fragment;
 *     static int hf_msg_fragment_error;
 *     static int hf_msg_fragment_count;
 *     static int hf_msg_reassembled_in;
 *     static int hf_msg_reassembled_length;
 *     static int hf_msg_body_segment;
 *     ...
 *     static int ett_msg_fragment;
 *     static int ett_msg_fragments;
 *     ...
 *     static const fragment_items msg_frag_items = {
 *         &ett_msg_fragment,
 *         &ett_msg_fragments,
 *         &hf_msg_fragments,
 *         &hf_msg_fragment,
 *         &hf_msg_fragment_overlap,
 *         &hf_msg_fragment_overlap_conflicts,
 *         &hf_msg_fragment_multiple_tails,
 *         &hf_msg_fragment_too_long_fragment,
 *         &hf_msg_fragment_error,
 *         &hf_msg_fragment_count,
 *         &hf_msg_reassembled_in,
 *         &hf_msg_reassembled_length,
 *         "ProtoA Message fragments"
 *     };
 *     ...
 *     static int
 *     dissect_proto_a(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
 *     {
 *         ...
 *         streaming_reassembly_info_t* streaming_reassembly_info = NULL;
 *         ...
 *         proto_a_tree = proto_item_add_subtree(ti, ett_proto_a);
 *         ...
 *         if (!PINFO_FD_VISITED(pinfo)) {
 *             streaming_reassembly_info = streaming_reassembly_info_new();
 *             // save streaming reassembly info in the stream conversation or something like that
 *             save_reassembly_info(pinfo, stream_id, flow_dir, streaming_reassembly_info);
 *         } else {
 *             streaming_reassembly_info = get_reassembly_info(pinfo, stream_id, flow_dir);
 *         }
 *         ...
 *         while (offset < tvb_len)
 *         {
 *             ...
 *             payload_len = xxx;
 *             ...
 *             if (dissecting_in_streaming_mode) {
 *                 // reassemble and call subdissector
 *                 reassemble_streaming_data_and_call_subdissector(tvb, pinfo, offset,
 *                     payload_len, proto_a_tree, proto_tree_get_parent_tree(proto_a_tree),
 *                     proto_a_streaming_reassembly_table, streaming_reassembly_info,
 *                     get_virtual_frame_num64(tvb, pinfo, offset), subdissector_handle,
 *                     proto_tree_get_parent_tree(tree), NULL,
 *                     "ProtoA", &msg_frag_items, hf_msg_body_segment);
 *             ...
 *         }
 *     }
 *
 *     ...
 *     void proto_register_proto_a(void) {
 *         ...
 *         static hf_register_info hf[] = {
 *             ...
 *             {&hf_msg_fragments,
 *                 {"Reassembled ProtoA Message fragments", "protoa.msg.fragments",
 *                 FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },
 *             {&hf_msg_fragment,
 *                 {"Message fragment", "protoa.msg.fragment",
 *                 FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
 *             {&hf_msg_fragment_overlap,
 *                 {"Message fragment overlap", "protoa.msg.fragment.overlap",
 *                 FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
 *             {&hf_msg_fragment_overlap_conflicts,
 *                 {"Message fragment overlapping with conflicting data",
 *                 "protoa.msg.fragment.overlap.conflicts",
 *                 FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
 *             {&hf_msg_fragment_multiple_tails,
 *                 {"Message has multiple tail fragments",
 *                 "protoa.msg.fragment.multiple_tails",
 *                 FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
 *             {&hf_msg_fragment_too_long_fragment,
 *                 {"Message fragment too long", "protoa.msg.fragment.too_long_fragment",
 *                 FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
 *             {&hf_msg_fragment_error,
 *                 {"Message defragmentation error", "protoa.msg.fragment.error",
 *                 FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
 *             {&hf_msg_fragment_count,
 *                 {"Message fragment count", "protoa.msg.fragment.count",
 *                 FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
 *             {&hf_msg_reassembled_in,
 *                 {"Reassembled in", "protoa.msg.reassembled.in",
 *                 FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
 *             {&hf_msg_reassembled_length,
 *                 {"Reassembled length", "protoa.msg.reassembled.length",
 *                 FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
 *             {&hf_msg_body_segment,
 *                 {"ProtoA body segment", "protoa.msg.body.segment",
 *                 FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL } },
 *         }
 *         ...
 *         static int *ett[] = {
 *             ...
 *             &ett_msg_fragment,
 *             &ett_msg_fragments
 *         }
 *         ...
 *         reassembly_table_register(&proto_a_streaming_reassembly_table,
 *                                    &addresses_ports_reassembly_table_functions);
 *         ...
 *     }
 * </code>
 *
 * Alternatively, the code of ProtoA (packet-proto-a.c) can be made simpler with helper macros:
 * <code>
 *     // file packet-proto-a.c
 *     ...
 *     // reassembly table for streaming chunk mode
 *     static reassembly_table proto_a_streaming_reassembly_table;
 *     // reassembly head field items definition
 *     REASSEMBLE_ITEMS_DEFINE(proto_a_body, "ProtoA Body");
 *     ...
 *     static int
 *     dissect_proto_a(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
 *     {
 *         ...
 *         streaming_reassembly_info_t* streaming_reassembly_info = NULL;
 *         ...
 *         proto_a_tree = proto_item_add_subtree(ti, ett_proto_a);
 *         ...
 *         if (!PINFO_FD_VISITED(pinfo)) {
 *             streaming_reassembly_info = streaming_reassembly_info_new();
 *             // save streaming reassembly info in the stream conversation or something like that
 *             save_reassembly_info(pinfo, stream_id, flow_dir, streaming_reassembly_info);
 *         } else {
 *             streaming_reassembly_info = get_reassembly_info(pinfo, stream_id, flow_dir);
 *         }
 *         ...
 *         while (offset < tvb_len)
 *         {
 *             ...
 *             payload_len = xxx;
 *             ...
 *             if (dissecting_in_streaming_mode) {
 *                 // reassemble and call subdissector
 *                 reassemble_streaming_data_and_call_subdissector(tvb, pinfo, offset,
 *                     payload_len, proto_a_tree, proto_tree_get_parent_tree(proto_a_tree),
 *                     proto_a_streaming_reassembly_table, streaming_reassembly_info,
 *                     get_virtual_frame_num64(tvb, pinfo, offset), subdissector_handle,
 *                     proto_tree_get_parent_tree(tree), NULL, "ProtoA Body",
 *                     &proto_a_body_fragment_items, hf_proto_a_body_segment);
 *             ...
 *         }
 *     }
 *
 *     ...
 *     void proto_register_proto_a(void) {
 *         ...
 *         static hf_register_info hf[] = {
 *             ...
 *             REASSEMBLE_INIT_HF_ITEMS(proto_a_body, "ProtoA Body", "protoa.body")
 *         }
 *         ...
 *         static int *ett[] = {
 *             ...
 *             REASSEMBLE_INIT_ETT_ITEMS(proto_a_body)
 *         }
 *         ...
 *         reassembly_table_register(&proto_a_streaming_reassembly_table,
 *                                    &addresses_ports_reassembly_table_functions);
 *         ...
 *     }
 * </code>
 *
 * @param  tvb            TVB contains (ProtoA) payload which will be passed to subdissector.
 * @param  pinfo          Packet information.
 * @param  offset         The beginning offset of payload in TVB.
 * @param  length         The length of payload in TVB.
 * @param  segment_tree   The tree for adding segment items.
 * @param  reassembled_tree   The tree for adding reassembled information items.
 * @param  streaming_reassembly_table   The reassembly table used for this kind of streaming reassembly.
 * @param  reassembly_info   The structure for keeping streaming reassembly information. This should be initialized
 *                           by streaming_reassembly_info_new(). Subdissector should keep it for each flow of per stream,
 *                           like per direction flow of a STREAM of HTTP/2 or each request or response message flow of
 *                           HTTP/1.1 chunked stream.
 * @param  cur_frame_num     The uniq index of current payload and number must always be increasing from the previous frame
 *                           number, so we can use "<" and ">" comparisons to determine before and after in time. You can use
 *                           get_virtual_frame_num64() if the ProtoA does not has a suitable field representing payload frame num.
 * @param  subdissector_handle   The subdissector the reassembly for. We will call subdissector for reassembly and dissecting.
 *                               The subdissector should set pinfo->desegment_len to the length it needed if the payload is
 *                               not enough for it to dissect.
 * @param  subdissector_tree     The tree to be passed to subdissector.
 * @param  subdissector_data     The data argument to be passed to subdissector.
 * @param  label                 The name of the data being reassembling. It can just be the name of protocol (ProtoA), for
 *                               example, "[ProtoA segment of a reassembled PDU]".
 * @param  frag_hf_items         The fragment field items for displaying fragment and reassembly information in tree. Please
 *                               refer to process_reassembled_data().
 * @param  hf_segment_data       The field item to show something like "ProtoA segment data (123 bytes)".
 *
 * @return Handled data length. Just equal to the length argument now.
 */
WS_DLL_PUBLIC int
reassemble_streaming_data_and_call_subdissector(
	tvbuff_t* tvb, packet_info* pinfo, unsigned offset, int length,
	proto_tree* segment_tree, proto_tree* reassembled_tree, reassembly_table streaming_reassembly_table,
	streaming_reassembly_info_t* reassembly_info, uint64_t cur_frame_num,
	dissector_handle_t subdissector_handle, proto_tree* subdissector_tree, void* subdissector_data,
	const char* label, const fragment_items* frag_hf_items, int hf_segment_data
);

/**
 * Return a 64 bits virtual frame number that is identified as follows:
 *
 * +--- 32 bits ---+--------- 8 bits -------+----- 24 bits --------------+
 * |  pinfo->num   | pinfo->curr_layer_num  |  tvb->raw_offset + offset  |
 * +---------------------------------------------------------------------+
 *
 * This allows for a single virtual frame to be uniquely identified across a capture with the
 * added benefit that the number will always be increasing from the previous virtual frame so
 * we can use "<" and ">" comparisons to determine before and after in time.
 *
 * This frame number similar to HTTP2 frame number.
 */
static inline uint64_t
get_virtual_frame_num64(tvbuff_t* tvb, packet_info* pinfo, int offset)
{
	return (((uint64_t)pinfo->num) << 32) + (((uint64_t)pinfo->curr_layer_num) << 24)
		+ ((uint64_t)tvb_raw_offset(tvb) + offset);
}

/**
 * How many additional bytes are still expected to complete this reassembly?
 *
 * @return How many additional bytes are expected to complete this reassembly.
 *         It may also be DESEGMENT_ONE_MORE_SEGMENT.
 *         0 means this reassembly is completed.
 */
WS_DLL_PUBLIC int
additional_bytes_expected_to_complete_reassembly(streaming_reassembly_info_t* reassembly_info);

/* ========================================================================= */

#endif
