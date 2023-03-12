/* reassemble.c
 * Routines for {fragment,segment} reassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/reassemble.h>
#include <epan/tvbuff-int.h>

#include <wsutil/str_util.h>
#include <wsutil/ws_assert.h>

/*
 * Functions for reassembly tables where the endpoint addresses, and a
 * fragment ID, are used as the key.
 */
typedef struct _fragment_addresses_key {
	address src;
	address dst;
	guint32 id;
} fragment_addresses_key;

GList* reassembly_table_list = NULL;

static guint
fragment_addresses_hash(gconstpointer k)
{
	const fragment_addresses_key* key = (const fragment_addresses_key*) k;
	guint hash_val;
/*
	int i;
*/

	hash_val = 0;

/*	More than likely: in most captures src and dst addresses are the
	same, and would hash the same.
	We only use id as the hash as an optimization.

	for (i = 0; i < key->src.len; i++)
		hash_val += key->src.data[i];
	for (i = 0; i < key->dst.len; i++)
		hash_val += key->dst.data[i];
*/

	hash_val += key->id;

	return hash_val;
}

static gint
fragment_addresses_equal(gconstpointer k1, gconstpointer k2)
{
	const fragment_addresses_key* key1 = (const fragment_addresses_key*) k1;
	const fragment_addresses_key* key2 = (const fragment_addresses_key*) k2;

	/*
	 * key.id is the first item to compare since it's the item most
	 * likely to differ between sessions, thus short-circuiting
	 * the comparison of addresses.
	 */
	return (key1->id == key2->id) &&
	       (addresses_equal(&key1->src, &key2->src)) &&
	       (addresses_equal(&key1->dst, &key2->dst));
}

/*
 * Create a fragment key for temporary use; it can point to non-
 * persistent data, and so must only be used to look up and
 * delete entries, not to add them.
 */
static gpointer
fragment_addresses_temporary_key(const packet_info *pinfo, const guint32 id,
				 const void *data _U_)
{
	fragment_addresses_key *key = g_slice_new(fragment_addresses_key);

	/*
	 * Do a shallow copy of the addresses.
	 */
	copy_address_shallow(&key->src, &pinfo->src);
	copy_address_shallow(&key->dst, &pinfo->dst);
	key->id = id;

	return (gpointer)key;
}

/*
 * Create a fragment key for permanent use; it must point to persistent
 * data, so that it can be used to add entries.
 */
static gpointer
fragment_addresses_persistent_key(const packet_info *pinfo, const guint32 id,
				  const void *data _U_)
{
	fragment_addresses_key *key = g_slice_new(fragment_addresses_key);

	/*
	 * Do a deep copy of the addresses.
	 */
	copy_address(&key->src, &pinfo->src);
	copy_address(&key->dst, &pinfo->dst);
	key->id = id;

	return (gpointer)key;
}

static void
fragment_addresses_free_temporary_key(gpointer ptr)
{
	fragment_addresses_key *key = (fragment_addresses_key *)ptr;
	g_slice_free(fragment_addresses_key, key);
}

static void
fragment_addresses_free_persistent_key(gpointer ptr)
{
	fragment_addresses_key *key = (fragment_addresses_key *)ptr;

	if(key){
		/*
		 * Free up the copies of the addresses from the old key.
		 */
		free_address(&key->src);
		free_address(&key->dst);

		g_slice_free(fragment_addresses_key, key);
	}
}

const reassembly_table_functions
addresses_reassembly_table_functions = {
	fragment_addresses_hash,
	fragment_addresses_equal,
	fragment_addresses_temporary_key,
	fragment_addresses_persistent_key,
	fragment_addresses_free_temporary_key,
	fragment_addresses_free_persistent_key
};

/*
 * Functions for reassembly tables where the endpoint addresses and ports,
 * and a fragment ID, are used as the key.
 */
typedef struct _fragment_addresses_ports_key {
	address src_addr;
	address dst_addr;
	guint32 src_port;
	guint32 dst_port;
	guint32 id;
} fragment_addresses_ports_key;

static guint
fragment_addresses_ports_hash(gconstpointer k)
{
	const fragment_addresses_ports_key* key = (const fragment_addresses_ports_key*) k;
	guint hash_val;
/*
	int i;
*/

	hash_val = 0;

/*	More than likely: in most captures src and dst addresses and ports
	are the same, and would hash the same.
	We only use id as the hash as an optimization.

	for (i = 0; i < key->src.len; i++)
		hash_val += key->src_addr.data[i];
	for (i = 0; i < key->dst.len; i++)
		hash_val += key->dst_addr.data[i];
	hash_val += key->src_port;
	hash_val += key->dst_port;
*/

	hash_val += key->id;

	return hash_val;
}

static gint
fragment_addresses_ports_equal(gconstpointer k1, gconstpointer k2)
{
	const fragment_addresses_ports_key* key1 = (const fragment_addresses_ports_key*) k1;
	const fragment_addresses_ports_key* key2 = (const fragment_addresses_ports_key*) k2;

	/*
	 * key.id is the first item to compare since it's the item most
	 * likely to differ between sessions, thus short-circuiting
	 * the comparison of addresses and ports.
	 */
	return (key1->id == key2->id) &&
	       (addresses_equal(&key1->src_addr, &key2->src_addr)) &&
	       (addresses_equal(&key1->dst_addr, &key2->dst_addr)) &&
	       (key1->src_port == key2->src_port) &&
	       (key1->dst_port == key2->dst_port);
}

/*
 * Create a fragment key for temporary use; it can point to non-
 * persistent data, and so must only be used to look up and
 * delete entries, not to add them.
 */
static gpointer
fragment_addresses_ports_temporary_key(const packet_info *pinfo, const guint32 id,
				       const void *data _U_)
{
	fragment_addresses_ports_key *key = g_slice_new(fragment_addresses_ports_key);

	/*
	 * Do a shallow copy of the addresses.
	 */
	copy_address_shallow(&key->src_addr, &pinfo->src);
	copy_address_shallow(&key->dst_addr, &pinfo->dst);
	key->src_port = pinfo->srcport;
	key->dst_port = pinfo->destport;
	key->id = id;

	return (gpointer)key;
}

/*
 * Create a fragment key for permanent use; it must point to persistent
 * data, so that it can be used to add entries.
 */
static gpointer
fragment_addresses_ports_persistent_key(const packet_info *pinfo,
					const guint32 id, const void *data _U_)
{
	fragment_addresses_ports_key *key = g_slice_new(fragment_addresses_ports_key);

	/*
	 * Do a deep copy of the addresses.
	 */
	copy_address(&key->src_addr, &pinfo->src);
	copy_address(&key->dst_addr, &pinfo->dst);
	key->src_port = pinfo->srcport;
	key->dst_port = pinfo->destport;
	key->id = id;

	return (gpointer)key;
}

static void
fragment_addresses_ports_free_temporary_key(gpointer ptr)
{
	fragment_addresses_ports_key *key = (fragment_addresses_ports_key *)ptr;
	g_slice_free(fragment_addresses_ports_key, key);
}

static void
fragment_addresses_ports_free_persistent_key(gpointer ptr)
{
	fragment_addresses_ports_key *key = (fragment_addresses_ports_key *)ptr;

	if(key){
		/*
		 * Free up the copies of the addresses from the old key.
		 */
		free_address(&key->src_addr);
		free_address(&key->dst_addr);

		g_slice_free(fragment_addresses_ports_key, key);
	}
}

const reassembly_table_functions
addresses_ports_reassembly_table_functions = {
	fragment_addresses_ports_hash,
	fragment_addresses_ports_equal,
	fragment_addresses_ports_temporary_key,
	fragment_addresses_ports_persistent_key,
	fragment_addresses_ports_free_temporary_key,
	fragment_addresses_ports_free_persistent_key
};

typedef struct _reassembled_key {
	guint32 id;
	guint32 frame;
} reassembled_key;

static gint
reassembled_equal(gconstpointer k1, gconstpointer k2)
{
	const reassembled_key* key1 = (const reassembled_key*) k1;
	const reassembled_key* key2 = (const reassembled_key*) k2;

	/*
	 * We assume that the frame numbers are unlikely to be equal,
	 * so we check them first.
	 */
	return key1->frame == key2->frame && key1->id == key2->id;
}

static guint
reassembled_hash(gconstpointer k)
{
	const reassembled_key* key = (const reassembled_key*) k;

	return key->frame;
}

static void
reassembled_key_free(gpointer ptr)
{
	g_slice_free(reassembled_key, (reassembled_key *)ptr);
}

/*
 * For a fragment hash table entry, free the associated fragments.
 * The entry value (fd_chain) is freed herein and the entry is freed
 * when the key freeing routine is called (as a consequence of returning
 * TRUE from this function).
 */
static gboolean
free_all_fragments(gpointer key_arg _U_, gpointer value, gpointer user_data _U_)
{
	fragment_head *fd_head;
	fragment_item *tmp_fd;

	/* g_hash_table_new_full() was used to supply a function
	 * to free the key and anything to which it points
	 */
	for (fd_head = (fragment_head *)value; fd_head != NULL; fd_head = tmp_fd) {
		tmp_fd=fd_head->next;

		if(fd_head->tvb_data && !(fd_head->flags&FD_SUBSET_TVB))
			tvb_free(fd_head->tvb_data);
		g_slice_free(fragment_item, fd_head);
	}

	return TRUE;
}

/* ------------------------- */
static fragment_head *new_head(const guint32 flags)
{
	fragment_head *fd_head;
	/* If head/first structure in list only holds no other data than
	* 'datalen' then we don't have to change the head of the list
	* even if we want to keep it sorted
	*/
	fd_head=g_slice_new0(fragment_head);

	fd_head->flags=flags;
	return fd_head;
}

#define FD_VISITED_FREE 0xffff

/*
 * For a reassembled-packet hash table entry, free the fragment data
 * to which the value refers and also the key itself.
 */
static gboolean
free_all_reassembled_fragments(gpointer key_arg _U_, gpointer value,
				   gpointer user_data)
{
	GPtrArray *allocated_fragments = (GPtrArray *) user_data;
	fragment_head *fd_head;

	for (fd_head = (fragment_head *)value; fd_head != NULL; fd_head = fd_head->next) {
		/*
		 * A reassembled packet is inserted into the
		 * hash table once for every frame that made
		 * up the reassembled packet; add first seen
		 * fragments to array and later free them in
		 * free_fragments()
		 */
		if (fd_head->flags == FD_VISITED_FREE)
			break;
		if (fd_head->flags & FD_SUBSET_TVB)
			fd_head->tvb_data = NULL;
		g_ptr_array_add(allocated_fragments, fd_head);
		fd_head->flags = FD_VISITED_FREE;
	}

	return TRUE;
}

static void
free_fragments(gpointer data, gpointer user_data _U_)
{
	fragment_item *fd_head = (fragment_item *) data;

	if (fd_head->tvb_data)
		tvb_free(fd_head->tvb_data);
	g_slice_free(fragment_item, fd_head);
}

typedef struct register_reassembly_table {
	reassembly_table *table;
	const reassembly_table_functions *funcs;
} register_reassembly_table_t;

/*
 * Register a reassembly table.
 */
void
reassembly_table_register(reassembly_table *table,
		      const reassembly_table_functions *funcs)
{
	register_reassembly_table_t* reg_table;

	DISSECTOR_ASSERT(table);
	DISSECTOR_ASSERT(funcs);

	reg_table = g_new(register_reassembly_table_t,1);

	reg_table->table = table;
	reg_table->funcs = funcs;

	reassembly_table_list = g_list_prepend(reassembly_table_list, reg_table);
}

/*
 * Initialize a reassembly table, with specified functions.
 */
void
reassembly_table_init(reassembly_table *table,
		      const reassembly_table_functions *funcs)
{
	if (table->temporary_key_func == NULL)
		table->temporary_key_func = funcs->temporary_key_func;
	if (table->persistent_key_func == NULL)
		table->persistent_key_func = funcs->persistent_key_func;
	if (table->free_temporary_key_func == NULL)
		table->free_temporary_key_func = funcs->free_temporary_key_func;
	if (table->fragment_table != NULL) {
		/*
		 * The fragment hash table exists.
		 *
		 * Remove all entries and free fragment data for each entry.
		 *
		 * The keys, and anything to which they point, are freed by
		 * calling the table's key freeing function.  The values
		 * are freed in free_all_fragments().
		 */
		g_hash_table_foreach_remove(table->fragment_table,
					    free_all_fragments, NULL);
	} else {
		/* The fragment table does not exist. Create it */
		table->fragment_table = g_hash_table_new_full(funcs->hash_func,
		    funcs->equal_func, funcs->free_persistent_key_func, NULL);
	}

	if (table->reassembled_table != NULL) {
		GPtrArray *allocated_fragments;

		/*
		 * The reassembled-packet hash table exists.
		 *
		 * Remove all entries and free reassembled packet
		 * data and key for each entry.
		 */

		allocated_fragments = g_ptr_array_new();
		g_hash_table_foreach_remove(table->reassembled_table,
				free_all_reassembled_fragments, allocated_fragments);

		g_ptr_array_foreach(allocated_fragments, free_fragments, NULL);
		g_ptr_array_free(allocated_fragments, TRUE);
	} else {
		/* The fragment table does not exist. Create it */
		table->reassembled_table = g_hash_table_new_full(reassembled_hash,
		    reassembled_equal, reassembled_key_free, NULL);
	}
}

/*
 * Destroy a reassembly table.
 */
void
reassembly_table_destroy(reassembly_table *table)
{
	/*
	 * Clear the function pointers.
	 */
	table->temporary_key_func = NULL;
	table->persistent_key_func = NULL;
	table->free_temporary_key_func = NULL;
	if (table->fragment_table != NULL) {
		/*
		 * The fragment hash table exists.
		 *
		 * Remove all entries and free fragment data for each entry.
		 *
		 * The keys, and anything to which they point, are freed by
		 * calling the table's key freeing function.  The values
		 * are freed in free_all_fragments().
		 */
		g_hash_table_foreach_remove(table->fragment_table,
					    free_all_fragments, NULL);

		/*
		 * Now destroy the hash table.
		 */
		g_hash_table_destroy(table->fragment_table);
		table->fragment_table = NULL;
	}
	if (table->reassembled_table != NULL) {
		GPtrArray *allocated_fragments;

		/*
		 * The reassembled-packet hash table exists.
		 *
		 * Remove all entries and free reassembled packet
		 * data and key for each entry.
		 */

		allocated_fragments = g_ptr_array_new();
		g_hash_table_foreach_remove(table->reassembled_table,
				free_all_reassembled_fragments, allocated_fragments);

		g_ptr_array_foreach(allocated_fragments, free_fragments, NULL);
		g_ptr_array_free(allocated_fragments, TRUE);

		/*
		 * Now destroy the hash table.
		 */
		g_hash_table_destroy(table->reassembled_table);
		table->reassembled_table = NULL;
	}
}

/*
 * Look up an fd_head in the fragment table, optionally returning the key
 * for it.
 */
static fragment_head *
lookup_fd_head(reassembly_table *table, const packet_info *pinfo,
	       const guint32 id, const void *data, gpointer *orig_keyp)
{
	gpointer key;
	gpointer value;

	/* Create key to search hash with */
	key = table->temporary_key_func(pinfo, id, data);

	/*
	 * Look up the reassembly in the fragment table.
	 */
	if (!g_hash_table_lookup_extended(table->fragment_table, key, orig_keyp,
					  &value))
		value = NULL;
	/* Free the key */
	table->free_temporary_key_func(key);

	return (fragment_head *)value;
}

/*
 * Insert an fd_head into the fragment table, and return the key used.
 */
static gpointer
insert_fd_head(reassembly_table *table, fragment_head *fd_head,
	       const packet_info *pinfo, const guint32 id, const void *data)
{
	gpointer key;

	/*
	 * We're going to use the key to insert the fragment,
	 * so make a persistent version of it.
	 */
	key = table->persistent_key_func(pinfo, id, data);
	g_hash_table_insert(table->fragment_table, key, fd_head);
	return key;
}

/* This function cleans up the stored state and removes the reassembly data and
 * (with one exception) all allocated memory for matching reassembly.
 *
 * The exception is :
 * If the PDU was already completely reassembled, then the tvbuff containing the
 * reassembled data WILL NOT be free()d, and the pointer to that tvbuff will be
 * returned.
 * Othervise the function will return NULL.
 *
 * So, if you call fragment_delete and it returns non-NULL, YOU are responsible
 * to tvb_free() that tvbuff.
 */
tvbuff_t *
fragment_delete(reassembly_table *table, const packet_info *pinfo,
		const guint32 id, const void *data)
{
	fragment_head *fd_head;
	fragment_item *fd;
	tvbuff_t *fd_tvb_data=NULL;
	gpointer key;

	fd_head = lookup_fd_head(table, pinfo, id, data, &key);
	if(fd_head==NULL){
		/* We do not recognize this as a PDU we have seen before. return */
		return NULL;
	}

	fd_tvb_data=fd_head->tvb_data;
	/* loop over all partial fragments and free any tvbuffs */
	for(fd=fd_head->next;fd;){
		fragment_item *tmp_fd;
		tmp_fd=fd->next;

		if (fd->tvb_data && !(fd->flags & FD_SUBSET_TVB))
			tvb_free(fd->tvb_data);
		g_slice_free(fragment_item, fd);
		fd=tmp_fd;
	}
	g_slice_free(fragment_head, fd_head);
	g_hash_table_remove(table->fragment_table, key);

	return fd_tvb_data;
}

/* This function is used to check if there is partial or completed reassembly state
 * matching this packet. I.e. Is there reassembly going on or not for this packet?
 */
fragment_head *
fragment_get(reassembly_table *table, const packet_info *pinfo,
	     const guint32 id, const void *data)
{
	return lookup_fd_head(table, pinfo, id, data, NULL);
}

fragment_head *
fragment_get_reassembled_id(reassembly_table *table, const packet_info *pinfo,
			    const guint32 id)
{
	fragment_head *fd_head;
	reassembled_key key;

	/* create key to search hash with */
	key.frame = pinfo->num;
	key.id = id;
	fd_head = (fragment_head *)g_hash_table_lookup(table->reassembled_table, &key);

	return fd_head;
}

/* To specify the offset for the fragment numbering, the first fragment is added with 0, and
 * afterwards this offset is set. All additional calls to off_seq_check will calculate
 * the number in sequence in regards to the offset */
void
fragment_add_seq_offset(reassembly_table *table, const packet_info *pinfo, const guint32 id,
		const void *data, const guint32 fragment_offset)
{
	fragment_head *fd_head;

	fd_head = lookup_fd_head(table, pinfo, id, data, NULL);
	if (!fd_head)
		return;

	/* Reseting the offset is not allowed */
	if ( fd_head->fragment_nr_offset != 0 )
		return;

	fd_head->fragment_nr_offset = fragment_offset;
}

/*
 * For use with fragment_add (and not the fragment_add_seq functions).
 * When the reassembled result is wrong (perhaps it needs to be extended), this
 * function clears any previous reassembly result, allowing the new reassembled
 * length to be set again.
 */
static void
fragment_reset_defragmentation(fragment_head *fd_head)
{
	/* Caller must ensure that this function is only called when
	 * defragmentation is safe to undo. */
	DISSECTOR_ASSERT(fd_head->flags & FD_DEFRAGMENTED);

	for (fragment_item *fd_i = fd_head->next; fd_i; fd_i = fd_i->next) {
		if (!fd_i->tvb_data) {
			fd_i->tvb_data = tvb_new_subset_remaining(fd_head->tvb_data, fd_i->offset);
			fd_i->flags |= FD_SUBSET_TVB;
		}
		fd_i->flags &= (~FD_TOOLONGFRAGMENT) & (~FD_MULTIPLETAILS);
	}
	fd_head->flags &= ~(FD_DEFRAGMENTED|FD_PARTIAL_REASSEMBLY|FD_DATALEN_SET);
	fd_head->flags &= ~(FD_TOOLONGFRAGMENT|FD_MULTIPLETAILS);
	fd_head->datalen = 0;
	fd_head->reassembled_in = 0;
	fd_head->reas_in_layer_num = 0;
}

/* This function can be used to explicitly set the total length (if known)
 * for reassembly of a PDU.
 * This is useful for reassembly of PDUs where one may have the total length specified
 * in the first fragment instead of as for, say, IPv4 where a flag indicates which
 * is the last fragment.
 *
 * Such protocols might fragment_add with a more_frags==TRUE for every fragment
 * and just tell the reassembly engine the expected total length of the reassembled data
 * using fragment_set_tot_len immediately after doing fragment_add for the first packet.
 *
 * Note that for FD_BLOCKSEQUENCE tot_len is the index for the tail fragment.
 * i.e. since the block numbers start at 0, if we specify tot_len==2, that
 * actually means we want to defragment 3 blocks, block 0, 1 and 2.
 */
void
fragment_set_tot_len(reassembly_table *table, const packet_info *pinfo,
		     const guint32 id, const void *data, const guint32 tot_len)
{
	fragment_head *fd_head;
	fragment_item *fd;
	guint32        max_offset = 0;

	fd_head = lookup_fd_head(table, pinfo, id, data, NULL);
	if (!fd_head)
		return;

	/* If we're setting a block sequence number, verify that it
	 * doesn't conflict with values set by existing fragments.
	 * XXX - eliminate this check?
	 */
	fd = fd_head;
	if (fd_head->flags & FD_BLOCKSEQUENCE) {
		while (fd) {
			if (fd->offset > max_offset) {
				max_offset = fd->offset;
				if (max_offset > tot_len) {
					fd_head->error = "Bad total reassembly block count";
					THROW_MESSAGE(ReassemblyError, fd_head->error);
				}
			}
			fd = fd->next;
		}
	}

	if (fd_head->flags & FD_DEFRAGMENTED) {
		if (max_offset != tot_len) {
			fd_head->error = "Defragmented complete but total length not satisfied";
			THROW_MESSAGE(ReassemblyError, fd_head->error);
		}
	}

	/* We got this far so the value is sane. */
	fd_head->datalen = tot_len;
	fd_head->flags |= FD_DATALEN_SET;
}

void
fragment_reset_tot_len(reassembly_table *table, const packet_info *pinfo,
		       const guint32 id, const void *data, const guint32 tot_len)
{
	fragment_head *fd_head;

	fd_head = lookup_fd_head(table, pinfo, id, data, NULL);
	if (!fd_head)
		return;

	/*
	 * If FD_PARTIAL_REASSEMBLY is set, it would make the next fragment_add
	 * call set the reassembled length based on the fragment offset and
	 * length. As the length is known now, be sure to disable that magic.
	 */
	fd_head->flags &= ~FD_PARTIAL_REASSEMBLY;

	/* If the length is already as expected, there is nothing else to do. */
	if (tot_len == fd_head->datalen)
		return;

	if (fd_head->flags & FD_DEFRAGMENTED) {
		/*
		 * Fragments were reassembled before, clear it to allow
		 * increasing the reassembled length.
		 */
		fragment_reset_defragmentation(fd_head);
	}

	fd_head->datalen = tot_len;
	fd_head->flags |= FD_DATALEN_SET;
}

void
fragment_truncate(reassembly_table *table, const packet_info *pinfo,
		       const guint32 id, const void *data, const guint32 tot_len)

{
	tvbuff_t      *old_tvb_data;
	fragment_head *fd_head;

	fd_head = lookup_fd_head(table, pinfo, id, data, NULL);
	if (!fd_head)
		return;

	/* Caller must ensure that this function is only called when
	 * we are defragmented. */
	DISSECTOR_ASSERT(fd_head->flags & FD_DEFRAGMENTED);

	/*
	 * If FD_PARTIAL_REASSEMBLY is set, it would make the next fragment_add
	 * call set the reassembled length based on the fragment offset and
	 * length. As the length is known now, be sure to disable that magic.
	 */
	fd_head->flags &= ~FD_PARTIAL_REASSEMBLY;

	/* If the length is already as expected, there is nothing else to do. */
	if (tot_len == fd_head->datalen)
		return;

	DISSECTOR_ASSERT(fd_head->datalen > tot_len);

	old_tvb_data=fd_head->tvb_data;
	fd_head->tvb_data = tvb_clone_offset_len(old_tvb_data, 0, tot_len);
	tvb_set_free_cb(fd_head->tvb_data, g_free);

	if (old_tvb_data)
		tvb_add_to_chain(fd_head->tvb_data, old_tvb_data);
	fd_head->datalen = tot_len;

	/* Keep the fragments before the split point, dividing any if
	 * necessary.
	 * XXX: In rare cases, there might be fragments marked as overlap that
	 * have data both before and after the split point, and which only
	 * overlap after the split point. In that case, after dividing the
	 * fragments the first part no longer overlap.
	 * However, at this point we can't test for overlap conflicts,
	 * so we'll just leave the overlap flags as-is.
	 */
	fd_head->flags &= ~(FD_OVERLAP|FD_OVERLAPCONFLICT|FD_TOOLONGFRAGMENT|FD_MULTIPLETAILS);
	fragment_item *fd_i, *prev_fd = fd_head;
	for (fd_i = fd_head->next; fd_i && (fd_i->offset < tot_len); fd_i = fd_i->next) {
		fd_i->flags &= ~(FD_TOOLONGFRAGMENT|FD_MULTIPLETAILS);
		/* Check for the split point occuring in the middle of the
		 * fragment. */
                if (fd_i->offset + fd_i->len > tot_len) {
			fd_i->len = tot_len - fd_i->offset;
		}
		fd_head->flags |= fd_i->flags & (FD_OVERLAP|FD_OVERLAPCONFLICT);
		prev_fd = fd_i;

		/* Below should do nothing since this is already defragmented */
		if (fd_i->flags & FD_SUBSET_TVB)
			fd_i->flags &= ~FD_SUBSET_TVB;
		else if (fd_i->tvb_data)
			tvb_free(fd_i->tvb_data);

		fd_i->tvb_data=NULL;
	}

	/* Remove all the other fragments, as they are past the split point. */
        prev_fd->next = NULL;
	fragment_item *tmp_fd;
	for (; fd_i; fd_i = tmp_fd) {
		tmp_fd=fd_i->next;

		if (fd_i->tvb_data && !(fd_i->flags & FD_SUBSET_TVB))
			tvb_free(fd_i->tvb_data);
		g_slice_free(fragment_item, fd_i);
	}
}

guint32
fragment_get_tot_len(reassembly_table *table, const packet_info *pinfo,
		     const guint32 id, const void *data)
{
	fragment_head *fd_head;

	fd_head = lookup_fd_head(table, pinfo, id, data, NULL);

	if(fd_head){
		return fd_head->datalen;
	}

	return 0;
}

/* This function will set the partial reassembly flag for a fh.
   When this function is called, the fh MUST already exist, i.e.
   the fh MUST be created by the initial call to fragment_add() before
   this function is called.
   Also note that this function MUST be called to indicate a fh will be
   extended (increase the already stored data)
*/

void
fragment_set_partial_reassembly(reassembly_table *table,
				const packet_info *pinfo, const guint32 id,
				const void *data)
{
	fragment_head *fd_head;

	fd_head = lookup_fd_head(table, pinfo, id, data, NULL);

	/*
	 * XXX - why not do all the stuff done early in "fragment_add_work()",
	 * turning off FD_DEFRAGMENTED and pointing the fragments' data
	 * pointers to the appropriate part of the already-reassembled
	 * data, and clearing the data length and "reassembled in" frame
	 * number, here?  We currently have a hack in the TCP dissector
	 * not to set the "reassembled in" value if the "partial reassembly"
	 * flag is set, so that in the first pass through the packets
	 * we don't falsely set a packet as reassembled in that packet
	 * if the dissector decided that even more reassembly was needed.
	 */
	if(fd_head){
		fd_head->flags |= FD_PARTIAL_REASSEMBLY;
	}
}

/*
 * This function gets rid of an entry from a fragment table, given
 * a pointer to the key for that entry.
 *
 * The key freeing routine will be called by g_hash_table_remove().
 */
static void
fragment_unhash(reassembly_table *table, gpointer key)
{
	/*
	 * Remove the entry from the fragment table.
	 */
	g_hash_table_remove(table->fragment_table, key);
}

/*
 * This function adds fragment_head structure to a reassembled-packet
 * hash table, using the frame numbers of each of the frames from
 * which it was reassembled as keys, and sets the "reassembled_in"
 * frame number.
 */
static void
fragment_reassembled(reassembly_table *table, fragment_head *fd_head,
		     const packet_info *pinfo, const guint32 id)
{
	reassembled_key *new_key;
	fragment_item *fd;

	if (fd_head->next == NULL) {
		/*
		 * This was not fragmented, so there's no fragment
		 * table; just hash it using the current frame number.
		 */
		new_key = g_slice_new(reassembled_key);
		new_key->frame = pinfo->num;
		new_key->id = id;
		g_hash_table_insert(table->reassembled_table, new_key, fd_head);
	} else {
		/*
		 * Hash it with the frame numbers for all the frames.
		 */
		for (fd = fd_head->next; fd != NULL; fd = fd->next){
			new_key = g_slice_new(reassembled_key);
			new_key->frame = fd->frame;
			new_key->id = id;
			g_hash_table_insert(table->reassembled_table, new_key,
				fd_head);
		}
	}
	fd_head->flags |= FD_DEFRAGMENTED;
	fd_head->reassembled_in = pinfo->num;
	fd_head->reas_in_layer_num = pinfo->curr_layer_num;
}

/*
 * This function is a variant of the above for the single sequence
 * case, using id+offset (i.e., the original sequence number) for the id
 * in the key.
 */
static void
fragment_reassembled_single(reassembly_table *table, fragment_head *fd_head,
			    const packet_info *pinfo, const guint32 id)
{
	reassembled_key *new_key;
	fragment_item *fd;

	if (fd_head->next == NULL) {
		/*
		 * This was not fragmented, so there's no fragment
		 * table; just hash it using the current frame number.
		 */
		new_key = g_slice_new(reassembled_key);
		new_key->frame = pinfo->num;
		new_key->id = id;
		g_hash_table_insert(table->reassembled_table, new_key, fd_head);
	} else {
		/*
		 * Hash it with the frame numbers for all the frames.
		 */
		for (fd = fd_head->next; fd != NULL; fd = fd->next){
			new_key = g_slice_new(reassembled_key);
			new_key->frame = fd->frame;
			new_key->id = id + fd->offset;
			g_hash_table_insert(table->reassembled_table, new_key,
				fd_head);
		}
	}
	fd_head->flags |= FD_DEFRAGMENTED;
	fd_head->reassembled_in = pinfo->num;
	fd_head->reas_in_layer_num = pinfo->curr_layer_num;
}

static void
LINK_FRAG(fragment_head *fd_head,fragment_item *fd)
{
	fragment_item *fd_i;

	/* add fragment to list, keep list sorted */
	for(fd_i= fd_head; fd_i->next;fd_i=fd_i->next) {
		if (fd->offset < fd_i->next->offset )
			break;
	}
	fd->next=fd_i->next;
	fd_i->next=fd;
}

static void
MERGE_FRAG(fragment_head *fd_head, fragment_item *fd)
{
	fragment_item *fd_i, *tmp;

	if (fd == NULL) return;

	for(fd_i = fd_head; fd_i->next; fd_i=fd_i->next) {
		if (fd->offset < fd_i->next->offset) {
			tmp = fd_i->next;
			fd_i->next = fd;
			fd = tmp;
		}
	}
	fd_i->next = fd;
}

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
 *
 * This function assumes frag_offset being a byte offset into the defragment
 * packet.
 *
 * 01-2002
 * Once the fh is defragmented (= FD_DEFRAGMENTED set), it can be
 * extended using the FD_PARTIAL_REASSEMBLY flag. This flag should be set
 * using fragment_set_partial_reassembly() before calling fragment_add
 * with the new fragment. FD_TOOLONGFRAGMENT and FD_MULTIPLETAILS flags
 * are lowered when a new extension process is started.
 */
static gboolean
fragment_add_work(fragment_head *fd_head, tvbuff_t *tvb, const int offset,
		 const packet_info *pinfo, const guint32 frag_offset,
		 const guint32 frag_data_len, const gboolean more_frags,
		 const guint32 frag_frame)
{
	fragment_item *fd;
	fragment_item *fd_i;
	guint32 max, dfpos, fraglen, overlap;
	tvbuff_t *old_tvb_data;
	guint8 *data;

	/* create new fd describing this fragment */
	fd = g_slice_new(fragment_item);
	fd->next = NULL;
	fd->flags = 0;
	fd->frame = frag_frame;
	fd->offset = frag_offset;
	fd->fragment_nr_offset = 0; /* will only be used with sequence */
	fd->len  = frag_data_len;
	fd->tvb_data = NULL;
	fd->error = NULL;

	/*
	 * Are we adding to an already-completed reassembly?
	 */
	if (fd_head->flags & FD_DEFRAGMENTED) {
		/*
		 * Yes.  Does this fragment go past the end of the results
		 * of that reassembly?
		 * XXX - shouldn't this be ">"?  If frag_offset + frag_data_len
		 * == fd_head->datalen, this overlaps the end of the
		 * reassembly, but doesn't go past it, right?
		 */
		if (frag_offset + frag_data_len >= fd_head->datalen) {
			/*
			 * Yes.  Have we been requested to continue reassembly?
			 */
			if (fd_head->flags & FD_PARTIAL_REASSEMBLY) {
				/*
				 * Yes.  Set flag in already empty fds &
				 * point old fds to malloc'ed data.
				 */
				fragment_reset_defragmentation(fd_head);
			} else {
				/*
				 * No.  Bail out since we have no idea what to
				 * do with this fragment (and if we keep going
				 * we'll run past the end of a buffer sooner
				 * or later).
				 */
				g_slice_free(fragment_item, fd);

				/*
				 * This is an attempt to add a fragment to a
				 * reassembly that had already completed.
				 * If it had no error, we don't want to
				 * mark it with an error, and if it had an
				 * error, we don't want to overwrite it, so
				 * we don't set fd_head->error.
				 */
				if (frag_offset >= fd_head->datalen) {
					/*
					 * The fragment starts past the end
					 * of the reassembled data.
					 */
					THROW_MESSAGE(ReassemblyError, "New fragment past old data limits");
				} else {
					/*
					 * The fragment starts before the end
					 * of the reassembled data, but
					 * runs past the end.  That could
					 * just be a retransmission.
					 */
					THROW_MESSAGE(ReassemblyError, "New fragment overlaps old data (retransmission?)");
				}
			}
		} else {
			/*
			 * No.  That means it still overlaps that, so report
			 * this as a problem, possibly a retransmission.
			 */
			g_slice_free(fragment_item, fd);
			THROW_MESSAGE(ReassemblyError, "New fragment overlaps old data (retransmission?)");
		}
	}

	/* Do this after we may have bailed out (above) so that we don't leave
	 * fd_head->frame in a bad state if we do */
	if (fd->frame > fd_head->frame)
		fd_head->frame = fd->frame;

	if (!more_frags) {
		/*
		 * This is the tail fragment in the sequence.
		 */
		if (fd_head->flags & FD_DATALEN_SET) {
			/* ok we have already seen other tails for this packet
			 * it might be a duplicate.
			 */
			if (fd_head->datalen != (fd->offset + fd->len) ){
				/* Oops, this tail indicates a different packet
				 * len than the previous ones. Something's wrong.
				 */
				fd->flags	   |= FD_MULTIPLETAILS;
				fd_head->flags |= FD_MULTIPLETAILS;
			}
		} else {
			/* This was the first tail fragment; now we know
			 * what the length of the packet should be.
			 */
			fd_head->datalen = fd->offset + fd->len;
			fd_head->flags |= FD_DATALEN_SET;
		}
	}



	/* If the packet is already defragmented, this MUST be an overlap.
	 * The entire defragmented packet is in fd_head->data.
	 * Even if we have previously defragmented this packet, we still
	 * check it. Someone might play overlap and TTL games.
	 *
	 * XXX: This code generally doesn't get called (unlike the versions
	 * in _add_seq*) because of the exceptions thrown above unless
	 * partial_reassembly has been set, but that doesn't seem right
	 * in the case of overlap as the flags don't get set. Shouldn't the
	 * behavior match the version with sequence numbers?
	 */
	if (fd_head->flags & FD_DEFRAGMENTED) {
		guint32 end_offset = fd->offset + fd->len;
		fd->flags	   |= FD_OVERLAP;
		fd_head->flags |= FD_OVERLAP;
		/* make sure it's not too long */
		if (end_offset > fd_head->datalen || end_offset < fd->offset || end_offset < fd->len) {
			fd->flags	   |= FD_TOOLONGFRAGMENT;
			fd_head->flags |= FD_TOOLONGFRAGMENT;
		}
		/* make sure it doesn't conflict with previous data */
		else if ( tvb_memeql(fd_head->tvb_data, fd->offset,
			tvb_get_ptr(tvb,offset,fd->len),fd->len) ){
			fd->flags	   |= FD_OVERLAPCONFLICT;
			fd_head->flags |= FD_OVERLAPCONFLICT;
		}
		/* it was just an overlap, link it and return */
		LINK_FRAG(fd_head,fd);
		return TRUE;
	}



	/* If we have reached this point, the packet is not defragmented yet.
	 * Save all payload in a buffer until we can defragment.
	 */
	if (!tvb_bytes_exist(tvb, offset, fd->len)) {
		g_slice_free(fragment_item, fd);
		THROW(BoundsError);
	}
	fd->tvb_data = tvb_clone_offset_len(tvb, offset, fd->len);
	LINK_FRAG(fd_head,fd);


	if( !(fd_head->flags & FD_DATALEN_SET) ){
		/* if we don't know the datalen, there are still missing
		 * packets. Cheaper than the check below.
		 */
		return FALSE;
	}


	/*
	 * Check if we have received the entire fragment.
	 * This is easy since the list is sorted and the head is faked.
	 *
	 * First, we compute the amount of contiguous data that's
	 * available.  (The check for fd_i->offset <= max rules out
	 * fragments that don't start before or at the end of the
	 * previous fragment, i.e. fragments that have a gap between
	 * them and the previous fragment.)
	 */
	max = 0;
	for (fd_i=fd_head->next;fd_i;fd_i=fd_i->next) {
		if ( ((fd_i->offset)<=max) &&
			((fd_i->offset+fd_i->len)>max) ){
			max = fd_i->offset+fd_i->len;
		}
	}

	if (max < (fd_head->datalen)) {
		/*
		 * The amount of contiguous data we have is less than the
		 * amount of data we're trying to reassemble, so we haven't
		 * received all packets yet.
		 */
		return FALSE;
	}

	/* we have received an entire packet, defragment it and
	 * free all fragments
	 */
	/* store old data just in case */
	old_tvb_data=fd_head->tvb_data;
	data = (guint8 *) g_malloc(fd_head->datalen);
	fd_head->tvb_data = tvb_new_real_data(data, fd_head->datalen, fd_head->datalen);
	tvb_set_free_cb(fd_head->tvb_data, g_free);

	/* add all data fragments */
	for (dfpos=0,fd_i=fd_head;fd_i;fd_i=fd_i->next) {
		if (fd_i->len) {
			/*
			 * The loop above that calculates max also
			 * ensures that the only gaps that exist here
			 * are ones where a fragment starts past the
			 * end of the reassembled datagram, and there's
			 * a gap between the previous fragment and
			 * that fragment.
			 *
			 * A "DESEGMENT_UNTIL_FIN" was involved wherein the
			 * FIN packet had an offset less than the highest
			 * fragment offset seen. [Seen from a fuzz-test:
			 * bug #2470]).
			 *
			 * Note that the "overlap" compare must only be
			 * done for fragments with (offset+len) <= fd_head->datalen
			 * and thus within the newly g_malloc'd buffer.
			 */

			if (fd_i->offset >= fd_head->datalen) {
				/*
				 * Fragment starts after the end
				 * of the reassembled packet.
				 *
				 * This can happen if the length was
				 * set after the offending fragment
				 * was added to the reassembly.
				 *
				 * Flag this fragment, but don't
				 * try to extract any data from
				 * it, as there's no place to put
				 * it.
				 *
				 * XXX - add different flag value
				 * for this.
				 */
				fd_i->flags    |= FD_TOOLONGFRAGMENT;
				fd_head->flags |= FD_TOOLONGFRAGMENT;
			} else if (fd_i->offset + fd_i->len < fd_i->offset) {
				/* Integer overflow, unhandled by rest of
				 * code so error out. This check handles
				 * all possible remaining overflows.
				 */
				fd_head->error = "offset + len < offset";
			} else if (!fd_i->tvb_data) {
				fd_head->error = "no data";
			} else {
				fraglen = fd_i->len;
				if (fd_i->offset + fraglen > fd_head->datalen) {
					/*
					 * Fragment goes past the end
					 * of the packet, as indicated
					 * by the last fragment.
					 *
					 * This can happen if the
					 * length was set after the
					 * offending fragment was
					 * added to the reassembly.
					 *
					 * Mark it as such, and only
					 * copy from it what fits in
					 * the packet.
					 */
					fd_i->flags    |= FD_TOOLONGFRAGMENT;
					fd_head->flags |= FD_TOOLONGFRAGMENT;
					fraglen = fd_head->datalen - fd_i->offset;
				}
				overlap = dfpos - fd_i->offset;
				/* Guaranteed to be >= 0, previous code
				 * has checked for gaps. */
				if (overlap) {
					/* duplicate/retransmission/overlap */
					guint32 cmp_len = MIN(fd_i->len,overlap);

					fd_i->flags    |= FD_OVERLAP;
					fd_head->flags |= FD_OVERLAP;
					if ( memcmp(data + fd_i->offset,
							tvb_get_ptr(fd_i->tvb_data, 0, cmp_len),
							cmp_len)
							 ) {
						fd_i->flags    |= FD_OVERLAPCONFLICT;
						fd_head->flags |= FD_OVERLAPCONFLICT;
					}
				}
				/* XXX: As in the fragment_add_seq funcs
				 * like fragment_defragment_and_free() the
				 * existing behavior does not overwrite
				 * overlapping bytes even if there is a
				 * conflict. It only adds new bytes.
				 *
				 * Since we only add fragments to a reassembly
				 * if the reassembly isn't complete, the most
				 * common case for overlap conflicts is when
				 * an earlier reassembly isn't fully contained
				 * in the capture, and we've reused an
				 * indentification number / wrapped around
				 * offset sequence numbers much later in the
				 * capture. In that case, we probably *do*
				 * want to overwrite conflicting bytes, since
				 * the earlier fragments didn't form a complete
				 * reassembly and should be effectively thrown
				 * out rather than mixed with the new ones?
				 */
				if (fd_i->offset + fraglen > dfpos) {
					memcpy(data+dfpos,
						tvb_get_ptr(fd_i->tvb_data, overlap, fraglen-overlap),
						fraglen-overlap);
					dfpos = fd_i->offset + fraglen;
				}
			}

			if (fd_i->flags & FD_SUBSET_TVB)
				fd_i->flags &= ~FD_SUBSET_TVB;
			else if (fd_i->tvb_data)
				tvb_free(fd_i->tvb_data);

			fd_i->tvb_data=NULL;
		}
	}

	if (old_tvb_data)
		tvb_add_to_chain(tvb, old_tvb_data);
	/* mark this packet as defragmented.
	   allows us to skip any trailing fragments */
	fd_head->flags |= FD_DEFRAGMENTED;
	fd_head->reassembled_in=pinfo->num;
	fd_head->reas_in_layer_num = pinfo->curr_layer_num;

	/* we don't throw until here to avoid leaking old_data and others */
	if (fd_head->error) {
		THROW_MESSAGE(ReassemblyError, fd_head->error);
	}

	return TRUE;
}

static fragment_head *
fragment_add_common(reassembly_table *table, tvbuff_t *tvb, const int offset,
		    const packet_info *pinfo, const guint32 id,
		    const void *data, const guint32 frag_offset,
		    const guint32 frag_data_len, const gboolean more_frags,
		    const gboolean check_already_added,
		    const guint32 frag_frame)
{
	fragment_head *fd_head;
	fragment_item *fd_item;
	gboolean already_added;


	/*
	 * Dissector shouldn't give us garbage tvb info.
	 *
	 * XXX - should this code take responsibility for preventing
	 * reassembly if data is missing due to the packets being
	 * sliced, rather than leaving it up to dissectors?
	 */
	DISSECTOR_ASSERT(tvb_bytes_exist(tvb, offset, frag_data_len));

	fd_head = lookup_fd_head(table, pinfo, id, data, NULL);

#if 0
	/* debug output of associated fragments. */
	/* leave it here for future debugging sessions */
	if(strcmp(pinfo->current_proto, "DCERPC") == 0) {
		printf("proto:%s num:%u id:%u offset:%u len:%u more:%u visited:%u\n",
			pinfo->current_proto, pinfo->num, id, frag_offset, frag_data_len, more_frags, pinfo->fd->visited);
		if(fd_head != NULL) {
			for(fd_item=fd_head->next;fd_item;fd_item=fd_item->next){
				printf("fd_frame:%u fd_offset:%u len:%u datalen:%u\n",
					fd_item->frame, fd_item->offset, fd_item->len, fd_item->datalen);
			}
		}
	}
#endif

	/*
	 * Is this the first pass through the capture?
	 */
	if (!pinfo->fd->visited) {
		/*
		 * Yes, so we could be doing reassembly.  If
		 * "check_already_added" is true, and fd_head is non-null,
		 * meaning that this fragment would be added to an
		 * in-progress reassembly, check if we have seen this
		 * fragment before, i.e., if we have already added it to
		 * that reassembly. That can be true even on the first pass
		 * since we sometimes might call a subdissector multiple
		 * times.
		 *
		 * We check both the frame number and the fragment offset,
		 * so that we support multiple fragments from the same
		 * frame being added to the same reassembled PDU.
		 */
		if (check_already_added && fd_head != NULL) {
			/*
			 * fd_head->frame is the maximum of the frame
			 * numbers of all the fragments added to this
			 * reassembly; if this frame is later than that
			 * frame, we know it hasn't been added yet.
			 */
			if (frag_frame <= fd_head->frame) {
				already_added = FALSE;
				/*
				 * The first item in the reassembly list
				 * is not a fragment, it's a data structure
				 * for the reassembled packet, so we
				 * start checking with the next item.
				 */
				for (fd_item = fd_head->next; fd_item;
				    fd_item = fd_item->next) {
					if (frag_frame == fd_item->frame &&
					    frag_offset == fd_item->offset) {
						already_added = TRUE;
						break;
					}
				}
				if (already_added) {
					/*
					 * Have we already finished
					 * reassembling?
					 */
					if (fd_head->flags & FD_DEFRAGMENTED) {
						/*
						 * Yes.
						 * XXX - can this ever happen?
						 */
						THROW_MESSAGE(ReassemblyError,
						    "Frame already added in first pass");
					} else {
						/*
						 * No.
						 */
						return NULL;
					}
				}
			}
		}
	} else {
		/*
		 * No, so we've already done all the reassembly and added
		 * all the fragments.  Do we have a reassembly and, if so,
		 * have we finished reassembling?
		 */
		if (fd_head != NULL && fd_head->flags & FD_DEFRAGMENTED) {
			/*
			 * Yes.  This is probably being done after the
			 * first pass, and we've already done the work
			 * on the first pass.
			 *
			 * If the reassembly got a fatal error, throw that
			 * error again.
			 */
			if (fd_head->error)
				THROW_MESSAGE(ReassemblyError, fd_head->error);

			/*
			 * Is it later in the capture than all of the
			 * fragments in the reassembly?
			 */
			if (frag_frame > fd_head->frame) {
				/*
				 * Yes, so report this as a problem,
				 * possibly a retransmission.
				 */
				THROW_MESSAGE(ReassemblyError, "New fragment overlaps old data (retransmission?)");
			}

			/*
			 * Does this fragment go past the end of the
			 * results of that reassembly?
			 */
		    	if (frag_offset + frag_data_len > fd_head->datalen) {
				/*
				 * Yes.
				 */
				if (frag_offset >= fd_head->datalen) {
					/*
					 * The fragment starts past the
					 * end of the reassembled data.
					 */
					THROW_MESSAGE(ReassemblyError, "New fragment past old data limits");
				} else {
					/*
					 * The fragment starts before the end
					 * of the reassembled data, but
					 * runs past the end.  That could
					 * just be a retransmission.
					 */
					THROW_MESSAGE(ReassemblyError, "New fragment overlaps old data (retransmission?)");
				}
			}

			return fd_head;
		} else {
			/*
			 * No.
			 */
			return NULL;
		}
	}

	if (fd_head==NULL){
		/* not found, this must be the first snooped fragment for this
		 * packet. Create list-head.
		 */
		fd_head = new_head(0);

		/*
		 * Insert it into the hash table.
		 */
		insert_fd_head(table, fd_head, pinfo, id, data);
	}

	if (fragment_add_work(fd_head, tvb, offset, pinfo, frag_offset,
		frag_data_len, more_frags, frag_frame)) {
		/*
		 * Reassembly is complete.
		 */
		return fd_head;
	} else {
		/*
		 * Reassembly isn't complete.
		 */
		return NULL;
	}
}

fragment_head *
fragment_add(reassembly_table *table, tvbuff_t *tvb, const int offset,
	     const packet_info *pinfo, const guint32 id, const void *data,
	     const guint32 frag_offset, const guint32 frag_data_len,
	     const gboolean more_frags)
{
	return fragment_add_common(table, tvb, offset, pinfo, id, data,
		frag_offset, frag_data_len, more_frags, TRUE, pinfo->num);
}

/*
 * For use when you can have multiple fragments in the same frame added
 * to the same reassembled PDU, e.g. with ONC RPC-over-TCP.
 */
fragment_head *
fragment_add_multiple_ok(reassembly_table *table, tvbuff_t *tvb,
			 const int offset, const packet_info *pinfo,
			 const guint32 id, const void *data,
			 const guint32 frag_offset,
			 const guint32 frag_data_len, const gboolean more_frags)
{
	return fragment_add_common(table, tvb, offset, pinfo, id, data,
		frag_offset, frag_data_len, more_frags, FALSE, pinfo->num);
}

/*
 * For use in protocols like TCP when you are adding an out of order segment
 * that arrived in an earlier frame because the correct fragment id could not
 * be determined until later. By allowing fd->frame to be different than
 * pinfo->num, show_fragment_tree will display the correct fragment numbers.
 *
 * Note that pinfo is still used to set reassembled_in if we have all the
 * fragments, so that results on subsequent passes can be the same as the
 * first pass.
 */
fragment_head *
fragment_add_out_of_order(reassembly_table *table, tvbuff_t *tvb,
			  const int offset, const packet_info *pinfo,
			  const guint32 id, const void *data,
			  const guint32 frag_offset,
			  const guint32 frag_data_len,
			  const gboolean more_frags, const guint32 frag_frame)
{
	return fragment_add_common(table, tvb, offset, pinfo, id, data,
		frag_offset, frag_data_len, more_frags, TRUE, frag_frame);
}

fragment_head *
fragment_add_check(reassembly_table *table, tvbuff_t *tvb, const int offset,
		   const packet_info *pinfo, const guint32 id,
		   const void *data, const guint32 frag_offset,
		   const guint32 frag_data_len, const gboolean more_frags)
{
	reassembled_key reass_key;
	fragment_head *fd_head;
	gpointer orig_key;

	/*
	 * If this isn't the first pass, look for this frame in the table
	 * of reassembled packets.
	 */
	if (pinfo->fd->visited) {
		reass_key.frame = pinfo->num;
		reass_key.id = id;
		return (fragment_head *)g_hash_table_lookup(table->reassembled_table, &reass_key);
	}

	/* Looks up a key in the GHashTable, returning the original key and the associated value
	 * and a gboolean which is TRUE if the key was found. This is useful if you need to free
	 * the memory allocated for the original key, for example before calling g_hash_table_remove()
	 */
	fd_head = lookup_fd_head(table, pinfo, id, data, &orig_key);
	if (fd_head == NULL) {
		/* not found, this must be the first snooped fragment for this
		 * packet. Create list-head.
		 */
		fd_head = new_head(0);

		/*
		 * Save the key, for unhashing it later.
		 */
		orig_key = insert_fd_head(table, fd_head, pinfo, id, data);
	}

	/*
	 * If this is a short frame, then we can't, and don't, do
	 * reassembly on it.  We just give up.
	 */
	if (!tvb_bytes_exist(tvb, offset, frag_data_len)) {
		return NULL;
	}

	if (fragment_add_work(fd_head, tvb, offset, pinfo, frag_offset,
		frag_data_len, more_frags, pinfo->num)) {
		/*
		 * Reassembly is complete.
		 * Remove this from the table of in-progress
		 * reassemblies, add it to the table of
		 * reassembled packets, and return it.
		 */

		/*
		 * Remove this from the table of in-progress reassemblies,
		 * and free up any memory used for it in that table.
		 */
		fragment_unhash(table, orig_key);

		/*
		 * Add this item to the table of reassembled packets.
		 */
		fragment_reassembled(table, fd_head, pinfo, id);
		return fd_head;
	} else {
		/*
		 * Reassembly isn't complete.
		 */
		return NULL;
	}
}

static void
fragment_defragment_and_free (fragment_head *fd_head, const packet_info *pinfo)
{
	fragment_item *fd_i = NULL;
	fragment_item *last_fd = NULL;
	guint32  dfpos = 0, size = 0;
	tvbuff_t *old_tvb_data = NULL;
	guint8 *data;

	for(fd_i=fd_head->next;fd_i;fd_i=fd_i->next) {
		if(!last_fd || last_fd->offset!=fd_i->offset){
			size+=fd_i->len;
		}
		last_fd=fd_i;
	}

	/* store old data in case the fd_i->data pointers refer to it */
	old_tvb_data=fd_head->tvb_data;
	data = (guint8 *) g_malloc(size);
	fd_head->tvb_data = tvb_new_real_data(data, size, size);
	tvb_set_free_cb(fd_head->tvb_data, g_free);
	fd_head->len = size;		/* record size for caller	*/

	/* add all data fragments */
	last_fd=NULL;
	for (fd_i=fd_head->next; fd_i; fd_i=fd_i->next) {
		if (fd_i->len) {
			if(!last_fd || last_fd->offset != fd_i->offset) {
				/* First fragment or in-sequence fragment */
				memcpy(data+dfpos, tvb_get_ptr(fd_i->tvb_data, 0, fd_i->len), fd_i->len);
				dfpos += fd_i->len;
			} else {
				/* duplicate/retransmission/overlap */
				fd_i->flags    |= FD_OVERLAP;
				fd_head->flags |= FD_OVERLAP;
				if(last_fd->len != fd_i->len
				   || tvb_memeql(last_fd->tvb_data, 0, tvb_get_ptr(fd_i->tvb_data, 0, last_fd->len), last_fd->len) ) {
					fd_i->flags    |= FD_OVERLAPCONFLICT;
					fd_head->flags |= FD_OVERLAPCONFLICT;
				}
			}
		}
		last_fd=fd_i;
	}

	/* we have defragmented the pdu, now free all fragments*/
	for (fd_i=fd_head->next;fd_i;fd_i=fd_i->next) {
		if (fd_i->flags & FD_SUBSET_TVB)
			fd_i->flags &= ~FD_SUBSET_TVB;
		else if (fd_i->tvb_data)
			tvb_free(fd_i->tvb_data);
		fd_i->tvb_data=NULL;
	}
	if (old_tvb_data)
		tvb_free(old_tvb_data);

	/* mark this packet as defragmented.
	 * allows us to skip any trailing fragments.
	 */
	fd_head->flags |= FD_DEFRAGMENTED;
	fd_head->reassembled_in=pinfo->num;
	fd_head->reas_in_layer_num = pinfo->curr_layer_num;
}

/*
 * This function adds a new fragment to the entry for a reassembly
 * operation.
 *
 * The list of fragments for a specific datagram is kept sorted for
 * easier handling.
 *
 * Returns TRUE if we have all the fragments, FALSE otherwise.
 *
 * This function assumes frag_number being a block sequence number.
 * The bsn for the first block is 0.
 */
static gboolean
fragment_add_seq_work(fragment_head *fd_head, tvbuff_t *tvb, const int offset,
		 const packet_info *pinfo, const guint32 frag_number,
		 const guint32 frag_data_len, const gboolean more_frags)
{
	fragment_item *fd;
	fragment_item *fd_i;
	fragment_item *last_fd;
	guint32 max, dfpos;
	guint32 frag_number_work;

	/* Enables the use of fragment sequence numbers, which do not start with 0 */
	frag_number_work = frag_number;
	if ( fd_head->fragment_nr_offset != 0 )
		if ( frag_number_work >= fd_head->fragment_nr_offset )
			frag_number_work = frag_number - fd_head->fragment_nr_offset;

	/* if the partial reassembly flag has been set, and we are extending
	 * the pdu, un-reassemble the pdu. This means pointing old fds to malloc'ed data.
	 */
	if(fd_head->flags & FD_DEFRAGMENTED && frag_number_work >= fd_head->datalen &&
		fd_head->flags & FD_PARTIAL_REASSEMBLY){
		guint32 lastdfpos = 0;
		dfpos = 0;
		for(fd_i=fd_head->next; fd_i; fd_i=fd_i->next){
			if( !fd_i->tvb_data ) {
				if( fd_i->flags & FD_OVERLAP ) {
					/* this is a duplicate of the previous
					 * fragment. */
					fd_i->tvb_data = tvb_new_subset_remaining(fd_head->tvb_data, lastdfpos);
				} else {
					fd_i->tvb_data = tvb_new_subset_remaining(fd_head->tvb_data, dfpos);
					lastdfpos = dfpos;
					dfpos += fd_i->len;
				}
				fd_i->flags |= FD_SUBSET_TVB;
			}
			fd_i->flags &= (~FD_TOOLONGFRAGMENT) & (~FD_MULTIPLETAILS);
		}
		fd_head->flags &= ~(FD_DEFRAGMENTED|FD_PARTIAL_REASSEMBLY|FD_DATALEN_SET);
		fd_head->flags &= (~FD_TOOLONGFRAGMENT) & (~FD_MULTIPLETAILS);
		fd_head->datalen=0;
		fd_head->reassembled_in=0;
		fd_head->reas_in_layer_num = 0;
	}


	/* create new fd describing this fragment */
	fd = g_slice_new(fragment_item);
	fd->next = NULL;
	fd->flags = 0;
	fd->frame = pinfo->num;
	fd->offset = frag_number_work;
	fd->len  = frag_data_len;
	fd->tvb_data = NULL;
	fd->error = NULL;

	/* fd_head->frame is the maximum of the frame numbers of all the
	 * fragments added to the reassembly. */
	if (fd->frame > fd_head->frame)
		fd_head->frame = fd->frame;

	if (!more_frags) {
		/*
		 * This is the tail fragment in the sequence.
		 */
		if (fd_head->flags&FD_DATALEN_SET) {
			/* ok we have already seen other tails for this packet
			 * it might be a duplicate.
			 */
			if (fd_head->datalen != fd->offset ){
				/* Oops, this tail indicates a different packet
				 * len than the previous ones. Something's wrong.
				 */
				fd->flags	|= FD_MULTIPLETAILS;
				fd_head->flags	|= FD_MULTIPLETAILS;
			}
		} else {
			/* this was the first tail fragment, now we know the
			 * sequence number of that fragment (which is NOT
			 * the length of the packet!)
			 */
			fd_head->datalen = fd->offset;
			fd_head->flags |= FD_DATALEN_SET;
		}
	}

	/* If the packet is already defragmented, this MUST be an overlap.
	 * The entire defragmented packet is in fd_head->data
	 * Even if we have previously defragmented this packet, we still check
	 * check it. Someone might play overlap and TTL games.
	 */
	if (fd_head->flags & FD_DEFRAGMENTED) {
		fd->flags	|= FD_OVERLAP;
		fd_head->flags	|= FD_OVERLAP;

		/* make sure it's not past the end */
		if (fd->offset > fd_head->datalen) {
			/* new fragment comes after the end */
			fd->flags	|= FD_TOOLONGFRAGMENT;
			fd_head->flags	|= FD_TOOLONGFRAGMENT;
			LINK_FRAG(fd_head,fd);
			return TRUE;
		}
		/* make sure it doesn't conflict with previous data */
		dfpos=0;
		last_fd=NULL;
		for (fd_i=fd_head->next;fd_i && (fd_i->offset!=fd->offset);fd_i=fd_i->next) {
		  if (!last_fd || last_fd->offset!=fd_i->offset){
			dfpos += fd_i->len;
		  }
		  last_fd=fd_i;
		}
		if(fd_i){
			/* new fragment overlaps existing fragment */
			if(fd_i->len!=fd->len){
				/*
				 * They have different lengths; this
				 * is definitely a conflict.
				 */
				fd->flags	|= FD_OVERLAPCONFLICT;
				fd_head->flags	|= FD_OVERLAPCONFLICT;
				LINK_FRAG(fd_head,fd);
				return TRUE;
			}
			DISSECTOR_ASSERT(fd_head->len >= dfpos + fd->len);
			if (tvb_memeql(fd_head->tvb_data, dfpos,
				tvb_get_ptr(tvb,offset,fd->len),fd->len) ){
				/*
				 * They have the same length, but the
				 * data isn't the same.
				 */
				fd->flags	|= FD_OVERLAPCONFLICT;
				fd_head->flags	|= FD_OVERLAPCONFLICT;
				LINK_FRAG(fd_head,fd);
				return TRUE;
			}
			/* it was just an overlap, link it and return */
			LINK_FRAG(fd_head,fd);
			return TRUE;
		} else {
			/*
			 * New fragment doesn't overlap an existing
			 * fragment - there was presumably a gap in
			 * the sequence number space.
			 *
			 * XXX - what should we do here?  Is it always
			 * the case that there are no gaps, or are there
			 * protcols using sequence numbers where there
			 * can be gaps?
			 *
			 * If the former, the check below for having
			 * received all the fragments should check for
			 * holes in the sequence number space and for the
			 * first sequence number being 0.  If we do that,
			 * the only way we can get here is if this fragment
			 * is past the end of the sequence number space -
			 * but the check for "fd->offset > fd_head->datalen"
			 * would have caught that above, so it can't happen.
			 *
			 * If the latter, we don't have a good way of
			 * knowing whether reassembly is complete if we
			 * get packet out of order such that the "last"
			 * fragment doesn't show up last - but, unless
			 * in-order reliable delivery of fragments is
			 * guaranteed, an implementation of the protocol
			 * has no way of knowing whether reassembly is
			 * complete, either.
			 *
			 * For now, we just link the fragment in and
			 * return.
			 */
			LINK_FRAG(fd_head,fd);
			return TRUE;
		}
	}

	/* If we have reached this point, the packet is not defragmented yet.
	 * Save all payload in a buffer until we can defragment.
	 */
	/* check len, there may be a fragment with 0 len, that is actually the tail */
	if (fd->len) {
		if (!tvb_bytes_exist(tvb, offset, fd->len)) {
			/* abort if we didn't capture the entire fragment due
			 * to a too-short snapshot length */
			g_slice_free(fragment_item, fd);
			return FALSE;
		}

		fd->tvb_data = tvb_clone_offset_len(tvb, offset, fd->len);
	}
	LINK_FRAG(fd_head,fd);


	if( !(fd_head->flags & FD_DATALEN_SET) ){
		/* if we don't know the sequence number of the last fragment,
		 * there are definitely still missing packets. Cheaper than
		 * the check below.
		 */
		return FALSE;
	}


	/* check if we have received the entire fragment
	 * this is easy since the list is sorted and the head is faked.
	 * common case the whole list is scanned.
	 */
	max = 0;
	for(fd_i=fd_head->next;fd_i;fd_i=fd_i->next) {
	  if ( fd_i->offset==max ){
		max++;
	  }
	}
	/* max will now be datalen+1 if all fragments have been seen */

	if (max <= fd_head->datalen) {
		/* we have not received all packets yet */
		return FALSE;
	}


	if (max > (fd_head->datalen+1)) {
		/* oops, too long fragment detected */
		fd->flags	|= FD_TOOLONGFRAGMENT;
		fd_head->flags	|= FD_TOOLONGFRAGMENT;
	}


	/* we have received an entire packet, defragment it and
	 * free all fragments
	 */
	fragment_defragment_and_free(fd_head, pinfo);

	return TRUE;
}

/*
 * This function adds a new fragment to the fragment hash table.
 * If this is the first fragment seen for this datagram, a new entry
 * is created in the hash table, otherwise this fragment is just added
 * to the linked list of fragments for this packet.
 *
 * Returns a pointer to the head of the fragment data list if we have all the
 * fragments, NULL otherwise.
 *
 * This function assumes frag_number being a block sequence number.
 * The bsn for the first block is 0.
 */
static fragment_head *
fragment_add_seq_common(reassembly_table *table, tvbuff_t *tvb,
			const int offset, const packet_info *pinfo,
			const guint32 id, const void *data,
			guint32 frag_number, const guint32 frag_data_len,
			const gboolean more_frags, const guint32 flags,
			gpointer *orig_keyp)
{
	fragment_head *fd_head;
	gpointer orig_key;

	fd_head = lookup_fd_head(table, pinfo, id, data, &orig_key);

	/* have we already seen this frame ?*/
	if (pinfo->fd->visited) {
		if (fd_head != NULL && fd_head->flags & FD_DEFRAGMENTED) {
			if (orig_keyp != NULL)
				*orig_keyp = orig_key;
			return fd_head;
		} else {
			return NULL;
		}
	}

	if (fd_head==NULL){
		/* not found, this must be the first snooped fragment for this
		 * packet. Create list-head.
		 */
		fd_head= new_head(FD_BLOCKSEQUENCE);

		if((flags & (REASSEMBLE_FLAGS_NO_FRAG_NUMBER|REASSEMBLE_FLAGS_802_11_HACK))
		   && !more_frags) {
			/*
			 * This is the last fragment for this packet, and
			 * is the only one we've seen.
			 *
			 * Either we don't have sequence numbers, in which
			 * case we assume this is the first fragment for
			 * this packet, or we're doing special 802.11
			 * processing, in which case we assume it's one
			 * of those reassembled packets with a non-zero
			 * fragment number (see packet-80211.c); just
			 * return a pointer to the head of the list;
			 * fragment_add_seq_check will then add it to the table
			 * of reassembled packets.
			 */
			if (orig_keyp != NULL)
				*orig_keyp = NULL;
			fd_head->reassembled_in=pinfo->num;
			fd_head->reas_in_layer_num = pinfo->curr_layer_num;
			return fd_head;
		}

		orig_key = insert_fd_head(table, fd_head, pinfo, id, data);
		if (orig_keyp != NULL)
			*orig_keyp = orig_key;

		/*
		 * If we weren't given an initial fragment number,
		 * make it 0.
		 */
		if (flags & REASSEMBLE_FLAGS_NO_FRAG_NUMBER)
			frag_number = 0;
	} else {
		if (orig_keyp != NULL)
			*orig_keyp = orig_key;

		if (flags & REASSEMBLE_FLAGS_NO_FRAG_NUMBER) {
			fragment_item *fd;
			/*
			 * If we weren't given an initial fragment number,
			 * use the next expected fragment number as the fragment
			 * number for this fragment.
			 */
			for (fd = fd_head; fd != NULL; fd = fd->next) {
				if (fd->next == NULL)
					frag_number = fd->offset + 1;
			}
		}
	}

	if (fragment_add_seq_work(fd_head, tvb, offset, pinfo,
				  frag_number, frag_data_len, more_frags)) {
		/*
		 * Reassembly is complete.
		 */
		return fd_head;
	} else {
		/*
		 * Reassembly isn't complete.
		 */
		return NULL;
	}
}

fragment_head *
fragment_add_seq(reassembly_table *table, tvbuff_t *tvb, const int offset,
		 const packet_info *pinfo, const guint32 id, const void *data,
		 const guint32 frag_number, const guint32 frag_data_len,
		 const gboolean more_frags, const guint32 flags)
{
	return fragment_add_seq_common(table, tvb, offset, pinfo, id, data,
				       frag_number, frag_data_len,
				       more_frags, flags, NULL);
}

/*
 * This does the work for "fragment_add_seq_check()" and
 * "fragment_add_seq_next()".
 *
 * This function assumes frag_number being a block sequence number.
 * The bsn for the first block is 0.
 *
 * If REASSEMBLE_FLAGS_NO_FRAG_NUMBER, it uses the next expected fragment number
 * as the fragment number if there is a reassembly in progress, otherwise
 * it uses 0.
 *
 * If not REASSEMBLE_FLAGS_NO_FRAG_NUMBER, it uses the "frag_number" argument as
 * the fragment number.
 *
 * If this is the first fragment seen for this datagram, a new
 * "fragment_head" structure is allocated to refer to the reassembled
 * packet.
 *
 * This fragment is added to the linked list of fragments for this packet.
 *
 * If "more_frags" is false and REASSEMBLE_FLAGS_802_11_HACK (as the name
 * implies, a special hack for 802.11) or REASSEMBLE_FLAGS_NO_FRAG_NUMBER
 * (implying messages must be in order since there's no sequence number) are
 * set in "flags", then this (one element) list is returned.
 *
 * If, after processing this fragment, we have all the fragments,
 * "fragment_add_seq_check_work()" removes that from the fragment hash
 * table if necessary and adds it to the table of reassembled fragments,
 * and returns a pointer to the head of the fragment list.
 *
 * Otherwise, it returns NULL.
 *
 * XXX - Should we simply return NULL for zero-length fragments?
 */
static fragment_head *
fragment_add_seq_check_work(reassembly_table *table, tvbuff_t *tvb,
			    const int offset, const packet_info *pinfo,
			    const guint32 id, const void *data,
			    const guint32 frag_number,
			    const guint32 frag_data_len,
			    const gboolean more_frags, const guint32 flags)
{
	reassembled_key reass_key;
	fragment_head *fd_head;
	gpointer orig_key;

	/*
	 * Have we already seen this frame?
	 * If so, look for it in the table of reassembled packets.
	 */
	if (pinfo->fd->visited) {
		reass_key.frame = pinfo->num;
		reass_key.id = id;
		return (fragment_head *)g_hash_table_lookup(table->reassembled_table, &reass_key);
	}

	fd_head = fragment_add_seq_common(table, tvb, offset, pinfo, id, data,
					  frag_number, frag_data_len,
					  more_frags,
					  flags,
					  &orig_key);
	if (fd_head) {
		/*
		 * Reassembly is complete.
		 *
		 * If this is in the table of in-progress reassemblies,
		 * remove it from that table.  (It could be that this
		 * was the first and last fragment, so that no
		 * reassembly was done.)
		 */
		if (orig_key != NULL)
			fragment_unhash(table, orig_key);

		/*
		 * Add this item to the table of reassembled packets.
		 */
		fragment_reassembled(table, fd_head, pinfo, id);
		return fd_head;
	} else {
		/*
		 * Reassembly isn't complete.
		 */
		return NULL;
	}
}

fragment_head *
fragment_add_seq_check(reassembly_table *table, tvbuff_t *tvb, const int offset,
		       const packet_info *pinfo, const guint32 id,
		       const void *data,
		       const guint32 frag_number, const guint32 frag_data_len,
		       const gboolean more_frags)
{
	return fragment_add_seq_check_work(table, tvb, offset, pinfo, id, data,
					   frag_number, frag_data_len,
					   more_frags, 0);
}

fragment_head *
fragment_add_seq_802_11(reassembly_table *table, tvbuff_t *tvb,
			const int offset, const packet_info *pinfo,
			const guint32 id, const void *data,
			const guint32 frag_number, const guint32 frag_data_len,
			const gboolean more_frags)
{
	return fragment_add_seq_check_work(table, tvb, offset, pinfo, id, data,
					   frag_number, frag_data_len,
					   more_frags,
					   REASSEMBLE_FLAGS_802_11_HACK);
}

fragment_head *
fragment_add_seq_next(reassembly_table *table, tvbuff_t *tvb, const int offset,
		      const packet_info *pinfo, const guint32 id,
		      const void *data, const guint32 frag_data_len,
		      const gboolean more_frags)
{
	/* Use a dummy frag_number (0), it is ignored since
	 * REASSEMBLE_FLAGS_NO_FRAG_NUMBER is set. */
	return fragment_add_seq_check_work(table, tvb, offset, pinfo, id, data,
					   0, frag_data_len, more_frags,
					   REASSEMBLE_FLAGS_NO_FRAG_NUMBER);
}

static void
fragment_add_seq_single_move(reassembly_table *table, const packet_info *pinfo,
		             const guint32 id, const void *data,
			     const guint32 offset)
{
	fragment_head *fh, *new_fh;
	fragment_item *fd, *prev_fd;
	tvbuff_t *old_tvb_data;
	if (offset == 0) {
		return;
	}
	fh = lookup_fd_head(table, pinfo, id, data, NULL);
	if (fh == NULL) {
		/* Shouldn't be called this way.
		 * Probably wouldn't hurt to just create fh in this case. */
		ws_assert_not_reached();
		return;
	}
	if (fh->flags & FD_DATALEN_SET && fh->datalen <= offset) {
		/* Don't take from past the end. <= because we don't
		 * want to take a First fragment from the next one
		 * either */
		return;
	}
	new_fh = lookup_fd_head(table, pinfo, id+offset, data, NULL);
	if (new_fh != NULL) {
		/* Attach to the end of the sorted list. */
		for(prev_fd = fh; prev_fd->next != NULL; prev_fd=prev_fd->next) {}
		/* Don't take a reassembly starting with a First fragment. */
		fd = new_fh->next;
		if (fd && fd->offset != 0) {
			prev_fd->next = fd;
			for (; fd; fd=fd->next) {
				fd->offset += offset;
				if (fh->frame < fd->frame) {
					fh->frame = fd->frame;
				}
			}
			/* If previously found a Last fragment,
			 * transfer that info to the new one. */
			if (new_fh->flags & FD_DATALEN_SET) {
				fh->flags |= FD_DATALEN_SET;
				fh->datalen = new_fh->datalen + offset;
			}
			/* Now remove and delete */
			new_fh->next = NULL;
			old_tvb_data = fragment_delete(table, pinfo, id+offset, data);
			if (old_tvb_data)
				tvb_free(old_tvb_data);
		}
	}
}

static fragment_head *
fragment_add_seq_single_work(reassembly_table *table, tvbuff_t *tvb,
			     const int offset, const packet_info *pinfo,
		             const guint32 id, const void* data,
			     const guint32 frag_data_len,
			     const gboolean first, const gboolean last,
			     const guint32 max_frags, const guint32 max_age,
			     const guint32 flags)
{
	reassembled_key reass_key;
	tvbuff_t *old_tvb_data;
	gpointer orig_key;
	fragment_head *fh, *new_fh;
	fragment_item *fd, *prev_fd;
	guint32 frag_number, tmp_offset;
	/* Have we already seen this frame?
	 * If so, look for it in the table of reassembled packets.
	 * Note here we store in the reassembly table by the single sequence
	 * number rather than the sequence number of the First fragment. */
	if (pinfo->fd->visited) {
		reass_key.frame = pinfo->num;
		reass_key.id = id;
		fh = (fragment_head *)g_hash_table_lookup(table->reassembled_table, &reass_key);
		return fh;
	}
	/* First let's figure out where we want to add our new fragment */
	fh = NULL;
	if (first) {
		frag_number = 0;
		fh = lookup_fd_head(table, pinfo, id-frag_number, data, NULL);
		if ((flags & REASSEMBLE_FLAGS_AGING) &&
		    fh && ((fh->frame + max_age) < pinfo->num)) {
			old_tvb_data = fragment_delete(table, pinfo, id-frag_number, data);
			if (old_tvb_data)
				tvb_free(old_tvb_data);
			fh = NULL;
		}
		if (fh == NULL) {
			/* Not found. Create list-head. */
			fh = new_head(FD_BLOCKSEQUENCE);
			insert_fd_head(table, fh, pinfo, id-frag_number, data);
		}
		/* As this is the first fragment, we might have added segments
		 * for this reassembly to the previous one in-progress. */
		fd = NULL;
		for (frag_number=1; frag_number < max_frags; frag_number++) {
			new_fh = lookup_fd_head(table, pinfo, id-frag_number, data, NULL);
			if (new_fh != NULL) {
				prev_fd = new_fh;
				new_fh->frame = 0;
				for (fd=new_fh->next; fd && fd->offset < frag_number; fd=fd->next) {
					prev_fd = fd;
					if (new_fh->frame < fd->frame) {
						new_fh->frame = fd->frame;
					}
				}
				prev_fd->next = NULL;
				break;
			}
		}
		if (fd != NULL) {
			tmp_offset = 0;
			for (prev_fd = fd; prev_fd; prev_fd = prev_fd->next) {
				prev_fd->offset -= frag_number;
				tmp_offset = prev_fd->offset;
				if (fh->frame < prev_fd->frame) {
					fh->frame = prev_fd->frame;
				}
			}
			MERGE_FRAG(fh, fd);
			if (new_fh != NULL) {
				/* If we've moved a Last packet, change datalen.
			         * Second part of this test prob. redundant? */
				if (new_fh->flags & FD_DATALEN_SET &&
				    new_fh->datalen >= frag_number) {
					fh->flags |= FD_DATALEN_SET;
					fh->datalen = new_fh->datalen - frag_number;
					new_fh->flags &= ~FD_DATALEN_SET;
					new_fh->datalen = 0;
				}
				/* If we've moved all the fragments,
				 * delete the old head */
				if (new_fh->next == NULL) {
					old_tvb_data = fragment_delete(table, pinfo, id-frag_number, data);
					if (old_tvb_data)
						tvb_free(old_tvb_data);
				}
			} else {
			/* Look forward and take off the next (this is
			 * necessary in some edge cases where max_frags
			 * prevented some fragments from going on the
			 * previous First, but they can go on this one. */
				fragment_add_seq_single_move(table, pinfo, id,
							     data, tmp_offset);
			}
		}
		frag_number = 0; /* For the rest of the function */
	} else {
		for (frag_number=1; frag_number < max_frags; frag_number++) {
			fh = lookup_fd_head(table, pinfo, id-frag_number, data, NULL);
			if ((flags & REASSEMBLE_FLAGS_AGING) &&
			    fh && ((fh->frame + max_age) < pinfo->num)) {
				old_tvb_data = fragment_delete(table, pinfo, id-frag_number, data);
				if (old_tvb_data)
					tvb_free(old_tvb_data);
				fh = NULL;
			}
			if (fh != NULL) {
				if (fh->flags & FD_DATALEN_SET &&
				    fh->datalen < frag_number) {
					/* This fragment is after the Last
					 * fragment, so must go after here. */
					fh = NULL;
				}
				break;
			}
		}
		if (fh == NULL) { /* Didn't find location, use default */
			frag_number = 1;
			/* Already looked for frag_number 1, so just create */
			fh = new_head(FD_BLOCKSEQUENCE);
			insert_fd_head(table, fh, pinfo, id-frag_number, data);
		}
	}
	if (last) {
		/* Look for fragments past the end set by this Last fragment. */
		prev_fd = fh;
		for (fd=fh->next; fd && fd->offset <= frag_number; fd=fd->next) {
			prev_fd = fd;
		}
		/* fd is now all fragments offset > frag_number (the Last).
		 * It shouldn't have a fragment with offset frag_number+1,
		 * as that would be a First fragment not marked as such.
		 * However, this can happen if we had unreassembled fragments
		 * (missing, or at the start of the capture) and we've also
		 * looped around on the sequence numbers. It can also happen
		 * if bit errors mess up Last or First. */
		if (fd != NULL) {
			prev_fd->next = NULL;
			fh->frame = 0;
			for (prev_fd=fh->next; prev_fd; prev_fd=prev_fd->next) {
				if (fh->frame < prev_fd->frame) {
					fh->frame = prev_fd->frame;
				}
			}
			while (fd && fd->offset == frag_number+1) {
				/* Definitely have bad data here. Best to
				 * delete these and leave unreassembled. */
				fragment_item *tmp_fd;
				tmp_fd=fd->next;

				if (fd->tvb_data && !(fd->flags & FD_SUBSET_TVB))
					tvb_free(fd->tvb_data);
				g_slice_free(fragment_item, fd);
				fd=tmp_fd;
			}
		}
		if (fd != NULL) {
			/* Move these onto the next frame. */
			new_fh = lookup_fd_head(table, pinfo, id+1, data, NULL);
			if (new_fh==NULL) {
				/* Not found. Create list-head. */
				new_fh = new_head(FD_BLOCKSEQUENCE);
				insert_fd_head(table, new_fh, pinfo, id+1, data);
			}
			tmp_offset = 0;
			for (prev_fd = fd; prev_fd; prev_fd = prev_fd->next) {
				prev_fd->offset -= (frag_number+1);
				tmp_offset = prev_fd->offset;
				if (new_fh->frame < fd->frame) {
					new_fh->frame = fd->frame;
				}
			}
			MERGE_FRAG(new_fh, fd);
			/* If we previously found a different Last fragment,
			 * transfer that information to the new reassembly. */
			if (fh->flags & FD_DATALEN_SET &&
			    fh->datalen > frag_number) {
				new_fh->flags |= FD_DATALEN_SET;
				new_fh->datalen = fh->datalen - (frag_number+1);
				fh->flags &= ~FD_DATALEN_SET;
				fh->datalen = 0;
			} else {
			/* Look forward and take off the next (this is
			 * necessary in some edge cases where max_frags
			 * prevented some fragments from going on the
			 * previous First, but they can go on this one. */
				fragment_add_seq_single_move(table, pinfo, id+1,
							     data, tmp_offset);
			}
		}
	} else {
		fragment_add_seq_single_move(table, pinfo, id-frag_number, data,
				             frag_number+1);
	}
	/* Having cleaned up everything, finally ready to add our new
	 * fragment. Note that only this will ever complete a reassembly. */
	fh = fragment_add_seq_common(table, tvb, offset, pinfo,
					 id-frag_number, data,
					 frag_number, frag_data_len,
					 !last, 0, &orig_key);
	if (fh) {
		/*
		 * Reassembly is complete.
		 *
		 * If this is in the table of in-progress reassemblies,
		 * remove it from that table.  (It could be that this
		 * was the first and last fragment, so that no
		 * reassembly was done.)
		 */
		if (orig_key != NULL)
			fragment_unhash(table, orig_key);

		/*
		 * Add this item to the table of reassembled packets.
		 */
		fragment_reassembled_single(table, fh, pinfo, id-frag_number);
		return fh;
	} else {
		/*
		 * Reassembly isn't complete.
		 */
		return NULL;
	}
}

fragment_head *
fragment_add_seq_single(reassembly_table *table, tvbuff_t *tvb,
			     const int offset, const packet_info *pinfo,
		             const guint32 id, const void* data,
			     const guint32 frag_data_len,
			     const gboolean first, const gboolean last,
			     const guint32 max_frags)
{
	return fragment_add_seq_single_work(table, tvb, offset, pinfo,
					    id, data, frag_data_len,
					    first, last, max_frags, 0, 0);
}

fragment_head *
fragment_add_seq_single_aging(reassembly_table *table, tvbuff_t *tvb,
			     const int offset, const packet_info *pinfo,
		             const guint32 id, const void* data,
			     const guint32 frag_data_len,
			     const gboolean first, const gboolean last,
			     const guint32 max_frags, const guint32 max_age)
{
	return fragment_add_seq_single_work(table, tvb, offset, pinfo,
					    id, data, frag_data_len,
					    first, last, max_frags, max_age,
					    REASSEMBLE_FLAGS_AGING);
}

void
fragment_start_seq_check(reassembly_table *table, const packet_info *pinfo,
			 const guint32 id, const void *data,
			 const guint32 tot_len)
{
	fragment_head *fd_head;

	/* Have we already seen this frame ?*/
	if (pinfo->fd->visited) {
		return;
	}

	/* Check if fragment data exists */
	fd_head = lookup_fd_head(table, pinfo, id, data, NULL);

	if (fd_head == NULL) {
		/* Create list-head. */
		fd_head = g_slice_new(fragment_head);
		fd_head->next = NULL;
		fd_head->frame = 0;
		fd_head->offset = 0;
		fd_head->len = 0;
		fd_head->fragment_nr_offset = 0;
		fd_head->datalen = tot_len;
		fd_head->reassembled_in = 0;
		fd_head->reas_in_layer_num = 0;
		fd_head->flags = FD_BLOCKSEQUENCE|FD_DATALEN_SET;
		fd_head->tvb_data = NULL;
		fd_head->error = NULL;

		insert_fd_head(table, fd_head, pinfo, id, data);
	}
}

fragment_head *
fragment_end_seq_next(reassembly_table *table, const packet_info *pinfo,
		      const guint32 id, const void *data)
{
	reassembled_key reass_key;
	reassembled_key *new_key;
	fragment_head *fd_head;
	gpointer orig_key;

	/*
	 * Have we already seen this frame?
	 * If so, look for it in the table of reassembled packets.
	 */
	if (pinfo->fd->visited) {
		reass_key.frame = pinfo->num;
		reass_key.id = id;
		return (fragment_head *)g_hash_table_lookup(table->reassembled_table, &reass_key);
	}

	fd_head = lookup_fd_head(table, pinfo, id, data, &orig_key);

	if (fd_head) {
		fd_head->datalen = fd_head->offset;
		fd_head->flags |= FD_DATALEN_SET;

		fragment_defragment_and_free (fd_head, pinfo);

		/*
		 * Remove this from the table of in-progress reassemblies,
		 * and free up any memory used for it in that table.
		 */
		fragment_unhash(table, orig_key);

		/*
		 * Add this item to the table of reassembled packets.
		 */
		fragment_reassembled(table, fd_head, pinfo, id);
		if (fd_head->next != NULL) {
			new_key = g_slice_new(reassembled_key);
			new_key->frame = pinfo->num;
			new_key->id = id;
			g_hash_table_insert(table->reassembled_table, new_key, fd_head);
		}

		return fd_head;
	} else {
		/*
		 * Fragment data not found.
		 */
		return NULL;
	}
}

/*
 * Process reassembled data; if we're on the frame in which the data
 * was reassembled, put the fragment information into the protocol
 * tree, and construct a tvbuff with the reassembled data, otherwise
 * just put a "reassembled in" item into the protocol tree.
 * offset from start of tvb, result up to end of tvb
 */
tvbuff_t *
process_reassembled_data(tvbuff_t *tvb, const int offset, packet_info *pinfo,
	const char *name, fragment_head *fd_head, const fragment_items *fit,
	gboolean *update_col_infop, proto_tree *tree)
{
	tvbuff_t *next_tvb;
	gboolean update_col_info;
	proto_item *frag_tree_item;

	if (fd_head != NULL && pinfo->num == fd_head->reassembled_in && pinfo->curr_layer_num == fd_head->reas_in_layer_num) {
		/*
		 * OK, we've reassembled this.
		 * Is this something that's been reassembled from more
		 * than one fragment?
		 */
		if (fd_head->next != NULL) {
			/*
			 * Yes.
			 * Allocate a new tvbuff, referring to the
			 * reassembled payload, and set
			 * the tvbuff to the list of tvbuffs to which
			 * the tvbuff we were handed refers, so it'll get
			 * cleaned up when that tvbuff is cleaned up.
			 */
			next_tvb = tvb_new_chain(tvb, fd_head->tvb_data);

			/* Add the defragmented data to the data source list. */
			add_new_data_source(pinfo, next_tvb, name);

			/* show all fragments */
			if (fd_head->flags & FD_BLOCKSEQUENCE) {
				update_col_info = !show_fragment_seq_tree(
					fd_head, fit,  tree, pinfo, next_tvb, &frag_tree_item);
			} else {
				update_col_info = !show_fragment_tree(fd_head,
					fit, tree, pinfo, next_tvb, &frag_tree_item);
			}
		} else {
			/*
			 * No.
			 * Return a tvbuff with the payload. next_tvb ist from offset until end
			 */
			next_tvb = tvb_new_subset_remaining(tvb, offset);
			pinfo->fragmented = FALSE;	/* one-fragment packet */
			update_col_info = TRUE;
		}
		if (update_col_infop != NULL)
			*update_col_infop = update_col_info;
	} else {
		/*
		 * We don't have the complete reassembled payload, or this
		 * isn't the final frame of that payload.
		 */
		next_tvb = NULL;

		/*
		 * If we know what frame this was reassembled in,
		 * and if there's a field to use for the number of
		 * the frame in which the packet was reassembled,
		 * add it to the protocol tree.
		 */
		if (fd_head != NULL && fit->hf_reassembled_in != NULL) {
			proto_item *fei = proto_tree_add_uint(tree,
				*(fit->hf_reassembled_in), tvb,
				0, 0, fd_head->reassembled_in);
			proto_item_set_generated(fei);
		}
	}
	return next_tvb;
}

/*
 * Show a single fragment in a fragment subtree, and put information about
 * it in the top-level item for that subtree.
 */
static void
show_fragment(fragment_item *fd, const int offset, const fragment_items *fit,
	proto_tree *ft, proto_item *fi, const gboolean first_frag,
	const guint32 count, tvbuff_t *tvb, packet_info *pinfo)
{
	proto_item *fei=NULL;
	int hf;

	if (first_frag) {
		gchar *name;
		if (count == 1) {
			name = g_strdup(proto_registrar_get_name(*(fit->hf_fragment)));
		} else {
			name = g_strdup(proto_registrar_get_name(*(fit->hf_fragments)));
		}
		proto_item_set_text(fi, "%u %s (%u byte%s): ", count, name, tvb_captured_length(tvb),
				    plurality(tvb_captured_length(tvb), "", "s"));
		g_free(name);
	} else {
		proto_item_append_text(fi, ", ");
	}
	proto_item_append_text(fi, "#%u(%u)", fd->frame, fd->len);

	if (fd->flags & (FD_OVERLAPCONFLICT
		|FD_MULTIPLETAILS|FD_TOOLONGFRAGMENT) ) {
		hf = *(fit->hf_fragment_error);
	} else {
		hf = *(fit->hf_fragment);
	}
	if (fd->len == 0) {
		fei = proto_tree_add_uint_format(ft, hf,
			tvb, offset, fd->len,
			fd->frame,
			"Frame: %u (no data)",
			fd->frame);
	} else {
		fei = proto_tree_add_uint_format(ft, hf,
			tvb, offset, fd->len,
			fd->frame,
			"Frame: %u, payload: %u-%u (%u byte%s)",
			fd->frame,
			offset,
			offset+fd->len-1,
			fd->len,
			plurality(fd->len, "", "s"));
	}
	proto_item_set_generated(fei);
	mark_frame_as_depended_upon(pinfo, fd->frame);
	if (fd->flags & (FD_OVERLAP|FD_OVERLAPCONFLICT
		|FD_MULTIPLETAILS|FD_TOOLONGFRAGMENT) ) {
		/* this fragment has some flags set, create a subtree
		 * for it and display the flags.
		 */
		proto_tree *fet=NULL;

		fet = proto_item_add_subtree(fei, *(fit->ett_fragment));
		if (fd->flags&FD_OVERLAP) {
			fei=proto_tree_add_boolean(fet,
				*(fit->hf_fragment_overlap),
				tvb, 0, 0,
				TRUE);
			proto_item_set_generated(fei);
		}
		if (fd->flags&FD_OVERLAPCONFLICT) {
			fei=proto_tree_add_boolean(fet,
				*(fit->hf_fragment_overlap_conflict),
				tvb, 0, 0,
				TRUE);
			proto_item_set_generated(fei);
		}
		if (fd->flags&FD_MULTIPLETAILS) {
			fei=proto_tree_add_boolean(fet,
				*(fit->hf_fragment_multiple_tails),
				tvb, 0, 0,
				TRUE);
			proto_item_set_generated(fei);
		}
		if (fd->flags&FD_TOOLONGFRAGMENT) {
			fei=proto_tree_add_boolean(fet,
				*(fit->hf_fragment_too_long_fragment),
				tvb, 0, 0,
				TRUE);
			proto_item_set_generated(fei);
		}
	}
}

static gboolean
show_fragment_errs_in_col(fragment_head *fd_head, const fragment_items *fit,
	packet_info *pinfo)
{
	if (fd_head->flags & (FD_OVERLAPCONFLICT
		|FD_MULTIPLETAILS|FD_TOOLONGFRAGMENT) ) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "[Illegal %s]", fit->tag);
		return TRUE;
	}

	return FALSE;
}

/* This function will build the fragment subtree; it's for fragments
   reassembled with "fragment_add()".

   It will return TRUE if there were fragmentation errors
   or FALSE if fragmentation was ok.
*/
gboolean
show_fragment_tree(fragment_head *fd_head, const fragment_items *fit,
	proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, proto_item **fi)
{
	fragment_item *fd;
	proto_tree *ft;
	gboolean first_frag;
	guint32 count = 0;
	/* It's not fragmented. */
	pinfo->fragmented = FALSE;

	*fi = proto_tree_add_item(tree, *(fit->hf_fragments), tvb, 0, -1, ENC_NA);
	proto_item_set_generated(*fi);

	ft = proto_item_add_subtree(*fi, *(fit->ett_fragments));
	first_frag = TRUE;
	for (fd = fd_head->next; fd != NULL; fd = fd->next) {
		count++;
	}
	for (fd = fd_head->next; fd != NULL; fd = fd->next) {
		show_fragment(fd, fd->offset, fit, ft, *fi, first_frag, count, tvb, pinfo);
		first_frag = FALSE;
	}

	if (fit->hf_fragment_count) {
		proto_item *fli = proto_tree_add_uint(ft, *(fit->hf_fragment_count),
						      tvb, 0, 0, count);
		proto_item_set_generated(fli);
	}

	if (fit->hf_reassembled_length) {
		proto_item *fli = proto_tree_add_uint(ft, *(fit->hf_reassembled_length),
						      tvb, 0, 0, tvb_captured_length (tvb));
		proto_item_set_generated(fli);
	}

	if (fit->hf_reassembled_data) {
		proto_item *fli = proto_tree_add_item(ft, *(fit->hf_reassembled_data),
						      tvb, 0, tvb_captured_length(tvb), ENC_NA);
		proto_item_set_generated(fli);
	}

	return show_fragment_errs_in_col(fd_head, fit, pinfo);
}

/* This function will build the fragment subtree; it's for fragments
   reassembled with "fragment_add_seq()" or "fragment_add_seq_check()".

   It will return TRUE if there were fragmentation errors
   or FALSE if fragmentation was ok.
*/
gboolean
show_fragment_seq_tree(fragment_head *fd_head, const fragment_items *fit,
	proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, proto_item **fi)
{
	guint32 offset, next_offset, count = 0;
	fragment_item *fd, *last_fd;
	proto_tree *ft;
	gboolean first_frag;

	/* It's not fragmented. */
	pinfo->fragmented = FALSE;

	*fi = proto_tree_add_item(tree, *(fit->hf_fragments), tvb, 0, -1, ENC_NA);
	proto_item_set_generated(*fi);

	ft = proto_item_add_subtree(*fi, *(fit->ett_fragments));
	offset = 0;
	next_offset = 0;
	last_fd = NULL;
	first_frag = TRUE;
	for (fd = fd_head->next; fd != NULL; fd = fd->next){
		count++;
	}
	for (fd = fd_head->next; fd != NULL; fd = fd->next){
		if (last_fd == NULL || last_fd->offset != fd->offset) {
			offset = next_offset;
			next_offset += fd->len;
		}
		last_fd = fd;
		show_fragment(fd, offset, fit, ft, *fi, first_frag, count, tvb, pinfo);
		first_frag = FALSE;
	}

	if (fit->hf_fragment_count) {
		proto_item *fli = proto_tree_add_uint(ft, *(fit->hf_fragment_count),
						      tvb, 0, 0, count);
		proto_item_set_generated(fli);
	}

	if (fit->hf_reassembled_length) {
		proto_item *fli = proto_tree_add_uint(ft, *(fit->hf_reassembled_length),
						      tvb, 0, 0, tvb_captured_length (tvb));
		proto_item_set_generated(fli);
	}

	if (fit->hf_reassembled_data) {
		proto_item *fli = proto_tree_add_item(ft, *(fit->hf_reassembled_data),
						      tvb, 0, tvb_captured_length(tvb), ENC_NA);
		proto_item_set_generated(fli);
	}

	return show_fragment_errs_in_col(fd_head, fit, pinfo);
}

static void
reassembly_table_init_reg_table(gpointer p, gpointer user_data _U_)
{
	register_reassembly_table_t* reg_table = (register_reassembly_table_t*)p;
	reassembly_table_init(reg_table->table, reg_table->funcs);
}

static void
reassembly_table_init_reg_tables(void)
{
	g_list_foreach(reassembly_table_list, reassembly_table_init_reg_table, NULL);
}

static void
reassembly_table_cleanup_reg_table(gpointer p, gpointer user_data _U_)
{
	register_reassembly_table_t* reg_table = (register_reassembly_table_t*)p;
	reassembly_table_destroy(reg_table->table);
}

static void
reassembly_table_cleanup_reg_tables(void)
{
	g_list_foreach(reassembly_table_list, reassembly_table_cleanup_reg_table, NULL);
}

void reassembly_tables_init(void)
{
	register_init_routine(&reassembly_table_init_reg_tables);
	register_cleanup_routine(&reassembly_table_cleanup_reg_tables);
}

static void
reassembly_table_free(gpointer p, gpointer user_data _U_)
{
	register_reassembly_table_t* reg_table = (register_reassembly_table_t*)p;
	reassembly_table_destroy(reg_table->table);
	g_free(reg_table);
}

void
reassembly_table_cleanup(void)
{
	g_list_foreach(reassembly_table_list, reassembly_table_free, NULL);
	g_list_free(reassembly_table_list);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
