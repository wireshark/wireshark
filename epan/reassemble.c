/* reassemble.c
 * Routines for {fragment,segment} reassembly
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>

#include <epan/packet.h>

#include <epan/reassemble.h>

#include <epan/emem.h>

#include <epan/dissectors/packet-dcerpc.h>

typedef struct _fragment_key {
	address src;
	address dst;
	guint32 id;
} fragment_key;

typedef struct _dcerpc_fragment_key {
	address src;
	address dst;
	guint32 id;
	e_uuid_t act_id;
} dcerpc_fragment_key;

static void LINK_FRAG(fragment_data *fd_head,fragment_data *fd)
{
	fragment_data *fd_i;

	/* add fragment to list, keep list sorted */
	for(fd_i= fd_head; fd_i->next;fd_i=fd_i->next) {
		if (fd->offset < fd_i->next->offset )
			break;
	}
	fd->next=fd_i->next;
	fd_i->next=fd;
}

/* copy a fragment key to heap store to insert in the hash */
static void *fragment_key_copy(const void *k)
{
	const fragment_key* key = (const fragment_key*) k;
	fragment_key *new_key = g_slice_new(fragment_key);

	COPY_ADDRESS(&new_key->src, &key->src);
	COPY_ADDRESS(&new_key->dst, &key->dst);
	new_key->id = key->id;
	return new_key;
}

/* copy a dcerpc fragment key to heap store to insert in the hash */
static void *dcerpc_fragment_key_copy(const void *k)
{
	const dcerpc_fragment_key* key = (const dcerpc_fragment_key*) k;

	dcerpc_fragment_key *new_key = g_slice_new(dcerpc_fragment_key);

	COPY_ADDRESS(&new_key->src, &key->src);
	COPY_ADDRESS(&new_key->dst, &key->dst);
	new_key->id = key->id;
	new_key->act_id = key->act_id;

	return new_key;
}


static gint
fragment_equal(gconstpointer k1, gconstpointer k2)
{
	const fragment_key* key1 = (const fragment_key*) k1;
	const fragment_key* key2 = (const fragment_key*) k2;

	/*key.id is the first item to compare since item is most
	  likely to differ between sessions, thus shortcircuiting
	  the comparasion of addresses.
	*/
	return ( ( (key1->id	== key2->id) &&
		   (ADDRESSES_EQUAL(&key1->src, &key2->src)) &&
		   (ADDRESSES_EQUAL(&key1->dst, &key2->dst))
		 ) ?
		 TRUE : FALSE);
}

static guint
fragment_hash(gconstpointer k)
{
	const fragment_key* key = (const fragment_key*) k;
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
dcerpc_fragment_equal(gconstpointer k1, gconstpointer k2)
{
	const dcerpc_fragment_key* key1 = (const dcerpc_fragment_key*) k1;
	const dcerpc_fragment_key* key2 = (const dcerpc_fragment_key*) k2;

	/*key.id is the first item to compare since item is most
	  likely to differ between sessions, thus shortcircuiting
	  the comparison of addresses.
	*/
	return (((key1->id == key2->id)
		  && (ADDRESSES_EQUAL(&key1->src, &key2->src))
		  && (ADDRESSES_EQUAL(&key1->dst, &key2->dst))
		  && (memcmp (&key1->act_id, &key2->act_id, sizeof (e_uuid_t)) == 0))
		 ? TRUE : FALSE);
}

static guint
dcerpc_fragment_hash(gconstpointer k)
{
	const dcerpc_fragment_key* key = (const dcerpc_fragment_key*) k;
	guint hash_val;

	hash_val = 0;

	hash_val += key->id;
	hash_val += key->act_id.Data1;
	hash_val += key->act_id.Data2 << 16;
	hash_val += key->act_id.Data3;

	return hash_val;
}

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

/*
 * For a fragment hash table entry, free the associated fragments.
 * The entry value (fd_chain) is freed herein and the entry is freed
 * when fragment_free_key() [or dcerpc_fragment_free_key()] is called
 * (as a consequence of returning TRUE from this function).
 */
static gboolean
free_all_fragments(gpointer key_arg _U_, gpointer value, gpointer user_data _U_)
{
	fragment_data *fd_head, *tmp_fd;

	/* g_hash_table_new_full() was used to supply a function
	 * to free the key and the addresses.
	 */
	for (fd_head = value; fd_head != NULL; fd_head = tmp_fd) {
		tmp_fd=fd_head->next;

		if(fd_head->data && !(fd_head->flags&FD_NOT_MALLOCED))
			g_free(fd_head->data);
		g_slice_free(fragment_data, fd_head);
	}

	return TRUE;
}

/* ------------------------- */
static fragment_data *new_head(const guint32 flags)
{
	fragment_data *fd_head;
	/* If head/first structure in list only holds no other data than
	* 'datalen' then we don't have to change the head of the list
	* even if we want to keep it sorted
	*/
	fd_head=g_slice_new0(fragment_data);

	fd_head->flags=flags;
	return fd_head;
}

/*
 * For a reassembled-packet hash table entry, free the fragment data
 * to which the value refers.
 */
static gboolean
free_all_reassembled_fragments(gpointer key_arg _U_, gpointer value,
				   gpointer user_data _U_)
{
	fragment_data *fd_head;

	for (fd_head = value; fd_head != NULL; fd_head = fd_head->next) {
		if(fd_head->data && !(fd_head->flags&FD_NOT_MALLOCED)) {
			g_free(fd_head->data);

			/*
			 * A reassembled packet is inserted into the
			 * hash table once for every frame that made
			 * up the reassembled packet; clear the data
			 * pointer so that we only free the data the
			 * first time we see it.
			 */
			fd_head->data = NULL;
		}
	}

	return TRUE;
}

static void
fragment_free_key(void *ptr)
{
	fragment_key *key = (fragment_key *)ptr;

	if(key){
		/*
		 * Free up the copies of the addresses from the old key.
		 */
		g_free((gpointer)key->src.data);
		g_free((gpointer)key->dst.data);

		g_slice_free(fragment_key, key);
	}
}

static void
dcerpc_fragment_free_key(void *ptr)
{
	dcerpc_fragment_key *key = (dcerpc_fragment_key *)ptr;

	if(key){
		/*
		 * Free up the copies of the addresses from the old key.
		 */
		g_free((gpointer)key->src.data);
		g_free((gpointer)key->dst.data);

		g_slice_free(dcerpc_fragment_key, key);
	}
}

/*
 * Initialize a fragment table.
 */
void
fragment_table_init(GHashTable **fragment_table)
{
	if (*fragment_table != NULL) {
		/*
		 * The fragment hash table exists.
		 *
		 * Remove all entries and free fragment data for each entry.
		 *
		 * If slices are used (GLIB >= 2.10)
		 * the keys are freed by calling fragment_free_key()
		 * and the values are freed in free_all_fragments().
		 *
		 * free_all_fragments()
		 * will free the address data associated with the key
		 */
		g_hash_table_foreach_remove(*fragment_table,
				free_all_fragments, NULL);
	} else {
		/* The fragment table does not exist. Create it */
		*fragment_table = g_hash_table_new_full(fragment_hash,
							fragment_equal, fragment_free_key, NULL);
	}
}

void
dcerpc_fragment_table_init(GHashTable **fragment_table)
{
	if (*fragment_table != NULL) {
		/*
		 * The fragment hash table exists.
		 *
		 * Remove all entries and free fragment data for each entry.
		 *
		 * If slices are used (GLIB >= 2.10)
		 * the keys are freed by calling dcerpc_fragment_free_key()
		 * and the values are freed in free_all_fragments().
		 *
		 * free_all_fragments()
		 * will free the adrress data associated with the key
		 */
		   g_hash_table_foreach_remove(*fragment_table,
						   free_all_fragments, NULL);
	} else {
		   /* The fragment table does not exist. Create it */
		*fragment_table = g_hash_table_new_full(dcerpc_fragment_hash,
							dcerpc_fragment_equal, dcerpc_fragment_free_key, NULL);
	}
}

/*
 * Initialize a reassembled-packet table.
 */
void
reassembled_table_init(GHashTable **reassembled_table)
{
	if (*reassembled_table != NULL) {
		/*
		 * The reassembled-packet hash table exists.
		 *
		 * Remove all entries and free reassembled packet
		 * data for each entry.
		 */
		g_hash_table_foreach_remove(*reassembled_table,
				free_all_reassembled_fragments, NULL);
	} else {
		/* The fragment table does not exist. Create it */
		*reassembled_table = g_hash_table_new(reassembled_hash,
				reassembled_equal);
	}
}

/* This function cleans up the stored state and removes the reassembly data and
 * (with one exception) all allocated memory for matching reassembly.
 *
 * The exception is :
 * If the PDU was already completely reassembled, then the buffer containing the
 * reassembled data WILL NOT be free()d, and the pointer to that buffer will be
 * returned.
 * Othervise the function will return NULL.
 *
 * So, if you call fragment_delete and it returns non-NULL, YOU are responsible to
 * g_free() that buffer.
 */
unsigned char *
fragment_delete(const packet_info *pinfo, const guint32 id, GHashTable *fragment_table)
{
	fragment_data *fd_head, *fd;
	fragment_key key;
	unsigned char *data=NULL;

	/* create key to search hash with */
	key.src = pinfo->src;
	key.dst = pinfo->dst;
	key.id	= id;

	fd_head = g_hash_table_lookup(fragment_table, &key);

	if(fd_head==NULL){
		/* We do not recognize this as a PDU we have seen before. return */
		return NULL;
	}

	data=fd_head->data;
	/* loop over all partial fragments and free any buffers */
	for(fd=fd_head->next;fd;){
		fragment_data *tmp_fd;
		tmp_fd=fd->next;

		if( !(fd->flags&FD_NOT_MALLOCED) )
			g_free(fd->data);
		g_slice_free(fragment_data, fd);
		fd=tmp_fd;
	}
	g_slice_free(fragment_data, fd_head);
	g_hash_table_remove(fragment_table, &key);

	return data;
}

/* This function is used to check if there is partial or completed reassembly state
 * matching this packet. I.e. Is there reassembly going on or not for this packet?
 */
fragment_data *
fragment_get(const packet_info *pinfo, const guint32 id, GHashTable *fragment_table)
{
	fragment_data *fd_head;
	fragment_key key;

	/* create key to search hash with */
	key.src = pinfo->src;
	key.dst = pinfo->dst;
	key.id	= id;

	fd_head = g_hash_table_lookup(fragment_table, &key);

	return fd_head;
}

/* id *must* be the frame number for this to work! */
fragment_data *
fragment_get_reassembled(const guint32 id, GHashTable *reassembled_table)
{
	fragment_data *fd_head;
	reassembled_key key;

	/* create key to search hash with */
	key.frame = id;
	key.id = id;
	fd_head = g_hash_table_lookup(reassembled_table, &key);

	return fd_head;
}

fragment_data *
fragment_get_reassembled_id(const packet_info *pinfo, const guint32 id, GHashTable *reassembled_table)
{
	fragment_data *fd_head;
	reassembled_key key;

	/* create key to search hash with */
	key.frame = pinfo->fd->num;
	key.id = id;
	fd_head = g_hash_table_lookup(reassembled_table, &key);

	return fd_head;
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
fragment_set_tot_len(const packet_info *pinfo, const guint32 id, GHashTable *fragment_table,
			 const guint32 tot_len)
{
	fragment_data *fd_head;
	fragment_key key;

	/* create key to search hash with */
	key.src = pinfo->src;
	key.dst = pinfo->dst;
	key.id	= id;

	fd_head = g_hash_table_lookup(fragment_table, &key);

	if(fd_head){
		fd_head->datalen = tot_len;
		fd_head->flags |= FD_DATALEN_SET;
	}

	return;
}

guint32
fragment_get_tot_len(const packet_info *pinfo, const guint32 id, GHashTable *fragment_table)
{
	fragment_data *fd_head;
	fragment_key key;

	/* create key to search hash with */
	key.src = pinfo->src;
	key.dst = pinfo->dst;
	key.id	= id;

	fd_head = g_hash_table_lookup(fragment_table, &key);

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
fragment_set_partial_reassembly(const packet_info *pinfo, const guint32 id, GHashTable *fragment_table)
{
	fragment_data *fd_head;
	fragment_key key;

	/* create key to search hash with */
	key.src = pinfo->src;
	key.dst = pinfo->dst;
	key.id	= id;

	fd_head = g_hash_table_lookup(fragment_table, &key);

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
 * a pointer to the key for that entry; it also frees up the key
 * and the addresses in it.
 * Note: If we use slices keys are freed by fragment_free_key()
         [or dcerpc_fragment_free_key()] being called
 *       during g_hash_table_remove().
 */
static void
fragment_unhash(GHashTable *fragment_table, fragment_key *key)
{
	/*
	 * Remove the entry from the fragment table.
	 */
	g_hash_table_remove(fragment_table, key);

	/*
	 * Free the key itself.
	 */
}

/*
 * This function adds fragment_data structure to a reassembled-packet
 * hash table, using the frame numbers of each of the frames from
 * which it was reassembled as keys, and sets the "reassembled_in"
 * frame number.
 */
static void
fragment_reassembled(fragment_data *fd_head, const packet_info *pinfo,
		 GHashTable *reassembled_table, const guint32 id)
{
	reassembled_key *new_key;
	fragment_data *fd;

	if (fd_head->next == NULL) {
		/*
		 * This was not fragmented, so there's no fragment
		 * table; just hash it using the current frame number.
		 */
		new_key = se_alloc(sizeof(reassembled_key));
		new_key->frame = pinfo->fd->num;
		new_key->id = id;
		g_hash_table_insert(reassembled_table, new_key, fd_head);
	} else {
		/*
		 * Hash it with the frame numbers for all the frames.
		 */
		for (fd = fd_head->next; fd != NULL; fd = fd->next){
			new_key = se_alloc(sizeof(reassembled_key));
			new_key->frame = fd->frame;
			new_key->id = id;
			g_hash_table_insert(reassembled_table, new_key,
				fd_head);
		}
	}
	fd_head->flags |= FD_DEFRAGMENTED;
	fd_head->reassembled_in = pinfo->fd->num;
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
fragment_add_work(fragment_data *fd_head, tvbuff_t *tvb, const int offset,
		 const packet_info *pinfo, const guint32 frag_offset,
		 const guint32 frag_data_len, const gboolean more_frags)
{
	fragment_data *fd;
	fragment_data *fd_i;
	guint32 max, dfpos;
	unsigned char *old_data;

	/* create new fd describing this fragment */
	fd = g_slice_new(fragment_data);
	fd->next = NULL;
	fd->flags = 0;
	fd->frame = pinfo->fd->num;
	if (fd->frame > fd_head->frame)
		fd_head->frame = fd->frame;
	fd->offset = frag_offset;
	fd->len  = frag_data_len;
	fd->data = NULL;

	/*
	 * If it was already defragmented and this new fragment goes beyond
	 * data limits, set flag in already empty fds & point old fds to malloc'ed data.
	 */
	if(fd_head->flags & FD_DEFRAGMENTED && (frag_offset+frag_data_len) >= fd_head->datalen &&
		fd_head->flags & FD_PARTIAL_REASSEMBLY){
		for(fd_i=fd_head->next; fd_i; fd_i=fd_i->next){
			if( !fd_i->data ) {
				fd_i->data = fd_head->data + fd_i->offset;
				fd_i->flags |= FD_NOT_MALLOCED;
			}
			fd_i->flags &= (~FD_TOOLONGFRAGMENT) & (~FD_MULTIPLETAILS);
		}
		fd_head->flags &= ~(FD_DEFRAGMENTED|FD_PARTIAL_REASSEMBLY|FD_DATALEN_SET);
		fd_head->flags &= (~FD_TOOLONGFRAGMENT) & (~FD_MULTIPLETAILS);
		fd_head->datalen=0;
		fd_head->reassembled_in=0;
	}

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
			/* this was the first tail fragment, now we know the
			 * length of the packet
			 */
			fd_head->datalen = fd->offset + fd->len;
			fd_head->flags |= FD_DATALEN_SET;
		}
	}




	/* If the packet is already defragmented, this MUST be an overlap.
	 * The entire defragmented packet is in fd_head->data.
	 * Even if we have previously defragmented this packet, we still
	 * check it. Someone might play overlap and TTL games.
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
		else if ( memcmp(fd_head->data+fd->offset,
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
	 * XXX - what if we didn't capture the entire fragment due
	 * to a too-short snapshot length?
	 */
	fd->data = g_malloc(fd->len);
	tvb_memcpy(tvb, fd->data, offset, fd->len);
	LINK_FRAG(fd_head,fd);


	if( !(fd_head->flags & FD_DATALEN_SET) ){
		/* if we dont know the datalen, there are still missing
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


	if (max > (fd_head->datalen)) {
		/*XXX not sure if current fd was the TOOLONG*/
		/*XXX is it fair to flag current fd*/
		/* oops, too long fragment detected */
		fd->flags	   |= FD_TOOLONGFRAGMENT;
		fd_head->flags |= FD_TOOLONGFRAGMENT;
	}

	/* we have received an entire packet, defragment it and
	 * free all fragments
	 */
	/* store old data just in case */
	old_data=fd_head->data;
	fd_head->data = g_malloc(max);

	/* add all data fragments */
	for (dfpos=0,fd_i=fd_head;fd_i;fd_i=fd_i->next) {
		if (fd_i->len) {
			/* dfpos is always >= than fd_i->offset */
			/* No gaps can exist here, max_loop(above) does this */
			/* XXX - true? Can we get fd_i->offset+fd-i->len */
			/* overflowing, for example? */
			/*	Actually: there is at least one pathological case wherein there can be fragments
			 *	on the list which are for offsets greater than max (i.e.: following a gap after max).
			 *	(Apparently a "DESEGMENT_UNTIL_FIN" was involved wherein the FIN packet had an offset
			 *	less than the highest fragment offset seen. [Seen from a fuzz-test: bug #2470]).
			 *	Note that the "overlap" compare must only be done for fragments with (offset+len) <= max
			 *	and thus within the newly g_malloc'd buffer.
			 */

			if ( fd_i->offset+fd_i->len > dfpos ) {
				if (fd_i->offset+fd_i->len > max)
					g_warning("Reassemble error in frame %u: offset %u + len %u > max %u",
						pinfo->fd->num, fd_i->offset,
						fd_i->len, max);
				else if (dfpos < fd_i->offset)
					g_warning("Reassemble error in frame %u: dfpos %u < offset %u",
						pinfo->fd->num, dfpos, fd_i->offset);
				else if (dfpos-fd_i->offset > fd_i->len)
					g_warning("Reassemble error in frame %u: dfpos %u - offset %u > len %u",
						pinfo->fd->num, dfpos, fd_i->offset,
						fd_i->len);
				else if (!fd_head->data)
					g_warning("Reassemble error in frame %u: no data",
						pinfo->fd->num);
				else {
					if (fd_i->offset < dfpos) {
						fd_i->flags    |= FD_OVERLAP;
						fd_head->flags |= FD_OVERLAP;
						if ( memcmp(fd_head->data+fd_i->offset,
								fd_i->data,
								MIN(fd_i->len,(dfpos-fd_i->offset))
								 ) ) {
							fd_i->flags    |= FD_OVERLAPCONFLICT;
							fd_head->flags |= FD_OVERLAPCONFLICT;
						}
					}
					memcpy(fd_head->data+dfpos,
						fd_i->data+(dfpos-fd_i->offset),
						fd_i->len-(dfpos-fd_i->offset));
				}
			} else {
				if (fd_i->offset + fd_i->len < fd_i->offset) /* Integer overflow? */
					g_warning("Reassemble error in frame %u: offset %u + len %u < offset",
						pinfo->fd->num, fd_i->offset,
						fd_i->len);
			}
			if( fd_i->flags & FD_NOT_MALLOCED )
				fd_i->flags &= ~FD_NOT_MALLOCED;
			else
				g_free(fd_i->data);
			fd_i->data=NULL;

			dfpos=MAX(dfpos,(fd_i->offset+fd_i->len));
		}
	}

	g_free(old_data);
	/* mark this packet as defragmented.
		   allows us to skip any trailing fragments */
	fd_head->flags |= FD_DEFRAGMENTED;
	fd_head->reassembled_in=pinfo->fd->num;

	return TRUE;
}

static fragment_data *
fragment_add_common(tvbuff_t *tvb, const int offset, const packet_info *pinfo, const guint32 id,
		 GHashTable *fragment_table, const guint32 frag_offset,
		 const guint32 frag_data_len, const gboolean more_frags,
		 const gboolean check_already_added)
{
	fragment_key key, *new_key;
	fragment_data *fd_head;
	fragment_data *fd_item;
	gboolean already_added=pinfo->fd->flags.visited;


	/* dissector shouldn't give us garbage tvb info */
	DISSECTOR_ASSERT(tvb_bytes_exist(tvb, offset, frag_data_len));

	/* create key to search hash with */
	key.src = pinfo->src;
	key.dst = pinfo->dst;
	key.id	= id;

	fd_head = g_hash_table_lookup(fragment_table, &key);

#if 0
	/* debug output of associated fragments. */
	/* leave it here for future debugging sessions */
	if(strcmp(pinfo->current_proto, "DCERPC") == 0) {
		printf("proto:%s num:%u id:%u offset:%u len:%u more:%u visited:%u\n",
			pinfo->current_proto, pinfo->fd->num, id, frag_offset, frag_data_len, more_frags, pinfo->fd->flags.visited);
		if(fd_head != NULL) {
			for(fd_item=fd_head->next;fd_item;fd_item=fd_item->next){
				printf("fd_frame:%u fd_offset:%u len:%u datalen:%u\n",
					fd_item->frame, fd_item->offset, fd_item->len, fd_item->datalen);
			}
		}
	}
#endif

	/*
	 * "already_added" is true if "pinfo->fd->flags.visited" is true;
	 * if "pinfo->fd->flags.visited", this isn't the first pass, so
	 * we've already done all the reassembly and added all the
	 * fragments.
	 *
	 * If it's not true, but "check_already_added" is true, just check
	 * if we have seen this fragment before, i.e., if we have already
	 * added it to reassembly.
	 * That can be true even if "pinfo->fd->flags.visited" is false
	 * since we sometimes might call a subdissector multiple times.
	 * As an additional check, just make sure we have not already added
	 * this frame to the reassembly list, if there is a reassembly list;
	 * note that the first item in the reassembly list is not a
	 * fragment, it's a data structure for the reassembled packet.
	 * We don't check it because its "frame" member isn't initialized
	 * to anything, and because it doesn't count in any case.
	 *
	 * And as another additional check, make sure the fragment offsets are
	 * the same, as otherwise we get into trouble if multiple fragments
	 * are in one PDU.
	 */
	if (!already_added && check_already_added && fd_head != NULL) {
		if (pinfo->fd->num <= fd_head->frame) {
			for(fd_item=fd_head->next;fd_item;fd_item=fd_item->next){
				if(pinfo->fd->num==fd_item->frame && frag_offset==fd_item->offset){
					already_added=TRUE;
				}
			}
		}
	}
	/* have we already added this frame ?*/
	if (already_added) {
		if (fd_head != NULL && fd_head->flags & FD_DEFRAGMENTED) {
			return fd_head;
		} else {
			return NULL;
		}
	}

	if (fd_head==NULL){
		/* not found, this must be the first snooped fragment for this
				 * packet. Create list-head.
		 */
		fd_head = new_head(0);

		/*
		 * We're going to use the key to insert the fragment,
		 * so allocate a structure for it, and copy the
		 * addresses, allocating new buffers for the address
		 * data.
		 */
		new_key = g_slice_new(fragment_key);
		COPY_ADDRESS(&new_key->src, &key.src);
		COPY_ADDRESS(&new_key->dst, &key.dst);
		new_key->id = key.id;
		g_hash_table_insert(fragment_table, new_key, fd_head);
	}

	if (fragment_add_work(fd_head, tvb, offset, pinfo, frag_offset,
		frag_data_len, more_frags)) {
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

fragment_data *
fragment_add(tvbuff_t *tvb, const int offset, const packet_info *pinfo, const guint32 id,
		 GHashTable *fragment_table, const guint32 frag_offset,
		 const guint32 frag_data_len, const gboolean more_frags)
{
	return fragment_add_common(tvb, offset, pinfo, id, fragment_table,
		frag_offset, frag_data_len, more_frags, TRUE);
}

/*
 * For use when you can have multiple fragments in the same frame added
 * to the same reassembled PDU, e.g. with ONC RPC-over-TCP.
 */
fragment_data *
fragment_add_multiple_ok(tvbuff_t *tvb, const int offset, const packet_info *pinfo,
			 const guint32 id, GHashTable *fragment_table,
			 const guint32 frag_offset, const guint32 frag_data_len,
			 const gboolean more_frags)
{
	return fragment_add_common(tvb, offset, pinfo, id, fragment_table,
		frag_offset, frag_data_len, more_frags, FALSE);
}

fragment_data *
fragment_add_check(tvbuff_t *tvb, const int offset, const packet_info *pinfo,
		 const guint32 id, GHashTable *fragment_table,
		 GHashTable *reassembled_table, const guint32 frag_offset,
		 const guint32 frag_data_len, const gboolean more_frags)
{
	reassembled_key reass_key;
	fragment_key key, *new_key, *old_key;
	gpointer orig_key, value;
	fragment_data *fd_head;

	/*
	 * If this isn't the first pass, look for this frame in the table
	 * of reassembled packets.
	 */
	if (pinfo->fd->flags.visited) {
		reass_key.frame = pinfo->fd->num;
		reass_key.id = id;
		return g_hash_table_lookup(reassembled_table, &reass_key);
	}

	/* create key to search hash with */
	key.src = pinfo->src;
	key.dst = pinfo->dst;
	key.id	= id;

	/* Looks up a key in the GHashTable, returning the original key and the associated value
	 * and a gboolean which is TRUE if the key was found. This is useful if you need to free
	 * the memory allocated for the original key, for example before calling g_hash_table_remove()
	 */
	if (!g_hash_table_lookup_extended(fragment_table, &key,
					  &orig_key, &value)) {
		/* not found, this must be the first snooped fragment for this
				 * packet. Create list-head.
		 */
		fd_head = new_head(0);

		/*
		 * We're going to use the key to insert the fragment,
		 * so allocate a structure for it, and copy the
		 * addresses, allocating new buffers for the address
		 * data.
		 */
		new_key = g_slice_new(fragment_key);
		COPY_ADDRESS(&new_key->src, &key.src);
		COPY_ADDRESS(&new_key->dst, &key.dst);
		new_key->id = key.id;
		g_hash_table_insert(fragment_table, new_key, fd_head);

		orig_key = new_key; /* for unhashing it later */
	} else {
		/*
		 * We found it.
		 */
		fd_head = value;
	}

	/*
	 * If this is a short frame, then we can't, and don't, do
	 * reassembly on it.  We just give up.
	 */
	if (tvb_reported_length(tvb) > tvb_length(tvb))
		return NULL;

	if (fragment_add_work(fd_head, tvb, offset, pinfo, frag_offset,
		frag_data_len, more_frags)) {
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
		old_key = orig_key;
		fragment_unhash(fragment_table, old_key);

		/*
		 * Add this item to the table of reassembled packets.
		 */
		fragment_reassembled(fd_head, pinfo, reassembled_table, id);
		return fd_head;
	} else {
		/*
		 * Reassembly isn't complete.
		 */
		return NULL;
	}
}

static void
fragment_defragment_and_free (fragment_data *fd_head, const packet_info *pinfo)
{
	fragment_data *fd_i = NULL;
	fragment_data *last_fd = NULL;
	guint32  dfpos = 0, size = 0;
	void *old_data = NULL;

	for(fd_i=fd_head->next;fd_i;fd_i=fd_i->next) {
		if(!last_fd || last_fd->offset!=fd_i->offset){
			size+=fd_i->len;
		}
		last_fd=fd_i;
	}

	/* store old data in case the fd_i->data pointers refer to it */
	old_data=fd_head->data;
	fd_head->data = g_malloc(size);
	fd_head->len = size;		/* record size for caller	*/

	/* add all data fragments */
	last_fd=NULL;
	for (fd_i=fd_head->next; fd_i; fd_i=fd_i->next) {
		if (fd_i->len) {
			if(!last_fd || last_fd->offset != fd_i->offset) {
				/* First fragment or in-sequence fragment */
				memcpy(fd_head->data+dfpos, fd_i->data, fd_i->len);
				dfpos += fd_i->len;
			} else {
				/* duplicate/retransmission/overlap */
				fd_i->flags    |= FD_OVERLAP;
				fd_head->flags |= FD_OVERLAP;
				if(last_fd->len != fd_i->len
				   || memcmp(last_fd->data, fd_i->data, last_fd->len) ) {
					fd_i->flags    |= FD_OVERLAPCONFLICT;
					fd_head->flags |= FD_OVERLAPCONFLICT;
				}
			}
		}
		last_fd=fd_i;
	}

	/* we have defragmented the pdu, now free all fragments*/
	for (fd_i=fd_head->next;fd_i;fd_i=fd_i->next) {
		if( fd_i->flags & FD_NOT_MALLOCED )
			fd_i->flags &= ~FD_NOT_MALLOCED;
		else
			g_free(fd_i->data);
		fd_i->data=NULL;
	}
	g_free(old_data);

	/* mark this packet as defragmented.
	 * allows us to skip any trailing fragments.
	 */
	fd_head->flags |= FD_DEFRAGMENTED;
	fd_head->reassembled_in=pinfo->fd->num;
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
fragment_add_seq_work(fragment_data *fd_head, tvbuff_t *tvb, const int offset,
		 const packet_info *pinfo, const guint32 frag_number,
		 const guint32 frag_data_len, const gboolean more_frags,
		 const guint32 flags _U_)
{
	fragment_data *fd;
	fragment_data *fd_i;
	fragment_data *last_fd;
	guint32 max, dfpos;

	/* if the partial reassembly flag has been set, and we are extending
	 * the pdu, un-reassemble the pdu. This means pointing old fds to malloc'ed data.
	 */
	if(fd_head->flags & FD_DEFRAGMENTED && frag_number >= fd_head->datalen &&
		fd_head->flags & FD_PARTIAL_REASSEMBLY){
		guint32 lastdfpos = 0;
		dfpos = 0;
		for(fd_i=fd_head->next; fd_i; fd_i=fd_i->next){
			if( !fd_i->data ) {
				if( fd_i->flags & FD_OVERLAP ) {
					/* this is a duplicate of the previous
					 * fragment. */
					fd_i->data = fd_head->data + lastdfpos;
				} else {
					fd_i->data = fd_head->data + dfpos;
					lastdfpos = dfpos;
					dfpos += fd_i->len;
				}
				fd_i->flags |= FD_NOT_MALLOCED;
			}
			fd_i->flags &= (~FD_TOOLONGFRAGMENT) & (~FD_MULTIPLETAILS);
		}
		fd_head->flags &= ~(FD_DEFRAGMENTED|FD_PARTIAL_REASSEMBLY|FD_DATALEN_SET);
		fd_head->flags &= (~FD_TOOLONGFRAGMENT) & (~FD_MULTIPLETAILS);
		fd_head->datalen=0;
		fd_head->reassembled_in=0;
	}


	/* create new fd describing this fragment */
	fd = g_slice_new(fragment_data);
	fd->next = NULL;
	fd->flags = 0;
	fd->frame = pinfo->fd->num;
	fd->offset = frag_number;
	fd->len  = frag_data_len;
	fd->data = NULL;

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
			if ( memcmp(fd_head->data+dfpos,
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
	 * XXX - what if we didn't capture the entire fragment due
	 * to a too-short snapshot length?
	 */
	/* check len, there may be a fragment with 0 len, that is actually the tail */
	if (fd->len) {
		fd->data = g_malloc(fd->len);
		tvb_memcpy(tvb, fd->data, offset, fd->len);
	}
	LINK_FRAG(fd_head,fd);


	if( !(fd_head->flags & FD_DATALEN_SET) ){
		/* if we dont know the sequence number of the last fragment,
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
fragment_data *
fragment_add_seq(tvbuff_t *tvb, const int offset, const packet_info *pinfo, const guint32 id,
		 GHashTable *fragment_table, const guint32 frag_number,
		 const guint32 frag_data_len, const gboolean more_frags)
{
	fragment_key key;

	/* create key to search hash with */
	key.src = pinfo->src;
	key.dst = pinfo->dst;
	key.id	= id;

	return fragment_add_seq_key(tvb, offset, pinfo,
					&key, fragment_key_copy,
					fragment_table, frag_number,
					frag_data_len, more_frags, 0);
}


fragment_data *
fragment_add_dcerpc_dg(tvbuff_t *tvb, const int offset, const packet_info *pinfo, const guint32 id,
					void *v_act_id,
					GHashTable *fragment_table, const guint32 frag_number,
					const guint32 frag_data_len, const gboolean more_frags)
{
	e_uuid_t *act_id = (e_uuid_t *)v_act_id;
	dcerpc_fragment_key key;

	/* create key to search hash with */
	key.src = pinfo->src;
	key.dst = pinfo->dst;
	key.id	= id;
	key.act_id	= *act_id;

	return fragment_add_seq_key(tvb, offset, pinfo,
					&key, dcerpc_fragment_key_copy,
					fragment_table, frag_number,
					frag_data_len, more_frags, 0);
}

fragment_data *
fragment_add_seq_key(tvbuff_t *tvb, const int offset, const packet_info *pinfo,
					 void *key, fragment_key_copier key_copier,
					GHashTable *fragment_table, guint32 frag_number,
					const guint32 frag_data_len, const gboolean more_frags,
					const guint32 flags)
{
	fragment_data *fd_head;
	fd_head = g_hash_table_lookup(fragment_table, key);

	/* have we already seen this frame ?*/
	if (pinfo->fd->flags.visited) {
		if (fd_head != NULL && fd_head->flags & FD_DEFRAGMENTED) {
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
			fd_head->reassembled_in=pinfo->fd->num;
			return fd_head;
		}

		/*
		 * We're going to use the key to insert the fragment,
		 * so copy it to a long-term store.
		 */
		if(key_copier != NULL)
			key = key_copier(key);
		g_hash_table_insert(fragment_table, key, fd_head);

		/*
		 * If we weren't given an initial fragment number,
		 * make it 0.
		 */
		if (flags & REASSEMBLE_FLAGS_NO_FRAG_NUMBER)
			frag_number = 0;
	} else {
		if (flags & REASSEMBLE_FLAGS_NO_FRAG_NUMBER) {
			fragment_data *fd;
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

	/*
	 * XXX I've copied this over from the old separate
	 * fragment_add_seq_check_work, but I'm not convinced it's doing the
	 * right thing -- rav
	 *
	 * If we don't have all the data that is in this fragment,
	 * then we can't, and don't, do reassembly on it.
	 *
	 * If it's the first frame, handle it as an unfragmented packet.
	 * Otherwise, just handle it as a fragment.
	 *
	 * If "more_frags" isn't set, we get rid of the entry in the
	 * hash table for this reassembly, as we don't need it any more.
	 */
	if ((flags & REASSEMBLE_FLAGS_CHECK_DATA_PRESENT) &&
		!tvb_bytes_exist(tvb, offset, frag_data_len)) {
		if (!more_frags) {
			gpointer orig_key;
			/*
			 * Remove this from the table of in-progress
			 * reassemblies, and free up any memory used for
			 * it in that table.
			 */
			if (g_hash_table_lookup_extended(fragment_table, key,
							 &orig_key, NULL)) {
				fragment_unhash(fragment_table, (fragment_key *)orig_key);
			}
		}
		fd_head -> flags |= FD_DATA_NOT_PRESENT;
		return frag_number == 0 ? fd_head : NULL;
	}

	if (fragment_add_seq_work(fd_head, tvb, offset, pinfo,
				  frag_number, frag_data_len, more_frags, flags)) {
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

/*
 * This does the work for "fragment_add_seq_check()" and
 * "fragment_add_seq_next()".
 *
 * This function assumes frag_number being a block sequence number.
 * The bsn for the first block is 0.
 *
 * If "no_frag_number" is TRUE, it uses the next expected fragment number
 * as the fragment number if there is a reassembly in progress, otherwise
 * it uses 0.
 *
 * If "no_frag_number" is FALSE, it uses the "frag_number" argument as
 * the fragment number.
 *
 * If this is the first fragment seen for this datagram, a new
 * "fragment_data" structure is allocated to refer to the reassembled
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
static fragment_data *
fragment_add_seq_check_work(tvbuff_t *tvb, const int offset,
			    const packet_info *pinfo, const guint32 id,
			    GHashTable *fragment_table,
			    GHashTable *reassembled_table,
			    const guint32 frag_number,
			    const guint32 frag_data_len,
			    const gboolean more_frags, const guint32 flags)
{
	reassembled_key reass_key;
	fragment_key key;
	fragment_data *fd_head;

	/*
	 * Have we already seen this frame?
	 * If so, look for it in the table of reassembled packets.
	 */
	if (pinfo->fd->flags.visited) {
		reass_key.frame = pinfo->fd->num;
		reass_key.id = id;
		return g_hash_table_lookup(reassembled_table, &reass_key);
	}

	/* create key to search hash with */
	key.src = pinfo->src;
	key.dst = pinfo->dst;
	key.id	= id;

	fd_head = fragment_add_seq_key(tvb, offset, pinfo,
					   &key, fragment_key_copy,
					   fragment_table, frag_number,
					   frag_data_len, more_frags, flags|REASSEMBLE_FLAGS_CHECK_DATA_PRESENT);
	if (fd_head) {
		gpointer orig_key;

		if(fd_head->flags & FD_DATA_NOT_PRESENT) {
			/* this is the first fragment of a datagram with
			 * truncated fragments. Don't move it to the
			 * reassembled table. */
			return fd_head;
		}

		/*
		 * Reassembly is complete.
		 * Remove this from the table of in-progress
		 * reassemblies, add it to the table of
		 * reassembled packets, and return it.
		 */
		if (g_hash_table_lookup_extended(fragment_table, &key,
						 &orig_key, NULL)) {
			/*
			 * Remove this from the table of in-progress reassemblies,
			 * and free up any memory used for it in that table.
			 */
			fragment_unhash(fragment_table, (fragment_key *)orig_key);
		}

		/*
		 * Add this item to the table of reassembled packets.
		 */
		fragment_reassembled(fd_head, pinfo, reassembled_table, id);
		return fd_head;
	} else {
		/*
		 * Reassembly isn't complete.
		 */
		return NULL;
	}
}

fragment_data *
fragment_add_seq_check(tvbuff_t *tvb, const int offset,
		       const packet_info *pinfo, const guint32 id,
		       GHashTable *fragment_table,
		       GHashTable *reassembled_table, const guint32 frag_number,
		       const guint32 frag_data_len, const gboolean more_frags)
{
	return fragment_add_seq_check_work(tvb, offset, pinfo, id,
					   fragment_table, reassembled_table,
					   frag_number, frag_data_len,
					   more_frags, 0);
}

fragment_data *
fragment_add_seq_802_11(tvbuff_t *tvb, const int offset,
			const packet_info *pinfo, const guint32 id,
			GHashTable *fragment_table,
			GHashTable *reassembled_table,
			const guint32 frag_number, const guint32 frag_data_len,
			const gboolean more_frags)
{
	return fragment_add_seq_check_work(tvb, offset, pinfo, id,
					   fragment_table, reassembled_table,
					   frag_number, frag_data_len,
					   more_frags,
					   REASSEMBLE_FLAGS_802_11_HACK);
}

fragment_data *
fragment_add_seq_next(tvbuff_t *tvb, const int offset, const packet_info *pinfo,
		      const guint32 id, GHashTable *fragment_table,
		      GHashTable *reassembled_table, const guint32 frag_data_len,
		      const gboolean more_frags)
{
	return fragment_add_seq_check_work(tvb, offset, pinfo, id,
					   fragment_table, reassembled_table, 0,
					   frag_data_len, more_frags,
					   REASSEMBLE_FLAGS_NO_FRAG_NUMBER);
}

void
fragment_start_seq_check(const packet_info *pinfo, const guint32 id, GHashTable *fragment_table,
			 const guint32 tot_len)
{
	fragment_key key, *new_key;
	fragment_data *fd_head;

	/* Have we already seen this frame ?*/
	if (pinfo->fd->flags.visited) {
		return;
	}

	/* Create key to search hash with */
	key.src = pinfo->src;
	key.dst = pinfo->dst;
	key.id	= id;

	/* Check if fragment data exist for this key */
	fd_head = g_hash_table_lookup(fragment_table, &key);

	if (fd_head == NULL) {
		/* Create list-head. */
		fd_head = g_slice_new(fragment_data);
		fd_head->next = NULL;
		fd_head->datalen = tot_len;
		fd_head->offset = 0;
		fd_head->len = 0;
		fd_head->flags = FD_BLOCKSEQUENCE|FD_DATALEN_SET;
		fd_head->data = NULL;
		fd_head->reassembled_in = 0;
		/*
		 * We're going to use the key to insert the fragment,
		 * so copy it to a long-term store.
		 */
		new_key = fragment_key_copy(&key);
		g_hash_table_insert(fragment_table, new_key, fd_head);
	}
}

fragment_data *
fragment_end_seq_next(const packet_info *pinfo, const guint32 id, GHashTable *fragment_table,
			  GHashTable *reassembled_table)
{
	reassembled_key reass_key;
	reassembled_key *new_key;
	fragment_key key;
	fragment_data *fd_head;

	/*
	 * Have we already seen this frame?
	 * If so, look for it in the table of reassembled packets.
	 */
	if (pinfo->fd->flags.visited) {
		reass_key.frame = pinfo->fd->num;
		reass_key.id = id;
		return g_hash_table_lookup(reassembled_table, &reass_key);
	}

	/* create key to search hash with */
	key.src = pinfo->src;
	key.dst = pinfo->dst;
	key.id	= id;

	fd_head = g_hash_table_lookup (fragment_table, &key);

	if (fd_head) {
		gpointer orig_key;

		if (fd_head->flags & FD_DATA_NOT_PRESENT) {
			/* No data added */
			return NULL;
		}

		fd_head->datalen = fd_head->offset;
		fd_head->flags |= FD_DATALEN_SET;

		fragment_defragment_and_free (fd_head, pinfo);

		/*
		 * Remove this from the table of in-progress
		 * reassemblies, add it to the table of
		 * reassembled packets, and return it.
		 */
		if (g_hash_table_lookup_extended(fragment_table, &key,
						 &orig_key, NULL)) {
			/*
			 * Remove this from the table of in-progress reassemblies,
			 * and free up any memory used for it in that table.
			 */
			fragment_unhash(fragment_table, (fragment_key *)orig_key);
		}

		/*
		 * Add this item to the table of reassembled packets.
		 */
		fragment_reassembled(fd_head, pinfo, reassembled_table, id);
		if (fd_head->next != NULL) {
			new_key = se_alloc(sizeof(reassembled_key));
			new_key->frame = pinfo->fd->num;
			new_key->id = id;
			g_hash_table_insert(reassembled_table, new_key, fd_head);
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
 */
tvbuff_t *
process_reassembled_data(tvbuff_t *tvb, const int offset, packet_info *pinfo,
	const char *name, fragment_data *fd_head, const fragment_items *fit,
	gboolean *update_col_infop, proto_tree *tree)
{
	tvbuff_t *next_tvb;
	gboolean update_col_info;
	proto_item *frag_tree_item;

	if (fd_head != NULL && pinfo->fd->num == fd_head->reassembled_in) {
		/*
		 * OK, we've reassembled this.
		 * Is this something that's been reassembled from more
		 * than one fragment?
		 */
		if (fd_head->next != NULL) {
			/*
			 * Yes.
			 * Allocate a new tvbuff, referring to the
			 * reassembled payload.
			 */
			if (fd_head->flags & FD_BLOCKSEQUENCE) {
				next_tvb = tvb_new_real_data(fd_head->data,
					  fd_head->len, fd_head->len);
			} else {
				next_tvb = tvb_new_real_data(fd_head->data,
					  fd_head->datalen, fd_head->datalen);
			}

			/*
			 * Add the tvbuff to the list of tvbuffs to which
			 * the tvbuff we were handed refers, so it'll get
			 * cleaned up when that tvbuff is cleaned up.
			 */
			tvb_set_child_real_data_tvbuff(tvb, next_tvb);

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
			 * Return a tvbuff with the payload.
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
			proto_tree_add_uint(tree,
				*(fit->hf_reassembled_in), tvb,
				0, 0, fd_head->reassembled_in);
		}
	}
	return next_tvb;
}

/*
 * Show a single fragment in a fragment subtree, and put information about
 * it in the top-level item for that subtree.
 */
static void
show_fragment(fragment_data *fd, const int offset, const fragment_items *fit,
	proto_tree *ft, proto_item *fi, const gboolean first_frag, const guint32 count, tvbuff_t *tvb)
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
		proto_item_set_text(fi, "%u %s (%u byte%s): ", count, name, tvb_length(tvb),
				    plurality(tvb_length(tvb), "", "s"));
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
	PROTO_ITEM_SET_GENERATED(fei);
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
			PROTO_ITEM_SET_GENERATED(fei);
		}
		if (fd->flags&FD_OVERLAPCONFLICT) {
			fei=proto_tree_add_boolean(fet,
				*(fit->hf_fragment_overlap_conflict),
				tvb, 0, 0,
				TRUE);
			PROTO_ITEM_SET_GENERATED(fei);
		}
		if (fd->flags&FD_MULTIPLETAILS) {
			fei=proto_tree_add_boolean(fet,
				*(fit->hf_fragment_multiple_tails),
				tvb, 0, 0,
				TRUE);
			PROTO_ITEM_SET_GENERATED(fei);
		}
		if (fd->flags&FD_TOOLONGFRAGMENT) {
			fei=proto_tree_add_boolean(fet,
				*(fit->hf_fragment_too_long_fragment),
				tvb, 0, 0,
				TRUE);
			PROTO_ITEM_SET_GENERATED(fei);
		}
	}
}

static gboolean
show_fragment_errs_in_col(fragment_data *fd_head, const fragment_items *fit,
	packet_info *pinfo)
{
	if (fd_head->flags & (FD_OVERLAPCONFLICT
		|FD_MULTIPLETAILS|FD_TOOLONGFRAGMENT) ) {
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_add_fstr(pinfo->cinfo, COL_INFO,
				"[Illegal %s]", fit->tag);
			return TRUE;
		}
	}

	return FALSE;
}

/* This function will build the fragment subtree; it's for fragments
   reassembled with "fragment_add()".

   It will return TRUE if there were fragmentation errors
   or FALSE if fragmentation was ok.
*/
gboolean
show_fragment_tree(fragment_data *fd_head, const fragment_items *fit,
	proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, proto_item **fi)
{
	fragment_data *fd;
	proto_tree *ft;
	gboolean first_frag;
	guint32 count = 0;
	/* It's not fragmented. */
	pinfo->fragmented = FALSE;

	*fi = proto_tree_add_item(tree, *(fit->hf_fragments), tvb, 0, -1, ENC_NA);
	PROTO_ITEM_SET_GENERATED(*fi);

	ft = proto_item_add_subtree(*fi, *(fit->ett_fragments));
	first_frag = TRUE;
	for (fd = fd_head->next; fd != NULL; fd = fd->next) {
		count++;
	}
	for (fd = fd_head->next; fd != NULL; fd = fd->next) {
		show_fragment(fd, fd->offset, fit, ft, *fi, first_frag, count, tvb);
		first_frag = FALSE;
	}

	if (fit->hf_fragment_count) {
		proto_item *fli = proto_tree_add_uint(ft, *(fit->hf_fragment_count),
						      tvb, 0, 0, count);
		PROTO_ITEM_SET_GENERATED(fli);
	}

	if (fit->hf_reassembled_length) {
		proto_item *fli = proto_tree_add_uint(ft, *(fit->hf_reassembled_length),
						      tvb, 0, 0, tvb_length (tvb));
		PROTO_ITEM_SET_GENERATED(fli);
	}

	return show_fragment_errs_in_col(fd_head, fit, pinfo);
}

/* This function will build the fragment subtree; it's for fragments
   reassembled with "fragment_add_seq()" or "fragment_add_seq_check()".

   It will return TRUE if there were fragmentation errors
   or FALSE if fragmentation was ok.
*/
gboolean
show_fragment_seq_tree(fragment_data *fd_head, const fragment_items *fit,
	proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, proto_item **fi)
{
	guint32 offset, next_offset, count = 0;
	fragment_data *fd, *last_fd;
	proto_tree *ft;
	gboolean first_frag;

	/* It's not fragmented. */
	pinfo->fragmented = FALSE;

	*fi = proto_tree_add_item(tree, *(fit->hf_fragments), tvb, 0, -1, ENC_NA);
	PROTO_ITEM_SET_GENERATED(*fi);

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
		show_fragment(fd, offset, fit, ft, *fi, first_frag, count, tvb);
		first_frag = FALSE;
	}

	if (fit->hf_fragment_count) {
		proto_item *fli = proto_tree_add_uint(ft, *(fit->hf_fragment_count),
						      tvb, 0, 0, count);
		PROTO_ITEM_SET_GENERATED(fli);
	}

	if (fit->hf_reassembled_length) {
		proto_item *fli = proto_tree_add_uint(ft, *(fit->hf_reassembled_length),
						      tvb, 0, 0, tvb_length (tvb));
		PROTO_ITEM_SET_GENERATED(fli);
	}

	return show_fragment_errs_in_col(fd_head, fit, pinfo);
}

/*
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * tab-width: 8
 * End:
 */
