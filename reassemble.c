/* reassemble.c
 * Routines for {fragment,segment} reassembly
 *
 * $Id: reassemble.c,v 1.33 2003/04/20 00:11:28 guy Exp $
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>

#include <epan/packet.h>

#include "reassemble.h"


typedef struct _fragment_key {
	address src;
	address dst;
	guint32	id;
} fragment_key;

static GMemChunk *fragment_key_chunk = NULL;
static GMemChunk *fragment_data_chunk = NULL;
static int fragment_init_count = 200;

#define LINK_FRAG(fd_head,fd)					\
	{ 	fragment_data *fd_i;				\
		/* add fragment to list, keep list sorted */		\
		for(fd_i=(fd_head);fd_i->next;fd_i=fd_i->next){	\
			if( ((fd)->offset) < (fd_i->next->offset) )	\
				break;					\
		}							\
		(fd)->next=fd_i->next;				\
		fd_i->next=(fd);					\
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
	return ( ( (key1->id    == key2->id) &&
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

/* 	More than likely: in most captures src and dst addresses are the
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

/*
 * XXX - we use the frame number as the key (we can't use the frame_data
 * structure, as in Tethereal there's only one such structure).
 *
 * This won't work if there's more than one form of reassembly using
 * the reassembled-packet hash tables going on in the frame, and two
 * or more are using the same protocol and thus the same hash table.
 *
 * We could use the addresses, or the reassembly ID, to distinguish
 * between the reassemblies, if necessary.
 *
 * Hopefully, we won't see anything perverse such as that (say, some
 * form of IP-in-IP tunneling, with fragments of an IP datagram
 * tunneled inside IP datagrams that are themselves fragmented).
 */
static gint
reassembled_equal(gconstpointer k1, gconstpointer k2)
{
	return ((guint32)k1 == (guint32)k2);
}

static guint
reassembled_hash(gconstpointer k)
{
	return (guint32)k;
}

/*
 * For a fragment hash table entry, free the address data to which the key
 * refers and the fragment data to which the value refers.
 * (The actual key and value structures get freed by "reassemble_init()".)
 */
static gboolean
free_all_fragments(gpointer key_arg, gpointer value, gpointer user_data _U_)
{
	fragment_key *key = key_arg;
	fragment_data *fd_head;

	/*
	 * Grr.  I guess the theory here is that freeing
	 * something sure as heck modifies it, so you
	 * want to ban attempts to free it, but, alas,
	 * if we make the "data" field of an "address"
	 * structure not a "const", the compiler whines if
	 * we try to make it point into the data for a packet,
	 * as that's a "const" array (and should be, as dissectors
	 * shouldn't trash it).
	 *
	 * So we cast the complaint into oblivion, and rely on
	 * the fact that these addresses are known to have had
	 * their data mallocated, i.e. they don't point into,
	 * say, the middle of the data for a packet.
	 */
	g_free((gpointer)key->src.data);
	g_free((gpointer)key->dst.data);

	for (fd_head = value; fd_head != NULL; fd_head = fd_head->next) {
		if(fd_head->data && !(fd_head->flags&FD_NOT_MALLOCED))
			g_free(fd_head->data);
	}

	return TRUE;
}

/*
 * For a reassembled-packet hash table entry, free the fragment data
 * to which the value refers.
 * (The actual value structures get freed by "reassemble_init()".)
 */
static gboolean
free_all_reassembled_fragments(gpointer key_arg _U_, gpointer value,
			       gpointer user_data _U_)
{
	fragment_data *fd_head;

	for (fd_head = value; fd_head != NULL; fd_head = fd_head->next) {
		if(fd_head->data && !(fd_head->flags&FD_NOT_MALLOCED))
			g_free(fd_head->data);
	}

	return TRUE;
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
		 * Remove all entries and free fragment data for
		 * each entry.  (The key and value data is freed
		 * by "reassemble_init()".)
		 */
		g_hash_table_foreach_remove(*fragment_table,
				free_all_fragments, NULL);
	} else {
		/* The fragment table does not exist. Create it */
		*fragment_table = g_hash_table_new(fragment_hash,
				fragment_equal);
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
		 * Remove all entries and free fragment data for
		 * each entry.  (The key and value data is freed
		 * by "reassemble_init()".)
		 */
		g_hash_table_foreach_remove(*reassembled_table,
				free_all_reassembled_fragments, NULL);
	} else {
		/* The fragment table does not exist. Create it */
		*reassembled_table = g_hash_table_new(reassembled_hash,
				reassembled_equal);
	}
}

/*
 * Free up all space allocated for fragment keys and data.
 */
void
reassemble_init(void)
{
	if (fragment_key_chunk != NULL)
		g_mem_chunk_destroy(fragment_key_chunk);
	if (fragment_data_chunk != NULL)
		g_mem_chunk_destroy(fragment_data_chunk);
	fragment_key_chunk = g_mem_chunk_new("fragment_key_chunk",
	    sizeof(fragment_key),
	    fragment_init_count * sizeof(fragment_key),
	    G_ALLOC_AND_FREE);
	fragment_data_chunk = g_mem_chunk_new("fragment_data_chunk",
	    sizeof(fragment_data),
	    fragment_init_count * sizeof(fragment_data),
	    G_ALLOC_ONLY);

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
fragment_delete(packet_info *pinfo, guint32 id, GHashTable *fragment_table)
{
	fragment_data *fd_head, *fd;
	fragment_key key;
	unsigned char *data=NULL;

	/* create key to search hash with */
	key.src = pinfo->src;
	key.dst = pinfo->dst;
	key.id  = id;

	fd_head = g_hash_table_lookup(fragment_table, &key);

	if(fd_head==NULL){
		/* We do not recognize this as a PDU we have seen before. return*/
		return NULL;
	}

	data=fd_head->data;
	/* loop over all partial fragments and free any buffers */
	for(fd=fd_head->next;fd;){
		fragment_data *tmp_fd;
		tmp_fd=fd->next;

		if( !(fd->flags&FD_NOT_MALLOCED) )
			g_free(fd->data);
		g_mem_chunk_free(fragment_data_chunk, fd);
		fd=tmp_fd;
	}
	g_mem_chunk_free(fragment_data_chunk, fd_head);
	g_hash_table_remove(fragment_table, &key);

	return data;
}

/* This function is used to check if there is partial or completed reassembly state
 * matching this packet. I.e. Are there reassembly going on or not for this packet?
 */
fragment_data *
fragment_get(packet_info *pinfo, guint32 id, GHashTable *fragment_table)
{
	fragment_data *fd_head;
	fragment_key key;

	/* create key to search hash with */
	key.src = pinfo->src;
	key.dst = pinfo->dst;
	key.id  = id;

	fd_head = g_hash_table_lookup(fragment_table, &key);

	return fd_head;
}

/* This function can be used to explicitely set the total length (if known)
 * for reassembly of a PDU.
 * This is useful for reassembly of PDUs where one may have the total length specified
 * in the first fragment instead of as for, say, IPv4 where a flag indicates which
 * is the last fragment.
 *
 * Such protocols might fragment_add with a more_frags==TRUE for every fragment
 * and just tell the reassembly engine the expected total length of the reassembled data
 * using fragment_set_tot_len immediately after doing fragment_add for the first packet.
 *
 * note that for FD_BLOCKSEQUENCE tot_len is the index for the tail fragment.
 * i.e. since the block numbers start at 0, if we specify tot_len==2, that
 * actually means we want to defragment 3 blocks, block 0, 1 and 2.
 */
void
fragment_set_tot_len(packet_info *pinfo, guint32 id, GHashTable *fragment_table,
		     guint32 tot_len)
{
	fragment_data *fd_head;
	fragment_key key;

	/* create key to search hash with */
	key.src = pinfo->src;
	key.dst = pinfo->dst;
	key.id  = id;

	fd_head = g_hash_table_lookup(fragment_table, &key);

	if(fd_head){
		fd_head->datalen = tot_len;
	}

	return;
}

guint32
fragment_get_tot_len(packet_info *pinfo, guint32 id, GHashTable *fragment_table)
{
	fragment_data *fd_head;
	fragment_key key;

	/* create key to search hash with */
	key.src = pinfo->src;
	key.dst = pinfo->dst;
	key.id  = id;

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
fragment_set_partial_reassembly(packet_info *pinfo, guint32 id, GHashTable *fragment_table)
{
	fragment_data *fd_head;
	fragment_key key;

	/* create key to search hash with */
	key.src = pinfo->src;
	key.dst = pinfo->dst;
	key.id  = id;

	fd_head = g_hash_table_lookup(fragment_table, &key);

	if(fd_head){
		fd_head->flags |= FD_PARTIAL_REASSEMBLY;
	}
}

/*
 * This function gets rid of an entry from a fragment table, given
 * a pointer to the key for that entry; it also frees up the key
 * and the addresses in it.
 */
static void
fragment_unhash(GHashTable *fragment_table, fragment_key *key)
{
	/*
	 * Free up the copies of the addresses from the old key.
	 */
	g_free((gpointer)key->src.data);
	g_free((gpointer)key->dst.data);

	/*
	 * Remove the entry from the fragment table.
	 */
	g_hash_table_remove(fragment_table, key);

	/*
	 * Free the key itself.
	 */
	g_mem_chunk_free(fragment_key_chunk, key);
}

/*
 * This function adds fragment_data structure to a reassembled-packet
 * hash table, using the frame data structure as the key.
 */
void
fragment_reassembled(fragment_data *fd_head, packet_info *pinfo,
	     GHashTable *reassembled_table)
{
	g_hash_table_insert(reassembled_table, (gpointer)pinfo->fd->num,
	    fd_head);
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
fragment_add_work(fragment_data *fd_head, tvbuff_t *tvb, int offset,
	     packet_info *pinfo, guint32 frag_offset,
	     guint32 frag_data_len, gboolean more_frags)
{
	fragment_data *fd;
	fragment_data *fd_i;
	guint32 max, dfpos;
	unsigned char *old_data;

	/* create new fd describing this fragment */
	fd = g_mem_chunk_alloc(fragment_data_chunk);
	fd->next = NULL;
	fd->flags = 0;
	fd->frame = pinfo->fd->num;
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
		fd_head->flags ^= FD_DEFRAGMENTED|FD_PARTIAL_REASSEMBLY;
		fd_head->flags &= (~FD_TOOLONGFRAGMENT) & (~FD_MULTIPLETAILS);
		fd_head->datalen=0;
	}

	if (!more_frags) {
		/*
		 * This is the tail fragment in the sequence.
		 */
		if (fd_head->datalen) {
			/* ok we have already seen other tails for this packet
			 * it might be a duplicate.
			 */
			if (fd_head->datalen != (fd->offset + fd->len) ){
				/* Oops, this tail indicates a different packet
				 * len than the previous ones. Somethings wrong
				 */
				fd->flags      |= FD_MULTIPLETAILS;
				fd_head->flags |= FD_MULTIPLETAILS;
			}
		} else {
			/* this was the first tail fragment, now we know the
			 * length of the packet
			 */
			fd_head->datalen = fd->offset + fd->len;
		}
	}




	/* If the packet is already defragmented, this MUST be an overlap.
         * The entire defragmented packet is in fd_head->data
	 * Even if we have previously defragmented this packet, we still check
	 * check it. Someone might play overlap and TTL games.
         */
	if (fd_head->flags & FD_DEFRAGMENTED) {
		fd->flags      |= FD_OVERLAP;
		fd_head->flags |= FD_OVERLAP;
		/* make sure its not too long */
		if (fd->offset + fd->len > fd_head->datalen) {
			fd->flags      |= FD_TOOLONGFRAGMENT;
			fd_head->flags |= FD_TOOLONGFRAGMENT;
			LINK_FRAG(fd_head,fd);
			return TRUE;
		}
		/* make sure it doesnt conflict with previous data */
		if ( memcmp(fd_head->data+fd->offset,
			tvb_get_ptr(tvb,offset,fd->len),fd->len) ){
			fd->flags      |= FD_OVERLAPCONFLICT;
			fd_head->flags |= FD_OVERLAPCONFLICT;
			LINK_FRAG(fd_head,fd);
			return TRUE;
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


	if( !(fd_head->datalen) ){
		/* if we dont know the datalen, there are still missing
		 * packets. Cheaper than the check below.
		 */
		return FALSE;
	}


	/* check if we have received the entire fragment
	 * this is easy since the list is sorted and the head is faked.
	 */
	max = 0;
	for (fd_i=fd_head->next;fd_i;fd_i=fd_i->next) {
		if ( ((fd_i->offset)<=max) &&
		    ((fd_i->offset+fd_i->len)>max) ){
			max = fd_i->offset+fd_i->len;
		}
	}

	if (max < (fd_head->datalen)) {
		/* we have not received all packets yet */
		return FALSE;
	}


	if (max > (fd_head->datalen)) {
		/*XXX not sure if current fd was the TOOLONG*/
		/*XXX is it fair to flag current fd*/
		/* oops, too long fragment detected */
		fd->flags      |= FD_TOOLONGFRAGMENT;
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
			if (fd_i->offset < dfpos) {
				fd_i->flags    |= FD_OVERLAP;
				fd_head->flags |= FD_OVERLAP;
				if ( memcmp(fd_head->data+fd_i->offset,
					fd_i->data,
					MIN(fd_i->len,(dfpos-fd_i->offset))
				   	) ){
					fd_i->flags    |= FD_OVERLAPCONFLICT;
					fd_head->flags |= FD_OVERLAPCONFLICT;
				}
			}
			/* dfpos is always >= than fd_i->offset */
			/* No gaps can exist here, max_loop(above) does this */
			if( fd_i->offset+fd_i->len > dfpos )
				memcpy(fd_head->data+dfpos, fd_i->data+(dfpos-fd_i->offset),
					fd_i->len-(dfpos-fd_i->offset));
			if( fd_i->flags & FD_NOT_MALLOCED )
				fd_i->flags ^= FD_NOT_MALLOCED;
			else
				g_free(fd_i->data);
			fd_i->data=NULL;

			dfpos=MAX(dfpos,(fd_i->offset+fd_i->len));
		}
	}

	if( old_data )
		g_free(old_data);
	/* mark this packet as defragmented.
           allows us to skip any trailing fragments */
	fd_head->flags |= FD_DEFRAGMENTED;
	fd_head->reassembled_in=pinfo->fd->num;

	return TRUE;
}

fragment_data *
fragment_add(tvbuff_t *tvb, int offset, packet_info *pinfo, guint32 id,
	     GHashTable *fragment_table, guint32 frag_offset,
	     guint32 frag_data_len, gboolean more_frags)
{
	fragment_key key, *new_key;
	fragment_data *fd_head;
	fragment_data *fd_item;
	gboolean already_added=pinfo->fd->flags.visited;

	/* create key to search hash with */
	key.src = pinfo->src;
	key.dst = pinfo->dst;
	key.id  = id;

	fd_head = g_hash_table_lookup(fragment_table, &key);

	/*
	 * "already_added" is true if "pinfo->fd->flags.visited" is true;
	 * if "pinfo->fd->flags.visited", this isn't the first pass, so
	 * we've already done all the reassembly and added all the
	 * fragments.
	 *
	 * If it's not true, just check if we have seen this fragment before,
	 * i.e., if we have already added it to reassembly.
	 * That can be true even if "pinfo->fd->flags.visited" is false
	 * since we sometimes might call a subdissector multiple times.
	 * As an additional check, just make sure we have not already added 
	 * this frame to the reassembly list, if there is a reassembly list;
	 * note that the first item in the reassembly list is not a
	 * fragment, it's a data structure for the reassembled packet.
	 * We don't check it because its "frame" member isn't initialized
	 * to anything, and because it doesn't count in any case.
	 */
	if (!already_added && fd_head != NULL) {
		for(fd_item=fd_head->next;fd_item;fd_item=fd_item->next){
			if(pinfo->fd->num==fd_item->frame){
				already_added=TRUE;
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
		fd_head=g_mem_chunk_alloc(fragment_data_chunk);

		/* head/first structure in list only holds no other data than
                 * 'datalen' then we don't have to change the head of the list
                 * even if we want to keep it sorted
                 */
		fd_head->next=NULL;
		fd_head->datalen=0;
		fd_head->offset=0;
		fd_head->len=0;
		fd_head->flags=0;
		fd_head->data=NULL;
		fd_head->reassembled_in=0;

		/*
		 * We're going to use the key to insert the fragment,
		 * so allocate a structure for it, and copy the
		 * addresses, allocating new buffers for the address
		 * data.
		 */
		new_key = g_mem_chunk_alloc(fragment_key_chunk);
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
fragment_add_check(tvbuff_t *tvb, int offset, packet_info *pinfo,
	     guint32 id, GHashTable *fragment_table,
	     GHashTable *reassembled_table, guint32 frag_offset,
	     guint32 frag_data_len, gboolean more_frags)
{
	fragment_key key, *new_key, *old_key;
	gpointer orig_key, value;
	fragment_data *fd_head;

	/*
	 * If this isn't the first pass, look for this frame in the table
	 * of reassembled packets.
	 */
	if (pinfo->fd->flags.visited)
		return g_hash_table_lookup(reassembled_table,
		    (gpointer)pinfo->fd->num);

	/* create key to search hash with */
	key.src = pinfo->src;
	key.dst = pinfo->dst;
	key.id  = id;

	if (!g_hash_table_lookup_extended(fragment_table, &key,
					  &orig_key, &value)) {
		/* not found, this must be the first snooped fragment for this
                 * packet. Create list-head.
		 */
		fd_head=g_mem_chunk_alloc(fragment_data_chunk);

		/* head/first structure in list only holds no other data than
                 * 'datalen' then we don't have to change the head of the list
                 * even if we want to keep it sorted
                 */
		fd_head->next=NULL;
		fd_head->datalen=0;
		fd_head->offset=0;
		fd_head->len=0;
		fd_head->flags=0;
		fd_head->data=NULL;
		fd_head->reassembled_in=0;

		/*
		 * We're going to use the key to insert the fragment,
		 * so allocate a structure for it, and copy the
		 * addresses, allocating new buffers for the address
		 * data.
		 */
		new_key = g_mem_chunk_alloc(fragment_key_chunk);
		COPY_ADDRESS(&new_key->src, &key.src);
		COPY_ADDRESS(&new_key->dst, &key.dst);
		new_key->id = key.id;
		g_hash_table_insert(fragment_table, new_key, fd_head);

		orig_key = new_key;	/* for unhashing it later */
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
		fragment_reassembled(fd_head, pinfo, reassembled_table);
		return fd_head;
	} else {
		/*
		 * Reassembly isn't complete.
		 */
		return NULL;
	}
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
fragment_add_seq_work(fragment_data *fd_head, tvbuff_t *tvb, int offset,
	     packet_info *pinfo, guint32 frag_number,
	     guint32 frag_data_len, gboolean more_frags)
{
	fragment_data *fd;
	fragment_data *fd_i;
	fragment_data *last_fd;
	guint32 max, dfpos, size;

	/* create new fd describing this fragment */
	fd = g_mem_chunk_alloc(fragment_data_chunk);
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
		if (fd_head->datalen) {
			/* ok we have already seen other tails for this packet
			 * it might be a duplicate.
			 */
			if (fd_head->datalen != fd->offset ){
				/* Oops, this tail indicates a different packet
				 * len than the previous ones. Somethings wrong
				 */
				fd->flags      |= FD_MULTIPLETAILS;
				fd_head->flags |= FD_MULTIPLETAILS;
			}
		} else {
			/* this was the first tail fragment, now we know the
			 * length of the packet
			 */
			fd_head->datalen = fd->offset;
		}
	}

	/* If the packet is already defragmented, this MUST be an overlap.
         * The entire defragmented packet is in fd_head->data
	 * Even if we have previously defragmented this packet, we still check
	 * check it. Someone might play overlap and TTL games.
         */
	if (fd_head->flags & FD_DEFRAGMENTED) {
		fd->flags      |= FD_OVERLAP;
		fd_head->flags |= FD_OVERLAP;

		/* make sure its not too long */
		if (fd->offset > fd_head->datalen) {
			fd->flags      |= FD_TOOLONGFRAGMENT;
			fd_head->flags |= FD_TOOLONGFRAGMENT;
			LINK_FRAG(fd_head,fd);
			return TRUE;
		}
		/* make sure it doesnt conflict with previous data */
		dfpos=0;
		last_fd=NULL;
		for (fd_i=fd_head->next;fd_i->offset!=fd->offset;fd_i=fd_i->next) {
		  if (!last_fd || last_fd->offset!=fd_i->offset){
		    dfpos += fd_i->len;
		  }
		  last_fd=fd_i;
		}
		if(fd_i->datalen!=fd->datalen){
			fd->flags      |= FD_OVERLAPCONFLICT;
			fd_head->flags |= FD_OVERLAPCONFLICT;
			LINK_FRAG(fd_head,fd);
			return TRUE;
		}
		g_assert(fd_head->len >= dfpos + fd->len);
		if ( memcmp(fd_head->data+dfpos,
			tvb_get_ptr(tvb,offset,fd->len),fd->len) ){
			fd->flags      |= FD_OVERLAPCONFLICT;
			fd_head->flags |= FD_OVERLAPCONFLICT;
			LINK_FRAG(fd_head,fd);
			return TRUE;
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


	if( !(fd_head->datalen) ){
		/* if we dont know the datalen, there are still missing
		 * packets. Cheaper than the check below.
		 */
		return FALSE;
	}


	/* check if we have received the entire fragment
	 * this is easy since the list is sorted and the head is faked.
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
		fd->flags      |= FD_TOOLONGFRAGMENT;
		fd_head->flags |= FD_TOOLONGFRAGMENT;
	}


	/* we have received an entire packet, defragment it and
         * free all fragments
         */
	size=0;
	last_fd=NULL;
	for(fd_i=fd_head->next;fd_i;fd_i=fd_i->next) {
	  if(!last_fd || last_fd->offset!=fd_i->offset){
	    size+=fd_i->len;
	  }
	  last_fd=fd_i;
	}
	fd_head->data = g_malloc(size);
	fd_head->len = size;		/* record size for caller	*/

	/* add all data fragments */
	last_fd=NULL;
	for (dfpos=0,fd_i=fd_head->next;fd_i;fd_i=fd_i->next) {
	  if (fd_i->len) {
	    if(!last_fd || last_fd->offset!=fd_i->offset){
	      memcpy(fd_head->data+dfpos,fd_i->data,fd_i->len);
	      dfpos += fd_i->len;
	    } else {
	      /* duplicate/retransmission/overlap */
	      fd_i->flags    |= FD_OVERLAP;
	      fd_head->flags |= FD_OVERLAP;
	      if( (last_fd->len!=fd_i->datalen)
		  || memcmp(last_fd->data, fd_i->data, last_fd->len) ){
			fd->flags      |= FD_OVERLAPCONFLICT;
			fd_head->flags |= FD_OVERLAPCONFLICT;
	      }
	    }
	    last_fd=fd_i;
	  }
	}

	/* we have defragmented the pdu, now free all fragments*/
	for (fd_i=fd_head->next;fd_i;fd_i=fd_i->next) {
	  if(fd_i->data){
	    g_free(fd_i->data);
	    fd_i->data=NULL;
	  }
	}

	/* mark this packet as defragmented.
           allows us to skip any trailing fragments */
	fd_head->flags |= FD_DEFRAGMENTED;
	fd_head->reassembled_in=pinfo->fd->num;

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
fragment_add_seq(tvbuff_t *tvb, int offset, packet_info *pinfo, guint32 id,
	     GHashTable *fragment_table, guint32 frag_number,
	     guint32 frag_data_len, gboolean more_frags)
{
	fragment_key key, *new_key;
	fragment_data *fd_head;

	/* create key to search hash with */
	key.src = pinfo->src;
	key.dst = pinfo->dst;
	key.id  = id;

	fd_head = g_hash_table_lookup(fragment_table, &key);

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
		fd_head=g_mem_chunk_alloc(fragment_data_chunk);

		/* head/first structure in list only holds no other data than
                 * 'datalen' then we don't have to change the head of the list
                 * even if we want to keep it sorted
                 */
		fd_head->next=NULL;
		fd_head->datalen=0;
		fd_head->offset=0;
		fd_head->len=0;
		fd_head->flags=FD_BLOCKSEQUENCE;
		fd_head->data=NULL;
		fd_head->reassembled_in=0;

		/*
		 * We're going to use the key to insert the fragment,
		 * so allocate a structure for it, and copy the
		 * addresses, allocating new buffers for the address
		 * data.
		 */
		new_key = g_mem_chunk_alloc(fragment_key_chunk);
		COPY_ADDRESS(&new_key->src, &key.src);
		COPY_ADDRESS(&new_key->dst, &key.dst);
		new_key->id = key.id;
		g_hash_table_insert(fragment_table, new_key, fd_head);
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
 * "fragment_data" structure is allocated to refer to the reassembled,
 * packet, and:
 *
 *	if "more_frags" is false, the structure is not added to
 *	the hash table, and not given any fragments to refer to,
 *	but is just returned;
 *
 *	if "more_frags" is true, this fragment is added to the linked
 *	list of fragments for this packet, and the "fragment_data"
 *	structure is put into the hash table.
 *
 * Otherwise, this fragment is just added to the linked list of fragments
 * for this packet.
 *
 * Returns a pointer to the head of the fragment data list, and removes
 * that from the fragment hash table if necessary and adds it to the
 * table of reassembled fragments, if we have all the fragments or if
 * this is the only fragment and "more_frags" is false, returns NULL
 * otherwise.
 */
fragment_data *
fragment_add_seq_check_work(tvbuff_t *tvb, int offset, packet_info *pinfo,
	     guint32 id, GHashTable *fragment_table,
	     GHashTable *reassembled_table, guint32 frag_number,
	     guint32 frag_data_len, gboolean more_frags,
	     gboolean no_frag_number)
{
	fragment_key key, *new_key, *old_key;
	gpointer orig_key, value;
	fragment_data *fd_head, *fd;

	/*
	 * Have we already seen this frame?
	 * If so, look for it in the table of reassembled packets.
	 */
	if (pinfo->fd->flags.visited)
		return g_hash_table_lookup(reassembled_table,
		    (gpointer)pinfo->fd->num);

	/* create key to search hash with */
	key.src = pinfo->src;
	key.dst = pinfo->dst;
	key.id  = id;

	if (!g_hash_table_lookup_extended(fragment_table, &key,
					  &orig_key, &value)) {
		/* not found, this must be the first snooped fragment for this
                 * packet. Create list-head.
		 */
		fd_head=g_mem_chunk_alloc(fragment_data_chunk);

		/* head/first structure in list only holds no other data than
                 * 'datalen' then we don't have to change the head of the list
                 * even if we want to keep it sorted
                 */
		fd_head->next=NULL;
		fd_head->datalen=0;
		fd_head->offset=0;
		fd_head->len=0;
		fd_head->flags=FD_BLOCKSEQUENCE;
		fd_head->data=NULL;
		fd_head->reassembled_in=0;

		if (!more_frags) {
			/*
			 * This is the last snooped fragment for this
			 * packet as well; that means it's the only
			 * fragment.  Just add it to the table of
			 * reassembled packets, and return it.
			 */
			fragment_reassembled(fd_head, pinfo,
			       reassembled_table);
			return fd_head;
		}

		/*
		 * We're going to use the key to insert the fragment,
		 * so allocate a structure for it, and copy the
		 * addresses, allocating new buffers for the address
		 * data.
		 */
		new_key = g_mem_chunk_alloc(fragment_key_chunk);
		COPY_ADDRESS(&new_key->src, &key.src);
		COPY_ADDRESS(&new_key->dst, &key.dst);
		new_key->id = key.id;
		g_hash_table_insert(fragment_table, new_key, fd_head);

		orig_key = new_key;	/* for unhashing it later */

		/*
		 * If we weren't given an initial fragment number,
		 * make it 0.
		 */
		if (no_frag_number)
			frag_number = 0;
	} else {
		/*
		 * We found it.
		 */
		fd_head = value;

		/*
		 * If we weren't given an initial fragment number,
		 * use the next expected fragment number as the fragment
		 * number for this fragment.
		 */
		if (no_frag_number) {
			for (fd = fd_head; fd != NULL; fd = fd->next) {
				if (fd->next == NULL)
					frag_number = fd->offset + 1;
			}
		}
	}

	/*
	 * If we don't have all the data that is in this fragment,
	 * then we can't, and don't, do reassembly on it.
	 *
	 * If it's the first frame, handle it as an unfragmented packet.
	 * Otherwise, just handle it as a fragment.
	 *
	 * If "more_frags" isn't set, we get rid of the entry in the
	 * hash table for this reassembly, as we don't need it any more.
	 */
	if (!tvb_bytes_exist(tvb, offset, frag_data_len)) {
		if (!more_frags) {
			/*
			 * Remove this from the table of in-progress
			 * reassemblies, and free up any memory used for
			 * it in that table.
			 */
			old_key = orig_key;
			fragment_unhash(fragment_table, old_key);
		}
		return frag_number == 0 ? fd_head : NULL;
	}

	if (fragment_add_seq_work(fd_head, tvb, offset, pinfo,
				  frag_number, frag_data_len, more_frags)) {
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
		fragment_reassembled(fd_head, pinfo, reassembled_table);
		return fd_head;
	} else {
		/*
		 * Reassembly isn't complete.
		 */
		return NULL;
	}
}

fragment_data *
fragment_add_seq_check(tvbuff_t *tvb, int offset, packet_info *pinfo,
	     guint32 id, GHashTable *fragment_table,
	     GHashTable *reassembled_table, guint32 frag_number,
	     guint32 frag_data_len, gboolean more_frags)
{
	return fragment_add_seq_check_work(tvb, offset, pinfo, id,
	    fragment_table, reassembled_table, frag_number, frag_data_len,
	    more_frags, FALSE);
}

fragment_data *
fragment_add_seq_next(tvbuff_t *tvb, int offset, packet_info *pinfo,
	     guint32 id, GHashTable *fragment_table,
	     GHashTable *reassembled_table, guint32 frag_data_len,
	     gboolean more_frags)
{
	return fragment_add_seq_check_work(tvb, offset, pinfo, id,
	    fragment_table, reassembled_table, 0, frag_data_len,
	    more_frags, TRUE);
}

/*
 * Show a single fragment in a fragment subtree.
 */
static void
show_fragment(fragment_data *fd, int offset, const fragment_items *fit,
    proto_tree *ft, tvbuff_t *tvb)
{
	if (fd->flags & (FD_OVERLAP|FD_OVERLAPCONFLICT
		|FD_MULTIPLETAILS|FD_TOOLONGFRAGMENT) ) {
		/* this fragment has some flags set, create a subtree
		 * for it and display the flags.
		 */
		proto_tree *fet=NULL;
		proto_item *fei=NULL;
		int hf;

		if (fd->flags & (FD_OVERLAPCONFLICT
			|FD_MULTIPLETAILS|FD_TOOLONGFRAGMENT) ) {
			hf = *(fit->hf_fragment_error);
		} else {
			hf = *(fit->hf_fragment);
		}
		fei = proto_tree_add_uint_format(ft, hf,
			tvb, offset, fd->len,
			fd->frame,
			"Frame:%u payload:%u-%u",
			fd->frame,
			offset,
			offset+fd->len-1);
		fet = proto_item_add_subtree(fei, *(fit->ett_fragment));
		if (fd->flags&FD_OVERLAP) {
			proto_tree_add_boolean(fet,
				*(fit->hf_fragment_overlap),
				tvb, 0, 0,
				TRUE);
		}
		if (fd->flags&FD_OVERLAPCONFLICT) {
			proto_tree_add_boolean(fet,
				*(fit->hf_fragment_overlap_conflict),
				tvb, 0, 0,
				TRUE);
		}
		if (fd->flags&FD_MULTIPLETAILS) {
			proto_tree_add_boolean(fet,
				*(fit->hf_fragment_multiple_tails),
				tvb, 0, 0,
				TRUE);
		}
		if (fd->flags&FD_TOOLONGFRAGMENT) {
			proto_tree_add_boolean(fet,
				*(fit->hf_fragment_too_long_fragment),
				tvb, 0, 0,
				TRUE);
		}
	} else {
		/* nothing of interest for this fragment */
		proto_tree_add_uint_format(ft, *(fit->hf_fragment),
			tvb, offset, fd->len,
			fd->frame,
			"Frame:%u payload:%u-%u",
			fd->frame,
			offset,
			offset+fd->len-1
		);
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
    proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb)
{
	fragment_data *fd;
	proto_tree *ft;
	proto_item *fi;

	/* It's not fragmented. */
	pinfo->fragmented = FALSE;

	fi = proto_tree_add_item(tree, *(fit->hf_fragments),
	    tvb, 0, -1, FALSE);
	ft = proto_item_add_subtree(fi, *(fit->ett_fragments));
	for (fd = fd_head->next; fd != NULL; fd = fd->next)
		show_fragment(fd, fd->offset, fit, ft, tvb);

	return show_fragment_errs_in_col(fd_head, fit, pinfo);
}

/* This function will build the fragment subtree; it's for fragments
   reassembled with "fragment_add_seq()" or "fragment_add_seq_check()".

   It will return TRUE if there were fragmentation errors
   or FALSE if fragmentation was ok.
*/
gboolean
show_fragment_seq_tree(fragment_data *fd_head, const fragment_items *fit,
    proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb)
{
	guint32 offset, next_offset;
	fragment_data *fd, *last_fd;
	proto_tree *ft;
	proto_item *fi;

	/* It's not fragmented. */
	pinfo->fragmented = FALSE;

	fi = proto_tree_add_item(tree, *(fit->hf_fragments),
	    tvb, 0, -1, FALSE);
	ft = proto_item_add_subtree(fi, *(fit->ett_fragments));
	offset = 0;
	next_offset = 0;
	last_fd = NULL;
	for (fd = fd_head->next; fd != NULL; fd = fd->next){
		if (last_fd == NULL || last_fd->offset != fd->offset) {
			offset = next_offset;
			next_offset += fd->len;
		}
		last_fd = fd;
		show_fragment(fd, offset, fit, ft, tvb);
	}

	return show_fragment_errs_in_col(fd_head, fit, pinfo);
}
