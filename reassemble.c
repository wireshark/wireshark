/* reassemble.c
 * Routines for {fragment,segment} reassembly
 *
 * $Id: reassemble.c,v 1.10 2002/03/31 21:05:47 guy Exp $
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
	fragment_key* key1 = (fragment_key*) k1;
	fragment_key* key2 = (fragment_key*) k2;

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
	fragment_key* key = (fragment_key*) k;
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
 * For a hash table entry, free the address data to which the key refers
 * and the fragment data to which the value refers.
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
	    G_ALLOC_ONLY);
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
fragment_data *
fragment_add(tvbuff_t *tvb, int offset, packet_info *pinfo, guint32 id,
	     GHashTable *fragment_table, guint32 frag_offset,
	     guint32 frag_data_len, gboolean more_frags)
{
	fragment_key key, *new_key;
	fragment_data *fd_head;
	fragment_data *fd;
	fragment_data *fd_i;
	guint32 max, dfpos;
	unsigned char *old_data;

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
		fd_head->flags=0;
		fd_head->data=NULL;

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
			return (fd_head);
		}
		/* make sure it doesnt conflict with previous data */
		if ( memcmp(fd_head->data+fd->offset,
			tvb_get_ptr(tvb,offset,fd->len),fd->len) ){
			fd->flags      |= FD_OVERLAPCONFLICT;
			fd_head->flags |= FD_OVERLAPCONFLICT;
			LINK_FRAG(fd_head,fd);
			return (fd_head);
		}
		/* it was just an overlap, link it and return */
		LINK_FRAG(fd_head,fd);
		return (fd_head);
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
		return NULL;
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
		return NULL;
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

	return fd_head;
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
 * This function assumes frag_offset being a block sequence number.
 * the bsn for the first block is 0.
 */
fragment_data *
fragment_add_seq(tvbuff_t *tvb, int offset, packet_info *pinfo, guint32 id,
	     GHashTable *fragment_table, guint32 frag_offset,
	     guint32 frag_data_len, gboolean more_frags)
{
	fragment_key key, *new_key;
	fragment_data *fd_head;
	fragment_data *fd;
	fragment_data *fd_i;
	fragment_data *last_fd;
	guint32 max, dfpos, size;

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

	/* create new fd describing this fragment */
	fd = g_mem_chunk_alloc(fragment_data_chunk);
	fd->next = NULL;
	fd->flags = 0;
	fd->frame = pinfo->fd->num;
	fd->offset = frag_offset;
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
			return (fd_head);
		}
		/* make sure it doesnt conflict with previous data */
		dfpos=0;
		for (fd_i=fd_head->next;fd_i->offset!=fd->offset;fd_i=fd_i->next) {
		  dfpos += fd_i->len;
		}
		if(fd_i->datalen!=fd->datalen){
			fd->flags      |= FD_OVERLAPCONFLICT;
			fd_head->flags |= FD_OVERLAPCONFLICT;
			LINK_FRAG(fd_head,fd);
			return (fd_head);
		}
		if ( memcmp(fd_head->data+dfpos,
			tvb_get_ptr(tvb,offset,fd->len),fd->len) ){
			fd->flags      |= FD_OVERLAPCONFLICT;
			fd_head->flags |= FD_OVERLAPCONFLICT;
			LINK_FRAG(fd_head,fd);
			return (fd_head);
		}
		/* it was just an overlap, link it and return */
		LINK_FRAG(fd_head,fd);
		return (fd_head);
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
		return NULL;
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
		return NULL;
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

	return fd_head;
}
