/* conversation.c
 * Routines for building lists of packets that are part of a "conversation"
 *
 * $Id: conversation.c,v 1.1 1999/10/22 07:17:28 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>
#include "packet.h"

static GHashTable *conversation_hashtable = NULL;
static GMemChunk *conversation_key_chunk = NULL;
static GMemChunk *conversation_val_chunk = NULL;

typedef struct conversation_key {
	struct conversation_key *next;
	address	src;
	address	dst;
	port_type ptype;
	guint16	port_src;
	guint16	port_dst;
} conversation_key;

/*
 * Linked list of conversation keys, so we can, before freeing them all,
 * free the address data allocations associated with them.
 */
static conversation_key *conversation_keys;

typedef struct conversation_val {
	struct conversation_val *next;
	guint32	index;
} conversation_val;

static guint32 new_index;

static int conversation_init_count = 200;

/*
 * Compare two conversation keys.
 */
static gint
conversation_equal(gconstpointer v, gconstpointer w)
{
	conversation_key *v1 = (conversation_key *)v;
	conversation_key *v2 = (conversation_key *)w;

	/*
	 * We assume that a source and a destination address for a given
	 * packet in a conversation have the same type.
	 */
	if (v1->src.type != v2->src.type)
		return 0;	/* different types of addresses */

	if (v1->ptype != v2->ptype)
		return 0;	/* different types of port */

	if (v1->src.len == v2->src.len &&
	    memcmp(v1->src.data, v2->src.data, v1->src.len) == 0) {
		/*
		 * The first and second source addresses are the same.
		 */
		if (v1->dst.len == v2->dst.len &&
		    memcmp(v1->dst.data, v2->dst.data, v1->dst.len) == 0) {
			/*
			 * The first and second destination addresses
			 * are the same, so they're both going from
			 * the same machine and they're both going to
			 * the same machine.
			 */
			if (v1->port_src == v2->port_src &&
			    v1->port_dst == v2->port_dst) {
			    	/*
				 * The first and second source ports
				 * are the same, and the first and second
				 * destination ports are the same, so
				 * it's the same conversation, and the two
				 * address/port pairs are going in the same
				 * direction.
				 */
				return 1;
			}
		}
	} else if (v1->src.len == v2->dst.len &&
	    memcmp(v1->src.data, v2->dst.data, v1->src.len) == 0) {
		/*
		 * The first source address is the same as the second
		 * destination address.
		 */
		if (v1->dst.len == v2->src.len &&
		    memcmp(v1->dst.data, v2->src.data, v1->dst.len) == 0) {
			/*
			 * The first destination address is the same as
			 * the second source address, so they're going
			 * between the same machines, but in opposite
			 * directions.
			 */
			if (v1->port_src == v2->port_dst &&
			    v1->port_dst == v2->port_src) {
			    	/*
				 * The first source port is the same as
				 * the second destination port, and the
				 * first destination port is the same as
				 * the second source port, so it's
				 * the same conversation, and the two
				 * address/port pairs are going in
				 * opposite directions.
				 */
				return 1;
			}
		}
	}

	/*
	 * The addresses or the ports don't match.
	 */	
	return 0;
}

/*
 * Compute the hash value for a given set of source and destination
 * addresses and ports.
 */
static guint 
conversation_hash(gconstpointer v)
{
	conversation_key *key = (conversation_key *)v;
	guint hash_val;
	int i;

	hash_val = 0;
	for (i = 0; i < key->src.len; i++)
		hash_val += key->src.data[i];
	for (i = 0; i < key->dst.len; i++)
		hash_val += key->dst.data[i];
	hash_val += key->port_src + key->port_dst;

	return hash_val;
}

/*
 * Initialize some variables every time a file is loaded or re-loaded.
 * Destroy all existing conversations, and create a new hash table
 * for the conversations in the new file.
 */
void
conversation_init(void)
{
	conversation_key *key;

	/*
	 * Free the addresses associated with the conversation keys.
	 */
	for (key = conversation_keys; key != NULL; key = key->next) {
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
	}
	if (conversation_hashtable != NULL)
		g_hash_table_destroy(conversation_hashtable);
	if (conversation_key_chunk != NULL)
		g_mem_chunk_destroy(conversation_key_chunk);
	if (conversation_val_chunk != NULL)
		g_mem_chunk_destroy(conversation_val_chunk);

	conversation_hashtable = g_hash_table_new(conversation_hash,
	    conversation_equal);
	conversation_key_chunk = g_mem_chunk_new("conversation_key_chunk",
	    sizeof(conversation_key),
	    conversation_init_count * sizeof(struct conversation_key),
	    G_ALLOC_AND_FREE);
	conversation_val_chunk = g_mem_chunk_new("conversation_val_chunk",
	    sizeof(conversation_val),
	    conversation_init_count * sizeof(struct conversation_val),
	    G_ALLOC_AND_FREE);

	/*
	 * Start the conversation indices over at 0.
	 */
	new_index = 0;
}

/*
 * Copy an address, allocating a new buffer for the address data.
 */
static void
copy_address(address *to, address *from)
{
	guint8 *data;

	to->type = from->type;
	to->len = from->len;
	data = g_malloc(from->len);
	memcpy(data, from->data, from->len);
	to->data = data;
}

/*
 * Given source and destination addresses and ports for a packet, add
 * it to the conversation containing packets between those address/port
 * pairs, creating a new conversation if none exists between them.
 *
 * Returns an index to use to refer to the conversation.
 */
guint32
add_to_conversation(address *src, address *dst, port_type ptype,
    guint16 src_port, guint16 dst_port)
{
	conversation_val *conversation;
	conversation_key key, *new_key;

	/*
	 * We don't make a copy of the address data, we just copy the
	 * pointer to it, as "key" disappears when we return.
	 */
	key.src = *src;
	key.dst = *dst;
	key.ptype = ptype;
	key.port_src = src_port;
	key.port_dst = dst_port;
	conversation =
	    (conversation_val *)g_hash_table_lookup(conversation_hashtable,
	    &key);
	if (conversation == NULL) {
		/*
		 * No such conversation yet.
		 * Allocate a new one.
		 * Here, we *do* have to copy the address data.
		 */
		new_key = g_mem_chunk_alloc(conversation_key_chunk);
		new_key->next = conversation_keys;
		conversation_keys = new_key;
		copy_address(&new_key->src, src);
		copy_address(&new_key->dst, dst);
		new_key->ptype = ptype;
		new_key->port_src = src_port;
		new_key->port_dst = dst_port;

		conversation = g_mem_chunk_alloc(conversation_val_chunk);
		conversation->index = new_index;
		new_index++;

		g_hash_table_insert(conversation_hashtable, new_key,
		    conversation);
	}
	return conversation->index;
}
