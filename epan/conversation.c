/* conversation.c
 * Routines for building lists of packets that are part of a "conversation"
 *
 * $Id: conversation.c,v 1.6 2000/11/18 11:47:21 guy Exp $
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
#include "conversation.h"

/*
 * Hash table for conversations with no wildcards.
 */
static GHashTable *conversation_hashtable_exact = NULL;

/*
 * Hash table for conversations with wildcard destination address.
 */
static GHashTable *conversation_hashtable_no_dst_addr = NULL;

/*
 * Hash table for conversations with wildcard destination port.
 */
static GHashTable *conversation_hashtable_no_dst_port = NULL;

/*
 * Hash table for conversations with wildcard destination address and port.
 */
static GHashTable *conversation_hashtable_no_dst = NULL;

static GMemChunk *conversation_key_chunk = NULL;
static GMemChunk *conversation_chunk = NULL;

#ifdef __NOT_USED__ 
typedef struct conversation_key {
	struct conversation_key *next;
	address	src;
	address	dst;
	port_type ptype;
	guint32	port_src;
	guint32	port_dst;
} conversation_key;
#endif
/*
 * Linked list of conversation keys, so we can, before freeing them all,
 * free the address data allocations associated with them.
 */
static conversation_key *conversation_keys;

static guint32 new_index;

static int conversation_init_count = 200;

/*
 * Compute the hash value for a given set of source and destination
 * addresses and ports if the match is to be exact.
 */
static guint 
conversation_hash_exact(gconstpointer v)
{
	conversation_key *key = (conversation_key *)v;
	guint hash_val;
	int i;

	hash_val = 0;
	for (i = 0; i < key->src.len; i++)
		hash_val += key->src.data[i];

	hash_val += key->port_src;

	for (i = 0; i < key->dst.len; i++)
		hash_val += key->dst.data[i];

	hash_val += key->port_dst;

	return hash_val;
}

/*
 * Compare two conversation keys for an exact match.
 */
static gint
conversation_match_exact(gconstpointer v, gconstpointer w)
{
	conversation_key *v1 = (conversation_key *)v;
	conversation_key *v2 = (conversation_key *)w;

	if (v1->ptype != v2->ptype)
		return 0;	/* different types of port */

	/*
	 * Are the first and second source ports the same, the first and
	 * second destination ports the same, the first and second source
	 * addresses the same, and the first and second destination
	 * addresses the same?
	 */
	if (v1->port_src == v2->port_src &&
	    v1->port_dst == v2->port_dst &&
	    v1->src.type == v2->src.type &&
	    v1->src.len == v2->src.len &&
	    memcmp(v1->src.data, v2->src.data, v1->src.len) == 0 &&
	    v1->dst.type == v2->dst.type &&
	    v1->dst.type == v2->dst.type &&
	    v1->dst.len == v2->dst.len &&
	    memcmp(v1->dst.data, v2->dst.data, v1->dst.len) == 0) {
		/*
		 * Yes.  It's the same conversation, and the two
		 * address/port pairs are going in the same direction.
		 */
		return 1;
	}

	/*
	 * Is the first destination port the same as the second source
	 * port, the first source port the same as the second destination
	 * port, the first destination address the same as the second
	 * source address, and the first source address the same as the
	 * second destination address?
	 */
	if (v1->port_dst == v2->port_src &&
	    v1->port_src == v2->port_dst &&
	    v1->dst.type == v2->src.type &&
	    v1->dst.len == v2->src.len &&
	    memcmp(v1->dst.data, v2->src.data, v1->dst.len) == 0 &&
	    v1->src.type == v2->dst.type &&
	    v1->src.len == v2->dst.len &&
	    memcmp(v1->src.data, v2->dst.data, v1->src.len) == 0) {
		/*
		 * Yes.  It's the same conversation, and the two
		 * address/port pairs are going in opposite directions.
		 */
		return 1;
	}

	/*
	 * The addresses or the ports don't match.
	 */	
	return 0;
}

/*
 * Compute the hash value for a given set of source and destination
 * addresses and ports if the match has a wildcard destination address.
 */
static guint 
conversation_hash_no_dst_addr(gconstpointer v)
{
	conversation_key *key = (conversation_key *)v;
	guint hash_val;
	int i;

	hash_val = 0;
	for (i = 0; i < key->src.len; i++)
		hash_val += key->src.data[i];

	hash_val += key->port_src;

	hash_val += key->port_dst;

	return hash_val;
}

/*
 * Compare two conversation keys, except for the destination address.
 * We don't check both directions of the conversation - the routine
 * doing the hash lookup has to do two searches, as the hash key
 * will be different for the two directions.
 */
static gint
conversation_match_no_dst_addr(gconstpointer v, gconstpointer w)
{
	conversation_key *v1 = (conversation_key *)v;
	conversation_key *v2 = (conversation_key *)w;

	if (v1->ptype != v2->ptype)
		return 0;	/* different types of port */

	/*
	 * Are the first and second source ports the same, the first and
	 * second destination ports the same, and the first and second
	 * source addresses the same?
	 */
	if (v1->port_src == v2->port_src &&
	    v1->port_dst == v2->port_dst &&
	    v1->src.type == v2->src.type &&
	    v1->src.len == v2->src.len &&
	    memcmp(v1->src.data, v2->src.data, v1->src.len) == 0) {
		/*
		 * Yes.  It's the same conversation, and the two
		 * address/port pairs are going in the same direction.
		 */
		return 1;
	}

	/*
	 * The addresses or the ports don't match.
	 */	
	return 0;
}

/*
 * Compute the hash value for a given set of source and destination
 * addresses and ports if the match has a wildcard destination port.
 */
static guint 
conversation_hash_no_dst_port(gconstpointer v)
{
	conversation_key *key = (conversation_key *)v;
	guint hash_val;
	int i;

	hash_val = 0;
	for (i = 0; i < key->src.len; i++)
		hash_val += key->src.data[i];

	hash_val += key->port_src;

	for (i = 0; i < key->dst.len; i++)
		hash_val += key->dst.data[i];

	return hash_val;
}

/*
 * Compare two conversation keys, except for the destination port.
 * We don't check both directions of the conversation - the routine
 * doing the hash lookup has to do two searches, as the hash key
 * will be different for the two directions.
 */
static gint
conversation_match_no_dst_port(gconstpointer v, gconstpointer w)
{
	conversation_key *v1 = (conversation_key *)v;
	conversation_key *v2 = (conversation_key *)w;

	if (v1->ptype != v2->ptype)
		return 0;	/* different types of port */

	/*
	 * Are the first and second source ports the same, the first and
	 * second source addresses the same, and the first and second
	 * destination addresses the same?
	 */
	if (v1->port_src == v2->port_src &&
	    v1->src.type == v2->src.type &&
	    v1->src.len == v2->src.len &&
	    memcmp(v1->src.data, v2->src.data, v1->src.len) == 0 &&
	    v1->dst.type == v2->dst.type &&
	    v1->dst.type == v2->dst.type &&
	    v1->dst.len == v2->dst.len &&
	    memcmp(v1->dst.data, v2->dst.data, v1->dst.len) == 0) {
		/*
		 * Yes.  It's the same conversation, and the two
		 * address/port pairs are going in the same direction.
		 */
		return 1;
	}

	/*
	 * The addresses or the ports don't match.
	 */	
	return 0;
}

/*
 * Compute the hash value for a given set of source and destination
 * addresses and ports if the match has a wildcard destination.
 */
static guint 
conversation_hash_no_dst(gconstpointer v)
{
	conversation_key *key = (conversation_key *)v;
	guint hash_val;
	int i;

	hash_val = 0;
	for (i = 0; i < key->src.len; i++)
		hash_val += key->src.data[i];

	hash_val += key->port_src;

	return hash_val;
}

/*
 * Compare the source address and port in the two conversation keys.
 * We don't check both directions of the conversation - the routine
 * doing the hash lookup has to do two searches, as the hash key
 * will be different for the two directions.
 */
static gint
conversation_match_no_dst(gconstpointer v, gconstpointer w)
{
	conversation_key *v1 = (conversation_key *)v;
	conversation_key *v2 = (conversation_key *)w;

	if (v1->ptype != v2->ptype)
		return 0;	/* different types of port */

	/*
	 * Are the first and second source ports the same and the first
	 * and second source addresses the same?
	 */
	if (v1->port_src == v2->port_src &&
	    v1->src.type == v2->src.type &&
	    v1->src.len == v2->src.len &&
	    memcmp(v1->src.data, v2->src.data, v1->src.len) == 0) {
		/*
		 * Yes.  It's the same conversation, and the two
		 * address/port pairs are going in the same direction.
		 */
		return 1;
	}

	/*
	 * The addresses or the ports don't match.
	 */	
	return 0;
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
	conversation_keys = NULL;
	if (conversation_hashtable_exact != NULL)
		g_hash_table_destroy(conversation_hashtable_exact);
	if (conversation_hashtable_no_dst_addr != NULL)
		g_hash_table_destroy(conversation_hashtable_no_dst_addr);
	if (conversation_hashtable_no_dst_port != NULL)
		g_hash_table_destroy(conversation_hashtable_no_dst_port);
	if (conversation_hashtable_no_dst != NULL)
		g_hash_table_destroy(conversation_hashtable_no_dst);
	if (conversation_key_chunk != NULL)
		g_mem_chunk_destroy(conversation_key_chunk);
	if (conversation_chunk != NULL)
		g_mem_chunk_destroy(conversation_chunk);

	conversation_hashtable_exact =
	    g_hash_table_new(conversation_hash_exact,
	      conversation_match_exact);
	conversation_hashtable_no_dst_addr =
	    g_hash_table_new(conversation_hash_no_dst_addr,
	      conversation_match_no_dst_addr);
	conversation_hashtable_no_dst_port =
	    g_hash_table_new(conversation_hash_no_dst_port,
	      conversation_match_no_dst_port);
	conversation_hashtable_no_dst =
	    g_hash_table_new(conversation_hash_no_dst,
	      conversation_match_no_dst);
	conversation_key_chunk = g_mem_chunk_new("conversation_key_chunk",
	    sizeof(conversation_key),
	    conversation_init_count * sizeof(struct conversation_key),
	    G_ALLOC_AND_FREE);
	conversation_chunk = g_mem_chunk_new("conversation_chunk",
	    sizeof(conversation_t),
	    conversation_init_count * sizeof(conversation_t),
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
 * Given source and destination addresses and ports for a packet,
 * create a new conversation to contain packets between those address/port
 * pairs. The options field is used to flag the destination address/port 
 * are not given and any value is acceptable.

 */
conversation_t *
conversation_new(address *src, address *dst, port_type ptype,
    guint32 src_port, guint32 dst_port, void *data, guint options)
{
	conversation_t *conversation;
	conversation_key *new_key;

	new_key = g_mem_chunk_alloc(conversation_key_chunk);
	new_key->next = conversation_keys;
	conversation_keys = new_key;
	copy_address(&new_key->src, src);
	copy_address(&new_key->dst, dst);
	new_key->ptype = ptype;
	new_key->port_src = src_port;
	new_key->port_dst = dst_port;

	conversation = g_mem_chunk_alloc(conversation_chunk);
	conversation->index = new_index;
	conversation->data = data;

/* clear dissector pointer */
	conversation->dissector.new_d = NULL;

/* set the options and key pointer */
	conversation->options = options;
	conversation->key_ptr = new_key;

	new_index++;

	if (options & NO_DST_ADDR) {
		if (options & NO_DST_PORT) {
			g_hash_table_insert(conversation_hashtable_no_dst,
			    new_key, conversation);
		} else {
			g_hash_table_insert(conversation_hashtable_no_dst_addr,
			    new_key, conversation);
		}
	} else {
		if (options & NO_DST_PORT) {
			g_hash_table_insert(conversation_hashtable_no_dst_port,
			    new_key, conversation);
		} else {
			g_hash_table_insert(conversation_hashtable_exact,
			    new_key, conversation);
		}
	}
	return conversation;
}

/* Set the destination port in a key.  Remove the original from table,
   update the options and port values, insert the updated key.
*/
void conversation_set_port( conversation_t *conv, guint32 port){

	/*
	 * If the destination port has already been set, don't set it
	 * again.
	 */
	if (!(conv->options & NO_DST_PORT))
		return;

	if (conv->options & NO_DST_ADDR) {
		g_hash_table_remove(conversation_hashtable_no_dst,
		    conv->key_ptr);
	} else {
		g_hash_table_remove(conversation_hashtable_no_dst_port,
		    conv->key_ptr);
	}
	conv->options &= ~NO_DST_PORT;
	conv->key_ptr->port_dst  = port;
	if (conv->options & NO_DST_ADDR) {
		g_hash_table_insert(conversation_hashtable_no_dst_addr,
		    conv->key_ptr, conv);
	} else {
		g_hash_table_insert(conversation_hashtable_exact,
		    conv->key_ptr, conv);
	}
} 

/* Set the destination address in a key.  Remove the original from
   table, update the options and port values, insert the updated key.
*/
void conversation_set_addr( conversation_t *conv, address *addr){

	/*
	 * If the destination address has already been set, don't set it
	 * again.
	 */
	if (!(conv->options & NO_DST_ADDR))
		return;

	if (conv->options & NO_DST_PORT) {
		g_hash_table_remove(conversation_hashtable_no_dst,
		    conv->key_ptr);
	} else {
		g_hash_table_remove(conversation_hashtable_no_dst_addr,
		    conv->key_ptr);
	}
	conv->options &= ~NO_DST_ADDR;
	copy_address(&conv->key_ptr->dst, addr);
	if (conv->options & NO_DST_PORT) {
		g_hash_table_insert(conversation_hashtable_no_dst_port,
		    conv->key_ptr, conv);
	} else {
		g_hash_table_insert(conversation_hashtable_exact,
		    conv->key_ptr, conv);
	}
}

static conversation_t *
conversation_match(GHashTable *hashtable, address *src, address *dst,
    port_type ptype, guint32 src_port, guint32 dst_port)
{
	conversation_key key;

	/*
	 * We don't make a copy of the address data, we just copy the
	 * pointer to it, as "key" disappears when we return.
	 */
	key.src = *src;
	key.dst = *dst;
	key.ptype = ptype;
	key.port_src = src_port;
	key.port_dst = dst_port;
	return g_hash_table_lookup(hashtable, &key);
}
 
/*
 * Given source and destination addresses and ports for a packet,
 * search for a conversation containing packets between those address/port
 * pairs.  Returns NULL if not found.  If the NO_DEST_ADDR and/or NO_DEST_PORT
 * flags are set in the conversation options field, that value will not
 * be used.
 */
conversation_t *
find_conversation(address *src, address *dst, port_type ptype,
    guint32 src_port, guint32 dst_port, guint options)
{
	conversation_t *conversation;

	if (options & NO_DST_ADDR) {
		if (options & NO_DST_PORT) {
			/*
			 * Wildcard the address and port - first try looking
			 * for a conversation with the specified source
			 * address and port, then try looking for one with a
			 * source address and port that's the specified
			 * *destination* address and port (this packet may be
			 * going in the opposite direction from the first
			 * packet in the conversation).
			 */
			conversation =
			    conversation_match(conversation_hashtable_no_dst,
			        src, dst, ptype, src_port, dst_port);
			if (conversation != NULL)
				return conversation;
			return conversation_match(conversation_hashtable_no_dst,
			    dst, src, ptype, dst_port, src_port);
		} else {
			/*
			 * Wildcard the address - first try looking for a
			 * conversation with the specified source address
			 * and port and destination port, then try looking
			 * for one with a source address and port that's
			 * the specified *destination* address and port and
			 * a destination port that's the specified *source*
			 * port (this packet may be going in the opposite
			 * direction from the first packet in the conversation).
			 */
			conversation =
			    conversation_match(conversation_hashtable_no_dst_addr,
			        src, dst, ptype, src_port, dst_port);
			if (conversation != NULL)
				return conversation;
			return conversation_match(conversation_hashtable_no_dst_addr,
			    dst, src, ptype, dst_port, src_port);
		}
	} else {
		if (options & NO_DST_PORT) {
			/*
			 * Wildcard the port - first try looking for a
			 * conversation with the specified source address
			 * and port and destination address, then try looking
			 * for one with a source address and port that's
			 * the specified *destination* address and port and
			 * a destination address that's the specified *source*
			 * address (this packet may be going in the opposite
			 * direction from the first packet in the conversation).
			 */
			conversation =
			    conversation_match(conversation_hashtable_no_dst_port,
			      src, dst, ptype, src_port, dst_port);
			if (conversation != NULL)
				return conversation;
			return conversation_match(conversation_hashtable_no_dst_port,
			    dst, src, ptype, dst_port, src_port);
		} else {
			/*
			 * Search for an exact match.  That search checks both
			 * directions.
			 */
			return conversation_match(conversation_hashtable_exact,
			    src, dst, ptype, src_port, dst_port);
		}
	}
}

/*
 * Set the dissector for a conversation.
 */
void
old_conversation_set_dissector(conversation_t *conversation,
    old_dissector_t dissector)
{
	conversation->is_old_dissector = TRUE;
	conversation->dissector.old_d = dissector;
}

void
conversation_set_dissector(conversation_t *conversation,
    dissector_t dissector)
{
	conversation->is_old_dissector = FALSE;
	conversation->dissector.new_d = dissector;
}

/*
 * Given source and destination addresses and ports for a packet,
 * search for a conversational dissector.
 * If found, call it and return TRUE, otherwise return FALSE.
 *
 * Will search for a exact match (src & dst), then search for wild
 * card matches: try to match any port on the destination address first,
 * then try to match any address on the port, then try to match any 
 * address and any port. 
 */
gboolean
try_conversation_dissector(address *src, address *dst, port_type ptype,
    guint32 src_port, guint32 dst_port, tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree)
{
	conversation_t *conversation;
	const guint8 *pd;
	int offset;

	conversation = find_conversation(src, dst, ptype, src_port, dst_port, 0);

	if (conversation == NULL)
		conversation = find_conversation(src, dst, ptype, src_port, dst_port, NO_DST_ADDR);

	if (conversation == NULL)
		conversation = find_conversation(src, dst, ptype, src_port, dst_port, NO_DST_PORT);

	if (conversation == NULL)
		conversation = find_conversation(src, dst, ptype, src_port, dst_port,
		    NO_DST_PORT | NO_DST_ADDR);

	if (conversation != NULL) {
		if (conversation->is_old_dissector) {
			if (conversation->dissector.old_d == NULL)
				return FALSE;

			/*
			 * New dissector calling old dissector; use
			 * "tvb_compat()" to remap.
			 *
			 * "is_old_dissector" won't be set unless
			 * "dissector.old_d" is set.
			 */
			tvb_compat(tvb, &pd, &offset);
			(*conversation->dissector.old_d)(pd, offset, pinfo->fd,
			    tree);
		} else {
			if (conversation->dissector.new_d == NULL)
				return FALSE;
			(*conversation->dissector.new_d)(tvb, pinfo, tree);
		}
		return TRUE;
	}
	return FALSE;
}
