/* conversation.c
 * Routines for building lists of packets that are part of a "conversation"
 *
 * $Id: conversation.c,v 1.14 2001/10/31 05:59:19 guy Exp $
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
 * Hash table for conversations with one wildcard address.
 */
static GHashTable *conversation_hashtable_no_addr2 = NULL;

/*
 * Hash table for conversations with one wildcard port.
 */
static GHashTable *conversation_hashtable_no_port2 = NULL;

/*
 * Hash table for conversations with one wildcard address and port.
 */
static GHashTable *conversation_hashtable_no_addr2_or_port2 = NULL;

static GMemChunk *conversation_key_chunk = NULL;
static GMemChunk *conversation_chunk = NULL;

#ifdef __NOT_USED__ 
typedef struct conversation_key {
	struct conversation_key *next;
	address	addr1;
	address	addr2;
	port_type ptype;
	guint32	port1;
	guint32	port2;
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
 * Protocol-specific data attached to a conversation_t structure - protocol
 * index and opaque pointer.
 */
typedef struct _conv_proto_data {
	int	proto;
	void	*proto_data;
} conv_proto_data;

static GMemChunk *conv_proto_data_area = NULL;

/*
 * Compute the hash value for two given address/port pairs if the match
 * is to be exact.
 */
static guint 
conversation_hash_exact(gconstpointer v)
{
	conversation_key *key = (conversation_key *)v;
	guint hash_val;
	int i;

	hash_val = 0;
	for (i = 0; i < key->addr1.len; i++)
		hash_val += key->addr1.data[i];

	hash_val += key->port1;

	for (i = 0; i < key->addr2.len; i++)
		hash_val += key->addr2.data[i];

	hash_val += key->port2;

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
	 * Are the first and second port 1 values the same, the first and
	 * second port 2 values the same, the first and second address
	 * 1 values the same, and the first and second address 2 values
	 * the same?
	 */
	if (v1->port1 == v2->port1 &&
	    v1->port2 == v2->port2 &&
	    ADDRESSES_EQUAL(&v1->addr1, &v2->addr1) &&
	    ADDRESSES_EQUAL(&v1->addr2, &v2->addr2)) {
		/*
		 * Yes.  It's the same conversation, and the two
		 * address/port pairs are going in the same direction.
		 */
		return 1;
	}

	/*
	 * Is the first port 2 the same as the second port 1, the first
	 * port 1 the same as the second port 2, the first address 2
	 * the same as the second address 1, and the first address 1
	 * the same as the second address 2?
	 */
	if (v1->port2 == v2->port1 &&
	    v1->port1 == v2->port2 &&
	    ADDRESSES_EQUAL(&v1->addr2, &v2->addr1) &&
	    ADDRESSES_EQUAL(&v1->addr1, &v2->addr2)) {
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
 * Compute the hash value for two given address/port pairs if the match
 * has a wildcard address 2.
 */
static guint 
conversation_hash_no_addr2(gconstpointer v)
{
	conversation_key *key = (conversation_key *)v;
	guint hash_val;
	int i;

	hash_val = 0;
	for (i = 0; i < key->addr1.len; i++)
		hash_val += key->addr1.data[i];

	hash_val += key->port1;

	hash_val += key->port2;

	return hash_val;
}

/*
 * Compare two conversation keys, except for the address 2 value.
 * We don't check both directions of the conversation - the routine
 * doing the hash lookup has to do two searches, as the hash key
 * will be different for the two directions.
 */
static gint
conversation_match_no_addr2(gconstpointer v, gconstpointer w)
{
	conversation_key *v1 = (conversation_key *)v;
	conversation_key *v2 = (conversation_key *)w;

	if (v1->ptype != v2->ptype)
		return 0;	/* different types of port */

	/*
	 * Are the first and second port 1 values the same, the first and
	 * second port 2 valuess the same, and the first and second
	 * address 1 values the same?
	 */
	if (v1->port1 == v2->port1 &&
	    v1->port2 == v2->port2 &&
	    ADDRESSES_EQUAL(&v1->addr1, &v2->addr1)) {
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
 * Compute the hash value for two given address/port pairs if the match
 * has a wildcard port 2.
 */
static guint 
conversation_hash_no_port2(gconstpointer v)
{
	conversation_key *key = (conversation_key *)v;
	guint hash_val;
	int i;

	hash_val = 0;
	for (i = 0; i < key->addr1.len; i++)
		hash_val += key->addr1.data[i];

	hash_val += key->port1;

	for (i = 0; i < key->addr2.len; i++)
		hash_val += key->addr2.data[i];

	return hash_val;
}

/*
 * Compare two conversation keys, except for the port 2 value.
 * We don't check both directions of the conversation - the routine
 * doing the hash lookup has to do two searches, as the hash key
 * will be different for the two directions.
 */
static gint
conversation_match_no_port2(gconstpointer v, gconstpointer w)
{
	conversation_key *v1 = (conversation_key *)v;
	conversation_key *v2 = (conversation_key *)w;

	if (v1->ptype != v2->ptype)
		return 0;	/* different types of port */

	/*
	 * Are the first and second port 1 values the same, the first and
	 * second address 1 values the same, and the first and second
	 * address 2 values the same?
	 */
	if (v1->port1 == v2->port1 &&
	    ADDRESSES_EQUAL(&v1->addr1, &v2->addr1) &&
	    ADDRESSES_EQUAL(&v1->addr2, &v2->addr2)) {
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
 * Compute the hash value for two given address/port pairs if the match
 * has a wildcard address 2 and port 2.
 */
static guint 
conversation_hash_no_addr2_or_port2(gconstpointer v)
{
	conversation_key *key = (conversation_key *)v;
	guint hash_val;
	int i;

	hash_val = 0;
	for (i = 0; i < key->addr1.len; i++)
		hash_val += key->addr1.data[i];

	hash_val += key->port1;

	return hash_val;
}

/*
 * Compare the address 1 and port 1 in the two conversation keys.
 * We don't check both directions of the conversation - the routine
 * doing the hash lookup has to do two searches, as the hash key
 * will be different for the two directions.
 */
static gint
conversation_match_no_addr2_or_port2(gconstpointer v, gconstpointer w)
{
	conversation_key *v1 = (conversation_key *)v;
	conversation_key *v2 = (conversation_key *)w;

	if (v1->ptype != v2->ptype)
		return 0;	/* different types of port */

	/*
	 * Are the first and second port 1 values the same and the first
	 * and second address 1 values the same?
	 */
	if (v1->port1 == v2->port1 &&
	    ADDRESSES_EQUAL(&v1->addr1, &v2->addr1)) {
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
		g_free((gpointer)key->addr1.data);
		g_free((gpointer)key->addr2.data);
	}
	conversation_keys = NULL;
	if (conversation_hashtable_exact != NULL)
		g_hash_table_destroy(conversation_hashtable_exact);
	if (conversation_hashtable_no_addr2 != NULL)
		g_hash_table_destroy(conversation_hashtable_no_addr2);
	if (conversation_hashtable_no_port2 != NULL)
		g_hash_table_destroy(conversation_hashtable_no_port2);
	if (conversation_hashtable_no_addr2_or_port2 != NULL)
		g_hash_table_destroy(conversation_hashtable_no_addr2_or_port2);
	if (conversation_key_chunk != NULL)
		g_mem_chunk_destroy(conversation_key_chunk);
	if (conversation_chunk != NULL)
		g_mem_chunk_destroy(conversation_chunk);

	/*
	 * Free up any space allocated for conversation protocol data
	 * areas.
	 *
	 * We can free the space, as the structures it contains are
	 * pointed to by conversation data structures that were freed
	 * above.
	 */
	if (conv_proto_data_area != NULL)
		g_mem_chunk_destroy(conv_proto_data_area);

	conversation_hashtable_exact =
	    g_hash_table_new(conversation_hash_exact,
	      conversation_match_exact);
	conversation_hashtable_no_addr2 =
	    g_hash_table_new(conversation_hash_no_addr2,
	      conversation_match_no_addr2);
	conversation_hashtable_no_port2 =
	    g_hash_table_new(conversation_hash_no_port2,
	      conversation_match_no_port2);
	conversation_hashtable_no_addr2_or_port2 =
	    g_hash_table_new(conversation_hash_no_addr2_or_port2,
	      conversation_match_no_addr2_or_port2);
	conversation_key_chunk = g_mem_chunk_new("conversation_key_chunk",
	    sizeof(conversation_key),
	    conversation_init_count * sizeof(struct conversation_key),
	    G_ALLOC_AND_FREE);
	conversation_chunk = g_mem_chunk_new("conversation_chunk",
	    sizeof(conversation_t),
	    conversation_init_count * sizeof(conversation_t),
	    G_ALLOC_AND_FREE);

	/*
	 * Allocate a new area for conversation protocol data items.
	 */
	conv_proto_data_area = g_mem_chunk_new("conv_proto_data_area",
	    sizeof(conv_proto_data), 20 * sizeof(conv_proto_data), /* FIXME*/
	    G_ALLOC_ONLY);

	/*
	 * Start the conversation indices over at 0.
	 */
	new_index = 0;
}

/*
 * Given two address/port pairs for a packet, create a new conversation
 * to contain packets between those address/port pairs.
 *
 * The options field is used to specify whether the address 2 value
 * and/or port 2 value are not given and any value is acceptable
 * when searching for this conversation.
 */
conversation_t *
conversation_new(address *addr1, address *addr2, port_type ptype,
    guint32 port1, guint32 port2, guint options)
{
	conversation_t *conversation;
	conversation_key *new_key;

	new_key = g_mem_chunk_alloc(conversation_key_chunk);
	new_key->next = conversation_keys;
	conversation_keys = new_key;
	COPY_ADDRESS(&new_key->addr1, addr1);
	COPY_ADDRESS(&new_key->addr2, addr2);
	new_key->ptype = ptype;
	new_key->port1 = port1;
	new_key->port2 = port2;

	conversation = g_mem_chunk_alloc(conversation_chunk);
	conversation->index = new_index;
	conversation->data_list = NULL;

/* clear dissector pointer */
	conversation->dissector = NULL;

/* set the options and key pointer */
	conversation->options = options;
	conversation->key_ptr = new_key;

	new_index++;

	if (options & NO_ADDR2) {
		if (options & NO_PORT2) {
			g_hash_table_insert(conversation_hashtable_no_addr2_or_port2,
			    new_key, conversation);
		} else {
			g_hash_table_insert(conversation_hashtable_no_addr2,
			    new_key, conversation);
		}
	} else {
		if (options & NO_PORT2) {
			g_hash_table_insert(conversation_hashtable_no_port2,
			    new_key, conversation);
		} else {
			g_hash_table_insert(conversation_hashtable_exact,
			    new_key, conversation);
		}
	}
	return conversation;
}

/*
 * Set the port 2 value in a key.  Remove the original from table,
 * update the options and port values, insert the updated key.
 */
void
conversation_set_port2(conversation_t *conv, guint32 port)
{
	/*
	 * If the port 2 value is wildcarded, don't set it.
	 */
	if (!(conv->options & NO_PORT2))
		return;

	if (conv->options & NO_ADDR2) {
		g_hash_table_remove(conversation_hashtable_no_addr2_or_port2,
		    conv->key_ptr);
	} else {
		g_hash_table_remove(conversation_hashtable_no_port2,
		    conv->key_ptr);
	}
	conv->options &= ~NO_PORT2;
	conv->key_ptr->port2  = port;
	if (conv->options & NO_ADDR2) {
		g_hash_table_insert(conversation_hashtable_no_addr2,
		    conv->key_ptr, conv);
	} else {
		g_hash_table_insert(conversation_hashtable_exact,
		    conv->key_ptr, conv);
	}
} 

/*
 * Set the address 2 value in a key.  Remove the original from
 * table, update the options and port values, insert the updated key.
 */
void
conversation_set_addr2(conversation_t *conv, address *addr)
{
	/*
	 * If the address 2 value is wildcarded, don't set it.
	 */
	if (!(conv->options & NO_ADDR2))
		return;

	if (conv->options & NO_PORT2) {
		g_hash_table_remove(conversation_hashtable_no_addr2_or_port2,
		    conv->key_ptr);
	} else {
		g_hash_table_remove(conversation_hashtable_no_addr2,
		    conv->key_ptr);
	}
	conv->options &= ~NO_ADDR2;
	COPY_ADDRESS(&conv->key_ptr->addr2, addr);
	if (conv->options & NO_PORT2) {
		g_hash_table_insert(conversation_hashtable_no_port2,
		    conv->key_ptr, conv);
	} else {
		g_hash_table_insert(conversation_hashtable_exact,
		    conv->key_ptr, conv);
	}
}

/*
 * Search a particular hash table for a conversaton with the specified
 * addr1, port1, addr2, and port2.
 */
static conversation_t *
conversation_lookup_hashtable(GHashTable *hashtable, address *addr1, address *addr2,
    port_type ptype, guint32 port1, guint32 port2)
{
	conversation_key key;

	/*
	 * We don't make a copy of the address data, we just copy the
	 * pointer to it, as "key" disappears when we return.
	 */
	key.addr1 = *addr1;
	key.addr2 = *addr2;
	key.ptype = ptype;
	key.port1 = port1;
	key.port2 = port2;
	return g_hash_table_lookup(hashtable, &key);
}
 

/*
 * Given two address/port pairs for a packet, search for a conversation
 * containing packets between those address/port pairs.  Returns NULL if
 * not found.
 *
 * We try to find the most exact match that we can, and then proceed to
 * try wildcard matches on the "addr_b" and/or "port_b" argument if a more
 * exact match failed.
 *
 * Either or both of the "addr_b" and "port_b" arguments may be specified as
 * a wildcard by setting the NO_ADDR_B or NO_PORT_B flags in the "options"
 * argument.  We do only wildcard matches on addresses and ports specified
 * as wildcards.
 *
 * I.e.:
 *
 *	if neither "addr_b" nor "port_b" were specified as wildcards, we
 *	do an exact match (addr_a/port_a and addr_b/port_b) and, if that
 *	succeeds, we return a pointer to the matched conversation;
 *
 *	otherwise, if "port_b" wasn't specified as a wildcard, we try to
 *	match any address 2 with the specified port 2 (addr_a/port_a and
 *	{any}/addr_b) and, if that succeeds, we return a pointer to the
 *	matched conversation;
 *
 *	otherwise, if "addr_b" wasn't specified as a wildcard, we try to
 *	match any port 2 with the specified address 2 (addr_a/port_a and
 *	addr_b/{any}) and, if that succeeds, we return a pointer to the
 *	matched conversation;
 *
 *	otherwise, we try to match any address 2 and any port 2
 *	(addr_a/port_a and {any}/{any}) and, if that succeeds, we return
 *	a pointer to the matched conversation;
 *
 *	otherwise, we found no matching conversation, and return NULL.
 */
conversation_t *
find_conversation(address *addr_a, address *addr_b, port_type ptype,
    guint32 port_a, guint32 port_b, guint options)
{
	conversation_t *conversation;

	/*
	 * First try an exact match, if we have two addresses and ports.
	 */
	if (!(options & (NO_ADDR_B|NO_PORT_B))) {
		/*
		 * Neither search address B nor search port B are wildcarded,
		 * start out with an exact match.
		 * Exact matches check both directions.
		 */
		conversation =
		    conversation_lookup_hashtable(conversation_hashtable_exact,
		      addr_a, addr_b, ptype, port_a, port_b);
		if (conversation != NULL)
			return conversation;
	}

	/*
	 * Well, that didn't find anything.  Try matches that wildcard
	 * one of the addresses, if we have two ports.
	 */
	if (!(options & NO_PORT_B)) {
		/*
		 * Search port B isn't wildcarded.
		 *
		 * First try looking for a conversation with the specified
		 * address A and port A as the first address and port, and
		 * with any address and the specified port B as the second
		 * address and port.
		 * ("addr_b" doesn't take part in this lookup.)
		 */
		conversation =
		    conversation_lookup_hashtable(conversation_hashtable_no_addr2,
		        addr_a, addr_b, ptype, port_a, port_b);
		if (conversation != NULL) {
			/*
			 * If search address B isn't wildcarded, and this
			 * is for a connection-oriented protocol, set the
			 * second address for this conversation to address
			 * B, as that's the address that matched the
			 * wildcarded second address for this conversation.
			 *
			 * (XXX - this assumes that, for all connection-
			 * oriented protocols, the endpoints of a connection
			 * have only one address each, i.e. you don't get
			 * packets in a given direction coming from more than
			 * one address.) 
			 */
			if (!(options & NO_ADDR_B) && ptype != PT_UDP)
				conversation_set_addr2(conversation, addr_b);
			return conversation;
		}

		/*
		 * Well, that didn't find anything.
		 * If search address B was specified, try looking for a
		 * conversation with the specified address B and port B as
		 * the first address and port, and with any address and the
		 * specified port A as the second address and port (this
		 * packet may be going in the opposite direction from the
		 * first packet in the conversation).
		 * ("addr_a" doesn't take part in this lookup.)
		 */
		if (!(options & NO_ADDR_B)) {
			conversation =
			    conversation_lookup_hashtable(conversation_hashtable_no_addr2,
			    addr_b, addr_a, ptype, port_b, port_a);
			if (conversation != NULL) {
				/*
				 * If this is for a connection-oriented
				 * protocol, set the second address for
				 * this conversation to address A, as
				 * that's the address that matched the
				 * wildcarded second address for this
				 * conversation.
				 */
				if (ptype != PT_UDP) {
					conversation_set_addr2(conversation,
					    addr_a);
				}
				return conversation;
			}
		}
	}

	/*
	 * Well, that didn't find anything.  Try matches that wildcard
	 * one of the ports, if we have two addresses.
	 */
	if (!(options & NO_ADDR_B)) {
		/*
		 * Search address B isn't wildcarded.
		 *
		 * First try looking for a conversation with the specified
		 * address A and port A as the first address and port, and
		 * with the specified address B and any port as the second
		 * address and port.
		 * ("port_b" doesn't take part in this lookup.)
		 */
		conversation =
		    conversation_lookup_hashtable(conversation_hashtable_no_port2,
		      addr_a, addr_b, ptype, port_a, port_b);
		if (conversation != NULL) {
			/*
			 * If search port B isn't wildcarded, and this is
			 * for a connection-oriented protocol, set the
			 * second port for this conversation to port B,
			 * as that's the port that matched the wildcarded
			 * second port for this conversation.
			 *
			 * (XXX - this assumes that, for all connection-
			 * oriented protocols, the endpoints of a connection
			 * have only one port each, i.e. you don't get
			 * packets in a given direction coming from more than
			 * one port.)
			 */
			if (!(options & NO_PORT_B) && ptype != PT_UDP)
				conversation_set_port2(conversation, port_b);
			return conversation;
		}

		/*
		 * Well, that didn't find anything.
		 * If search port B was specified, try looking for a
		 * conversation with the specified address B and port B
		 * as the first address and port, and with the specified
		 * address A and any port as the second address and port
		 * (this packet may be going in the opposite direction
		 * from the first packet in the conversation).
		 * ("port_a" doesn't take part in this lookup.)
		 */
		if (!(options & NO_PORT_B)) {
			conversation =
			    conversation_lookup_hashtable(conversation_hashtable_no_port2,
			      addr_b, addr_a, ptype, port_b, port_a);
			if (conversation != NULL) {
				/*
				 * If this is for a connection-oriented
				 * protocol, set the second port for
				 * this conversation to port A, as
				 * that's the address that matched the
				 * wildcarded second address for this
				 * conversation.
				 */
				if (ptype != PT_UDP) {
					conversation_set_port2(conversation,
					    port_a);
				}
				return conversation;
			}
		}
	}

	/*
	 * Well, that didn't find anything.  Try matches that wildcard
	 * one address/port pair.
	 *
	 * First try looking for a conversation with the specified address A
	 * and port B as the first address and port.
	 * (Neither "addr_b" nor "port_b" take part in this lookup.)
	 */
	conversation =
	    conversation_lookup_hashtable(conversation_hashtable_no_addr2_or_port2,
	      addr_a, addr_b, ptype, port_a, port_b);
	if (conversation != NULL) {
		/*
		 * If this is for a connection-oriented protocol:
		 *
		 *	if search address B isn't wildcarded, set the
		 *	second address for this conversation to address
		 *	B, as that's the address that matched the
		 *	wildcarded second address for this conversation;
		 *
		 *	if search port B isn't wildcarded, set the
		 *	second port for this conversation to port B,
		 *	as that's the port that matched the wildcarded
		 *	second port for this conversation.
		 */
		if (ptype != PT_UDP) {
			if (!(options & NO_ADDR_B))
				conversation_set_addr2(conversation, addr_b);
			if (!(options & NO_PORT_B))
				conversation_set_port2(conversation, port_b);
		}
		return conversation;
	}

	/*
	 * Well, that didn't find anything.
	 * If search address and port B were specified, try looking for a
	 * conversation with the specified address B and port B as the
	 * first address and port, and with any second address and port
	 * (this packet may be going in the opposite direction from the
	 * first packet in the conversation).
	 * (Neither "addr_a" nor "port_a" take part in this lookup.)
	 */
	conversation =
	    conversation_lookup_hashtable(conversation_hashtable_no_addr2_or_port2,
	      addr_b, addr_a, ptype, port_b, port_a);
	if (conversation != NULL) {
		/*
		 * If this is for a connection-oriented protocol, set the
		 * second address for this conversation to address A, as
		 * that's the address that matched the wildcarded second
		 * address for this conversation, and set the second port
		 * for this conversation to port A, as that's the port
		 * that matched the wildcarded second port for this
		 * conversation.
		 */
		if (ptype != PT_UDP) {
			conversation_set_addr2(conversation, addr_a);
			conversation_set_port2(conversation, port_a);
		}
		return conversation;
	}

	/*
	 * We found no conversation.
	 */
	return NULL;
}

static gint
p_compare(gconstpointer a, gconstpointer b)
{
	if (((conv_proto_data *)a)->proto > ((conv_proto_data *)b)->proto)
		return 1;
	else if (((conv_proto_data *)a)->proto == ((conv_proto_data *)b)->proto)
		return 0;
	else
		return -1;
}

void
conversation_add_proto_data(conversation_t *conv, int proto, void *proto_data)
{
	conv_proto_data *p1 = g_mem_chunk_alloc(conv_proto_data_area);

	p1->proto = proto;
	p1->proto_data = proto_data;

	/* Add it to the list of items for this conversation. */

	conv->data_list = g_slist_insert_sorted(conv->data_list, (gpointer *)p1,
	    p_compare);
}

void *
conversation_get_proto_data(conversation_t *conv, int proto)
{
	conv_proto_data temp, *p1;
	GSList *item;

	temp.proto = proto;
	temp.proto_data = NULL;

	item = g_slist_find_custom(conv->data_list, (gpointer *)&temp,
	    p_compare);

	if (item != NULL) {
		p1 = (conv_proto_data *)item->data;
		return p1->proto_data;
	}

	return NULL;
}

void
conversation_delete_proto_data(conversation_t *conv, int proto)
{
	conv_proto_data temp;
	GSList *item;

	temp.proto = proto;
	temp.proto_data = NULL;

	item = g_slist_find_custom(conv->data_list, (gpointer *)&temp,
	    p_compare);

	if (item != NULL)
		conv->data_list = g_slist_remove(conv->data_list, item);
}

void
conversation_set_dissector(conversation_t *conversation,
    dissector_t dissector)
{
	conversation->dissector = dissector;
}

/*
 * Given two address/port pairs for a packet, search for a matching
 * conversation and, if found and it has a conversation dissector,
 * call that dissector and return TRUE, otherwise return FALSE.
 */
gboolean
try_conversation_dissector(address *addr_a, address *addr_b, port_type ptype,
    guint32 port_a, guint32 port_b, tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree)
{
	conversation_t *conversation;
	const guint8 *pd;
	int offset;

	conversation = find_conversation(addr_a, addr_b, ptype, port_a,
	    port_b, 0);
	
	if (conversation != NULL) {
		if (conversation->dissector == NULL)
			return FALSE;
		(*conversation->dissector)(tvb, pinfo, tree);
		return TRUE;
	}
	return FALSE;
}
