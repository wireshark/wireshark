/* conversation.c
 * Routines for building lists of packets that are part of a "conversation"
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdio.h>

#include <string.h>
#include <glib.h>
#include "packet.h"
#include "emem.h"
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

/*
 * Protocol-specific data attached to a conversation_t structure - protocol
 * index and opaque pointer.
 */
typedef struct _conv_proto_data {
	int	proto;
	void	*proto_data;
} conv_proto_data;

/*
 * Creates a new conversation with known endpoints based on a conversation
 * created with the CONVERSATION_TEMPLATE option while keeping the
 * conversation created with the CONVERSATION_TEMPLATE option so it can still
 * match future connections.
 *
 * Passing a pointer to a conversation whose options mask does not include
 * CONVERSATION_TEMPLATE or where the conversation's protocol type (ptype)
 * indicates a non-connnection oriented protocol will return the conversation
 * without changes.
 *
 * addr2 and port2 are used in the function if their respective conversation
 * options bits are set (NO_ADDR2 and NO_PORT2).
 */
static conversation_t *
conversation_create_from_template(conversation_t *conversation, const address *addr2, const guint32 port2)
{
   /*
    * Add a new conversation and keep the conversation template only if the
    * CONVERSATION_TEMPLATE bit is set for a connection oriented protocol.
    */
   if(conversation->options & CONVERSATION_TEMPLATE &&
      conversation->key_ptr->ptype != PT_UDP)
   {
      /*
       * Set up a new options mask where the conversation template bit and the
       * bits for absence of a second address and port pair have been removed.
       */
      conversation_t *new_conversation_from_template;
      guint options = conversation->options & ~(CONVERSATION_TEMPLATE | NO_ADDR2 | NO_PORT2);

      /*
       * Are both the NO_ADDR2 and NO_PORT2 wildcards set in the options mask?
       */
      if(conversation->options & NO_ADDR2 &&
         conversation->options & NO_PORT2)
      {
         /*
          * The conversation template was created without knowledge of both
          * the second address as well as the second port. Create a new
          * conversation with new 2nd address and 2nd port.
          */
         new_conversation_from_template =
            conversation_new(conversation->setup_frame,
                             &conversation->key_ptr->addr1, addr2,
                             conversation->key_ptr->ptype, conversation->key_ptr->port1,
                             port2, options);
      }
      else if(conversation->options & NO_PORT2)
      {
         /*
          * The conversation template was created without knowledge of port 2
          * only. Create a new conversation with new 2nd port.
          */
         new_conversation_from_template =
            conversation_new(conversation->setup_frame,
                             &conversation->key_ptr->addr1, &conversation->key_ptr->addr2,
                             conversation->key_ptr->ptype, conversation->key_ptr->port1,
                             port2, options);
      }
      else if(conversation->options & NO_ADDR2)
      {
         /*
          * The conversation template was created without knowledge of address
          * 2. Create a new conversation with new 2nd address.
          */
         new_conversation_from_template =
            conversation_new(conversation->setup_frame,
                             &conversation->key_ptr->addr1, addr2,
                             conversation->key_ptr->ptype, conversation->key_ptr->port1,
                             conversation->key_ptr->port2, options);
      }
      else
      {
         /*
          * The CONVERSATION_TEMPLATE bit was set, but no other bit that the
          * CONVERSATION_TEMPLATE bit controls is active. Just return the old
          * conversation.
          */
         return conversation;
      }

      /*
       * Set the protocol dissector used for the template conversation as
       * the handler of the new conversation as well.
       */
      new_conversation_from_template->dissector_handle = conversation->dissector_handle;

      return new_conversation_from_template;
   }
   else
   {
      return conversation;
   }
}

/*
 * Compute the hash value for two given address/port pairs if the match
 * is to be exact.
 */
static guint
conversation_hash_exact(gconstpointer v)
{
	const conversation_key *key = (const conversation_key *)v;
	guint hash_val;

	hash_val = 0;
	ADD_ADDRESS_TO_HASH(hash_val, &key->addr1);
	hash_val += key->port1;
	ADD_ADDRESS_TO_HASH(hash_val, &key->addr2);
	hash_val += key->port2;

	return hash_val;
}

/*
 * Compare two conversation keys for an exact match.
 */
static gint
conversation_match_exact(gconstpointer v, gconstpointer w)
{
	const conversation_key *v1 = (const conversation_key *)v;
	const conversation_key *v2 = (const conversation_key *)w;

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
	const conversation_key *key = (const conversation_key *)v;
	guint hash_val;

	hash_val = 0;
	ADD_ADDRESS_TO_HASH(hash_val, &key->addr1);
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
	const conversation_key *v1 = (const conversation_key *)v;
	const conversation_key *v2 = (const conversation_key *)w;

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
	const conversation_key *key = (const conversation_key *)v;
	guint hash_val;

	hash_val = 0;
	ADD_ADDRESS_TO_HASH(hash_val, &key->addr1);
	hash_val += key->port1;
	ADD_ADDRESS_TO_HASH(hash_val, &key->addr2);

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
	const conversation_key *v1 = (const conversation_key *)v;
	const conversation_key *v2 = (const conversation_key *)w;

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
	const conversation_key *key = (const conversation_key *)v;
	guint hash_val;

	hash_val = 0;
	ADD_ADDRESS_TO_HASH(hash_val, &key->addr1);
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
	const conversation_key *v1 = (const conversation_key *)v;
	const conversation_key *v2 = (const conversation_key *)w;

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
 * Free the proto_data.  The conversation itself is se_allocated.
 */
static void
free_data_list(gpointer key _U_, gpointer value, gpointer user_data _U_)
{
	conversation_t *conv = (conversation_t *)value;

	/* TODO: se_slist? */
	g_slist_free(conv->data_list);

	/* Not really necessary, but... */
	conv->data_list = NULL;

}

/*
 * Destroy all existing conversations
 */
void
conversation_cleanup(void)
{
	/*  Clean up the hash tables, but only after freeing any proto_data
	 *  that may be hanging off the conversations.
	 *  The conversation keys are se_ allocated so we don't have to clean them up.
	 */
	conversation_keys = NULL;
	if (conversation_hashtable_exact != NULL) {
		g_hash_table_foreach(conversation_hashtable_exact, free_data_list, NULL);
		g_hash_table_destroy(conversation_hashtable_exact);
	}
	if (conversation_hashtable_no_addr2 != NULL) {
		g_hash_table_foreach(conversation_hashtable_no_addr2, free_data_list, NULL);
		g_hash_table_destroy(conversation_hashtable_no_addr2);
	}
	if (conversation_hashtable_no_port2 != NULL) {
		g_hash_table_foreach(conversation_hashtable_no_port2, free_data_list, NULL);
		g_hash_table_destroy(conversation_hashtable_no_port2);
	}
	if (conversation_hashtable_no_addr2_or_port2 != NULL) {
		g_hash_table_foreach(conversation_hashtable_no_addr2_or_port2, free_data_list, NULL);
		g_hash_table_destroy(conversation_hashtable_no_addr2_or_port2);
	}

	conversation_hashtable_exact = NULL;
	conversation_hashtable_no_addr2 = NULL;
	conversation_hashtable_no_port2 = NULL;
	conversation_hashtable_no_addr2_or_port2 = NULL;
}

/*
 * Initialize some variables every time a file is loaded or re-loaded.
 * Create a new hash table for the conversations in the new file.
 */
void
conversation_init(void)
{
	/*
	 * Free up any space allocated for conversation protocol data
	 * areas.
	 *
	 * We can free the space, as the structures it contains are
	 * pointed to by conversation data structures that were freed
	 * above.
	 */
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

	/*
	 * Start the conversation indices over at 0.
	 */
	new_index = 0;
}

/*
 * Does the right thing when inserting into one of the conversation hash tables,
 * taking into account ordering and hash chains and all that good stuff.
 *
 * Mostly adapted from the old conversation_new().
 */
void
conversation_insert_into_hashtable(GHashTable *hashtable, conversation_t *conv)
{
	conversation_t *chain_head, *chain_tail, *cur, *prev;

	chain_head = (conversation_t *)g_hash_table_lookup(hashtable, conv->key_ptr);

	if (NULL==chain_head) {
		/* New entry */
		conv->next = NULL;
		conv->last = conv;
		g_hash_table_insert(hashtable, conv->key_ptr, conv);
	}
	else {
		/* There's an existing chain for this key */

		chain_tail = chain_head->last;

		if(conv->setup_frame >= chain_tail->setup_frame) {
			/* This convo belongs at the end of the chain */
			conv->next = NULL;
			conv->last = NULL;
			chain_tail->next = conv;
			chain_head->last = conv;
		}
		else {
			/* Loop through the chain to find the right spot */
			cur = chain_head;
			prev = NULL;

			for (; (conv->setup_frame > cur->setup_frame) && cur->next; prev=cur, cur=cur->next)
				;

			if (NULL==prev) {
				/* Changing the head of the chain */
				conv->next = chain_head;
				conv->last = chain_tail;
				chain_head->last = NULL;
				g_hash_table_insert(hashtable, conv->key_ptr, conv);
			}
			else {
				/* Inserting into the middle of the chain */
				conv->next = cur;
				conv->last = NULL;
				prev->next = conv;
			}
		}
	}
}

/*
 * Does the right thing when removing from one of the conversation hash tables,
 * taking into account ordering and hash chains and all that good stuff.
 */
void
conversation_remove_from_hashtable(GHashTable *hashtable, conversation_t *conv)
{
	conversation_t *chain_head, *cur, *prev;

	chain_head = (conversation_t *)g_hash_table_lookup(hashtable, conv->key_ptr);

	if (conv == chain_head) {
		/* We are currently the front of the chain */
		if (NULL == conv->next) {
			/* We are the only conversation in the chain */
			g_hash_table_remove(hashtable, conv->key_ptr);
		}
		else {
			/* Update the head of the chain */
			chain_head = conv->next;
			chain_head->last = conv->last;

			if (conv->latest_found == conv)
				chain_head->latest_found = NULL;
			else
				chain_head->latest_found = conv->latest_found;

			g_hash_table_insert(hashtable, chain_head->key_ptr, chain_head);
		}
	}
	else {
		/* We are not the front of the chain. Loop through to find us.
		 * Start loop at chain_head->next rather than chain_head because
		 * we already know we're not at the head. */
		cur = chain_head->next;
		prev = chain_head;

		for (; (cur != conv) && cur->next; prev=cur, cur=cur->next)
			;

		if (cur != conv) {
			/* XXX: Conversation not found. Wrong hashtable? */
			return;
		}

		prev->next = conv->next;

		if (NULL == conv->next) {
			/* We're at the very end of the list. */
			chain_head->last = prev;
		}

		if (chain_head->latest_found == conv)
			chain_head->latest_found = prev;
	}
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
conversation_new(const guint32 setup_frame, const address *addr1, const address *addr2, const port_type ptype,
    const guint32 port1, const guint32 port2, const guint options)
{
/*
	DISSECTOR_ASSERT(!(options | CONVERSATION_TEMPLATE) || ((options | (NO_ADDR2 | NO_PORT2 | NO_PORT2_FORCE))) &&
				"A conversation template may not be constructed without wildcard options");
*/
	GHashTable* hashtable;
	conversation_t *conversation=NULL;
	conversation_key *new_key;

	if (options & NO_ADDR2) {
		if (options & (NO_PORT2|NO_PORT2_FORCE)) {
			hashtable = conversation_hashtable_no_addr2_or_port2;
		} else {
			hashtable = conversation_hashtable_no_addr2;
		}
	} else {
		if (options & (NO_PORT2|NO_PORT2_FORCE)) {
			hashtable = conversation_hashtable_no_port2;
		} else {
			hashtable = conversation_hashtable_exact;
		}
	}

	new_key = se_alloc(sizeof(struct conversation_key));
	new_key->next = conversation_keys;
	conversation_keys = new_key;
	SE_COPY_ADDRESS(&new_key->addr1, addr1);
	SE_COPY_ADDRESS(&new_key->addr2, addr2);
	new_key->ptype = ptype;
	new_key->port1 = port1;
	new_key->port2 = port2;

	conversation = se_new(conversation_t); 
	memset(conversation, 0, sizeof(conversation_t));

	conversation->index = new_index;
	conversation->setup_frame = setup_frame;
	conversation->data_list = NULL;

	/* clear dissector handle */
	conversation->dissector_handle = NULL;

	/* set the options and key pointer */
	conversation->options = options;
	conversation->key_ptr = new_key;

	new_index++;

	conversation_insert_into_hashtable(hashtable, conversation);

	return conversation;
}

/*
 * Set the port 2 value in a key.  Remove the original from table,
 * update the options and port values, insert the updated key.
 */
void
conversation_set_port2(conversation_t *conv, const guint32 port)
{
   DISSECTOR_ASSERT_HINT(!(conv->options & CONVERSATION_TEMPLATE),
            "Use the conversation_create_from_template function when the CONVERSATION_TEMPLATE bit is set in the options mask");

	/*
	 * If the port 2 value is not wildcarded, don't set it.
	 */
	if ((!(conv->options & NO_PORT2)) || (conv->options & NO_PORT2_FORCE))
		return;

	if (conv->options & NO_ADDR2) {
		conversation_remove_from_hashtable(conversation_hashtable_no_addr2_or_port2, conv);
	} else {
		conversation_remove_from_hashtable(conversation_hashtable_no_port2, conv);
	}
	conv->options &= ~NO_PORT2;
	conv->key_ptr->port2  = port;
	if (conv->options & NO_ADDR2) {
		conversation_insert_into_hashtable(conversation_hashtable_no_addr2, conv);
	} else {
		conversation_insert_into_hashtable(conversation_hashtable_exact, conv);
	}
}

/*
 * Set the address 2 value in a key.  Remove the original from
 * table, update the options and port values, insert the updated key.
 */
void
conversation_set_addr2(conversation_t *conv, const address *addr)
{
   DISSECTOR_ASSERT_HINT(!(conv->options & CONVERSATION_TEMPLATE),
            "Use the conversation_create_from_template function when the CONVERSATION_TEMPLATE bit is set in the options mask");

	/*
	 * If the address 2 value is not wildcarded, don't set it.
	 */
	if (!(conv->options & NO_ADDR2))
		return;

	if (conv->options & NO_PORT2) {
		conversation_remove_from_hashtable(conversation_hashtable_no_addr2_or_port2, conv);
	} else {
		conversation_remove_from_hashtable(conversation_hashtable_no_port2, conv);
	}
	conv->options &= ~NO_ADDR2;
	SE_COPY_ADDRESS(&conv->key_ptr->addr2, addr);
	if (conv->options & NO_PORT2) {
		conversation_insert_into_hashtable(conversation_hashtable_no_port2, conv);
	} else {
		conversation_insert_into_hashtable(conversation_hashtable_exact, conv);
	}
}

/*
 * Search a particular hash table for a conversation with the specified
 * {addr1, port1, addr2, port2} and set up before frame_num.
 */
static conversation_t *
conversation_lookup_hashtable(GHashTable *hashtable, const guint32 frame_num, const address *addr1, const address *addr2,
    const port_type ptype, const guint32 port1, const guint32 port2)
{
	conversation_t* convo=NULL;
	conversation_t* match=NULL;
	conversation_t* chain_head=NULL;
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

	chain_head = g_hash_table_lookup(hashtable, &key);

	if (chain_head && (chain_head->setup_frame <= frame_num)) {
		match = chain_head;

		if((chain_head->last)&&(chain_head->last->setup_frame<=frame_num))
			return chain_head->last;

		if((chain_head->latest_found)&&(chain_head->latest_found->setup_frame<=frame_num))
			match = chain_head->latest_found;

		for (convo = match; convo && convo->setup_frame <= frame_num; convo = convo->next) {
			if (convo->setup_frame > match->setup_frame) {
				match = convo;
			}
		}
	}

    if (match)
    	chain_head->latest_found = match;

	return match;
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
find_conversation(const guint32 frame_num, const address *addr_a, const address *addr_b, const port_type ptype,
    const guint32 port_a, const guint32 port_b, const guint options)
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
         frame_num, addr_a, addr_b, ptype,
         port_a, port_b);
      if ((conversation == NULL) && (addr_a->type == AT_FC)) {
         /* In Fibre channel, OXID & RXID are never swapped as
          * TCP/UDP ports are in TCP/IP.
          */
         conversation =
            conversation_lookup_hashtable(conversation_hashtable_exact,
            frame_num, addr_b, addr_a, ptype,
            port_a, port_b);
      }
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
         frame_num, addr_a, addr_b, ptype, port_a, port_b);
      if ((conversation == NULL) && (addr_a->type == AT_FC)) {
         /* In Fibre channel, OXID & RXID are never swapped as
          * TCP/UDP ports are in TCP/IP.
          */
         conversation =
            conversation_lookup_hashtable(conversation_hashtable_no_addr2,
            frame_num, addr_b, addr_a, ptype,
            port_a, port_b);
      }
      if (conversation != NULL) {
         /*
          * If search address B isn't wildcarded, and this is for a
          * connection-oriented protocol, set the second address for this
          * conversation to address B, as that's the address that matched the
          * wildcarded second address for this conversation.
          *
          * (This assumes that, for all connection oriented protocols, the
          * endpoints of a connection have only one address each, i.e. you
          * don't get packets in a given direction coming from more than one
          * address, unless the CONVERSATION_TEMPLATE option is set.)
          */
         if (!(conversation->options & NO_ADDR_B) && ptype != PT_UDP)
         {
            if(!(conversation->options & CONVERSATION_TEMPLATE))
            {
               conversation_set_addr2(conversation, addr_b);
            }
            else
            {
               conversation =
                  conversation_create_from_template(conversation, addr_b, 0);
            }
         }
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
            frame_num, addr_b, addr_a, ptype, port_b, port_a);
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
               if(!(conversation->options & CONVERSATION_TEMPLATE))
               {
                  conversation_set_addr2(conversation, addr_a);
               }
               else
               {
                  conversation =
                     conversation_create_from_template(conversation, addr_a, 0);
               }
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
         frame_num, addr_a, addr_b, ptype, port_a, port_b);
      if ((conversation == NULL) && (addr_a->type == AT_FC)) {
         /* In Fibre channel, OXID & RXID are never swapped as
          * TCP/UDP ports are in TCP/IP
          */
         conversation =
            conversation_lookup_hashtable(conversation_hashtable_no_port2,
            frame_num, addr_b, addr_a, ptype, port_a, port_b);
      }
      if (conversation != NULL) {
         /*
          * If search port B isn't wildcarded, and this is for a connection-
          * oriented protocol, set the second port for this conversation to
          * port B, as that's the port that matched the wildcarded second port
          * for this conversation.
          *
          * (This assumes that, for all connection oriented protocols, the
          * endpoints of a connection have only one port each, i.e. you don't
          * get packets in a given direction coming from more than one port,
          * unless the CONVERSATION_TEMPLATE option is set.)
          */
         if (!(conversation->options & NO_PORT_B) && ptype != PT_UDP)
         {
            if(!(conversation->options & CONVERSATION_TEMPLATE))
            {
               conversation_set_port2(conversation, port_b);
            }
            else
            {
               conversation =
                  conversation_create_from_template(conversation, 0, port_b);
            }
         }
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
            frame_num, addr_b, addr_a, ptype, port_b, port_a);
         if (conversation != NULL) {
            /*
             * If this is for a connection-oriented
             * protocol, set the second port for
             * this conversation to port A, as
             * that's the address that matched the
             * wildcarded second address for this
             * conversation.
             */
            if (ptype != PT_UDP)
            {
               if(!(conversation->options & CONVERSATION_TEMPLATE))
               {
                  conversation_set_port2(conversation, port_a);
               }
               else
               {
                  conversation =
                     conversation_create_from_template(conversation, 0, port_a);
               }
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
    * and port A as the first address and port.
    * (Neither "addr_b" nor "port_b" take part in this lookup.)
    */
   conversation =
      conversation_lookup_hashtable(conversation_hashtable_no_addr2_or_port2,
      frame_num, addr_a, addr_b, ptype, port_a, port_b);
   if (conversation != NULL) {
      /*
       * If this is for a connection-oriented protocol:
       *
       * if search address B isn't wildcarded, set the
       * second address for this conversation to address
       * B, as that's the address that matched the
       * wildcarded second address for this conversation;
       *
       * if search port B isn't wildcarded, set the
       * second port for this conversation to port B,
       * as that's the port that matched the wildcarded
       * second port for this conversation.
       */
      if (ptype != PT_UDP)
      {
         if(!(conversation->options & CONVERSATION_TEMPLATE))
         {
            if (!(conversation->options & NO_ADDR_B))
               conversation_set_addr2(conversation, addr_b);
            if (!(conversation->options & NO_PORT_B))
               conversation_set_port2(conversation, port_b);
         }
         else
         {
            conversation =
               conversation_create_from_template(conversation, addr_b, port_b);
         }
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
   if (addr_a->type == AT_FC)
      conversation =
      conversation_lookup_hashtable(conversation_hashtable_no_addr2_or_port2,
      frame_num, addr_b, addr_a, ptype, port_a, port_b);
   else
      conversation =
      conversation_lookup_hashtable(conversation_hashtable_no_addr2_or_port2,
      frame_num, addr_b, addr_a, ptype, port_b, port_a);
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
      if (ptype != PT_UDP)
      {
         if(!(conversation->options & CONVERSATION_TEMPLATE))
         {
            conversation_set_addr2(conversation, addr_a);
            conversation_set_port2(conversation, port_a);
         }
         else
         {
            conversation = conversation_create_from_template(conversation, addr_a, port_a);
         }
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
	const conv_proto_data *ap = (const conv_proto_data *)a;
	const conv_proto_data *bp = (const conv_proto_data *)b;

	if (ap->proto > bp->proto)
		return 1;
	else if (ap->proto == bp->proto)
		return 0;
	else
		return -1;
}

void
conversation_add_proto_data(conversation_t *conv, const int proto, void *proto_data)
{
	conv_proto_data *p1 = se_alloc(sizeof(conv_proto_data));

	p1->proto = proto;
	p1->proto_data = proto_data;

	/* Add it to the list of items for this conversation. */

	conv->data_list = g_slist_insert_sorted(conv->data_list, (gpointer *)p1,
	    p_compare);
}

void *
conversation_get_proto_data(const conversation_t *conv, const int proto)
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
conversation_delete_proto_data(conversation_t *conv, const int proto)
{
	conv_proto_data temp;
	GSList *item;

	temp.proto = proto;
	temp.proto_data = NULL;

	item = g_slist_find_custom(conv->data_list, (gpointer *)&temp,
	    p_compare);

	while(item){
		conv->data_list = g_slist_remove(conv->data_list, item->data);
		item=item->next;
	}
}

void
conversation_set_dissector(conversation_t *conversation, const dissector_handle_t handle)
{
	conversation->dissector_handle = handle;
}

/*
 * Given two address/port pairs for a packet, search for a matching
 * conversation and, if found and it has a conversation dissector,
 * call that dissector and return TRUE, otherwise return FALSE.
 *
 * This helper uses call_dissector_only which will NOT call the default
 * "data" dissector if the packet was rejected.
 * Our caller is responsible to call the data dissector explicitely in case
 * this function returns FALSE.
 */
gboolean
try_conversation_dissector(const address *addr_a, const address *addr_b, const port_type ptype,
    const guint32 port_a, const guint32 port_b, tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree)
{
	conversation_t *conversation;

	conversation = find_conversation(pinfo->fd->num, addr_a, addr_b, ptype, port_a,
	    port_b, 0);

	if (conversation != NULL) {
		int ret;
		if (conversation->dissector_handle == NULL)
			return FALSE;
		ret=call_dissector_only(conversation->dissector_handle, tvb, pinfo,
		    tree, NULL);
		if(!ret) {
			/* this packet was rejected by the dissector
			 * so return FALSE in case our caller wants
			 * to do some cleaning up.
			 */
			return FALSE;
		}
		return TRUE;
	}
	return FALSE;
}

/*  A helper function that calls find_conversation() and, if a conversation is
 *  not found, calls conversation_new().
 *  The frame number and addresses are taken from pinfo.
 *  No options are used, though we could extend this API to include an options
 *  parameter.
 */
conversation_t *
find_or_create_conversation(packet_info *pinfo)
{
	conversation_t *conv=NULL;

	/* Have we seen this conversation before? */
	if((conv = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
				     pinfo->ptype, pinfo->srcport,
				     pinfo->destport, 0)) == NULL) {
		/* No, this is a new conversation. */
		conv = conversation_new(pinfo->fd->num, &pinfo->src,
					&pinfo->dst, pinfo->ptype,
					pinfo->srcport, pinfo->destport, 0);
	}

	return conv;
}
