/* conversation.c
 * Routines for building lists of packets that are part of a "conversation"
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>
#include <glib.h>
#include "packet.h"
#include "to_str.h"
#include "conversation.h"

/* define DEBUG_CONVERSATION for pretty debug printing */
/* #define DEBUG_CONVERSATION */
#include "conversation_debug.h"

#ifdef DEBUG_CONVERSATION
int _debug_conversation_indent = 0;
#endif

struct endpoint {
	address addr1;
	address addr2;
	endpoint_type etype;
	guint32 port1;
	guint32 port2;
	guint options;
};

struct conversation_key {
	struct conversation_key *next;
	address	addr1;
	address	addr2;
	endpoint_type etype;
	guint32	port1;
	guint32	port2;
};

/*
 * Hash table for conversations with no wildcards.
 */
static wmem_map_t *conversation_hashtable_exact = NULL;

/*
 * Hash table for conversations with one wildcard address.
 */
static wmem_map_t *conversation_hashtable_no_addr2 = NULL;

/*
 * Hash table for conversations with one wildcard port.
 */
static wmem_map_t *conversation_hashtable_no_port2 = NULL;

/*
 * Hash table for conversations with one wildcard address and port.
 */
static wmem_map_t *conversation_hashtable_no_addr2_or_port2 = NULL;


static guint32 new_index;

/*
 * Placeholder for address-less conversations.
 */
static address null_address_ = ADDRESS_INIT_NONE;


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
	if (conversation->options & CONVERSATION_TEMPLATE &&
	    conversation->key_ptr->etype != ENDPOINT_UDP)
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
		if (conversation->options & NO_ADDR2 &&
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
						 conversation->key_ptr->etype, conversation->key_ptr->port1,
						 port2, options);
		}
		else if (conversation->options & NO_PORT2)
		{
			/*
			 * The conversation template was created without knowledge of port 2
			 * only. Create a new conversation with new 2nd port.
			 */
			new_conversation_from_template =
				conversation_new(conversation->setup_frame,
						 &conversation->key_ptr->addr1, &conversation->key_ptr->addr2,
						 conversation->key_ptr->etype, conversation->key_ptr->port1,
						 port2, options);
		}
		else if (conversation->options & NO_ADDR2)
		{
			/*
			 * The conversation template was created without knowledge of address
			 * 2. Create a new conversation with new 2nd address.
			 */
			new_conversation_from_template =
				conversation_new(conversation->setup_frame,
						 &conversation->key_ptr->addr1, addr2,
						 conversation->key_ptr->etype, conversation->key_ptr->port1,
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
		new_conversation_from_template->dissector_tree = conversation->dissector_tree;

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
/* http://eternallyconfuzzled.com/tuts/algorithms/jsw_tut_hashing.aspx#existing
 * One-at-a-Time hash
 */
guint
conversation_hash_exact(gconstpointer v)
{
	const conversation_key_t key = (const conversation_key_t)v;
	guint hash_val;
	address tmp_addr;

	hash_val = 0;
	tmp_addr.len  = 4;

	hash_val = add_address_to_hash(hash_val, &key->addr1);

	tmp_addr.data = &key->port1;
	hash_val = add_address_to_hash(hash_val, &tmp_addr);

	hash_val = add_address_to_hash(hash_val, &key->addr2);

	tmp_addr.data = &key->port2;
	hash_val = add_address_to_hash(hash_val, &tmp_addr);

	hash_val += ( hash_val << 3 );
	hash_val ^= ( hash_val >> 11 );
	hash_val += ( hash_val << 15 );

	return hash_val;
}

/*
 * Compare two conversation keys for an exact match.
 */
static gint
conversation_match_exact(gconstpointer v, gconstpointer w)
{
	const conversation_key_t v1 = (const conversation_key_t)v;
	const conversation_key_t v2 = (const conversation_key_t)w;

	if (v1->etype != v2->etype)
		return 0;	/* different types of port */

	/*
	 * Are the first and second port 1 values the same, the first and
	 * second port 2 values the same, the first and second address
	 * 1 values the same, and the first and second address 2 values
	 * the same?
	 */
	if (v1->port1 == v2->port1 &&
	    v1->port2 == v2->port2 &&
	    addresses_equal(&v1->addr1, &v2->addr1) &&
	    addresses_equal(&v1->addr2, &v2->addr2)) {
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
	    addresses_equal(&v1->addr2, &v2->addr1) &&
	    addresses_equal(&v1->addr1, &v2->addr2)) {
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
	const conversation_key_t key = (const conversation_key_t)v;
	guint hash_val;
	address tmp_addr;

	hash_val = 0;
	tmp_addr.len  = 4;

	hash_val = add_address_to_hash(hash_val, &key->addr1);

	tmp_addr.data = &key->port1;
	hash_val = add_address_to_hash(hash_val, &tmp_addr);

	tmp_addr.data = &key->port2;
	hash_val = add_address_to_hash(hash_val, &tmp_addr);

	hash_val += ( hash_val << 3 );
	hash_val ^= ( hash_val >> 11 );
	hash_val += ( hash_val << 15 );

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
	const conversation_key_t v1 = (const conversation_key_t)v;
	const conversation_key_t v2 = (const conversation_key_t)w;

	if (v1->etype != v2->etype)
		return 0;	/* different types of port */

	/*
	 * Are the first and second port 1 values the same, the first and
	 * second port 2 valuess the same, and the first and second
	 * address 1 values the same?
	 */
	if (v1->port1 == v2->port1 &&
	    v1->port2 == v2->port2 &&
	    addresses_equal(&v1->addr1, &v2->addr1)) {
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
	const conversation_key_t key = (const conversation_key_t)v;
	guint hash_val;
	address tmp_addr;

	hash_val = 0;
	tmp_addr.len  = 4;

	hash_val = add_address_to_hash(hash_val, &key->addr1);

	tmp_addr.data = &key->port1;
	hash_val = add_address_to_hash(hash_val, &tmp_addr);

	hash_val = add_address_to_hash(hash_val, &key->addr2);

	hash_val += ( hash_val << 3 );
	hash_val ^= ( hash_val >> 11 );
	hash_val += ( hash_val << 15 );

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
	const conversation_key_t v1 = (const conversation_key_t)v;
	const conversation_key_t v2 = (const conversation_key_t)w;

	if (v1->etype != v2->etype)
		return 0;	/* different types of port */

	/*
	 * Are the first and second port 1 values the same, the first and
	 * second address 1 values the same, and the first and second
	 * address 2 values the same?
	 */
	if (v1->port1 == v2->port1 &&
	    addresses_equal(&v1->addr1, &v2->addr1) &&
	    addresses_equal(&v1->addr2, &v2->addr2)) {
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
	const conversation_key_t key = (const conversation_key_t)v;
	guint hash_val;
	address tmp_addr;

	hash_val = 0;
	tmp_addr.len  = 4;

	hash_val = add_address_to_hash(hash_val, &key->addr1);

	tmp_addr.data = &key->port1;
	hash_val = add_address_to_hash(hash_val, &tmp_addr);

	hash_val += ( hash_val << 3 );
	hash_val ^= ( hash_val >> 11 );
	hash_val += ( hash_val << 15 );

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
	const conversation_key_t v1 = (const conversation_key_t)v;
	const conversation_key_t v2 = (const conversation_key_t)w;

	if (v1->etype != v2->etype)
		return 0;	/* different types of port */

	/*
	 * Are the first and second port 1 values the same and the first
	 * and second address 1 values the same?
	 */
	if (v1->port1 == v2->port1 &&
	    addresses_equal(&v1->addr1, &v2->addr1)) {
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

/**
 * Create a new hash tables for conversations.
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
	    wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), conversation_hash_exact,
	      conversation_match_exact);
	conversation_hashtable_no_addr2 =
	    wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), conversation_hash_no_addr2,
	      conversation_match_no_addr2);
	conversation_hashtable_no_port2 =
	    wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), conversation_hash_no_port2,
	      conversation_match_no_port2);
	conversation_hashtable_no_addr2_or_port2 =
	    wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), conversation_hash_no_addr2_or_port2,
	      conversation_match_no_addr2_or_port2);

}

/**
 * Initialize some variables every time a file is loaded or re-loaded.
 */
void conversation_epan_reset(void)
{
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
static void
conversation_insert_into_hashtable(wmem_map_t *hashtable, conversation_t *conv)
{
	conversation_t *chain_head, *chain_tail, *cur, *prev;

	chain_head = (conversation_t *)wmem_map_lookup(hashtable, conv->key_ptr);

	if (NULL==chain_head) {
		/* New entry */
		conv->next = NULL;
		conv->last = conv;
		wmem_map_insert(hashtable, conv->key_ptr, conv);
		DPRINT(("created a new conversation chain"));
	}
	else {
		/* There's an existing chain for this key */
		DPRINT(("there's an existing conversation chain"));

		chain_tail = chain_head->last;

		if (conv->setup_frame >= chain_tail->setup_frame) {
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
				wmem_map_insert(hashtable, conv->key_ptr, conv);
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
static void
conversation_remove_from_hashtable(wmem_map_t *hashtable, conversation_t *conv)
{
	conversation_t *chain_head, *cur, *prev;

	chain_head = (conversation_t *)wmem_map_lookup(hashtable, conv->key_ptr);

	if (conv == chain_head) {
		/* We are currently the front of the chain */
		if (NULL == conv->next) {
			/* We are the only conversation in the chain, no need to
			 * update next pointer, but do not call
			 * wmem_map_remove() either because the conv data
			 * will be re-inserted. */
			wmem_map_steal(hashtable, conv->key_ptr);
		}
		else {
			/* Update the head of the chain */
			chain_head = conv->next;
			chain_head->last = conv->last;

			if (conv->latest_found == conv)
				chain_head->latest_found = NULL;
			else
				chain_head->latest_found = conv->latest_found;

			wmem_map_insert(hashtable, chain_head->key_ptr, chain_head);
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
conversation_new(const guint32 setup_frame, const address *addr1, const address *addr2,
    const endpoint_type etype, const guint32 port1, const guint32 port2, const guint options)
{
/*
	DISSECTOR_ASSERT(!(options | CONVERSATION_TEMPLATE) || ((options | (NO_ADDR2 | NO_PORT2 | NO_PORT2_FORCE))) &&
				"A conversation template may not be constructed without wildcard options");
*/
	wmem_map_t* hashtable;
	conversation_t *conversation=NULL;
	conversation_key_t new_key;

#ifdef DEBUG_CONVERSATION
	gchar *addr1_str, *addr2_str;
	if (addr1 == NULL) {
		/*
		 * No address 1.
		 */
		if (options & NO_ADDR2) {
			/*
			 * Neither address 1 nor address 2.
			 */
			if (options & NO_PORT2) {
				/*
				 * Port 1 but not port 2.
				 */
				DPRINT(("creating conversation for frame #%u: ID %u (etype=%d)",
					    setup_frame, port1, etype));
			} else {
				/*
				 * Ports 1 and 2.
				 */
				DPRINT(("creating conversation for frame #%u: %u -> %u (etype=%d)",
					    setup_frame, port1, port2, etype));
			}
		} else {
			/*
			 * Address 2 but not address 1.
			 */
			addr2_str = address_to_str(NULL, addr2);
			if (options & NO_PORT2) {
				/*
				 * Port 1 but not port 2.
				 */
				DPRINT(("creating conversation for frame #%u: ID %u, address %s (etype=%d)",
					    setup_frame, port1, addr2_str, etype));
			} else {
				/*
				 * Ports 1 and 2.
				 */
				DPRINT(("creating conversation for frame #%u: %u -> %s:%u (etype=%d)",
					    setup_frame, port1, addr2_str, port2, etype));
			}
			wmem_free(NULL, addr2_str);
		}
	} else {
		/*
		 * Address 1.
		 */
		addr1_str = address_to_str(NULL, addr1);
		if (options & NO_ADDR2) {
			/*
			 * Address 1 but no address 2.
			 */
			if (options & NO_PORT2) {
				/*
				 * Port 1 but not port 2.
				 */
				DPRINT(("creating conversation for frame #%u: %s:%u (etype=%d)",
					    setup_frame, addr1_str, port1, etype));
			} else {
				/*
				 * Ports 1 and 2.
				 */
				DPRINT(("creating conversation for frame #%u: %s:%u -> %u (etype=%d)",
					    setup_frame, addr1_str, port1, port2, etype));
			}
		} else {
			/*
			 * Addresses 1 and 2.
			 */
			addr2_str = address_to_str(NULL, addr2);
			if (options & NO_PORT2) {
				/*
				 * Port 1 but not port 2.
				 */
				DPRINT(("creating conversation for frame #%u: %s:%u -> %s (etype=%d)",
					    setup_frame, addr1_str, port1, addr2_str, etype));
			} else {
				/*
				 * Ports 1 and 2.
				 */
				DPRINT(("creating conversation for frame #%u: %s:%u -> %s:%u (etype=%d)",
					    setup_frame, addr1_str, port1, addr2_str, port2, etype));
			}
			wmem_free(NULL, addr2_str);
		}
		wmem_free(NULL, addr1_str);
	}
#endif

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

	new_key = wmem_new(wmem_file_scope(), struct conversation_key);
	if (addr1 != NULL) {
		copy_address_wmem(wmem_file_scope(), &new_key->addr1, addr1);
	} else {
		clear_address(&new_key->addr1);
	}
	if (addr2 != NULL) {
		copy_address_wmem(wmem_file_scope(), &new_key->addr2, addr2);
	} else {
		clear_address(&new_key->addr2);
	}
	new_key->etype = etype;
	new_key->port1 = port1;
	new_key->port2 = port2;

	conversation = wmem_new0(wmem_file_scope(), conversation_t);

	conversation->conv_index = new_index;
	conversation->setup_frame = conversation->last_frame = setup_frame;
	conversation->data_list = NULL;

	conversation->dissector_tree = wmem_tree_new(wmem_file_scope());

	/* set the options and key pointer */
	conversation->options = options;
	conversation->key_ptr = new_key;

	new_index++;

	DINDENT();
	conversation_insert_into_hashtable(hashtable, conversation);
	DENDENT();

	return conversation;
}

conversation_t *conversation_new_by_id(const guint32 setup_frame, const endpoint_type etype, const guint32 id, const guint options)
{
	/* Force the lack of an address or port 2 */
	return conversation_new(setup_frame, NULL, NULL, etype, id, 0, options | NO_ADDR2 | NO_PORT2);
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

	DPRINT(("called for port=%d", port));

	/*
	 * If the port 2 value is not wildcarded, don't set it.
	 */
	if ((!(conv->options & NO_PORT2)) || (conv->options & NO_PORT2_FORCE))
		return;

	DINDENT();
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
	DENDENT();
}

/*
 * Set the address 2 value in a key.  Remove the original from
 * table, update the options and port values, insert the updated key.
 */
void
conversation_set_addr2(conversation_t *conv, const address *addr)
{
	char* addr_str;
	DISSECTOR_ASSERT_HINT(!(conv->options & CONVERSATION_TEMPLATE),
			"Use the conversation_create_from_template function when the CONVERSATION_TEMPLATE bit is set in the options mask");

	addr_str = address_to_str(NULL, addr);
	DPRINT(("called for addr=%s", addr_str));
	wmem_free(NULL, addr_str);

	/*
	 * If the address 2 value is not wildcarded, don't set it.
	 */
	if (!(conv->options & NO_ADDR2))
		return;

	DINDENT();
	if (conv->options & NO_PORT2) {
		conversation_remove_from_hashtable(conversation_hashtable_no_addr2_or_port2, conv);
	} else {
		conversation_remove_from_hashtable(conversation_hashtable_no_port2, conv);
	}
	conv->options &= ~NO_ADDR2;
	copy_address_wmem(wmem_file_scope(), &conv->key_ptr->addr2, addr);
	if (conv->options & NO_PORT2) {
		conversation_insert_into_hashtable(conversation_hashtable_no_port2, conv);
	} else {
		conversation_insert_into_hashtable(conversation_hashtable_exact, conv);
	}
	DENDENT();
}

/*
 * Search a particular hash table for a conversation with the specified
 * {addr1, port1, addr2, port2} and set up before frame_num.
 */
static conversation_t *
conversation_lookup_hashtable(wmem_map_t *hashtable, const guint32 frame_num, const address *addr1, const address *addr2,
    const endpoint_type etype, const guint32 port1, const guint32 port2)
{
	conversation_t* convo=NULL;
	conversation_t* match=NULL;
	conversation_t* chain_head=NULL;
	struct conversation_key key;

	/*
	 * We don't make a copy of the address data, we just copy the
	 * pointer to it, as "key" disappears when we return.
	 */
	if (addr1 != NULL) {
		key.addr1 = *addr1;
	} else {
		clear_address(&key.addr1);
	}
	if (addr2 != NULL) {
		key.addr2 = *addr2;
	} else {
		clear_address(&key.addr2);
	}
	key.etype = etype;
	key.port1 = port1;
	key.port2 = port2;

	chain_head = (conversation_t *)wmem_map_lookup(hashtable, &key);

	if (chain_head && (chain_head->setup_frame <= frame_num)) {
		match = chain_head;

		if ((chain_head->last)&&(chain_head->last->setup_frame<=frame_num))
			return chain_head->last;

		if ((chain_head->latest_found)&&(chain_head->latest_found->setup_frame<=frame_num))
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
 *	{any}/port_b) and, if that succeeds, we return a pointer to the
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
find_conversation(const guint32 frame_num, const address *addr_a, const address *addr_b, const endpoint_type etype,
    const guint32 port_a, const guint32 port_b, const guint options)
{
	conversation_t *conversation;

	DINSTR(gchar *addr_a_str = address_to_str(NULL, addr_a));
	DINSTR(gchar *addr_b_str = address_to_str(NULL, addr_b));
	/*
	 * First try an exact match, if we have two addresses and ports.
	 */
	if (!(options & (NO_ADDR_B|NO_PORT_B))) {
		/*
		 * Neither search address B nor search port B are wildcarded,
		 * start out with an exact match.
		 */
		DPRINT(("trying exact match: %s:%d -> %s:%d",
		    addr_a_str, port_a, addr_b_str, port_b));
		conversation =
		    conversation_lookup_hashtable(conversation_hashtable_exact,
			frame_num, addr_a, addr_b, etype,
			port_a, port_b);
		/* Didn't work, try the other direction */
		if (conversation == NULL) {
			DPRINT(("trying exact match: %s:%d -> %s:%d",
			    addr_b_str, port_b, addr_a_str, port_a));
			conversation =
			    conversation_lookup_hashtable(conversation_hashtable_exact,
				frame_num, addr_b, addr_a, etype,
				port_b, port_a);
		}
		if ((conversation == NULL) && (addr_a->type == AT_FC)) {
			/* In Fibre channel, OXID & RXID are never swapped as
			 * TCP/UDP ports are in TCP/IP.
			 */
			DPRINT(("trying exact match: %s:%d -> %s:%d",
			    addr_b_str, port_a, addr_a_str, port_b));
			conversation =
			    conversation_lookup_hashtable(conversation_hashtable_exact,
				frame_num, addr_b, addr_a, etype,
				port_a, port_b);
		}
		DPRINT(("exact match %sfound",conversation?"":"not "));
		if (conversation != NULL)
			goto end;
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
		DPRINT(("trying wildcarded match: %s:%d -> *:%d",
		    addr_a_str, port_a, port_b));
		conversation =
		    conversation_lookup_hashtable(conversation_hashtable_no_addr2,
			frame_num, addr_a, addr_b, etype, port_a, port_b);
		if ((conversation == NULL) && (addr_a->type == AT_FC)) {
			/* In Fibre channel, OXID & RXID are never swapped as
			 * TCP/UDP ports are in TCP/IP.
			 */
			DPRINT(("trying wildcarded match: %s:%d -> *:%d",
			    addr_b_str, port_a, port_b));
			conversation =
			    conversation_lookup_hashtable(conversation_hashtable_no_addr2,
				frame_num, addr_b, addr_a, etype,
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
			DPRINT(("wildcarded dest address match found"));
			if (!(conversation->options & NO_ADDR_B) && etype != ENDPOINT_UDP)
			{
				if (!(conversation->options & CONVERSATION_TEMPLATE))
				{
					conversation_set_addr2(conversation, addr_b);
				}
				else
				{
					conversation =
						conversation_create_from_template(conversation, addr_b, 0);
				}
			}
			goto end;
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
			DPRINT(("trying wildcarded match: %s:%d -> *:%d",
			    addr_b_str, port_b, port_a));
			conversation =
			    conversation_lookup_hashtable(conversation_hashtable_no_addr2,
				frame_num, addr_b, addr_a, etype, port_b, port_a);
			if (conversation != NULL) {
				/*
				 * If this is for a connection-oriented
				 * protocol, set the second address for
				 * this conversation to address A, as
				 * that's the address that matched the
				 * wildcarded second address for this
				 * conversation.
				 */
				DPRINT(("match found"));
				if (etype != ENDPOINT_UDP) {
					if (!(conversation->options & CONVERSATION_TEMPLATE))
					{
						conversation_set_addr2(conversation, addr_a);
					}
					else
					{
						conversation =
						    conversation_create_from_template(conversation, addr_a, 0);
					}
				}
				goto end;
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
		DPRINT(("trying wildcarded match: %s:%d -> %s:*",
		    addr_a_str, port_a, addr_b_str));
		conversation =
		    conversation_lookup_hashtable(conversation_hashtable_no_port2,
			frame_num, addr_a, addr_b, etype, port_a, port_b);
		if ((conversation == NULL) && (addr_a->type == AT_FC)) {
			/* In Fibre channel, OXID & RXID are never swapped as
			 * TCP/UDP ports are in TCP/IP
			 */
			DPRINT(("trying wildcarded match: %s:%d -> %s:*", addr_b_str, port_a, addr_a_str));
			conversation =
			    conversation_lookup_hashtable(conversation_hashtable_no_port2,
				frame_num, addr_b, addr_a, etype, port_a, port_b);
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
			DPRINT(("match found"));
			if (!(conversation->options & NO_PORT_B) && etype != ENDPOINT_UDP)
			{
				if (!(conversation->options & CONVERSATION_TEMPLATE))
				{
					conversation_set_port2(conversation, port_b);
				}
				else
				{
					conversation =
					    conversation_create_from_template(conversation, 0, port_b);
				}
			}
			goto end;
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
			DPRINT(("trying wildcarded match: %s:%d -> %s:*",
			    addr_b_str, port_b, addr_a_str));
			conversation =
			    conversation_lookup_hashtable(conversation_hashtable_no_port2,
				frame_num, addr_b, addr_a, etype, port_b, port_a);
			if (conversation != NULL) {
				/*
				 * If this is for a connection-oriented
				 * protocol, set the second port for
				 * this conversation to port A, as
				 * that's the address that matched the
				 * wildcarded second address for this
				 * conversation.
				 */
				DPRINT(("match found"));
				if (etype != ENDPOINT_UDP)
				{
					if (!(conversation->options & CONVERSATION_TEMPLATE))
					{
						conversation_set_port2(conversation, port_a);
					}
					else
					{
						conversation =
						    conversation_create_from_template(conversation, 0, port_a);
					}
				}
				goto end;
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
	DPRINT(("trying wildcarded match: %s:%d -> *:*", addr_a_str, port_a));
	conversation =
	    conversation_lookup_hashtable(conversation_hashtable_no_addr2_or_port2,
		frame_num, addr_a, addr_b, etype, port_a, port_b);
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
		DPRINT(("match found"));
		if (etype != ENDPOINT_UDP)
		{
			if (!(conversation->options & CONVERSATION_TEMPLATE))
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
		goto end;
	}
	/* for Infiniband, don't try to look in addresses of reverse
	 * direction, because it could be another different
	 * valid conversation than what is being searched using
	 * addr_a, port_a.
	 */
	if (etype != ENDPOINT_IBQP)
	{

		/*
		 * Well, that didn't find anything.
		 * If search address and port B were specified, try looking for a
		 * conversation with the specified address B and port B as the
		 * first address and port, and with any second address and port
		 * (this packet may be going in the opposite direction from the
		 * first packet in the conversation).
		 * (Neither "addr_a" nor "port_a" take part in this lookup.)
		 */
		if ((addr_a != NULL) && (addr_a->type == AT_FC)) {
			DPRINT(("trying wildcarded match: %s:%d -> *:*",
			    addr_b_str, port_a));
			conversation =
			    conversation_lookup_hashtable(conversation_hashtable_no_addr2_or_port2,
				frame_num, addr_b, addr_a, etype, port_a, port_b);
		} else {
			DPRINT(("trying wildcarded match: %s:%d -> *:*",
			    addr_b_str, port_b));
			conversation =
			    conversation_lookup_hashtable(conversation_hashtable_no_addr2_or_port2,
				frame_num, addr_b, addr_a, etype, port_b, port_a);
		}
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
			DPRINT(("match found"));
			if (etype != ENDPOINT_UDP)
			{
				if (!(conversation->options & CONVERSATION_TEMPLATE))
				{
					conversation_set_addr2(conversation, addr_a);
					conversation_set_port2(conversation, port_a);
				}
				else
				{
					conversation = conversation_create_from_template(conversation, addr_a, port_a);
				}
			}
			goto end;
		}
	}
	DPRINT(("no matches found"));

	/*
	 * We found no conversation.
	 */
	conversation = NULL;

end:
	DINSTR(wmem_free(NULL, addr_a_str));
	DINSTR(wmem_free(NULL, addr_b_str));
	return conversation;
}

conversation_t *find_conversation_by_id(const guint32 frame, const endpoint_type etype, const guint32 id, const guint options)
{
	/* Force the lack of a address or port B */
	return find_conversation(frame, &null_address_, &null_address_, etype, id, 0, options|NO_ADDR_B|NO_PORT_B);
}

void
conversation_add_proto_data(conversation_t *conv, const int proto, void *proto_data)
{
	/* Add it to the list of items for this conversation. */
	if (conv->data_list == NULL)
		conv->data_list = wmem_tree_new(wmem_file_scope());

	wmem_tree_insert32(conv->data_list, proto, proto_data);
}

void *
conversation_get_proto_data(const conversation_t *conv, const int proto)
{
	/* No tree created yet */
	if (conv->data_list == NULL)
		return NULL;

	return wmem_tree_lookup32(conv->data_list, proto);
}

void
conversation_delete_proto_data(conversation_t *conv, const int proto)
{
	if (conv->data_list != NULL)
		wmem_tree_remove32(conv->data_list, proto);
}

void
conversation_set_dissector_from_frame_number(conversation_t *conversation,
	const guint32 starting_frame_num, const dissector_handle_t handle)
{
	wmem_tree_insert32(conversation->dissector_tree, starting_frame_num, (void *)handle);
}

void
conversation_set_dissector(conversation_t *conversation, const dissector_handle_t handle)
{
	conversation_set_dissector_from_frame_number(conversation, 0, handle);
}

dissector_handle_t
conversation_get_dissector(conversation_t *conversation, const guint32 frame_num)
{
	return (dissector_handle_t)wmem_tree_lookup32_le(conversation->dissector_tree, frame_num);
}

static gboolean try_conversation_call_dissector_helper(conversation_t *conversation, gboolean* dissector_success,
					tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	int ret;
	dissector_handle_t handle = (dissector_handle_t)wmem_tree_lookup32_le(
					conversation->dissector_tree, pinfo->num);
	if (handle == NULL)
		return FALSE;

	ret = call_dissector_only(handle, tvb, pinfo, tree, data);

	/* Let the caller decide what to do with success or rejection */
	(*dissector_success) = (ret != 0);

	return TRUE;
}

/*
 * Given two address/port pairs for a packet, search for a matching
 * conversation and, if found and it has a conversation dissector,
 * call that dissector and return TRUE, otherwise return FALSE.
 *
 * This helper uses call_dissector_only which will NOT call the default
 * "data" dissector if the packet was rejected.
 * Our caller is responsible to call the data dissector explicitly in case
 * this function returns FALSE.
 */
gboolean
try_conversation_dissector(const address *addr_a, const address *addr_b, const endpoint_type etype,
    const guint32 port_a, const guint32 port_b, tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, void* data, const guint options)
{
	conversation_t *conversation;
	gboolean dissector_success;

	/* Try each mode based on option flags */

	conversation = find_conversation(pinfo->num, addr_a, addr_b, etype, port_a, port_b, 0);
	if (conversation != NULL) {
		if (try_conversation_call_dissector_helper(conversation, &dissector_success, tvb, pinfo, tree, data))
			return dissector_success;
	}

	if (options & NO_ADDR_B) {
		conversation = find_conversation(pinfo->num, addr_a, addr_b, etype, port_a, port_b, NO_ADDR_B);
		if (conversation != NULL) {
			if (try_conversation_call_dissector_helper(conversation, &dissector_success, tvb, pinfo, tree, data))
				return dissector_success;
		}
	}

	if (options & NO_PORT_B) {
		conversation = find_conversation(pinfo->num, addr_a, addr_b, etype, port_a, port_b, NO_PORT_B);
		if (conversation != NULL) {
			if (try_conversation_call_dissector_helper(conversation, &dissector_success, tvb, pinfo, tree, data))
				return dissector_success;
		}
	}

	if (options & (NO_ADDR_B|NO_PORT_B)) {
		conversation = find_conversation(pinfo->num, addr_a, addr_b, etype, port_a, port_b, NO_ADDR_B|NO_PORT_B);
		if (conversation != NULL) {
			if (try_conversation_call_dissector_helper(conversation, &dissector_success, tvb, pinfo, tree, data))
				return dissector_success;
		}
	}

	return FALSE;
}

gboolean
try_conversation_dissector_by_id(const endpoint_type etype, const guint32 id, tvbuff_t *tvb,
    packet_info *pinfo, proto_tree *tree, void* data)
{
	conversation_t *conversation;

	conversation = find_conversation_by_id(pinfo->num, etype, id, 0);

	if (conversation != NULL) {
		int ret;

		dissector_handle_t handle = (dissector_handle_t)wmem_tree_lookup32_le(conversation->dissector_tree, pinfo->num);
		if (handle == NULL)
			return FALSE;
		ret = call_dissector_only(handle, tvb, pinfo, tree, data);
		if (!ret) {
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

/**  A helper function that calls find_conversation() using data from pinfo
 *  The frame number and addresses are taken from pinfo.
 */
conversation_t *
find_conversation_pinfo(packet_info *pinfo, const guint options)
{
	conversation_t *conv=NULL;

	DINSTR(gchar *src_str = address_to_str(NULL, &pinfo->src));
	DINSTR(gchar *dst_str = address_to_str(NULL, &pinfo->dst));
	DPRINT(("called for frame #%u: %s:%d -> %s:%d (ptype=%d)",
		pinfo->num, src_str, pinfo->srcport,
		dst_str, pinfo->destport, pinfo->ptype));
	DINDENT();
	DINSTR(wmem_free(NULL, src_str));
	DINSTR(wmem_free(NULL, dst_str));

	/* Have we seen this conversation before? */
	if (pinfo->use_endpoint) {
		DISSECTOR_ASSERT(pinfo->conv_endpoint);
		if ((conv = find_conversation(pinfo->num, &pinfo->conv_endpoint->addr1, &pinfo->conv_endpoint->addr2,
					      pinfo->conv_endpoint->etype, pinfo->conv_endpoint->port1,
					      pinfo->conv_endpoint->port2, pinfo->conv_endpoint->options)) != NULL) {
			DPRINT(("found previous conversation for frame #%u (last_frame=%d)",
					pinfo->num, conv->last_frame));
			if (pinfo->num > conv->last_frame) {
				conv->last_frame = pinfo->num;
			}
		}
	} else {
		if ((conv = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst,
					      conversation_pt_to_endpoint_type(pinfo->ptype), pinfo->srcport,
					      pinfo->destport, options)) != NULL) {
			DPRINT(("found previous conversation for frame #%u (last_frame=%d)",
					pinfo->num, conv->last_frame));
			if (pinfo->num > conv->last_frame) {
				conv->last_frame = pinfo->num;
			}
		}
	}

	DENDENT();

	return conv;
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
	if ((conv = find_conversation_pinfo(pinfo, 0)) == NULL) {
		/* No, this is a new conversation. */
		DPRINT(("did not find previous conversation for frame #%u",
				pinfo->num));
		DINDENT();
		conv = conversation_new(pinfo->num, &pinfo->src,
					&pinfo->dst, conversation_pt_to_endpoint_type(pinfo->ptype),
					pinfo->srcport, pinfo->destport, 0);
		DENDENT();
	}

	return conv;
}

conversation_t *
find_or_create_conversation_by_id(packet_info *pinfo, const endpoint_type etype, const guint32 id)
{
	conversation_t *conv=NULL;

	/* Have we seen this conversation before? */
	if ((conv = find_conversation_by_id(pinfo->num, etype, id, 0)) == NULL) {
		/* No, this is a new conversation. */
		DPRINT(("did not find previous conversation for frame #%u",
				pinfo->num));
		DINDENT();
		conv = conversation_new_by_id(pinfo->num, etype, id, 0);
		DENDENT();
	}

	return conv;
}

void conversation_create_endpoint(struct _packet_info *pinfo, address* addr1, address* addr2,
    endpoint_type etype, guint32 port1, guint32	port2, const guint options)
{
	pinfo->conv_endpoint = wmem_new0(pinfo->pool, struct endpoint);
	pinfo->use_endpoint = TRUE;

	if (addr1 != NULL)
		copy_address_wmem(pinfo->pool, &pinfo->conv_endpoint->addr1, addr1);

	if (addr2 != NULL)
		copy_address_wmem(pinfo->pool, &pinfo->conv_endpoint->addr2, addr2);

	pinfo->conv_endpoint->etype = etype;
	pinfo->conv_endpoint->port1 = port1;
	pinfo->conv_endpoint->port2 = port2;
	pinfo->conv_endpoint->options = options;
}

void conversation_create_endpoint_by_id(struct _packet_info *pinfo,
    endpoint_type etype, guint32 id, const guint options)
{
	/* Force the lack of a address or port B */
	conversation_create_endpoint(pinfo, &null_address_, &null_address_, etype, id, 0, options|NO_ADDR_B|NO_PORT_B);
}

guint32 conversation_get_endpoint_by_id(struct _packet_info *pinfo, endpoint_type etype, const guint options)
{
	if (pinfo->conv_endpoint == NULL)
		return 0;

	if ((pinfo->conv_endpoint->etype != etype) &&
	    ((options & USE_LAST_ENDPOINT) != USE_LAST_ENDPOINT))
		return 0;

	return pinfo->conv_endpoint->port1;
}

wmem_map_t *
get_conversation_hashtable_exact(void)
{
	return conversation_hashtable_exact;
}

wmem_map_t *
get_conversation_hashtable_no_addr2(void)
{
	return conversation_hashtable_no_addr2;
}

wmem_map_t *
get_conversation_hashtable_no_port2(void)
{
	return conversation_hashtable_no_port2;
}

wmem_map_t *
get_conversation_hashtable_no_addr2_or_port2(void)
{
	return conversation_hashtable_no_addr2_or_port2;
}

address*
conversation_key_addr1(const conversation_key_t key)
{
	return &key->addr1;
}

address*
conversation_key_addr2(const conversation_key_t key)
{
	return &key->addr2;
}

guint32
conversation_key_port1(const conversation_key_t key)
{
	return key->port1;
}

guint32
conversation_key_port2(const conversation_key_t key)
{
	return key->port2;
}

WS_DLL_PUBLIC
endpoint_type conversation_pt_to_endpoint_type(port_type pt)
{
	switch (pt)
	{
	case PT_NONE:
		return ENDPOINT_NONE;
	case PT_SCTP:
		return ENDPOINT_SCTP;
	case PT_TCP:
		return ENDPOINT_TCP;
	case PT_UDP:
		return ENDPOINT_UDP;
	case PT_DCCP:
		return ENDPOINT_DCCP;
	case PT_IPX:
		return ENDPOINT_IPX;
	case PT_DDP:
		return ENDPOINT_DDP;
	case PT_IDP:
		return ENDPOINT_IDP;
	case PT_USB:
		return ENDPOINT_USB;
	case PT_I2C:
		return ENDPOINT_I2C;
	case PT_IBQP:
		return ENDPOINT_IBQP;
	case PT_BLUETOOTH:
		return ENDPOINT_BLUETOOTH;
	}

	DISSECTOR_ASSERT(FALSE);
	return ENDPOINT_NONE;
}

gchar*
conversation_get_html_hash(const conversation_key_t key)
{
	gchar *hash, *addr1, *addr2;

	addr1 = address_to_str(NULL, &key->addr1);
	addr2 = address_to_str(NULL, &key->addr2);
	hash = wmem_strdup_printf(NULL, "<tr><td>%s</td><td>%d</td><td>%s</td><td>%d</td></tr>\n",
				  addr1, key->port1, addr2, key->port2);
	wmem_free(NULL, addr1);
	wmem_free(NULL, addr2);

	return hash;
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
