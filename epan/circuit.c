/* circuit.c
 * Routines for building lists of packets that are part of a "circuit"
 *
 * $Id: circuit.c,v 1.2 2002/10/29 07:22:55 guy Exp $
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

#include <string.h>
#include <glib.h>
#include "packet.h"
#include "circuit.h"

/*
 * Hash table for circuits.
 */
static GHashTable *circuit_hashtable = NULL;

static GMemChunk *circuit_key_chunk = NULL;
static GMemChunk *circuit_chunk = NULL;

static guint32 new_index;

static int circuit_init_count = 200;

/*
 * Protocol-specific data attached to a circuit_t structure - protocol
 * index and opaque pointer.
 */
typedef struct _circuit_proto_data {
	int	proto;
	void	*proto_data;
} circuit_proto_data;

static GMemChunk *circuit_proto_data_area = NULL;

/*
 * Compute the hash value for a circuit.
 */
static guint
circuit_hash(gconstpointer v)
{
	circuit_key *key = (circuit_key *)v;

	return key->ctype ^ key->circuit_id;
}

/*
 * Compare two circuit keys.
 */
static gint
circuit_match(gconstpointer v, gconstpointer w)
{
	circuit_key *v1 = (circuit_key *)v;
	circuit_key *v2 = (circuit_key *)w;

	return v1->ctype == v2->ctype && v1->circuit_id == v2->circuit_id;
}

/*
 * Initialize some variables every time a file is loaded or re-loaded.
 * Destroy all existing circuits, and create a new hash table
 * for the circuits in the new file.
 */
void
circuit_init(void)
{
	if (circuit_hashtable != NULL)
		g_hash_table_destroy(circuit_hashtable);
	if (circuit_key_chunk != NULL)
		g_mem_chunk_destroy(circuit_key_chunk);
	if (circuit_chunk != NULL)
		g_mem_chunk_destroy(circuit_chunk);

	/*
	 * Free up any space allocated for circuit protocol data
	 * areas.
	 *
	 * We can free the space, as the structures it contains are
	 * pointed to by circuit data structures that were freed
	 * above.
	 */
	if (circuit_proto_data_area != NULL)
		g_mem_chunk_destroy(circuit_proto_data_area);

	circuit_hashtable = g_hash_table_new(circuit_hash, circuit_match);
	circuit_key_chunk = g_mem_chunk_new("circuit_key_chunk",
	    sizeof(circuit_key),
	    circuit_init_count * sizeof(struct circuit_key),
	    G_ALLOC_AND_FREE);
	circuit_chunk = g_mem_chunk_new("circuit_chunk",
	    sizeof(circuit_t),
	    circuit_init_count * sizeof(circuit_t),
	    G_ALLOC_AND_FREE);

	/*
	 * Allocate a new area for circuit protocol data items.
	 */
	circuit_proto_data_area = g_mem_chunk_new("circuit_proto_data_area",
	    sizeof(circuit_proto_data), 20 * sizeof(circuit_proto_data), /* FIXME*/
	    G_ALLOC_ONLY);

	/*
	 * Start the circuit indices over at 0.
	 */
	new_index = 0;
}

/*
 * Given a circuit type and circuit ID for a packet, create a new circuit
 * to contain packets for that circuit.
 */
circuit_t *
circuit_new(circuit_type ctype, guint32 circuit_id)
{
	circuit_t *circuit;
	circuit_key *new_key;

	new_key = g_mem_chunk_alloc(circuit_key_chunk);
	new_key->ctype = ctype;
	new_key->circuit_id = circuit_id;

	circuit = g_mem_chunk_alloc(circuit_chunk);
	circuit->index = new_index;
	circuit->data_list = NULL;

/* clear dissector handle */
	circuit->dissector_handle = NULL;

/* set the options and key pointer */
	circuit->key_ptr = new_key;

	new_index++;

	g_hash_table_insert(circuit_hashtable, new_key, circuit);

	return circuit;
}

/*
 * Given a circuit type and ID, search for the corresponding circuit.
 * Returns NULL if not found.
 */
circuit_t *
find_circuit(circuit_type ctype, guint32 circuit_id)
{
	circuit_key key;

	key.ctype = ctype;
	key.circuit_id = circuit_id;
	return g_hash_table_lookup(circuit_hashtable, &key);
}

static gint
p_compare(gconstpointer a, gconstpointer b)
{
	if (((circuit_proto_data *)a)->proto > ((circuit_proto_data *)b)->proto)
		return 1;
	else if (((circuit_proto_data *)a)->proto == ((circuit_proto_data *)b)->proto)
		return 0;
	else
		return -1;
}

void
circuit_add_proto_data(circuit_t *conv, int proto, void *proto_data)
{
	circuit_proto_data *p1 = g_mem_chunk_alloc(circuit_proto_data_area);

	p1->proto = proto;
	p1->proto_data = proto_data;

	/* Add it to the list of items for this circuit. */

	conv->data_list = g_slist_insert_sorted(conv->data_list, (gpointer *)p1,
	    p_compare);
}

void *
circuit_get_proto_data(circuit_t *conv, int proto)
{
	circuit_proto_data temp, *p1;
	GSList *item;

	temp.proto = proto;
	temp.proto_data = NULL;

	item = g_slist_find_custom(conv->data_list, (gpointer *)&temp,
	    p_compare);

	if (item != NULL) {
		p1 = (circuit_proto_data *)item->data;
		return p1->proto_data;
	}

	return NULL;
}

void
circuit_delete_proto_data(circuit_t *conv, int proto)
{
	circuit_proto_data temp;
	GSList *item;

	temp.proto = proto;
	temp.proto_data = NULL;

	item = g_slist_find_custom(conv->data_list, (gpointer *)&temp,
	    p_compare);

	if (item != NULL)
		conv->data_list = g_slist_remove(conv->data_list, item);
}

void
circuit_set_dissector(circuit_t *circuit,
    dissector_handle_t handle)
{
	circuit->dissector_handle = handle;
}

/*
 * Given a circuit type and ID for a packet, search for a matching
 * circuit and, if found and it has a circuit dissector,
 * call that dissector and return TRUE, otherwise return FALSE.
 */
gboolean
try_circuit_dissector(circuit_type ctype, guint32 circuit_id, tvbuff_t *tvb,
    packet_info *pinfo, proto_tree *tree)
{
	circuit_t *circuit;

	circuit = find_circuit(ctype, circuit_id);

	if (circuit != NULL) {
		if (circuit->dissector_handle == NULL)
			return FALSE;
		call_dissector(circuit->dissector_handle, tvb, pinfo,
		    tree);
		return TRUE;
	}
	return FALSE;
}
