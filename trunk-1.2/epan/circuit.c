/* circuit.c
 * Routines for building lists of packets that are part of a "circuit"
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

#include <stdio.h>

#include <string.h>
#include <glib.h>
#include "packet.h"
#include "circuit.h"
#include "emem.h"

/*
 * Hash table for circuits.
 */
static GHashTable *circuit_hashtable = NULL;

static guint32 new_index;

/*
 * Protocol-specific data attached to a circuit_t structure - protocol
 * index and opaque pointer.
 */
typedef struct _circuit_proto_data {
	int	proto;
	void	*proto_data;
} circuit_proto_data;

/*
 * Compute the hash value for a circuit.
 */
static guint
circuit_hash(gconstpointer v)
{
	const circuit_key *key = (const circuit_key *)v;

	return key->ctype ^ key->circuit_id;
}

/*
 * Compare two circuit keys.
 */
static gint
circuit_match(gconstpointer v, gconstpointer w)
{
	const circuit_key *v1 = (const circuit_key *)v;
	const circuit_key *v2 = (const circuit_key *)w;

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

	/*
	 * Free up any space allocated for circuit protocol data
	 * areas.
	 *
	 * We can free the space, as the structures it contains are
	 * pointed to by circuit data structures that were freed
	 * above.
	 */

	circuit_hashtable = g_hash_table_new(circuit_hash, circuit_match);

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
circuit_new(circuit_type ctype, guint32 circuit_id, guint32 first_frame)
{
	circuit_t *circuit, *old_circuit;
	circuit_key *new_key;

	new_key = se_alloc(sizeof(struct circuit_key));
	new_key->ctype = ctype;
	new_key->circuit_id = circuit_id;

	circuit = se_alloc(sizeof(circuit_t));
	circuit->next = NULL;
	circuit->first_frame = first_frame;
	circuit->last_frame = 0;	/* not known yet */
	circuit->index = new_index;
	circuit->data_list = NULL;
	circuit->dissector_handle = NULL;
	circuit->key_ptr = new_key;

	new_index++;

	/*
	 * Is there already a circuit with this circuit ID?
	 */
	old_circuit = g_hash_table_lookup(circuit_hashtable, new_key);
	if (old_circuit != NULL) {
		/*
		 * Yes.  Find the last circuit in the list of circuits
		 * with this circuit ID, and if its last frame isn't
		 * known, make it be the previous frame to this one.
		 */
		while (old_circuit->next != NULL)
			old_circuit = old_circuit->next;
		if (old_circuit->last_frame == 0)
			old_circuit->last_frame = first_frame - 1;

		/*
		 * Now put the new circuit after the last one in the
		 * list.
		 */
		old_circuit->next = circuit;
	} else {
		/*
		 * No.  This is the first one with this circuit ID; add
		 * it to the hash table.
		 */
		g_hash_table_insert(circuit_hashtable, new_key, circuit);
	}

	return circuit;
}

/*
 * Given a circuit type and ID, and a frame number, search for a circuit with
 * that type and ID whose range of frames includes that frame number.
 * Returns NULL if not found.
 */
circuit_t *
find_circuit(circuit_type ctype, guint32 circuit_id, guint32 frame)
{
	circuit_key key;
	circuit_t *circuit;

	key.ctype = ctype;
	key.circuit_id = circuit_id;

	/*
	 * OK, search the list of circuits with that type and ID for
	 * a circuit whose range of frames includes that frame number.
	 */
	for (circuit = g_hash_table_lookup(circuit_hashtable, &key);
	    circuit != NULL; circuit = circuit->next) {
		/*
		 * The circuit includes that frame number if:
		 *
		 *	the circuit's first frame is unknown or is at or
		 *	before that frame
		 *
		 * and
		 *
		 *	the circuit's last frame is unknown or is at or
		 *	after that frame.
		 */
		if ((circuit->first_frame == 0 || circuit->first_frame <= frame)
		    && (circuit->last_frame == 0 || circuit->last_frame >= frame))
			break;
	}
	return circuit;
}

/*
 * Set the last frame of a circuit, if it's not already known,
 * "closing" the circuit.
 */
void
close_circuit(circuit_t *circuit, guint32 last_frame)
{
	if (circuit->last_frame == 0)
		circuit->last_frame = last_frame;
}

static gint
p_compare(gconstpointer a, gconstpointer b)
{
	const circuit_proto_data *ap = (const circuit_proto_data *)a;
	const circuit_proto_data *bp = (const circuit_proto_data *)b;

	if (ap->proto > bp->proto)
		return 1;
	else if (ap->proto == bp->proto)
		return 0;
	else
		return -1;
}

void
circuit_add_proto_data(circuit_t *conv, int proto, void *proto_data)
{
	circuit_proto_data *p1 = se_alloc(sizeof(circuit_proto_data));

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
circuit_set_dissector(circuit_t *circuit, dissector_handle_t handle)
{
	circuit->dissector_handle = handle;
}

dissector_handle_t
circuit_get_dissector(circuit_t *circuit)
{
	return circuit->dissector_handle;
}

/*
 * Given a circuit type and ID for a packet, search for a matching
 * circuit and, if found and it has a circuit dissector,
 * call that dissector and return TRUE, otherwise return FALSE.
 */
gboolean
try_circuit_dissector(circuit_type ctype, guint32 circuit_id, guint32 frame,
    tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	circuit_t *circuit;

	circuit = find_circuit(ctype, circuit_id, frame);

	if (circuit != NULL) {
		if (circuit->dissector_handle == NULL)
			return FALSE;
		call_dissector(circuit->dissector_handle, tvb, pinfo,
		    tree);
		return TRUE;
	}
	return FALSE;
}
