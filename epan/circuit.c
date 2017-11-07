/* circuit.c
 * Routines for building lists of packets that are part of a "circuit"
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

#include <glib.h>
#include "packet.h"
#include "circuit.h"

struct circuit_key {
	circuit_type ctype;
	guint32 circuit_id;
};

/*
 * Hash table for circuits.
 */
static GHashTable *circuit_hashtable = NULL;

static guint32 new_index;

/*
 * Compute the hash value for a circuit.
 */
static guint
circuit_hash(gconstpointer v)
{
	const circuit_key_t key = (const circuit_key_t)v;

	return key->ctype ^ key->circuit_id;
}

/*
 * Compare two circuit keys.
 */
static gint
circuit_match(gconstpointer v, gconstpointer w)
{
	const circuit_key_t v1 = (const circuit_key_t)v;
	const circuit_key_t v2 = (const circuit_key_t)w;

	return v1->ctype == v2->ctype && v1->circuit_id == v2->circuit_id;
}

/*
 * Destroy all existing circuits.
 */
void
circuit_cleanup(void)
{
	/*
	 * Free up any space allocated for the circuit hashtable.
	 *
	 * We can free the hash as the structures pointed to in the
	 * hash are in "seasonal" memory which is freed separately.
	 * Note: circuit_cleanup() must be called only when
	 *       seasonal memory is also freed.
	 */

	if (circuit_hashtable != NULL)
		g_hash_table_destroy(circuit_hashtable);

	circuit_hashtable = NULL;
}

/*
 * Initialize some variables every time a file is loaded or re-loaded.
 * Create a new hash table for the circuits in the new file.
 */
void
circuit_init(void)
{
	g_assert(circuit_hashtable == NULL);
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
	circuit_key_t new_key;

	new_key = wmem_new(wmem_file_scope(), struct circuit_key);
	new_key->ctype = ctype;
	new_key->circuit_id = circuit_id;

	circuit = wmem_new(wmem_file_scope(), circuit_t);
	circuit->next = NULL;
	circuit->first_frame = first_frame;
	circuit->last_frame = 0;	/* not known yet */
	circuit->circuit_index = new_index;
	circuit->data_list = NULL;
	circuit->dissector_tree = wmem_tree_new(wmem_file_scope());
	circuit->key_ptr = new_key;

	new_index++;

	/*
	 * Is there already a circuit with this circuit ID?
	 */
	old_circuit = (circuit_t *)g_hash_table_lookup(circuit_hashtable, new_key);
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
	struct circuit_key key;
	circuit_t *circuit;

	key.ctype = ctype;
	key.circuit_id = circuit_id;

	/*
	 * OK, search the list of circuits with that type and ID for
	 * a circuit whose range of frames includes that frame number.
	 */
	for (circuit = (circuit_t *)g_hash_table_lookup(circuit_hashtable, &key);
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

void
circuit_add_proto_data(circuit_t *conv, int proto, void *proto_data)
{
	/* Add it to the list of items for this conversation. */
	if (conv->data_list == NULL)
		conv->data_list = wmem_tree_new(wmem_file_scope());

	wmem_tree_insert32(conv->data_list, proto, proto_data);
}

void *
circuit_get_proto_data(circuit_t *conv, int proto)
{
	/* No tree created yet */
	if (conv->data_list == NULL)
		return NULL;

	return wmem_tree_lookup32(conv->data_list, proto);
}

void
circuit_delete_proto_data(circuit_t *conv, int proto)
{
	if (conv->data_list != NULL)
		wmem_tree_remove32(conv->data_list, proto);
}

void
circuit_set_dissector(circuit_t *circuit, dissector_handle_t handle)
{
	wmem_tree_insert32(circuit->dissector_tree, 0, (void *)handle);
}

dissector_handle_t
circuit_get_dissector(circuit_t *circuit)
{
	if (circuit == NULL)
		return NULL;

	return (dissector_handle_t)wmem_tree_lookup32_le(circuit->dissector_tree, 0);
}

/*
 * Given a circuit type and ID for a packet, search for a matching
 * circuit and, if found and it has a circuit dissector,
 * call that dissector and return TRUE, otherwise return FALSE.
 */
gboolean
try_circuit_dissector(circuit_type ctype, guint32 circuit_id, guint32 frame,
		      tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	circuit_t *circuit;
	dissector_handle_t handle;

	circuit = find_circuit(ctype, circuit_id, frame);

	if (circuit != NULL) {
		handle = circuit_get_dissector(circuit);
		if (handle == NULL)
			return FALSE;
		call_dissector_with_data(handle, tvb, pinfo, tree, data);
		return TRUE;
	}
	return FALSE;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
