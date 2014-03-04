/* circuit.h
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

#ifndef __CIRCUIT_H__
#define __CIRCUIT_H__

#include "packet.h"		/* for circuit dissector type */
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * Data structure representing a circuit.
 */
typedef struct circuit_key {
	circuit_type ctype;
	guint32 circuit_id;
} circuit_key;

typedef struct circuit {
	struct circuit *next;		/**< pointer to next circuit with given circuit ID */
	guint32 first_frame;		/**< # of first frame for that circuit */
	guint32 last_frame;			/**< # of last frame for that circuit */
	guint32	index;				/**< unique ID for circuit */
	GSList *data_list;			/**< list of data associated with circuit */
	dissector_handle_t dissector_handle; /**< handle for protocol dissector client associated with circuit */
	guint	options;			/**< wildcard flags */
	circuit_key *key_ptr;		/**< pointer to the key for this circuit */
} circuit_t;

/**
 * Destroy all existing circuits.
 */
extern void circuit_cleanup(void);

/**
 * Initialize some variables every time a file is loaded or re-loaded.
 * Create a new hash table for the circuits in the new file.
 */
extern void circuit_init(void);

/**
 * Given a circuit type and circuit ID for a packet, create a new circuit
 * to contain packets for that circuit.
 */
WS_DLL_PUBLIC circuit_t *circuit_new(circuit_type ctype, guint32 circuit_id,
    guint32 first_frame);

/**
 * Given a circuit type and ID, and a frame number, search for a circuit with
 * that type and ID whose range of frames includes that frame number.
 * Returns NULL if not found.
 */
WS_DLL_PUBLIC circuit_t *find_circuit(circuit_type ctype, guint32 circuit_id,
    guint32 frame);

/**
 * Set the last frame of a circuit, if it's not already known,
 * "closing" the circuit.
 */
extern void close_circuit(circuit_t *circuit, guint32 last_frame);

WS_DLL_PUBLIC void circuit_add_proto_data(circuit_t *conv, int proto,
    void *proto_data);
WS_DLL_PUBLIC void *circuit_get_proto_data(circuit_t *conv, int proto);
void circuit_delete_proto_data(circuit_t *conv, int proto);

extern void circuit_set_dissector(circuit_t *circuit,
    dissector_handle_t handle);
extern dissector_handle_t circuit_get_dissector(circuit_t *circuit);

/**
 * Given a circuit type and ID for a packet, search for a matching
 * circuit and, if found and it has a circuit dissector,
 * call that dissector and return TRUE, otherwise return FALSE.
 */
extern gboolean
try_circuit_dissector(circuit_type ctype, guint32 circuit_id, guint32 frame,
   tvbuff_t *tvb,  packet_info *pinfo, proto_tree *tree, void* data);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* circuit.h */
