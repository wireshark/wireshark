/* circuit.h
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

#ifndef __CIRCUIT_H__
#define __CIRCUIT_H__

#include "packet.h"		/* for circuit dissector type */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Data structure representing a circuit.
 */
typedef struct circuit_key {
	circuit_type ctype;
	guint32 circuit_id;
} circuit_key;

typedef struct circuit {
	struct circuit *next;		/* pointer to next circuit with given circuit ID */
	guint32 first_frame;		/* # of first frame for that circuit */
	guint32 last_frame;		/* # of last frame for that circuit */
	guint32	index;			/* unique ID for circuit */
	GSList *data_list;		/* list of data associated with circuit */
	dissector_handle_t dissector_handle;
					/* handle for protocol dissector client associated with circuit */
	guint	options;		/* wildcard flags */
	circuit_key *key_ptr;		/* pointer to the key for this circuit */
} circuit_t;

extern void circuit_init(void);

extern circuit_t *circuit_new(circuit_type ctype, guint32 circuit_id,
    guint32 first_frame);

extern circuit_t *find_circuit(circuit_type ctype, guint32 circuit_id,
    guint32 frame);

extern void close_circuit(circuit_t *circuit, guint32 last_frame);

extern void circuit_add_proto_data(circuit_t *conv, int proto,
    void *proto_data);
extern void *circuit_get_proto_data(circuit_t *conv, int proto);
extern void circuit_delete_proto_data(circuit_t *conv, int proto);

extern void circuit_set_dissector(circuit_t *circuit,
    dissector_handle_t handle);
extern dissector_handle_t circuit_get_dissector(circuit_t *circuit);
extern gboolean
try_circuit_dissector(circuit_type ctype, guint32 circuit_id, guint32 frame,
   tvbuff_t *tvb,  packet_info *pinfo, proto_tree *tree);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* circuit.h */
