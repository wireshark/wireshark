/* conversation.h
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __CONVERSATION_H__
#define __CONVERSATION_H__

/*
 * Flags to pass to "conversation_new()" to indicate that the address 2
 * and/or port 2 values for the conversation should be wildcards.
 * The CONVERSATION_TEMPLATE option tells that any of the other supplied
 * port and / or address wildcards will be used to match an infinite number
 * of new connections to the conversation(s) that have the CONVERSATION_-
 * TEMPLATE flag set. Any conversation created without the CONVERSATION_-
 * TEMPLATE flag will be altered once the first connections (connection
 * oriented protocols only) to include the newly found information which
 * matched the wildcard options.
 */
#define NO_ADDR2 0x01
#define NO_PORT2 0x02
#define NO_PORT2_FORCE 0x04
#define CONVERSATION_TEMPLATE 0x08

/*
 * Flags to pass to "find_conversation()" to indicate that the address B
 * and/or port B search arguments are wildcards.
 */
#define NO_ADDR_B 0x01
#define NO_PORT_B 0x02
#define NO_PORT_B_FORCE 0x04

#include "packet.h"		/* for conversation dissector type */

/*
 * Data structure representing a conversation.
 */
typedef struct conversation_key {
	struct conversation_key *next;
	address	addr1;
	address	addr2;
	port_type ptype;
	guint32	port1;
	guint32	port2;
} conversation_key;

typedef struct conversation {
	struct conversation *next;	/* pointer to next conversation on hash chain */
	guint32	index;			/* unique ID for conversation */
	guint32 setup_frame;	/* frame number that setup this conversation */
	GSList *data_list;		/* list of data associated with conversation */
	dissector_handle_t dissector_handle;
					/* handle for protocol dissector client associated with conversation */
	guint	options;		/* wildcard flags */
	conversation_key *key_ptr;	/* pointer to the key for this conversation */
} conversation_t;

extern void conversation_init(void);

extern conversation_t *conversation_new(guint32 setup_frame, address *addr1, address *addr2,
    port_type ptype, guint32 port1, guint32 port2, guint options);

extern conversation_t *find_conversation(guint32 frame_num, address *addr_a, address *addr_b,
    port_type ptype, guint32 port_a, guint32 port_b, guint options);

extern void conversation_add_proto_data(conversation_t *conv, int proto,
    void *proto_data);
extern void *conversation_get_proto_data(conversation_t *conv, int proto);
extern void conversation_delete_proto_data(conversation_t *conv, int proto);

extern void conversation_set_dissector(conversation_t *conversation,
    dissector_handle_t handle);
extern gboolean
try_conversation_dissector(address *addr_a, address *addr_b, port_type ptype,
    guint32 port_a, guint32 port_b, tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree);

/* These routines are used to set undefined values for a conversation */

extern void conversation_set_port2(conversation_t *conv, guint32 port);
extern void conversation_set_addr2(conversation_t *conv, address *addr);

#endif /* conversation.h */
