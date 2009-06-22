/* packet-alcap.h
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <epan/dissectors/packet-e164.h>

extern void alcap_tree_from_bearer_key(proto_tree* tree, tvbuff_t* tvb, const gchar* key);

typedef struct _alcap_msg_data_t {
    guint msg_type;
    guint framenum;
    struct _alcap_msg_data_t* next;
    struct _alcap_msg_data_t* last;
} alcap_msg_data_t;

typedef struct _alcap_leg_info_t  {
	guint32 dsaid;
	guint32 osaid;
	guint32 pathid;
	guint32 cid;
	guint32 sugr;
	gchar* orig_nsap;
	gchar* dest_nsap;
    alcap_msg_data_t* msgs;
    guint release_cause;
} alcap_leg_info_t;


typedef struct _alcap_message_info_t {
	guint msg_type;
	guint32 dsaid;
	guint32 osaid;
	guint32 pathid;
	guint32 cid;
	guint32 sugr;
	gchar* orig_nsap;
	gchar* dest_nsap;
    guint release_cause;
} alcap_message_info_t;

