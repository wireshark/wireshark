/* packet-mle.h
 * Routines for MLE packet dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
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

#ifndef __PACKET_MLE_H__
#define __PACKET_MLE_H__

#include "packet-ieee802154.h"

typedef gboolean (*mle_set_mle_key_func) (ieee802154_packet * packet, unsigned char* key, unsigned char* alt_key, ieee802154_key_t* uat_key);
extern void register_mle_key_hash_handler(guint hash_identifier, mle_set_mle_key_func key_func);

#endif
