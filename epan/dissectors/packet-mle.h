/* packet-mle.h
 * Routines for MLE packet dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_MLE_H__
#define __PACKET_MLE_H__

#include "packet-ieee802154.h"

typedef gboolean (*mle_set_mle_key_func) (ieee802154_packet * packet, unsigned char* key, unsigned char* alt_key, ieee802154_key_t* uat_key);
extern void register_mle_key_hash_handler(guint hash_identifier, mle_set_mle_key_func key_func);

#endif
