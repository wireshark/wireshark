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

extern void register_mle_key_hash_handler(unsigned hash_identifier, ieee802154_set_key_func key_func);

#endif
