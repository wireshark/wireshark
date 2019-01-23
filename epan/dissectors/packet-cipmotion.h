/* packet-cipmotion.h
 * Routines for CIP (Common Industrial Protocol) Motion dissection
 * CIP Motion Home: www.odva.org
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_CIPMOTION_H
#define PACKET_CIPMOTION_H

#include "packet-cip.h"  // For attribute_info_t

extern attribute_info_t cip_motion_attribute_vals[17];

#endif /* PACKET_CIPMOTION_H */
