/* packet-rtse.h
 * Routines for RTSE packet dissection
 * Graeme Lunt 2005
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_RTSE_H
#define PACKET_RTSE_H

#include "packet-rtse-exp.h"

void register_rtse_oid_dissector_handle(const char *oid, dissector_handle_t dissector, int proto _U_, const char *name, gboolean uses_ros);

#endif  /* PACKET_RTSE_H */
