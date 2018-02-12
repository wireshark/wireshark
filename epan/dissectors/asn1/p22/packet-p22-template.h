/* packet-p22.h
 * Routines for X.420 (X.400 Message Transfer) packet dissection
 * Graeme Lunt 2005
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_P22_H
#define PACKET_P22_H

#include "packet-p22-exp.h"

void proto_reg_handoff_p22(void);
void proto_register_p22(void);

#endif  /* PACKET_P22_H */
