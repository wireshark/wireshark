/* packet-cmp.h
 * Routines for RFC2510 Certificate Management Protocol packet dissection
 *   Ronnie Sahlberg 2004
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_CMP_H
#define PACKET_CMP_H

void proto_reg_handoff_cmp(void);

#include "packet-cmp-exp.h"

#endif  /* PACKET_CMP_H */

