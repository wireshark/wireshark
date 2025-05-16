/* packet-pkcs10.h
 *
 * Routines for PKCS10 dissection
 *   Martin Peylo 2017
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_PKCS10_H
#define PACKET_PKCS10_H

void proto_reg_handoff_pkcs10(void);

#include "packet-pkcs10-exp.h"

#endif  /* PACKET_PKCS10_H */
