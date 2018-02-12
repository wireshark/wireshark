/* packet-credssp.h
 * Routines for CredSSP (Credential Security Support Provider) packet dissection
 * Graeme Lunt 2011
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_CREDSSP_H
#define PACKET_CREDSSP_H

#include "packet-credssp-val.h"

void proto_reg_handoff_credssp(void);
void proto_register_credssp(void);

#endif  /* PACKET_CREDSSP_H */
