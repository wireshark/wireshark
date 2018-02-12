/* packet-x509ce.h
 * Routines for X.509 Certificate Extensions packet dissection
 *  Ronnie Sahlberg 2004
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_X509CE_H
#define PACKET_X509CE_H

#include "packet-x509ce-exp.h"

void x509ce_enable_ciplus(void);
void x509ce_disable_ciplus(void);

#endif  /* PACKET_X509CE_H */

