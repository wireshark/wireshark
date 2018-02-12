/* packet-x509af.h
 * Routines for X.509 Authentication Framework packet dissection
 *  Ronnie Sahlberg 2004
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_X509AF_H
#define PACKET_X509AF_H

#include "packet-x509af-exp.h"

extern const char* x509af_get_last_algorithm_id(void);

#endif  /* PACKET_X509AF_H */

