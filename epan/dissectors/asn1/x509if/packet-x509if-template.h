/* packet-x509if.h
 * Routines for X.509 Information Framework packet dissection
 *  Ronnie Sahlberg 2004
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_X509IF_H
#define PACKET_X509IF_H

#include "packet-x509if-exp.h"

extern const char * x509if_get_last_dn(void);

extern gboolean x509if_register_fmt(int hf_index, const gchar *fmt);
extern const char * x509if_get_last_ava(void);

#endif  /* PACKET_X509IF_H */

