/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-pkcs10.h                                                            */
/* asn2wrs.py -b -q -L -p pkcs10 -c ./pkcs10.cnf -s ./packet-pkcs10-template -D . -O ../.. PKCS10.asn */

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

int dissect_pkcs10_CertificationRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

#endif  /* PACKET_PKCS10_H */
