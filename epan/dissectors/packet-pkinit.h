/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-pkinit.h                                                            */
/* asn2wrs.py -b -q -L -p pkinit -c ./pkinit.cnf -s ./packet-pkinit-template -D . -O ../.. PKINIT_RFC_4556.asn */

/* packet-pkinit.h
 * Routines for PKINIT packet dissection
 *  Ronnie Sahlberg 2004
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_PKINIT_H
#define PACKET_PKINIT_H

#include <epan/asn1.h>

extern const value_string pkinit_PA_PK_AS_REP_vals[];
unsigned dissect_pkinit_PA_PK_AS_REQ(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
unsigned dissect_pkinit_PA_PK_AS_REP(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
unsigned dissect_pkinit_PA_PK_AS_REQ_Win2k(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
unsigned dissect_pkinit_PA_PK_AS_REP_Win2k(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

#endif  /* PACKET_PKINIT_H */

