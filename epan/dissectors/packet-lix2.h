/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-lix2.h                                                              */
/* asn2wrs.py -b -q -L -p lix2 -c ./lix2.cnf -s ./packet-lix2-template -D . -O ../.. lix2.asn */

/* packet-lix2-template.h
 * Routines for Lawful Interception X2 xIRI event dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_LIX2_H
#define PACKET_LIX2_H

#include <epan/asn1.h>

unsigned dissect_lix2_IRIPayload(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
unsigned dissect_lix2_CCPayload(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
unsigned dissect_lix2_LINotificationPayload(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
unsigned dissect_lix2_UserLocation(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

#endif  /* PACKET_LIX2_H */
