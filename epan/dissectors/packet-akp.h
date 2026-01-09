/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-akp.h                                                               */
/* asn2wrs.py -b -q -L -p akp -c ./akp.cnf -s ./packet-akp-template -D . -O ../.. AsymmetricKeyPackageModuleV1.asn */

/* packet-akp.h
 * Routines for Asymmetric Key Packages (formerly known as PKCS #8) dissection
 *
 * See <https://datatracker.ietf.org/doc/html/rfc5958>.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_AKP_H
#define PACKET_AKP_H

#include <epan/asn1.h>

unsigned dissect_akp_PrivateKeyInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
unsigned dissect_akp_EncryptedPrivateKeyInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

#endif  /* PACKET_AKP_H */
