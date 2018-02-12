/* packet-pkix1explicit.h
 * Routines for PKIX1Explicit packet dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_PKIX1EXPLICIT_H
#define PACKET_PKIX1EXPLICIT_H

int dissect_pkix1explicit_Certificate(gboolean implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_pkix1explicit_CertificateList(gboolean implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
#if 0
int dissect_pkix1explicit_CertificateSerialNumber(gboolean implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
#endif
int dissect_pkix1explicit_Name(gboolean implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_pkix1explicit_GeneralName(gboolean implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_pkix1explicit_AlgorithmIdentifier(gboolean implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,proto_tree *tree, int hf_index);
int dissect_pkix1explicit_SubjectPublicKeyInfo(gboolean implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);


#include "packet-pkix1explicit-exp.h"

#endif  /* PACKET_PKIX1EXPLICIT_H */

