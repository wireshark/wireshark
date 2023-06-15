/* packet-pkix1implicit.h
 * Routines for PKIX1Implicit packet dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_PKIX1IMPLICIT_H
#define PACKET_PKIX1IMPLICIT_H

int dissect_pkix1implicit_GeneralName(bool implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_);
int dissect_pkix1implicit_ReasonFlags(bool implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_);

#include "packet-pkix1implicit-exp.h"

#endif  /* PACKET_PKIX1IMPLICIT_H */

