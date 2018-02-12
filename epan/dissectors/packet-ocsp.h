/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-ocsp.h                                                              */
/* asn2wrs.py -b -p ocsp -c ./ocsp.cnf -s ./packet-ocsp-template -D . -O ../.. OCSP.asn */

/* Input file: packet-ocsp-template.h */

#line 1 "./asn1/ocsp/packet-ocsp-template.h"
/* packet-ocsp.h
 * Routines for Online Certificate Status Protocol (RFC2560) packet dissection
 *  Ronnie Sahlberg 2004
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_OCSP_H
#define PACKET_OCSP_H

/*#include "packet-ocsp-exp.h"*/

extern int proto_ocsp;
int dissect_ocsp_OCSPResponse(gboolean implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);

#endif  /* PACKET_OCSP_H */

