/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-disp.h                                                              */
/* asn2wrs.py -b -q -L -p disp -c ./disp.cnf -s ./packet-disp-template -D . -O ../.. disp.asn */

/* packet-disp.h
 * Routines for X.525 (X.400 Message Transfer) packet dissection
 * Graeme Lunt 2005
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_DISP_H
#define PACKET_DISP_H

int dissect_disp_AgreementID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

#endif  /* PACKET_DISP_H */
