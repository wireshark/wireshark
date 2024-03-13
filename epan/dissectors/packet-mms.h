/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-mms.h                                                               */
/* asn2wrs.py -b -q -L -p mms -c ./mms.cnf -s ./packet-mms-template -D . -O ../.. mms.asn */

/* packet-mms.h
 * Routines for MMS packet dissection
 *   Ronnie Sahlberg 2005
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_MMS_H
#define PACKET_MMS_H

extern const value_string mms_MMSpdu_vals[];
int dissect_mms_MMSpdu(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

#endif  /* PACKET_MMS_H */

