/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-cdt.h                                                               */
/* asn2wrs.py -b -p cdt -c ./cdt.cnf -s ./packet-cdt-template -D . -O ../.. cdt.asn */

/* Input file: packet-cdt-template.h */

#line 1 "./asn1/cdt/packet-cdt-template.h"
/* packet-cdt.h
 *
 * Routines for Compressed Data Type packet dissection.
 *
 * Copyright 2005, Stig Bjorlykke <stig@bjorlykke.org>, Thales Norway AS
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_CDT_H
#define PACKET_CDT_H

void dissect_cdt (tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree);

/*--- Included file: packet-cdt-exp.h ---*/
#line 1 "./asn1/cdt/packet-cdt-exp.h"
int dissect_cdt_CompressedData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/*--- End of included file: packet-cdt-exp.h ---*/
#line 19 "./asn1/cdt/packet-cdt-template.h"

#endif  /* PACKET_CDT_H */

