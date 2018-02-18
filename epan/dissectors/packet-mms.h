/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-mms.h                                                               */
/* asn2wrs.py -b -p mms -c ./mms.cnf -s ./packet-mms-template -D . -O ../.. mms.asn */

/* Input file: packet-mms-template.h */

#line 1 "./asn1/mms/packet-mms-template.h"
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


/*--- Included file: packet-mms-exp.h ---*/
#line 1 "./asn1/mms/packet-mms-exp.h"
extern const value_string mms_MMSpdu_vals[];
int dissect_mms_MMSpdu(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/*--- End of included file: packet-mms-exp.h ---*/
#line 16 "./asn1/mms/packet-mms-template.h"

#endif  /* PACKET_MMS_H */

