/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-credssp.h                                                           */
/* asn2wrs.py -b -C -p credssp -c ./credssp.cnf -s ./packet-credssp-template -D . -O ../.. CredSSP.asn */

/* Input file: packet-credssp-template.h */

#line 1 "./asn1/credssp/packet-credssp-template.h"
/* packet-credssp.h
 * Routines for CredSSP (Credential Security Support Provider) packet dissection
 * Graeme Lunt 2011
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_CREDSSP_H
#define PACKET_CREDSSP_H


/*--- Included file: packet-credssp-val.h ---*/
#line 1 "./asn1/credssp/packet-credssp-val.h"

/*--- End of included file: packet-credssp-val.h ---*/
#line 16 "./asn1/credssp/packet-credssp-template.h"

void proto_reg_handoff_credssp(void);
void proto_register_credssp(void);

#endif  /* PACKET_CREDSSP_H */
