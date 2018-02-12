/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-pres.h                                                              */
/* asn2wrs.py -b -p pres -c ./pres.cnf -s ./packet-pres-template -D . -O ../.. ISO8823-PRESENTATION.asn ISO9576-PRESENTATION.asn */

/* Input file: packet-pres-template.h */

#line 1 "./asn1/pres/packet-pres-template.h"
/* packet-pres.h
 * Routines for pres packet dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_PRES_H
#define PACKET_PRES_H

/*#include "packet-pres-exp.h"*/

extern char *find_oid_by_pres_ctx_id(packet_info *pinfo, guint32 idx);

#endif  /* PACKET_PRES_H */
