/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-lcsap.h                                                             */
/* asn2wrs.py -p lcsap -c ./lcsap.cnf -s ./packet-lcsap-template -D . -O ../.. LCS-AP-CommonDataTypes.asn LCS-AP-Constants.asn LCS-AP-Containers.asn LCS-AP-IEs.asn LCS-AP-PDU-Contents.asn LCS-AP-PDU-Descriptions.asn */

/* Input file: packet-lcsap-template.h */

#line 1 "./asn1/lcsap/packet-lcsap-template.h"
/* packet-lcsap.c
 * Routines for LCS-AP packet dissembly.
 *
 * Copyright (c) 2011 by Spenser Sheng <spenser.sheng@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 * References:
 * ETSI TS 129 171 V9.2.0 (2010-10)
 */

#ifndef PACKET_LCSAP_H
#define PACKET_LCSAP_H


/*--- Included file: packet-lcsap-exp.h ---*/
#line 1 "./asn1/lcsap/packet-lcsap-exp.h"
int dissect_lcsap_Correlation_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

/*--- End of included file: packet-lcsap-exp.h ---*/
#line 31 "./asn1/lcsap/packet-lcsap-template.h"

#endif  /* PACKET_LCSAP_H */
