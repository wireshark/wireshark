/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-ess.h                                                               */
/* asn2wrs.py -b -k -C -p ess -c ./ess.cnf -s ./packet-ess-template -D . -O ../.. ExtendedSecurityServices.asn */

/* Input file: packet-ess-template.h */

#line 1 "./asn1/ess/packet-ess-template.h"
/* packet-ess.h
 * Routines for RFC5035 Extended Security Services packet dissection
 *    Ronnie Sahlberg 2004
 *    Stig Bjorlykke 2010
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
 */

#ifndef PACKET_ESS_H
#define PACKET_ESS_H


/*--- Included file: packet-ess-exp.h ---*/
#line 1 "./asn1/ess/packet-ess-exp.h"
int dissect_ess_ESSSecurityLabel_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

/*--- End of included file: packet-ess-exp.h ---*/
#line 29 "./asn1/ess/packet-ess-template.h"

#endif  /* PACKET_ESS_H */

