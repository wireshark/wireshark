/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-ess.h                                                               */
/* ../../tools/asn2wrs.py -b -k -C -p ess -c ./ess.cnf -s ./packet-ess-template -D . -O ../../epan/dissectors ExtendedSecurityServices.asn */

/* Input file: packet-ess-template.h */

#line 1 "../../asn1/ess/packet-ess-template.h"
/* packet-ess.h
 * Routines for RFC5035 Extended Security Services packet dissection
 *    Ronnie Sahlberg 2004
 *    Stig Bjorlykke 2010
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef PACKET_ESS_H
#define PACKET_ESS_H


/*--- Included file: packet-ess-exp.h ---*/
#line 1 "../../asn1/ess/packet-ess-exp.h"
void dissect_ess_ESSSecurityLabel_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_);

/*--- End of included file: packet-ess-exp.h ---*/
#line 31 "../../asn1/ess/packet-ess-template.h"

#endif  /* PACKET_ESS_H */

