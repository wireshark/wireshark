/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-lpp.h                                                               */
/* ../../tools/asn2wrs.py -p lpp -c ./lpp.cnf -s ./packet-lpp-template -D . -O ../../epan/dissectors LPP.asn */

/* Input file: packet-lpp-template.h */

#line 1 "../../asn1/lpp/packet-lpp-template.h"
/* packet-lpp.h
 * Routines for 3GPP LTE Positioning Protocol (LLP) packet dissection
 * Copyright 2011, Pascal Quantin <pascal.quantin@gmail.com>
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
 *
 * Ref 3GPP TS 36.355 version 9.7.0 Release 9
 * http://www.3gpp.org
 */

#ifndef PACKET_LPP_H
#define PACKET_LPP_H


/*--- Included file: packet-lpp-exp.h ---*/
#line 1 "../../asn1/lpp/packet-lpp-exp.h"
int dissect_lpp_Ellipsoid_Point_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_);
int dissect_lpp_EllipsoidPointWithAltitude_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_);
int dissect_lpp_HorizontalVelocity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_);

/*--- End of included file: packet-lpp-exp.h ---*/
#line 33 "../../asn1/lpp/packet-lpp-template.h"

#endif  /* PACKET_LPP_H */
