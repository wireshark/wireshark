/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-rrc.h                                                               */
/* ../../tools/asn2wrs.py -p rrc -c rrc.cnf -s packet-rrc-template Class-definitions.asn PDU-definitions.asn InformationElements.asn Constant-definitions.asn Internode-definitions.asn */

/* Input file: packet-rrc-template.h */

#line 1 "packet-rrc-template.h"
/* packet-rrc-template.h
 * Copyright 2009, Anders Broman <anders.broman@ericsson.com>
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

#ifndef PACKET_RRC_H
#define PACKET_RRC_H


/*--- Included file: packet-rrc-exp.h ---*/
#line 1 "packet-rrc-exp.h"
int dissect_rrc_InterRATHandoverInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
void dissect_rrc_InterRATHandoverInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_);

/*--- End of included file: packet-rrc-exp.h ---*/
#line 29 "packet-rrc-template.h"

#endif  /* PACKET_RRC_H */
