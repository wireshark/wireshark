/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* .\packet-ranap.h                                                           */
/* ../../tools/asn2wrs.py -e -F -p ranap -c ranap.cnf -s packet-ranap-template ranap.asn */

/* Input file: packet-ranap-template.h */

#line 1 "packet-ranap-template.h"
/* packet-ranap-template.h
 * Routines for GSM Supplementary Services dissection
 * Copyright 2005, Anders Broman <anders.broman@ericsson.com>
 * $Id$ *
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

#ifndef PACKET_RANAP_H
#define PACKET_RANAP_H

/*--- Included file: packet-ranap-exp.h ---*/
#line 1 "packet-ranap-exp.h"
extern const value_string ranap_TargetID_vals[];
int dissect_ranap_TargetID(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);

/*--- End of included file: packet-ranap-exp.h ---*/
#line 27 "packet-ranap-template.h"

#endif  /* PACKET_RANAP_H */
