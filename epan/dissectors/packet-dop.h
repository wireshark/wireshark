/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* .\packet-dop.h                                                             */
/* ../../tools/asn2eth.py -X -b -e -p dop -c dop.cnf -s packet-dop-template dop.asn */

/* Input file: packet-dop-template.h */

#line 1 "packet-dop-template.h"
/* packet-x501.h
 * Routines for X.501 (DSA Operational Attributes) packet dissection
 * Graeme Lunt 2005
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifndef PACKET_X501_H
#define PACKET_X501_H


/*--- Included file: packet-dop-exp.h ---*/
#line 1 "packet-dop-exp.h"
int dissect_dop_DSEType(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dop_SupplierAndConsumers(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);

/*--- End of included file: packet-dop-exp.h ---*/
#line 30 "packet-dop-template.h"

#endif  /* PACKET_X501_H */
