/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-cms.h                                                               */
/* ../../tools/asn2eth.py -X -b -p cms -c cms.cnf -s packet-cms-template CryptographicMessageSyntax.asn */

/* Input file: packet-cms-template.h */
/* Include files: packet-cms-exp.h, packet-cms-valexp.h */

/* packet-cms.h
 * Routines for RFC2630 Cryptographic Message Syntax packet dissection
 *
 * $Id: packet-cms-template.h,v 1.1 2004/05/24 08:42:29 sahlberg Exp $
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

#ifndef PACKET_CMS_H
#define PACKET_CMS_H


/*--- Included file: packet-cms-exp.h ---*/

/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-cms-exp.h                                                           */
/* ../../tools/asn2eth.py -X -b -p cms -c cms.cnf -s packet-cms-template CryptographicMessageSyntax.asn */

int dissect_cms_SignedData(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_cms_Countersignature(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);

/*--- End of included file: packet-cms-exp.h ---*/


#endif  /* PACKET_CMS_H */

