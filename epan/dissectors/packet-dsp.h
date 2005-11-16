/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* ./packet-dsp.h                                                             */
/* ../../tools/asn2eth.py -X -b -e -p dsp -c dsp.cnf -s packet-dsp-template dsp.asn */

/* Input file: packet-dsp-template.h */

/* packet-dsp.h
 * Routines for X.511 (X.500 Directory Access Protocol) packet dissection
 * Graeme Lunt 2005
 *
 * $Id: packet-dsp-template.h 14773 2005-06-26 10:59:15Z etxrab $
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

#ifndef PACKET_DSP_H
#define PACKET_DSP_H


/*--- Included file: packet-dsp-exp.h ---*/

extern const value_string dsp_ReferenceType_vals[];
int dissect_dsp_OperationProgress(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dsp_ReferenceType(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dsp_AccessPoint(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dsp_ContinuationReference(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);

/*--- End of included file: packet-dsp-exp.h ---*/


#endif  /* PACKET_DSP_H */
