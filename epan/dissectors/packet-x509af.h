/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* ./packet-x509af.h                                                          */
/* ../../tools/asn2eth.py -X -b -e -p x509af -c x509af.cnf -s packet-x509af-template AuthenticationFramework.asn */

/* Input file: packet-x509af-template.h */

/* packet-x509af.h
 * Routines for X.509 Authentication Framework packet dissection
 *
 * $Id: packet-x509af-template.h 12203 2004-10-05 09:18:55Z guy $
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

#ifndef PACKET_X509AF_H
#define PACKET_X509AF_H

int dissect_x509af_AlgorithmIdentifier(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index);


/*--- Included file: packet-x509af-exp.h ---*/

int dissect_x509af_Certificate(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_x509af_CertificateSerialNumber(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_x509af_SubjectPublicKeyInfo(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_x509af_Certificates(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_x509af_CertificationPath(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_x509af_CertificateList(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_x509af_AttributeCertificationPath(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_x509af_AttributeCertificate(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_x509af_AttributeCertificateAssertion(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);

/*--- End of included file: packet-x509af-exp.h ---*/


#endif  /* PACKET_X509AF_H */

