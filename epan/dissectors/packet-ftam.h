/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-ftam.h                                                              */
/* ../../tools/asn2wrs.py -b -p ftam -c ./ftam.cnf -s ./packet-ftam-template -D . ISO8571-FTAM.asn */

/* Input file: packet-ftam-template.h */

#line 1 "../../asn1/ftam/packet-ftam-template.h"
/* packet-ftam.h
 * Routine to dissect OSI ISO 8571 FTAM Protocol packets
 * based on the ASN.1 specification from http://www.itu.int/ITU-T/asn1/database/iso/8571-4/1988/
 *
 * also based on original handwritten dissector by
 * Yuriy Sidelnikov <YSidelnikov@hotmail.com>
 *
 * Anders Broman and Ronnie Sahlberg 2005
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

#ifndef PACKET_FTAM_H
#define PACKET_FTAM_H


/*--- Included file: packet-ftam-exp.h ---*/
#line 1 "../../asn1/ftam/packet-ftam-exp.h"
extern const value_string ftam_Date_and_Time_Attribute_vals[];
extern const value_string ftam_Object_Availability_Attribute_vals[];
extern const value_string ftam_Object_Size_Attribute_vals[];
extern const value_string ftam_Legal_Qualification_Attribute_vals[];
extern const value_string ftam_Private_Use_Attribute_vals[];
int dissect_ftam_Concurrency_Access(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_ftam_Date_and_Time_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_ftam_Object_Availability_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_ftam_Object_Size_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_ftam_Legal_Qualification_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_ftam_Permitted_Actions_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_ftam_Private_Use_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_ftam_Attribute_Extensions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_ftam_Pathname(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/*--- End of included file: packet-ftam-exp.h ---*/
#line 35 "../../asn1/ftam/packet-ftam-template.h"

#endif  /* PACKET_FTAM_H */
