/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* .\packet-umts_rrc.h                                                        */
/* ../../tools/asn2wrs.py -u -e -p umts_rrc -c umts_rrc.cnf -s packet-umts_rrc-template umts_rrc_Class-definitions.asn */

/* Input file: packet-umts_rrc-template.h */

#line 1 "packet-umts_rrc-template.h"
/* packet-umts_rrc.h
 * Routines for Universal Mobile Telecommunications System (UMTS);
 * Radio Resource Control (RRC) protocol specification
 * (3GPP TS 25.331 version 6.7.0 Release 6) packet dissection
 * Copyright 2005, Anders Broman <anders.broman@ericsson.com>
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

#ifndef PACKET_UMTS_RRC_H
#define PACKET_UMTS_RRC_H




/*--- Included file: packet-umts_rrc-exp.h ---*/
#line 1 "packet-umts_rrc-exp.h"
int dissect_umts_rrc_DL_DCCH_Message(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_UL_DCCH_Message(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_DL_CCCH_Message(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_UL_CCCH_Message(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_PCCH_Message(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_DL_SHCCH_Message(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_UL_SHCCH_Message(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_BCCH_FACH_Message(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_BCCH_BCH_Message(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_MCCH_Message(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_MSCH_Message(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);

/*--- End of included file: packet-umts_rrc-exp.h ---*/
#line 34 "packet-umts_rrc-template.h"

#endif  /* PACKET_UMTS_RRC_H */


