/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-tetra.h                                                             */
/* ../../tools/asn2wrs.py -u -p tetra -c ./tetra.cnf -s ./packet-tetra-template -D . -O ../../epan/dissectors tetra.asn */

/* Input file: packet-tetra-template.h */

#line 1 "../../asn1/tetra/packet-tetra-template.h"
/* packet-tetra.h
 * Routines for TETRA packet dissection
 *
 * Copyright (c) 2007 - 2011 Professional Mobile Communication Research Group,
 *    Beijing Institute of Technology, China
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
 * REF: ETSI EN 300 392-2 V3.2.1
 */

#ifndef PACKET_TETRA_H
#define PACKET_TETRA_H

enum {
	TETRA_CHAN_AACH		= 1,
	TETRA_CHAN_SCH_F	= 2,
	TETRA_CHAN_SCH_D	= 3,
	TETRA_CHAN_BSCH		= 5,
	TETRA_CHAN_BNCH		= 6,
	TETRA_CHAN_TCH_F	= 7,
	TETRA_CHAN_TCH_H	= 8,
	TETRA_CHAN_TCH_2_4	= 9,
	TETRA_CHAN_TCH_4_8	= 10,
	TETRA_CHAN_STCH		= 11,
	TETRA_CHAN_SCH_HU	= 15
};

enum {
	TETRA_UPLINK,
	TETRA_DOWNLINK
};

void tetra_dissect_pdu(int channel_type, int dir, tvbuff_t *pdu, proto_tree *head, packet_info *pinfo);


/*--- Included file: packet-tetra-exp.h ---*/
#line 1 "../../asn1/tetra/packet-tetra-exp.h"
int dissect_tetra_D_LOCATION_UPDATE_ACCEPT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_D_LOCATION_UPDATE_REJECT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_U_MM_STATUS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_D_MM_STATUS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_U_RELEASE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_U_SDS_DATA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_U_STATUS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_U_INFO(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_D_SDS_DATA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_D_STATUS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_D_DISCONNECT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_D_INFO(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_D_TX_WAIT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_D_TX_CONTINUE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_U_LOCATION_UPDATE_DEMAND(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_U_ATTACH_DETACH_GROUP_IDENTITY(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_U_ATTACH_DETACH_GROUP_IDENTITY_ACK(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_U_SETUP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_U_ALERT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_U_CONNECT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_U_TX_CEASED(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_U_TX_DEMAND(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_U_DISCONNECT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_U_CALL_RESTORE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_D_SETUP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_D_CALL_PROCEEDING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_D_ALERT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_D_CONNECT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_D_CONNECT_ACK(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_D_RELEASE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_D_CALL_RESTORE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_D_TX_CEASED(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_D_TX_GRANTED(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_D_ATTACH_DETACH_GROUP_IDENTITY(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_tetra_D_ATTACH_DETACH_GROUP_IDENTITY_ACK(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/*--- End of included file: packet-tetra-exp.h ---*/
#line 55 "../../asn1/tetra/packet-tetra-template.h"
#endif  /* PACKET_TETRA_H */
