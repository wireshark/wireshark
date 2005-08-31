/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* .\packet-h245.h                                                            */
/* ../../tools/asn2eth.py -X -e -p h245 -c h245.cnf -s packet-h245-template h245.asn */

/* Input file: packet-h245-template.h */

/* packet-h245.h
 * Routines for h245 packet dissection
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

#ifndef PACKET_H245_H
#define PACKET_H245_H
typedef enum _h245_msg_type {
	H245_TermCapSet,
	H245_TermCapSetAck,
	H245_TermCapSetRjc,
	H245_TermCapSetRls,
	H245_OpenLogChn,
	H245_OpenLogChnCnf,
	H245_OpenLogChnAck,
	H245_OpenLogChnRjc,	
	H245_CloseLogChn,
	H245_CloseLogChnAck,
	H245_MastSlvDet,
	H245_MastSlvDetAck,
	H245_MastSlvDetRjc,
	H245_MastSlvDetRls,
        H245_OTHER
} h245_msg_type;

typedef struct _h245_packet_info {
        h245_msg_type msg_type;         /* type of message */
        gchar frame_label[50];          /* the Frame label used by graph_analysis, what is a abreviation of cinfo */
        gchar comment[50];                      /* the Frame Comment used by graph_analysis, what is a message desc */
} h245_packet_info;



/*--- Included file: packet-h245-exp.h ---*/

extern const value_string DataProtocolCapability_vals[];
int dissect_h245_DataProtocolCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_h245_T38FaxProfile(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_h245_OpenLogicalChannel(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);

/*--- End of included file: packet-h245-exp.h ---*/

void dissect_h245_OpenLogicalChannelCodec(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, char *codec_str);


#endif  /* PACKET_H245_H */


