/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* .\packet-gsm_map.h                                                         */
/* ../../tools/asn2eth.py -X -b -e -p gsm_map -c gsmmap.cnf -s packet-gsm_map-template GSMMAP.asn */

/* Input file: packet-gsm_map-template.h */

/* packet-gsm_map-template.h
 * Routines for GSM MAP packet dissection
 * Copyright 2004, Anders Broman <anders.broman@ericsson.com>
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

#ifndef PACKET_GSM_MAP_H
#define PACKET_GSM_MAP_H

/* Defines for the GSM MAP taps */
#define	GSM_MAP_MAX_NUM_OPR_CODES	256

typedef struct _gsm_map_tap_rec_t {
    gboolean		invoke;
    guint8		opr_code_idx;
    guint16		size;
} gsm_map_tap_rec_t;

ETH_VAR_IMPORT const value_string gsm_map_opr_code_strings[];
char* unpack_digits(tvbuff_t *tvb, int offset);


/*--- Included file: packet-gsm_map-exp.h ---*/

int dissect_gsm_map_AddressString(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_SecurityHeader(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_ProtectedPayload(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_ExtensionContainer(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);

/*--- End of included file: packet-gsm_map-exp.h ---*/


#endif  /* PACKET_GSM_MAP_H */
