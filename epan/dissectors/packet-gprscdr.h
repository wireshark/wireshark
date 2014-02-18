/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-gprscdr.h                                                           */
/* ../../tools/asn2wrs.py -b -p gprscdr -c ./gprscdr.cnf -s ./packet-gprscdr-template -D . -O ../../epan/dissectors GenericChargingDataTypesV1171.asn GPRSChargingDataTypesV641.asn GPRSChargingDataTypesV1171.asn */

/* Input file: packet-gprscdr-template.h */

#line 1 "../../asn1/gprscdr/packet-gprscdr-template.h"
/* packet-gprscdr.h
 * Routines for gprscdr packet dissection
 * Copyright 2011, Anders Broman <anders.broman@ericsson.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef PACKET_GPRSCDR_H
#define PACKET_GPRSCDR_H



/*--- Included file: packet-gprscdr-exp.h ---*/
#line 1 "../../asn1/gprscdr/packet-gprscdr-exp.h"
extern const value_string gprscdr_GPRSCallEventRecord_vals[];
extern const value_string gprscdr_GPRSRecord_vals[];
int dissect_gprscdr_GPRSCallEventRecord(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gprscdr_GPRSRecord(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_gprscdr_GPRSCallEventRecord_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_gprscdr_GPRSRecord_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

/*--- End of included file: packet-gprscdr-exp.h ---*/
#line 29 "../../asn1/gprscdr/packet-gprscdr-template.h"

#endif  /* PACKET_GPRSCDR_H */


