/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-charging_ase.h                                                      */
/* asn2wrs.py -b -p charging_ase -c ./charging_ase.cnf -s ./packet-charging_ase-template -D . -O ../.. Tariffing-Data-Types.asn */

/* Input file: packet-charging_ase-template.h */

#line 1 "./asn1/charging_ase/packet-charging_ase-template.h"
/* packet-charging_ase-template.h
 * Copyright 2009, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_CHARGING_ASE_H
#define PACKET_CHARGING_ASE_H


/*--- Included file: packet-charging_ase-exp.h ---*/
#line 1 "./asn1/charging_ase/packet-charging_ase-exp.h"
extern const value_string charging_ase_ChargingMessageType_vals[];
int dissect_charging_ase_ChargingMessageType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_charging_ase_ChargingMessageType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

/*--- End of included file: packet-charging_ase-exp.h ---*/
#line 15 "./asn1/charging_ase/packet-charging_ase-template.h"

#endif  /* PACKET_CHARGING_ASE_H */
