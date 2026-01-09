/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-charging_ase.h                                                      */
/* asn2wrs.py -b -q -L -p charging_ase -c ./charging_ase.cnf -s ./packet-charging_ase-template -D . -O ../.. Tariffing-Data-Types.asn */

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

#define minSubTariffControlLen         1
#define maxSubTariffControlLen         8
#define minAcknowledgementIndicatorsLen 1
#define maxAcknowledgementIndicatorsLen 8
#define minChargingControlIndicatorsLen 1
#define maxChargingControlIndicatorsLen 8
#define maxNetworkOperators            6
#define minStopIndicatorsLen           1
#define maxStopIndicatorsLen           8
#define minTariffIndicatorsLen         1
#define maxTariffIndicatorsLen         8
#define minCommunicationTariffNum      1
#define maxCommunicationTariffNum      4
#define noCharge                       0
#define noScale                        0
#define numOfExtensions                1

#include <epan/asn1.h>

extern const value_string charging_ase_ChargingMessageType_vals[];
unsigned dissect_charging_ase_ChargingMessageType(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_charging_ase_ChargingMessageType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

#endif  /* PACKET_CHARGING_ASE_H */
