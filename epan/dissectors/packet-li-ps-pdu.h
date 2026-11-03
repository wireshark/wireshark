/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-li-ps-pdu.h                                                         */
/* asn2wrs.py -b -q -L -p li-ps-pdu -c ./li-ps-pdu.cnf -s ./packet-li-ps-pdu-template -D . -O ../.. LI-PS-PDU.asn IPAccessPDU.asn Common-Parameters.asn */

/* packet-li-ps-pdu-template.h
 * Routines for ETSI TS 102 232-1 LI-PS-PDU dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_LI_PS_PDU_H
#define PACKET_LI_PS_PDU_H

#include <epan/asn1.h>

unsigned dissect_li_ps_pdu_IPIRIPacketReport(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

#endif  /* PACKET_LI_PS_PDU_H */
