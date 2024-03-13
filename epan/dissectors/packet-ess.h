/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-ess.h                                                               */
/* asn2wrs.py -b -k -C -q -L -p ess -c ./ess.cnf -s ./packet-ess-template -D . -O ../.. ExtendedSecurityServices.asn */

/* packet-ess.h
 * Routines for RFC5035 Extended Security Services packet dissection
 *    Ronnie Sahlberg 2004
 *    Stig Bjorlykke 2010
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_ESS_H
#define PACKET_ESS_H

int dissect_ess_ESSSecurityLabel_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

#endif  /* PACKET_ESS_H */

