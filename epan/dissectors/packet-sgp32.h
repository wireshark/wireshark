/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-sgp32.h                                                             */
/* asn2wrs.py -b -q -L -p sgp32 -c ./sgp32.cnf -s ./packet-sgp32-template -D . -O ../.. SGP32Definitions.asn */

/* packet-sgp32.h
 * Routines for SGP.32 packet dissection.
 *
 * Copyright 2025, Stig Bjorlykke <stig@bjorlykke.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_SGP32_H
#define PACKET_SGP32_H

bool is_sgp32_request(tvbuff_t *tvb);
bool is_sgp32_response(tvbuff_t *tvb);

int dissect_sgp32_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
int dissect_sgp32_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);


#endif  /* PACKET_SGP32_H */
