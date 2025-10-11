/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-HI2Operations.h                                                     */
/* asn2wrs.py -b -q -L -p HI2Operations -c ./HI2Operations.cnf -s ./packet-HI2Operations-template -D . -O ../.. HI2Operations_ver18.asn HI3CCLinkData.asn EpsHI2Operations.asn UmtsHI2Operations.asn */

/* packet-HI2Operations.h
 * Routines for HI2 (ETSI TS 101 671 V3.15.1 (2018-06))
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_HI2OPERATIONS_H
#define PACKET_HI2OPERATIONS_H

#define lawfulInterceptDomainId        "0.4.0.2.2"
#define hi2DomainId                    lawfulInterceptDomainId".1"
#define hi2OperationId                 hi2DomainId".18"
#define maxNrOfPoints                  15
#define hi3CCLinkId                    lawfulInterceptDomainId".2.4"
#define hi3CCLinkIdOperationId         hi3CCLinkId".4"
#define threeGPPSUBDomainId            lawfulInterceptDomainId".4"
#define hi2epsDomainId                 threeGPPSUBDomainId".8.16.1"

#endif  /* PACKET_HI2OPERATIONS_H */
