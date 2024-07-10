/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-nrppa.h                                                             */
/* asn2wrs.py -q -L -p nrppa -c ./nrppa.cnf -s ./packet-nrppa-template -D . -O ../.. NRPPA-CommonDataTypes.asn NRPPA-Constants.asn NRPPA-Containers.asn NRPPA-PDU-Descriptions.asn NRPPA-IEs.asn NRPPA-PDU-Contents.asn */

/* packet-nrppa.h
 * Routines for 3GPP NR Positioning Protocol A (NRPPa) packet dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_NRPPA_H
#define PACKET_NRPPA_H

int dissect_nrppa_Assistance_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_nrppa_SRSConfiguration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

#endif  /* PACKET_NRPPA_H */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
