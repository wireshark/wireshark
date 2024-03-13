/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-f1ap.h                                                              */
/* asn2wrs.py -q -L -p f1ap -c ./f1ap.cnf -s ./packet-f1ap-template -D . -O ../.. F1AP-CommonDataTypes.asn F1AP-Constants.asn F1AP-Containers.asn F1AP-IEs.asn F1AP-PDU-Contents.asn F1AP-PDU-Descriptions.asn */

/* packet-f1ap.h
 * Routines for E-UTRAN F1 Application Protocol (F1AP) packet dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_F1AP_H
#define PACKET_F1AP_H

int dissect_f1ap_NRPRACHConfig_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

#endif  /* PACKET_F1AP_H */

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
