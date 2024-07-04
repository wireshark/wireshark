/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-lppa.h                                                              */
/* asn2wrs.py -q -L -p lppa -c ./lppa.cnf -s ./packet-lppa-template -D . -O ../.. LPPA-CommonDataTypes.asn LPPA-Constants.asn LPPA-Containers.asn LPPA-IEs.asn LPPA-PDU-Contents.asn LPPA-PDU-Descriptions.asn */

/* packet-lppa.h
 * Routines for 3GPP LTE Positioning Protocol A (LLPa) packet dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_LPPA_H
#define PACKET_LPPA_H

typedef struct _lppa_ctx_t {
  uint32_t message_type;
  uint32_t ProcedureCode;
  uint32_t ProtocolIE_ID;
  uint32_t ProtocolExtensionID;
} lppa_ctx_t;



#endif  /* PACKET_LPPA_H */

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
