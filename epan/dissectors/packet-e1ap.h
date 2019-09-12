/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-e1ap.h                                                              */
/* asn2wrs.py -p e1ap -c ./e1ap.cnf -s ./packet-e1ap-template -D . -O ../.. E1AP-CommonDataTypes.asn E1AP-Constants.asn E1AP-Containers.asn E1AP-IEs.asn E1AP-PDU-Contents.asn E1AP-PDU-Descriptions.asn */

/* Input file: packet-e1ap-template.h */

#line 1 "./asn1/e1ap/packet-e1ap-template.h"
/* packet-e1ap.h
 * Routines for E-UTRAN E1 Application Protocol (E1AP) packet dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_E1AP_H
#define PACKET_E1AP_H

typedef struct {
    guint32 message_type;
    guint32 ProcedureCode;
    guint32 ProtocolIE_ID;
    guint32 ProtocolExtensionID;
} e1ap_ctx_t;



/*--- Included file: packet-e1ap-exp.h ---*/
#line 1 "./asn1/e1ap/packet-e1ap-exp.h"

/*--- End of included file: packet-e1ap-exp.h ---*/
#line 23 "./asn1/e1ap/packet-e1ap-template.h"

#endif  /* PACKET_E1AP_H */

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
