/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-xnap.h                                                              */
/* asn2wrs.py -p xnap -c ./xnap.cnf -s ./packet-xnap-template -D . -O ../.. XnAP-CommonDataTypes.asn XnAP-Constants.asn XnAP-Containers.asn XnAP-IEs.asn XnAP-PDU-Contents.asn XnAP-PDU-Descriptions.asn */

/* Input file: packet-xnap-template.h */

#line 1 "./asn1/xnap/packet-xnap-template.h"
/* packet-xnap.h
 * Routines for dissecting NG-RAN Xn application protocol (XnAP)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_XnAP_H
#define PACKET_XnAP_H


/*--- Included file: packet-xnap-exp.h ---*/
#line 1 "./asn1/xnap/packet-xnap-exp.h"
int dissect_xnap_IntendedTDD_DL_ULConfiguration_NR_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

/*--- End of included file: packet-xnap-exp.h ---*/
#line 15 "./asn1/xnap/packet-xnap-template.h"

#endif  /* PACKET_XnAP_H */

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
