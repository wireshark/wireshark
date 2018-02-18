/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-t124.h                                                              */
/* asn2wrs.py -p t124 -c ./t124.cnf -s ./packet-t124-template -D . -O ../.. GCC-PROTOCOL.asn ../t125/MCS-PROTOCOL.asn */

/* Input file: packet-t124-template.h */

#line 1 "./asn1/t124/packet-t124-template.h"
/* packet-t124.h
 * Routines for t124 packet dissection
 * Copyright 2010, Graeme Lunt
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_T124_H
#define PACKET_T124_H

#include <epan/packet_info.h>
#include <epan/dissectors/packet-per.h>

extern int dissect_DomainMCSPDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_);
extern guint32 t124_get_last_channelId(void);
extern void t124_set_top_tree(proto_tree *tree);

extern void register_t124_ns_dissector(const char *nsKey, dissector_t dissector, int proto);
extern void register_t124_sd_dissector(packet_info *pinfo, guint32 channelId, dissector_t dissector, int proto);


/*--- Included file: packet-t124-exp.h ---*/
#line 1 "./asn1/t124/packet-t124-exp.h"
extern const value_string t124_ConnectGCCPDU_vals[];
int dissect_t124_ConnectData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_t124_ConnectGCCPDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/*--- End of included file: packet-t124-exp.h ---*/
#line 26 "./asn1/t124/packet-t124-template.h"

#endif  /* PACKET_T124_H */


