/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-e2ap.h                                                              */
/* asn2wrs.py -p e2ap -c ./e2ap.cnf -s ./packet-e2ap-template -D . -O ../.. E2AP-CommonDataTypes.asn E2AP-Constants.asn E2AP-Containers.asn E2AP-IEs.asn E2AP-PDU-Contents.asn E2AP-PDU-Descriptions.asn e2sm-kpm-v1.asn */

/* Input file: packet-e2ap-template.h */

#line 1 "./asn1/e2ap/packet-e2ap-template.h"
/* packet-e2ap.h
 * Routines for NG-RAN NG Application Protocol (NGAP) packet dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_E2AP_H
#define PACKET_E2AP_H


/*--- Included file: packet-e2ap-exp.h ---*/
#line 1 "./asn1/e2ap/packet-e2ap-exp.h"

/*--- End of included file: packet-e2ap-exp.h ---*/
#line 15 "./asn1/e2ap/packet-e2ap-template.h"

typedef int (*pdu_dissector_t)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);

/* Function pointers for a RANFunction */
typedef struct {
    pdu_dissector_t ran_function_definition_dissector;

    pdu_dissector_t ric_control_header_dissector;
    pdu_dissector_t ric_control_message_dissector;
    pdu_dissector_t ric_control_outcome_dissector;
    /* new for v3 */
    pdu_dissector_t ric_query_outcome_dissector;
    pdu_dissector_t ric_query_definition_dissector;
    pdu_dissector_t ric_query_header_dissector;

    pdu_dissector_t ran_action_definition_dissector;
    pdu_dissector_t ran_indication_message_dissector;
    pdu_dissector_t ran_indication_header_dissector;
    pdu_dissector_t ran_callprocessid_dissector;
    pdu_dissector_t ran_event_trigger_dissector;
} ran_function_pointers_t;

typedef enum {
    MIN_RANFUNCTIONS,
    KPM_RANFUNCTIONS=0,
    RC_RANFUNCTIONS,
    NI_RANFUNCTIONS,
    CCC_RANFUNCTIONS,
    MAX_RANFUNCTIONS
} ran_function_t;

#define MAX_OID_LEN 1001

typedef struct {
    const char* name;
    char        oid[MAX_OID_LEN];                /* i.e., this dissector */
    uint8_t     major_version;                   /* these are currently not used.. */
    uint8_t     minor_version;
    ran_function_pointers_t functions;
} ran_function_dissector_t;

void register_e2ap_ran_function_dissector(ran_function_t ran_function, ran_function_dissector_t *dissector);

void e2ap_store_ran_function_mapping(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, const char *name);
void e2ap_update_ran_function_mapping(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, const char *oid);


#endif  /* PACKET_E2AP_H */

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
