/* irda-appl.h
 * Interface for IrDA application dissectors
 * By Jan Kiszka <jan.kiszka@web.de>
 * Copyright 2003 Jan Kiszka
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#ifndef __IRDA_APPL_H__
#define __IRDA_APPL_H__

/*
 * Prototypes, defines, and typedefs needed for implementing IrDA application
 * layer dissectors.
 * There should be no need to modify this part.
 */

/* LM-IAS Attribute types */
#define IAS_MISSING         0
#define IAS_INTEGER         1
#define IAS_OCT_SEQ         2
#define IAS_STRING          3

/* Maximum number of handled list entries of an IAP result */
#define MAX_IAP_ENTRIES     32


typedef enum {
    CONNECT_PDU,
    DISCONNECT_PDU,
    DATA_PDU
} pdu_type_t;

typedef bool (*ias_value_dissector_t)(tvbuff_t* tvb, unsigned offset, packet_info* pinfo, proto_tree* tree,
                                          unsigned list_index, uint8_t attr_type, uint8_t circuit_id);

typedef const struct ias_attr_dissector {
    const char*             attr_name;
    ias_value_dissector_t   value_dissector;
} ias_attr_dissector_t;

typedef const struct ias_class_dissector {
    const char*             class_name;
    ias_attr_dissector_t*   pattr_dissector;
} ias_class_dissector_t;


extern bool check_iap_octet_result(tvbuff_t* tvb, proto_tree* tree, unsigned offset,
                                       const char* attr_name, uint8_t attr_type);
extern uint8_t check_iap_lsap_result(tvbuff_t* tvb, proto_tree* tree, unsigned offset,
                                    const char* attr_name, uint8_t attr_type);

extern void add_lmp_conversation(packet_info* pinfo, uint8_t dlsap, bool ttp, dissector_handle_t dissector, uint8_t circuit_id);

extern unsigned dissect_param_tuple(tvbuff_t* tvb, proto_tree* tree, unsigned offset);

/*
 * Protocol exports.
 * Modify the lines below to add new protocols.
 */

/* IrCOMM/IrLPT protocol */
extern void proto_register_ircomm(void);
extern ias_attr_dissector_t ircomm_attr_dissector[];
extern ias_attr_dissector_t irlpt_attr_dissector[];

/* Serial Infrared (SIR) */
extern void proto_register_irsir(void);


/*
 * Protocol hooks
 */

/* IAS class dissectors */
#define CLASS_DISSECTORS                                    \
    { "Device",         device_attr_dissector },            \
    { "IrDA:IrCOMM",    ircomm_attr_dissector },            \
    { "IrLPT",          irlpt_attr_dissector },             \
    { NULL,             NULL }

#endif /* __IRDA_APPL_H__ */
