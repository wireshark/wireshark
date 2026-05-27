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


/**
 * @brief Protocol Data Unit (PDU) type for a connection-oriented protocol message.
 */
typedef enum {
    CONNECT_PDU,    /**< Connection establishment PDU */
    DISCONNECT_PDU, /**< Connection teardown PDU */
    DATA_PDU        /**< Data transfer PDU */
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


/**
 * @brief Checks if an IAP attribute is an octet sequence.
 *
 * @param tvb The TVB buffer containing the data to be dissected.
 * @param tree The protocol tree where the item will be added.
 * @param offset The current offset in the TVB buffer.
 * @param attr_name The name of the attribute being checked.
 * @param attr_type The type of the attribute being checked.
 * @return true if the attribute is an octet sequence, false otherwise.
 */
extern bool check_iap_octet_result(tvbuff_t* tvb, proto_tree* tree, unsigned offset,
                                       const char* attr_name, uint8_t attr_type);

/**
 * @brief Checks if the IAP LSAP result is valid.
 *
 * This function verifies that the given LSAP (Logical Service Access Point) value
 * is within the valid range for IAP (IrDA Application Protocol). If the value is
 * invalid, it adds an error item to the protocol tree and returns 0. Otherwise,
 * it returns the valid LSAP value.
 *
 * @param tvb The TVB buffer containing the data to be dissected.
 * @param tree The protocol tree where the error item will be added if necessary.
 * @param offset The current offset within the TVB buffer.
 * @param attr_name The name of the attribute being checked.
 * @param attr_type The type of the attribute being checked.
 * @return The valid LSAP value if it is within the range, otherwise 0.
 */
extern uint8_t check_iap_lsap_result(tvbuff_t* tvb, proto_tree* tree, unsigned offset,
                                    const char* attr_name, uint8_t attr_type);

/**
 * @brief Adds an LMP conversation to the Wireshark conversation list.
 *
 * This function creates a new LMP (Logical Link Management Protocol) conversation
 * based on the provided parameters and adds it to the Wireshark conversation list.
 *
 * @param pinfo Pointer to the packet information structure.
 * @param dlsap Destination Logical Link Service Access Point identifier.
 * @param ttp Indicates if TTP (Transport Transport Protocol) is used.
 * @param dissector Handle to the dissector for this protocol.
 * @param circuit_id Circuit ID used in the conversation.
 */
extern void add_lmp_conversation(packet_info* pinfo, uint8_t dlsap, bool ttp, dissector_handle_t dissector, uint8_t circuit_id);

/**
 * @brief Dissects a parameter tuple from an IRDA packet.
 *
 * @param tvb The TVB buffer containing the packet data.
 * @param tree The protocol tree to add items to.
 * @param offset The current offset within the TVB buffer.
 * @return The new offset after dissecting the parameter tuple.
 */
extern unsigned dissect_param_tuple(tvbuff_t* tvb, proto_tree* tree, unsigned offset);

/*
 * Protocol exports.
 * Modify the lines below to add new protocols.
 */

/* IrCOMM/IrLPT protocol */

/**
 * @brief Registers the IrCOMM protocol with Wireshark.
 *
 * This function sets up the header fields and dissector tables for the IrCOMM protocol.
 */
extern void proto_register_ircomm(void);
extern ias_attr_dissector_t ircomm_attr_dissector[];
extern ias_attr_dissector_t irlpt_attr_dissector[];

/* Serial Infrared (SIR) */

/**
 * @brief Registers the IR-SIR protocol dissector.
 *
 * This function registers the IR-SIR protocol dissector with Wireshark.
 */
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
