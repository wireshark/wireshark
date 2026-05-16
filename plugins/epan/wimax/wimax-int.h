/* wimax-int.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WIMAX_INT_H__
#define __WIMAX_INT_H__

extern int proto_wimax;

extern bool first_gmh;                  /* defined in wimax_pdu_decoder.c */

extern int8_t arq_enabled;                      /* declared in packet-wmx.c */
extern int   scheduling_service_type;           /* declared in packet-wmx.c */
extern int   mac_sdu_length;                    /* declared in packet-wmx.c */

extern address bs_address;                      /* declared in packet-wmx.c */
extern unsigned max_logical_bands;              /* declared in wimax_compact_dlmap_ie_decoder.c */

/**
 * @brief Registers WiMAX CDMA protocol.
 */
void wimax_proto_register_wimax_cdma(void);

/**
 * @brief Registers WiMAX Compact DL-MAP IE protocol.
 */
void wimax_proto_register_wimax_compact_dlmap_ie(void);

/**
 * @brief Registers WiMAX Compact UL-MAP IE protocol.
 */
void wimax_proto_register_wimax_compact_ulmap_ie(void);

/**
 * @brief Registers WiMAX FCH (Forward Channel Header) protocol.
 */
void wimax_proto_register_wimax_fch(void);

/**
 * @brief Registers WiMAX FFB protocol.
 */
void wimax_proto_register_wimax_ffb(void);

/**
 * @brief Registers various WiMAX protocol decoders and handlers.
 *
 * This function registers several key components for decoding WiMAX protocols,
 * including compact UL-MAP IE, HARQ map, PDU, PHY attributes, utility decoders,
 * and MAC header generic.
 */
void wimax_proto_register_wimax_hack(void);

/**
 * @brief Registers WiMAX FCH (Forward Channel Header) protocol decoders.
 *
 * This function registers various fields and dissectors for the WiMAX Forward Channel Header.
 */
void wimax_proto_register_wimax_harq_map(void);

/**
 * @brief Registers the WiMAX PDU decoder.
 *
 * This function registers the necessary fields and subtrees for decoding WiMAX PDUs.
 */
void wimax_proto_register_wimax_pdu(void);

/**
 * @brief Registers the WiMAX PHY attributes decoder.
 *
 * This function registers the necessary fields and subtrees for decoding WiMAX PHY attributes.
 */
void wimax_proto_register_wimax_phy_attributes(void);

/**
 * @brief Registers various utility decoders for WiMAX protocol.
 */
void wimax_proto_register_wimax_utility_decoders(void);

/**
 * @brief Registers the WiMAX HARQ map for display.
 *
 * This function registers the fields and information associated with the WiMAX HARQ map,
 * which is used to manage Hybrid Automatic Repeat Request (HARQ) in WiMAX communications.
 */
void wimax_proto_register_mac_header_generic(void);

/**
 * @brief Registers the MAC header type 1 for WiMAX protocol.
 */
void wimax_proto_register_mac_header_type_1(void);

/**
 * @brief Registers the MAC header type 2 display information.
 *
 * This function registers the necessary fields and handlers for displaying
 * the MAC header type 2 in Wireshark.
 */
void wimax_proto_register_mac_header_type_2(void);

/**
* @brief Registers handoffs for WiMAX PDU and MAC header generic.
*
* This function registers the necessary dissector handles for WiMAX PDU and MAC header generic.
*/
void wimax_proto_reg_handoff_wimax_pdu(void);

/**
 * @brief Registers handoffs for the generic MAC header decoder.
 *
 * This function registers the necessary dissector handles for the generic MAC header decoder in Wireshark.
 * It finds and sets up the dissectors for management messages and IP traffic.
 */
void wimax_proto_reg_handoff_mac_header_generic(void);

#endif
