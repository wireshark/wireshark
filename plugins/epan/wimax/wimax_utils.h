/* wimax_utils.h
 * Header file of WiMax Utility Decoders
 *
 * Copyright (c) 2007 by Intel Corporation.
 *
 * Author: Lu Pan <lu.pan@intel.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef WIMAX_UTILS_H
#define WIMAX_UTILS_H

#include <epan/packet.h>
#include <epan/unit_strings.h>

#include <wsutil/array.h>

/**
 * @brief Dissects an extended TLV in a WiMAX registration request.
 *
 * @param reg_req_tree The protocol tree for the registration request.
 * @param tlv_type The type of the TLV to dissect.
 * @param tvb The TVB containing the data to dissect.
 * @param tlv_offset The offset of the TLV within the TVB.
 * @param tlv_len The length of the TLV.
 * @param pinfo Packet information.
 * @param offset The current offset within the TVB.
 * @param proto_registry Protocol registry.
 */
extern void dissect_extended_tlv(proto_tree *reg_req_tree, int tlv_type, tvbuff_t *tvb, unsigned tlv_offset, unsigned tlv_len, packet_info *pinfo, unsigned offset, int proto_registry);

/**
 * @brief Dissects the power saving class parameters.
 *
 * @param rng_req_tree The protocol tree for the range request message.
 * @param tlv_type The type of the TLV.
 * @param tvb The TVB containing the data to dissect.
 * @param compound_tlv_len The length of the compound TLV.
 * @param pinfo The packet information structure.
 * @param offset The current offset in the TVB.
 */
extern void dissect_power_saving_class(proto_tree *rng_req_tree, int tlv_type, tvbuff_t *tvb, unsigned  compound_tlv_len, packet_info *pinfo, unsigned offset);

/**
 * @brief Dissects a single UL-MAP IE from the packet buffer.
 *
 * @param ie_tree The protocol tree to add the dissected information to.
 * @param pinfo The packet information structure.
 * @param offset The offset in bits where the UL-MAP IE starts.
 * @param length The length of the UL-MAP IE in bits.
 * @param tvb The TVB containing the packet data.
 * @return The length of the dissected UL-MAP IE in nibbles.
 */
extern int dissect_ulmap_ie(proto_tree *ie_tree, packet_info* pinfo, int offset, int length, tvbuff_t *tvb);

/**
 * @brief Retrieves the current service type.
 *
 * @return The current scheduling service type.
 */
extern unsigned get_service_type(void);

/**
 * @brief Initializes the global WiMax variables.
 */
extern void init_wimax_globals(void); /* defined in msg_ulmap.c */

/**
 * @brief Determines if the packet is a downlink.
 *
 * @param pinfo Pointer to the packet information structure.
 * @return true if the packet is a downlink, false otherwise.
 */
extern bool is_down_link(packet_info *pinfo);

/**
 * @brief Decodes the RCID IE (Radio Channel Identifier Information Element).
 *
 * @param diuc_tree The parent protocol tree.
 * @param offset The offset of the IE in bits.
 * @param length The length of the IE in bits.
 * @param tvb The TVB buffer containing the packet data.
 * @param RCID_Type The type of RCID to decode.
 * @return The result of the decoding process.
 */
extern int RCID_IE(proto_tree *diuc_tree, int offset, int length, tvbuff_t *tvb, int RCID_Type);

/**
 * @brief Decodes and displays WiMax Service Flow Encodings.
 *
 * @param tvb Pointer to the TVB containing the service flow encodings data.
 * @param pinfo Pointer to the packet information structure.
 * @param tree Pointer to the protocol tree for displaying the decoded information.
 */
extern void wimax_service_flow_encodings_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/**
 * @brief Decodes and displays the WiMax Convergence Service Parameter Encoding Rules.
 *
 * @param sfe_type The Service Flow Encodings type.
 * @param tvb The TVB buffer containing the data to decode.
 * @param pinfo Packet information structure.
 * @param tree The protocol tree to add the decoded information to.
 */
extern void wimax_convengence_service_parameter_encoding_rules_decoder(unsigned sfe_type, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/**
 * @brief Decodes and displays the WiMax UL-MAP compressed format.
 *
 * @param base_tree The protocol tree to add the decoded information to.
 * @param pinfo Packet information structure.
 * @param offset Offset within the TVB where decoding should start.
 * @param length Length of the data to decode in bytes.
 * @param tvb The TVB containing the data to decode.
 * @return Length of the decoded data in nibbles.
 */
extern int wimax_decode_ulmapc(proto_tree *base_tree, packet_info* pinfo, int offset, int length, tvbuff_t *tvb);

/**
 * @brief Decodes and displays the Reduced AAS private UL-MAP.
 *
 * @param ie_tree Pointer to the protocol tree.
 * @param offset Offset in bits.
 * @param length Length in bits.
 * @param tvb Pointer to the TVB containing the data.
 * @return Length in bits.
 */
extern int wimax_decode_ulmap_reduced_aas(proto_tree *ie_tree, int offset, int length, tvbuff_t *tvb);

/**
 * @brief Decode a compressed DL-MAP and optionally an associated UL-MAP.
 *
 * @param tvb Pointer to the TVB containing the data to decode.
 * @param pinfo Pointer to the packet information structure.
 * @param pdu_tree Pointer to the protocol tree for the base message.
 * @return The length of the decoded data in bytes.
 */
extern int wimax_decode_dlmapc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pdu_tree);

/**
 * @brief Decodes and displays the WiMax DL-MAP reduced AAS.
 *
 * @param tvb The TVB containing the data to decode.
 * @param pinfo Packet information structure.
 * @param base_tree The protocol tree to add the decoded information to.
 */
extern int wimax_decode_dlmap_reduced_aas(tvbuff_t *tvb, packet_info *pinfo, proto_tree *base_tree);

/**
 * @brief Decode and display the WiMax Error Parameter Set.
 *
 * @param tvb Pointer to the TVB containing the error parameter set data.
 * @param pinfo Pointer to the packet information structure.
 * @param tree Pointer to the protocol tree for displaying the decoded information.
 */
extern void wimax_error_parameter_set_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/**
 * @brief Decode and display the WiMax HMAC Tuple.
 *
 * @param tree Pointer to the Wireshark display tree.
 * @param tvb Pointer to the TVB containing the data.
 * @param offset Offset of the HMAC Tuple in the TVB.
 * @param length Length of the HMAC Tuple.
 */
extern void wimax_hmac_tuple_decoder(proto_tree *tree, tvbuff_t *tvb, unsigned offset, unsigned length);

/**
 * @brief Decode and display the CMAC Tuple.
 *
 * @param tree Pointer to the Wireshark display tree.
 * @param tvb Pointer to the TVB containing the data.
 * @param offset Offset within the TVB where the CMAC Tuple starts.
 * @param length Length of the CMAC Tuple in bytes.
 */
extern void wimax_cmac_tuple_decoder(proto_tree *tree, tvbuff_t *tvb, unsigned offset, unsigned length);

/**
 * @brief Decode and display the Short HMAC Tuple.
 *
 * @param tree Pointer to the Wireshark display tree.
 * @param tvb Pointer to the TVB containing the data.
 * @param offset Offset within the TVB where the Short HMAC Tuple starts.
 * @param length Length of the Short HMAC Tuple in bytes.
 */
extern void wimax_short_hmac_tuple_decoder(proto_tree *tree, tvbuff_t *tvb, unsigned offset, unsigned length);

/**
 * @brief Decode and display the WiMax Security Negotiation Parameters.
 *
 * @param tvb Pointer to the TVB of service flow encodings.
 * @param pinfo Pointer to the packet information structure.
 * @param tree Pointer to the protocol tree.
 */
extern void wimax_security_negotiation_parameters_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/**
 * @brief Decode and display the WiMax TEK Parameters.
 *
 * @param tvb Pointer to the TVB of service flow encodings.
 * @param pinfo Pointer to the packet information structure.
 * @param tree Pointer to the protocol tree.
 */
extern void wimax_tek_parameters_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/**
 * @brief Decode and display the WiMax PKM Configuration Settings.
 *
 * @param tvb Pointer to the TVB of service flow encodings.
 * @param pinfo Pointer to the packet information structure.
 * @param tree Pointer to the protocol tree.
 */
extern void wimax_pkm_configuration_settings_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/**
 * @brief Decode and display the WiMax PKM message SA-Descriptor.
 *
 * @param tvb Pointer to the TVB of service flow encodings.
 * @param pinfo Pointer to the packet information structure.
 * @param tree Pointer to the protocol tree.
 */
extern void wimax_sa_descriptor_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/**
 * @brief Decodes and displays the WiMax PKM TLV Encoded Attributes.
 *
 * @param tvb Pointer to the TVB containing the data to be decoded.
 * @param pinfo Pointer to the packet information structure.
 * @param tree Pointer to the protocol tree where the decoded information will be added.
 */
extern void wimax_pkm_tlv_encoded_attributes_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/**
 * @brief Decodes and displays the WiMax Cryptographic Suite List.
 *
 * @param tvb Pointer to the TVB containing the data to be decoded.
 * @param pinfo Pointer to the packet information structure.
 * @param tree Pointer to the protocol tree where the decoded information will be added.
 */
extern void wimax_cryptographic_suite_list_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/**
 * @brief Decodes and displays WiMax Security Capabilities.
 *
 * @param tvb Pointer to the TVB containing the data to be decoded.
 * @param pinfo Pointer to the packet information structure.
 * @param tree Pointer to the protocol tree where the decoded information will be added.
 */
extern void wimax_security_capabilities_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/**
 * @brief Decodes and displays the WiMax Vendor Specific Information.
 *
 * @param tvb Pointer to the TVB containing the data to be decoded.
 * @param pinfo Pointer to the packet information structure.
 * @param tree Pointer to the protocol tree where the decoded information will be added.
 */
extern void wimax_vendor_specific_information_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/**
 * @brief Decodes and displays the WiMax Common TLV Encoding.
 *
 * @param tvb Pointer to the TVB of service flow encodings.
 * @param pinfo Pointer to the packet information.
 * @param tree Pointer to the protocol tree.
 * @return unsigned The number of bytes processed.
 */
extern unsigned wimax_common_tlv_encoding_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

//Windows can't handle plugins using globals from epan, so copies are necessary
extern const unit_name_string wimax_units_byte_bytes;
extern const unit_name_string wimax_units_bit_sec;
extern const unit_name_string wimax_units_db;
extern const unit_name_string wimax_units_dbm;
extern const unit_name_string wimax_units_frame_frames;
extern const unit_name_string wimax_units_frame_offset;
extern const unit_name_string wimax_units_hz;
extern const unit_name_string wimax_units_khz;
extern const unit_name_string wimax_units_ms;
extern const unit_name_string wimax_units_ps;

#endif /* WIMAX_UTILS_H */
