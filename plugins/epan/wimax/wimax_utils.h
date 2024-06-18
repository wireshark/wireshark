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

extern void dissect_extended_tlv(proto_tree *reg_req_tree, int tlv_type, tvbuff_t *tvb, unsigned tlv_offset, unsigned tlv_len, packet_info *pinfo, unsigned offset, int proto_registry);
extern void dissect_power_saving_class(proto_tree *rng_req_tree, int tlv_type, tvbuff_t *tvb, unsigned  compound_tlv_len, packet_info *pinfo, unsigned offset);
extern int dissect_ulmap_ie(proto_tree *ie_tree, packet_info* pinfo, int offset, int length, tvbuff_t *tvb);
extern unsigned get_service_type(void);
extern void init_wimax_globals(void); /* defined in msg_ulmap.c */
extern bool is_down_link(packet_info *pinfo);
extern int RCID_IE(proto_tree *diuc_tree, int offset, int length, tvbuff_t *tvb, int RCID_Type);
extern void wimax_service_flow_encodings_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void wimax_convengence_service_parameter_encoding_rules_decoder(unsigned sfe_type, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern int wimax_decode_ulmapc(proto_tree *base_tree, packet_info* pinfo, int offset, int length, tvbuff_t *tvb);
extern int wimax_decode_ulmap_reduced_aas(proto_tree *ie_tree, int offset, int length, tvbuff_t *tvb);
extern int wimax_decode_dlmapc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pdu_tree);
extern int wimax_decode_dlmap_reduced_aas(tvbuff_t *tvb, packet_info *pinfo, proto_tree *base_tree);
extern void wimax_error_parameter_set_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void wimax_hmac_tuple_decoder(proto_tree *tree, tvbuff_t *tvb, unsigned offset, unsigned length);
extern void wimax_cmac_tuple_decoder(proto_tree *tree, tvbuff_t *tvb, unsigned offset, unsigned length);
extern void wimax_short_hmac_tuple_decoder(proto_tree *tree, tvbuff_t *tvb, unsigned offset, unsigned length);
extern void wimax_security_negotiation_parameters_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void wimax_tek_parameters_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void wimax_pkm_configuration_settings_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void wimax_sa_descriptor_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void wimax_pkm_tlv_encoded_attributes_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void wimax_cryptographic_suite_list_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void wimax_security_capabilities_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void wimax_vendor_specific_information_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
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
