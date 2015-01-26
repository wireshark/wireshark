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
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef WIMAX_UTILS_H
#define WIMAX_UTILS_H

#include <epan/packet.h>

extern void dissect_extended_tlv(proto_tree *reg_req_tree, gint tlv_type, tvbuff_t *tvb, guint tlv_offset, guint tlv_len, packet_info *pinfo, guint offset, gint proto_registry);
extern void dissect_power_saving_class(proto_tree *rng_req_tree, gint tlv_type, tvbuff_t *tvb, guint  compound_tlv_len, packet_info *pinfo, guint offset);
extern gint dissect_ulmap_ie(proto_tree *ie_tree, packet_info* pinfo, gint offset, gint length, tvbuff_t *tvb);
extern guint get_service_type(void);
extern void init_wimax_globals(void); /* defined in msg_ulmap.c */
extern gboolean is_down_link(packet_info *pinfo);
extern gint RCID_IE(proto_tree *diuc_tree, gint offset, gint length, tvbuff_t *tvb, gint RCID_Type);
extern void wimax_service_flow_encodings_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void wimax_convengence_service_parameter_encoding_rules_decoder(guint sfe_type, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern gint wimax_decode_ulmapc(proto_tree *base_tree, packet_info* pinfo, gint offset, gint length, tvbuff_t *tvb);
extern gint wimax_decode_ulmap_reduced_aas(proto_tree *ie_tree, gint offset, gint length, tvbuff_t *tvb);
extern gint wimax_decode_dlmapc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pdu_tree);
extern gint wimax_decode_dlmap_reduced_aas(tvbuff_t *tvb, packet_info *pinfo, proto_tree *base_tree);
extern void wimax_error_parameter_set_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void wimax_hmac_tuple_decoder(proto_tree *tree, tvbuff_t *tvb, guint offset, guint length);
extern void wimax_cmac_tuple_decoder(proto_tree *tree, tvbuff_t *tvb, guint offset, guint length);
extern void wimax_short_hmac_tuple_decoder(proto_tree *tree, tvbuff_t *tvb, guint offset, guint length);
extern void wimax_security_negotiation_parameters_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void wimax_tek_parameters_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void wimax_pkm_configuration_settings_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void wimax_sa_descriptor_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void wimax_pkm_tlv_encoded_attributes_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void wimax_cryptographic_suite_list_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void wimax_security_capabilities_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void wimax_vendor_specific_information_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern guint wimax_common_tlv_encoding_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

#endif /* WIMAX_UTILS_H */
