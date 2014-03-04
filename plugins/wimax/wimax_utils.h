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

#include <glib.h>
#include <epan/packet.h>

extern guint get_service_type(void);
extern void wimax_service_flow_encodings_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void wimax_convengence_service_parameter_encoding_rules_decoder(guint sfe_type, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
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
