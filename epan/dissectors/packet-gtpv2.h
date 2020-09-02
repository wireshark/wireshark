/* packet-gtpv2.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <epan/dissectors/packet-gtp.h>

extern void dissect_gtpv2_mbms_service_area(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_, session_args_t * args _U_);
extern void dissect_gtpv2_mbms_session_duration(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_, session_args_t * args _U_);
extern void dissect_gtpv2_mbms_time_to_data_xfer(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_, session_args_t * args _U_);
extern void dissect_gtpv2_arp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_, session_args_t * args _U_);
extern void dissect_gtpv2_fq_csid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_, session_args_t * args _U_);
extern void dissect_gtpv2_selec_mode(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_, session_args_t * args _U_);
extern void dissect_gtpv2_epc_timer(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_, session_args_t * args _U_);
extern void dissect_gtpv2_twan_identifier(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_, session_args_t * args _U_);
/*Used by custom dissector*/
extern gchar* dissect_gtpv2_tai(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset);
extern void dissect_gtpv2_uli(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, guint8 instance _U_, session_args_t * args _U_);
extern void dissect_gtpv2_pdn_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, guint8 instance _U_, session_args_t * args _U_);

extern value_string_ext gtpv2_cause_vals_ext;

typedef struct _gtpv2_priv_ext_info {
    guint8 instance;
    proto_item *item;
} gtpv2_priv_ext_info_t;
