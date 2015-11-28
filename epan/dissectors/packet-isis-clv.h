/* packet-isis-clv.h
 * Declares for common clv decoding functions.
 *
 * Stuart Stanley <stuarts@mxmail.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#ifndef _PACKET_ISIS_CLV_H
#define _PACKET_ISIS_CLV_H

/*
 * A CLV is a tuple of a type, length and a value and is normally used for
 * encoding information in all sorts of places.
 * IS-IS uses a uniform CLV code space that is shared across
 * all PDU Types.
 *
 * list taken from rfc3359 plus some memory from veterans ;-)
 *
 * http://www.iana.org/assignments/isis-tlv-codepoints/isis-tlv-codepoints.xhtml#tlv-codepoints
 */

#define ISIS_CLV_AREA_ADDRESS        1   /* iso10589 */
#define ISIS_CLV_IS_REACH            2   /* iso10589 */
#define ISIS_CLV_ES_NEIGHBORS        3   /* iso10589 */
#define ISIS_CLV_PARTITION_DIS       4   /* iso10589 */
#define ISIS_CLV_PREFIX_NEIGHBORS    5   /* iso10589 */
#define ISIS_CLV_IS_NEIGHBORS        6   /* iso10589 */
#define ISIS_CLV_INSTANCE_IDENTIFIER 7   /* rfc6822 */
#define ISIS_CLV_PADDING             8   /* iso10589 */
#define ISIS_CLV_LSP_ENTRIES         9   /* iso10589 */
#define ISIS_CLV_AUTHENTICATION      10  /* iso10589, rfc3567 */
#define ISIS_CLV_CHECKSUM            12  /* rfc3358 */
#define ISIS_CLV_LSP_BUFFERSIZE      14  /* iso10589 rev2 */
#define ISIS_CLV_EXTD_IS_REACH       22  /* draft-ietf-isis-traffic-05 */
#define ISIS_CLV_IS_ALIAS_ID         24  /* draft-ietf-isis-ext-lsp-frags-02 */
#define ISIS_CLV_INT_IP_REACH        128 /* rfc1195, rfc2966 */
#define ISIS_CLV_PROTOCOLS_SUPPORTED 129 /* rfc1195 */
#define ISIS_CLV_EXT_IP_REACH        130 /* rfc1195, rfc2966 */
#define ISIS_CLV_IDRP_INFO           131 /* rfc1195 */
#define ISIS_CLV_IP_ADDR             132 /* rfc1195 */
#define ISIS_CLV_IP_AUTHENTICATION   133 /* rfc1195, depreciated */
#define ISIS_CLV_TE_ROUTER_ID        134 /* draft-ietf-isis-traffic-05 */
#define ISIS_CLV_EXTD_IP_REACH       135 /* draft-ietf-isis-traffic-05 */
#define ISIS_CLV_HOSTNAME            137 /* rfc2763 */
#define ISIS_CLV_SHARED_RISK_GROUP   138 /* rfc5307 */
#define ISIS_GRP_ADDR                142 /* rfc7176 */
#define ISIS_CLV_MT_PORT_CAP         143 /* rfc6165, rfc7176 */
#define ISIS_CLV_MT_CAP              144 /* rfc6329, rfc7176 */
#define ISIS_CLV_TRILL_NEIGHBOR      145 /* rfc7176 */
#define ISIS_CLV_SID_LABEL_BINDING   149 /* draft-previdi-isis-segment-routing-extensions-05 */
#define ISIS_CLV_RESTART             211 /* draft-ietf-isis-restart-01 */
#define ISIS_CLV_MT_IS_REACH         222 /* draft-ietf-isis-wg-multi-topology-05 */
#define ISIS_CLV_MT_SUPPORTED        229 /* draft-ietf-isis-wg-multi-topology-05 */
#define ISIS_CLV_IP6_ADDR            232 /* draft-ietf-isis-ipv6-02 */
#define ISIS_CLV_MT_IP_REACH         235 /* draft-ietf-isis-wg-multi-topology-05 */
#define ISIS_CLV_IP6_REACH           236 /* draft-ietf-isis-ipv6-02 */
#define ISIS_CLV_MT_IP6_REACH        237 /* draft-ietf-isis-wg-multi-topology-05 */
#define ISIS_CLV_PTP_ADJ_STATE       240 /* rfc3373 */
#define ISIS_CLV_IIH_SEQNR           241 /* draft-shen-isis-iih-sequence-00 */
#define ISIS_CLV_RT_CAPABLE          242 /* rfc4971, rfc7176 */
#define ISIS_CLV_VENDOR_PRIVATE      250 /* draft-ietf-isis-proprietary-tlv-00 */

/*
 * Our sub-packet dismantle structure for CLV's
 */
typedef struct {
        int     optcode;                /* code for option */
        const char    *tree_text;       /* text for fold out */
        gint    *tree_id;               /* id for add_item */
        void    (*dissect)(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree,
                                int offset, int id_length, int length);
} isis_clv_handle_t;

/*
 * Published API functions.  NOTE, this are "local" API functions and
 * are only valid from with isis decodes.
 */
extern void isis_dissect_clvs(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
        const isis_clv_handle_t *opts, expert_field* expert_short_len, int len, int id_length,
        int unknown_tree_id,  int tree_type, int tree_length, expert_field ei_unknown);

extern void isis_dissect_nlpid_clv(tvbuff_t *tvb, proto_tree *tree,
        int hf_nlpid, int offset, int length);
extern void isis_dissect_te_router_id_clv(proto_tree *tree, packet_info* pinfo, tvbuff_t *tvb, expert_field* expert,
        int offset, int length, int tree_id);
extern void isis_dissect_ipv6_int_clv(proto_tree *tree, packet_info* pinfo, tvbuff_t *tvb, expert_field* expert,
        int offset, int length, int tree_id);
extern void isis_dissect_ip_int_clv(proto_tree *tree, packet_info* pinfo, tvbuff_t *tvb, expert_field* expert,
        int offset, int length, int tree_id);
extern void isis_dissect_mt_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree,
        int offset, int length, int tree_id, expert_field* mtid_expert);
extern void isis_dissect_hostname_clv(tvbuff_t *tvb, proto_tree *tree,
        int offset, int length, int tree_id);
extern void isis_dissect_authentication_clv(proto_tree *tree, packet_info* pinfo, tvbuff_t *tvb,
        int hf_auth_bytes, expert_field* auth_expert, int offset, int length);
extern void isis_dissect_area_address_clv(proto_tree *tree, packet_info* pinfo, tvbuff_t *tvb,
        expert_field* expert, int hf_area, int offset, int length);
extern void isis_dissect_instance_identifier_clv(proto_tree *tree, packet_info* pinfo, tvbuff_t *tvb,
        expert_field* expert, int hf_iid, int hf_supported_itid, int offset, int length);

extern void isis_dissect_metric(tvbuff_t *tvb, proto_tree *tree, int offset,
        guint8 value, char *pstr, int force_supported);

#endif /* _PACKET_ISIS_CLV_H */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
