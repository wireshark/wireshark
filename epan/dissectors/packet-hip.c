/* packet-hip.c
 * Definitions and routines for HIP control packet disassembly
 * Samu Varjonen <samu.varjonen@hiit.fi>
 *
 * $Id$
 *
 * Based on dissector originally created by
 *   Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 *   Thomas Henderson <thomas.r.henderson@boeing.com>
 *   Samu Varjonen <samu.varjonen@hiit.fi>
 *   Thomas Jansen <mithi@mithi.net>
 *
 * Packet dissector for Host Identity Protocol (HIP) packets.
 * This tool displays the TLV structure, verifies checksums,
 * and shows NULL encrypted parameters, but will not verify
 * signatures or decode encrypted parameters.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/addr_resolv.h>

#include <epan/ipproto.h>
#include <epan/in_cksum.h>

#define HI_ALG_DSA 3
#define HI_ALG_RSA 5

/* HIP packet types */
typedef enum {
        HIP_I1=1,
        HIP_R1,
        HIP_I2,
        HIP_R2,
        HIP_UPDATE=16,
        HIP_NOTIFY=17,
        HIP_CLOSE=18,
        HIP_CLOSE_ACK=19
} HIP_PACKETS;

/* HIP TLV parameters listed in order of RFCs */

/* RFC 5201 */
#define PARAM_R1_COUNTER                128
#define PARAM_PUZZLE                    257
#define PARAM_SOLUTION                  321
#define PARAM_SEQ                       385
#define PARAM_ACK                       449
#define PARAM_DIFFIE_HELLMAN            513
#define PARAM_HIP_TRANSFORM             577
#define PARAM_ENCRYPTED                 641
#define PARAM_HOST_ID                   705
/* Type number defined in RFC 5201 contents
   in draft-ietf-hip-cert-00 */
#define PARAM_CERT                      768
#define PARAM_NOTIFICATION              832
#define PARAM_ECHO_REQUEST_SIGNED       897
#define PARAM_ECHO_RESPONSE_SIGNED      961
#define PARAM_HMAC                      61505
#define PARAM_HMAC_2                    61569
#define PARAM_HIP_SIGNATURE_2           61633
#define PARAM_HIP_SIGNATURE             61697
#define PARAM_ECHO_REQUEST_UNSIGNED     63661
#define PARAM_ECHO_RESPONSE_UNSIGNED    63425
/* RFC 5202 */
#define PARAM_ESP_INFO                  65
#define PARAM_ESP_TRANSFORM             4095
/* RFC 5203 */
#define PARAM_REG_INFO                  930
#define PARAM_REG_REQUEST               932
#define PARAM_REG_RESPONSE              934
#define PARAM_REG_FAILED                936
/* RFC 5204 */
#define PARAM_FROM                      65498
#define PARAM_RVS_HMAC                  65500
#define PARAM_VIA_RVS                   65502
/* RFC 5206 */
#define PARAM_LOCATOR                   193
/* RFC 5770 */
#define PARAM_NAT_TRAVERSAL_MODE        608
#define PARAM_TRANSACTION_PACING        610
#define PARAM_REG_FROM                  950
#define PARAM_RELAY_FROM                63998
#define PARAM_RELAY_TO                  64002
#define PARAM_RELAY_HMAC                65520

/* Bit masks */
#define PARAM_CRITICAL_BIT              0x0001
/* See RFC 5201 section 5.1 */
#define HIP_PACKET_TYPE_MASK            0x7F
/* draft-ietf-shim6-proto-12 see section 5.3 */
#define HIP_SHIM6_FIXED_BIT_P_MASK      0x80
#define HIP_SHIM6_FIXED_BIT_S_MASK      0x01
/* 00001110 Excluding the shim6 compatibility bit */
#define HIP_RESERVED_MASK               0x0E
#define HIP_VERSION_MASK                0xF0
#define HIP_CONTROL_A_MASK              0x0001
#define HIP_CONTROL_C_MASK              0x0002
#define HI_HDR_FLAGS_MASK               0xFFFF0000
#define HI_HDR_PROTO_MASK               0x0000FF00
#define HI_HDR_ALG_MASK                 0x000000FF

static const value_string pinfo_vals[] = {
        { HIP_I1, "HIP I1 (HIP Initiator Packet)" },
        { HIP_R1, "HIP R1 (HIP Responder Packet)" },
        { HIP_I2, "HIP I2 (Second HIP Initiator Packet)" },
        { HIP_R2, "HIP R2 (Second HIP Responder Packet)" },
        { HIP_UPDATE, "HIP UPDATE (HIP Update Packet)" },
        { HIP_NOTIFY, "HIP NOTIFY (HIP Notify Packet)" },
        { HIP_CLOSE, "HIP CLOSE (HIP Close Packet)" },
        { HIP_CLOSE_ACK, "HIP CLOSE_ACK (HIP Close Acknowledgment Packet)" },
        { 0, NULL }
};

static const value_string hip_param_vals[] = {
        { PARAM_ESP_INFO, "ESP_INFO" },
        { PARAM_R1_COUNTER, "R1_COUNTER" },
        { PARAM_LOCATOR, "LOCATOR" },
        { PARAM_PUZZLE, "PUZZLE" },
        { PARAM_SOLUTION, "SOLUTION" },
        { PARAM_SEQ, "SEQ" },
        { PARAM_ACK, "ACK" },
        { PARAM_DIFFIE_HELLMAN, "DIFFIE_HELLMAN" },
        { PARAM_HIP_TRANSFORM, "HIP_TRANSFORM" },
        { PARAM_ENCRYPTED, "ENCRYPTED" },
        { PARAM_HOST_ID, "HOST_ID" },
        { PARAM_CERT, "CERT" },
        { PARAM_NOTIFICATION, "NOTIFICATION" },
        { PARAM_ECHO_REQUEST_SIGNED, "ECHO_REQUEST_SIGNED" },
        { PARAM_ECHO_RESPONSE_SIGNED, "ECHO_RESPONSE_SIGNED" },
        { PARAM_ESP_TRANSFORM, "ESP_TRANSFORM" },
        { PARAM_HMAC, "HMAC" },
        { PARAM_HMAC_2, "HMAC_2" },
        { PARAM_HIP_SIGNATURE, "HIP_SIGNATURE" },
        { PARAM_HIP_SIGNATURE_2, "HIP_SIGNATURE_2" },
        { PARAM_ECHO_REQUEST_UNSIGNED, "ECHO_REQUEST_UNSIGNED" },
        { PARAM_ECHO_RESPONSE_UNSIGNED, "ECHO_RESPONSE_UNSIGNED" },
        { PARAM_NAT_TRAVERSAL_MODE, "NAT_TRAVERSAL_MODE" },
        { PARAM_TRANSACTION_PACING, "TRANSACTION_PACING" },
        { PARAM_RELAY_FROM, "RELAY_FROM" },
        { PARAM_RELAY_TO, "RELAY_TO" },
        { PARAM_RELAY_HMAC, "RELAY_HMAC" },
        { PARAM_REG_INFO, "REG_INFO" },
        { PARAM_REG_REQUEST, "REG_REQUEST" },
        { PARAM_REG_RESPONSE, "REG_RESPONSE" },
        { PARAM_REG_FROM, "REG_FROM" },
        { 0, NULL }
};

/* RFC 5201 section 5.2.6. */
static const value_string dh_group_id_vals[] = {
        { 0x0, "Reserved" },
        { 0x01, "384-bit group" },
        { 0x02, "OAKLEY well-known group 1" },
        { 0x03, "1536-bit MODP group" },
        { 0x04, "3072-bit MODP group" },
        { 0x05, "6144-bit MODP group" },
        { 0x06, "8192-bit MODP group" },
        { 0, NULL }
};

/* RFC 5202 section 5.1.2. */
static const value_string transform_id_vals[] = {
        { 0x0, "Reserved" },
        { 0x01, "AES-CBC with HMAC-SHA1" },
        { 0x02, "3DES-CBC with HMAC-SHA1" },
        { 0x03, "3DES-CBC with HMAC-MD5" },
        { 0x04, "BLOWFISH-CBC with HMAC-SHA1" },
        { 0x05, "NULL with HMAC-SHA1" },
        { 0x06, "NULL with HMAC-MD5" },
        { 0, NULL }
};

static const value_string reg_type_vals[] = {
        { 0x01, "RENDEZVOUS" }, /* RFC 5204 */
        { 0x02, "RELAY_UDP_HIP" }, /* RFC 5770 */
        { 0, NULL }
};

/* RFC 5201 section 5.2.8 */
static const value_string sig_alg_vals[] = {
        { 0x0, "Reserved" },
        { HI_ALG_DSA, "DSA" },
        { HI_ALG_RSA, "RSA" },
        { 0, NULL }
};

/* RFC 5770 */
static const value_string mode_id_vals[] = {
        { 0x0, "Reserved" },
        { 0x01, "UDP-encapsulation" },
        { 0x02, "ICE-STUN-UDP" },
        { 0, NULL }
};

static const value_string hi_hdr_flags_vals[] = {
        { 0x0, "Other" },
        { 0x0200, "Key is associated with a user" },
        { 0x0201, "Zone key" },
        { 0x0202, "Key is associated with non-zone entity" },
        { 0, NULL }
};

/* RFC 2535 section 3.1.3 */
static const value_string hi_hdr_proto_vals[] = {
        { 0x01, "Key is used for TLS" },
        { 0x02, "Key is used for email" },
        { 0x03, "Key is used for DNS security" },
        { 0x04, "Key is used for Oakley/IPSEC" },
        { 0xFF, "Key is valid for any protocol" },
        { 0, NULL }
};

/* RFC 2535 section 3.2 */
static const value_string hi_hdr_alg_vals[] = {
        { 0x00, "Reserved" },
        { 0x01, "RSA/MD5" },
        { 0x02, "Diffie-Hellman" },
        { 0x03, "DSA" },
        { 0x04, "elliptic curve crypto" },
        { 0x05, "RSA" },
        { 0xFF, "Reserved" },
        { 0, NULL }
};

/* RFC 5201 */
static const value_string notification_vals[] = {
        { 1,  "Unsupported critical parameter type" },
        { 7,  "Invalid syntax" },
        { 14, "No Diffie-Hellman proposal chosen" },
        { 15, "Invalid Diffie-Hellman chosen" },
        { 16, "No HIP proposal chosen" },
        { 17, "Invalid HIP transform chosen" },
        { 18, "No ESP proposal chosen" },
        { 19, "Invalid ESP transform chosen" },
        { 24, "Authentication failed" },
        { 26, "Checksum failed" },
        { 28, "HMAC failed" },
        { 32, "Encryption failed" },
        { 40, "Invalid HIT" },
        { 42, "Blocked by policy" },
        { 44, "Server busy please retry" },
        { 0, NULL }
};

/* RFC 5770 */
static const value_string nat_traversal_mode_vals[] = {
        { 0, "Reserved"},
        { 1, "UDP-encapsulation"},
        { 2, "ICE-STUN-UDP"},
        { 0, NULL }
};

/* functions */
static int dissect_hip_tlv(tvbuff_t *tvb, int offset, proto_item *ti, int type, int tlv_len);

static int proto_hip = -1;
static int hf_hip_proto = -1;
static int hf_hip_hdr_len = -1;
static int hf_hip_shim6_fixed_bit_p = -1;
static int hf_hip_packet_type = -1;
static int hf_hip_version = -1;
static int hf_hip_shim6_fixed_bit_s = -1;
static int hf_hip_controls = -1;
static int hf_hip_controls_anon = -1;
static int hf_hip_checksum = -1;
static int hf_hip_hit_sndr = -1;
static int hf_hip_hit_rcvr = -1;

static int hf_hip_type = -1;
static int hf_hip_tlv_ei_res = -1;
static int hf_hip_tlv_ei_keyidx = -1;
static int hf_hip_tlv_ei_oldspi = -1;
static int hf_hip_tlv_ei_newspi = -1;
static int hf_hip_tlv_r1_res = -1;
static int hf_hip_tlv_r1count = -1;
static int hf_hip_tlv_puzzle_k = -1;
static int hf_hip_tlv_puzzle_life = -1;
static int hf_hip_tlv_puzzle_o = -1;
static int hf_hip_tlv_puzzle_i = -1;
static int hf_hip_tlv_solution_k = -1;
static int hf_hip_tlv_solution_reserved = -1;
static int hf_hip_tlv_solution_o = -1;
static int hf_hip_tlv_solution_i = -1;
static int hf_hip_tlv_solution_j = -1;
static int hf_hip_tlv_seq_updid = -1;
static int hf_hip_tlv_ack_updid = -1;
static int hf_hip_tlv_dh_group_id = -1;
static int hf_hip_tlv_dh_pub = -1;
static int hf_hip_tlv_dh_pv_length = -1;
static int hf_hip_tlv_trans_id = -1;
static int hf_hip_tlv_esp_reserved = -1;
static int hf_hip_tlv_host_id_len = -1;
static int hf_hip_tlv_host_di_type = -1;
static int hf_hip_tlv_host_di_len = -1;
static int hf_hip_tlv_host_id_hdr = -1;
static int hf_hip_tlv_host_id_hdr_flags = -1;
static int hf_hip_tlv_host_id_hdr_proto = -1;
static int hf_hip_tlv_host_id_hdr_alg = -1;
static int hf_hip_tlv_host_id_t = -1;
static int hf_hip_tlv_host_id_q = -1;
static int hf_hip_tlv_host_id_p = -1;
static int hf_hip_tlv_host_id_g = -1;
static int hf_hip_tlv_host_id_y = -1;
static int hf_hip_tlv_host_id_e_len = -1;
static int hf_hip_tlv_host_id_e = -1;
static int hf_hip_tlv_host_id_n = -1;
static int hf_hip_tlv_notification_res = -1;
static int hf_hip_tlv_notification_type = -1;
static int hf_hip_tlv_notification_data = -1;
static int hf_hip_tlv_opaque_data = -1;
static int hf_hip_tlv_reg_ltmin = -1;
static int hf_hip_tlv_reg_ltmax = -1;
static int hf_hip_tlv_reg_lt = -1;
static int hf_hip_tlv_reg_type = -1;
static int hf_hip_tlv_reg_failtype = -1;
static int hf_hip_tlv_hmac = -1;
static int hf_hip_tlv_sig_alg = -1;
static int hf_hip_tlv_sig = -1;
static int hf_hip_tlv_enc_reserved = -1;
static int hf_hip_tlv_locator_traffic_type = -1;
static int hf_hip_tlv_locator_type = -1;
static int hf_hip_tlv_locator_len = -1;
static int hf_hip_tlv_locator_reserved = -1;
static int hf_hip_tlv_locator_lifetime = -1;
static int hf_hip_tlv_locator_port = -1;
static int hf_hip_tlv_locator_transport_protocol = -1;
static int hf_hip_tlv_locator_kind = -1;
static int hf_hip_tlv_locator_priority = -1;
static int hf_hip_tlv_locator_spi = -1;
static int hf_hip_tlv_locator_address = -1;

static int hf_hip_tlv_cert_group = -1;
static int hf_hip_tlv_cert_count = -1;
static int hf_hip_tlv_cert_id = -1;
static int hf_hip_tlv_cert_type = -1;
static int hf_hip_tlv_certificate = -1;

static int hf_hip_tlv_from_address = -1;
static int hf_hip_tlv_rvs_address = -1;

static int hf_hip_tlv_nat_traversal_mode_id = -1;
static int hf_hip_tlv_transaction_minta = -1;
static int hf_hip_tlv_relay_from_port = -1;
static int hf_hip_tlv_relay_from_protocol = -1;
static int hf_hip_tlv_relay_from_reserved = -1;
static int hf_hip_tlv_relay_from_address = -1;
static int hf_hip_tlv_relay_to_port = -1;
static int hf_hip_tlv_relay_to_protocol = -1;
static int hf_hip_tlv_relay_to_reserved = -1;
static int hf_hip_tlv_relay_to_address = -1;
static int hf_hip_tlv_reg_from_port = -1;
static int hf_hip_tlv_reg_from_protocol = -1;
static int hf_hip_tlv_reg_from_reserved = -1;
static int hf_hip_tlv_reg_from_address = -1;

static gint ett_hip = -1;
static gint ett_hip_controls = -1;
static gint ett_hip_tlv = -1;
static gint ett_hip_tlv_data = -1;
static gint ett_hip_tlv_host_id_hdr = -1;
static gint ett_hip_locator_data = -1;

/* Dissect the HIP packet */
static void
dissect_hip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        proto_tree *hip_tree, *hip_tlv_tree=NULL;
        proto_item *ti, *ti_tlv;
        int length, offset = 0, newoffset = 0;
        guint16 control_h, checksum_h, computed_checksum;
        guint16 tlv_type_h, tlv_length_h; /* For storing in host order */
        vec_t cksum_vec[4];
        guint32 phdr[2];

        /* Payload format RFC 5201 section 5.1 */
        /* hiph_proto; */	          /* payload protocol              */
        guint8 hiph_hdr_len;              /* header length                 */
        guint8 hiph_shim6_fixed_bit_s;    /* This is always 0              */
        guint8 hiph_packet_type;          /* packet type                   */
        guint8 hiph_res_ver, hiph_version, hiph_reserved;
                                          /* byte for reserved and version */
        guint8 hiph_shim6_fixed_bit_p;    /* This is always 1              */
        /* checksum_h */                  /* checksum                      */
        /* control_h */                   /* control                       */
        /* HIP parameters ...  */

        /*  load the top pane info. This should be overwritten by
            the next protocol in the stack */
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "HIP");
        col_clear(pinfo->cinfo, COL_INFO);

        newoffset = offset;
	/* hiph Proto */
        newoffset++;
        hiph_hdr_len = tvb_get_guint8(tvb, newoffset);
        newoffset++;
        hiph_packet_type = tvb_get_guint8(tvb, newoffset);
        /* draft-ietf-shim6-proto-12 see section 5.3 */
        hiph_shim6_fixed_bit_p = (hiph_packet_type & HIP_SHIM6_FIXED_BIT_P_MASK) >> 7;
        hiph_packet_type = hiph_packet_type & HIP_PACKET_TYPE_MASK;
        newoffset++;
        hiph_res_ver = tvb_get_guint8(tvb, newoffset);
        /* divide to reserved and version and shim6_fixed_bit_s
           draft-ietf-shim6-proto-12 see section 5.3 */
        hiph_version = (hiph_res_ver & HIP_VERSION_MASK) >> 4;
        hiph_reserved = hiph_res_ver & HIP_RESERVED_MASK;
        hiph_shim6_fixed_bit_s = hiph_res_ver & HIP_SHIM6_FIXED_BIT_S_MASK;
        newoffset++;
        checksum_h = tvb_get_ntohs(tvb, newoffset);
        newoffset += 2;
        control_h = tvb_get_ntohs(tvb, newoffset);

        col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(hiph_packet_type, pinfo_vals, "Unknown"));

        /* populate a tree in the second pane with the status of the link layer (i.e. none) */
        if(tree) {
                ti = proto_tree_add_item(tree, proto_hip, tvb, 0, -1, FALSE);

                hip_tree = proto_item_add_subtree(ti, ett_hip);
                proto_tree_add_item(hip_tree, hf_hip_proto, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(hip_tree, hf_hip_hdr_len, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                proto_tree_add_uint_format(hip_tree, hf_hip_shim6_fixed_bit_p, tvb, offset+2, 1,
                                           hiph_shim6_fixed_bit_p,
                                           "Fixed P-bit: %u (Always zero)",
                                           hiph_shim6_fixed_bit_p);
                proto_tree_add_uint(hip_tree, hf_hip_packet_type, tvb, offset+2, 1,
                                    hiph_packet_type);
                proto_tree_add_uint_format(hip_tree, hf_hip_version, tvb, offset+3, 1,
                                           hiph_version, "Version: %u, Reserved: %u",
                                           hiph_version, hiph_reserved);
                proto_tree_add_uint_format(hip_tree, hf_hip_shim6_fixed_bit_s, tvb, offset+3, 1,
                                           hiph_shim6_fixed_bit_s,
                                           "Fixed S-bit: %u (%s)",
                                           hiph_shim6_fixed_bit_s,
                                          ((hiph_shim6_fixed_bit_s) ? "HIP" : "SHIM6"));

                /* Checksum - this is the same algorithm from UDP, ICMPv6 */
                if (!pinfo->fragmented) {
                        /* IPv4 or IPv6 addresses */
                        cksum_vec[0].ptr = pinfo->src.data;
                        cksum_vec[0].len = pinfo->src.len;
                        cksum_vec[1].ptr = pinfo->dst.data;
                        cksum_vec[1].len = pinfo->dst.len;

                        /* the rest of the pseudo-header */
                        if (pinfo->src.type == AT_IPv6) {
                                cksum_vec[2].ptr = (const guint8 *)&phdr;
                                phdr[0] = g_htonl(tvb_reported_length(tvb));
                                phdr[1] = g_htonl(IP_PROTO_HIP);
                                cksum_vec[2].len = 8;
                        } else {
                                cksum_vec[2].ptr = (const guint8 *)&phdr;
                                phdr[0] = g_htonl((IP_PROTO_HIP<<16)+tvb_reported_length(tvb));
                                cksum_vec[2].len = 4;
                        }
                        /* pointer to the HIP header (packet data) */
                        cksum_vec[3].len = tvb_reported_length(tvb);
                        cksum_vec[3].ptr = tvb_get_ptr(tvb, 0, cksum_vec[3].len);
                        computed_checksum = in_cksum(cksum_vec, 4);
                        if (computed_checksum == 0) {
                                proto_tree_add_uint_format(hip_tree, hf_hip_checksum, tvb,
                                                           offset+4, 2, checksum_h,
                                                           "Checksum: 0x%04x (correct)",
                                                           checksum_h);
                        } else {
                               if (checksum_h == 0 && pinfo->ipproto == IP_PROTO_UDP) {
                                       proto_tree_add_uint_format(hip_tree, hf_hip_checksum, tvb,
                                                                  offset+4, 2, checksum_h,
                                                                  "Checksum: 0x%04x (correct)",
                                                                  checksum_h);
                               } else {
                                       proto_tree_add_uint_format(hip_tree, hf_hip_checksum, tvb,
                                                                  offset+4, 2, checksum_h,
                                                                  "Checksum: 0x%04x (incorrect, "
                                                                  "should be 0x%04x)",
                                                                  checksum_h,
                                                                  in_cksum_shouldbe(checksum_h,
                                                                  computed_checksum));
                               }
                        }
                } else {
                        proto_tree_add_uint_format(hip_tree, hf_hip_checksum, tvb,
                                                   offset+4, 2, checksum_h,
                                                   "Checksum: 0x%04x (unverified)",
                                                   checksum_h);
                }

                ti = proto_tree_add_item(hip_tree, hf_hip_controls, tvb, offset+6, 2, ENC_BIG_ENDIAN);
                if (ti) {
                        /* HIP Controls subtree */
                        ti = proto_item_add_subtree(ti, ett_hip_controls);
                        proto_tree_add_boolean(ti, hf_hip_controls_anon, tvb,
                                               offset+7,1, control_h);
                }

                offset += 8;
                proto_tree_add_item(hip_tree, hf_hip_hit_sndr, tvb, offset,
                                     16, ENC_NA);
                offset += 16;
                proto_tree_add_item(hip_tree, hf_hip_hit_rcvr, tvb, offset,
                                     16, ENC_NA);
                offset += 16;

                length = (hiph_hdr_len + 1) * 8;
                /* Begin TLV parsing */
                if (offset < length) {
                        ti_tlv = proto_tree_add_text(hip_tree, tvb, offset,
                                                     tvb_length(tvb), "HIP Parameters");
                        hip_tlv_tree = proto_item_add_subtree(ti_tlv, ett_hip_tlv);
                }
                /* Parse type and length in TLV */
                while (offset < length)
                {
                        tlv_type_h = tvb_get_ntohs(tvb, offset);
                        tlv_length_h = tvb_get_ntohs(tvb, offset + 2);
                        ti_tlv = proto_tree_add_uint_format(hip_tlv_tree, hf_hip_type, tvb,
                                                            offset, 4 + tlv_length_h, tlv_type_h,
                                                            "%s (type=%u, length=%u)",
                                                            val_to_str(tlv_type_h, hip_param_vals, "Unknown"),
                                                            tlv_type_h, tlv_length_h);

                        /* Parse value */
                        dissect_hip_tlv(tvb, offset, ti_tlv, tlv_type_h, tlv_length_h);

                        offset += 11 + tlv_length_h - (tlv_length_h + 3) % 8;
                }

        }
}

static void
dissect_hip_in_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        guint32 nullbytes;
        nullbytes = tvb_get_ntohl(tvb, 0);
        if (nullbytes == 0)
        {
                tvbuff_t *newtvb = tvb_new_subset_remaining(tvb, 4);
                dissect_hip(newtvb, pinfo, tree);
        }
}


static int
dissect_hip_tlv(tvbuff_t *tvb, int offset, proto_item *ti, int type, int tlv_len)
{
        proto_tree *t=NULL;
        proto_item *ti_tlv, *ti_loc;
        guint8 n, algorithm, reg_type;
        guint16 trans, hi_len, di_len, di_type, e_len, pv_len;
        guint32 reserved, hi_hdr;
        guint8 transport_proto;
        guint8 locator_type;
        int newoffset, newlen, hi_t;

        /* move over the TLV */
        newoffset = offset + 4;
        switch (type)
        {
        case PARAM_ESP_INFO:
                t = proto_item_add_subtree(ti, ett_hip_tlv_data);
                /* Reserved */
                proto_tree_add_item(t, hf_hip_tlv_ei_res, tvb, newoffset, 2, ENC_BIG_ENDIAN);
                /* KEYMAT index */
                newoffset += 2;
                proto_tree_add_item(t, hf_hip_tlv_ei_keyidx, tvb, newoffset, 2, ENC_BIG_ENDIAN);
                /* OLD SPI */
                newoffset += 2;
                proto_tree_add_item(t, hf_hip_tlv_ei_oldspi, tvb, newoffset, 4, ENC_BIG_ENDIAN);
                /* NEW SPI */
                newoffset += 4;
                proto_tree_add_item(t, hf_hip_tlv_ei_newspi, tvb, newoffset, 4, ENC_BIG_ENDIAN);
                break;
        case PARAM_R1_COUNTER:
                t = proto_item_add_subtree(ti, ett_hip_tlv_data);
                /* Reserved */
                proto_tree_add_item(t, hf_hip_tlv_r1_res, tvb, newoffset, 4, ENC_BIG_ENDIAN);
                /* R1 generation counter */
                newoffset += 4;
                proto_tree_add_item(t, hf_hip_tlv_r1count, tvb, newoffset, 8, ENC_NA);
                break;
        case PARAM_LOCATOR:
                /* RFC 5206 section 4. and  RFC 5770 section 5.7. for type 2 locators
                 */
                t = proto_item_add_subtree(ti, ett_hip_tlv_data);
                tlv_len -= 4;
                /* loop through included locators */
                while (tlv_len > 0) {
                        /* Every locator to new tree node
                         * Skip ahead and read the 0 or 1 type locator from 8 bytes
                         * and type 2 locator from 20 bytes to be used as the top level
                         * tree_item for this subtree
                         */
                        locator_type = tvb_get_guint8(tvb, newoffset + 1);
                        if (locator_type == 0) {
                                ti_loc = proto_tree_add_item(t, hf_hip_tlv_locator_address,
                                                             tvb, newoffset + 8, 16, FALSE);
                        } else if (locator_type == 1) {
                                ti_loc = proto_tree_add_item(t, hf_hip_tlv_locator_address,
                                                             tvb, newoffset + 12, 16, FALSE);
                        } else if (locator_type == 2) {
                                ti_loc = proto_tree_add_item(t, hf_hip_tlv_locator_address,
                                                             tvb, newoffset + 20, 16, FALSE);
                        } else {
                                /* unknown or malformed locator type jumping over it */
                                ti_loc = NULL;
                                newoffset += (1 + tvb_get_guint8(tvb, newoffset + 2));
                                tlv_len -= (1 + tvb_get_guint8(tvb, newoffset + 2));
                        }
                        if (ti_loc) {
                                ti_loc = proto_item_add_subtree(ti_loc, ett_hip_locator_data);
                                /* Traffic type */
                                proto_tree_add_item(ti_loc, hf_hip_tlv_locator_traffic_type, tvb,
                                                    newoffset, 1, ENC_BIG_ENDIAN);
                                newoffset++;
                                /* Locator type */
#if 0
                                locator_type = tvb_get_guint8(tvb, newoffset);
#endif
                                proto_tree_add_item(ti_loc, hf_hip_tlv_locator_type, tvb, newoffset, 1, ENC_BIG_ENDIAN);
                                newoffset++;
                                /* Locator length */
                                proto_tree_add_item(ti_loc, hf_hip_tlv_locator_len, tvb, newoffset, 1, ENC_BIG_ENDIAN);
                                newoffset++;
                                /* Reserved includes the Preferred bit */
                                reserved = tvb_get_guint8(tvb, newoffset);
                                proto_tree_add_uint_format(ti_loc, hf_hip_tlv_locator_reserved, tvb,
                                                           newoffset, 1, reserved,
                                                           "Reserved: 0x%x %s", reserved,
                                                           (reserved >> 31) ? "(Preferred)" : "");
                                newoffset++;
                                /* Locator lifetime */
                                proto_tree_add_item(ti_loc, hf_hip_tlv_locator_lifetime, tvb,
                                                    newoffset, 4, ENC_BIG_ENDIAN);
                                newoffset += 4;
                                if (locator_type == 0) {
                                        /* Locator types 1 and 0 RFC 5206 section 4.2.*/
                                        /* Locator */
                                        proto_tree_add_item(ti_loc, hf_hip_tlv_locator_address,
                                                            tvb, newoffset, 16, FALSE);
                                        newoffset += 16;                                       
                                        tlv_len -= 24;
                                } else if (locator_type == 1) {
                                        /* Locator types 1 and 0 RFC 5206 section 4.2.*/
                                        /* SPI */
                                        proto_tree_add_item(ti_loc, hf_hip_tlv_locator_spi, tvb,
                                                            newoffset, 4, ENC_BIG_ENDIAN);
                                        newoffset += 4;
                                        /* Locator */
                                        proto_tree_add_item(ti_loc, hf_hip_tlv_locator_address,
                                                            tvb, newoffset, 16, FALSE);
                                        newoffset += 16;                                       
                                        tlv_len -= 28;
                                } else if (locator_type == 2) {
                                        /* Locator type 2 RFC 5770 section 5.7. */
                                        /* Tansport port */
                                        proto_tree_add_item(ti_loc, hf_hip_tlv_locator_port, tvb,
                                                            newoffset, 2, ENC_BIG_ENDIAN);
                                        newoffset += 2;
                                        /* Transport protocol */
                                        transport_proto = tvb_get_guint8(tvb, newoffset);
                                        /* RFC 5770 section 5.6 */
                                        proto_tree_add_uint_format(ti_loc, hf_hip_tlv_locator_transport_protocol,
                                                                   tvb, newoffset, 1, transport_proto,
                                                                   "Transport protocol: %d %s",
                                                                   transport_proto,
                                                                   (transport_proto == 17) ?
                                                                   "(UDP)" : "");
                                        newoffset++;
                                        /* Kind */
                                        proto_tree_add_item(ti_loc, hf_hip_tlv_locator_kind, tvb,
                                                            newoffset, 1, ENC_BIG_ENDIAN);
                                        newoffset++;
                                        /* Priority */
                                        proto_tree_add_item(ti_loc, hf_hip_tlv_locator_priority, tvb,
                                                            newoffset, 4, ENC_BIG_ENDIAN);
                                        newoffset += 4;
                                        /* SPI */
                                        proto_tree_add_item(ti_loc, hf_hip_tlv_locator_spi, tvb,
                                                            newoffset, 4, ENC_BIG_ENDIAN);
                                        newoffset += 4;
                                        /* Locator */
                                        proto_tree_add_item(ti_loc, hf_hip_tlv_locator_address,
                                                            tvb, newoffset, 16, FALSE);
                                        newoffset += 16;
                                        tlv_len -= 36;
                                }
                        }
                }
                break;
        case PARAM_PUZZLE:
                t = proto_item_add_subtree(ti, ett_hip_tlv_data);
                /* K number of verified bits */
                proto_tree_add_item(t, hf_hip_tlv_puzzle_k, tvb, newoffset, 1, ENC_BIG_ENDIAN);
                /* Puzzle lifetime */
                newoffset++;
                proto_tree_add_item(t, hf_hip_tlv_puzzle_life, tvb, newoffset, 1, ENC_BIG_ENDIAN);
                /* Puzzle O*/
                newoffset++;
                proto_tree_add_item(t, hf_hip_tlv_puzzle_o, tvb, newoffset, 2, ENC_BIG_ENDIAN);
                /* Puzzle I */
                newoffset += 2;
                proto_tree_add_item(t, hf_hip_tlv_puzzle_i, tvb,newoffset, 8, ENC_NA);
                break;
        case PARAM_SOLUTION:
                t = proto_item_add_subtree(ti, ett_hip_tlv_data);
                /* K number of verified bits */
                proto_tree_add_item(t, hf_hip_tlv_solution_k, tvb, newoffset, 1, ENC_BIG_ENDIAN);
                /* Solution Reserved */
                newoffset++;
                proto_tree_add_item(t, hf_hip_tlv_solution_reserved, tvb, newoffset, 1, ENC_BIG_ENDIAN);
                /* Solution Opaque */
                newoffset++;
                proto_tree_add_item(t, hf_hip_tlv_solution_o, tvb,newoffset, 2, ENC_BIG_ENDIAN);
                /* Solution I */
                newoffset += 2;
                proto_tree_add_item(t, hf_hip_tlv_solution_i, tvb, newoffset, 8, ENC_NA);
                /* Solution J */
                newoffset += 8;
                proto_tree_add_item(t, hf_hip_tlv_solution_j, tvb, newoffset, 8, ENC_NA);
                break;
        case PARAM_SEQ:
                t = proto_item_add_subtree(ti, ett_hip_tlv_data);
                /* Update ID */
                proto_tree_add_item(t, hf_hip_tlv_seq_updid, tvb, newoffset, 4, ENC_BIG_ENDIAN);
                break;
        case PARAM_ACK:
                t = proto_item_add_subtree(ti, ett_hip_tlv_data);
                /* Can contain multiple Update IDs from peer */
                while (tlv_len > 0) {
                        /* peer Update ID */
                        proto_tree_add_item(t, hf_hip_tlv_ack_updid, tvb, newoffset, 4, ENC_BIG_ENDIAN);
                        newoffset += 4;
                        tlv_len -= 4;
                }
                break;
        case PARAM_DIFFIE_HELLMAN:
                t = proto_item_add_subtree(ti, ett_hip_tlv_data);
                n = tvb_get_guint8(tvb, newoffset);
                /* First Group ID*/
                proto_tree_add_uint_format(t, hf_hip_tlv_dh_group_id, tvb, newoffset,
                                           1, n, "%u (%s)", n,
                                           val_to_str(n, dh_group_id_vals, "Unknown"));
                /* First Public value len */
                newoffset++;
                pv_len = tvb_get_ntohs(tvb, newoffset);
                proto_tree_add_item(t, hf_hip_tlv_dh_pv_length, tvb, newoffset, 2, ENC_BIG_ENDIAN);

                /* First Public value */
                newoffset += 2;
                proto_tree_add_item(t, hf_hip_tlv_dh_pub, tvb, newoffset, pv_len, ENC_NA);
                /* Check for the second group */
                if ((pv_len + newoffset) < tlv_len) {
                        /* Second Group ID*/
                        newoffset += pv_len;
                        proto_tree_add_uint_format(t, hf_hip_tlv_dh_group_id, tvb, newoffset,
                                                   1, n, "%u (%s)", n,
                                                   val_to_str(n, dh_group_id_vals, "Unknown"));
                        /* Second Public value len */
                        newoffset += 1;
                        pv_len = tvb_get_ntohs(tvb, newoffset);
                        proto_tree_add_item(t, hf_hip_tlv_dh_pv_length, tvb, newoffset, 2, ENC_BIG_ENDIAN);
                        /* Second Public Value */
                        newoffset += 2;
                        proto_tree_add_item(t, hf_hip_tlv_dh_pub, tvb, newoffset,
                                             pv_len, ENC_NA);
                }
                break;
        case PARAM_ESP_TRANSFORM:
                t = proto_item_add_subtree(ti, ett_hip_tlv_data);
                /* Reserved */
                proto_tree_add_item(t, hf_hip_tlv_esp_reserved, tvb, newoffset, 2, ENC_BIG_ENDIAN);
                newoffset +=2;
                tlv_len -= 2;
                while (tlv_len > 0) {
                        /* Suite # 1, 2, ...,  n
                         * two bytes per transform id
                         */
                        trans = tvb_get_ntohs(tvb, newoffset);
                        proto_tree_add_uint_format(t, hf_hip_tlv_trans_id, tvb,
                                                   newoffset, 2, trans, "%u (%s)", trans,
                                                   val_to_str(trans, transform_id_vals, "Unknown"));
                        tlv_len -= 2;
                        newoffset += 2;
                }
                break;
        case PARAM_HIP_TRANSFORM:
                t = proto_item_add_subtree(ti, ett_hip_tlv_data);
                while (tlv_len > 0) {
                        /* Suite # 1, 2, ...,  n
                           two bytes per transform id */
                        trans = tvb_get_ntohs(tvb, newoffset);
                        proto_tree_add_uint_format(t, hf_hip_tlv_trans_id, tvb,
                                                   newoffset, 2, trans, "%u (%s)", trans,
                                                   val_to_str(trans, transform_id_vals, "Unknown"));
                        tlv_len -= 2;
                        newoffset += 2;
                }
                break;
        case PARAM_NAT_TRAVERSAL_MODE:
                t = proto_item_add_subtree(ti, ett_hip_tlv_data);
                /* Reserved */
                proto_tree_add_item(t, hf_hip_tlv_esp_reserved, tvb, newoffset, 2, ENC_BIG_ENDIAN);
                newoffset += 2;
                tlv_len -= 2;
                while (tlv_len > 0) {
                        /* Suite # 1, 2, ...,  n
                           two bytes per mode id */
                        trans = tvb_get_ntohs(tvb, newoffset);
                        proto_tree_add_uint_format(t, hf_hip_tlv_nat_traversal_mode_id, tvb,
                                                   newoffset, 2, trans, "%u (%s)", trans,
                                                   val_to_str(trans, mode_id_vals, "Unknown"));
                        tlv_len -= 2;
                        newoffset += 2;
                }
                break;
        case PARAM_TRANSACTION_PACING:
                t = proto_item_add_subtree(ti, ett_hip_tlv_data);
                /* Min Ta */
                proto_tree_add_item(t, hf_hip_tlv_transaction_minta, tvb, newoffset, 4, ENC_BIG_ENDIAN);
                break;
        case PARAM_ENCRYPTED:
                t = proto_item_add_subtree(ti, ett_hip_tlv_data);
                /* Reserved */
                proto_tree_add_item(t, hf_hip_tlv_enc_reserved, tvb, newoffset, 4, ENC_BIG_ENDIAN);
                newoffset += 4;
                /* IV
                 * 16 bytes IV for AES CBC RFC 3602
                 *  8 bytes IV for 3DES CBC RFC 2405
                 *  0 bytes IV for NULL
                 *  and
                 *  encrypted data after that.
                 */
                proto_tree_add_text(t, tvb, newoffset, tlv_len - 4,
                                    "Encrypted Parameter Data (%u bytes)",  tlv_len - 4);
                break;
        case PARAM_HOST_ID:
                t = proto_item_add_subtree(ti, ett_hip_tlv_data);
                hi_len = tvb_get_ntohs(tvb, newoffset);
                proto_tree_add_item(t, hf_hip_tlv_host_id_len, tvb, newoffset, 2, ENC_BIG_ENDIAN);
                newoffset += 2;
                di_len = tvb_get_ntohs(tvb, newoffset);
                di_type = (di_len >> 12) & 0x000F;        /* get 4 bits for DI type */
                di_len = di_len & 0x0FFF;                /* 12 bits for DI length */
                /* DI type */
                proto_tree_add_item(t, hf_hip_tlv_host_di_type, tvb, newoffset, 1, ENC_BIG_ENDIAN);
                /* DI len */
                proto_tree_add_item(t, hf_hip_tlv_host_di_len, tvb, newoffset, 2, ENC_BIG_ENDIAN);
                newoffset += 2;
                /* hi_hdr - first 4 bytes are 0200ff03 (KEY RR in RFC 2535)
                 *   flags     2  octets
                 *   protocol  1  octet
                 *   algorithm 1  octet (DSA or RSA)
                 *   <public key>
                 */
                hi_hdr = tvb_get_ntohl(tvb, newoffset);
                ti_tlv = proto_tree_add_item(t, hf_hip_tlv_host_id_hdr,
                                             tvb, newoffset, 4, ENC_BIG_ENDIAN);
                if (ti_tlv) {
                        ti_tlv = proto_item_add_subtree(ti_tlv, ett_hip_tlv_host_id_hdr);
                        /* HDR Flags*/
                        proto_tree_add_uint(ti_tlv, hf_hip_tlv_host_id_hdr_flags, tvb,
                                            newoffset, 2, hi_hdr);
                        newoffset += 2;
                        /* HDR Protocol */
                        proto_tree_add_uint(ti_tlv, hf_hip_tlv_host_id_hdr_proto, tvb,
                                            newoffset, 1,  hi_hdr);
                        newoffset += 1;
                        /* HDR Algorithm */
                        proto_tree_add_uint(ti_tlv, hf_hip_tlv_host_id_hdr_alg, tvb,
                                            newoffset, 1, hi_hdr);
                }
                algorithm = tvb_get_guint8(tvb, newoffset);
                switch (algorithm) {
                case HI_ALG_DSA:
                        /* DSA KEY RR RFC 2536
                         *   T         1  octet
                         *   Q         20  octets
                         *   P         64 + T*8  octets
                         *   G         64 + T*8  octets
                         *   Y         64 + T*8  octets
                         */
                        newoffset++; /* 12 + offset */
                        /* T */
                        proto_tree_add_item(t, hf_hip_tlv_host_id_t, tvb, newoffset, 1, ENC_BIG_ENDIAN);
                        hi_t = tvb_get_guint8(tvb, newoffset);
                        newoffset++;
                        /* Q */
                        proto_tree_add_item(t, hf_hip_tlv_host_id_q, tvb, newoffset,
                                             20, ENC_NA);
                        newoffset += 20;
                        if (hi_t > 56) /* max 4096 bits */
                                break;
                        /* P */
                        newlen = 64 + (hi_t * 8);
                        proto_tree_add_item(t, hf_hip_tlv_host_id_p, tvb, newoffset,
                                             newlen, ENC_NA);
                        /* G */
                        newoffset += newlen;
                        proto_tree_add_item(t, hf_hip_tlv_host_id_g, tvb, newoffset,
                                             newlen, ENC_NA);
                        /* Y */
                        newoffset += newlen;
                        proto_tree_add_item(t, hf_hip_tlv_host_id_y, tvb, newoffset,
                                             newlen, ENC_NA);
                        break;
                case HI_ALG_RSA:
                        /* RSA KEY RR RFC 3110
                         * e_len        1 or 3 octets
                         * e            specified by e_len
                         * n            variable length public modulus
                         */
                        newoffset++; /* 12 + offset */
                        /* E len */
                        e_len = tvb_get_guint8(tvb, newoffset);
                        proto_tree_add_item(t, hf_hip_tlv_host_id_e_len, tvb, newoffset,
                                            (e_len > 255) ? 3 : 1, ENC_BIG_ENDIAN);
                        newoffset++;
                        hi_len -= 5; /* subtract RDATA + e_len */
                        if (e_len == 0) { /* e_len is 0 followed by 16-bit value */
                                e_len = tvb_get_ntohs(tvb, newoffset);
                                newoffset += 2;
                                hi_len -= 2;
                        }
                        if (e_len > 512) { /* per, RFC 3110 < 4096 bits */
                                proto_tree_add_text(t, tvb, newoffset, 2,
                                                    "<< e_len too large >>");
                                break;
                        }
                        /* e */
                        proto_tree_add_item(t, hf_hip_tlv_host_id_e, tvb, newoffset,
                                             e_len, ENC_NA);
                        newoffset += e_len;
                        hi_len -= e_len;

                        if (hi_len > 512) {
                                proto_tree_add_text(t, tvb, newoffset, 1,
                                                    "<< Invalid HI length >>");
                                break;
                        }

                        /* RSA public modulus n */
                        proto_tree_add_item(t, hf_hip_tlv_host_id_n, tvb, newoffset,
                                             hi_len, ENC_NA);
                        break;
                default:
                        proto_tree_add_text(t, tvb, newoffset, 1,
                                            "Unknown algorithm type (%d).\n", algorithm);

                        break;
                }
                /* FQDN */
                if (di_type == 0)
                        break;
                if (di_type == 1) {
                        /* RFC 1035 */
                        proto_tree_add_text(t, tvb, offset+16+hi_len, di_len,
                                            "FQDN: %s", tvb_get_ephemeral_string (tvb, offset+16+hi_len, di_len));
                } else if (di_type == 2) {
                        /* RFC 4282 */
                        proto_tree_add_text(t, tvb, offset+16+hi_len, di_len,
                                            "NAI: %s", tvb_get_ephemeral_string (tvb, offset+16+hi_len, di_len));
                }
                break;
        case PARAM_CERT: /* CERT */
                t = proto_item_add_subtree(ti, ett_hip_tlv_data);
                /* Cert Group */
                proto_tree_add_item(t, hf_hip_tlv_cert_group, tvb, newoffset, 1, ENC_BIG_ENDIAN);
                newoffset++;
                /* Cert Count */
                proto_tree_add_item(t, hf_hip_tlv_cert_count, tvb, newoffset, 1, ENC_BIG_ENDIAN);
                newoffset++;
                /* Cert ID */
                proto_tree_add_item(t, hf_hip_tlv_cert_id, tvb, newoffset, 1, ENC_BIG_ENDIAN);
                newoffset++;
                /* Cert Type */
                proto_tree_add_item(t, hf_hip_tlv_cert_type, tvb, newoffset, 1, ENC_BIG_ENDIAN);
                newoffset++;
                /* Certificate */
                proto_tree_add_item(t, hf_hip_tlv_certificate, tvb, newoffset,
                                     tlv_len-4, ENC_NA);
                break;
        case PARAM_NOTIFICATION:
                t = proto_item_add_subtree(ti, ett_hip_tlv_data);
                /* Reserved */
                proto_tree_add_item(t, hf_hip_tlv_notification_res, tvb, newoffset, 2, ENC_BIG_ENDIAN);
                newoffset += 2;
                /* Notification Message Type */
                proto_tree_add_item(t, hf_hip_tlv_notification_type, tvb, newoffset, 2, ENC_BIG_ENDIAN);
                newoffset += 2;
                /* Notification Data */
                proto_tree_add_item(t, hf_hip_tlv_notification_data, tvb, newoffset,
                                     tlv_len-4, ENC_NA);
                break;
        case PARAM_ECHO_REQUEST_SIGNED:
        case PARAM_ECHO_RESPONSE_SIGNED:
        case PARAM_ECHO_REQUEST_UNSIGNED:
        case PARAM_ECHO_RESPONSE_UNSIGNED:
                t = proto_item_add_subtree(ti, ett_hip_tlv_data);
                /* Variable length Opaque Data */
                proto_tree_add_item(t, hf_hip_tlv_opaque_data, tvb, newoffset,
                                     tlv_len, ENC_NA);
                break;
        case PARAM_REG_INFO:
        case PARAM_REG_REQUEST:
        case PARAM_REG_RESPONSE:
        case PARAM_REG_FAILED:
                t = proto_item_add_subtree(ti, ett_hip_tlv_data);
                if (type == PARAM_REG_INFO) {
                        /* Min Lifetime */
                        proto_tree_add_item(t, hf_hip_tlv_reg_ltmin, tvb, newoffset, 1, ENC_BIG_ENDIAN);
                        newoffset++;
                        /* Max Lifetime */
                        proto_tree_add_item(t, hf_hip_tlv_reg_ltmax, tvb, newoffset, 1, ENC_BIG_ENDIAN);
                        newoffset++;
                        tlv_len -= 2;
                } else if (type == PARAM_REG_FAILED) {
                        /* Failure Type */
                        proto_tree_add_item(t, hf_hip_tlv_reg_failtype, tvb, newoffset, 1, ENC_BIG_ENDIAN);
                        newoffset++;;
                        tlv_len--;
                } else {
                        /* Lifetime */
                        proto_tree_add_item(t, hf_hip_tlv_reg_lt, tvb, newoffset, 1, ENC_BIG_ENDIAN);
                        newoffset++;
                        tlv_len--;
                }
                /* Reg Type 1 ... n, Padding */
                while (tlv_len > 0) {
                        reg_type = tvb_get_guint8(tvb, newoffset);
                        proto_tree_add_uint_format(t, hf_hip_tlv_reg_type, tvb,
                                                   newoffset, 1, reg_type, "%u (%s)", reg_type,
                                                   val_to_str(reg_type, reg_type_vals, "Unknown"));
                        /* one byte per registration type */
                        tlv_len--;
                        newoffset++;
                }
                break;
        case PARAM_HMAC:
        case PARAM_HMAC_2:
        case PARAM_RVS_HMAC:
        case PARAM_RELAY_HMAC:
                t = proto_item_add_subtree(ti, ett_hip_tlv_data);
                /* HMAC */
                proto_tree_add_item(t, hf_hip_tlv_hmac, tvb, offset+4,
                                     tlv_len, ENC_NA);
                break;
        case PARAM_HIP_SIGNATURE:
        case PARAM_HIP_SIGNATURE_2:
                t = proto_item_add_subtree(ti, ett_hip_tlv_data);
                /* Signature algorithm */
                n = tvb_get_guint8(tvb, offset+4);
                proto_tree_add_uint_format(t, hf_hip_tlv_sig_alg, tvb, newoffset, 1,
                                           n, "%u (%s)", n,
                                           val_to_str(n, sig_alg_vals, "Unknown"));
                newoffset++;
                /* Signature */
                proto_tree_add_item(t, hf_hip_tlv_sig, tvb, newoffset, tlv_len-1,
                                    ENC_NA);
                break;
        case PARAM_FROM:
                t = proto_item_add_subtree(ti, ett_hip_tlv_data);
                /* Address */
                proto_tree_add_item(t, hf_hip_tlv_from_address, tvb, newoffset, 16, FALSE);
                break;
        case PARAM_VIA_RVS:
                t = proto_item_add_subtree(ti, ett_hip_tlv_data);
                /* RVS Addresses  */
                while (tlv_len > 0) {
                        proto_tree_add_item(t, hf_hip_tlv_rvs_address, tvb, newoffset, 16, FALSE);
                        tlv_len -= 16;
                        newoffset += 16;
                }
                break;
        case PARAM_RELAY_FROM:
                t = proto_item_add_subtree(ti, ett_hip_tlv_data);
                /* Port */
                proto_tree_add_item(t, hf_hip_tlv_relay_from_port, tvb, newoffset, 2, ENC_BIG_ENDIAN);
                newoffset += 2;
                /* Protocol */
                proto_tree_add_item(t, hf_hip_tlv_relay_from_protocol, tvb, newoffset, 1, ENC_BIG_ENDIAN);
                newoffset += 1;
                /* Reserved */
                proto_tree_add_item(t, hf_hip_tlv_relay_from_reserved, tvb, newoffset, 1, ENC_BIG_ENDIAN);
                newoffset += 1;
                /* Address */
                proto_tree_add_item(t, hf_hip_tlv_relay_to_address, tvb, newoffset, 16, FALSE);
                break;
        case PARAM_RELAY_TO:
                t = proto_item_add_subtree(ti, ett_hip_tlv_data);
                /* Port */
                proto_tree_add_item(t, hf_hip_tlv_relay_to_port, tvb, newoffset, 2, ENC_BIG_ENDIAN);
                newoffset += 2;
                /* Protocol */
                proto_tree_add_item(t, hf_hip_tlv_relay_to_protocol, tvb, newoffset, 1, ENC_BIG_ENDIAN);
                newoffset += 1;
                /* Reserved */
                proto_tree_add_item(t, hf_hip_tlv_relay_to_reserved, tvb, newoffset, 1, ENC_BIG_ENDIAN);
                newoffset += 1;
                /* Address */
                proto_tree_add_item(t, hf_hip_tlv_relay_to_address, tvb, newoffset, 16, FALSE);
                break;
        case PARAM_REG_FROM:
                t = proto_item_add_subtree(ti, ett_hip_tlv_data);
                /* Port */
                proto_tree_add_item(t, hf_hip_tlv_reg_from_port, tvb, newoffset, 2, ENC_BIG_ENDIAN);
                newoffset += 2;
                /* Protocol */
                proto_tree_add_item(t, hf_hip_tlv_reg_from_protocol, tvb, newoffset, 1, ENC_BIG_ENDIAN);
                newoffset += 1;
                /* Reserved */
                proto_tree_add_item(t, hf_hip_tlv_reg_from_reserved, tvb, newoffset, 1, ENC_BIG_ENDIAN);
                newoffset += 1;
                /* Address */
                proto_tree_add_item(t, hf_hip_tlv_reg_from_address, tvb, newoffset, 16, FALSE);
                break;
        default:
                break;
        }
        return (0);
}

void
proto_register_hip(void)
{
        static hf_register_info hf[] = {
                { &hf_hip_proto,
                  { "Payload Protocol", "hip.proto",
                    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_hdr_len,
                  { "Header Length", "hip.hdr_len",
                    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_packet_type,
                  { "Packet Type", "hip.packet_type",
                    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_shim6_fixed_bit_p,
                  { "Header fixed bit P", "hip.shim6_fixed_p",
                    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_version,
                  { "Version", "hip.version",
                    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_shim6_fixed_bit_s,
                  { "Header fixed bit S", "hip.shim6_fixed_s",
                    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_controls,
                  { "HIP Controls", "hip.controls",
                    FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_controls_anon,
                  { "Anonymous (Sender's HI is anonymous)", "hip.controls.a",
                    FT_BOOLEAN, 16, NULL, HIP_CONTROL_A_MASK, NULL, HFILL }},

                { &hf_hip_checksum,
                  { "Checksum", "hip.checksum",
                    FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_hit_sndr,
                  { "Sender's HIT", "hip.hit_sndr",
                    FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_hit_rcvr,
                  { "Receiver's HIT", "hip.hit_rcvr",
                    FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_type,
                  { "Type", "hip.type",
                    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_r1_res,
                  { "Reserved", "hip.tlv.r1_reserved",
                    FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_r1count,
                  { "R1 Counter", "hip.tlv.r1_counter",
                    FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_puzzle_k,
                  { "Difficulty (K)", "hip.tlv_puzzle_k",
                    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_puzzle_life,
                  { "Lifetime", "hip.tlv_puzzle_lifetime",
                    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_puzzle_o,
                  { "Opaque Data", "hip.tlv_puzzle_opaque",
                    FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_puzzle_i,
                  { "Random number (I)", "hip.tlv.puzzle_random_i",
                    FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_solution_k,
                  { "Difficulty (K)", "hip.tlv_solution_k",
                    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_solution_reserved,
                  { "Reserved", "hip.tlv_solution_reserved",
                    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_solution_o,
                  { "Opaque Data", "hip.tlv_solution_opaque",
                    FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_solution_i,
                  { "Random number (I)", "hip.tlv.solution_random_i",
                    FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_solution_j,
                  { "Solution (J)", "hip.tlv_solution_j",
                    FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_ei_res,
                  { "Reserved", "hip.tlv_esp_info_reserved",
                  FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_ei_keyidx,
                  { "Keymaterial Index", "hip.tlv_esp_info_key_index",
                    FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_ei_oldspi,
                  { "Old SPI", "hip.tlv_esp_info_old_spi",
                    FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_ei_newspi,
                  { "New SPI", "hip.tlv_esp_info_new_spi",
                    FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_seq_updid,
                  { "Seq Update ID", "hip.tlv_seq_update_id",
                    FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_ack_updid,
                  { "ACKed Peer Update ID", "hip.tlv_ack_updid",
                    FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_dh_group_id,
                  { "Group ID", "hip.tlv.dh_group_id",
                    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_dh_pv_length,
                  { "Public Value Length", "hip.tlv.dh_pv_length",
                    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_dh_pub,
                  { "Public Value", "hip.tlv.dh_public_value",
                    FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_trans_id,
                  { "Transform ID", "hip.tlv.trans_id",
                    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_esp_reserved,
                  { "Reserved", "hip.tlv.esp_trans_res",
                    FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_host_id_len,
                  { "Host Identity Length", "hip.tlv.host_id_length",
                    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_host_di_type,
                  { "Domain Identifier Type", "hip.tlv.host_domain_id_type",
                    FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }},

                { &hf_hip_tlv_host_di_len,
                  { "Domain Identifier Length", "hip.tlv.host_domain_id_length",
                    FT_UINT16, BASE_DEC, NULL, 0x0FFF, NULL, HFILL }},

                { &hf_hip_tlv_host_id_hdr,
                  { "Host Identity flags", "hip.tlv.host_id_hdr",
                    FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_host_id_hdr_flags,
                  { "Host Identity Header Flags", "hip.tlv.host_id_header_flags",
                    FT_UINT32, BASE_HEX, VALS(hi_hdr_flags_vals),
                    HI_HDR_FLAGS_MASK, NULL, HFILL }},

                { &hf_hip_tlv_host_id_hdr_proto,
                  { "Host Identity Header Protocol", "hip.tlv.host_id_header_proto",
                    FT_UINT32, BASE_HEX, VALS(hi_hdr_proto_vals),
                    HI_HDR_PROTO_MASK, NULL, HFILL }},

                { &hf_hip_tlv_host_id_hdr_alg,
                  { "Host Identity Header Algorithm", "hip.tlv.host_id_header_algo",
                    FT_UINT32, BASE_HEX, VALS(hi_hdr_alg_vals),
                    HI_HDR_ALG_MASK, NULL, HFILL }},

                { &hf_hip_tlv_host_id_t,
                  { "Host Identity T", "hip.tlv.host_identity_t",
                    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_host_id_q,
                  { "Host Identity Q", "hip.tlv.host_identity_q",
                    FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_host_id_p,
                  { "Host Identity P", "hip.tlv.host_id_p",
                    FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_host_id_g,
                  { "Host Identity G", "hip.tlv.host_id_g",
                    FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_host_id_y,
                  { "Host Identity Y (public value)", "hip.tlv.host_id_y",
                    FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_host_id_e_len,
                  { "RSA Host Identity exponent length (e_len)", "hip.tlv.host_id_e_length",
                    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_host_id_e,
                  { "RSA Host Identity exponent (e)", "hip.tlv.host_id_e",
                    FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_host_id_n,
                  { "RSA Host Identity public modulus (n)", "hip.tlv.host_id_n",
                    FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_notification_res,
                  { "Notification Reserved", "hip.tlv.notification_res",
                    FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_notification_type,
                  { "Notification Message Type", "hip.tlv.notification_type",
                    FT_UINT16, BASE_DEC, VALS(notification_vals), 0xFFFF, NULL, HFILL }},

                { &hf_hip_tlv_notification_data,
                  { "Notification Data", "hip.tlv.notification_data",
                    FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_opaque_data,
                  { "Opaque Data", "hip.tlv.opaque_data",
                    FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_reg_ltmin,
                  { "Minimum Registration Lifetime", "hip.tlv.reg_ltmin",
                    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_reg_ltmax,
                  { "Maximum Registration Lifetime", "hip.tlv.reg_ltmax",
                    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_reg_lt,
                  { "Registration Lifetime", "hip.tlv.reg_lt",
                    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_reg_type,
                  { "Registration Type", "hip.tlv.reg_type",
                    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_reg_failtype,
                  { "Registration Failure Type", "hip.tlv.reg_failtype",
                    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_hmac,
                  { "HMAC", "hip.tlv.hmac",
                    FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_sig_alg,
                  { "Signature Algorithm", "hip.tlv.sig_alg",
                    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_sig,
                  { "Signature", "hip.tlv.sig",
                    FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_enc_reserved,
                  { "Reserved", "hip.tlv.enc_reserved",
                    FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_locator_traffic_type,
                  { "Traffic Type", "hip.tlv.locator_traffic_type",
                    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_locator_type,
                  { "Locator Type", "hip.tlv.locator_type",
                    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_locator_len,
                  { "Locator Length", "hip.tlv.locator_len",
                    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_locator_reserved,
                  { "Reserved", "hip.tlv.locator_reserved",
                    FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_locator_lifetime,
                  { "Locator Lifetime", "hip.tlv.locator_lifetime",
                    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_locator_port,
                  { "Locator port", "hip.tlv.locator_port",
                    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_locator_transport_protocol,
                  { "Locator transport protocol", "hip.tlv.locator_transport_protocol",
                    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_locator_kind,
                  { "Locator kind", "hip.tlv.locator_kind",
                    FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_locator_priority,
                  { "Locator priority", "hip.tlv.locator_priority",
                    FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_locator_spi,
                  { "Locator SPI", "hip.tlv.locator_spi",
                    FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_locator_address,
                  { "Locator" , "hip.tlv.locator_address",
                    FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_cert_group,
                  { "Cert group", "hip.tlv.cert_group",
                    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_cert_count,
                  { "Cert count", "hip.tlv.cert_count",
                    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_cert_id,
                  { "Cert ID", "hip.tlv.cert_id",
                    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_cert_type,
                  { "Cert type", "hip.tlv.cert_type",
                    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_certificate,
                  { "Certificate", "hip.tlv.certificate",
                    FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_nat_traversal_mode_id,
                  { "NAT Traversal Mode ID", "hip.tlv.nat_traversal_mode_id",
                    FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_relay_from_port,
                  { "Relay From Port", "hip.tlv.relay_from_port",
                    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_relay_to_port,
                  { "Relay To Port", "hip.tlv.relay_to_port",
                    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_reg_from_port,
                  { "Port", "hip.tlv.reg_from_port",
                    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_transaction_minta,
                  { "Min Ta" , "hip.tlv_transaction_minta",
                    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_from_address,
                  { "Address" , "hip.tlv_from_address",
                    FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_rvs_address,
                  { "RVS Address" , "hip.tlv_rvs_address",
                    FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_relay_from_protocol,
                  { "Protocol" , "hip.tlv_relay_from_protocol",
                    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_relay_from_reserved,
                  { "Reserved" , "hip.tlv_relay_from_reserved",
                    FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_relay_from_address,
                  { "Address" , "hip.tlv_relay_from_address",
                    FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_relay_to_protocol,
                  { "Protocol" , "hip.tlv_relay_to_protocol",
                    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_relay_to_reserved,
                  { "Reserved" , "hip.tlv_relay_to_reserved",
                    FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_relay_to_address,
                  { "Address" , "hip.tlv_relay_to_address",
                    FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_reg_from_protocol,
                  { "Protocol" , "hip.tlv_reg_from_protocol",
                    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_reg_from_reserved,
                  { "Reserved" , "hip.tlv_reg_from_reserved",
                    FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_hip_tlv_reg_from_address,
                  { "Address" , "hip.tlv_reg_from_address",
                    FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        };

        static gint *ett[] = {
                &ett_hip,
                &ett_hip_controls,
                &ett_hip_tlv,
                &ett_hip_tlv_data,
                &ett_hip_tlv_host_id_hdr,
                &ett_hip_locator_data,
        };

        proto_hip = proto_register_protocol("Host Identity Protocol",
                                            "HIP", "hip");

        proto_register_field_array(proto_hip, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_hip(void)
{
        dissector_handle_t hip_handle;
        dissector_handle_t hip_handle2;

        hip_handle = create_dissector_handle(dissect_hip, proto_hip);
        dissector_add_uint("ip.proto", IP_PROTO_HIP, hip_handle);

        hip_handle2 = create_dissector_handle(dissect_hip_in_udp, proto_hip);
        dissector_add_uint("udp.port", 10500, hip_handle2);
}
