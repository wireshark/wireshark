/* packet-lisp.c
 * Routines for Locator/ID Separation Protocol (LISP) Control Message dissection
 * Copyright 2011, 2014 Lorand Jakab <ljakab@ac.upc.edu>
 *
 * Geo Coordinates LCAF dissection based on previous work by Radu Terciu
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "packet-lisp.h"

#include <epan/to_str.h>
#include <epan/afn.h>
#include <epan/oui.h>
#include <epan/expert.h>

#include <wsutil/utf8_entities.h>

void proto_register_lisp(void);
void proto_reg_handoff_lisp(void);

/*
 * See RFC 6830 "Locator/ID Separation Protocol (LISP)",
 * draft-ietf-lisp-lcaf-05 "LISP Canonical Address Format (LCAF)",
 * draft-ietf-lisp-vendor-lcaf-07 "Vendor Specific LISP Canonical Address Format (LCAF)"
 * draft-ietf-lisp-sec-04 "LISP-Security (LISP-SEC)",
 * draft-ermagan-lisp-nat-traversal-03 "NAT traversal for LISP",
 * draft-farinacci-lisp-name-encoding-09 "LISP Distinguished Name Encoding"
 * for packet format and protocol information.
 */

/* LISP Control Message types */
#define LISP_MAP_REQUEST    1
#define LISP_MAP_REPLY      2
#define LISP_MAP_REGISTER   3
#define LISP_MAP_NOTIFY     4
#define LISP_MAP_REFERRAL   6
#define LISP_INFO           7
#define LISP_ECM            8

#define LISP_ACT_NONE       0
#define LISP_ACT_FWD_NATIVE 1
#define LISP_ACT_MREQ       2
#define LISP_ACT_DROP       3
#define LISP_ACT_DROP_PD    4
#define LISP_ACT_DROP_AF    5
#define LISP_ACT_FWD_UA     6

#define DDT_NODE_REF        0
#define DDT_MS_REF          1
#define DDT_MS_ACK          2
#define DDT_MS_NREG         3
#define DDT_DLGT_HOLE       4
#define DDT_NAUTH           5

#define LCAF_NULL           0
#define LCAF_AFI_LIST       1
#define LCAF_IID            2
#define LCAF_ASN            3
#define LCAF_APP_DATA       4
#define LCAF_GEO            5
#define LCAF_OKEY           6
#define LCAF_NATT           7
#define LCAF_NONCE_LOC      8
#define LCAF_MCAST_INFO     9
#define LCAF_ELP            10
#define LCAF_SEC_KEY        11
#define LCAF_SRC_DST_KEY    12
#define LCAF_RLE            13
#define LCAF_JSON           14
#define LCAF_KV_ADDR_PAIR   15
#define LCAF_VENDOR         255

#define LCAF_HEADER_LEN     6
#define LISP_ECM_HEADER_LEN 4

#define LISP_MAP_ACT        0xE000
#define LISP_MAP_AUTH       0x1000
#define REFERRAL_INCOMPLETE 0x0800
#define LOCAL_BIT_MASK      0x0004
#define PROBE_BIT_MASK      0x0002
#define REACH_BIT_MASK      0x0001

#define MAP_REQ_FLAG_A      0x080000
#define MAP_REQ_FLAG_M      0x040000
#define MAP_REQ_FLAG_P      0x020000
#define MAP_REQ_FLAG_S      0x010000
#define MAP_REQ_FLAG_p      0x008000
#define MAP_REQ_FLAG_s      0x004000
#define MAP_REQ_RESERVED    0x003FE0

#define MAP_REP_FLAG_P      0x080000
#define MAP_REP_FLAG_E      0x040000
#define MAP_REP_FLAG_S      0x020000
#define MAP_REP_RESERVED    0x01FFFF

#define MAP_REG_FLAG_P      0x080000
#define MAP_REG_FLAG_S      0x040000
#define MAP_REG_FLAG_I      0x020000
#define MAP_REG_FLAG_R      0x010000
#define MAP_REG_RESERVED    0x00FFFE
#define MAP_REG_FLAG_M      0x000001

#define MAP_NOT_FLAG_I      0x080000
#define MAP_NOT_FLAG_R      0x040000
#define MAP_NOT_RESERVED    0x03FFFF

#define MAP_REF_RESERVED    0x0FFFFF

#define INFO_FLAG_R         0x080000
#define INFO_RESERVED       0x07FFFFFF

#define ECM_FLAG_S          0x08000000
#define ECM_FLAG_D          0x04000000

#define MCINFO_FLAG_R       0x04
#define MCINFO_FLAG_L       0x02
#define MCINFO_FLAG_J       0x01

#define ELP_FLAG_L          0x0004
#define ELP_FLAG_P          0x0002
#define ELP_FLAG_S          0x0001

/* Initialize the protocol and registered fields */
static int proto_lisp;
static int hf_lisp_type;
static int hf_lisp_irc;
static int hf_lisp_records;
static int hf_lisp_nonce;
static int hf_lisp_keyid;
static int hf_lisp_authlen;
static int hf_lisp_auth;
static int hf_lisp_msrtr_keyid;
static int hf_lisp_msrtr_authlen;
static int hf_lisp_msrtr_auth;
static int hf_lisp_xtrid;
static int hf_lisp_siteid;

/* Map-Request fields */
static int hf_lisp_mreq_flags;
static int hf_lisp_mreq_flags_auth;
static int hf_lisp_mreq_flags_mrp;
static int hf_lisp_mreq_flags_probe;
static int hf_lisp_mreq_flags_smr;
static int hf_lisp_mreq_flags_pitr;
static int hf_lisp_mreq_flags_smri;
static int hf_lisp_mreq_res;
static int hf_lisp_mreq_srceid_afi;
static int hf_lisp_mreq_srceid_string;
static int hf_lisp_mreq_srceid_ipv4;
static int hf_lisp_mreq_srceid_ipv6;
static int hf_lisp_mreq_srceid_mac;
static int hf_lisp_mreq_itr_rloc;
static int hf_lisp_mreq_itr_rloc_afi;
static int hf_lisp_mreq_itr_rloc_ipv4;
static int hf_lisp_mreq_itr_rloc_ipv6;
static int hf_lisp_mreq_record;
static int hf_lisp_mreq_record_res;
static int hf_lisp_mreq_record_prefix_length;
static int hf_lisp_mreq_record_prefix_afi;
static int hf_lisp_mreq_record_prefix_ipv4;
static int hf_lisp_mreq_record_prefix_ipv6;
static int hf_lisp_mreq_record_prefix_mac;
static int hf_lisp_mreq_record_prefix_dn;

/* Map-Reply fields */
static int hf_lisp_mrep_record;
static int hf_lisp_mrep_flags_probe;
static int hf_lisp_mrep_flags_enlr;
static int hf_lisp_mrep_flags_sec;
static int hf_lisp_mrep_res;

/* Map-Register fields */
static int hf_lisp_mreg_flags_pmr;
static int hf_lisp_mreg_flags_sec;
static int hf_lisp_mreg_flags_xtrid;
static int hf_lisp_mreg_flags_rtr;
static int hf_lisp_mreg_flags_wmn;
static int hf_lisp_mreg_res;

/* Map-Notify fields */
static int hf_lisp_mnot_flags_xtrid;
static int hf_lisp_mnot_flags_rtr;
static int hf_lisp_mnot_res;

/* Map-Referral fields */
static int hf_lisp_mref_res;
static int hf_lisp_referral_sigcnt;
static int hf_lisp_referral_incomplete;

/* Info fields */
static int hf_lisp_info_r;
static int hf_lisp_info_res1;
static int hf_lisp_info_ttl;
static int hf_lisp_info_res2;
static int hf_lisp_info_prefix_masklen;
static int hf_lisp_info_prefix_afi;
static int hf_lisp_info_prefix_ipv4;
static int hf_lisp_info_prefix_ipv6;
static int hf_lisp_info_afi;

/* Mapping record fields */
static int hf_lisp_mapping;
static int hf_lisp_mapping_ttl;
static int hf_lisp_mapping_loccnt;
static int hf_lisp_mapping_eid_masklen;
static int hf_lisp_mapping_act;
static int hf_lisp_mapping_auth;
static int hf_lisp_mapping_res1;
static int hf_lisp_mapping_res2;
static int hf_lisp_mapping_ver;
static int hf_lisp_mapping_eid_afi;
static int hf_lisp_mapping_eid_ipv4;
static int hf_lisp_mapping_eid_ipv6;
static int hf_lisp_mapping_eid_mac;
static int hf_lisp_mapping_eid_dn;

/* Locator fields */
static int hf_lisp_loc;
static int hf_lisp_loc_priority;
static int hf_lisp_loc_weight;
static int hf_lisp_loc_mpriority;
static int hf_lisp_loc_mweight;
static int hf_lisp_loc_flags;
static int hf_lisp_loc_flags_local;
static int hf_lisp_loc_flags_probe;
static int hf_lisp_loc_flags_reach;
static int hf_lisp_loc_flags_res;
static int hf_lisp_loc_afi;
static int hf_lisp_loc_locator;

/* LCAF fields */
static int hf_lisp_lcaf;
static int hf_lisp_lcaf_header;
static int hf_lisp_lcaf_res1;
static int hf_lisp_lcaf_flags;
static int hf_lisp_lcaf_type;
static int hf_lisp_lcaf_res2;
static int hf_lisp_lcaf_length;

/* LCAF AFI List fields */
static int hf_lisp_lcaf_afi_list_item;
static int hf_lisp_lcaf_afi_list_afi;
static int hf_lisp_lcaf_afi_list_ipv4;
static int hf_lisp_lcaf_afi_list_ipv6;
static int hf_lisp_lcaf_afi_list_mac;
static int hf_lisp_lcaf_afi_list_dn;

/* LCAF IID fields */
static int hf_lisp_lcaf_iid;
static int hf_lisp_lcaf_iid_afi;
static int hf_lisp_lcaf_iid_ipv4;
static int hf_lisp_lcaf_iid_ipv6;
static int hf_lisp_lcaf_iid_mac;
static int hf_lisp_lcaf_iid_dn;

/* LCAF ASN fields */
static int hf_lisp_lcaf_asn;
static int hf_lisp_lcaf_asn_afi;
static int hf_lisp_lcaf_asn_ipv4;
static int hf_lisp_lcaf_asn_ipv6;
static int hf_lisp_lcaf_asn_mac;
static int hf_lisp_lcaf_asn_dn;

/* LCAF Geo Coordinates fields */
static int hf_lisp_lcaf_geo_lat;
static int hf_lisp_lcaf_geo_lat_hemisphere;
static int hf_lisp_lcaf_geo_lat_deg;
static int hf_lisp_lcaf_geo_lat_min;
static int hf_lisp_lcaf_geo_lat_sec;
static int hf_lisp_lcaf_geo_lon;
static int hf_lisp_lcaf_geo_lon_hemisphere;
static int hf_lisp_lcaf_geo_lon_deg;
static int hf_lisp_lcaf_geo_lon_min;
static int hf_lisp_lcaf_geo_lon_sec;
static int hf_lisp_lcaf_geo_alt;
static int hf_lisp_lcaf_geo_afi;
static int hf_lisp_lcaf_geo_ipv4;
static int hf_lisp_lcaf_geo_ipv6;
static int hf_lisp_lcaf_geo_mac;
static int hf_lisp_lcaf_geo_dn;

/* LCAF NATT fields */
static int hf_lisp_lcaf_natt_msport;
static int hf_lisp_lcaf_natt_etrport;
static int hf_lisp_lcaf_natt_rloc;
static int hf_lisp_lcaf_natt_rloc_afi;
static int hf_lisp_lcaf_natt_rloc_ipv4;
static int hf_lisp_lcaf_natt_rloc_ipv6;

/* LCAF Nonce Locator fields */
static int hf_lisp_lcaf_nonce_loc_res;
static int hf_lisp_lcaf_nonce_loc;
static int hf_lisp_lcaf_nonce_loc_afi;
static int hf_lisp_lcaf_nonce_loc_ipv4;
static int hf_lisp_lcaf_nonce_loc_ipv6;
static int hf_lisp_lcaf_nonce_loc_mac;
static int hf_lisp_lcaf_nonce_loc_dn;

/* LCAF Multicast Group Membership Information fields */
static int hf_lisp_lcaf_mcinfo_flags;
static int hf_lisp_lcaf_mcinfo_flags_res;
static int hf_lisp_lcaf_mcinfo_flags_rp;
static int hf_lisp_lcaf_mcinfo_flags_leave;
static int hf_lisp_lcaf_mcinfo_flags_join;
static int hf_lisp_lcaf_mcinfo_iid;
static int hf_lisp_lcaf_mcinfo_res;
static int hf_lisp_lcaf_mcinfo_src_masklen;
static int hf_lisp_lcaf_mcinfo_grp_masklen;
static int hf_lisp_lcaf_mcinfo_src;
static int hf_lisp_lcaf_mcinfo_src_afi;
static int hf_lisp_lcaf_mcinfo_src_ipv4;
static int hf_lisp_lcaf_mcinfo_src_ipv6;
static int hf_lisp_lcaf_mcinfo_grp;
static int hf_lisp_lcaf_mcinfo_grp_afi;
static int hf_lisp_lcaf_mcinfo_grp_ipv4;
static int hf_lisp_lcaf_mcinfo_grp_ipv6;

/* LCAF ELP fields */
static int hf_lisp_lcaf_elp_hop;
static int hf_lisp_lcaf_elp_hop_flags;
static int hf_lisp_lcaf_elp_hop_flags_res;
static int hf_lisp_lcaf_elp_hop_flags_lookup;
static int hf_lisp_lcaf_elp_hop_flags_probe;
static int hf_lisp_lcaf_elp_hop_flags_strict;
static int hf_lisp_lcaf_elp_hop_afi;
static int hf_lisp_lcaf_elp_hop_ipv4;
static int hf_lisp_lcaf_elp_hop_ipv6;

/* LCAF Source/Destination 2-Tuple Lookups fields */
static int hf_lisp_lcaf_srcdst_res;
static int hf_lisp_lcaf_srcdst_src_masklen;
static int hf_lisp_lcaf_srcdst_dst_masklen;
static int hf_lisp_lcaf_srcdst_src;
static int hf_lisp_lcaf_srcdst_src_afi;
static int hf_lisp_lcaf_srcdst_src_ipv4;
static int hf_lisp_lcaf_srcdst_src_ipv6;
static int hf_lisp_lcaf_srcdst_src_mac;
static int hf_lisp_lcaf_srcdst_dst;
static int hf_lisp_lcaf_srcdst_dst_afi;
static int hf_lisp_lcaf_srcdst_dst_ipv4;
static int hf_lisp_lcaf_srcdst_dst_ipv6;
static int hf_lisp_lcaf_srcdst_dst_mac;

/* LCAF RLE fields */
static int hf_lisp_lcaf_rle_entry;
static int hf_lisp_lcaf_rle_entry_res;
static int hf_lisp_lcaf_rle_entry_level;
static int hf_lisp_lcaf_rle_entry_afi;
static int hf_lisp_lcaf_rle_entry_ipv4;
static int hf_lisp_lcaf_rle_entry_ipv6;

/* LCAF Key/Value Pair fields */
static int hf_lisp_lcaf_kv_key;
static int hf_lisp_lcaf_kv_key_afi;
static int hf_lisp_lcaf_kv_key_ipv4;
static int hf_lisp_lcaf_kv_key_ipv6;
static int hf_lisp_lcaf_kv_key_mac;
static int hf_lisp_lcaf_kv_key_dn;
static int hf_lisp_lcaf_kv_value;
static int hf_lisp_lcaf_kv_value_afi;
static int hf_lisp_lcaf_kv_value_ipv4;
static int hf_lisp_lcaf_kv_value_ipv6;
static int hf_lisp_lcaf_kv_value_mac;
static int hf_lisp_lcaf_kv_value_dn;

/* Vendor Specific LCAF fields */
static int hf_lisp_lcaf_vendor_res;
static int hf_lisp_lcaf_vendor_oui;
static int hf_lisp_lcaf_vendor_data;

/* Encapsulated Control Message fields */
static int hf_lisp_ecm_flags_sec;
static int hf_lisp_ecm_flags_ddt;
static int hf_lisp_ecm_res;

/* Initialize the subtree pointers */
static int ett_lisp;
static int ett_lisp_mr;
static int ett_lisp_mreq_flags;
static int ett_lisp_mapping;
static int ett_lisp_itr;
static int ett_lisp_record;
static int ett_lisp_lcaf;
static int ett_lisp_lcaf_header;
static int ett_lisp_lcaf_geo_lat;
static int ett_lisp_lcaf_geo_lon;
static int ett_lisp_lcaf_natt_rloc;
static int ett_lisp_lcaf_mcinfo_flags;
static int ett_lisp_lcaf_mcinfo_src;
static int ett_lisp_lcaf_mcinfo_grp;
static int ett_lisp_lcaf_elp_hop;
static int ett_lisp_lcaf_elp_hop_flags;
static int ett_lisp_lcaf_srcdst_src;
static int ett_lisp_lcaf_srcdst_dst;
static int ett_lisp_lcaf_rle_entry;
static int ett_lisp_lcaf_kv_key;
static int ett_lisp_lcaf_kv_value;
static int ett_lisp_lcaf_vendor;
static int ett_lisp_loc;
static int ett_lisp_loc_flags;
static int ett_lisp_info_prefix;
static int ett_lisp_afi_list;

static expert_field ei_lisp_undecoded;
static expert_field ei_lisp_expected_field;
static expert_field ei_lisp_invalid_field;
static expert_field ei_lisp_unexpected_field;

static dissector_handle_t lisp_handle;

static dissector_handle_t ipv4_handle;
static dissector_handle_t ipv6_handle;

static bool encapsulated;
static bool ddt_originated;

static const value_string lisp_typevals[] = {
    { LISP_MAP_REQUEST,     "Map-Request" },
    { LISP_MAP_REPLY,       "Map-Reply" },
    { LISP_MAP_REGISTER,    "Map-Register" },
    { LISP_MAP_NOTIFY,      "Map-Notify" },
    { LISP_MAP_REFERRAL,    "Map-Referral" },
    { LISP_INFO,            "Info" },
    { LISP_ECM,             "Encapsulated Control Message" },
    { 0,                    NULL}
};

static const value_string mapping_actions[] = {
    { LISP_ACT_NONE,        "No-Action" },
    { LISP_ACT_FWD_NATIVE,  "Natively-Forward" },
    { LISP_ACT_MREQ,        "Send-Map-Request" },
    { LISP_ACT_DROP,        "Drop/No-Reason" },
    { LISP_ACT_DROP_PD,     "Drop/Policy-Denied" },
    { LISP_ACT_DROP_AF,     "Drop/Authentication-Failure" },
    { LISP_ACT_FWD_UA,      "Forward-For-Unknown-Address" },
    { 0,                    NULL}
};

static const value_string referral_actions[] = {
    { DDT_NODE_REF,         "Node Referral" },
    { DDT_MS_REF,           "Map-Server Referral" },
    { DDT_MS_ACK,           "Map-Server ACK" },
    { DDT_MS_NREG,          "Map-Server Not Registered" },
    { DDT_DLGT_HOLE,        "Delegation Hole" },
    { DDT_NAUTH,            "Not Authoritative" },
    { 0,                    NULL}
};

static const value_string lcaf_typevals[] = {
    { LCAF_NULL,            "Null Body" },
    { LCAF_AFI_LIST,        "AFI List" },
    { LCAF_IID,             "Instance ID" },
    { LCAF_ASN,             "AS Number" },
    { LCAF_APP_DATA,        "Application Data" },
    { LCAF_GEO,             "Geo Coordinates" },
    { LCAF_OKEY,            "Opaque Key" },
    { LCAF_NATT,            "NAT Traversal" },
    { LCAF_NONCE_LOC,       "Nonce Locator" },
    { LCAF_MCAST_INFO,      "Multicast Info" },
    { LCAF_ELP,             "Explicit Locator Path" },
    { LCAF_SEC_KEY,         "Security Key" },
    { LCAF_SRC_DST_KEY,     "Source/Dest Key" },
    { LCAF_RLE,             "Replication List Entry" },
    { LCAF_JSON,            "JSON Data Model" },
    { LCAF_KV_ADDR_PAIR,    "Key/Value Address Pair" },
    { LCAF_VENDOR,          "Vendor Specific LCAF" },
    { 0,                    NULL}
};

static const value_string lat_typevals[] = {
    { 0,                    "S" },
    { 1,                    "N" },
    { 0,                    NULL}
};

static const value_string lon_typevals[] = {
    { 0,                    "W" },
    { 1,                    "E" },
    { 0,                    NULL}
};

/* Add your company OUI here if you're developing a vendor LCAF dissector */
static const value_string oui_vals[] = {
    { OUI_CISCO,            "Cisco" },
    { 0,                    NULL}
};

static int
get_lcaf_data(tvbuff_t *tvb, int offset, uint8_t *lcaf_type, uint16_t *len)
{
    /* Jump over Rsvd1 and Flags (16 bits) */
    offset += 2;

    /* Type (8 bits) */
    if (lcaf_type)
        *lcaf_type = tvb_get_uint8(tvb, offset);
    offset += 1;

    /* Jump over Rsvd2 bits (8 bits) */
    offset += 1;

    /* Length (16 bits) */
    if (len)
        /* Adding the size of the LCAF header as well */
        *len = tvb_get_ntohs(tvb, offset) + LCAF_HEADER_LEN;
    offset += 2;

    return offset;
}

const char *
// NOLINTNEXTLINE(misc-no-recursion)
get_addr_str(tvbuff_t *tvb, packet_info *pinfo, int offset, uint16_t afi, uint16_t *addr_len)
{
    const char        *notset_str = "not set";
    const char        *addr_str;
    uint8_t            lcaf_type;
    uint32_t           iid, asn;
    uint16_t           cur_len;

    switch (afi) {
        case AFNUM_RESERVED:
            *addr_len  = 0;
            return notset_str;
        case AFNUM_INET:
            *addr_len  = INET_ADDRLEN;
            addr_str   = tvb_ip_to_str(pinfo->pool, tvb, offset);
            return addr_str;
        case AFNUM_INET6:
            *addr_len  = INET6_ADDRLEN;
            addr_str   = tvb_ip6_to_str(pinfo->pool, tvb, offset);
            return addr_str;
        case AFNUM_LCAF:
            get_lcaf_data(tvb, offset, &lcaf_type, addr_len);
            addr_str = val_to_str(lcaf_type, lcaf_typevals, "Unknown LCAF Type (%d)");
            if (lcaf_type == LCAF_IID) {
                iid = tvb_get_ntohl(tvb, offset + LCAF_HEADER_LEN);
                afi = tvb_get_ntohs(tvb, offset + LCAF_HEADER_LEN + 4);
                increment_dissection_depth(pinfo);
                addr_str = get_addr_str(tvb, pinfo, offset + LCAF_HEADER_LEN + 6, afi, &cur_len);
                decrement_dissection_depth(pinfo);
                return wmem_strdup_printf(pinfo->pool, "[%d] %s", iid, addr_str);
            }
            if (lcaf_type == LCAF_ASN) {
                asn = tvb_get_ntohl(tvb, offset + LCAF_HEADER_LEN);
                afi = tvb_get_ntohs(tvb, offset + LCAF_HEADER_LEN + 4);
                increment_dissection_depth(pinfo);
                addr_str = get_addr_str(tvb, pinfo, offset + LCAF_HEADER_LEN + 6, afi, &cur_len);
                decrement_dissection_depth(pinfo);
                return wmem_strdup_printf(pinfo->pool, "%s (ASN %d)", addr_str, asn);
            }
            return addr_str;
        case AFNUM_802:
        case AFNUM_EUI48:
            *addr_len = EUI48_ADDRLEN;
            addr_str  = tvb_ether_to_str(pinfo->pool, tvb, offset);
            return addr_str;
        case AFNUM_DISTNAME:
            *addr_len = tvb_strsize(tvb, offset);
            addr_str  = tvb_get_stringz_enc(pinfo->pool, tvb, offset, NULL, ENC_ASCII);
            return addr_str;
        default:
            return NULL;
    }
}

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_lcaf_natt_rloc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, const char *str, int idx)
{
    uint16_t     addr_len = 0;
    uint16_t     rloc_afi;
    const char *rloc_str;
    proto_item  *ti;
    proto_tree  *rloc_tree;

    ti = proto_tree_add_item(tree, hf_lisp_lcaf_natt_rloc, tvb, offset, 2, ENC_NA);
    rloc_tree = proto_item_add_subtree(ti, ett_lisp_lcaf_natt_rloc);

    /* AFI (2 bytes) */
    proto_tree_add_item(rloc_tree, hf_lisp_lcaf_natt_rloc_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
    rloc_afi = tvb_get_ntohs(tvb, offset);
    offset += 2;

    /* Reencap hop */
    rloc_str = get_addr_str(tvb, pinfo, offset, rloc_afi, &addr_len);

    switch (rloc_afi) {
        case AFNUM_RESERVED:
            break;
        case AFNUM_INET:
            proto_tree_add_item(rloc_tree, hf_lisp_lcaf_natt_rloc_ipv4,
                    tvb, offset, INET_ADDRLEN, ENC_BIG_ENDIAN);
            break;
        case AFNUM_INET6:
            proto_tree_add_item(rloc_tree, hf_lisp_lcaf_natt_rloc_ipv6,
                    tvb, offset, INET6_ADDRLEN, ENC_NA);
            break;
        case AFNUM_LCAF:
            dissect_lcaf(tvb, pinfo, rloc_tree, offset, NULL);
            break;
        default:
            expert_add_info_format(pinfo, rloc_tree, &ei_lisp_unexpected_field,
                    "Unexpected NAT-T RLOC AFI (%d), cannot decode", rloc_afi);
    }

    if (idx) {
        proto_item_append_text(ti, str, idx, rloc_str);
    } else {
        proto_item_append_text(ti, str, rloc_str);
    }
    proto_item_set_len(ti, 2 + addr_len);

    return addr_len + 2;
}

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_lcaf_elp_hop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, int idx, proto_item *tip)
{
    uint16_t     addr_len = 0;
    uint16_t     hop_afi;
    uint16_t     hop_flags;
    const char *hop_str;
    proto_item  *ti, *ti_flags;
    proto_tree  *hop_tree, *flags_tree;

    ti = proto_tree_add_item(tree, hf_lisp_lcaf_elp_hop, tvb, offset, 2, ENC_NA);
    hop_tree = proto_item_add_subtree(ti, ett_lisp_lcaf_elp_hop);

    /* Flags (2 bytes) */
    ti_flags = proto_tree_add_item(hop_tree, hf_lisp_lcaf_elp_hop_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
    flags_tree = proto_item_add_subtree(ti_flags, ett_lisp_lcaf_elp_hop_flags);
    proto_tree_add_item(flags_tree, hf_lisp_lcaf_elp_hop_flags_res, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lisp_lcaf_elp_hop_flags_lookup, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lisp_lcaf_elp_hop_flags_probe, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lisp_lcaf_elp_hop_flags_strict, tvb, offset, 2, ENC_BIG_ENDIAN);

    hop_flags = tvb_get_ntohs(tvb, offset);
    offset += 2;

    /* AFI (2 bytes) */
    proto_tree_add_item(hop_tree, hf_lisp_lcaf_elp_hop_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
    hop_afi = tvb_get_ntohs(tvb, offset);
    offset += 2;

    /* Reencap hop */
    hop_str = get_addr_str(tvb, pinfo, offset, hop_afi, &addr_len);

    switch (hop_afi) {
        case AFNUM_INET:
            proto_tree_add_item(hop_tree, hf_lisp_lcaf_elp_hop_ipv4,
                    tvb, offset, INET_ADDRLEN, ENC_BIG_ENDIAN);
            break;
        case AFNUM_INET6:
            proto_tree_add_item(hop_tree, hf_lisp_lcaf_elp_hop_ipv6,
                    tvb, offset, INET6_ADDRLEN, ENC_NA);
            break;
        case AFNUM_LCAF:
            dissect_lcaf(tvb, pinfo, hop_tree, offset, NULL);
            break;
        default:
            expert_add_info_format(pinfo, hop_tree, &ei_lisp_unexpected_field,
                    "Unexpected Reencap Hop AFI (%d), cannot decode", hop_afi);
    }

    if (idx) {
        proto_item_append_text(ti, " %d.", idx);
    } else {
        proto_item_append_text(ti, ":");
    }

    proto_item_append_text(ti, " %s", hop_str);
    proto_item_set_len(ti, 4 + addr_len);

    if (hop_flags & 0x04)
        proto_item_append_text(ti, ", Lookup");
    if (hop_flags & 0x02)
        proto_item_append_text(ti, ", RLOC-Probe");
    if (hop_flags & 0x01)
        proto_item_append_text(ti, ", Strict");

    proto_item_append_text(tip, ", %s", hop_str);

    return addr_len + 4;
}


static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_lcaf_rle_entry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, int idx, proto_item *tip)
{
    uint8_t      level;
    uint16_t     addr_len = 0;
    uint16_t     entry_afi;
    const char *entry_str;
    proto_item  *ti;
    proto_tree  *entry_tree;

    ti = proto_tree_add_item(tree, hf_lisp_lcaf_rle_entry, tvb, offset, 2, ENC_NA);
    entry_tree = proto_item_add_subtree(ti, ett_lisp_lcaf_rle_entry);

    /* Reserved (3 bytes) */
    proto_tree_add_item(entry_tree, hf_lisp_lcaf_rle_entry_res, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    /* Level Value (1 byte) */
    proto_tree_add_item(entry_tree, hf_lisp_lcaf_rle_entry_level, tvb, offset, 1, ENC_BIG_ENDIAN);
    level = tvb_get_uint8(tvb, offset);
    offset += 1;

    /* AFI (2 bytes) */
    proto_tree_add_item(entry_tree, hf_lisp_lcaf_rle_entry_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
    entry_afi = tvb_get_ntohs(tvb, offset);
    offset += 2;

    /* RTR/ETR entry */
    entry_str = get_addr_str(tvb, pinfo, offset, entry_afi, &addr_len);

    switch (entry_afi) {
        case AFNUM_INET:
            proto_tree_add_item(entry_tree, hf_lisp_lcaf_rle_entry_ipv4,
                    tvb, offset, INET_ADDRLEN, ENC_BIG_ENDIAN);
            break;
        case AFNUM_INET6:
            proto_tree_add_item(entry_tree, hf_lisp_lcaf_rle_entry_ipv6,
                    tvb, offset, INET6_ADDRLEN, ENC_NA);
            break;
        case AFNUM_LCAF:
            dissect_lcaf(tvb, pinfo, entry_tree, offset, NULL);
            break;
        default:
            expert_add_info_format(pinfo, entry_tree, &ei_lisp_unexpected_field,
                    "Unexpected RTR/ETR AFI (%d), cannot decode", entry_afi);
    }

    if (idx) {
        proto_item_append_text(ti, " %d.", idx);
    } else {
        proto_item_append_text(ti, ":");
    }

    proto_item_append_text(ti, " %s, level %d", entry_str, level);
    proto_item_set_len(ti, 6 + addr_len);

    proto_item_append_text(tip, ", %s (%d)", entry_str, level);

    return addr_len + 6;
}


/*
 * Dissector code for AFI List
 *
 */

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_lcaf_afi_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, uint16_t length)
{
    int old_offset;
    int remaining = length;
    int i = 1;
    int str_len;

    uint16_t           addr_len = 0;
    uint16_t           afi;
    const char        *lcaf_str;
    char              *disp_str;
    proto_item        *tir;
    proto_tree        *lisp_afi_list_tree;

    while (remaining > 0) {
        afi = tvb_get_ntohs(tvb, offset);
        tir = proto_tree_add_item(tree, hf_lisp_lcaf_afi_list_item, tvb, offset, LCAF_HEADER_LEN, ENC_NA);
        lisp_afi_list_tree = proto_item_add_subtree(tir, ett_lisp_afi_list);
        proto_tree_add_item(lisp_afi_list_tree, hf_lisp_lcaf_afi_list_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset    += 2;
        remaining -= 2;

        switch (afi) {
            case AFNUM_INET:
                proto_tree_add_item(lisp_afi_list_tree, hf_lisp_lcaf_afi_list_ipv4, tvb, offset, INET_ADDRLEN, ENC_BIG_ENDIAN);
                proto_item_append_text(tir, " %d. IPv4 Address: %s", i, tvb_ip_to_str(pinfo->pool, tvb, offset));
                proto_item_set_len(tir, 2 + INET_ADDRLEN);
                offset    += INET_ADDRLEN;
                remaining -= INET_ADDRLEN;
                break;
            case AFNUM_INET6:
                proto_tree_add_item(lisp_afi_list_tree, hf_lisp_lcaf_afi_list_ipv6, tvb, offset, INET6_ADDRLEN, ENC_NA);
                proto_item_append_text(tir, " %d. IPv6 Address: %s", i, tvb_ip6_to_str(pinfo->pool, tvb, offset));
                proto_item_set_len(tir, 2 + INET6_ADDRLEN);
                offset    += INET6_ADDRLEN;
                remaining -= INET6_ADDRLEN;
                break;
            case AFNUM_LCAF:
                old_offset = offset;
                lcaf_str = get_addr_str(tvb, pinfo, offset, afi, &addr_len);
                proto_item_append_text(tir, " %d. %s", i, lcaf_str);
                proto_item_set_len(tir, 2 + addr_len);
                offset = dissect_lcaf(tvb, pinfo, lisp_afi_list_tree, offset, tir);
                remaining -= (offset - old_offset);
                break;
            case AFNUM_802:
            case AFNUM_EUI48:
                proto_tree_add_item(lisp_afi_list_tree, hf_lisp_lcaf_afi_list_mac, tvb, offset, EUI48_ADDRLEN, ENC_NA);
                proto_item_append_text(tir, " %d. MAC Address: %s", i, tvb_ether_to_str(pinfo->pool, tvb, offset));
                proto_item_set_len(tir, 2 + EUI48_ADDRLEN);
                offset    += EUI48_ADDRLEN;
                remaining -= EUI48_ADDRLEN;
                break;
            case AFNUM_DISTNAME:
                str_len = tvb_strsize(tvb, offset);
                proto_tree_add_item_ret_display_string(lisp_afi_list_tree, hf_lisp_lcaf_afi_list_dn, tvb, offset, str_len, ENC_ASCII,
                                                        pinfo->pool, &disp_str);
                proto_item_append_text(tir, " %d. Distinguished Name: %s", i, disp_str);
                offset    += str_len;
                remaining -= str_len;
                break;
            default:
                expert_add_info_format(pinfo, tree, &ei_lisp_unexpected_field,
                        "Unexpected AFI (%d), cannot decode", afi);
                return -1;
        }
        i++;
    }

    return offset;
}


/*
 * Dissector code for Instance ID
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |           AFI = 16387         |    Rsvd1      |    Flags      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   Type = 2    |     Rsvd2     |             4 + n             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                         Instance ID                           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |              AFI = x          |         Address  ...          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_lcaf_iid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_item *tip)
{
    const char *ip_address;
    uint16_t afi, addr_len = 0;
    int str_len;

    /* Instance ID (4 bytes) */
    proto_tree_add_item(tree, hf_lisp_lcaf_iid, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_item_append_text(tip, ": %d", tvb_get_ntohl(tvb, offset));
    offset += 4;

    /* AFI (2 bytes) */
    afi = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_lisp_lcaf_iid_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Address */
    ip_address = get_addr_str(tvb, pinfo, offset, afi, &addr_len);
    if (ip_address && afi)
        proto_item_append_text(tip, ", Address: %s", ip_address);

    switch (afi) {
        case AFNUM_RESERVED:
            break;
        case AFNUM_INET:
            proto_tree_add_item(tree, hf_lisp_lcaf_iid_ipv4,
                    tvb, offset, INET_ADDRLEN, ENC_BIG_ENDIAN);
            offset += INET_ADDRLEN;
            break;
        case AFNUM_INET6:
            proto_tree_add_item(tree, hf_lisp_lcaf_iid_ipv6,
                    tvb, offset, INET6_ADDRLEN, ENC_NA);
            offset += INET6_ADDRLEN;
            break;
        case AFNUM_LCAF:
            offset = dissect_lcaf(tvb, pinfo, tree, offset, NULL);
            break;
        case AFNUM_802:
        case AFNUM_EUI48:
            proto_tree_add_item(tree, hf_lisp_lcaf_iid_mac,
                    tvb, offset, EUI48_ADDRLEN, ENC_NA);
            offset += EUI48_ADDRLEN;
            break;
        case AFNUM_DISTNAME:
            str_len = tvb_strsize(tvb, offset);
            proto_tree_add_item(tree, hf_lisp_lcaf_iid_dn, tvb, offset, str_len, ENC_ASCII);
            offset += str_len;
            break;
        default:
            expert_add_info_format(pinfo, tree, &ei_lisp_unexpected_field,
                    "Unexpected Instance ID AFI (%d), cannot decode", afi);
    }
    return offset;
}


/*
 * Dissector code for AS Number
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           AFI = 16387         |     Rsvd1     |     Flags     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   Type = 3    |     Rsvd2     |             4 + n             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                           AS Number                           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |              AFI = x          |         Address  ...          |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_lcaf_asn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_item *tip)
{
    const char *addr;
    uint16_t afi, addr_len = 0;
    int str_len;

    /* AS Number (4 bytes) */
    proto_tree_add_item(tree, hf_lisp_lcaf_asn, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_item_append_text(tip, ": %d", tvb_get_ntohl(tvb, offset));
    offset += 4;

    /* AFI (2 bytes) */
    afi = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_lisp_lcaf_asn_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Address */
    addr = get_addr_str(tvb, pinfo, offset, afi, &addr_len);
    if (addr && afi)
        proto_item_append_text(tip, ", Address: %s", addr);

    switch (afi) {
        case AFNUM_RESERVED:
            break;
        case AFNUM_INET:
            proto_tree_add_item(tree, hf_lisp_lcaf_asn_ipv4,
                    tvb, offset, INET_ADDRLEN, ENC_BIG_ENDIAN);
            offset += INET_ADDRLEN;
            break;
        case AFNUM_INET6:
            proto_tree_add_item(tree, hf_lisp_lcaf_asn_ipv6,
                    tvb, offset, INET6_ADDRLEN, ENC_NA);
            offset += INET6_ADDRLEN;
            break;
        case AFNUM_LCAF:
            offset = dissect_lcaf(tvb, pinfo, tree, offset, NULL);
            break;
        case AFNUM_802:
        case AFNUM_EUI48:
            proto_tree_add_item(tree, hf_lisp_lcaf_asn_mac,
                    tvb, offset, EUI48_ADDRLEN, ENC_NA);
            offset += EUI48_ADDRLEN;
            break;
        case AFNUM_DISTNAME:
            str_len = tvb_strsize(tvb, offset);
            proto_tree_add_item(tree, hf_lisp_lcaf_asn_dn, tvb, offset, str_len, ENC_ASCII);
            offset += str_len;
            break;
        default:
            expert_add_info_format(pinfo, tree, &ei_lisp_unexpected_field,
                    "Unexpected Instance ID AFI (%d), cannot decode", afi);
    }
    return offset;
}


/*
 * Dissector code for Geo Coordinates LCAF
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |           AFI = 16387         |     Rsvd1     |     Flags     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   Type = 5    |     Rsvd2     |            12 + n             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |N|     Latitude Degrees        |    Minutes    |    Seconds    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |E|     Longitude Degrees       |    Minutes    |    Seconds    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                            Altitude                           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |              AFI = x          |         Address  ...          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_lcaf_geo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_item *tir)
{
    uint16_t addr_len = 0;
    bool north, east;
    uint16_t deg;
    uint8_t min, sec;
    uint32_t alt;
    uint16_t afi;
    int str_len;
    const char *ip_address;
    const uint16_t mask = 0x7FFF;   /* prepare mask for N or E bit */
    proto_item *ti_lat, *ti_lon, *ti_alt;
    proto_tree *lat_tree, *lon_tree;

    /* PROCESS LATITUDE */

    ti_lat = proto_tree_add_item(tree, hf_lisp_lcaf_geo_lat, tvb, offset, 4, ENC_NA);
    lat_tree = proto_item_add_subtree(ti_lat, ett_lisp_lcaf_geo_lat);

    /* Hemisphere and degrees (2 bytes) */
    proto_tree_add_item(lat_tree, hf_lisp_lcaf_geo_lat_hemisphere, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(lat_tree, hf_lisp_lcaf_geo_lat_deg, tvb, offset, 2, ENC_BIG_ENDIAN);
    deg = tvb_get_ntohs(tvb, offset);
    north = deg >> 15;
    deg &= mask;
    if (deg > 90)
        expert_add_info_format(pinfo, tree, &ei_lisp_invalid_field,
                "Invalid latitude degrees value (%d)", deg);
    offset += 2;

    /* Minutes (1 byte) */
    proto_tree_add_item(lat_tree, hf_lisp_lcaf_geo_lat_min, tvb, offset, 1, ENC_BIG_ENDIAN);
    min = tvb_get_uint8(tvb, offset);
    if (min > 60)
        expert_add_info_format(pinfo, tree, &ei_lisp_invalid_field,
                "Invalid latitude minutes value (%d)", min);
    offset += 1;

    /* Seconds (1 byte) */
    proto_tree_add_item(lat_tree, hf_lisp_lcaf_geo_lat_sec, tvb, offset, 1, ENC_BIG_ENDIAN);
    sec = tvb_get_uint8(tvb, offset);
    if (sec > 60)
        expert_add_info_format(pinfo, tree, &ei_lisp_invalid_field,
                "Invalid latitude seconds value (%d)", min);
    offset += 1;

    proto_item_append_text(ti_lat, ": %s %d" UTF8_DEGREE_SIGN "%d' %d\"",
            val_to_str_const(north, lat_typevals, ""), deg, min, sec);
    proto_item_append_text(tir, ": (%s%d" UTF8_DEGREE_SIGN "%d'%d\"",
            val_to_str_const(north, lat_typevals, ""), deg, min, sec);

    /* PROCESS LONGITUDE */

    ti_lon = proto_tree_add_item(tree, hf_lisp_lcaf_geo_lon, tvb, offset, 4, ENC_NA);
    lon_tree = proto_item_add_subtree(ti_lon, ett_lisp_lcaf_geo_lon);

    /* Hemisphere and degrees (2 bytes) */
    proto_tree_add_item(lon_tree, hf_lisp_lcaf_geo_lon_hemisphere, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(lon_tree, hf_lisp_lcaf_geo_lon_deg, tvb, offset, 2, ENC_BIG_ENDIAN);
    deg = tvb_get_ntohs(tvb, offset);
    east = deg >> 15;
    deg &= mask;
    if (deg > 180)
        expert_add_info_format(pinfo, tree, &ei_lisp_invalid_field,
                "Invalid longitude degrees value (%d)", deg);
    offset += 2;

    /* Minutes (1 byte) */
    proto_tree_add_item(lon_tree, hf_lisp_lcaf_geo_lon_min, tvb, offset, 1, ENC_BIG_ENDIAN);
    min = tvb_get_uint8(tvb, offset);
    if (min > 60)
        expert_add_info_format(pinfo, tree, &ei_lisp_invalid_field,
                "Invalid longitude minutes value (%d)", min);
    offset += 1;

    /* Seconds (1 byte) */
    proto_tree_add_item(lon_tree, hf_lisp_lcaf_geo_lon_sec, tvb, offset, 1, ENC_BIG_ENDIAN);
    sec = tvb_get_uint8(tvb, offset);
    if (sec > 60)
        expert_add_info_format(pinfo, tree, &ei_lisp_invalid_field,
                "Invalid longitude seconds value (%d)", min);
    offset += 1;

    proto_item_append_text(ti_lon, ": %s %d" UTF8_DEGREE_SIGN " %d' %d\"",
            val_to_str_const(east, lon_typevals, ""), deg, min, sec);
    proto_item_append_text(tir, ", %s%d" UTF8_DEGREE_SIGN "%d'%d\")",
            val_to_str_const(east, lon_typevals, ""), deg, min, sec);

    /* PROCESS ALTITUDE */

    ti_alt = proto_tree_add_item(tree, hf_lisp_lcaf_geo_alt, tvb, offset, 4, ENC_NA);
    alt = tvb_get_ntohl(tvb, offset);
    /* if altitude equals 0x7fffffff then no altitude information encoded */
    if (alt == 0x7fffffff) {
        proto_item_append_text(ti_alt, ": no value encoded");
    } else {
        proto_item_append_text(ti_alt, ": %d m", alt);
        proto_item_append_text(tir, ", Altitude: %d m", alt);
    }
    offset += 4;

    /* PROCESS ADDRESS */

    /* AFI (2 bytes) */
    afi = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_lisp_lcaf_geo_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    ip_address = get_addr_str(tvb, pinfo, offset, afi, &addr_len);
    if (ip_address && afi)
        proto_item_append_text(tir, ", Address: %s", ip_address);

    switch (afi) {
        case AFNUM_RESERVED:
            break;
        case AFNUM_INET:
            proto_tree_add_item(tree, hf_lisp_lcaf_geo_ipv4,
                    tvb, offset, INET_ADDRLEN, ENC_BIG_ENDIAN);
            offset += INET_ADDRLEN;
            break;
        case AFNUM_INET6:
            proto_tree_add_item(tree, hf_lisp_lcaf_geo_ipv6,
                    tvb, offset, INET6_ADDRLEN, ENC_NA);
            offset += INET6_ADDRLEN;
            break;
        case AFNUM_LCAF:
            offset = dissect_lcaf(tvb, pinfo, tree, offset, NULL);
            break;
        case AFNUM_802:
        case AFNUM_EUI48:
            proto_tree_add_item(tree, hf_lisp_lcaf_geo_mac,
                    tvb, offset, EUI48_ADDRLEN, ENC_NA);
            offset += EUI48_ADDRLEN;
            break;
        case AFNUM_DISTNAME:
            str_len = tvb_strsize(tvb, offset);
            proto_tree_add_item(tree, hf_lisp_lcaf_geo_dn, tvb, offset, str_len, ENC_ASCII);
            offset += str_len;
            break;
        default:
            expert_add_info_format(pinfo, tree, &ei_lisp_unexpected_field,
                    "Unexpected Geo Coordinates AFI (%d), cannot decode", afi);
    }
    return offset;
}


/*
 * Dissector code for NAT-Traversal
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |           AFI = 16387         |    Rsvd1      |     Flags     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |    Type = 7     |     Rsvd2   |             4 + n             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        MS UDP Port Number     |      ETR UDP Port Number      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |              AFI = x          | Global ETR RLOC Address  ...  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |              AFI = x          |       MS RLOC Address  ...    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |              AFI = x          | Private ETR RLOC Address ...  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |              AFI = x          |      RTR RLOC Address 1 ...   |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |              AFI = x          |       RTR RLOC Address n ...  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_lcaf_natt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, uint16_t length)
{
    int          i;
    int          len;
    int          remaining   = length;
    const char *global_etr  = " of Global ETR: %s";
    const char *ms          = " of MS: %s";
    const char *private_etr = " of Private ETR: %s";
    const char *rtr         = " of RTR %d: %s";

    remaining -= 4;

    proto_tree_add_item(tree, hf_lisp_lcaf_natt_msport, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    remaining -= 2;
    proto_tree_add_item(tree, hf_lisp_lcaf_natt_etrport, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    remaining -= 2;

    len = dissect_lcaf_natt_rloc(tvb, pinfo, tree, offset, global_etr, 0);
    offset += len;
    remaining -= len;

    len = dissect_lcaf_natt_rloc(tvb, pinfo, tree, offset, ms, 0);
    offset += len;
    remaining -= len;

    len = dissect_lcaf_natt_rloc(tvb, pinfo, tree, offset, private_etr, 0);
    offset += len;
    remaining -= len;

    i = 1;
    while (remaining > 0) {
        len = dissect_lcaf_natt_rloc(tvb, pinfo, tree, offset, rtr, i);
        offset += len;
        remaining -= len;
        i++;
    }

    return offset;
}


/*
 * Dissector code for Nonce Locator
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |           AFI = 16387         |     Rsvd1     |     Flags     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   Type = 8    |     Rsvd2     |             4 + n             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   Reserved    |                  Nonce                        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |              AFI = x          |         Address  ...          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_lcaf_nonce_loc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_item *tip)
{
    const char *addr;
    uint16_t afi, addr_len = 0;
    int str_len;

    /* Reserved (1 byte) */
    proto_tree_add_item(tree, hf_lisp_lcaf_nonce_loc_res, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(tip, ": %d", tvb_get_ntohl(tvb, offset));
    offset += 1;

    /* Nonce (3 bytes) */
    proto_tree_add_item(tree, hf_lisp_lcaf_nonce_loc, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_item_append_text(tip, ": %d", tvb_get_ntohl(tvb, offset));
    offset += 3;

    /* AFI (2 bytes) */
    afi = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_lisp_lcaf_nonce_loc_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Address */
    addr = get_addr_str(tvb, pinfo, offset, afi, &addr_len);
    if (addr && afi)
        proto_item_append_text(tip, ", Address: %s", addr);

    switch (afi) {
        case AFNUM_RESERVED:
            break;
        case AFNUM_INET:
            proto_tree_add_item(tree, hf_lisp_lcaf_nonce_loc_ipv4,
                    tvb, offset, INET_ADDRLEN, ENC_BIG_ENDIAN);
            offset += INET_ADDRLEN;
            break;
        case AFNUM_INET6:
            proto_tree_add_item(tree, hf_lisp_lcaf_nonce_loc_ipv6,
                    tvb, offset, INET6_ADDRLEN, ENC_NA);
            offset += INET6_ADDRLEN;
            break;
        case AFNUM_LCAF:
            offset = dissect_lcaf(tvb, pinfo, tree, offset, NULL);
            break;
        case AFNUM_802:
        case AFNUM_EUI48:
            proto_tree_add_item(tree, hf_lisp_lcaf_nonce_loc_mac,
                    tvb, offset, EUI48_ADDRLEN, ENC_NA);
            offset += EUI48_ADDRLEN;
            break;
        case AFNUM_DISTNAME:
            str_len = tvb_strsize(tvb, offset);
            proto_tree_add_item(tree, hf_lisp_lcaf_nonce_loc_dn, tvb, offset, str_len, ENC_ASCII);
            offset += str_len;
            break;
        default:
            expert_add_info_format(pinfo, tree, &ei_lisp_unexpected_field,
                    "Unexpected Instance ID AFI (%d), cannot decode", afi);
    }
    return offset;
}


/*
 * Dissector code for Multicast Group Membership Information
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           AFI = 16387         |     Rsvd1     |     Flags     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   Type = 9    |  Rsvd2  |R|L|J|             8 + n             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                         Instance-ID                           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |            Reserved           | Source MaskLen| Group MaskLen |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |              AFI = x          |   Source/Subnet Address  ...  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |              AFI = x          |       Group Address  ...      |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_lcaf_mcast_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, proto_item *tir)
{
    uint8_t      src_masklen, grp_masklen;
    uint16_t     afi, addr_len = 0;
    uint32_t     iid;
    const char *src_str, *grp_str;
    proto_item  *ti_src, *ti_grp;
    proto_tree  *src_tree, *grp_tree;

    /* Instance ID (4 bytes) */
    proto_tree_add_item(tree, hf_lisp_lcaf_mcinfo_iid, tvb, offset, 4, ENC_BIG_ENDIAN);
    iid = tvb_get_ntohl(tvb, offset);
    offset += 4;

    /* Reserved (2 bytes) */
    proto_tree_add_item(tree, hf_lisp_lcaf_mcinfo_res, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Source Mask Length (1 byte) */
    proto_tree_add_item(tree, hf_lisp_lcaf_mcinfo_src_masklen, tvb, offset, 1, ENC_BIG_ENDIAN);
    src_masklen = tvb_get_uint8(tvb, offset);
    offset += 1;

    /* Group Mask Length (1 byte) */
    proto_tree_add_item(tree, hf_lisp_lcaf_mcinfo_grp_masklen, tvb, offset, 1, ENC_BIG_ENDIAN);
    grp_masklen = tvb_get_uint8(tvb, offset);
    offset += 1;

    ti_src   = proto_tree_add_item(tree, hf_lisp_lcaf_mcinfo_src, tvb, offset, 2, ENC_NA);
    src_tree = proto_item_add_subtree(ti_src, ett_lisp_lcaf_mcinfo_src);

    /* Source/Subnet AFI (2 bytes) */
    proto_tree_add_item(src_tree, hf_lisp_lcaf_mcinfo_src_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
    afi = tvb_get_ntohs(tvb, offset);
    offset += 2;

    /* Source/Subnet Address */
    src_str = get_addr_str(tvb, pinfo, offset, afi, &addr_len);

    switch (afi) {
        case AFNUM_INET:
            proto_tree_add_item(src_tree, hf_lisp_lcaf_mcinfo_src_ipv4,
                    tvb, offset, INET_ADDRLEN, ENC_BIG_ENDIAN);
            offset += INET_ADDRLEN;
            break;
        case AFNUM_INET6:
            proto_tree_add_item(src_tree, hf_lisp_lcaf_mcinfo_src_ipv6,
                    tvb, offset, INET6_ADDRLEN, ENC_NA);
            offset += INET6_ADDRLEN;
            break;
        case AFNUM_LCAF:
            offset = dissect_lcaf(tvb, pinfo, src_tree, offset, NULL);
            break;
        default:
            expert_add_info_format(pinfo, src_tree, &ei_lisp_unexpected_field,
                    "Unexpected Source Prefix AFI (%d), cannot decode", afi);
    }

    proto_item_append_text(ti_src, ": %s", src_str);
    proto_item_set_len(ti_src, 2 + addr_len);

    ti_grp = proto_tree_add_item(tree, hf_lisp_lcaf_mcinfo_grp, tvb, offset, 2, ENC_NA);
    grp_tree = proto_item_add_subtree(ti_grp, ett_lisp_lcaf_mcinfo_grp);

    /* Group AFI (2 bytes) */
    proto_tree_add_item(grp_tree, hf_lisp_lcaf_mcinfo_grp_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
    afi = tvb_get_ntohs(tvb, offset);
    offset += 2;

    /* Group Address */
    grp_str = get_addr_str(tvb, pinfo, offset, afi, &addr_len);

    switch (afi) {
        case AFNUM_INET:
            proto_tree_add_item(grp_tree, hf_lisp_lcaf_mcinfo_grp_ipv4,
                    tvb, offset, INET_ADDRLEN, ENC_BIG_ENDIAN);
            offset += INET_ADDRLEN;
            break;
        case AFNUM_INET6:
            proto_tree_add_item(grp_tree, hf_lisp_lcaf_mcinfo_grp_ipv6,
                    tvb, offset, INET6_ADDRLEN, ENC_NA);
            offset += INET6_ADDRLEN;
            break;
        case AFNUM_LCAF:
            offset = dissect_lcaf(tvb, pinfo, grp_tree, offset, NULL);
            break;
        default:
            expert_add_info_format(pinfo, grp_tree, &ei_lisp_unexpected_field,
                    "Unexpected Destination Prefix AFI (%d), cannot decode", afi);
    }

    proto_item_append_text(ti_grp, ": %s", grp_str);
    proto_item_set_len(ti_grp, 2 + addr_len);

    proto_item_append_text(tir, " ([%d], %s/%d, %s/%d)", iid, src_str, src_masklen, grp_str, grp_masklen);
    return offset;
}


/*
 * Dissector code for Explicit Locator Path
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |           AFI = 16387         |     Rsvd1     |     Flags     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   Type = 10   |     Rsvd2     |               n               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |           Rsvd3         |L|P|S|           AFI = x             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                         Reencap Hop 1  ...                    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |           Rsvd3         |L|P|S|           AFI = x             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                         Reencap Hop k  ...                    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 */

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_lcaf_elp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, uint16_t length, proto_item *tir)
{
    int len;
    int remaining = length;
    int i = 1;

    while (remaining > 0) {
        len = dissect_lcaf_elp_hop(tvb, pinfo, tree, offset, i, tir);
        offset += len;
        remaining -= len;
        i++;
    }

    return offset;
}


 /*
  *  Dissector code for Source/Destination 2-Tuple Lookups
  *
  *   0                   1                   2                   3
  *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *  |           AFI = 16387         |     Rsvd1     |     Flags     |
  *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *  |   Type = 12   |     Rsvd2     |             4 + n             |
  *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *  |            Reserved           |   Source-ML   |    Dest-ML    |
  *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *  |              AFI = x          |         Source-Prefix ...     |
  *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *  |              AFI = x          |     Destination-Prefix ...    |
  *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *
  */

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_lcaf_src_dst_key(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, proto_item *tir)
{
    uint8_t      src_masklen, dst_masklen;
    uint16_t     afi, addr_len = 0;
    const char *src_str, *dst_str;
    proto_item  *ti_src, *ti_dst;
    proto_tree  *src_tree, *dst_tree;

    /* Reserved (2 bytes) */
    proto_tree_add_item(tree, hf_lisp_lcaf_srcdst_res, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Source Prefix Mask Length (1 byte) */
    proto_tree_add_item(tree, hf_lisp_lcaf_srcdst_src_masklen, tvb, offset, 1, ENC_BIG_ENDIAN);
    src_masklen = tvb_get_uint8(tvb, offset);
    offset += 1;

    /* Destination Prefix Mask Length (1 byte) */
    proto_tree_add_item(tree, hf_lisp_lcaf_srcdst_dst_masklen, tvb, offset, 1, ENC_BIG_ENDIAN);
    dst_masklen = tvb_get_uint8(tvb, offset);
    offset += 1;

    ti_src   = proto_tree_add_item(tree, hf_lisp_lcaf_srcdst_src, tvb, offset, 2, ENC_NA);
    src_tree = proto_item_add_subtree(ti_src, ett_lisp_lcaf_srcdst_src);

    /* Source Prefix AFI (2 bytes) */
    proto_tree_add_item(src_tree, hf_lisp_lcaf_srcdst_src_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
    afi = tvb_get_ntohs(tvb, offset);
    offset += 2;

    /* Source Prefix */
    src_str = get_addr_str(tvb, pinfo, offset, afi, &addr_len);

    switch (afi) {
        case AFNUM_INET:
            proto_tree_add_item(src_tree, hf_lisp_lcaf_srcdst_src_ipv4,
                    tvb, offset, INET_ADDRLEN, ENC_BIG_ENDIAN);
            offset += INET_ADDRLEN;
            break;
        case AFNUM_INET6:
            proto_tree_add_item(src_tree, hf_lisp_lcaf_srcdst_src_ipv6,
                    tvb, offset, INET6_ADDRLEN, ENC_NA);
            offset += INET6_ADDRLEN;
            break;
        case AFNUM_LCAF:
            offset = dissect_lcaf(tvb, pinfo, src_tree, offset, NULL);
            break;
        case AFNUM_802:
        case AFNUM_EUI48:
            proto_tree_add_item(src_tree, hf_lisp_lcaf_srcdst_src_mac,
                    tvb, offset, EUI48_ADDRLEN, ENC_NA);
            offset += EUI48_ADDRLEN;
            break;
        default:
            expert_add_info_format(pinfo, src_tree, &ei_lisp_unexpected_field,
                    "Unexpected Source Prefix AFI (%d), cannot decode", afi);
    }

    proto_item_append_text(ti_src, ": %s", src_str);
    proto_item_set_len(ti_src, 2 + addr_len);

    ti_dst = proto_tree_add_item(tree, hf_lisp_lcaf_srcdst_dst, tvb, offset, 2, ENC_NA);
    dst_tree = proto_item_add_subtree(ti_dst, ett_lisp_lcaf_srcdst_dst);

    /* Destination Prefix AFI (2 bytes) */
    proto_tree_add_item(dst_tree, hf_lisp_lcaf_srcdst_dst_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
    afi = tvb_get_ntohs(tvb, offset);
    offset += 2;

    /* Destination Prefix */
    dst_str = get_addr_str(tvb, pinfo, offset, afi, &addr_len);

    switch (afi) {
        case AFNUM_INET:
            proto_tree_add_item(dst_tree, hf_lisp_lcaf_srcdst_dst_ipv4,
                    tvb, offset, INET_ADDRLEN, ENC_BIG_ENDIAN);
            offset += INET_ADDRLEN;
            break;
        case AFNUM_INET6:
            proto_tree_add_item(dst_tree, hf_lisp_lcaf_srcdst_dst_ipv6,
                    tvb, offset, INET6_ADDRLEN, ENC_NA);
            offset += INET6_ADDRLEN;
            break;
        case AFNUM_LCAF:
            offset = dissect_lcaf(tvb, pinfo, dst_tree, offset, NULL);
            break;
        case AFNUM_802:
        case AFNUM_EUI48:
            proto_tree_add_item(dst_tree, hf_lisp_lcaf_srcdst_dst_mac,
                    tvb, offset, EUI48_ADDRLEN, ENC_NA);
            offset += EUI48_ADDRLEN;
            break;
        default:
            expert_add_info_format(pinfo, dst_tree, &ei_lisp_unexpected_field,
                    "Unexpected Destination Prefix AFI (%d), cannot decode", afi);
    }

    proto_item_append_text(ti_dst, ": %s", dst_str);
    proto_item_set_len(ti_dst, 2 + addr_len);

    proto_item_append_text(tir, " (%s/%d, %s/%d)", src_str, src_masklen, dst_str, dst_masklen);
    return offset;
}


/*
 * Dissector code for Replication List Entries for Multicast Forwarding
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |           AFI = 16387         |     Rsvd1     |     Flags     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   Type = 13   |    Rsvd2      |             4 + n             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |              Rsvd3            |     Rsvd4     |  Level Value  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |              AFI = x          |           RTR/ETR #1 ...      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |              Rsvd3            |     Rsvd4     |  Level Value  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |              AFI = x          |           RTR/ETR  #n ...     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_lcaf_rle(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, uint16_t length, proto_item *tir)
{
    int len;
    int remaining = length;
    int i = 1;

    while (remaining > 0) {
        len = dissect_lcaf_rle_entry(tvb, pinfo, tree, offset, i, tir);
        offset += len;
        remaining -= len;
        i++;
    }

    return offset;
}


 /*
  *  Dissector code for Key/Value Address Pairs
  *
  *   0                   1                   2                   3
  *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *  |           AFI = 16387         |     Rsvd1     |     Flags     |
  *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *  |   Type = 15   |     Rsvd2     |               n               |
  *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *  |              AFI = x          |       Address as Key ...      |
  *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *  |              AFI = x          |       Address as Value ...    |
  *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *
  */

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_lcaf_kv_addr_pair(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset)
{
    uint16_t     afi, addr_len = 0;
    const char *key_str, *value_str;
    proto_item  *ti_key, *ti_value;
    proto_tree  *key_tree, *value_tree;
    int          str_len;

    ti_key   = proto_tree_add_item(tree, hf_lisp_lcaf_kv_key, tvb, offset, 2, ENC_NA);
    key_tree = proto_item_add_subtree(ti_key, ett_lisp_lcaf_kv_key);

    /* Key AFI (2 bytes) */
    proto_tree_add_item(key_tree, hf_lisp_lcaf_kv_key_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
    afi = tvb_get_ntohs(tvb, offset);
    offset += 2;

    /* Key */
    key_str = get_addr_str(tvb, pinfo, offset, afi, &addr_len);

    switch (afi) {
        case AFNUM_INET:
            proto_tree_add_item(key_tree, hf_lisp_lcaf_kv_key_ipv4,
                    tvb, offset, INET_ADDRLEN, ENC_BIG_ENDIAN);
            offset += INET_ADDRLEN;
            break;
        case AFNUM_INET6:
            proto_tree_add_item(key_tree, hf_lisp_lcaf_kv_key_ipv6,
                    tvb, offset, INET6_ADDRLEN, ENC_NA);
            offset += INET6_ADDRLEN;
            break;
        case AFNUM_LCAF:
            offset = dissect_lcaf(tvb, pinfo, key_tree, offset, NULL);
            break;
        case AFNUM_802:
        case AFNUM_EUI48:
            proto_tree_add_item(key_tree, hf_lisp_lcaf_kv_key_mac,
                    tvb, offset, EUI48_ADDRLEN, ENC_NA);
            offset += EUI48_ADDRLEN;
            break;
        case AFNUM_DISTNAME:
            str_len = tvb_strsize(tvb, offset);
            proto_tree_add_item(key_tree, hf_lisp_lcaf_kv_key_dn, tvb, offset, str_len, ENC_ASCII);
            offset += str_len;
            break;
        default:
            expert_add_info_format(pinfo, key_tree, &ei_lisp_unexpected_field,
                    "Unexpected Key AFI (%d), cannot decode", afi);
    }

    proto_item_append_text(ti_key, ": %s", key_str);
    proto_item_set_len(ti_key, 2 + addr_len);

    ti_value = proto_tree_add_item(tree, hf_lisp_lcaf_kv_value, tvb, offset, 2, ENC_NA);
    value_tree = proto_item_add_subtree(ti_value, ett_lisp_lcaf_kv_value);

    /* Value AFI (2 bytes) */
    proto_tree_add_item(value_tree, hf_lisp_lcaf_kv_value_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
    afi = tvb_get_ntohs(tvb, offset);
    offset += 2;

    /* Value */
    value_str = get_addr_str(tvb, pinfo, offset, afi, &addr_len);

    switch (afi) {
        case AFNUM_INET:
            proto_tree_add_item(value_tree, hf_lisp_lcaf_kv_value_ipv4,
                    tvb, offset, INET_ADDRLEN, ENC_BIG_ENDIAN);
            offset += INET_ADDRLEN;
            break;
        case AFNUM_INET6:
            proto_tree_add_item(value_tree, hf_lisp_lcaf_kv_value_ipv6,
                    tvb, offset, INET6_ADDRLEN, ENC_NA);
            offset += INET6_ADDRLEN;
            break;
        case AFNUM_LCAF:
            offset = dissect_lcaf(tvb, pinfo, value_tree, offset, NULL);
            break;
        case AFNUM_802:
        case AFNUM_EUI48:
            proto_tree_add_item(value_tree, hf_lisp_lcaf_kv_value_mac,
                    tvb, offset, EUI48_ADDRLEN, ENC_NA);
            offset += EUI48_ADDRLEN;
            break;
        case AFNUM_DISTNAME:
            str_len = tvb_strsize(tvb, offset);
            proto_tree_add_item(value_tree, hf_lisp_lcaf_kv_value_dn, tvb, offset, str_len, ENC_ASCII);
            offset += str_len;
            break;
        default:
            expert_add_info_format(pinfo, value_tree, &ei_lisp_unexpected_field,
                    "Unexpected Value AFI (%d), cannot decode", afi);
    }

    proto_item_append_text(ti_value, ": %s", value_str);
    proto_item_set_len(ti_value, 2 + addr_len);

    return offset;
}


/*
  *  Dissector code for Vendor Specific LCAF
  *
  *   0                   1                   2                   3
  *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *  |           AFI = 16387         |     Rsvd1     |     Flags     |
  *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *  |   Type = 255  |     Rsvd2     |            Length             |
  *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *  |      Rsvd3    |    Organizationally Unique Identifier (OUI)   |
  *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *  |                        Internal format...                     |
  *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *
  */

static int
dissect_lcaf_vendor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int offset, uint16_t length)
{
    int len;
    proto_item  *ti_vendor;
    proto_tree  *vendor_tree;

    /* Reserved (1 byte) */
    proto_tree_add_item(tree, hf_lisp_lcaf_vendor_res, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Organizationally Unique Identifier (3 bytes) */
    proto_tree_add_item(tree, hf_lisp_lcaf_vendor_oui, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    /* Vendor Data */
    len = length - 4;
    ti_vendor = proto_tree_add_item(tree, hf_lisp_lcaf_vendor_data, tvb, offset, len, ENC_NA);
    vendor_tree = proto_item_add_subtree(ti_vendor, ett_lisp_lcaf_vendor);
    expert_add_info_format(pinfo, vendor_tree, &ei_lisp_undecoded,
                    "Look up the vendor's OUI (IEEE 802-2001) and contact them for support on decoding this field");
    offset += len;

    return offset;
}


/*
 * Dissector code for LISP Canonical Address Format (LCAF)
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |           AFI = 16387         |    Rsvd1     |     Flags      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |    Type       |     Rsvd2     |            Length             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  Type 0:   Null Body Type
 *  Type 1:   AFI List Type
 *  Type 2:   Instance ID Type
 *  Type 3:   AS Number Type
 *  Type 4:   Application Data Type
 *  Type 5:   Geo Coordinates Type
 *  Type 6:   Opaque Key Type
 *  Type 7:   NAT-Traversal Type
 *  Type 8:   Nonce Locator Type
 *  Type 9:   Multicast Info Type
 *  Type 10:  Explicit Locator Path Type
 *  Type 11:  Security Key Type
 *  Type 12:  Source/Dest Key Type
 *  Type 13:  Replication List Entry Type
 *  Type 14:  JSON Data Model Type
 *  Type 15:  Key/Value Address Pair Type
 *  Type 255: Vendor Specific LCAF
 *
 */

int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_lcaf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_item *tip)
{
    uint8_t      lcaf_type;
    uint16_t     len;
    proto_item  *tir, *ti_header, *ti_flags, *ti;
    proto_tree  *lcaf_tree, *lcaf_header_tree, *flags_tree;
    tvbuff_t    *payload_tvb;

    len = tvb_get_ntohs(tvb, offset + 4);

    tir = proto_tree_add_item(tree, hf_lisp_lcaf, tvb, offset, LCAF_HEADER_LEN + len, ENC_NA);
    lcaf_tree = proto_item_add_subtree(tir, ett_lisp_lcaf);

    ti_header = proto_tree_add_item(lcaf_tree, hf_lisp_lcaf_header, tvb, offset, LCAF_HEADER_LEN, ENC_NA);
    lcaf_header_tree = proto_item_add_subtree(ti_header, ett_lisp_lcaf_header);

    /* Reserved bits (8 bits) */
    proto_tree_add_item(lcaf_header_tree, hf_lisp_lcaf_res1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Flags (8 bits) */
    proto_tree_add_item(lcaf_header_tree, hf_lisp_lcaf_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Type (8 bits) */
    proto_tree_add_item(lcaf_header_tree, hf_lisp_lcaf_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    lcaf_type = tvb_get_uint8(tvb, offset);
    proto_item_append_text(tir, ": %s", val_to_str(lcaf_type, lcaf_typevals, "Unknown (%d)"));
    offset += 1;

    if (lcaf_type == LCAF_MCAST_INFO) {
        ti_flags = proto_tree_add_item(lcaf_header_tree, hf_lisp_lcaf_mcinfo_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
        flags_tree = proto_item_add_subtree(ti_flags, ett_lisp_lcaf_mcinfo_flags);

        /* Reserved (5 bits) */
        proto_tree_add_item(flags_tree, hf_lisp_lcaf_mcinfo_flags_res, tvb, offset, 1, ENC_BIG_ENDIAN);

        /* Flags (3 bits) */
        proto_tree_add_item(flags_tree, hf_lisp_lcaf_mcinfo_flags_rp, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(flags_tree, hf_lisp_lcaf_mcinfo_flags_leave, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(flags_tree, hf_lisp_lcaf_mcinfo_flags_join, tvb, offset, 1, ENC_NA);
    } else {
        /* Reserved (8 bits) */
        proto_tree_add_item(lcaf_header_tree, hf_lisp_lcaf_res2, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    offset += 1;

    /* Length (16 bits) */
    proto_tree_add_item(lcaf_header_tree, hf_lisp_lcaf_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    payload_tvb = tvb_new_subset_length(tvb, 0, offset + len);
    ti = (tip) ? tip : tir;

    increment_dissection_depth(pinfo);
    switch (lcaf_type) {
        case LCAF_NULL:
            break;
        case LCAF_AFI_LIST:
            offset = dissect_lcaf_afi_list(payload_tvb, pinfo, lcaf_tree, offset, len);
            break;
        case LCAF_IID:
            offset = dissect_lcaf_iid(payload_tvb, pinfo, lcaf_tree, offset, ti);
            break;
        case LCAF_ASN:
            offset = dissect_lcaf_asn(payload_tvb, pinfo, lcaf_tree, offset, ti);
            break;
        case LCAF_GEO:
            offset = dissect_lcaf_geo(payload_tvb, pinfo, lcaf_tree, offset, ti);
            break;
        case LCAF_NATT:
            offset = dissect_lcaf_natt(payload_tvb, pinfo, lcaf_tree, offset, len);
            break;
        case LCAF_NONCE_LOC:
            offset = dissect_lcaf_nonce_loc(payload_tvb, pinfo, lcaf_tree, offset, ti);
            break;
        case LCAF_MCAST_INFO:
            offset = dissect_lcaf_mcast_info(payload_tvb, pinfo, lcaf_tree, offset, ti);
            break;
        case LCAF_ELP:
            offset = dissect_lcaf_elp(payload_tvb, pinfo, lcaf_tree, offset, len, ti);
            break;
        case LCAF_SRC_DST_KEY:
            offset = dissect_lcaf_src_dst_key(payload_tvb, pinfo, lcaf_tree, offset, ti);
            break;
        case LCAF_RLE:
            offset = dissect_lcaf_rle(payload_tvb, pinfo, lcaf_tree, offset, len, ti);
            break;
        case LCAF_KV_ADDR_PAIR:
            offset = dissect_lcaf_kv_addr_pair(payload_tvb, pinfo, lcaf_tree, offset);
            break;
        case LCAF_VENDOR:
            offset = dissect_lcaf_vendor(payload_tvb, pinfo, lcaf_tree, offset, len);
            break;
        default:
            proto_tree_add_expert(tree, pinfo, &ei_lisp_undecoded, tvb, offset, len);
            return offset + len;
    }
    decrement_dissection_depth(pinfo);
    return offset;
}


/*
 * Dissector code for locator records within control packets
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |    Priority   |    Weight     |  M Priority   |   M Weight    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Unused Flags     |L|p|R|           Loc-AFI             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                             Locator                           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

static int
dissect_lisp_locator(tvbuff_t *tvb, packet_info *pinfo, proto_tree *lisp_mapping_tree, int rec)
{
    int          offset   = 0;
    uint16_t     addr_len = 0;
    uint8_t      prio;
    uint8_t      weight;
    uint8_t      m_prio;
    uint8_t      m_weight;
    uint16_t     flags;
    uint16_t     loc_afi;
    const char *locator;
    proto_item  *tir, *ti_flags;
    proto_tree  *lisp_lcaf_tree, *lisp_loc_tree, *lisp_flags_tree;

    tir = proto_tree_add_item(lisp_mapping_tree, hf_lisp_loc, tvb, offset, 8, ENC_NA);

    lisp_loc_tree = proto_item_add_subtree(tir, ett_lisp_loc);

    proto_tree_add_item(lisp_loc_tree, hf_lisp_loc_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
    prio = tvb_get_uint8(tvb, offset);
    offset += 1;

    proto_tree_add_item(lisp_loc_tree, hf_lisp_loc_weight, tvb, offset, 1, ENC_BIG_ENDIAN);
    weight = tvb_get_uint8(tvb, offset);
    offset += 1;

    proto_tree_add_item(lisp_loc_tree, hf_lisp_loc_mpriority, tvb, offset, 1, ENC_BIG_ENDIAN);
    m_prio = tvb_get_uint8(tvb, offset);
    offset += 1;

    proto_tree_add_item(lisp_loc_tree, hf_lisp_loc_mweight, tvb, offset, 1, ENC_BIG_ENDIAN);
    m_weight = tvb_get_uint8(tvb, offset);
    offset += 1;

    ti_flags = proto_tree_add_item(lisp_loc_tree, hf_lisp_loc_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
    lisp_flags_tree = proto_item_add_subtree(ti_flags, ett_lisp_loc_flags);
    proto_tree_add_item(lisp_flags_tree, hf_lisp_loc_flags_res, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(lisp_flags_tree, hf_lisp_loc_flags_local, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(lisp_flags_tree, hf_lisp_loc_flags_probe, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(lisp_flags_tree, hf_lisp_loc_flags_reach, tvb, offset, 2, ENC_BIG_ENDIAN);
    flags = tvb_get_ntohs(tvb, offset);
    offset += 2;

    proto_tree_add_item(lisp_loc_tree, hf_lisp_loc_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
    loc_afi  = tvb_get_ntohs(tvb, offset);
    offset += 2;

    locator = get_addr_str(tvb, pinfo, offset, loc_afi, &addr_len);

    if (locator == NULL) {
        expert_add_info_format(pinfo, lisp_mapping_tree, &ei_lisp_unexpected_field,
                "Unexpected locator AFI (%d), cannot decode", loc_afi);
        return offset;
    }

    if (loc_afi == AFNUM_LCAF) {
        /* Create a sub-tree for the mapping */
        lisp_lcaf_tree = proto_item_add_subtree(tir, ett_lisp_lcaf);
        offset = dissect_lcaf(tvb, pinfo, lisp_lcaf_tree, offset, NULL);
    } else {
        proto_tree_add_string(lisp_loc_tree, hf_lisp_loc_locator, tvb, offset, addr_len, locator);
        offset += addr_len;
    }

    proto_item_append_text(tir, " %d, %sRLOC: %s%s, %s, Priority/Weight: %d/%d, Multicast Priority/Weight: %d/%d",
            rec,
            (flags&LOCAL_BIT_MASK) ? "Local " : "",
            locator,
            (flags&PROBE_BIT_MASK) ? " (probed)" : "",
            (flags&REACH_BIT_MASK) ? "Reachable" : "Unreachable",
            prio, weight, m_prio, m_weight);
    proto_item_set_len(tir, 8 + addr_len);

    return offset;
}


/*
 * Dissector code for mapping records within control packets
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                          Record  TTL                          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | Locator Count | EID mask-len  | ACT |A|      Reserved         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | Rsvd  |  Map-Version Number   |            EID-AFI            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                          EID-prefix                           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

int
dissect_lisp_mapping(tvbuff_t *tvb, packet_info *pinfo, proto_tree *lisp_tree,
        uint8_t rec_cnt, int rec, bool referral, int offset, proto_item *tim)
{
    int          i;
    int          str_len;
    uint16_t     addr_len      = 0;
    uint8_t      prefix_mask, loc_cnt;
    uint16_t     flags;
    uint16_t     act;
    uint16_t     prefix_afi, eid_afi;
    const char *prefix;
    proto_item  *tir;
    proto_tree  *lisp_mapping_tree, *lcaf_prefix_tree;

    prefix_mask   = tvb_get_uint8(tvb, offset + 5);
    flags         = tvb_get_ntohs(tvb, offset + 6);
    prefix_afi    = tvb_get_ntohs(tvb, offset + 10);

    act = flags & LISP_MAP_ACT;
    act >>= 13;

    prefix = get_addr_str(tvb, pinfo, offset + 12, prefix_afi, &addr_len);

    if (prefix == NULL) {
        expert_add_info_format(pinfo, lisp_tree, &ei_lisp_unexpected_field,
                "Unexpected EID prefix AFI (%d), cannot decode", prefix_afi);
        return offset;
    }
    tir = proto_tree_add_item(lisp_tree, hf_lisp_mapping, tvb, offset, 12 + addr_len, ENC_NA);
    if (tim) {
        proto_item_append_text(tim, " for %s/%d", prefix, prefix_mask);
    }

    /* Update the INFO column if there is only one record */
    if (rec_cnt == 1)
        col_append_fstr(pinfo->cinfo, COL_INFO, " for %s/%d",
                prefix, prefix_mask);

    /* Create a sub-tree for the mapping */
    lisp_mapping_tree = proto_item_add_subtree(tir, ett_lisp_mapping);
    proto_item_append_text(tir, " %d, EID Prefix: %s/%d", rec, prefix, prefix_mask);

    /* TTL (32 bits) */
    proto_tree_add_item(lisp_mapping_tree, hf_lisp_mapping_ttl, tvb, offset, 4, ENC_BIG_ENDIAN);
    if (tvb_get_ntohl(tvb, offset) == 0xFFFFFFFF) {
        proto_item_append_text(tir, ", TTL: Unlimited");
    } else {
        proto_item_append_text(tir, ", TTL: %d", tvb_get_ntohl(tvb, offset));
    }
    offset += 4;

    /* Locator count (8 bits) */
    proto_tree_add_item(lisp_mapping_tree, hf_lisp_mapping_loccnt, tvb, offset, 1, ENC_BIG_ENDIAN);
    loc_cnt = tvb_get_uint8(tvb, offset);
    offset += 1;

    /* EID mask length (8 bits) */
    proto_tree_add_item(lisp_mapping_tree, hf_lisp_mapping_eid_masklen, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Action (3 bits) */
    proto_tree_add_item(lisp_mapping_tree, hf_lisp_mapping_act, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_item_append_text(tir, ", %s%s%s",
            (referral) ? "" : "Action: ",
            val_to_str(act, (referral) ? referral_actions : mapping_actions, "Invalid action code (%d)"),
            (referral&&(flags&REFERRAL_INCOMPLETE)) ? " (Incomplete)" : "");

    /* Authoritative bit */
    proto_tree_add_item(lisp_mapping_tree, hf_lisp_mapping_auth, tvb, offset, 2, ENC_BIG_ENDIAN);
    if (flags&LISP_MAP_AUTH) {
        proto_item_append_text(tir, ", Authoritative");
    } else {
        proto_item_append_text(tir, ", Not Authoritative");
    }

    /* Incomplete bit in Map-Referrals */
    if (referral)
        proto_tree_add_item(lisp_mapping_tree, hf_lisp_referral_incomplete, tvb, offset, 2, ENC_BIG_ENDIAN);

    /* Reserved (11 bits) */
    proto_tree_add_item(lisp_mapping_tree, hf_lisp_mapping_res1, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (referral) {
        /* SigCnt (4 bits) */
        proto_tree_add_item(lisp_mapping_tree, hf_lisp_referral_sigcnt, tvb, offset, 2, ENC_BIG_ENDIAN);
    } else {
        /* Reserved (4 bits) */
        proto_tree_add_item(lisp_mapping_tree, hf_lisp_mapping_res2, tvb, offset, 2, ENC_BIG_ENDIAN);
    }

    /* Map-Version Number (12 bits) */
    proto_tree_add_item(lisp_mapping_tree, hf_lisp_mapping_ver, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* EID prefix AFI (16 bits) */
    eid_afi = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(lisp_mapping_tree, hf_lisp_mapping_eid_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* EID */
    switch (eid_afi) {
        case AFNUM_INET:
            proto_tree_add_item(lisp_mapping_tree, hf_lisp_mapping_eid_ipv4, tvb, offset, INET_ADDRLEN, ENC_BIG_ENDIAN);
            offset += INET_ADDRLEN;
            break;
        case AFNUM_INET6:
            proto_tree_add_item(lisp_mapping_tree, hf_lisp_mapping_eid_ipv6, tvb, offset, INET6_ADDRLEN, ENC_NA);
            offset += INET6_ADDRLEN;
            break;
        case AFNUM_LCAF:
            lcaf_prefix_tree = proto_tree_add_subtree_format(lisp_mapping_tree, tvb, offset, addr_len, ett_lisp_lcaf, NULL, "EID Prefix: %s", prefix);
            dissect_lcaf(tvb, pinfo, lcaf_prefix_tree, offset, NULL);
            offset += addr_len;
            break;
        case AFNUM_802:
        case AFNUM_EUI48:
            proto_tree_add_item(lisp_mapping_tree, hf_lisp_mapping_eid_mac, tvb, offset, EUI48_ADDRLEN, ENC_NA);
            offset += EUI48_ADDRLEN;
            break;
        case AFNUM_DISTNAME:
            str_len = tvb_strsize(tvb, offset);
            proto_tree_add_item(lisp_mapping_tree, hf_lisp_mapping_eid_dn, tvb, offset, str_len, ENC_ASCII);
            offset += str_len;
            break;
    }

    /* Locators */
    for(i=0; i < loc_cnt; i++) {
        tvbuff_t *loc_tvb;
        int len = 0;

        loc_tvb = tvb_new_subset_remaining(tvb, offset);
        len = dissect_lisp_locator(loc_tvb, pinfo, lisp_mapping_tree, i+1);
        offset += len;
    }

    return offset;
}


/*
 * Dissector code for Map-Request type control packets
 *
 *        0                   1                   2                   3
 *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |Type=1 |A|M|P|S|p|s|    Reserved     |   IRC   | Record Count  |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                         Nonce . . .                           |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                         . . . Nonce                           |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |         Source-EID-AFI        |   Source EID Address  ...     |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |         ITR-RLOC-AFI 1        |    ITR-RLOC Address 1  ...    |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                              ...                              |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |         ITR-RLOC-AFI n        |    ITR-RLOC Address n  ...    |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     / |   Reserved    | EID mask-len  |        EID-prefix-AFI         |
 *   Rec +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     \ |                       EID-prefix  ...                         |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                   Map-Reply Record  ...                       |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

static void
dissect_lisp_map_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *lisp_tree)
{
    int                i;
    uint16_t           addr_len    = 0;
    int                offset      = 0;
    uint16_t           flags;
    bool               mrep;
    bool               smr;
    bool               probe;
    bool               pitr;
    bool               smr_invoked;
    uint8_t            itr_rec_cnt = 0;
    uint8_t            rec_cnt     = 0;
    uint16_t           src_eid_afi;
    const char        *src_eid;
    proto_item        *ti_flags;
    proto_tree        *flags_tree, *lcaf_src_eid_tree, *lcaf_prefix_tree;
    tvbuff_t          *next_tvb;

    /* Flags (6 bits)*/
    flags       = tvb_get_ntohs(tvb, offset);
    mrep        = flags & (MAP_REQ_FLAG_M >> 8);
    smr         = flags & (MAP_REQ_FLAG_S >> 8);
    probe       = flags & (MAP_REQ_FLAG_P >> 8);
    pitr        = flags & (MAP_REQ_FLAG_p >> 8);
    smr_invoked = flags & (MAP_REQ_FLAG_s >> 8);

    ti_flags = proto_tree_add_item(lisp_tree, hf_lisp_mreq_flags, tvb, offset, 3, ENC_BIG_ENDIAN);
    flags_tree = proto_item_add_subtree(ti_flags, ett_lisp_mreq_flags);
    proto_tree_add_item(flags_tree, hf_lisp_mreq_flags_auth, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lisp_mreq_flags_mrp, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lisp_mreq_flags_probe, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lisp_mreq_flags_smr, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lisp_mreq_flags_pitr, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lisp_mreq_flags_smri, tvb, offset, 3, ENC_BIG_ENDIAN);

    if (pitr)
        col_append_str(pinfo->cinfo, COL_INFO, " by P-ITR");

    if (smr)
        col_append_str(pinfo->cinfo, COL_INFO, " (SMR)");

    if (probe)
        col_append_str(pinfo->cinfo, COL_INFO, " (RLOC-probe)");

    if (smr_invoked)
        col_append_str(pinfo->cinfo, COL_INFO, " (SMR-invoked)");

    /* Reserved bits (9 bits) */
    proto_tree_add_item(lisp_tree, hf_lisp_mreq_res, tvb, offset, 3, ENC_BIG_ENDIAN);

    /* ITR record count (5 bits) */
    itr_rec_cnt = tvb_get_uint8(tvb, offset + 2) & 0x1F;
    proto_tree_add_item(lisp_tree, hf_lisp_irc, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    /* Record count (8 bits) */
    rec_cnt = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(lisp_tree, hf_lisp_records, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Nonce (64 bits) */
    proto_tree_add_item(lisp_tree, hf_lisp_nonce, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    /* Source EID AFI (16 bits) */
    src_eid_afi = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(lisp_tree, hf_lisp_mreq_srceid_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Source EID */
    switch (src_eid_afi) {
        case AFNUM_RESERVED:
            proto_tree_add_string(lisp_tree, hf_lisp_mreq_srceid_string, tvb, offset, 0, "not set");
            break;
        case AFNUM_INET:
            proto_tree_add_item(lisp_tree,
                    hf_lisp_mreq_srceid_ipv4, tvb, offset, INET_ADDRLEN, ENC_BIG_ENDIAN);
            offset += INET_ADDRLEN;
            break;
        case AFNUM_INET6:
            proto_tree_add_item(lisp_tree,
                    hf_lisp_mreq_srceid_ipv6, tvb, offset, INET6_ADDRLEN, ENC_NA);
            offset += INET6_ADDRLEN;
            break;
        case AFNUM_LCAF:
            src_eid = get_addr_str(tvb, pinfo, offset, src_eid_afi, &addr_len);
            lcaf_src_eid_tree = proto_tree_add_subtree_format(lisp_tree, tvb, offset, addr_len, ett_lisp_lcaf, NULL, "Source EID: %s", src_eid);
            dissect_lcaf(tvb, pinfo, lcaf_src_eid_tree, offset, NULL);
            offset += addr_len;
            break;
        case AFNUM_802:
        case AFNUM_EUI48:
            proto_tree_add_item(lisp_tree,
                    hf_lisp_mreq_srceid_mac, tvb, offset, EUI48_ADDRLEN, ENC_NA);
            offset += EUI48_ADDRLEN;
            break;
        default:
            expert_add_info_format(pinfo, lisp_tree, &ei_lisp_unexpected_field,
                    "Unexpected Source EID AFI (%d), cannot decode", src_eid_afi);
            next_tvb = tvb_new_subset_remaining(tvb, offset);
            call_data_dissector(next_tvb, pinfo, lisp_tree);
            return;
    }

    /* ITR records */
    for(i=0; i < itr_rec_cnt+1; i++) {
        uint16_t itr_afi;
        proto_item *tir;
        proto_tree *lisp_itr_tree;

        itr_afi = tvb_get_ntohs(tvb, offset);
        tir = proto_tree_add_item(lisp_tree, hf_lisp_mreq_itr_rloc, tvb, offset, 2, ENC_NA);
        lisp_itr_tree = proto_item_add_subtree(tir, ett_lisp_itr);
        proto_tree_add_item(lisp_itr_tree, hf_lisp_mreq_itr_rloc_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        switch (itr_afi) {
            case AFNUM_INET:
                proto_tree_add_item(lisp_itr_tree, hf_lisp_mreq_itr_rloc_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_item_append_text(tir, " %d: %s", i + 1, tvb_ip_to_str(pinfo->pool, tvb, offset));
                proto_item_set_len(tir, 2 + INET_ADDRLEN);
                offset += INET_ADDRLEN;
                break;
            case AFNUM_INET6:
                proto_tree_add_item(lisp_itr_tree, hf_lisp_mreq_itr_rloc_ipv6, tvb, offset, 16, ENC_NA);
                proto_item_append_text(tir, " %d: %s", i + 1, tvb_ip6_to_str(pinfo->pool, tvb, offset));
                proto_item_set_len(tir, 2 + INET6_ADDRLEN);
                offset += INET6_ADDRLEN;
                break;
            default:
                expert_add_info_format(pinfo, lisp_tree, &ei_lisp_unexpected_field,
                        "Unexpected ITR-RLOC-AFI (%d), cannot decode", itr_afi);
                next_tvb = tvb_new_subset_remaining(tvb, offset);
                call_data_dissector(next_tvb, pinfo, lisp_tree);
                return;
        }
    }

    /* Query records */
    for(i=0; i < rec_cnt; i++) {
        int str_len;
        uint16_t prefix_mask;
        uint16_t prefix_afi;
        const char *prefix;
        proto_item *tir;
        proto_tree *lisp_record_tree;

        addr_len = 0;
        prefix_mask = tvb_get_uint8(tvb, offset + 1);
        prefix_afi = tvb_get_ntohs(tvb, offset + 2);
        prefix = get_addr_str(tvb, pinfo, offset + 4, prefix_afi, &addr_len);

        if (prefix == NULL) {
            expert_add_info_format(pinfo, lisp_tree, &ei_lisp_unexpected_field,
                    "Unexpected EID prefix AFI (%d), cannot decode", prefix_afi);
            next_tvb = tvb_new_subset_remaining(tvb, offset);
            call_data_dissector(next_tvb, pinfo, lisp_tree);
            return;
        }

        tir = proto_tree_add_item(lisp_tree, hf_lisp_mreq_record, tvb, offset, 4+addr_len, ENC_NA);

        /* Update the INFO column if there is only one record */
        if (rec_cnt == 1)
            col_append_fstr(pinfo->cinfo, COL_INFO, " for %s/%d", prefix, prefix_mask);

        lisp_record_tree = proto_item_add_subtree(tir, ett_lisp_record);
        proto_tree_add_item(lisp_record_tree, hf_lisp_mreq_record_res, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(lisp_record_tree, hf_lisp_mreq_record_prefix_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(lisp_record_tree, hf_lisp_mreq_record_prefix_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        switch (prefix_afi) {
            case AFNUM_INET:
                proto_tree_add_item(lisp_record_tree, hf_lisp_mreq_record_prefix_ipv4, tvb, offset, INET_ADDRLEN, ENC_NA);
                offset += INET_ADDRLEN;
                break;
            case AFNUM_INET6:
                proto_tree_add_item(lisp_record_tree, hf_lisp_mreq_record_prefix_ipv6, tvb, offset, INET6_ADDRLEN, ENC_NA);
                offset += INET6_ADDRLEN;
                break;
            case AFNUM_LCAF:
                lcaf_prefix_tree = proto_tree_add_subtree_format(lisp_record_tree, tvb, offset, addr_len, ett_lisp_lcaf, NULL, "Prefix: %s", prefix);
                dissect_lcaf(tvb, pinfo, lcaf_prefix_tree, offset, NULL);
                offset += addr_len;
                break;
            case AFNUM_802:
            case AFNUM_EUI48:
                proto_tree_add_item(lisp_record_tree, hf_lisp_mreq_record_prefix_mac, tvb, offset, EUI48_ADDRLEN, ENC_NA);
                offset += EUI48_ADDRLEN;
                break;
            case AFNUM_DISTNAME:
                str_len = tvb_strsize(tvb, offset);
                proto_tree_add_item(lisp_record_tree, hf_lisp_mreq_record_prefix_dn, tvb, offset, str_len, ENC_ASCII);
                offset += str_len;
                break;
        }
        proto_item_append_text(tir, " %d: %s/%d", i+1, prefix, prefix_mask);
    }

    /* If M bit is set, we also have a Map-Reply */
    if (mrep) {
        proto_item *tim;
        proto_tree *lisp_mr_tree;

        tim = proto_tree_add_item(lisp_tree, hf_lisp_mrep_record, tvb, offset, -1, ENC_NA);
        lisp_mr_tree = proto_item_add_subtree(tim, ett_lisp_mr);

        offset = dissect_lisp_mapping(tvb, pinfo, lisp_mr_tree, 0, 1, false, offset, NULL);
    }

    next_tvb = tvb_new_subset_remaining(tvb, offset);
    call_data_dissector(next_tvb, pinfo, lisp_tree);
}


/*
 * Dissector code for Map-Reply type control packets
 *
 *        0                   1                   2                   3
 *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |Type=2 |P|E|S|           Reserved              | Record Count  |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                         Nonce . . .                           |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                         . . . Nonce                           |
 *   +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   |                          Record  TTL                          |
 *   |   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   R   | Locator Count | EID mask-len  | ACT |A|      Reserved         |
 *   e   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   c   | Rsvd  |  Map-Version Number   |            EID-AFI            |
 *   o   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   r   |                          EID-prefix                           |
 *   d   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  /|    Priority   |    Weight     |  M Priority   |   M Weight    |
 *   | L +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   | o |        Unused Flags     |L|p|R|           Loc-AFI             |
 *   | c +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  \|                             Locator                           |
 *   +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

static void
dissect_lisp_map_reply(tvbuff_t *tvb, packet_info *pinfo, proto_tree *lisp_tree)
{
    int       i;
    int       offset  = 0;
    bool      probe;
    uint8_t   flags;
    uint8_t   rec_cnt = 0;
    tvbuff_t *next_tvb;

    /* Flags (2 bits) */
    flags = tvb_get_uint8(tvb, offset);
    probe = flags & (MAP_REP_FLAG_P >> 16);
    proto_tree_add_item(lisp_tree, hf_lisp_mrep_flags_probe, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(lisp_tree, hf_lisp_mrep_flags_enlr, tvb, offset, 3, ENC_BIG_ENDIAN);

    /* Flags defined in LISP-SEC draft (1 bit) */
    proto_tree_add_item(lisp_tree, hf_lisp_mrep_flags_sec, tvb, offset, 3, ENC_BIG_ENDIAN);

    if (probe)
        col_append_str(pinfo->cinfo, COL_INFO, " (RLOC-probe reply)");

    /* Reserved bits (18 bits) */
    proto_tree_add_item(lisp_tree, hf_lisp_mrep_res, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    /* Record count (8 bits) */
    rec_cnt = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(lisp_tree, hf_lisp_records, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Nonce (64 bits) */
    proto_tree_add_item(lisp_tree, hf_lisp_nonce, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    /* Reply records */
    for(i=0; i < rec_cnt; i++) {
        offset = dissect_lisp_mapping(tvb, pinfo, lisp_tree, rec_cnt, i+1, false, offset, NULL);
    }

    next_tvb = tvb_new_subset_remaining(tvb, offset);
    call_data_dissector(next_tvb, pinfo, lisp_tree);
}


/*
 *  Dissector code for Map-Register type control packets
 *
 *        0                   1                   2                   3
 *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |Type=3 |P|S|I|R|         Reserved            |M| Record Count  |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                         Nonce . . .                           |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                         . . . Nonce                           |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |            Key ID             |  Authentication Data Length   |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       ~                     Authentication Data                       ~
 *   +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   |                          Record  TTL                          |
 *   |   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   R   | Locator Count | EID mask-len  | ACT |A|      Reserved         |
 *   e   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   c   | Rsvd  |  Map-Version Number   |            EID-AFI            |
 *   o   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   r   |                          EID-prefix                           |
 *   d   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  /|    Priority   |    Weight     |  M Priority   |   M Weight    |
 *   | L +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   | o |        Unused Flags     |L|p|R|           Loc-AFI             |
 *   | c +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  \|                             Locator                           |
 *   +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

int
dissect_lisp_map_register(tvbuff_t *tvb, packet_info *pinfo, proto_tree *lisp_tree,
        int offset, proto_item *tim, bool keep_going)
{
    int       i;
    uint8_t   rec_cnt = 0;
    tvbuff_t *next_tvb;
    uint16_t  authlen = 0;
    uint16_t  flags;
    bool      xtrid;
    bool      rtr;

    /* Flags (1 bit) */
    proto_tree_add_item(lisp_tree, hf_lisp_mreg_flags_pmr, tvb, offset, 3, ENC_BIG_ENDIAN);

    /* Flags defined in LISP-SEC draft (1 bit) */
    proto_tree_add_item(lisp_tree, hf_lisp_mreg_flags_sec, tvb, offset, 3, ENC_BIG_ENDIAN);

    /* Flags defined in NAT Traversal draft (2 bits) */
    flags = tvb_get_ntohs(tvb, offset);
    xtrid = flags & (MAP_REG_FLAG_I >> 8);
    rtr   = flags & (MAP_REG_FLAG_R >> 8);

    proto_tree_add_item(lisp_tree, hf_lisp_mreg_flags_xtrid, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(lisp_tree, hf_lisp_mreg_flags_rtr, tvb, offset, 3, ENC_BIG_ENDIAN);

    if (rtr)
        col_append_str(pinfo->cinfo, COL_INFO, " (RTR)");

    /* Reserved bits (15 bits) */
    proto_tree_add_item(lisp_tree, hf_lisp_mreg_res, tvb, offset, 3, ENC_BIG_ENDIAN);

    /* Flags (1 bit) */
    proto_tree_add_item(lisp_tree, hf_lisp_mreg_flags_wmn, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    /* Record count (8 bits) */
    rec_cnt = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(lisp_tree, hf_lisp_records, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Nonce (64 bits) */
    proto_tree_add_item(lisp_tree, hf_lisp_nonce, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    /* Key ID (16 bits) */
    proto_tree_add_item(lisp_tree, hf_lisp_keyid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Authentication Data Length (16 bits) */
    authlen = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(lisp_tree, hf_lisp_authlen, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Authentication Data */
    /* XXX: need to check is there is still enough data in buffer */
    proto_tree_add_item(lisp_tree, hf_lisp_auth, tvb, offset, authlen, ENC_NA);
    offset += authlen;

    for(i=0; i < rec_cnt; i++) {
        offset = dissect_lisp_mapping(tvb, pinfo, lisp_tree, rec_cnt, i+1, false, offset, tim);
    }

    /* If I bit is set, we have an xTR-ID and a site-ID field */
    if (xtrid) {
        proto_tree_add_item(lisp_tree, hf_lisp_xtrid, tvb, offset, LISP_XTRID_LEN, ENC_NA);
        proto_tree_add_item(lisp_tree, hf_lisp_siteid, tvb, offset + LISP_XTRID_LEN, LISP_SITEID_LEN, ENC_NA);
        offset += LISP_XTRID_LEN + LISP_SITEID_LEN;
    }

    if (keep_going) {
        next_tvb = tvb_new_subset_remaining(tvb, offset);
        call_data_dissector(next_tvb, pinfo, lisp_tree);
    } else {
        return offset;
    }

    return 0;
}


/*
 *  Dissector code for Map-Notify type control packets
 *
 *        0                   1                   2                   3
 *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |Type=4 |I|R|            Reserved               | Record Count  |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                         Nonce . . .                           |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                         . . . Nonce                           |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |            Key ID             |  Authentication Data Length   |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       ~                     Authentication Data                       ~
 *   +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   |                          Record  TTL                          |
 *   |   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   R   | Locator Count | EID mask-len  | ACT |A|      Reserved         |
 *   e   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   c   | Rsvd  |  Map-Version Number   |            EID-AFI            |
 *   o   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   r   |                          EID-prefix                           |
 *   d   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  /|    Priority   |    Weight     |  M Priority   |   M Weight    |
 *   | L +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   | o |        Unused Flags     |L|p|R|           Loc-AFI             |
 *   | c +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  \|                             Locator                           |
 *   +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

static void
dissect_lisp_map_notify(tvbuff_t *tvb, packet_info *pinfo, proto_tree *lisp_tree)
{
    int       i;
    int       offset  = 0;
    uint8_t   rec_cnt = 0;
    tvbuff_t *next_tvb;
    uint16_t  authlen = 0;
    uint16_t  flags;
    bool      xtrid;
    bool      rtr;

    /* Flags defined in NAT Traversal draft (2 bits) */
    flags = tvb_get_ntohs(tvb, offset);
    xtrid = flags & (MAP_NOT_FLAG_I >> 8);
    rtr   = flags & (MAP_NOT_FLAG_R >> 8);

    proto_tree_add_item(lisp_tree, hf_lisp_mnot_flags_xtrid, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(lisp_tree, hf_lisp_mnot_flags_rtr, tvb, offset, 3, ENC_BIG_ENDIAN);

    if (rtr)
        col_append_str(pinfo->cinfo, COL_INFO, " (RTR)");

    /* Reserved bits (18 bits) */
    proto_tree_add_item(lisp_tree, hf_lisp_mnot_res, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    /* Record count (8 bits) */
    rec_cnt = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(lisp_tree, hf_lisp_records, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Nonce (64 bits) */
    proto_tree_add_item(lisp_tree, hf_lisp_nonce, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    /* Key ID (16 bits) */
    proto_tree_add_item(lisp_tree, hf_lisp_keyid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Authentication Data Length (16 bits) */
    authlen = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(lisp_tree, hf_lisp_authlen, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Authentication Data */
    /* XXX: need to check is there is still enough data in buffer */
    proto_tree_add_item(lisp_tree, hf_lisp_auth, tvb, offset, authlen, ENC_NA);
    offset += authlen;

    for(i=0; i < rec_cnt; i++) {
        offset = dissect_lisp_mapping(tvb, pinfo, lisp_tree, rec_cnt, i+1, false, offset, NULL);
    }

    /* If I bit is set, we have an xTR-ID and a site-ID field */
    if (xtrid) {
        proto_tree_add_item(lisp_tree, hf_lisp_xtrid, tvb, offset, LISP_XTRID_LEN, ENC_NA);
        proto_tree_add_item(lisp_tree, hf_lisp_siteid, tvb, offset + LISP_XTRID_LEN, LISP_SITEID_LEN, ENC_NA);
        offset += LISP_XTRID_LEN + LISP_SITEID_LEN;
    }

    /* If R bit is set, we have MS-RTR authentication data */
    if (rtr) {
        /* MS-RTR Key ID (16 bits) */
        proto_tree_add_item(lisp_tree, hf_lisp_msrtr_keyid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        /* MS-RTR Authentication Data Length (16 bits) */
        authlen = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(lisp_tree, hf_lisp_msrtr_authlen, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        /* MS-RTR Authentication Data */
        /* XXX: need to check is there is still enough data in buffer */
        proto_tree_add_item(lisp_tree, hf_lisp_msrtr_auth, tvb, offset, authlen, ENC_NA);
        offset += authlen;
    }

    next_tvb = tvb_new_subset_remaining(tvb, offset);
    call_data_dissector(next_tvb, pinfo, lisp_tree);
}

/*
 *  Dissector code for Map-Referral type control packets
 *
 *        0                   1                   2                   3
 *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |Type=6 |                Reserved               | Record Count  |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                         Nonce . . .                           |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                         . . . Nonce                           |
 *   +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   |                          Record  TTL                          |
 *   |   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   R   | Referral Count| EID mask-len  | ACT |A|I|     Reserved        |
 *   e   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   c   |SigCnt |   Map Version Number  |            EID-AFI            |
 *   o   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   r   |                          EID-prefix ...                       |
 *   d   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  /|    Priority   |    Weight     |  M Priority   |   M Weight    |
 *   | L +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   | o |        Unused Flags         |R|         Loc/LCAF-AFI          |
 *   | c +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  \|                             Locator ...                       |
 *   +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

static void
dissect_lisp_map_referral(tvbuff_t *tvb, packet_info *pinfo, proto_tree *lisp_tree)
{
    int       i;
    int       offset  = 0;
    uint8_t   rec_cnt = 0;
    tvbuff_t *next_tvb;

    /* Reserved bits (20 bits) */
    proto_tree_add_item(lisp_tree, hf_lisp_mref_res, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    /* Record count (8 bits) */
    rec_cnt = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(lisp_tree, hf_lisp_records, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Nonce (64 bits) */
    proto_tree_add_item(lisp_tree, hf_lisp_nonce, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    /* Referral records */
    for(i=0; i < rec_cnt; i++) {
        offset = dissect_lisp_mapping(tvb, pinfo, lisp_tree, rec_cnt, i+1, true, offset, NULL);
    }

    next_tvb = tvb_new_subset_remaining(tvb, offset);
    call_data_dissector(next_tvb, pinfo, lisp_tree);
}


/*
 *  Dissector code for Info type control packets
 *
 *        0                   1                   2                   3
 *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |Type=7 |R|            Reserved                                 |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                         Nonce . . .                           |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                      . . . Nonce                              |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |              Key ID           |  Authentication Data Length   |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       ~                     Authentication Data                       ~
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                              TTL                              |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |   Reserved    | EID mask-len  |        EID-prefix-AFI         |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                          EID-prefix                           |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |               AFI             |              ...
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

static void
dissect_lisp_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *lisp_tree)
{
    int          offset   = 0;
    tvbuff_t    *next_tvb;
    uint8_t      flags;
    bool         reply;
    uint16_t     authlen  = 0;
    uint8_t      prefix_mask;
    uint16_t     prefix_afi, afi;
    const char *prefix;
    uint16_t     addr_len = 0;
    proto_item  *tir, *ti_prefix;
    proto_tree  *prefix_tree;

    /* Flags (1 bit) */
    flags = tvb_get_uint8(tvb, offset);
    reply = flags & (INFO_FLAG_R >> 16);

    if (reply)
        col_append_str(pinfo->cinfo, COL_INFO, "-Reply");
    else
        col_append_str(pinfo->cinfo, COL_INFO, "-Request");

    proto_tree_add_item(lisp_tree, hf_lisp_info_r, tvb, offset, 3, ENC_BIG_ENDIAN);

    /* Reserved bits (27 bits) */
    proto_tree_add_item(lisp_tree, hf_lisp_info_res1, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* Nonce (64 bits) */
    proto_tree_add_item(lisp_tree, hf_lisp_nonce, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    /* Key ID (16 bits) */
    proto_tree_add_item(lisp_tree, hf_lisp_keyid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Authentication Data Length (16 bits) */
    authlen = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(lisp_tree, hf_lisp_authlen, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Authentication Data */
    /* XXX: need to check is there is still enough data in buffer */
    proto_tree_add_item(lisp_tree, hf_lisp_auth, tvb, offset, authlen, ENC_NA);
    offset += authlen;

    /* TTL */
    proto_tree_add_item(lisp_tree, hf_lisp_info_ttl, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* Reserved bits (8 bits) */
    proto_tree_add_item(lisp_tree, hf_lisp_info_res2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    prefix_tree = proto_tree_add_subtree(lisp_tree, tvb, offset, 3, ett_lisp_info_prefix, &ti_prefix, "EID Prefix: ");

    proto_tree_add_item(prefix_tree, hf_lisp_info_prefix_masklen, tvb, offset, 1, ENC_BIG_ENDIAN);
    prefix_mask = tvb_get_uint8(tvb, offset); offset += 1;

    proto_tree_add_item(prefix_tree, hf_lisp_info_prefix_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
    prefix_afi = tvb_get_ntohs(tvb, offset);  offset += 2;

    prefix = get_addr_str(tvb, pinfo, offset, prefix_afi, &addr_len);

    if (prefix == NULL) {
        expert_add_info_format(pinfo, lisp_tree, &ei_lisp_unexpected_field,
                "Unexpected EID prefix AFI (%d), cannot decode", prefix_afi);
        next_tvb = tvb_new_subset_remaining(tvb, offset);
        call_data_dissector(next_tvb, pinfo, lisp_tree);
        return;
    }

    switch (prefix_afi) {
        case AFNUM_INET:
            proto_tree_add_item(prefix_tree, hf_lisp_info_prefix_ipv4, tvb, offset, INET_ADDRLEN, ENC_BIG_ENDIAN);
            break;
        case AFNUM_INET6:
            proto_tree_add_item(prefix_tree, hf_lisp_info_prefix_ipv6, tvb, offset, INET6_ADDRLEN, ENC_NA);
            break;
    }

    proto_item_append_text(ti_prefix, "%s/%d", prefix, prefix_mask);
    proto_item_set_len(ti_prefix, 3 + addr_len);
    offset += addr_len;

    /* Update the INFO column */
    col_append_fstr(pinfo->cinfo, COL_INFO, " for %s/%d", prefix, prefix_mask);

    tir = proto_tree_add_item(lisp_tree, hf_lisp_info_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
    afi  = tvb_get_ntohs(tvb, offset); offset += 2;

    if (!reply) {
        if (afi != 0) {
            expert_add_info_format(pinfo, tir, &ei_lisp_expected_field,
                    "Expecting NULL AFI (0), found %d, incorrect packet!", afi);
        }
    } else {
        if (afi != AFNUM_LCAF) {
            expert_add_info_format(pinfo, tir, &ei_lisp_expected_field,
                    "Expecting LCAF AFI (%d), found %d, incorrect packet!",
                    AFNUM_LCAF, afi);
        } else {
            offset = dissect_lcaf(tvb, pinfo, lisp_tree, offset, NULL);
        }
    }

    next_tvb = tvb_new_subset_remaining(tvb, offset);
    call_data_dissector(next_tvb, pinfo, lisp_tree);
}


/*
 * Dissector code for Encapsulated Control Message type packets
 *
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |Type=8 |S|D|                 Reserved                          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                       IPv4 or IPv6 Header                     |
 *  |                  (uses RLOC or EID addresses)                 |
 *  ~                                                               ~
 *
 */

static void
dissect_lisp_ecm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *lisp_tree)
{
    tvbuff_t *next_tvb;
    uint8_t   flags;
    uint8_t   ip_ver;

    /* Flags (2 bits) */
    flags = tvb_get_uint8(tvb, 0);
    ddt_originated = flags & (ECM_FLAG_D >> 24);

    proto_tree_add_item(lisp_tree, hf_lisp_ecm_flags_sec, tvb, 0, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(lisp_tree, hf_lisp_ecm_flags_ddt, tvb, 0, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(lisp_tree, hf_lisp_ecm_res, tvb, 0, 4, ENC_BIG_ENDIAN);

    /* Determine if encapsulated packet is IPv4 or IPv6, and call dissector */
    next_tvb = tvb_new_subset_remaining(tvb, LISP_ECM_HEADER_LEN);
    ip_ver = tvb_get_bits8(next_tvb, 0, 4);

    switch (ip_ver) {
        case 4:
            call_dissector(ipv4_handle, next_tvb, pinfo, tree);
            break;
        case 6:
            call_dissector(ipv6_handle, next_tvb, pinfo, tree);
            break;
        default:
            call_data_dissector(next_tvb, pinfo, tree);
            break;
    }
    encapsulated = false;
}


/*
 * Main dissector code
 */

static int
dissect_lisp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    uint8_t type;

    proto_tree *lisp_tree = NULL;

    /* Clear Info column before fetching data in case an exception is thrown */
    col_clear(pinfo->cinfo, COL_INFO);

    type = tvb_get_bits8(tvb, 0, 4);

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LISP");

    if (encapsulated) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Encapsulated %s", val_to_str(type, lisp_typevals,
                    "Unknown LISP Control Packet (%d)"));
    } else {
        col_add_str(pinfo->cinfo, COL_INFO, val_to_str(type, lisp_typevals,
                    "Unknown LISP Control Packet (%d)"));
    }

    if (ddt_originated) {
        col_append_str(pinfo->cinfo, COL_INFO, " (DDT-originated)");
        ddt_originated = false;
    }

    if (tree) {
        proto_item *ti;

        /* create display subtree for the protocol */
        ti = proto_tree_add_item(tree, proto_lisp, tvb, 0,
                (type == LISP_ECM) ? LISP_ECM_HEADER_LEN : -1, ENC_NA);

        lisp_tree = proto_item_add_subtree(ti, ett_lisp);

        proto_tree_add_item(lisp_tree,
            hf_lisp_type, tvb, 0, 3, ENC_BIG_ENDIAN);
    }

    /* Sub-dissectors are indirectly called by the following and thus
       this code should be executed whether or not tree==NULL.
    */
    switch (type) {
    case LISP_MAP_REQUEST:
        dissect_lisp_map_request(tvb, pinfo, lisp_tree);
        break;
    case LISP_MAP_REPLY:
        dissect_lisp_map_reply(tvb, pinfo, lisp_tree);
        break;
    case LISP_MAP_REGISTER:
        dissect_lisp_map_register(tvb, pinfo, lisp_tree, 0, NULL, true);
        break;
    case LISP_MAP_NOTIFY:
        dissect_lisp_map_notify(tvb, pinfo, lisp_tree);
        break;
    case LISP_MAP_REFERRAL:
        dissect_lisp_map_referral(tvb, pinfo, lisp_tree);
        break;
    case LISP_INFO:
        dissect_lisp_info(tvb, pinfo, lisp_tree);
        break;
    case LISP_ECM:
        encapsulated = true;
        dissect_lisp_ecm(tvb, pinfo, tree, lisp_tree);
        break;
    default:
        call_data_dissector(tvb, pinfo, tree);
        break;
    }

    /* Return the amount of data this dissector was able to dissect */
    return tvb_reported_length(tvb);
}


/*
 *  Register the LISP protocol with Wireshark
 */

void
proto_register_lisp(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {
        { &hf_lisp_type,
            { "Type", "lisp.type",
            FT_UINT24, BASE_DEC, VALS(lisp_typevals), 0xF00000, "LISP Control Message Type", HFILL }},
        { &hf_lisp_irc,
            { "ITR-RLOC Count", "lisp.irc",
            FT_UINT24, BASE_DEC, NULL, 0x00001F, NULL, HFILL }},
        { &hf_lisp_records,
            { "Record Count", "lisp.records",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_nonce,
            { "Nonce", "lisp.nonce",
            FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_mreq_flags,
            { "Flags", "lisp.mreq.flags",
            FT_UINT24, BASE_HEX, NULL, 0x0FC000, NULL, HFILL }},
        { &hf_lisp_mreq_flags_auth,
            { "A bit (Authoritative)", "lisp.mreq.flags.auth",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), MAP_REQ_FLAG_A, NULL, HFILL }},
        { &hf_lisp_mreq_flags_mrp,
            { "M bit (Map-Reply present)", "lisp.mreq.flags.mrp",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), MAP_REQ_FLAG_M, NULL, HFILL }},
        { &hf_lisp_mreq_flags_probe,
            { "P bit (Probe)", "lisp.mreq.flags.probe",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), MAP_REQ_FLAG_P, NULL, HFILL }},
        { &hf_lisp_mreq_flags_smr,
            { "S bit (Solicit-Map-Request)", "lisp.mreq.flags.smr",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), MAP_REQ_FLAG_S, NULL, HFILL }},
        { &hf_lisp_mreq_flags_pitr,
            { "p bit (Proxy ITR)", "lisp.mreq.flags.pitr",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), MAP_REQ_FLAG_p, NULL, HFILL }},
        { &hf_lisp_mreq_flags_smri,
            { "s bit (SMR-invoked)", "lisp.mreq.flags.smri",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), MAP_REQ_FLAG_s, NULL, HFILL }},
        { &hf_lisp_mreq_res,
            { "Reserved bits", "lisp.mreq.res",
            FT_UINT24, BASE_HEX, NULL, MAP_REQ_RESERVED, "Must be zero", HFILL }},
        { &hf_lisp_mreq_srceid_afi,
            { "Source EID AFI", "lisp.mreq.srceid.afi",
            FT_UINT16, BASE_DEC, VALS(afn_vals), 0x0, "Source EID Address Family Indicator", HFILL }},
        { &hf_lisp_mreq_srceid_string,
            { "Source EID", "lisp.mreq.srceid.string",
            FT_STRING, BASE_NONE, NULL, 0x0, "Source EID Address", HFILL }},
        { &hf_lisp_mreq_srceid_ipv4,
            { "Source EID", "lisp.mreq.srceid.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0, "Source EID Address", HFILL }},
        { &hf_lisp_mreq_srceid_ipv6,
            { "Source EID", "lisp.mreq.srceid_ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0, "Source EID Address", HFILL }},
        { &hf_lisp_mreq_srceid_mac,
            { "Source EID", "lisp.mreq.srceid.mac",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_mreq_itr_rloc,
            { "ITR-RLOC", "lisp.mreq.itr_rloc",
            FT_NONE, BASE_NONE, NULL, 0x0, "Originating ITR RLOC Address", HFILL }},
        { &hf_lisp_mreq_itr_rloc_afi,
            { "ITR-RLOC AFI", "lisp.mreq.itr_rloc.afi",
            FT_UINT16, BASE_DEC, VALS(afn_vals), 0x0, "Originating ITR RLOC Address Family Indicator", HFILL }},
        { &hf_lisp_mreq_itr_rloc_ipv4,
            { "ITR-RLOC Address", "lisp.mreq.itr_rloc_ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0, "Originating ITR RLOC Address", HFILL }},
        { &hf_lisp_mreq_itr_rloc_ipv6,
            { "ITR-RLOC Address", "lisp.mreq.itr_rloc_ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0, "Originating ITR RLOC Address", HFILL }},
        { &hf_lisp_mreq_record_res,
            { "Reserved", "lisp.mreq.record.res",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_mreq_record_prefix_length,
            { "Prefix Length", "lisp.mreq.record.prefix.length",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_mreq_record_prefix_afi,
            { "Prefix AFI", "lisp.mreq.record.prefix.afi",
            FT_UINT16, BASE_DEC, VALS(afn_vals), 0x0, NULL, HFILL }},
        { &hf_lisp_mreq_record_prefix_ipv4,
            { "Prefix", "lisp.mreq.record.prefix.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_mreq_record_prefix_ipv6,
            { "Prefix", "lisp.mreq.record.prefix.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_mreq_record_prefix_mac,
            { "Prefix", "lisp.mreq.record.prefix.mac",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_mreq_record_prefix_dn,
            { "Prefix", "lisp.mreq.record.prefix.dn",
            FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_mreq_record,
            { "Map-Request Record", "lisp.mreq.record",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_mrep_record,
            { "Map-Reply Record", "lisp.mrep.record",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_mrep_flags_probe,
            { "P bit (Probe)", "lisp.mrep.flags.probe",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), MAP_REP_FLAG_P, NULL, HFILL }},
        { &hf_lisp_mrep_flags_enlr,
            { "E bit (Echo-Nonce locator reachability algorithm enabled)", "lisp.mrep.flags.enlr",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), MAP_REP_FLAG_E, NULL, HFILL }},
        { &hf_lisp_mrep_flags_sec,
            { "S bit (LISP-SEC capable)", "lisp.mrep.flags.sec",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), MAP_REP_FLAG_S, NULL, HFILL }},
        { &hf_lisp_mrep_res,
            { "Reserved bits", "lisp.mrep.res",
            FT_UINT24, BASE_HEX, NULL, MAP_REP_RESERVED, "Must be zero", HFILL }},
        { &hf_lisp_mreg_flags_pmr,
            { "P bit (Proxy-Map-Reply)", "lisp.mreg.flags.pmr",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), MAP_REG_FLAG_P, NULL, HFILL }},
        { &hf_lisp_mreg_flags_sec,
            { "S bit (LISP-SEC capable)", "lisp.mreg.flags.sec",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), MAP_REG_FLAG_S, NULL, HFILL }},
        { &hf_lisp_mreg_flags_xtrid,
            { "I bit (xTR-ID present)", "lisp.mreg.flags.xtrid",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), MAP_REG_FLAG_I, NULL, HFILL }},
        { &hf_lisp_mreg_flags_rtr,
            { "R bit (Built for an RTR)", "lisp.mreg.flags.rtr",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), MAP_REG_FLAG_R, NULL, HFILL }},
        { &hf_lisp_mreg_flags_wmn,
            { "M bit (Want-Map-Notify)", "lisp.mreg.flags.wmn",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), MAP_REG_FLAG_M, NULL, HFILL }},
        { &hf_lisp_mreg_res,
            { "Reserved bits", "lisp.mreg.res",
            FT_UINT24, BASE_HEX, NULL, MAP_REG_RESERVED, "Must be zero", HFILL }},
        { &hf_lisp_mref_res,
            { "Reserved bits", "lisp.mref.res",
            FT_UINT24, BASE_HEX, NULL, MAP_REF_RESERVED, "Must be zero", HFILL }},
        { &hf_lisp_keyid,
            { "Key ID", "lisp.keyid",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_authlen,
            { "Authentication Data Length", "lisp.authlen",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_auth,
            { "Authentication Data", "lisp.auth",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_msrtr_keyid,
            { "MS-RTR Key ID", "lisp.msrtr.keyid",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_msrtr_authlen,
            { "MS-RTR Authentication Data Length", "lisp.msrtr.authlen",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_msrtr_auth,
            { "MS-RTR Authentication Data", "lisp.msrtr.auth",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_xtrid,
            { "xTR-ID", "lisp.xtrid",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_siteid,
            { "Site-ID", "lisp.siteid",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_mnot_flags_xtrid,
            { "I bit (xTR-ID present)", "lisp.mnot.flags.xtrid",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), MAP_NOT_FLAG_I, NULL, HFILL }},
        { &hf_lisp_mnot_flags_rtr,
            { "R bit (Built for an RTR)", "lisp.mnot.flags.rtr",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), MAP_NOT_FLAG_R, NULL, HFILL }},
        { &hf_lisp_mnot_res,
            { "Reserved bits", "lisp.mnot.res",
            FT_UINT24, BASE_HEX, NULL, MAP_NOT_RESERVED, "Must be zero", HFILL }},
        { &hf_lisp_info_r,
            { "R bit (Info-Reply)", "lisp.info.r",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), INFO_FLAG_R, NULL, HFILL }},
        { &hf_lisp_info_res1,
            { "Reserved bits", "lisp.info.res1",
            FT_UINT32, BASE_HEX, NULL, INFO_RESERVED, "Must be zero", HFILL }},
        { &hf_lisp_info_ttl,
            { "TTL", "lisp.info.ttl",
            FT_UINT32, BASE_DEC, NULL, 0x0, "RTR information time-to-live", HFILL }},
        { &hf_lisp_info_res2,
            { "Reserved bits", "lisp.info.res2",
            FT_UINT8, BASE_HEX, NULL, 0xFF, "Must be zero", HFILL }},
        { &hf_lisp_info_prefix_masklen,
            { "EID Prefix Mask Length", "lisp.info.prefix.masklen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_info_prefix_afi,
            { "Prefix AFI", "lisp.info.prefix.afi",
            FT_UINT16, BASE_DEC, VALS(afn_vals), 0x0, NULL, HFILL }},
        { &hf_lisp_info_prefix_ipv4,
            { "Prefix", "lisp.info.prefix.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_info_prefix_ipv6,
            { "Prefix", "lisp.info.prefix.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_info_afi,
            { "AFI", "lisp.info.afi",
            FT_UINT16, BASE_DEC, VALS(afn_vals), 0x0, "Address Family Indicator", HFILL }},
        { &hf_lisp_loc,
            { "Locator Record", "lisp.loc",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_loc_priority,
            { "Priority", "lisp.loc.priority",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_loc_weight,
            { "Weight", "lisp.loc.weight",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_loc_mpriority,
            { "Multicast Priority", "lisp.loc.multicast_priority",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_loc_mweight,
            { "Multicast Weight", "lisp.loc.multicast_weight",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_loc_flags,
            { "Flags", "lisp.loc.flags",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_loc_flags_local,
            { "Local", "lisp.loc.flags.local",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), LOCAL_BIT_MASK, NULL, HFILL }},
        { &hf_lisp_loc_flags_probe,
            { "Probe", "lisp.loc.flags.probe",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), PROBE_BIT_MASK, NULL, HFILL }},
        { &hf_lisp_loc_flags_reach,
            { "Reachable", "lisp.loc.flags.reach",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), REACH_BIT_MASK, NULL, HFILL }},
        { &hf_lisp_loc_flags_res,
            { "Reserved", "lisp.loc.flags.res",
            FT_UINT16, BASE_HEX, NULL, 0xFFF8, "Must be zero", HFILL }},
        { &hf_lisp_loc_afi,
            { "AFI", "lisp.loc.afi",
            FT_UINT16, BASE_DEC, VALS(afn_vals), 0x0, NULL, HFILL }},
        { &hf_lisp_loc_locator,
            { "Locator", "lisp.loc.locator",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_mapping,
            { "Mapping Record", "lisp.mapping",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_mapping_ttl,
            { "Record TTL", "lisp.mapping.ttl",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_mapping_loccnt,
            { "Locator Count", "lisp.mapping.loccnt",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_mapping_eid_masklen,
            { "EID Mask Length", "lisp.mapping.eid.masklen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_mapping_act,
            { "Action", "lisp.mapping.act",
            FT_UINT16, BASE_DEC, VALS(mapping_actions), 0xE000, NULL, HFILL }},
        { &hf_lisp_mapping_auth,
            { "Authoritative bit", "lisp.mapping.auth",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), LISP_MAP_AUTH, NULL, HFILL }},
        { &hf_lisp_referral_incomplete,
            { "Incomplete", "lisp.referral.incomplete",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), REFERRAL_INCOMPLETE, NULL, HFILL }},
        { &hf_lisp_mapping_res1,
            { "Reserved", "lisp.mapping.res1",
            FT_UINT16, BASE_HEX, NULL, 0x07FF, NULL, HFILL }},
        { &hf_lisp_mapping_res2,
            { "Reserved", "lisp.mapping.res2",
            FT_UINT16, BASE_HEX, NULL, 0xF000, NULL, HFILL }},
        { &hf_lisp_mapping_ver,
            { "Mapping Version", "lisp.mapping.ver",
            FT_UINT16, BASE_DEC, NULL, 0x0FFF, NULL, HFILL }},
        { &hf_lisp_referral_sigcnt,
            { "Signature Count", "lisp.referral.sigcnt",
            FT_UINT16, BASE_DEC, NULL, 0xF000, NULL, HFILL }},
        { &hf_lisp_mapping_eid_afi,
            { "EID Prefix AFI", "lisp.mapping.eid.afi",
            FT_UINT16, BASE_DEC, VALS(afn_vals), 0x0, NULL, HFILL }},
        { &hf_lisp_mapping_eid_ipv4,
            { "EID Prefix", "lisp.mapping.eid.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_mapping_eid_ipv6,
            { "EID Prefix", "lisp.mapping.eid.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_mapping_eid_mac,
            { "EID Prefix", "lisp.mapping.eid.mac",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_mapping_eid_dn,
            { "EID Prefix", "lisp.mapping.eid.dn",
            FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_ecm_flags_sec,
            { "S bit (LISP-SEC capable)", "lisp.ecm.flags.sec",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), ECM_FLAG_S, NULL, HFILL }},
        { &hf_lisp_ecm_flags_ddt,
            { "D bit (DDT-originated)", "lisp.ecm.flags.ddt",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), ECM_FLAG_D, NULL, HFILL }},
        { &hf_lisp_ecm_res,
            { "Reserved bits", "lisp.ecm.res",
            FT_UINT32, BASE_HEX, NULL, 0x03FFFFFF, NULL, HFILL }},
        { &hf_lisp_lcaf,
            { "LCAF", "lisp.lcaf",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_header,
            { "LCAF Header", "lisp.lcaf.header",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_res1,
            { "Reserved bits", "lisp.lcaf.res1",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_flags,
            { "Flags", "lisp.lcaf.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_type,
            { "Type", "lisp.lcaf.type",
            FT_UINT8, BASE_DEC, VALS(lcaf_typevals), 0x0, "LISP LCAF Type", HFILL }},
        { &hf_lisp_lcaf_res2,
            { "Reserved bits", "lisp.lcaf.res2",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_length,
            { "Length", "lisp.lcaf.length",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_afi_list_item,
            { "List Item", "lisp.lcaf.afi_list.item",
            FT_NONE, BASE_NONE, NULL, 0x0, "AFI List Item", HFILL }},
        { &hf_lisp_lcaf_afi_list_afi,
            { "List Item AFI", "lisp.lcaf.afi_list.afi",
            FT_UINT16, BASE_DEC, VALS(afn_vals), 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_afi_list_ipv4,
            { "List Item Address", "lisp.lcaf.afi_list.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_afi_list_ipv6,
            { "List Item Address", "lisp.lcaf.afi_list.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_afi_list_mac,
            { "List Item Address", "lisp.lcaf.afi_list.mac",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_afi_list_dn,
            { "List Item Address", "lisp.lcaf.afi_list.dn",
            FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_iid,
            { "Instance ID", "lisp.lcaf.iid",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_iid_afi,
            { "Address AFI", "lisp.lcaf.iid.afi",
            FT_UINT16, BASE_DEC, VALS(afn_vals), 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_iid_ipv4,
            { "Address", "lisp.lcaf.iid.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_iid_ipv6,
            { "Address", "lisp.lcaf.iid.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_iid_mac,
            { "Address", "lisp.lcaf.iid.mac",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_iid_dn,
            { "Address", "lisp.lcaf.iid.dn",
            FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_asn,
            { "AS Number", "lisp.lcaf.asn",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_asn_afi,
            { "Address AFI", "lisp.lcaf.asn.afi",
            FT_UINT16, BASE_DEC, VALS(afn_vals), 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_asn_ipv4,
            { "Address", "lisp.lcaf.asn.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_asn_ipv6,
            { "Address", "lisp.lcaf.asn.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_asn_mac,
            { "Address", "lisp.lcaf.asn.mac",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_asn_dn,
            { "Address", "lisp.lcaf.asn.dn",
            FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_geo_lat,
            { "Latitude", "lisp.lcaf.geo.lat",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_geo_lat_hemisphere,
            { "Hemisphere", "lisp.lcaf.geo.lat.hemisphere",
            FT_UINT16, BASE_DEC, VALS(lat_typevals), 0x8000, NULL, HFILL }},
        { &hf_lisp_lcaf_geo_lat_deg,
            { "Degrees", "lisp.lcaf.geo.lat.deg",
            FT_UINT16, BASE_DEC, NULL, 0x7FFF, NULL, HFILL }},
        { &hf_lisp_lcaf_geo_lat_min,
            { "Minutes", "lisp.lcaf.geo.lat.min",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_geo_lat_sec,
            { "Seconds", "lisp.lcaf.geo.lat.sec",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_geo_lon,
            { "Longitude", "lisp.lcaf.geo.lon",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_geo_lon_hemisphere,
            { "Hemisphere", "lisp.lcaf.geo.lon.hemisphere",
            FT_UINT16, BASE_DEC, VALS(lon_typevals), 0x8000, NULL, HFILL }},
        { &hf_lisp_lcaf_geo_lon_deg,
            { "Degrees", "lisp.lcaf.geo.lon.deg",
            FT_UINT16, BASE_DEC, NULL, 0x7FFF, NULL, HFILL }},
        { &hf_lisp_lcaf_geo_lon_min,
            { "Minutes", "lisp.lcaf.geo.lon.min",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_geo_lon_sec,
            { "Seconds", "lisp.lcaf.geo.lon.sec",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_geo_alt,
            { "Altitude", "lisp.lcaf.geo.alt",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_geo_afi,
            { "Address AFI", "lisp.lcaf.geo.afi",
            FT_UINT16, BASE_DEC, VALS(afn_vals), 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_geo_ipv4,
            { "Address", "lisp.lcaf.geo.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_geo_ipv6,
            { "Address", "lisp.lcaf.geo.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_geo_mac,
            { "Address", "lisp.lcaf.geo.mac",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_geo_dn,
            { "Address", "lisp.lcaf.geo.dn",
            FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_nonce_loc_res,
            { "Reserved bits", "lisp.lcaf.nonce_loc.res",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_nonce_loc,
            { "Nonce", "lisp.lcaf.nonce_loc",
            FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_nonce_loc_afi,
            { "Address AFI", "lisp.lcaf.nonce_loc.afi",
            FT_UINT16, BASE_DEC, VALS(afn_vals), 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_nonce_loc_ipv4,
            { "Address", "lisp.lcaf.nonce_loc.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_nonce_loc_ipv6,
            { "Address", "lisp.lcaf.nonce_loc.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_nonce_loc_mac,
            { "Address", "lisp.lcaf.nonce_loc.mac",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_nonce_loc_dn,
            { "Address", "lisp.lcaf.nonce_loc.dn",
            FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_mcinfo_flags,
            { "Multicast Info Flags", "lisp.lcaf.mcinfo.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_mcinfo_flags_res,
            { "Reserved", "lisp.lcaf.mcinfo.flags.res",
            FT_UINT8, BASE_HEX, NULL, 0xF8, "Must be zero", HFILL }},
        { &hf_lisp_lcaf_mcinfo_flags_rp,
            { "RP-bit", "lisp.lcaf.mcinfo.flags.rp",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), MCINFO_FLAG_R, NULL, HFILL }},
        { &hf_lisp_lcaf_mcinfo_flags_leave,
            { "Leave (L-bit)", "lisp.lcaf.mcinfo.flags.leave",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), MCINFO_FLAG_L, NULL, HFILL }},
        { &hf_lisp_lcaf_mcinfo_flags_join,
            { "Join (J-bit)", "lisp.lcaf_mcinfo.flags.join",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), MCINFO_FLAG_J, NULL, HFILL }},
        { &hf_lisp_lcaf_mcinfo_iid,
            { "Instance ID", "lisp.lcaf.mcinfo_iid",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_mcinfo_res,
            { "Reserved bits", "lisp.lcaf.mcinfo.res",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_mcinfo_src_masklen,
            { "Source Mask Length", "lisp.lcaf.mcinfo.src.masklen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_mcinfo_grp_masklen,
            { "Group Mask Length", "lisp.lcaf.mcinfo.grp.masklen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_mcinfo_src,
            { "Source/Subnet Address", "lisp.lcaf.mcinfo.src",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_mcinfo_src_afi,
            { "Source/Subnet AFI", "lisp.lcaf.mcinfo.src.afi",
            FT_UINT16, BASE_DEC, VALS(afn_vals), 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_mcinfo_src_ipv4,
            { "Source/Subnet Address", "lisp.lcaf.mcinfo.src.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_mcinfo_src_ipv6,
            { "Source/Subnet Address", "lisp.lcaf.mcinfo.src.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_mcinfo_grp,
            { "Group Address", "lisp.lcaf.mcinfo.grp",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_mcinfo_grp_afi,
            { "Group AFI", "lisp.lcaf.mcinfo.grp.afi",
            FT_UINT16, BASE_DEC, VALS(afn_vals), 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_mcinfo_grp_ipv4,
            { "Group Address", "lisp.lcaf.mcinfo.grp.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_mcinfo_grp_ipv6,
            { "Group Address", "lisp.lcaf.mcinfo.grp.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_elp_hop,
            { "Reencap Hop", "lisp.lcaf.elp_hop",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_elp_hop_flags,
            { "Flags", "lisp.lcaf.elp_hop.flags",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_elp_hop_flags_res,
            { "Reserved", "lisp.lcaf.elp_hop.flags.res",
            FT_UINT16, BASE_HEX, NULL, 0xFFF8, "Must be zero", HFILL }},
        { &hf_lisp_lcaf_elp_hop_flags_lookup,
            { "Lookup", "lisp.lcaf.elp_hop.flags.local",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), ELP_FLAG_L, NULL, HFILL }},
        { &hf_lisp_lcaf_elp_hop_flags_probe,
            { "Probe", "lisp.lcaf.elp_hop.flags.probe",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), ELP_FLAG_P, NULL, HFILL }},
        { &hf_lisp_lcaf_elp_hop_flags_strict,
            { "Strict", "lisp.lcaf_elp_hop.flags.strict",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), ELP_FLAG_S, NULL, HFILL }},
        { &hf_lisp_lcaf_elp_hop_afi,
            { "Reencap Hop AFI", "lisp.lcaf.elp_hop.afi",
            FT_UINT16, BASE_DEC, VALS(afn_vals), 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_elp_hop_ipv4,
            { "Reencap Hop", "lisp.lcaf.elp_hop.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_elp_hop_ipv6,
            { "Reencap Hop", "lisp.lcaf.elp_hop.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_srcdst_res,
            { "Reserved bits", "lisp.lcaf.srcdst.res",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_srcdst_src_masklen,
            { "Source Prefix Mask Length", "lisp.lcaf.srcdst.src.masklen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_srcdst_dst_masklen,
            { "Destination Prefix Mask Length", "lisp.lcaf.srcdst.dst.masklen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_srcdst_src,
            { "Source Prefix", "lisp.lcaf.srcdst.src",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_srcdst_src_afi,
            { "Source Prefix AFI", "lisp.lcaf.srcdst.src.afi",
            FT_UINT16, BASE_DEC, VALS(afn_vals), 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_srcdst_src_ipv4,
            { "Source Prefix", "lisp.lcaf.srcdst.src.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_srcdst_src_ipv6,
            { "Source Prefix", "lisp.lcaf.srcdst.src.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_srcdst_src_mac,
            { "Destination Prefix", "lisp.lcaf.srcdst.src.mac",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_srcdst_dst,
            { "Destination Prefix", "lisp.lcaf.srcdst.dst",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_srcdst_dst_afi,
            { "Destination Prefix AFI", "lisp.lcaf.srcdst.dst.afi",
            FT_UINT16, BASE_DEC, VALS(afn_vals), 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_srcdst_dst_ipv4,
            { "Destination Prefix", "lisp.lcaf.srcdst.dst.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_srcdst_dst_ipv6,
            { "Destination Prefix", "lisp.lcaf.srcdst.dst.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_srcdst_dst_mac,
            { "Destination Prefix", "lisp.lcaf.srcdst.dst.mac",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_rle_entry,
            { "RTR/ETR", "lisp.lcaf.rle_entry",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_rle_entry_res,
            { "Reserved bits", "lisp.lcaf.rle_entry.res",
            FT_UINT24, BASE_HEX, NULL, 0x0, "Must be zero", HFILL }},
        { &hf_lisp_lcaf_rle_entry_level,
            { "Level Value", "lisp.lcaf.rle_entry.level",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_rle_entry_afi,
            { "RTR/ETR AFI", "lisp.lcaf.rle_entry.afi",
            FT_UINT16, BASE_DEC, VALS(afn_vals), 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_rle_entry_ipv4,
            { "RTR/ETR", "lisp.lcaf.rle_entry.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_rle_entry_ipv6,
            { "RTR/ETR", "lisp.lcaf.rle_entry.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_kv_key,
            { "Key", "lisp.lcaf.kv_key",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_kv_key_afi,
            { "Key AFI", "lisp.lcaf.kv_key.afi",
            FT_UINT16, BASE_DEC, VALS(afn_vals), 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_kv_key_ipv4,
            { "Key", "lisp.lcaf.kv_key.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_kv_key_ipv6,
            { "Key", "lisp.lcaf.kv_key.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_kv_key_mac,
            { "Key", "lisp.lcaf.kv_key.mac",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_kv_key_dn,
            { "Key", "lisp.lcaf.kv_key.dn",
            FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_kv_value,
            { "Value", "lisp.lcaf.kv_value",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_kv_value_afi,
            { "Value AFI", "lisp.lcaf.kv_value.afi",
            FT_UINT16, BASE_DEC, VALS(afn_vals), 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_kv_value_ipv4,
            { "Value", "lisp.lcaf.kv_value.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_kv_value_ipv6,
            { "Value", "lisp.lcaf.kv_value.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_kv_value_mac,
            { "Value", "lisp.lcaf.kv_value.mac",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_kv_value_dn,
            { "Value", "lisp.lcaf.kv_value.dn",
            FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_natt_rloc,
            { "RLOC", "lisp.lcaf.natt.rloc",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_natt_rloc_afi,
            { "RLOC AFI", "lisp.lcaf.natt.rloc.afi",
            FT_UINT16, BASE_DEC, VALS(afn_vals), 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_natt_rloc_ipv4,
            { "RLOC", "lisp.lcaf.natt.rloc.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_natt_rloc_ipv6,
            { "RLOC", "lisp.lcaf.natt.rloc.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_natt_msport,
            { "MS UDP Port Number", "lisp.lcaf.natt.msport",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_natt_etrport,
            { "ETR UDP Port Number", "lisp.lcaf.natt.etrport",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_vendor_res,
            { "Reserved", "lisp.lcaf.vendor.res",
            FT_UINT8, BASE_HEX, NULL, 0x0, "Must be zero", HFILL }},
        { &hf_lisp_lcaf_vendor_oui,
            { "OUI", "lisp.lcaf.vendor.oui",
            FT_UINT24, BASE_HEX, VALS(oui_vals), 0x0, "Organizationally Unique Identifier", HFILL }},
        { &hf_lisp_lcaf_vendor_data,
            { "Vendor Specific Data", "lisp.lcaf.vendor.data",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_lisp,
        &ett_lisp_mr,
        &ett_lisp_mreq_flags,
        &ett_lisp_mapping,
        &ett_lisp_itr,
        &ett_lisp_record,
        &ett_lisp_lcaf,
        &ett_lisp_lcaf_header,
        &ett_lisp_lcaf_geo_lat,
        &ett_lisp_lcaf_geo_lon,
        &ett_lisp_lcaf_natt_rloc,
        &ett_lisp_lcaf_mcinfo_flags,
        &ett_lisp_lcaf_mcinfo_src,
        &ett_lisp_lcaf_mcinfo_grp,
        &ett_lisp_lcaf_elp_hop,
        &ett_lisp_lcaf_elp_hop_flags,
        &ett_lisp_lcaf_srcdst_src,
        &ett_lisp_lcaf_srcdst_dst,
        &ett_lisp_lcaf_rle_entry,
        &ett_lisp_lcaf_kv_key,
        &ett_lisp_lcaf_kv_value,
        &ett_lisp_lcaf_vendor,
        &ett_lisp_loc,
        &ett_lisp_loc_flags,
        &ett_lisp_info_prefix,
        &ett_lisp_afi_list
    };

    static ei_register_info ei[] = {
        { &ei_lisp_undecoded, { "lisp.undecoded", PI_UNDECODED, PI_WARN, "Not dissected yet (report to wireshark.org)", EXPFILL }},
        { &ei_lisp_unexpected_field, { "lisp.unexpected_field", PI_PROTOCOL, PI_ERROR, "Unexpected field", EXPFILL }},
        { &ei_lisp_invalid_field, { "lisp.invalid_field", PI_PROTOCOL, PI_WARN, "Invalid field", EXPFILL }},
        { &ei_lisp_expected_field, { "lisp.expected_field", PI_PROTOCOL, PI_ERROR, "Expecting field", EXPFILL }},
    };

    expert_module_t* expert_lisp;

    /* Register the protocol name and description */
    proto_lisp = proto_register_protocol("Locator/ID Separation Protocol",
        "LISP Control", "lisp");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_lisp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_lisp = expert_register_protocol(proto_lisp);
    expert_register_field_array(expert_lisp, ei, array_length(ei));

    /* Register dissector so that other dissectors can call it */
    lisp_handle = register_dissector("lisp", dissect_lisp, proto_lisp);
}


/*
 * Simple form of proto_reg_handoff_lisp which can be used if there are
 * no prefs-dependent registration function calls.
 */

void
proto_reg_handoff_lisp(void)
{
    dissector_add_uint_with_preference("udp.port", LISP_CONTROL_PORT, lisp_handle);
    ipv4_handle = find_dissector_add_dependency("ip", proto_lisp);
    ipv6_handle = find_dissector_add_dependency("ipv6", proto_lisp);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
