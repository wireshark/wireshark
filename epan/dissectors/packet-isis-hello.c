/* packet-isis-hello.c
 * Routines for decoding isis hello packets and their CLVs
 *
 * Stuart Stanley <stuarts@mxmail.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/nlpid.h>
#include "packet-osi.h"
#include "packet-isis.h"
#include "packet-isis-clv.h"


/*
 * Declarations for L1/L2 hello base header.
 */
#define ISIS_HELLO_CTYPE_MASK           0x03
#define ISIS_HELLO_CT_RESERVED_MASK     0xfc
#define ISIS_HELLO_PRIORITY_MASK        0x7f
#define ISIS_HELLO_P_RESERVED_MASK      0x80

#define ISIS_HELLO_TYPE_RESERVED        0
#define ISIS_HELLO_TYPE_LEVEL_1         1
#define ISIS_HELLO_TYPE_LEVEL_2         2
#define ISIS_HELLO_TYPE_LEVEL_12        3

/*
 * misc. bittest macros
 */

#define ISIS_RESTART_RR                 0x01
#define ISIS_RESTART_RA                 0x02
#define ISIS_RESTART_SA                 0x04
#define ISIS_MASK_RESTART_RR(x)            ((x)&ISIS_RESTART_RR)
#define ISIS_MASK_RESTART_RA(x)            ((x)&ISIS_RESTART_RA)
#define ISIS_MASK_RESTART_SA(x)            ((x)&ISIS_RESTART_SA)

void proto_register_isis_hello(void);
void proto_reg_handoff_isis_hello(void);

static int proto_isis_hello;

/* hello packets */
static int hf_isis_hello_circuit;
static int hf_isis_hello_circuit_reserved;
static int hf_isis_hello_source_id;
static int hf_isis_hello_holding_timer;
static int hf_isis_hello_pdu_length;
static int hf_isis_hello_priority;
static int hf_isis_hello_priority_reserved;
static int hf_isis_hello_lan_id;
static int hf_isis_hello_clv_type;
static int hf_isis_hello_clv_length;
static int hf_isis_hello_local_circuit_id;
static int hf_isis_hello_clv_ipv4_int_addr;
static int hf_isis_hello_clv_ipv6_int_addr;
/* static int hf_isis_hello_clv_ptp_adj; */
static int hf_isis_hello_clv_mt;
static int hf_isis_hello_clv_restart_flags;
static int hf_isis_hello_clv_restart_flags_rr;
static int hf_isis_hello_clv_restart_flags_ra;
static int hf_isis_hello_clv_restart_flags_sa;
static int hf_isis_hello_clv_restart_remain_time;
static int hf_isis_hello_clv_restart_neighbor;
/* Generated from convert_proto_tree_add_text.pl */
static int hf_isis_hello_extended_local_circuit_id;
static int hf_isis_hello_adjacency_state;
static int hf_isis_hello_neighbor_systemid;
static int hf_isis_hello_digest;
static int hf_isis_hello_digest_v;
static int hf_isis_hello_digest_a;
static int hf_isis_hello_digest_d;
static int hf_isis_hello_ect;
static int hf_isis_hello_bvid;
static int hf_isis_hello_bvid_u;
static int hf_isis_hello_bvid_m;
static int hf_isis_hello_area_address;
static int hf_isis_hello_instance_identifier;
static int hf_isis_hello_supported_itid;
static int hf_isis_hello_clv_nlpid_nlpid;
static int hf_isis_hello_clv_ip_authentication;
static int hf_isis_hello_authentication;

static int hf_isis_hello_aux_mcid;
static int hf_isis_hello_mcid;
static int hf_isis_hello_is_neighbor;
static int hf_isis_hello_mtid;
static int hf_isis_hello_checksum;
static int hf_isis_hello_checksum_status;
static int hf_isis_hello_trill_neighbor_sf;
static int hf_isis_hello_trill_neighbor_lf;
static int hf_isis_hello_trill_neighbor_ff;
static int hf_isis_hello_trill_neighbor_of;
static int hf_isis_hello_trill_neighbor_size;
static int hf_isis_hello_trill_neighbor_reserved;
static int hf_isis_hello_trill_neighbor_mtu;
static int hf_isis_hello_trill_neighbor_snpa;
static int hf_isis_hello_reverse_metric_flags;
static int hf_isis_hello_reverse_metric_flag_reserved;
static int hf_isis_hello_reverse_metric_flag_u;
static int hf_isis_hello_reverse_metric_flag_w;
static int hf_isis_hello_reverse_metric_metric;
static int hf_isis_hello_reverse_metric_sub_length;
static int hf_isis_hello_reverse_metric_sub_data;
static int hf_isis_hello_bfd_enabled_nlpid;
static int hf_isis_hello_neighbor_extended_local_circuit_id;
static int hf_isis_hello_vlan_flags_port_id;
static int hf_isis_hello_vlan_flags_nickname;
static int hf_isis_hello_vlan_flags_af;
static int hf_isis_hello_vlan_flags_ac;
static int hf_isis_hello_vlan_flags_vm;
static int hf_isis_hello_vlan_flags_by;
static int hf_isis_hello_vlan_flags_outer_vlan;
static int hf_isis_hello_vlan_flags_tr;
static int hf_isis_hello_vlan_flags_reserved;
static int hf_isis_hello_vlan_flags_designated_vlan;
static int hf_isis_hello_enabled_vlans;
static int hf_isis_hello_appointed_vlans;
static int hf_isis_hello_af_nickname;
static int hf_isis_hello_af_start_vlan;
static int hf_isis_hello_af_end_vlan;
static int hf_isis_hello_trill_version;
static int hf_isis_hello_trill_hello_reduction;
static int hf_isis_hello_trill_unassigned_1;
static int hf_isis_hello_trill_hop_by_hop_flags;
static int hf_isis_hello_trill_unassigned_2;
static int hf_isis_hello_clv_ipv6_glb_int_addr;

static int ett_isis_hello;
static int ett_isis_hello_clv_area_addr;
static int ett_isis_hello_clv_instance_identifier;
static int ett_isis_hello_clv_is_neighbors;
static int ett_isis_hello_clv_padding;
static int ett_isis_hello_clv_unknown;
static int ett_isis_hello_clv_nlpid;
static int ett_isis_hello_clv_nlpid_nlpid;
static int ett_isis_hello_clv_authentication;
static int ett_isis_hello_clv_ip_authentication;
static int ett_isis_hello_clv_ipv4_int_addr;
static int ett_isis_hello_clv_ipv6_int_addr;
static int ett_isis_hello_clv_ptp_adj;
static int ett_isis_hello_clv_mt;
static int ett_isis_hello_clv_restart;
static int ett_isis_hello_clv_restart_flags;
static int ett_isis_hello_clv_mt_port_cap;
static int ett_isis_hello_clv_mt_port_cap_spb_mcid;
static int ett_isis_hello_clv_mt_port_cap_spb_digest;
static int ett_isis_hello_clv_mt_port_cap_spb_bvid_tuples;
static int ett_isis_hello_clv_mt_port_cap_vlan_flags;
static int ett_isis_hello_clv_mt_port_cap_enabled_vlans;
static int ett_isis_hello_clv_mt_port_cap_appointedfwrdrs;
static int ett_isis_hello_clv_mt_port_cap_port_trill_ver;
static int ett_isis_hello_clv_mt_port_cap_vlans_appointed;
static int ett_isis_hello_clv_trill_neighbor;
static int ett_isis_hello_clv_checksum;
static int ett_isis_hello_clv_reverse_metric;
static int ett_isis_hello_clv_bfd_enabled;
static int ett_isis_hello_clv_ipv6_glb_int_addr;
static int ett_isis_hello_reverse_metric_flags;

static expert_field ei_isis_hello_short_pdu;
static expert_field ei_isis_hello_long_pdu;
static expert_field ei_isis_hello_bad_checksum;
static expert_field ei_isis_hello_authentication;
static expert_field ei_isis_hello_subtlv;
static expert_field ei_isis_hello_short_clv;
static expert_field ei_isis_hello_clv_mt;
static expert_field ei_isis_hello_clv_unknown;

static const value_string isis_hello_circuit_type_vals[] = {
    { ISIS_HELLO_TYPE_RESERVED,    "Reserved 0 (discard PDU)"},
    { ISIS_HELLO_TYPE_LEVEL_1,    "Level 1 only"},
    { ISIS_HELLO_TYPE_LEVEL_2,    "Level 2 only"},
    { ISIS_HELLO_TYPE_LEVEL_12,    "Level 1 and 2"},
    { 0,        NULL} };

extern const range_string mtid_strings[];

static void
dissect_hello_mt_port_cap_spb_mcid_clv(tvbuff_t *tvb, packet_info* pinfo,
        proto_tree *tree, int offset, int subtype, int sublen)
{
    const int MCID_LEN = 51;
    const int SUBLEN   = 2 * MCID_LEN;
    proto_tree *subtree;

    if (sublen != SUBLEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_hello_short_clv, tvb, offset, -1,
                                     "Short SPB MCID TLV (%d vs %d)", sublen, SUBLEN);
        return;
    }


    subtree = proto_tree_add_subtree_format( tree, tvb, offset-2, sublen+2, ett_isis_hello_clv_mt_port_cap_spb_mcid, NULL,
                                "SPB MCID: Type: 0x%02x, Length: %d", subtype, sublen);

    /* MCID: */
    proto_tree_add_item(subtree, hf_isis_hello_mcid, tvb, offset, MCID_LEN, ENC_NA);
    offset += MCID_LEN;

    /* Aux MCID: */
    proto_tree_add_item(subtree, hf_isis_hello_aux_mcid, tvb, offset, MCID_LEN, ENC_NA);
    /* offset += MCID_LEN; */
}

static void
dissect_hello_mt_port_cap_spb_digest_clv(tvbuff_t *tvb, packet_info* pinfo,
        proto_tree *tree, int offset, int subtype, int sublen)
{
    const int DIGEST_LEN = 32;
    const int SUBLEN     = 1 + DIGEST_LEN;
    if (sublen != SUBLEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_hello_short_clv, tvb, offset, -1,
                              "Short SPB Digest TLV (%d vs %d)", sublen, SUBLEN);
        return;
    }
    else {
        proto_tree *subtree;

        subtree = proto_tree_add_subtree_format( tree, tvb, offset-2, sublen+2, ett_isis_hello_clv_mt_port_cap_spb_digest, NULL,
                                  "SPB Digest: Type: 0x%02x, Length: %d", subtype, sublen);

        proto_tree_add_item( subtree, hf_isis_hello_digest_v, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item( subtree, hf_isis_hello_digest_a, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item( subtree, hf_isis_hello_digest_d, tvb, offset, 1, ENC_BIG_ENDIAN);
        ++offset;

        /* Digest: */
        proto_tree_add_item(subtree, hf_isis_hello_digest, tvb, offset, DIGEST_LEN, ENC_NA);
        /* offset += DIGEST_LEN; */
    }
}

static void
dissect_hello_mt_port_cap_spb_bvid_tuples_clv(tvbuff_t *tvb, packet_info* pinfo,
        proto_tree *tree, int offset, int subtype, int sublen)
{
    proto_tree *subtree;
    int subofs = offset;

    subtree = proto_tree_add_subtree_format( tree, tvb, offset-2, sublen+2, ett_isis_hello_clv_mt_port_cap_spb_bvid_tuples, NULL,
                              "SPB Base Vlan Identifiers: Type: 0x%02x, Length: %d", subtype, sublen);

    while (sublen > 0) {
        if (sublen < 6) {
            proto_tree_add_expert_format(tree, pinfo, &ei_isis_hello_short_clv, tvb, offset, -1,
                                  "Short SPB BVID header entry (%d vs %d)", sublen, 6);
            return;
        }
        else {
            proto_tree_add_item( subtree, hf_isis_hello_ect, tvb, subofs, 4, ENC_NA);
            proto_tree_add_item( subtree, hf_isis_hello_bvid, tvb, subofs+4, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item( subtree, hf_isis_hello_bvid_u, tvb, subofs+4, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item( subtree, hf_isis_hello_bvid_m, tvb, subofs+4, 2, ENC_BIG_ENDIAN);
        }
        sublen -= 6;
        subofs += 6;
    }
}

static void
dissect_hello_mt_port_cap_vlan_flags_clv(tvbuff_t *tvb, packet_info* pinfo _U_,
        proto_tree *tree, int offset, int subtype, int sublen)
{
    proto_tree *subtree;

    subtree = proto_tree_add_subtree_format( tree, tvb, offset-2, sublen+2, ett_isis_hello_clv_mt_port_cap_vlan_flags, NULL,
                                "Special VLANs and Flags (t=%u, l=%u)", subtype, sublen);

    proto_tree_add_item(subtree, hf_isis_hello_vlan_flags_port_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(subtree, hf_isis_hello_vlan_flags_nickname, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(subtree, hf_isis_hello_vlan_flags_af, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_isis_hello_vlan_flags_ac, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_isis_hello_vlan_flags_vm, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_isis_hello_vlan_flags_by, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_isis_hello_vlan_flags_outer_vlan, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(subtree, hf_isis_hello_vlan_flags_tr, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_isis_hello_vlan_flags_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_isis_hello_vlan_flags_designated_vlan, tvb, offset, 2, ENC_BIG_ENDIAN);

}

static void
parse_vlan_bitmap(proto_item *item, tvbuff_t *tvb, unsigned vlan, int offset, int sublen)
{
    int range=0, next=0;
    uint8_t mask, bitmap, i;

    while (sublen>0) {

        bitmap = tvb_get_uint8(tvb, offset);
        mask = 0x80;

        for (i=0; i<8; i++) {

           if (bitmap & mask) {

               if (range==0) {
                   proto_item_append_text(item, "%s%u", next++ ? ", " : "", vlan);
               }
               range++;

           } else {

               if (range>1) {
                   proto_item_append_text(item, "-%u", vlan-1);
               }
               range=0;

           }
           vlan++;
           mask>>=1;
        }
        offset++;
        sublen--;
    }

    if (range>1) {
        proto_item_append_text(item, "-%u", vlan-1);
    }
}


static void
dissect_hello_mt_port_cap_enabled_vlans_clv(tvbuff_t *tvb, packet_info* pinfo _U_,
        proto_tree *tree, int offset, int subtype, int sublen)
{
    proto_tree *subtree;
    proto_item *item;
    unsigned vlan;

    subtree = proto_tree_add_subtree_format( tree, tvb, offset-2, sublen+2, ett_isis_hello_clv_mt_port_cap_enabled_vlans, NULL,
                                "Enabled-VLANs (t=%u, l=%u)", subtype, sublen);

    vlan = tvb_get_ntohs(tvb, offset) & 0xfff;
    offset+=2;
    sublen-=2;

    item = proto_tree_add_string(subtree, hf_isis_hello_enabled_vlans, tvb, offset, sublen, "");

    parse_vlan_bitmap(item, tvb, vlan, offset, sublen);
}

static void
dissect_hello_mt_port_cap_appointedfwrdrs_clv(tvbuff_t *tvb, packet_info* pinfo _U_,
        proto_tree *tree, int offset, int subtype, int sublen)
{
    proto_tree *subtree;

    subtree = proto_tree_add_subtree_format( tree, tvb, offset-2, sublen+2, ett_isis_hello_clv_mt_port_cap_appointedfwrdrs, NULL,
                                "Appointed Forwarders (t=%u, l=%u)", subtype, sublen);

    while (sublen>=6) {
        proto_tree_add_item(subtree, hf_isis_hello_af_nickname, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_isis_hello_af_start_vlan, tvb, offset+2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_isis_hello_af_end_vlan, tvb, offset+4, 2, ENC_BIG_ENDIAN);

        offset += 6;
        sublen -=6;
    }
}

static void
dissect_hello_mt_port_cap_port_trill_ver_clv(tvbuff_t *tvb, packet_info* pinfo _U_,
        proto_tree *tree, int offset, int subtype, int sublen)
{
    proto_tree *subtree;

    subtree = proto_tree_add_subtree_format( tree, tvb, offset-2, sublen+2, ett_isis_hello_clv_mt_port_cap_port_trill_ver, NULL,
                                "Port TRILL Version (t=%u, l=%u)", subtype, sublen);

    proto_tree_add_item(subtree, hf_isis_hello_trill_version, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    proto_tree_add_item(subtree, hf_isis_hello_trill_hello_reduction, tvb, offset, 4, ENC_NA);
    proto_tree_add_item(subtree, hf_isis_hello_trill_unassigned_1, tvb, offset, 4, ENC_NA);
    proto_tree_add_item(subtree, hf_isis_hello_trill_hop_by_hop_flags, tvb, offset, 4, ENC_NA);
    proto_tree_add_item(subtree, hf_isis_hello_trill_unassigned_2, tvb, offset, 4, ENC_NA);
}

static void
dissect_hello_mt_port_cap_vlans_appointed_clv(tvbuff_t *tvb, packet_info* pinfo _U_,
        proto_tree *tree, int offset, int subtype, int sublen)
{
    proto_tree *subtree;
    proto_item *item;
    unsigned vlan;

    subtree = proto_tree_add_subtree_format( tree, tvb, offset-2, sublen+2, ett_isis_hello_clv_mt_port_cap_vlans_appointed, NULL,
                                "Appointed VLANs (t=%u, l=%u)", subtype, sublen);

    vlan = tvb_get_ntohs(tvb, offset) & 0xfff;
    offset+=2;
    sublen-=2;

    item = proto_tree_add_string(subtree, hf_isis_hello_appointed_vlans, tvb, offset, sublen, "");

    parse_vlan_bitmap(item, tvb, vlan, offset, sublen);
}

static void
dissect_hello_mt_port_cap_clv(tvbuff_t *tvb, packet_info* pinfo,
        proto_tree *tree, int offset, isis_data_t *isis _U_, int length)
{
    if (length >= 2) {
        /* mtid */
        proto_tree_add_item(tree, hf_isis_hello_mtid, tvb, offset, 2, ENC_BIG_ENDIAN);
        length -= 2;
        offset += 2;
        while (length >= 2) {
            uint8_t subtype   = tvb_get_uint8(tvb, offset);
            uint8_t subtlvlen = tvb_get_uint8(tvb, offset+1);
            length -= 2;
            offset += 2;
            if (subtlvlen > length) {
                proto_tree_add_expert_format(tree, pinfo, &ei_isis_hello_short_clv, tvb, offset, -1,
                                      "Short type %d TLV (%d vs %d)", subtype, subtlvlen, length);
                return;
            }
            switch(subtype)
            {
            case 1:  /* TRILL Special VLANs and Flags */
                dissect_hello_mt_port_cap_vlan_flags_clv(tvb, pinfo, tree, offset, subtype, subtlvlen);
                break;
            case 2:  /* TRILL Enabled VLANs */
                dissect_hello_mt_port_cap_enabled_vlans_clv(tvb, pinfo, tree, offset, subtype, subtlvlen);
                break;
            case 3:  /* TRILL Appointed Forwarders */
                dissect_hello_mt_port_cap_appointedfwrdrs_clv(tvb, pinfo, tree, offset, subtype, subtlvlen);
                break;
            case 4:  /* SPB MCID */
                dissect_hello_mt_port_cap_spb_mcid_clv(tvb, pinfo, tree, offset, subtype, subtlvlen);
                break;
            case 5:  /* SPB Digest */
                dissect_hello_mt_port_cap_spb_digest_clv(tvb, pinfo, tree, offset, subtype, subtlvlen);
                break;
            case 6:  /* SPB BVID Tuples */
                dissect_hello_mt_port_cap_spb_bvid_tuples_clv(tvb, pinfo, tree, offset, subtype, subtlvlen);
                break;
            case 7:  /* Port TRILL Version */
                dissect_hello_mt_port_cap_port_trill_ver_clv(tvb, pinfo, tree, offset, subtype, subtlvlen);
                break;
            case 8:  /* TRILL VLANs Appointed */
                dissect_hello_mt_port_cap_vlans_appointed_clv(tvb, pinfo, tree, offset, subtype, subtlvlen);
                break;
            default:
                proto_tree_add_expert_format(tree, pinfo, &ei_isis_hello_subtlv, tvb, offset-2, subtlvlen+2,
                         "Unknown Sub-TLV: Type: %d, Length: %d", subtype, subtlvlen );
            }
            length -= subtlvlen;
            offset += subtlvlen;
        }
    }
}

/*
 * The Restart CLV is documented in RFC 3847 (Restart Signaling for
 * Intermediate System to Intermediate System).  The CLV looks like this
 *
 *  Type   211
 *  Length # of octets in the value field (1 to (3 + ID Length))
 *  Value
 *
 *                                    No. of octets
 *     +-----------------------+
 *     |   Flags               |     1
 *     +-----------------------+
 *     | Remaining Time        |     2
 *     +-----------------------+
 *     | Restarting Neighbor ID|     ID Length
 *     +-----------------------+
 *
 *   Flags (1 octet)
 *
 *      0  1  2  3  4  5  6  7
 *     +--+--+--+--+--+--+--+--+
 *     |  Reserved    |SA|RA|RR|
 *     +--+--+--+--+--+--+--+--+
 *
 *     RR - Restart Request
 *     RA - Restart Acknowledgement
 *     SA - Suppress adjacency advertisement
 *
 * The Remaining Time and Restarting Neighbor ID fields are only required when
 * the RA flag is set.  The Flags field is always required.
 *
 */
/*
 * Name: dissect_hello_restart_clv()
 *
 * Description:
 *    Decode for a restart clv - only found in IIHs
 *      hence no call in the common clv dissector
 *
 */

static void
dissect_hello_restart_clv(tvbuff_t *tvb, packet_info* pinfo _U_,
        proto_tree *tree, int offset, isis_data_t *isis, int length)
{
    int restart_options=0;
    proto_item *hold_time_item;

    if (length >= 1) {
        static int * const flags[] = {
            &hf_isis_hello_clv_restart_flags_sa,
            &hf_isis_hello_clv_restart_flags_ra,
            &hf_isis_hello_clv_restart_flags_rr,
            NULL
        };

        restart_options = tvb_get_uint8(tvb, offset);
        proto_tree_add_bitmask_with_flags(tree, tvb, offset, hf_isis_hello_clv_restart_flags, ett_isis_hello_clv_restart_flags, flags, ENC_NA, BMT_NO_FALSE|BMT_NO_TFS);
    }

    /* The Remaining Time field should only be present if the RA flag is
     * set
     */
    if (length >= 3 && ISIS_MASK_RESTART_RA(restart_options)) {
        hold_time_item = proto_tree_add_item( tree, hf_isis_hello_clv_restart_remain_time,
            tvb, offset+1, 2, ENC_BIG_ENDIAN );
        proto_item_append_text( hold_time_item, "s" );
    }

    /* The Restarting Neighbor ID should only be present if the RA flag is
     * set.
     */
    if (length >= 3 + isis->system_id_len && ISIS_MASK_RESTART_RA(restart_options)) {
        proto_tree_add_item( tree, hf_isis_hello_clv_restart_neighbor, tvb, offset+3, isis->system_id_len, ENC_NA);
    }
}

/*
 * Name: dissect_hello_nlpid_clv()
 *
 * Description:
 *    Decode for a hello packets NLPID clv.  Calls into the
 *    clv common one.
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : proto tree to build on (may be null)
 *    int : current offset into packet data
 *    int : length of IDs in packet.
 *    int : length of this clv
 *
 * Output:
 *    void, will modify proto_tree if not null.
 */
static void
dissect_hello_nlpid_clv(tvbuff_t *tvb, packet_info* pinfo _U_,
    proto_tree *tree, int offset, isis_data_t *isis _U_, int length)
{
    isis_dissect_nlpid_clv(tvb, tree, ett_isis_hello_clv_nlpid_nlpid, hf_isis_hello_clv_nlpid_nlpid, offset, length);
}

/*
 * Name: dissect_hello_mt_clv()
 *
 * Description:
 *    Decode for a hello packets Multi Topology clv.  Calls into the
 *    clv common one.
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : proto tree to build on (may be null)
 *    int : current offset into packet data
 *    int : length of IDs in packet.
 *    int : length of this clv
 *
 * Output:
 *    void, will modify proto_tree if not null.
 */

static void
dissect_hello_mt_clv(tvbuff_t *tvb, packet_info* pinfo,
    proto_tree *tree, int offset, isis_data_t *isis _U_, int length)
{
    isis_dissect_mt_clv(tvb, pinfo, tree, offset, length,
        hf_isis_hello_clv_mt, &ei_isis_hello_clv_mt);
}

/*
 * Name: dissect_hello_ip_int_addr_clv()
 *
 * Description:
 *    Decode for a hello packets ip interface addr clv.  Calls into the
 *    clv common one.
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : proto tree to build on (may be null)
 *    int : current offset into packet data
 *    int : length of IDs in packet.
 *    int : length of this clv
 *
 * Output:
 *    void, will modify proto_tree if not null.
 */
static void
dissect_hello_ip_int_addr_clv(tvbuff_t *tvb, packet_info* pinfo,
    proto_tree *tree, int offset, isis_data_t *isis _U_, int length)
{
    isis_dissect_ip_int_clv(tree, pinfo, tvb, &ei_isis_hello_short_clv,
        offset, length, hf_isis_hello_clv_ipv4_int_addr );
}

/*
 * Name: dissect_hello_ipv6_int_addr_clv()
 *
 * Description:
 *    Decode for a hello packets ipv6 interface addr clv.  Calls into the
 *    clv common one.
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : proto tree to build on (may be null)
 *    int : current offset into packet data
 *    int : length of IDs in packet.
 *    int : length of this clv
 *
 * Output:
 *    void, will modify proto_tree if not null.
 */
static void
dissect_hello_ipv6_int_addr_clv(tvbuff_t *tvb, packet_info* pinfo,
    proto_tree *tree, int offset, isis_data_t *isis _U_, int length)
{
    isis_dissect_ipv6_int_clv(tree, pinfo, tvb, &ei_isis_hello_short_clv,
        offset, length, hf_isis_hello_clv_ipv6_int_addr );
}

/*
 * Name: dissect_hello_authentication_clv()
 *
 * Description:
 *    Decode for a hello packets authentication clv.
 *      Calls into the CLV common one.
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : proto tree to build on (may be null)
 *    int : current offset into packet data
 *    int : length of IDs in packet.
 *    int : length of this clv
 *
 * Output:
 *    void, will modify proto_tree if not null.
 */
static void
dissect_hello_authentication_clv(tvbuff_t *tvb, packet_info* pinfo,
    proto_tree *tree, int offset, isis_data_t *isis _U_, int length)
{
    isis_dissect_authentication_clv(tree, pinfo, tvb, hf_isis_hello_authentication, hf_isis_clv_key_id, &ei_isis_hello_authentication, offset, length);
}

/*
 * Name: dissect_hello_ip_authentication_clv()
 *
 * Description:
 *    Decode for a hello packets IP authentication clv.
 *      Calls into the CLV common one.
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : proto tree to build on (may be null)
 *    int : current offset into packet data
 *    int : length of IDs in packet.
 *    int : length of this clv
 *
 * Output:
 *    void, will modify proto_tree if not null.
 */
static void
dissect_hello_ip_authentication_clv(tvbuff_t *tvb, packet_info* pinfo _U_,
    proto_tree *tree, int offset, isis_data_t *isis _U_, int length)
{
    if ( length != 0 ) {
       proto_tree_add_item( tree, hf_isis_hello_clv_ip_authentication, tvb, offset, length, ENC_ASCII);
    }
}

/*
 * Name: dissect_hello_trill_neighbor_clv
 */
static void
dissect_hello_trill_neighbor_clv(tvbuff_t *tvb, packet_info* pinfo _U_,
        proto_tree *tree, int offset, isis_data_t *isis _U_, int length) {

    uint8_t size = (tvb_get_uint8(tvb, offset)) & 0x1f;

    if(size==0)
        size=6;

    proto_tree_add_item(tree, hf_isis_hello_trill_neighbor_sf, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_isis_hello_trill_neighbor_lf, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_isis_hello_trill_neighbor_size, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    length--;

    while(length>=(size+3)) {
        proto_tree_add_item(tree, hf_isis_hello_trill_neighbor_ff, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_isis_hello_trill_neighbor_of, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_isis_hello_trill_neighbor_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);

        offset++;
        length--;

        proto_tree_add_item(tree, hf_isis_hello_trill_neighbor_mtu, tvb, offset, 2, ENC_BIG_ENDIAN);

        offset += 2;
        length -= 2;

        proto_tree_add_item(tree, hf_isis_hello_trill_neighbor_snpa, tvb, offset, 6, ENC_NA);

        offset += 6;
        length -= 6;
    }
}

/*
 * Name: dissect_hello_reverse_metric_clv
 */
static void
dissect_hello_reverse_metric_clv(tvbuff_t *tvb, packet_info* pinfo _U_,
        proto_tree *tree, int offset, isis_data_t *isis _U_, int length _U_) {

    uint32_t sub_length;

    static int * const flags[] = {
        &hf_isis_hello_reverse_metric_flag_reserved,
        &hf_isis_hello_reverse_metric_flag_u,
        &hf_isis_hello_reverse_metric_flag_w,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_isis_hello_reverse_metric_flags, ett_isis_hello_reverse_metric_flags, flags, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_isis_hello_reverse_metric_metric, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;
    proto_tree_add_item_ret_uint(tree, hf_isis_hello_reverse_metric_sub_length, tvb, offset, 1, ENC_BIG_ENDIAN, &sub_length);
    offset += 1;
    if (sub_length > 0) {
        proto_tree_add_item(tree, hf_isis_hello_reverse_metric_sub_data, tvb, offset, sub_length, ENC_NA);
    }
}

/*
 * Name: dissect_hello_bfd_enabled_clv
 *
 * Description:
 *    Decode for a hello packets BFD enabled clv.
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : proto tree to build on (may be null)
 *    int : current offset into packet data
 *    int : length of IDs in packet.
 *    int : length of this clv
 *
 * Output:
 *    void, will modify proto_tree if not null.
 */
static void
dissect_hello_bfd_enabled_clv(tvbuff_t *tvb, packet_info* pinfo _U_,
        proto_tree *tree, int offset, isis_data_t *isis _U_, int length) {

    while (length >= 3) {
        /* mtid */
        proto_tree_add_item(tree, hf_isis_hello_mtid, tvb, offset, 2, ENC_BIG_ENDIAN);
        length -= 2;
        offset += 2;
        /* nlpid */
        proto_tree_add_item(tree, hf_isis_hello_bfd_enabled_nlpid, tvb, offset, 1, ENC_NA);
        length -= 1;
        offset += 1;
    };
}

/*
 * Name: dissect_hello_checksum_clv()
 *
 * Description:
 *      dump and verify the optional checksum in TLV 12
 *
 * Input:
 *      tvbuff_t * : tvbuffer for packet data
 *      proto_tree * : protocol display tree to fill out.  May be NULL
 *      int : offset into packet data where we are.
 *      int : length of clv we are decoding
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */

static void
dissect_hello_checksum_clv(tvbuff_t *tvb, packet_info* pinfo,
        proto_tree *tree, int offset, isis_data_t *isis, int length) {

    uint16_t checksum, cacl_checksum=0;

    if ( length != 2 ) {
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_hello_short_clv, tvb, offset, length,
                                "incorrect checksum length (%u), should be (2)", length );
        return;
    }

    checksum = tvb_get_ntohs(tvb, offset);

    if (checksum == 0) {
        /* No checksum present */
        proto_tree_add_checksum(tree, tvb, offset, hf_isis_hello_checksum, hf_isis_hello_checksum_status, &ei_isis_hello_bad_checksum, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NOT_PRESENT);
    } else {
        if (osi_check_and_get_checksum(tvb, 0, isis->pdu_length, offset, &cacl_checksum)) {
            /* Successfully processed checksum, verify it */
            proto_tree_add_checksum(tree, tvb, offset, hf_isis_hello_checksum, hf_isis_hello_checksum_status, &ei_isis_hello_bad_checksum, pinfo, cacl_checksum, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
        } else {
            /* We didn't capture the entire packet, so we can't verify it */
            proto_tree_add_checksum(tree, tvb, offset, hf_isis_hello_checksum, hf_isis_hello_checksum_status, &ei_isis_hello_bad_checksum, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
        }
    }
}



/*
 * Name: dissect_hello_area_address_clv()
 *
 * Description:
 *    Decode for a hello packets area address clv.
 *      Calls into the CLV common one.
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : proto tree to build on (may be null)
 *    int : current offset into packet data
 *    int : length of IDs in packet.
 *    int : length of this clv
 *
 * Output:
 *    void, will modify proto_tree if not null.
 */
static void
dissect_hello_area_address_clv(tvbuff_t *tvb, packet_info* pinfo _U_,
    proto_tree *tree, int offset, isis_data_t *isis _U_, int length)
{
    isis_dissect_area_address_clv(tree, pinfo, tvb, &ei_isis_hello_short_clv, hf_isis_hello_area_address, offset, length);
}

/*
 * Name: dissect_hello_instance_identifier_clv()
 *
 * Description:
 *    Decode for a hello packets Instance Identifier clv.
 *      Calls into the CLV common one.
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : proto tree to build on (may be null)
 *    int : current offset into packet data
 *    int : length of IDs in packet.
 *    int : length of this clv
 *
 * Output:
 *    void, will modify proto_tree if not null.
 */
static void
dissect_hello_instance_identifier_clv(tvbuff_t *tvb, packet_info* pinfo _U_,
    proto_tree *tree, int offset, isis_data_t *isis _U_, int length)
{
    isis_dissect_instance_identifier_clv(tree, pinfo, tvb, &ei_isis_hello_short_clv, hf_isis_hello_instance_identifier, hf_isis_hello_supported_itid, offset, length);
}

static const value_string adj_state_vals[] = {
    { 0, "Up" },
    { 1, "Initializing" },
    { 2, "Down" },
    { 0, NULL }
};

static void
dissect_hello_ptp_adj_clv(tvbuff_t *tvb, packet_info* pinfo,
        proto_tree *tree, int offset, isis_data_t *isis, int length)
{
    switch(length)
    {
    case 1:
        proto_tree_add_item(tree, hf_isis_hello_adjacency_state, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    case 5:
        proto_tree_add_item(tree, hf_isis_hello_adjacency_state, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_isis_hello_extended_local_circuit_id, tvb, offset+1, 4, ENC_BIG_ENDIAN);
        break;
    case 11:
        proto_tree_add_item(tree, hf_isis_hello_adjacency_state, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_isis_hello_extended_local_circuit_id, tvb, offset+1, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_isis_hello_neighbor_systemid, tvb, offset+5, isis->system_id_len, ENC_NA);
    break;
    case 15:
        proto_tree_add_item(tree, hf_isis_hello_adjacency_state, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_isis_hello_extended_local_circuit_id, tvb, offset+1, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_isis_hello_neighbor_systemid, tvb, offset+5, isis->system_id_len, ENC_NA);
        proto_tree_add_item(tree, hf_isis_hello_neighbor_extended_local_circuit_id, tvb, offset+5+isis->system_id_len, 4, ENC_BIG_ENDIAN);
    break;
    default:
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_hello_short_clv, tvb, offset, -1,
                   "malformed TLV (%d vs 1,5,11,15)", length );
    }
}

/*
 * Name: isis_dissect_is_neighbors_clv()
 *
 * Description:
 *    Take apart a IS neighbor packet.  A neighbor is n 6 byte packets.
 *    (they tend to be an 802.3 MAC address, but it's not required).
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : protocol display tree to fill out.  May be NULL
 *    int : offset into packet data where we are.
 *    int : length of IDs in packet.
 *    int : length of clv we are decoding
 *
 * Output:
 *    void, but we will add to proto tree if !NULL.
 */
static void
dissect_hello_is_neighbors_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
    isis_data_t *isis _U_, int length)
{
    while ( length > 0 ) {
        if (length<6) {
            proto_tree_add_expert_format(tree, pinfo, &ei_isis_hello_short_clv, tvb, offset, -1,
                "short is neighbor (%d vs 6)", length );
            return;
        }
        /*
         * Lets turn the area address into "standard" 0000.0000.etc
         * format string.
         */
        proto_tree_add_item(tree, hf_isis_hello_is_neighbor, tvb, offset, 6, ENC_NA);
        offset += 6;
        length -= 6;
    }
}

/*
 * Name: dissect_hello_padding_clv()
 *
 * Description:
 *    Decode for a hello packet's padding clv.  Padding does nothing,
 *    so we just return.
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : proto tree to build on (may be null)
 *    int : current offset into packet data
 *    int : length of IDs in packet.
 *    int : length of this clv
 *
 * Output:
 *    void
 */
static void
dissect_hello_padding_clv(tvbuff_t *tvb _U_, packet_info* pinfo _U_, proto_tree *tree _U_, int offset _U_,
    isis_data_t *isis _U_, int length _U_)
{
    /* nothing to do here! */
}

/*
 * Name: dissect_hello_ipv6_glb_int_addr_clv()
 *
 * Description:
 *    Decode for a hello packets ipv6 gobal interface addr clv.  Calls into the
 *    clv 233.
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : proto tree to build on (may be null)
 *    int : current offset into packet data
 *    int : length of IDs in packet.
 *    int : length of this clv
 *
 * Output:
 *    void, will modify proto_tree if not null.
 */
static void
dissect_hello_ipv6_glb_int_addr_clv(tvbuff_t *tvb, packet_info* pinfo,
    proto_tree *tree, int offset, isis_data_t *isis _U_, int length)
{
    isis_dissect_ipv6_int_clv(tree, pinfo, tvb, &ei_isis_hello_short_clv,
        offset, length, hf_isis_hello_clv_ipv6_glb_int_addr );
}
static const isis_clv_handle_t clv_l1_hello_opts[] = {
    {
        ISIS_CLV_AREA_ADDRESS,
        "Area address(es)",
        &ett_isis_hello_clv_area_addr,
        dissect_hello_area_address_clv
    },
    {
        ISIS_CLV_IS_NEIGHBORS,
        "IS Neighbor(s)",
        &ett_isis_hello_clv_is_neighbors,
        dissect_hello_is_neighbors_clv
    },
    {
        ISIS_CLV_INSTANCE_IDENTIFIER,
        "Instance Identifier",
        &ett_isis_hello_clv_instance_identifier,
        dissect_hello_instance_identifier_clv
    },
    {
        ISIS_CLV_PADDING,
        "Padding",
        &ett_isis_hello_clv_padding,
        dissect_hello_padding_clv
    },
    {
        ISIS_CLV_PROTOCOLS_SUPPORTED,
        "Protocols Supported",
        &ett_isis_hello_clv_nlpid,
        dissect_hello_nlpid_clv
    },
    {
        ISIS_CLV_IP_ADDR,
        "IP Interface address(es)",
        &ett_isis_hello_clv_ipv4_int_addr,
        dissect_hello_ip_int_addr_clv
    },
    {
        ISIS_CLV_IP6_ADDR,
        "IPv6 Interface address(es)",
        &ett_isis_hello_clv_ipv6_int_addr,
        dissect_hello_ipv6_int_addr_clv
    },
    {
        ISIS_CLV_RESTART,
        "Restart Signaling",
        &ett_isis_hello_clv_restart,
        dissect_hello_restart_clv
    },
    {
        ISIS_CLV_AUTHENTICATION,
        "Authentication",
        &ett_isis_hello_clv_authentication,
        dissect_hello_authentication_clv
    },
    {
        ISIS_CLV_IP_AUTHENTICATION,
        "IP Authentication",
        &ett_isis_hello_clv_ip_authentication,
        dissect_hello_ip_authentication_clv
    },
    {
        ISIS_CLV_MT_PORT_CAP,
        "MT Port Capability",
        &ett_isis_hello_clv_mt_port_cap,
        dissect_hello_mt_port_cap_clv
    },
    {
        ISIS_CLV_MT_SUPPORTED,
        "Multi Topology",
        &ett_isis_hello_clv_mt,
        dissect_hello_mt_clv
    },
    {
        ISIS_CLV_TRILL_NEIGHBOR,
        "TRILL Neighbor",
        &ett_isis_hello_clv_trill_neighbor,
        dissect_hello_trill_neighbor_clv
    },
    {
        ISIS_CLV_CHECKSUM,
        "Checksum",
        &ett_isis_hello_clv_checksum,
        dissect_hello_checksum_clv
    },
    {
        ISIS_CLV_IPV6_GBL_INT_ADDR,
        "IPv6 Global Interface Address",
        &ett_isis_hello_clv_ipv6_glb_int_addr,
        dissect_hello_ipv6_glb_int_addr_clv
    },
    {
        ISIS_CLV_REVERSE_METRIC,
        "Reverse Metric",
        &ett_isis_hello_clv_reverse_metric,
        dissect_hello_reverse_metric_clv
    },
    {
        ISIS_CLV_BFD_ENABLED,
        "BFD Enabled",
        &ett_isis_hello_clv_bfd_enabled,
        dissect_hello_bfd_enabled_clv
    },
    {
        0,
        "",
        NULL,
        NULL
    }
};

static const isis_clv_handle_t clv_l2_hello_opts[] = {
    {
        ISIS_CLV_AREA_ADDRESS,
        "Area address(es)",
        &ett_isis_hello_clv_area_addr,
        dissect_hello_area_address_clv
    },
    {
        ISIS_CLV_IS_NEIGHBORS,
        "IS Neighbor(s)",
        &ett_isis_hello_clv_is_neighbors,
        dissect_hello_is_neighbors_clv
    },
    {
        ISIS_CLV_INSTANCE_IDENTIFIER,
        "Instance Identifier",
        &ett_isis_hello_clv_instance_identifier,
        dissect_hello_instance_identifier_clv
    },
    {
        ISIS_CLV_PADDING,
        "Padding",
        &ett_isis_hello_clv_padding,
        dissect_hello_padding_clv
    },
    {
        ISIS_CLV_PROTOCOLS_SUPPORTED,
        "Protocols Supported",
        &ett_isis_hello_clv_nlpid,
        dissect_hello_nlpid_clv
    },
    {
        ISIS_CLV_IP_ADDR,
        "IP Interface address(es)",
        &ett_isis_hello_clv_ipv4_int_addr,
        dissect_hello_ip_int_addr_clv
    },
    {
        ISIS_CLV_IP6_ADDR,
        "IPv6 Interface address(es)",
        &ett_isis_hello_clv_ipv6_int_addr,
        dissect_hello_ipv6_int_addr_clv
    },
    {
        ISIS_CLV_AUTHENTICATION,
        "Authentication",
        &ett_isis_hello_clv_authentication,
        dissect_hello_authentication_clv
    },
    {
        ISIS_CLV_IP_AUTHENTICATION,
        "IP Authentication",
        &ett_isis_hello_clv_ip_authentication,
        dissect_hello_ip_authentication_clv
    },
    {
        ISIS_CLV_RESTART,
        "Restart Signaling",
        &ett_isis_hello_clv_restart,
        dissect_hello_restart_clv
    },
    {
        ISIS_CLV_MT_SUPPORTED,
        "Multi Topology",
        &ett_isis_hello_clv_mt,
        dissect_hello_mt_clv
    },
    {
        ISIS_CLV_CHECKSUM,
        "Checksum",
        &ett_isis_hello_clv_checksum,
        dissect_hello_checksum_clv
    },
    {
        ISIS_CLV_IPV6_GBL_INT_ADDR,
        "IPv6 Global Interface Address",
        &ett_isis_hello_clv_ipv6_glb_int_addr,
        dissect_hello_ipv6_glb_int_addr_clv
    },
    {
        ISIS_CLV_BFD_ENABLED,
        "BFD Enabled",
        &ett_isis_hello_clv_bfd_enabled,
        dissect_hello_bfd_enabled_clv
    },
    {
        0,
        "",
        NULL,
        NULL
    }
};

static const isis_clv_handle_t clv_ptp_hello_opts[] = {
    {
        ISIS_CLV_AREA_ADDRESS,
        "Area address(es)",
        &ett_isis_hello_clv_area_addr,
        dissect_hello_area_address_clv
    },
    {
        ISIS_CLV_INSTANCE_IDENTIFIER,
        "Instance Identifier",
        &ett_isis_hello_clv_instance_identifier,
        dissect_hello_instance_identifier_clv
    },
    {
        ISIS_CLV_PADDING,
        "Padding",
        &ett_isis_hello_clv_padding,
        dissect_hello_padding_clv
    },
    {
        ISIS_CLV_PROTOCOLS_SUPPORTED,
        "Protocols Supported",
        &ett_isis_hello_clv_nlpid,
        dissect_hello_nlpid_clv
    },
    {
        ISIS_CLV_IP_ADDR,
        "IP Interface address(es)",
        &ett_isis_hello_clv_ipv4_int_addr,
        dissect_hello_ip_int_addr_clv
    },
    {
        ISIS_CLV_IP6_ADDR,
        "IPv6 Interface address(es)",
        &ett_isis_hello_clv_ipv6_int_addr,
        dissect_hello_ipv6_int_addr_clv
    },
    {
        ISIS_CLV_AUTHENTICATION,
        "Authentication",
        &ett_isis_hello_clv_authentication,
        dissect_hello_authentication_clv
    },
    {
        ISIS_CLV_IP_AUTHENTICATION,
        "IP Authentication",
        &ett_isis_hello_clv_ip_authentication,
        dissect_hello_ip_authentication_clv
    },
    {
        ISIS_CLV_MT_PORT_CAP,
        "MT Port Capability",
        &ett_isis_hello_clv_mt_port_cap,
        dissect_hello_mt_port_cap_clv
    },
    {
        ISIS_CLV_RESTART,
        "Restart Signaling",
        &ett_isis_hello_clv_restart,
        dissect_hello_restart_clv
    },
    {
        ISIS_CLV_PTP_ADJ_STATE,
        "Point-to-point Adjacency State",
        &ett_isis_hello_clv_ptp_adj,
        dissect_hello_ptp_adj_clv
    },
    {
        ISIS_CLV_MT_SUPPORTED,
        "Multi Topology",
        &ett_isis_hello_clv_mt,
        dissect_hello_mt_clv
    },
    {
        ISIS_CLV_CHECKSUM,
        "Checksum",
        &ett_isis_hello_clv_checksum,
        dissect_hello_checksum_clv
    },
    {
        ISIS_CLV_IPV6_GBL_INT_ADDR,
        "IPv6 Global Interface Address",
        &ett_isis_hello_clv_ipv6_glb_int_addr,
        dissect_hello_ipv6_glb_int_addr_clv
    },
    {
        ISIS_CLV_BFD_ENABLED,
        "BFD Enabled",
        &ett_isis_hello_clv_bfd_enabled,
        dissect_hello_bfd_enabled_clv
    },
    {
        0,
        "",
        NULL,
        NULL
    }
};

/*
 * Name: isis_dissect_isis_hello()
 *
 * Description:
 *    This procedure rips apart the various types of ISIS hellos.  L1H and
 *    L2H's are identical for the most part, while the PTP hello has
 *    a shorter header.
 */
static void
dissect_isis_hello(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
    const isis_clv_handle_t *opts, isis_data_t *isis)
{
    proto_item    *ti;
    proto_tree    *hello_tree;
    uint16_t       pdu_length;
    bool           pdu_length_too_short = false;

    /*
     * We are passed a tvbuff for the entire ISIS PDU, because some ISIS
     * PDUs may contain a checksum CLV, and that's a checksum covering
     * the entire PDU.  Skip the part of the header that's already been
     * dissected.
     */
    offset += 8;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISIS HELLO");

    ti = proto_tree_add_item(tree, proto_isis_hello, tvb, offset, -1, ENC_NA);
    hello_tree = proto_item_add_subtree(ti, ett_isis_hello);

    if (isis->header_length < 8 + 1) {
        /* Not large enough to include the part of the header that
           we dissect here. */
        expert_add_info(pinfo, isis->header_length_item, isis->ei_bad_header_length);
        return;
    }
    proto_tree_add_item(hello_tree, hf_isis_hello_circuit, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(hello_tree, hf_isis_hello_circuit_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (isis->header_length < 8 + 1 + isis->system_id_len) {
        /* Not large enough to include the part of the header that
           we dissect here. */
        expert_add_info(pinfo, isis->header_length_item, isis->ei_bad_header_length);
        return;
    }
    proto_tree_add_item(hello_tree, hf_isis_hello_source_id, tvb, offset, isis->system_id_len, ENC_NA);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", System-ID: %s", tvb_print_system_id( pinfo->pool, tvb, offset, isis->system_id_len ));
    offset += isis->system_id_len;

    if (isis->header_length < 8 + 1 + isis->system_id_len + 2) {
        /* Not large enough to include the part of the header that
           we dissect here. */
        expert_add_info(pinfo, isis->header_length_item, isis->ei_bad_header_length);
        return;
    }
    proto_tree_add_item(hello_tree, hf_isis_hello_holding_timer, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (isis->header_length < 8 + 1 + isis->system_id_len + 2 + 2) {
        /* Not large enough to include the part of the header that
           we dissect here. */
        expert_add_info(pinfo, isis->header_length_item, isis->ei_bad_header_length);
        return;
    }
    pdu_length = tvb_get_ntohs(tvb, offset);
    ti = proto_tree_add_uint(hello_tree, hf_isis_hello_pdu_length, tvb,
                             offset, 2, pdu_length);
    if (pdu_length < isis->header_length) {
        expert_add_info(pinfo, ti, &ei_isis_hello_short_pdu);
        pdu_length_too_short = true;
    } else if (pdu_length > tvb_reported_length(tvb) + isis->header_length) {
        expert_add_info(pinfo, ti, &ei_isis_hello_long_pdu);
    }
    offset += 2;

    if (opts == clv_ptp_hello_opts) {
        if (isis->header_length < 8 + 1 + isis->system_id_len + 2 + 2 + 1) {
            /* Not large enough to include the part of the header that
               we dissect here. */
            expert_add_info(pinfo, isis->header_length_item, isis->ei_bad_header_length);
            return;
        }
        proto_tree_add_item(hello_tree, hf_isis_hello_local_circuit_id, tvb,
                         offset, 1, ENC_BIG_ENDIAN );
        offset += 1;
    } else {
        if (isis->header_length < 8 + 1 + isis->system_id_len + 2 + 2 + 1) {
            /* Not large enough to include the part of the header that
               we dissect here. */
            expert_add_info(pinfo, isis->header_length_item, isis->ei_bad_header_length);
            return;
        }
        proto_tree_add_item(hello_tree, hf_isis_hello_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(hello_tree, hf_isis_hello_priority_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        if (isis->header_length < 8 + 1 + isis->system_id_len + 2 + 2 + 1 + isis->system_id_len + 1) {
            /* Not large enough to include the part of the header that
               we dissect here. */
            expert_add_info(pinfo, isis->header_length_item, isis->ei_bad_header_length);
            return;
        }
        proto_tree_add_item(hello_tree, hf_isis_hello_lan_id, tvb, offset, isis->system_id_len + 1, ENC_NA);
        offset += isis->system_id_len + 1;
    }

    if (pdu_length_too_short) {
        return;
    }
    /*
     * Now, we need to decode our CLVs.  We need to pass in
     * our list of valid ones!
     */
    isis->pdu_length = pdu_length;
    isis_dissect_clvs(tvb, pinfo, hello_tree, offset,
            opts, &ei_isis_hello_short_clv, isis, ett_isis_hello_clv_unknown,
            hf_isis_hello_clv_type, hf_isis_hello_clv_length,
            &ei_isis_hello_clv_unknown);
}


static int
dissect_isis_l1_hello(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    isis_data_t* isis = (isis_data_t*)data;
    dissect_isis_hello(tvb, pinfo, tree, 0, clv_l1_hello_opts, isis);
    return tvb_captured_length(tvb);
}

static int
dissect_isis_l2_hello(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    isis_data_t* isis = (isis_data_t*)data;
    dissect_isis_hello(tvb, pinfo, tree, 0, clv_l2_hello_opts, isis);
    return tvb_captured_length(tvb);
}

static int
dissect_isis_ptp_hello(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    isis_data_t* isis = (isis_data_t*)data;
    dissect_isis_hello(tvb, pinfo, tree, 0, clv_ptp_hello_opts, isis);
    return tvb_captured_length(tvb);
}

/*
 * Name: isis_register_hello()
 *
 * Description:
 *    Register our protocol sub-sets with protocol manager.
 *
 * Input:
 *    int : protocol index for the ISIS protocol
 *
 * Output:
 *    void
 */
void
proto_register_isis_hello(void)
{
    static hf_register_info hf[] = {
        { &hf_isis_hello_circuit,
        { "Circuit type", "isis.hello.circuit_type",
            FT_UINT8, BASE_HEX, VALS(isis_hello_circuit_type_vals), ISIS_HELLO_CTYPE_MASK, NULL, HFILL }},

        { &hf_isis_hello_circuit_reserved,
        { "Reserved", "isis.hello.reserved",
            FT_UINT8, BASE_HEX, NULL, ISIS_HELLO_CT_RESERVED_MASK, NULL, HFILL }},

        { &hf_isis_hello_source_id,
        { "SystemID {Sender of PDU}", "isis.hello.source_id",
            FT_SYSTEM_ID, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_isis_hello_holding_timer,
        { "Holding timer", "isis.hello.holding_timer",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_isis_hello_pdu_length,
        { "PDU length", "isis.hello.pdu_length",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_isis_hello_priority,
         { "Priority", "isis.hello.priority",
            FT_UINT8, BASE_DEC, NULL, ISIS_HELLO_PRIORITY_MASK, NULL, HFILL }},

        { &hf_isis_hello_priority_reserved,
         { "Reserved", "isis.hello.reserved",
            FT_UINT8, BASE_DEC, NULL, ISIS_HELLO_P_RESERVED_MASK, NULL, HFILL }},

        { &hf_isis_hello_lan_id,
        { "SystemID {Designated IS}", "isis.hello.lan_id",
            FT_SYSTEM_ID, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_isis_hello_clv_type,
        { "Type", "isis.hello.clv.type",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_isis_hello_clv_length,
        { "Length", "isis.hello.clv.length",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_isis_hello_local_circuit_id,
        { "Local circuit ID", "isis.hello.local_circuit_id",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_isis_hello_clv_ipv4_int_addr,
        { "IPv4 interface address", "isis.hello.clv_ipv4_int_addr",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_isis_hello_clv_ipv6_int_addr,
        { "IPv6 interface address", "isis.hello.clv_ipv6_int_addr",
            FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},

#if 0
        { &hf_isis_hello_clv_ptp_adj,
        { "Point-to-point Adjacency", "isis.hello.clv_ptp_adj",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
#endif

        { &hf_isis_hello_clv_mt,
        { "MT-ID", "isis.hello.clv_mt",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_isis_hello_clv_restart_flags,
        { "Restart Signaling Flags", "isis.hello.clv_restart_flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_isis_hello_clv_restart_flags_rr,
        { "Restart Request", "isis.hello.clv_restart_flags.rr",
            FT_BOOLEAN, 8, NULL, ISIS_RESTART_RR,
            "When set, the router is beginning a graceful restart", HFILL }},

        { &hf_isis_hello_clv_restart_flags_ra,
        { "Restart Acknowledgment", "isis.hello.clv_restart_flags.ra",
            FT_BOOLEAN, 8, NULL, ISIS_RESTART_RA,
            "When set, the router is willing to enter helper mode", HFILL }},

        { &hf_isis_hello_clv_restart_flags_sa,
        { "Suppress Adjacency", "isis.hello.clv_restart_flags.sa",
            FT_BOOLEAN, 8, NULL, ISIS_RESTART_SA,
            "When set, the router is starting as opposed to restarting", HFILL }},

        { &hf_isis_hello_clv_restart_remain_time,
        { "Remaining holding time", "isis.hello.clv_restart.remain_time",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "How long the helper router will maintain the existing adjacency", HFILL }},

        { &hf_isis_hello_clv_restart_neighbor,
        { "Restarting Neighbor ID", "isis.hello.clv_restart.neighbor",
            FT_SYSTEM_ID, BASE_NONE, NULL, 0x0,
            "The System ID of the restarting neighbor", HFILL }},

      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_isis_hello_mcid, { "MCID", "isis.hello.mcid", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_aux_mcid, { "Aux MCID", "isis.hello.aux_mcid", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_digest, { "Digest", "isis.hello.digest", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_digest_v, { "V", "isis.hello.digest.v", FT_UINT8, BASE_DEC, NULL, 0x10, NULL, HFILL }},
      { &hf_isis_hello_digest_a, { "A", "isis.hello.digest.a", FT_UINT8, BASE_DEC, NULL, 0x0c, NULL, HFILL }},
      { &hf_isis_hello_digest_d, { "D", "isis.hello.digest.d", FT_UINT8, BASE_DEC, NULL, 0x03, NULL, HFILL }},
      { &hf_isis_hello_ect, { "ECT", "isis.hello.ect", FT_BYTES, SEP_DASH, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_bvid, { "BVID", "isis.hello.bvid", FT_UINT16, BASE_HEX_DEC, NULL, 0xFFF0, NULL, HFILL }},
      { &hf_isis_hello_bvid_u, { "U", "isis.hello.bvid.u", FT_UINT16, BASE_HEX_DEC, NULL, 0x0008, NULL, HFILL }},
      { &hf_isis_hello_bvid_m, { "M", "isis.hello.bvid.m", FT_UINT16, BASE_HEX_DEC, NULL, 0x0004, NULL, HFILL }},
      { &hf_isis_hello_area_address, { "Area address", "isis.hello.area_address", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_instance_identifier, { "Instance Identifier", "isis.hello.iid", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_supported_itid, { "Supported ITID", "isis.hello.supported_itid", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_clv_nlpid_nlpid, { "NLPID", "isis.hello.clv_nlpid.nlpid", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_clv_ip_authentication, { "NLPID", "isis.hello.clv_ip_authentication", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_authentication, { "Authentication", "isis.hello.clv_authentication", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_mtid, { "Topology ID", "isis.hello.mtid", FT_UINT16, BASE_DEC|BASE_RANGE_STRING, RVALS(mtid_strings), 0x0fff, NULL, HFILL }},
      { &hf_isis_hello_trill_neighbor_sf, { "Smallest flag", "isis.hello.trill_neighbor.sf", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80, NULL, HFILL }},
      { &hf_isis_hello_trill_neighbor_lf, { "Largest flag", "isis.hello.trill_neighbor.lf", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40, NULL, HFILL }},
      { &hf_isis_hello_trill_neighbor_size, { "SNPA Size", "isis.hello.trill_neighbor.size", FT_UINT8, BASE_DEC, NULL, 0x1f, NULL, HFILL }},
      { &hf_isis_hello_trill_neighbor_ff, { "Failed flag", "isis.hello.trill_neighbor.ff", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80, NULL, HFILL }},
      { &hf_isis_hello_trill_neighbor_of, { "OOMF flag", "isis.hello.trill_neighbor.of", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40, NULL, HFILL }},
      { &hf_isis_hello_trill_neighbor_reserved, { "Reserved", "isis.hello.trill_neighbor.reserved", FT_UINT8, BASE_DEC, NULL, 0x3f, NULL, HFILL }},
      { &hf_isis_hello_trill_neighbor_mtu, { "Tested MTU", "isis.hello.trill_neighbor.mtu", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_trill_neighbor_snpa, { "SNPA", "isis.hello.trill_neighbor.snpa", FT_SYSTEM_ID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_checksum, { "Checksum", "isis.hello.checksum", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_checksum_status, { "Checksum Status", "isis.hello.checksum.status", FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0, NULL, HFILL }},
      { &hf_isis_hello_adjacency_state, { "Adjacency State", "isis.hello.adjacency_state", FT_UINT8, BASE_DEC, VALS(adj_state_vals), 0x0, NULL, HFILL }},
      { &hf_isis_hello_extended_local_circuit_id, { "Extended Local circuit ID", "isis.hello.extended_local_circuit_id", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_neighbor_systemid, { "Neighbor SystemID", "isis.hello.neighbor_systemid", FT_SYSTEM_ID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_neighbor_extended_local_circuit_id, { "Neighbor Extended Local circuit ID", "isis.hello.neighbor_extended_local_circuit_id", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_vlan_flags_port_id, { "Port ID", "isis.hello.vlan_flags.port_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_vlan_flags_nickname, { "Nickname", "isis.hello.vlan_flags.nickname", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_vlan_flags_af, { "Appointed Forwarder", "isis.hello.vlan_flags.af", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x8000, NULL, HFILL }},
      { &hf_isis_hello_vlan_flags_ac, { "Access Port", "isis.hello.vlan_flags.ac", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x4000, NULL, HFILL }},
      { &hf_isis_hello_vlan_flags_vm, { "VLAN Mapping Detected", "isis.hello.vlan_flags.vm", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x2000, NULL, HFILL }},
      { &hf_isis_hello_vlan_flags_by, { "Bypass Pseudonode", "isis.hello.vlan_flags.by", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x1000, NULL, HFILL }},
      { &hf_isis_hello_vlan_flags_outer_vlan, { "Outer VLAN", "isis.hello.vlan_flags.outer_vlan", FT_UINT16, BASE_DEC, NULL, 0x0fff, NULL, HFILL }},
      { &hf_isis_hello_vlan_flags_tr, { "Trunk Port", "isis.hello.vlan_flags.tr", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x8000, NULL, HFILL }},
      { &hf_isis_hello_vlan_flags_reserved, { "Reserved", "isis.hello.vlan_flags.reserved", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x7000, NULL, HFILL }},
      { &hf_isis_hello_vlan_flags_designated_vlan, { "Designated VLAN", "isis.hello.vlan_flags.designated_vlan", FT_UINT16, BASE_DEC, NULL, 0x0fff, NULL, HFILL }},
      { &hf_isis_hello_enabled_vlans, { "Enabled VLANs", "isis.hello.enabled_vlans", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_appointed_vlans, { "Appointed VLANs", "isis.hello.appointed_vlans", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_af_nickname, { "Nickname", "isis.hello.af.nickname", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_af_start_vlan, { "Start VLAN", "isis.hello.af.start_vlan", FT_UINT16, BASE_DEC, NULL, 0x0fff, NULL, HFILL }},
      { &hf_isis_hello_af_end_vlan, { "End VLAN", "isis.hello.af.end_vlan", FT_UINT16, BASE_DEC, NULL, 0x0fff, NULL, HFILL }},
      { &hf_isis_hello_trill_version, { "Maximum version", "isis.hello.trill.maximum_version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_trill_hello_reduction, { "Hello Reduction", "isis.hello.trill.hello_reduction", FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x80000000, NULL, HFILL }},
      { &hf_isis_hello_trill_unassigned_1, { "Unassigned", "isis.hello.trill.unassigned_1", FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x60000000, NULL, HFILL }},
      { &hf_isis_hello_trill_hop_by_hop_flags, { "Hop-by-hop Extended Header Flags", "isis.hello.trill.hop_by_hop_flags", FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x1ffc0000, NULL, HFILL }},
      { &hf_isis_hello_trill_unassigned_2, { "Unassigned", "isis.hello.trill.unassigned_2",FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x0003ffff, NULL, HFILL }},
      { &hf_isis_hello_is_neighbor, { "IS Neighbor", "isis.hello.is_neighbor", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_reverse_metric_flags, { "Flags", "isis.hello.reverse_metric.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_reverse_metric_flag_reserved, { "Reserved", "isis.hello.reverse_metric.flags.reserved", FT_UINT8, BASE_HEX, NULL, 0xFC, NULL, HFILL }},
      { &hf_isis_hello_reverse_metric_flag_u, { "U", "isis.hello.reverse_metric.flags.u", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02, NULL, HFILL }},
      { &hf_isis_hello_reverse_metric_flag_w, { "W", "isis.hello.reverse_metric.flags.w", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01, NULL, HFILL }},
      { &hf_isis_hello_reverse_metric_metric, { "Metric", "isis.hello.reverse_metric.metric", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_reverse_metric_sub_length, { "Sub-TLV length", "isis.hello.reverse_metric.sub_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_reverse_metric_sub_data, { "Sub-TLV data", "isis.hello.reverse_metric.sub_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_bfd_enabled_nlpid, { "NLPID", "isis.hello.bfd_enabled.nlpid", FT_UINT8, BASE_HEX, VALS(nlpid_vals), 0x0, NULL, HFILL }},

      /* rfc6119 */
      { &hf_isis_hello_clv_ipv6_glb_int_addr,
        { "IPv6 Global interface address", "isis.hello.clv_ipv6_glb_int_addr",
            FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    };

    static int *ett[] = {
        &ett_isis_hello,
        &ett_isis_hello_clv_area_addr,
        &ett_isis_hello_clv_instance_identifier,
        &ett_isis_hello_clv_is_neighbors,
        &ett_isis_hello_clv_padding,
        &ett_isis_hello_clv_unknown,
        &ett_isis_hello_clv_nlpid,
        &ett_isis_hello_clv_nlpid_nlpid,
        &ett_isis_hello_clv_authentication,
        &ett_isis_hello_clv_ip_authentication,
        &ett_isis_hello_clv_ipv4_int_addr,
        &ett_isis_hello_clv_ipv6_int_addr,
        &ett_isis_hello_clv_ptp_adj,
        &ett_isis_hello_clv_mt,
        &ett_isis_hello_clv_restart,
        &ett_isis_hello_clv_restart_flags,
        &ett_isis_hello_clv_mt_port_cap,
        &ett_isis_hello_clv_mt_port_cap_spb_mcid,
        &ett_isis_hello_clv_mt_port_cap_spb_digest,
        &ett_isis_hello_clv_mt_port_cap_spb_bvid_tuples,
        &ett_isis_hello_clv_mt_port_cap_vlan_flags,
        &ett_isis_hello_clv_mt_port_cap_enabled_vlans,
        &ett_isis_hello_clv_mt_port_cap_appointedfwrdrs,
        &ett_isis_hello_clv_mt_port_cap_port_trill_ver,
        &ett_isis_hello_clv_mt_port_cap_vlans_appointed,
        &ett_isis_hello_clv_trill_neighbor,
        &ett_isis_hello_clv_checksum,
        &ett_isis_hello_clv_reverse_metric,
        &ett_isis_hello_clv_bfd_enabled,
        &ett_isis_hello_clv_ipv6_glb_int_addr, /* CLV 233, rfc6119 */
        &ett_isis_hello_reverse_metric_flags
    };

    static ei_register_info ei[] = {
        { &ei_isis_hello_short_pdu, { "isis.lsp.hello_pdu", PI_MALFORMED, PI_ERROR, "PDU length less than header length", EXPFILL }},
        { &ei_isis_hello_long_pdu, { "isis.lsp.hello_pdu", PI_MALFORMED, PI_ERROR, "PDU length greater than packet length", EXPFILL }},
        { &ei_isis_hello_bad_checksum, { "isis.hello.bad_checksum", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
        { &ei_isis_hello_subtlv, { "isis.hello.subtlv.unknown", PI_PROTOCOL, PI_WARN, "Unknown Sub-TLV", EXPFILL }},
        { &ei_isis_hello_authentication, { "isis.hello.authentication.unknown", PI_PROTOCOL, PI_WARN, "Unknown authentication type", EXPFILL }},
        { &ei_isis_hello_short_clv, { "isis.hello.short_clv", PI_MALFORMED, PI_ERROR, "Short CLV", EXPFILL }},
        { &ei_isis_hello_clv_mt, { "isis.hello.clv_mt.malformed", PI_MALFORMED, PI_ERROR, "malformed MT-ID", EXPFILL }},
        { &ei_isis_hello_clv_unknown, { "isis.hello.clv.unknown", PI_UNDECODED, PI_NOTE, "Unknown option", EXPFILL }},
    };

    expert_module_t* expert_isis_hello;

    /* Register the protocol name and description */
    proto_isis_hello = proto_register_protocol("ISIS HELLO", "ISIS HELLO", "isis.hello");

    proto_register_field_array(proto_isis_hello, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_isis_hello = expert_register_protocol(proto_isis_hello);
    expert_register_field_array(expert_isis_hello, ei, array_length(ei));
}

void
proto_reg_handoff_isis_hello(void)
{
    dissector_add_uint("isis.type", ISIS_TYPE_L1_HELLO, create_dissector_handle(dissect_isis_l1_hello, proto_isis_hello));
    dissector_add_uint("isis.type", ISIS_TYPE_L2_HELLO, create_dissector_handle(dissect_isis_l2_hello, proto_isis_hello));
    dissector_add_uint("isis.type", ISIS_TYPE_PTP_HELLO, create_dissector_handle(dissect_isis_ptp_hello, proto_isis_hello));
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
