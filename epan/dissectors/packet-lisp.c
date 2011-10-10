/* packet-lisp.c
 * Routines for LISP Control Message dissection
 * Copyright 2011, Lorand Jakab <lj@lispmon.net>
 *
 * $Id$
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <epan/packet.h>
#include <epan/afn.h>
#include <epan/ipv6-utils.h>

#define INET_ADDRLEN        4
#define INET6_ADDRLEN       16

/* See draft-ietf-lisp-11 "Locator/ID Separation Protocol (LISP)" */

#define LISP_CONTROL_PORT   4342

/* LISP Control Message types */
#define LISP_MAP_REQUEST    1
#define LISP_MAP_REPLY      2
#define LISP_MAP_REGISTER   3
#define LISP_MAP_NOTIFY     4
#define LISP_ECM            8

#define LISP_ECM_HEADER_LEN 4

#define LISP_MAP_ACT        0xE0
#define LISP_MAP_AUTH       0x10
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
#define MAP_REP_RESERVED    0x03FFFF

#define MAP_REG_FLAG_P      0x080000
#define MAP_REG_RESERVED    0x07FFFE
#define MAP_REG_FLAG_M      0x000001

#define MAP_NOT_RESERVED    0x0FFFFF

/* Initialize the protocol and registered fields */
static int proto_lisp = -1;
static int hf_lisp_type = -1;
static int hf_lisp_irc = -1;
static int hf_lisp_records = -1;
static int hf_lisp_nonce = -1;

/* Map-Request fields */
static int hf_lisp_mreq_flags_auth = -1;
static int hf_lisp_mreq_flags_mrp = -1;
static int hf_lisp_mreq_flags_probe = -1;
static int hf_lisp_mreq_flags_smr = -1;
static int hf_lisp_mreq_flags_pitr = -1;
static int hf_lisp_mreq_flags_smri = -1;
static int hf_lisp_mreq_res = -1;
static int hf_lisp_mreq_srceid_afi = -1;
static int hf_lisp_mreq_srceid = -1;
static int hf_lisp_mreq_srceidv6 = -1;
static int hf_lisp_mreq_srcitr = -1;
static int hf_lisp_mreq_srcitrv6 = -1;

/* Map-Reply fields */
static int hf_lisp_mrep_flags = -1;
static int hf_lisp_mrep_flags_probe = -1;
static int hf_lisp_mrep_flags_enlr = -1;
static int hf_lisp_mrep_res = -1;

/* Map-Register fields */
static int hf_lisp_mreg_flags = -1;
static int hf_lisp_mreg_flags_pmr = -1;
static int hf_lisp_mreg_flags_wmn = -1;
static int hf_lisp_mreg_res = -1;
static int hf_lisp_mreg_keyid = -1;
static int hf_lisp_mreg_authlen = -1;
static int hf_lisp_mreg_auth = -1;

/* Map-Notify fields */
static int hf_lisp_mnot_res = -1;
static int hf_lisp_mnot_keyid = -1;
static int hf_lisp_mnot_authlen = -1;
static int hf_lisp_mnot_auth = -1;

/* Mapping record fields */
static int hf_lisp_mapping_res = -1;
static int hf_lisp_mapping_ver = -1;

/* Encapsulated Control Message fields */
static int hf_lisp_ecm_res = -1;

/* Initialize the subtree pointers */
static gint ett_lisp = -1;
static gint ett_lisp_mr = -1;
static gint ett_lisp_mapping = -1;
static gint ett_lisp_itr = -1;
static gint ett_lisp_record = -1;

static dissector_handle_t ipv4_handle;
static dissector_handle_t ipv6_handle;
static dissector_handle_t data_handle;

static gboolean encapsulated = FALSE;

const value_string lisp_typevals[] = {
    { LISP_MAP_REQUEST,     "Map-Request" },
    { LISP_MAP_REPLY,       "Map-Reply" },
    { LISP_MAP_REGISTER,    "Map-Register" },
    { LISP_MAP_NOTIFY,      "Map-Notify" },
    { LISP_ECM,             "Encapsulated Control Message" },
    { 0,                    NULL}
};

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
dissect_lisp_locator(tvbuff_t *tvb, packet_info *pinfo, proto_tree *lisp_mapping_tree)
{
    gint offset = 0;
    guint8 prio, weight, m_prio, m_weight;
    guint16 flags, loc_afi;
    guint32 locator_v4;
    struct e_in6_addr locator_v6;
    tvbuff_t *next_tvb;

    prio     = tvb_get_guint8(tvb, offset); offset += 1;
    weight   = tvb_get_guint8(tvb, offset); offset += 1;
    m_prio   = tvb_get_guint8(tvb, offset); offset += 1;
    m_weight = tvb_get_guint8(tvb, offset); offset += 1;
    flags    = tvb_get_ntohs(tvb, offset);  offset += 2;
    loc_afi  = tvb_get_ntohs(tvb, offset);  offset += 2;

    switch (loc_afi) {
        case AFNUM_INET:
            locator_v4 = tvb_get_ipv4(tvb, offset);
            proto_tree_add_text(lisp_mapping_tree, tvb, 0, 8 + INET_ADDRLEN,
                    "%sRLOC: %s%s, %s, Priority/Weight: %d/%d, Multicast Priority/Weight: %d/%d",
                    (flags&LOCAL_BIT_MASK) ? "Local " : "",
                    ip_to_str((guint8 *)&locator_v4),
                    (flags&PROBE_BIT_MASK) ? " (probed)" : "",
                    (flags&REACH_BIT_MASK) ? "Reachable" : "Unreachable",
                    prio, weight, m_prio, m_weight);
            offset += INET_ADDRLEN;
            break;
        case AFNUM_INET6:
            tvb_get_ipv6(tvb, offset, &locator_v6);
            proto_tree_add_text(lisp_mapping_tree, tvb, 0, 8 + INET6_ADDRLEN,
                    "%sRLOC: %s%s, %s, Priority/Weight: %d/%d, Multicast Priority/Weight: %d/%d",
                    (flags&LOCAL_BIT_MASK) ? "Local " : "",
                    ip6_to_str(&locator_v6),
                    (flags&PROBE_BIT_MASK) ? " (probed)" : "",
                    (flags&REACH_BIT_MASK) ? "Reachable" : "Unreachable",
                    prio, weight, m_prio, m_weight);
            offset += INET6_ADDRLEN;
            break;
        default:
            proto_tree_add_text(lisp_mapping_tree, tvb, 0, 2, "Unexpected AFI, cannot decode");
            next_tvb = tvb_new_subset(tvb, offset, -1, -1);
            call_dissector(data_handle, next_tvb, pinfo, lisp_mapping_tree);
    }

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

static int
dissect_lisp_mapping(tvbuff_t *tvb, packet_info *pinfo, proto_tree *lisp_tree, guint8 rec_cnt)
{
    int i;
    gint offset = 0;
    gint mapver_offset = 0;
    guint32 ttl;
    guint8 loc_cnt;
    guint8 prefix_mask, flags, act;
    guint16 prefix_afi;
    guint32 prefix_v4;
    struct e_in6_addr prefix_v6;
    proto_item *tir;
    proto_tree *lisp_mapping_tree;
    tvbuff_t *next_tvb;
    const char *lisp_actions[] = {
        "No-Action",
        "Natively-Forward",
        "Send-Map-Request",
        "Drop",
        "Illegal action value"
    };

    ttl           = tvb_get_ntohl(tvb, offset);  offset += 4;
    loc_cnt       = tvb_get_guint8(tvb, offset); offset += 1;
    prefix_mask   = tvb_get_guint8(tvb, offset); offset += 1;
    flags         = tvb_get_guint8(tvb, offset); offset += 2;
    mapver_offset = offset;                      offset += 2;
    prefix_afi    = tvb_get_ntohs(tvb, offset);  offset += 2;

    act = flags & LISP_MAP_ACT;
    act >>= 5;
    if (act > 3) act = 4;

    switch (prefix_afi) {
        case AFNUM_INET:
            prefix_v4 = tvb_get_ipv4(tvb, offset);
            tir = proto_tree_add_text(lisp_tree, tvb, 0, 12 + INET_ADDRLEN,
                    "EID prefix: %s/%d, TTL: %s, %sAuthoritative, %s",
                    ip_to_str((guint8 *)&prefix_v4), prefix_mask,
                    (ttl == 0xFFFFFFFF) ? "Unlimited" : g_strdup_printf("%d", ttl),
                    (flags&LISP_MAP_AUTH) ? "" : "Not ", lisp_actions[act]);
            offset += INET_ADDRLEN;
            /* Update the INFO column if there is only one record */
            if (rec_cnt == 1)
                col_append_fstr(pinfo->cinfo, COL_INFO, " for %s/%d",
                        ip_to_str((guint8 *)&prefix_v4), prefix_mask);
            break;
        case AFNUM_INET6:
            tvb_get_ipv6(tvb, offset, &prefix_v6);
            tir = proto_tree_add_text(lisp_tree, tvb, 0, 12 + INET6_ADDRLEN,
                    "EID prefix: %s/%d, TTL: %s, %sAuthoritative, %s",
                    ip6_to_str(&prefix_v6), prefix_mask,
                    (ttl == 0xFFFFFFFF) ? "Unlimited" : g_strdup_printf("%d", ttl),
                    (flags&LISP_MAP_AUTH) ? "" : "Not ", lisp_actions[act]);
            offset += INET6_ADDRLEN;
            /* Update the INFO column if there is only one record */
            if (rec_cnt == 1)
                col_append_fstr(pinfo->cinfo, COL_INFO, " for %s/%d",
                        ip6_to_str(&prefix_v6), prefix_mask);
            break;
        default:
            proto_tree_add_text(lisp_tree, tvb, 0, 2, "Unexpected AFI, cannot decode");
            next_tvb = tvb_new_subset(tvb, offset, -1, -1);
            call_dissector(data_handle, next_tvb, pinfo, lisp_tree);
            return offset;
    }

    lisp_mapping_tree = proto_item_add_subtree(tir, ett_lisp_mapping);

    /* Reserved (4 bits) */
    proto_tree_add_item(lisp_mapping_tree, hf_lisp_mapping_res, tvb, mapver_offset, 2, ENC_BIG_ENDIAN);

    /* Map-Version Number (12 bits) */
    proto_tree_add_item(lisp_mapping_tree, hf_lisp_mapping_ver, tvb, mapver_offset, 2, ENC_BIG_ENDIAN);

    /* Locators */
    for(i=0; i < loc_cnt; i++) {
        tvbuff_t *loc_tvb;
        int len = 0;

        loc_tvb = tvb_new_subset(tvb, offset, -1, -1);
        len = dissect_lisp_locator(loc_tvb, pinfo, lisp_mapping_tree);
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
    int i;
    gint offset = 0;
    gboolean mrep = FALSE;
    guint8 flags;
    guint8 itr_rec_cnt = 0;
    guint8 rec_cnt = 0;
    guint16 src_eid_afi;
    struct e_in6_addr e_in6_addr;
    tvbuff_t *next_tvb;

    /* Flags (6 bits)*/
    flags = tvb_get_guint8(tvb, offset);
    mrep = flags & (MAP_REQ_FLAG_M >> 16);
    proto_tree_add_item(lisp_tree, hf_lisp_mreq_flags_auth, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(lisp_tree, hf_lisp_mreq_flags_mrp, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(lisp_tree, hf_lisp_mreq_flags_probe, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(lisp_tree, hf_lisp_mreq_flags_smr, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(lisp_tree, hf_lisp_mreq_flags_pitr, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(lisp_tree, hf_lisp_mreq_flags_smri, tvb, offset, 3, ENC_BIG_ENDIAN);

    /* Reserved bits (9 bits) */
    proto_tree_add_item(lisp_tree, hf_lisp_mreq_res, tvb, offset, 3, ENC_BIG_ENDIAN);

    /* ITR record count (5 bits) */
    itr_rec_cnt = tvb_get_guint8(tvb, offset + 2) & 0x1F;
    proto_tree_add_item(lisp_tree, hf_lisp_irc, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    /* Record count (8 bits) */
    rec_cnt = tvb_get_guint8(tvb, offset);
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
            proto_tree_add_text(lisp_tree, tvb, offset, 0, "(Source EID not present)");
            break;
        case AFNUM_INET:
            proto_tree_add_ipv4(lisp_tree,
                    hf_lisp_mreq_srceid, tvb, offset, INET_ADDRLEN, tvb_get_ipv4(tvb, offset));
            offset += INET_ADDRLEN;
            break;
        case AFNUM_INET6:
            tvb_get_ipv6(tvb, offset, &e_in6_addr);
            proto_tree_add_ipv6(lisp_tree,
                    hf_lisp_mreq_srceidv6, tvb, offset, INET6_ADDRLEN, (guint8 *)&e_in6_addr);
            offset += INET6_ADDRLEN;
            break;
        default:
            proto_tree_add_text(lisp_tree, tvb, offset, 0,
                    "Unexpected Source EID AFI, cannot decode");
            next_tvb = tvb_new_subset(tvb, offset, -1, -1);
            call_dissector(data_handle, next_tvb, pinfo, lisp_tree);
            return;
    }

    /* ITR records */
    for(i=0; i < itr_rec_cnt+1; i++) {
        guint16 itr_afi;
        guint32 itr_rloc_v4;
        struct e_in6_addr itr_rloc_v6;
        proto_item *tir;
        proto_tree *lisp_itr_tree;

        itr_afi = tvb_get_ntohs(tvb, offset);

        switch (itr_afi) {
            case AFNUM_INET:
                itr_rloc_v4 = tvb_get_ipv4(tvb, offset + 2);
                tir = proto_tree_add_text(lisp_tree, tvb, offset, INET_ADDRLEN + 2,
                        "ITR-RLOC %d: %s", i + 1, ip_to_str((guint8 *)&itr_rloc_v4));
                lisp_itr_tree = proto_item_add_subtree(tir, ett_lisp_itr);
                proto_tree_add_text(lisp_itr_tree, tvb, offset, 2, "ITR-RLOC-AFI: %d", itr_afi);
                proto_tree_add_ipv4(lisp_itr_tree, hf_lisp_mreq_srcitr, tvb, offset + 2,
                        INET_ADDRLEN, itr_rloc_v4);
                offset += INET_ADDRLEN + 2;
                break;
            case AFNUM_INET6:
                tvb_get_ipv6(tvb, offset + 2, &itr_rloc_v6);
                tir = proto_tree_add_text(lisp_tree, tvb, offset, INET6_ADDRLEN + 2,
                        "ITR-RLOC %d: %s", i + 1, ip6_to_str(&itr_rloc_v6));
                lisp_itr_tree = proto_item_add_subtree(tir, ett_lisp_itr);
                proto_tree_add_text(lisp_itr_tree, tvb, offset, 2, "ITR-RLOC-AFI: %d", itr_afi);
                proto_tree_add_ipv6(lisp_itr_tree, hf_lisp_mreq_srcitrv6, tvb, offset + 2,
                        INET6_ADDRLEN, (guint8 *)&itr_rloc_v6);
                offset += INET6_ADDRLEN + 2;
                break;
            default:
                proto_tree_add_text(lisp_tree, tvb, offset, 2,
                        "Unexpected ITR-RLOC-AFI, cannot decode");
                next_tvb = tvb_new_subset(tvb, offset, -1, -1);
                call_dissector(data_handle, next_tvb, pinfo, lisp_tree);
                return;
        }
    }

    /* Query records */
    for(i=0; i < rec_cnt; i++) {
        guint8 reserved;
        guint8 prefix_mask;
        guint16 prefix_afi;
        guint32 prefix_v4;
        struct e_in6_addr prefix_v6;
        proto_item *tir;
        proto_tree *lisp_record_tree;

        reserved = tvb_get_guint8(tvb, offset);
        prefix_mask = tvb_get_guint8(tvb, offset + 1);
        prefix_afi = tvb_get_ntohs(tvb, offset + 2);

        switch (prefix_afi) {
            case AFNUM_INET:
                prefix_v4 = tvb_get_ipv4(tvb, offset + 4);
                tir = proto_tree_add_text(lisp_tree, tvb, offset, 4 + INET_ADDRLEN,
                        "Record %d: %s/%d",
                        i+1, ip_to_str((guint8 *)&prefix_v4), prefix_mask);
                /* Update the INFO column if there is only one record */
                if (rec_cnt == 1)
                    col_append_fstr(pinfo->cinfo, COL_INFO, " for %s/%d",
                            ip_to_str((guint8 *)&prefix_v4), prefix_mask);
                lisp_record_tree = proto_item_add_subtree(tir, ett_lisp_record);
                proto_tree_add_text(lisp_record_tree, tvb, offset, 1, "Reserved bits: 0x%02X",
                        reserved);
                proto_tree_add_text(lisp_record_tree, tvb, offset + 1, 1, "Prefix length: %d",
                        prefix_mask);
                proto_tree_add_text(lisp_record_tree, tvb, offset + 2, 2, "Prefix AFI: %d",
                        prefix_afi);
                proto_tree_add_text(lisp_record_tree, tvb, offset + 4, INET_ADDRLEN, "Prefix: %s",
                        ip_to_str((guint8 *)&prefix_v4));
                offset += 4 + INET_ADDRLEN;
                break;
            case AFNUM_INET6:
                tvb_get_ipv6(tvb, offset + 4, &prefix_v6);
                tir = proto_tree_add_text(lisp_tree, tvb, offset, 4 + INET6_ADDRLEN,
                        "Record %d: %s/%d",
                        i+1, ip6_to_str(&prefix_v6), prefix_mask);
                /* Update the INFO column if there is only one record */
                if (rec_cnt == 1)
                    col_append_fstr(pinfo->cinfo, COL_INFO, " for %s/%d",
                            ip6_to_str(&prefix_v6), prefix_mask);
                lisp_record_tree = proto_item_add_subtree(tir, ett_lisp_record);
                proto_tree_add_text(lisp_record_tree, tvb, offset, 1, "Reserved bits: 0x%02X",
                        reserved);
                proto_tree_add_text(lisp_record_tree, tvb, offset + 1, 1, "Prefix length: %d",
                        prefix_mask);
                proto_tree_add_text(lisp_record_tree, tvb, offset + 2, 2, "Prefix AFI: %d",
                        prefix_afi);
                proto_tree_add_text(lisp_record_tree, tvb, offset + 4, INET6_ADDRLEN, "Prefix: %s",
                        ip6_to_str(&prefix_v6));
                offset += 4 + INET6_ADDRLEN;
                break;
            default:
                proto_tree_add_text(lisp_tree, tvb, offset, 2, "Unexpected AFI, cannot decode");
                next_tvb = tvb_new_subset(tvb, offset, -1, -1);
                call_dissector(data_handle, next_tvb, pinfo, lisp_tree);
                return;
        }
    }

    /* If M bit is set, we also have a Map-Reply */
    if (mrep) {
        int len = 0;
        tvbuff_t *rep_tvb;
        proto_item *tim;
        proto_tree *lisp_mr_tree;

        tim = proto_tree_add_text(lisp_tree, tvb, offset, -1, "Map-Reply record");
        lisp_mr_tree = proto_item_add_subtree(tim, ett_lisp_mr);

        rep_tvb = tvb_new_subset(tvb, offset, -1, -1);
        len = dissect_lisp_mapping(rep_tvb, pinfo, lisp_mr_tree, 0);
        offset += len;
    }

    next_tvb = tvb_new_subset(tvb, offset, -1, -1);
    call_dissector(data_handle, next_tvb, pinfo, lisp_tree);
}


/*
 * Dissector code for Map-Reply type control packets
 *
 *        0                   1                   2                   3
 *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |Type=2 |P|E|            Reserved               | Record Count  |
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
    int i;
    gint offset = 0;
    guint8 rec_cnt = 0;
    tvbuff_t *next_tvb;

    /* Flags (2 bits) */
    proto_tree_add_item(lisp_tree, hf_lisp_mrep_flags_probe, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(lisp_tree, hf_lisp_mrep_flags_enlr, tvb, offset, 3, ENC_BIG_ENDIAN);

    /* Reserved bits (18 bits) */
    proto_tree_add_item(lisp_tree, hf_lisp_mrep_res, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    /* Record count (8 bits) */
    rec_cnt = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(lisp_tree, hf_lisp_records, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Nonce (64 bits) */
    proto_tree_add_item(lisp_tree, hf_lisp_nonce, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    /* Reply records */
    for(i=0; i < rec_cnt; i++) {
        tvbuff_t *rec_tvb;
        int len = 0;

        rec_tvb = tvb_new_subset(tvb, offset, -1, -1);
        len = dissect_lisp_mapping(rec_tvb, pinfo, lisp_tree, rec_cnt);
        offset += len;
    }

    next_tvb = tvb_new_subset(tvb, offset, -1, -1);
    call_dissector(data_handle, next_tvb, pinfo, lisp_tree);
}


/*
 *  Dissector code for Map-Register type control packets
 *
 *        0                   1                   2                   3
 *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |Type=3 |P|            Reserved               |M| Record Count  |
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
dissect_lisp_map_register(tvbuff_t *tvb, packet_info *pinfo, proto_tree *lisp_tree)
{
    int i;
    gint offset = 0;
    guint8 rec_cnt = 0;
    tvbuff_t *next_tvb;
    guint16 authlen = 0;

    /* Flags (1 bit) */
    proto_tree_add_item(lisp_tree, hf_lisp_mreg_flags_pmr, tvb, offset, 3, ENC_BIG_ENDIAN);

    /* Reserved bits (18 bits) */
    proto_tree_add_item(lisp_tree, hf_lisp_mreg_res, tvb, offset, 3, ENC_BIG_ENDIAN);

    /* Flags (1 bit) */
    proto_tree_add_item(lisp_tree, hf_lisp_mreg_flags_wmn, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    /* Record count (8 bits) */
    rec_cnt = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(lisp_tree, hf_lisp_records, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Nonce (64 bits) */
    proto_tree_add_item(lisp_tree, hf_lisp_nonce, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    /* Key ID (16 bits) */
    proto_tree_add_item(lisp_tree, hf_lisp_mreg_keyid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Authentication Data Length (16 bits) */
    authlen = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(lisp_tree, hf_lisp_mreg_authlen, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Authentication Data */
    /* XXX: need to check is there is still enough data in buffer */
    proto_tree_add_item(lisp_tree, hf_lisp_mreg_auth, tvb, offset, authlen, ENC_NA);
    offset += authlen;

    for(i=0; i < rec_cnt; i++) {
        tvbuff_t *rec_tvb;
        int len = 0;

        rec_tvb = tvb_new_subset(tvb, offset, -1, -1);
        len = dissect_lisp_mapping(rec_tvb, pinfo, lisp_tree, rec_cnt);
        offset += len;
    }

    next_tvb = tvb_new_subset(tvb, offset, -1, -1);
    call_dissector(data_handle, next_tvb, pinfo, lisp_tree);
}


/*
 *  Dissector code for Map-Notify type control packets
 *
 *        0                   1                   2                   3
 *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |Type=4 |              Reserved                 | Record Count  |
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
    int i;
    gint offset = 0;
    guint8 rec_cnt = 0;
    tvbuff_t *next_tvb;
    guint16 authlen = 0;

    /* Reserved bits (20 bits) */
    proto_tree_add_item(lisp_tree, hf_lisp_mnot_res, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    /* Record count (8 bits) */
    rec_cnt = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(lisp_tree, hf_lisp_records, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Nonce (64 bits) */
    proto_tree_add_item(lisp_tree, hf_lisp_nonce, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    /* Key ID (16 bits) */
    proto_tree_add_item(lisp_tree, hf_lisp_mnot_keyid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Authentication Data Length (16 bits) */
    authlen = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(lisp_tree, hf_lisp_mnot_authlen, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Authentication Data */
    /* XXX: need to check is there is still enough data in buffer */
    proto_tree_add_item(lisp_tree, hf_lisp_mnot_auth, tvb, offset, authlen, ENC_NA);
    offset += authlen;

    for(i=0; i < rec_cnt; i++) {
        tvbuff_t *rec_tvb;
        int len = 0;

        rec_tvb = tvb_new_subset(tvb, offset, -1, -1);
        len = dissect_lisp_mapping(rec_tvb, pinfo, lisp_tree, rec_cnt);
        offset += len;
    }

    next_tvb = tvb_new_subset(tvb, offset, -1, -1);
    call_dissector(data_handle, next_tvb, pinfo, lisp_tree);
}


/*
 * Dissector code for Encapsulated Control Message type packets
 *
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |Type=8 |                   Reserved                            |
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
    guint8 ip_ver;

    proto_tree_add_item(lisp_tree, hf_lisp_ecm_res, tvb, 0, 4, ENC_BIG_ENDIAN);

    /* Determine if encapsulated packet is IPv4 or IPv6, and call dissector */
    next_tvb = tvb_new_subset(tvb, LISP_ECM_HEADER_LEN, -1, -1);
    ip_ver = tvb_get_bits8(next_tvb, 0, 4);

    switch (ip_ver) {
        case 4:
            call_dissector(ipv4_handle, next_tvb, pinfo, tree);
            break;
        case 6:
            call_dissector(ipv6_handle, next_tvb, pinfo, tree);
            break;
        default:
            call_dissector(data_handle, next_tvb, pinfo, tree);
            break;
    }
    encapsulated = FALSE;
}


/*
 * Main dissector code
 */

static int
dissect_lisp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8 type;

    proto_tree *lisp_tree = NULL;

    /* Clear Info column before fetching data in case an exception is thrown */
    col_clear(pinfo->cinfo, COL_INFO);

    type = tvb_get_bits8(tvb, 0, 4);

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LISP");

    if (encapsulated) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Encapsulated %s", val_to_str(type, lisp_typevals,
                    "Unknown (0x%02x)"));
    } else {
        col_add_str(pinfo->cinfo, COL_INFO, val_to_str(type, lisp_typevals,
                    "Unknown (0x%02x)"));
    }

    if (tree) {
        proto_item *ti;

        /* create display subtree for the protocol */
        ti = proto_tree_add_item(tree, proto_lisp, tvb, 0,
                (type == LISP_ECM) ? LISP_ECM_HEADER_LEN : -1, FALSE);

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
        dissect_lisp_map_register(tvb, pinfo, lisp_tree);
        break;
    case LISP_MAP_NOTIFY:
        dissect_lisp_map_notify(tvb, pinfo, lisp_tree);
        break;
    case LISP_ECM:
        encapsulated = TRUE;
        dissect_lisp_ecm(tvb, pinfo, tree, lisp_tree);
        break;
    default:
        call_dissector(data_handle, tvb, pinfo, tree);
        break;
    }

    /* Return the amount of data this dissector was able to dissect */
    return tvb_length(tvb);
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
            { "Source EID AFI", "lisp.mreq.srceid_afi",
            FT_UINT16, BASE_DEC, NULL, 0x0, "Source EID Address Family Indicator", HFILL }},
        { &hf_lisp_mreq_srceid,
            { "Source EID", "lisp.mreq.srceid",
            FT_IPv4, BASE_NONE, NULL, 0x0, "Source EID Address", HFILL }},
        { &hf_lisp_mreq_srceidv6,
            { "Source EID", "lisp.mreq.srceidv6",
            FT_IPv6, BASE_NONE, NULL, 0x0, "Source EID Address", HFILL }},
        { &hf_lisp_mreq_srcitr,
            { "ITR-RLOC Address", "lisp.mreq.srcitr",
            FT_IPv4, BASE_NONE, NULL, 0x0, "Originating ITR RLOC Address", HFILL }},
        { &hf_lisp_mreq_srcitrv6,
            { "ITR-RLOC Address", "lisp.mreq.srcitrv6",
            FT_IPv6, BASE_NONE, NULL, 0x0, "Originating ITR RLOC Address", HFILL }},
        { &hf_lisp_mrep_flags,
            { "Flags", "lisp.mrep.flags",
            FT_UINT8, BASE_HEX, NULL, 0x06, NULL, HFILL }},
        { &hf_lisp_mrep_flags_probe,
            { "P bit (Probe)", "lisp.mrep.flags.probe",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), MAP_REP_FLAG_P, NULL, HFILL }},
        { &hf_lisp_mrep_flags_enlr,
            { "E bit (Echo-Nonce locator reachability algorithm enabled)", "lisp.mrep.flags.enlr",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), MAP_REP_FLAG_E, NULL, HFILL }},
        { &hf_lisp_mrep_res,
            { "Reserved bits", "lisp.mrep.res",
            FT_UINT24, BASE_HEX, NULL, MAP_REP_RESERVED, "Must be zero", HFILL }},
        { &hf_lisp_mreg_flags,
            { "Flags", "lisp.mreg.flags",
            FT_UINT8, BASE_HEX, NULL, 0x08, NULL, HFILL }},
        { &hf_lisp_mreg_flags_pmr,
            { "P bit (Proxy-Map-Reply)", "lisp.mreg.flags.pmr",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), MAP_REG_FLAG_P, NULL, HFILL }},
        { &hf_lisp_mreg_flags_wmn,
            { "M bit (Want-Map-Notify)", "lisp.mreg.flags.pmr",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), MAP_REG_FLAG_M, NULL, HFILL }},
        { &hf_lisp_mreg_res,
            { "Reserved bits", "lisp.mreg.res",
            FT_UINT24, BASE_HEX, NULL, MAP_REG_RESERVED, "Must be zero", HFILL }},
        { &hf_lisp_mreg_keyid,
            { "Key ID", "lisp.mreg.keyid",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_mreg_authlen,
            { "Authentication Data Length", "lisp.mreg.authlen",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_mreg_auth,
            { "Authentication Data", "lisp.mreg.auth",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_mnot_res,
            { "Reserved bits", "lisp.mnot.res",
            FT_UINT24, BASE_HEX, NULL, MAP_NOT_RESERVED, "Must be zero", HFILL }},
        { &hf_lisp_mnot_keyid,
            { "Key ID", "lisp.mnot.keyid",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_mnot_authlen,
            { "Authentication Data Length", "lisp.mnot.authlen",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_mnot_auth,
            { "Authentication Data", "lisp.mnot.auth",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_mapping_res,
            { "Reserved", "lisp.mapping.res",
            FT_UINT16, BASE_HEX, NULL, 0xF000, NULL, HFILL }},
        { &hf_lisp_mapping_ver,
            { "Mapping Version", "lisp.mapping.ver",
            FT_UINT16, BASE_DEC, NULL, 0x0FFF, NULL, HFILL }},
        { &hf_lisp_ecm_res,
            { "Reserved bits", "lisp.ecm_res",
            FT_UINT32, BASE_HEX, NULL, 0x0FFFFFFF, NULL, HFILL }},
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_lisp,
        &ett_lisp_mr,
        &ett_lisp_mapping,
        &ett_lisp_itr,
        &ett_lisp_record
    };

    /* Register the protocol name and description */
    proto_lisp = proto_register_protocol("Locator/ID Separation Protocol",
        "LISP Control", "lisp");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_lisp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


/*
 * Simple form of proto_reg_handoff_lisp which can be used if there are
 * no prefs-dependent registration function calls.
 */

void
proto_reg_handoff_lisp(void)
{
    dissector_handle_t lisp_handle;

    lisp_handle = new_create_dissector_handle(dissect_lisp, proto_lisp);
    dissector_add_uint("udp.port", LISP_CONTROL_PORT, lisp_handle);
    ipv4_handle = find_dissector("ip");
    ipv6_handle = find_dissector("ipv6");
    data_handle = find_dissector("data");
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
