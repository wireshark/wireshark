/* packet-lisp.c
 * Routines for Locator/ID Separation Protocol (LISP) Control Message dissection
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

#include "config.h"

#include <epan/packet.h>
#include <epan/afn.h>
#include <epan/ipv6-utils.h>
#include <epan/expert.h>

#define INET_ADDRLEN        4
#define INET6_ADDRLEN       16

/*
 * See draft-ietf-lisp-23 "Locator/ID Separation Protocol (LISP)",
 * draft-farinacci-lisp-lcaf-10 "LISP Canonical Address Format (LCAF)", and
 * draft-ermagan-lisp-nat-traversal-01 "NAT traversal for LISP" for packet
 * format and protocol information.
 */

#define LCAF_DRAFT_VERSION  10
#define LISP_CONTROL_PORT   4342

/* LISP Control Message types */
#define LISP_MAP_REQUEST    1
#define LISP_MAP_REPLY      2
#define LISP_MAP_REGISTER   3
#define LISP_MAP_NOTIFY     4
#define LISP_INFO           7
#define LISP_ECM            8

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

#define LCAF_HEADER_LEN     6
#define LISP_ECM_HEADER_LEN 4
#define LISP_XTRID_LEN      16

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
#define MAP_REG_FLAG_S      0x040000
#define MAP_REG_FLAG_I      0x020000
#define MAP_REG_FLAG_R      0x010000
#define MAP_REG_RESERVED    0x00FFFE
#define MAP_REG_FLAG_M      0x000001

#define MAP_NOT_FLAG_I      0x080000
#define MAP_NOT_FLAG_R      0x040000
#define MAP_NOT_RESERVED    0x03FFFF

#define INFO_FLAG_R         0x080000
#define INFO_RESERVED       0x07FFFFFF

/* Initialize the protocol and registered fields */
static int proto_lisp = -1;
static int hf_lisp_type = -1;
static int hf_lisp_irc = -1;
static int hf_lisp_records = -1;
static int hf_lisp_nonce = -1;
static int hf_lisp_keyid = -1;
static int hf_lisp_authlen = -1;
static int hf_lisp_auth = -1;
static int hf_lisp_msrtr_keyid = -1;
static int hf_lisp_msrtr_authlen = -1;
static int hf_lisp_msrtr_auth = -1;
static int hf_lisp_xtrid = -1;

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
static int hf_lisp_mrep_flags_probe = -1;
static int hf_lisp_mrep_flags_enlr = -1;
static int hf_lisp_mrep_res = -1;

/* Map-Register fields */
static int hf_lisp_mreg_flags_pmr = -1;
static int hf_lisp_mreg_flags_sec = -1;
static int hf_lisp_mreg_flags_xtrid = -1;
static int hf_lisp_mreg_flags_rtr = -1;
static int hf_lisp_mreg_flags_wmn = -1;
static int hf_lisp_mreg_res = -1;

/* Map-Notify fields */
static int hf_lisp_mnot_flags_xtrid = -1;
static int hf_lisp_mnot_flags_rtr = -1;
static int hf_lisp_mnot_res = -1;

/* Info fields */
static int hf_lisp_info_r = -1;
static int hf_lisp_info_res1 = -1;
static int hf_lisp_info_ttl = -1;
static int hf_lisp_info_res2 = -1;
static int hf_lisp_info_afi = -1;

/* Mapping record fields */
static int hf_lisp_mapping_res = -1;
static int hf_lisp_mapping_ver = -1;

/* LCAF fields */
static int hf_lisp_lcaf_res1 = -1;
static int hf_lisp_lcaf_flags = -1;
static int hf_lisp_lcaf_type = -1;
static int hf_lisp_lcaf_res2 = -1;
static int hf_lisp_lcaf_length = -1;

/* LCAF IID fields */
static int hf_lisp_lcaf_iid = -1;

/* LCAF NATT fields */
static int hf_lisp_lcaf_natt_msport = -1;
static int hf_lisp_lcaf_natt_etrport = -1;

/* Encapsulated Control Message fields */
static int hf_lisp_ecm_res = -1;

/* Initialize the subtree pointers */
static gint ett_lisp = -1;
static gint ett_lisp_mr = -1;
static gint ett_lisp_mapping = -1;
static gint ett_lisp_itr = -1;
static gint ett_lisp_record = -1;
static gint ett_lisp_lcaf = -1;
static gint ett_lisp_elp = -1;

static dissector_handle_t ipv4_handle;
static dissector_handle_t ipv6_handle;
static dissector_handle_t data_handle;

static gboolean encapsulated = FALSE;

const value_string lisp_typevals[] = {
    { LISP_MAP_REQUEST,     "Map-Request" },
    { LISP_MAP_REPLY,       "Map-Reply" },
    { LISP_MAP_REGISTER,    "Map-Register" },
    { LISP_MAP_NOTIFY,      "Map-Notify" },
    { LISP_INFO,            "Info" },
    { LISP_ECM,             "Encapsulated Control Message" },
    { 0,                    NULL}
};

const value_string lcaf_typevals[] = {
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
    { 0,                    NULL}
};


static int
dissect_lcaf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);

static int
get_lcaf_data(tvbuff_t *tvb, gint offset, guint8 *lcaf_type, guint16 *len)
{
    /* Jump over Rsvd1 and Flags (16 bits) */
    offset += 2;

    /* Type (8 bits) */
    if (lcaf_type)
        *lcaf_type = tvb_get_guint8(tvb, offset);
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

static const gchar *
get_addr_str(tvbuff_t *tvb, gint offset, guint16 afi, guint16 *addr_len)
{
    const gchar       *notset_str = "not set";
    const gchar       *addr_str;
    guint32            locator_v4;
    struct e_in6_addr  locator_v6;
    guint8             lcaf_type;
    guint32            iid;
    guint16            cur_len;

    switch (afi) {
        case AFNUM_RESERVED:
            *addr_len  = 0;
            return notset_str;
        case AFNUM_INET:
            locator_v4 = tvb_get_ipv4(tvb, offset);
            *addr_len  = INET_ADDRLEN;
            addr_str   = ip_to_str((guint8 *)&locator_v4);
            return addr_str;
        case AFNUM_INET6:
            tvb_get_ipv6(tvb, offset, &locator_v6);
            *addr_len  = INET6_ADDRLEN;
            addr_str   = ip6_to_str(&locator_v6);
            return addr_str;
        case AFNUM_LCAF:
            get_lcaf_data(tvb, offset, &lcaf_type, addr_len);
            addr_str = val_to_str(lcaf_type, lcaf_typevals, "Unknown LCAF Type (%d)");
            if (lcaf_type == LCAF_IID) {
                iid = tvb_get_ntohl(tvb, offset + LCAF_HEADER_LEN);
                afi = tvb_get_ntohs(tvb, offset + LCAF_HEADER_LEN + 4);
                addr_str = get_addr_str(tvb, offset + LCAF_HEADER_LEN + 6, afi, &cur_len);
                return ep_strdup_printf("[%d] %s", iid, addr_str);
            }
            return addr_str;
        default:
            return NULL;
    }
}

static int
dissect_lcaf_natt_rloc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, const gchar *str, int idx)
{
    guint16      addr_len = 0;
    guint16      rloc_afi;
    const gchar *rloc_str;

    rloc_afi = tvb_get_ntohs(tvb, offset); offset += 2;
    rloc_str = get_addr_str(tvb, offset, rloc_afi, &addr_len);

    if (rloc_str == NULL) {
        expert_add_info_format(pinfo, tree, PI_PROTOCOL, PI_ERROR,
                "Unexpected RLOC AFI (%d), cannot decode", rloc_afi);
        return offset;
    }

    if (idx) {
        proto_tree_add_text(tree, tvb, offset - 2, 2 + addr_len, str, idx, rloc_str);
    } else {
        proto_tree_add_text(tree, tvb, offset - 2, 2 + addr_len, str, rloc_str);
    }

    return addr_len + 2;
}

static int
dissect_lcaf_elp_hop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, int idx)
{
    guint16      addr_len = 0;
    guint16      hop_afi;
    guint16      hop_flags;
    const gchar *hop_str;
    proto_item  *ti;

    hop_afi   = tvb_get_ntohs(tvb, offset); offset += 2;
    hop_flags = tvb_get_ntohs(tvb, offset); offset += 2;
    hop_str   = get_addr_str(tvb, offset, hop_afi, &addr_len);

    if (hop_str == NULL) {
        expert_add_info_format(pinfo, tree, PI_PROTOCOL, PI_ERROR,
                "Unexpected reencap hop AFI (%d), cannot decode", hop_afi);
        return offset;
    }

    if (idx) {
        ti = proto_tree_add_text(tree, tvb, offset - 4, addr_len + 4, "Reencap hop %d: %s", idx, hop_str);
    } else {
        ti = proto_tree_add_text(tree, tvb, offset - 4, addr_len + 4, "Reencap hop: %s", hop_str);
    }
    if (hop_flags & 0x04)
        proto_item_append_text(ti, ", Lookup");
    if (hop_flags & 0x02)
        proto_item_append_text(ti, ", RLOC-Probe");
    if (hop_flags & 0x01)
        proto_item_append_text(ti, ", Strict");

    return addr_len + 4;
}


/*
 * Dissector code for AFI List
 *
 */

static int
dissect_lcaf_afi_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, guint16 length)
{
    gint old_offset;
    gint remaining = length;
    gint i = 1;

    guint16            addr_len = 0;
    guint16            afi;
    guint32            ipv4;
    struct e_in6_addr  ipv6;
    const gchar       *lcaf_str;
    proto_item        *tir;
    proto_tree        *lisp_elp_tree;

    while (remaining > 0) {
        afi = tvb_get_ntohs(tvb, offset); offset += 2; remaining -= 2;

        switch (afi) {
            case AFNUM_INET:
                ipv4 = tvb_get_ipv4(tvb, offset);
                proto_tree_add_text(tree, tvb, offset - 2, 2 + INET_ADDRLEN,
                        "%d. IPv4 Addess: %s", i, ip_to_str((guint8 *)&ipv4));
                offset    += INET_ADDRLEN;
                remaining -= INET_ADDRLEN;
                break;
            case AFNUM_INET6:
                tvb_get_ipv6(tvb, offset, &ipv6);
                proto_tree_add_text(tree, tvb, offset - 2, 2 + INET6_ADDRLEN,
                        "%d. IPv6 Addess: %s", i, ip6_to_str(&ipv6));
                offset    += INET6_ADDRLEN;
                remaining -= INET6_ADDRLEN;
                break;
            case AFNUM_LCAF:
                old_offset = offset;
                lcaf_str = get_addr_str(tvb, offset, afi, &addr_len);
                tir = proto_tree_add_text(tree, tvb, offset - 2, 2 + addr_len,
                        "%d. %s", i, lcaf_str);
                /* XXX need to check LCAF type */
                lisp_elp_tree = proto_item_add_subtree(tir, ett_lisp_elp);
                offset     = dissect_lcaf(tvb, pinfo, lisp_elp_tree, offset);
                remaining -= (offset - old_offset);
                break;
            default:
                expert_add_info_format(pinfo, tree, PI_PROTOCOL, PI_ERROR,
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
dissect_lcaf_iid(tvbuff_t *tvb, proto_tree *tree, gint offset)
{
    /* For now, we don't print reserved and length fields */
    offset += 3;

    proto_tree_add_item(tree, hf_lisp_lcaf_iid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
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
dissect_lcaf_natt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, guint16 length)
{
    gint         i;
    gint         len;
    gint         remaining   = length;
    const gchar *global_etr  = "Global ETR RLOC: %s";
    const gchar *ms          = "MS RLOC: %s";
    const gchar *private_etr = "Private ETR RLOC: %s";
    const gchar *rtr         = "RTR RLOC %d: %s";

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
 * Dissector code for Explicit Locator Path
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |           AFI = 16387         |    Rsvd1      |    Flags      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   Type = 10   |     Rsvd2     |               n               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |              AFI = x          |           Rsvd3         |L|P|S|
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                         Reencap Hop 1  ...                    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |              AFI = x          |           Rsvd3         |L|P|S|
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                         Reencap Hop k  ...                    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

static int
dissect_lcaf_elp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, guint16 length)
{
    gint len;
    gint remaining = length;
    gint i = 1;

    while (remaining > 0) {
        len = dissect_lcaf_elp_hop(tvb, pinfo, tree, offset, i);
        offset += len;
        remaining -= len;
        i++;
    }

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
 *  Type 0:  Null Body Type
 *  Type 1:  AFI List Type
 *  Type 2:  Instance ID Type
 *  Type 3:  AS Number Type
 *  Type 4:  Application Data Type
 *  Type 5:  Geo Coordinates Type
 *  Type 6:  Opaque Key Type
 *  Type 7:  NAT-Traversal Type
 *  Type 8:  Nonce Locator Type
 *  Type 9:  Multicast Info Type
 *  Type 10: Explicit Locator Path Type
 *  Type 11: Security Key Type
 *  Type 12: Source/Dest Key Type
 *
 */

static int
dissect_lcaf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    guint8       lcaf_type;
    guint16      len;
    proto_item  *tir;
    proto_tree  *lcaf_tree;

    lcaf_type = tvb_get_guint8(tvb, offset + 2);
    len       = tvb_get_ntohs(tvb, offset + 4);

    tir = proto_tree_add_text(tree, tvb, offset, 6,
            "LCAF Header (Type: %s, Length: %d bytes)",
            val_to_str(lcaf_type, lcaf_typevals, "Unknown (%d)"),
            len);
    lcaf_tree = proto_item_add_subtree(tir, ett_lisp_lcaf);

    /* Reserved bits (8 bits) */
    proto_tree_add_item(lcaf_tree, hf_lisp_lcaf_res1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Flags (8 bits) */
    proto_tree_add_item(lcaf_tree, hf_lisp_lcaf_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Type (8 bits) */
    proto_tree_add_item(lcaf_tree, hf_lisp_lcaf_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Reserved bits (8 bits) */
    proto_tree_add_item(lcaf_tree, hf_lisp_lcaf_res2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Length (16 bits) */
    proto_tree_add_item(lcaf_tree, hf_lisp_lcaf_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    switch (lcaf_type) {
        case LCAF_NULL:
            break;
        case LCAF_AFI_LIST:
            offset = dissect_lcaf_afi_list(tvb, pinfo, tree, offset, len);
            break;
        case LCAF_IID:
            offset = dissect_lcaf_iid(tvb, tree, offset);
            break;
        case LCAF_NATT:
            offset = dissect_lcaf_natt(tvb, pinfo, tree, offset, len);
            break;
        case LCAF_ELP:
            offset = dissect_lcaf_elp(tvb, pinfo, tree, offset, len);
            break;
        default:
            if (lcaf_type < 13)
                expert_add_undecoded_item(tvb, pinfo, tree, offset,
                        len, PI_WARN);
            else
                expert_add_info_format(pinfo, tree, PI_PROTOCOL, PI_ERROR,
                        "LCAF type %d is not defined in draft-farinacci-lisp-lcaf-%d",
                        lcaf_type, LCAF_DRAFT_VERSION);
            return offset + len;
    }
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
dissect_lisp_locator(tvbuff_t *tvb, packet_info *pinfo, proto_tree *lisp_mapping_tree)
{
    gint         offset   = 0;
    guint16      addr_len = 0;
    guint8       prio;
    guint8       weight;
    guint8       m_prio;
    guint8       m_weight;
    guint16      flags;
    guint16      loc_afi;
    const gchar *locator;
    proto_item  *tir;
    proto_tree  *lisp_elp_tree;

    prio     = tvb_get_guint8(tvb, offset); offset += 1;
    weight   = tvb_get_guint8(tvb, offset); offset += 1;
    m_prio   = tvb_get_guint8(tvb, offset); offset += 1;
    m_weight = tvb_get_guint8(tvb, offset); offset += 1;
    flags    = tvb_get_ntohs(tvb, offset);  offset += 2;
    loc_afi  = tvb_get_ntohs(tvb, offset);  offset += 2;

    locator = get_addr_str(tvb, offset, loc_afi, &addr_len);

    if (locator == NULL) {
        expert_add_info_format(pinfo, lisp_mapping_tree, PI_PROTOCOL, PI_ERROR,
                "Unexpected locator AFI (%d), cannot decode", loc_afi);
        return offset;
    }

    tir = proto_tree_add_text(lisp_mapping_tree, tvb, 0, 8 + addr_len,
            "%sRLOC: %s%s, %s, Priority/Weight: %d/%d, Multicast Priority/Weight: %d/%d",
            (flags&LOCAL_BIT_MASK) ? "Local " : "",
            locator,
            (flags&PROBE_BIT_MASK) ? " (probed)" : "",
            (flags&REACH_BIT_MASK) ? "Reachable" : "Unreachable",
            prio, weight, m_prio, m_weight);

    if (loc_afi == AFNUM_LCAF) {
        /* Create a sub-tree for the mapping */
        lisp_elp_tree = proto_item_add_subtree(tir, ett_lisp_elp);
        offset = dissect_lcaf(tvb, pinfo, lisp_elp_tree, offset);
    } else {
        offset += addr_len;
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
    int          i;
    gint         offset        = 0;
    gint         mapver_offset = 0;
    guint32      ttl;
    guint16      addr_len      = 0;
    guint8       loc_cnt;
    guint8       prefix_mask;
    guint8       flags;
    guint8       act;
    guint16      prefix_afi;
    const gchar *prefix;
    proto_item  *tir;
    proto_tree  *lisp_mapping_tree;

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

    prefix = get_addr_str(tvb, offset, prefix_afi, &addr_len);

    if (prefix == NULL) {
        expert_add_info_format(pinfo, lisp_tree, PI_PROTOCOL, PI_ERROR,
                "Unexpected EID prefix AFI (%d), cannot decode", prefix_afi);
        return offset;
    }

    tir = proto_tree_add_text(lisp_tree, tvb, 0, 12 + addr_len,
            "EID prefix: %s/%d, TTL: %s, %sAuthoritative, %s",
            prefix, prefix_mask,
            (ttl == 0xFFFFFFFF) ? "Unlimited" : ep_strdup_printf("%d", ttl),
            (flags&LISP_MAP_AUTH) ? "" : "Not ", lisp_actions[act]);
    offset += addr_len;

    /* Update the INFO column if there is only one record */
    if (rec_cnt == 1)
        col_append_fstr(pinfo->cinfo, COL_INFO, " for %s/%d",
                prefix, prefix_mask);

    /* Create a sub-tree for the mapping */
    lisp_mapping_tree = proto_item_add_subtree(tir, ett_lisp_mapping);

    /* Reserved (4 bits) */
    proto_tree_add_item(lisp_mapping_tree, hf_lisp_mapping_res, tvb, mapver_offset, 2, ENC_BIG_ENDIAN);

    /* Map-Version Number (12 bits) */
    proto_tree_add_item(lisp_mapping_tree, hf_lisp_mapping_ver, tvb, mapver_offset, 2, ENC_BIG_ENDIAN);

    /* Locators */
    for(i=0; i < loc_cnt; i++) {
        tvbuff_t *loc_tvb;
        int len = 0;

        loc_tvb = tvb_new_subset_remaining(tvb, offset);
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
    int                i;
    guint16            addr_len    = 0;
    gint               offset      = 0;
    guint16            flags;
    gboolean           mrep        = FALSE;
    gboolean           smr         = FALSE;
    gboolean           probe       = FALSE;
    gboolean           pitr        = FALSE;
    gboolean           smr_invoked = FALSE;
    guint8             itr_rec_cnt = 0;
    guint8             rec_cnt     = 0;
    guint16            src_eid_afi;
    const gchar       *src_eid;
    struct e_in6_addr  e_in6_addr;
    tvbuff_t          *next_tvb;

    /* Flags (6 bits)*/
    flags       = tvb_get_ntohs(tvb, offset);
    mrep        = flags & (MAP_REQ_FLAG_M >> 8);
    smr         = flags & (MAP_REQ_FLAG_S >> 8);
    probe       = flags & (MAP_REQ_FLAG_P >> 8);
    pitr        = flags & (MAP_REQ_FLAG_p >> 8);
    smr_invoked = flags & (MAP_REQ_FLAG_s >> 8);

    proto_tree_add_item(lisp_tree, hf_lisp_mreq_flags_auth, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(lisp_tree, hf_lisp_mreq_flags_mrp, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(lisp_tree, hf_lisp_mreq_flags_probe, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(lisp_tree, hf_lisp_mreq_flags_smr, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(lisp_tree, hf_lisp_mreq_flags_pitr, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(lisp_tree, hf_lisp_mreq_flags_smri, tvb, offset, 3, ENC_BIG_ENDIAN);

    if (pitr)
        col_append_fstr(pinfo->cinfo, COL_INFO, " by P-ITR");

    if (smr)
        col_append_fstr(pinfo->cinfo, COL_INFO, " (SMR)");

    if (probe)
        col_append_fstr(pinfo->cinfo, COL_INFO, " (RLOC-probe)");

    if (smr_invoked)
        col_append_fstr(pinfo->cinfo, COL_INFO, " (SMR-invoked)");

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
            proto_tree_add_text(lisp_tree, tvb, offset, 0, "Source EID: not set");
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
        case AFNUM_LCAF:
            src_eid = get_addr_str(tvb, offset, src_eid_afi, &addr_len);
            proto_tree_add_text(lisp_tree, tvb, offset, addr_len, "Source EID: %s", src_eid);
            offset += addr_len;
            break;
        default:
            expert_add_info_format(pinfo, lisp_tree, PI_PROTOCOL, PI_ERROR,
                    "Unexpected Source EID AFI (%d), cannot decode", src_eid_afi);
            next_tvb = tvb_new_subset_remaining(tvb, offset);
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
                expert_add_info_format(pinfo, lisp_tree, PI_PROTOCOL, PI_ERROR,
                        "Unexpected ITR-RLOC-AFI (%d), cannot decode", itr_afi);
                next_tvb = tvb_new_subset_remaining(tvb, offset);
                call_dissector(data_handle, next_tvb, pinfo, lisp_tree);
                return;
        }
    }

    /* Query records */
    for(i=0; i < rec_cnt; i++) {
        guint16 reserved, prefix_mask;
        guint16 prefix_afi;
        const gchar *prefix;
        proto_item *tir;
        proto_tree *lisp_record_tree;

        addr_len = 0;
        reserved = tvb_get_guint8(tvb, offset);
        prefix_mask = tvb_get_guint8(tvb, offset + 1);
        prefix_afi = tvb_get_ntohs(tvb, offset + 2);
        prefix = get_addr_str(tvb, offset + 4, prefix_afi, &addr_len);

        if (prefix == NULL) {
            expert_add_info_format(pinfo, lisp_tree, PI_PROTOCOL, PI_ERROR,
                    "Unexpected EID prefix AFI (%d), cannot decode", prefix_afi);
            next_tvb = tvb_new_subset_remaining(tvb, offset);
            call_dissector(data_handle, next_tvb, pinfo, lisp_tree);
            return;
        }

        tir = proto_tree_add_text(lisp_tree, tvb, offset, 4 + addr_len,
                "Record %d: %s/%d", i+1, prefix, prefix_mask);

        /* Update the INFO column if there is only one record */
        if (rec_cnt == 1)
            col_append_fstr(pinfo->cinfo, COL_INFO, " for %s/%d", prefix, prefix_mask);

        lisp_record_tree = proto_item_add_subtree(tir, ett_lisp_record);
        proto_tree_add_text(lisp_record_tree, tvb, offset, 1, "Reserved bits: 0x%02X",
                reserved);
        proto_tree_add_text(lisp_record_tree, tvb, offset + 1, 1, "Prefix length: %d",
                prefix_mask);
        proto_tree_add_text(lisp_record_tree, tvb, offset + 2, 2, "Prefix AFI: %d",
                prefix_afi);
        proto_tree_add_text(lisp_record_tree, tvb, offset + 4, addr_len, "Prefix: %s",
                prefix);
        offset += 4 + addr_len;
    }

    /* If M bit is set, we also have a Map-Reply */
    if (mrep) {
        int len = 0;
        tvbuff_t *rep_tvb;
        proto_item *tim;
        proto_tree *lisp_mr_tree;

        tim = proto_tree_add_text(lisp_tree, tvb, offset, -1, "Map-Reply record");
        lisp_mr_tree = proto_item_add_subtree(tim, ett_lisp_mr);

        rep_tvb = tvb_new_subset_remaining(tvb, offset);
        len = dissect_lisp_mapping(rep_tvb, pinfo, lisp_mr_tree, 0);
        offset += len;
    }

    next_tvb = tvb_new_subset_remaining(tvb, offset);
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
    int       i;
    gint      offset  = 0;
    gboolean  probe   = FALSE;
    guint8    flags;
    guint8    rec_cnt = 0;
    tvbuff_t *next_tvb;

    /* Flags (2 bits) */
    flags = tvb_get_guint8(tvb, offset);
    probe = flags & (MAP_REP_FLAG_P >> 16);
    proto_tree_add_item(lisp_tree, hf_lisp_mrep_flags_probe, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(lisp_tree, hf_lisp_mrep_flags_enlr, tvb, offset, 3, ENC_BIG_ENDIAN);

    if (probe)
        col_append_fstr(pinfo->cinfo, COL_INFO, " (RLOC-probe reply)");

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

        rec_tvb = tvb_new_subset_remaining(tvb, offset);
        len = dissect_lisp_mapping(rec_tvb, pinfo, lisp_tree, rec_cnt);
        offset += len;
    }

    next_tvb = tvb_new_subset_remaining(tvb, offset);
    call_dissector(data_handle, next_tvb, pinfo, lisp_tree);
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

static void
dissect_lisp_map_register(tvbuff_t *tvb, packet_info *pinfo, proto_tree *lisp_tree)
{
    int       i;
    gint      offset  = 0;
    guint8    rec_cnt = 0;
    tvbuff_t *next_tvb;
    guint16   authlen = 0;
    guint16   flags;
    gboolean  xtrid   = FALSE;
    gboolean  rtr     = FALSE;

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
        col_append_fstr(pinfo->cinfo, COL_INFO, " (RTR)");

    /* Reserved bits (15 bits) */
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
        tvbuff_t *rec_tvb;
        int len = 0;

        rec_tvb = tvb_new_subset_remaining(tvb, offset);
        len = dissect_lisp_mapping(rec_tvb, pinfo, lisp_tree, rec_cnt);
        offset += len;
    }

    /* If I bit is set, we have an xTR-ID field */
    if (xtrid) {
        proto_tree_add_item(lisp_tree, hf_lisp_xtrid, tvb, offset, LISP_XTRID_LEN, ENC_NA);
        offset += LISP_XTRID_LEN;
    }

    next_tvb = tvb_new_subset_remaining(tvb, offset);
    call_dissector(data_handle, next_tvb, pinfo, lisp_tree);
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
    gint      offset  = 0;
    guint8    rec_cnt = 0;
    tvbuff_t *next_tvb;
    guint16   authlen = 0;
    guint16   flags;
    gboolean  xtrid   = FALSE;
    gboolean  rtr     = FALSE;

    /* Flags defined in NAT Traversal draft (2 bits) */
    flags = tvb_get_ntohs(tvb, offset);
    xtrid = flags & (MAP_NOT_FLAG_I >> 8);
    rtr   = flags & (MAP_NOT_FLAG_R >> 8);

    proto_tree_add_item(lisp_tree, hf_lisp_mnot_flags_xtrid, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(lisp_tree, hf_lisp_mnot_flags_rtr, tvb, offset, 3, ENC_BIG_ENDIAN);

    if (rtr)
        col_append_fstr(pinfo->cinfo, COL_INFO, " (RTR)");

    /* Reserved bits (18 bits) */
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
        tvbuff_t *rec_tvb;
        int len = 0;

        rec_tvb = tvb_new_subset_remaining(tvb, offset);
        len = dissect_lisp_mapping(rec_tvb, pinfo, lisp_tree, rec_cnt);
        offset += len;
    }

    /* If I bit is set, we have an xTR-ID field */
    if (xtrid) {
        proto_tree_add_item(lisp_tree, hf_lisp_xtrid, tvb, offset, LISP_XTRID_LEN, ENC_NA);
        offset += LISP_XTRID_LEN;
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
    call_dissector(data_handle, next_tvb, pinfo, lisp_tree);
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
    gint         offset   = 0;
    tvbuff_t    *next_tvb;
    guint8       flags;
    gboolean     reply;
    guint16      authlen  = 0;
    guint8       prefix_mask;
    guint16      prefix_afi, afi;
    const gchar *prefix;
    guint16      addr_len = 0;
    proto_item  *tir;
    proto_tree  *lisp_lcaf_tree;

    /* Flags (1 bit) */
    flags = tvb_get_guint8(tvb, offset);
    reply = flags & (INFO_FLAG_R >> 16);

    if (reply)
        col_append_fstr(pinfo->cinfo, COL_INFO, "-Reply");
    else
        col_append_fstr(pinfo->cinfo, COL_INFO, "-Request");

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

    prefix_mask = tvb_get_guint8(tvb, offset); offset += 1;
    prefix_afi  = tvb_get_ntohs(tvb, offset);  offset += 2;
    prefix      = get_addr_str(tvb, offset, prefix_afi, &addr_len);

    if (prefix == NULL) {
        expert_add_info_format(pinfo, lisp_tree, PI_PROTOCOL, PI_ERROR,
                "Unexpected EID prefix AFI (%d), cannot decode", prefix_afi);
        next_tvb = tvb_new_subset_remaining(tvb, offset);
        call_dissector(data_handle, next_tvb, pinfo, lisp_tree);
        return;
    }

    proto_tree_add_text(lisp_tree, tvb, offset - 3, 3 + addr_len,
            "EID prefix: %s/%d", prefix, prefix_mask);
    offset += addr_len;

    /* Update the INFO column */
    col_append_fstr(pinfo->cinfo, COL_INFO, " for %s/%d", prefix, prefix_mask);

    tir = proto_tree_add_item(lisp_tree, hf_lisp_info_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
    afi  = tvb_get_ntohs(tvb, offset); offset += 2;

    if (!reply) {
        if (afi != 0) {
            expert_add_info_format(pinfo, tir, PI_PROTOCOL, PI_ERROR,
                    "Expecting NULL AFI (0), found %d, incorrect packet!", afi);
        }
    } else {
        if (afi != AFNUM_LCAF) {
            expert_add_info_format(pinfo, tir, PI_PROTOCOL, PI_ERROR,
                    "Expecting LCAF AFI (%d), found %d, incorrect packet!",
                    AFNUM_LCAF, afi);
        } else {
            lisp_lcaf_tree = proto_item_add_subtree(tir, ett_lisp_lcaf);
            offset = dissect_lcaf(tvb, pinfo, lisp_lcaf_tree, offset);
        }
    }

    next_tvb = tvb_new_subset_remaining(tvb, offset);
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
    guint8    ip_ver;

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
            call_dissector(data_handle, next_tvb, pinfo, tree);
            break;
    }
    encapsulated = FALSE;
}


/*
 * Main dissector code
 */

static int
dissect_lisp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
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
                    "Unknown LISP Control Packet (%d)"));
    } else {
        col_add_str(pinfo->cinfo, COL_INFO, val_to_str(type, lisp_typevals,
                    "Unknown LISP Control Packet (%d)"));
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
        dissect_lisp_map_register(tvb, pinfo, lisp_tree);
        break;
    case LISP_MAP_NOTIFY:
        dissect_lisp_map_notify(tvb, pinfo, lisp_tree);
        break;
    case LISP_INFO:
        dissect_lisp_info(tvb, pinfo, lisp_tree);
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
            FT_UINT16, BASE_DEC, VALS(afn_vals), 0x0, "Source EID Address Family Indicator", HFILL }},
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
        { &hf_lisp_mrep_flags_probe,
            { "P bit (Probe)", "lisp.mrep.flags.probe",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), MAP_REP_FLAG_P, NULL, HFILL }},
        { &hf_lisp_mrep_flags_enlr,
            { "E bit (Echo-Nonce locator reachability algorithm enabled)", "lisp.mrep.flags.enlr",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), MAP_REP_FLAG_E, NULL, HFILL }},
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
        { &hf_lisp_mnot_flags_xtrid,
            { "I bit (xTR-ID present)", "lisp.mnot.flags.xtrid",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), MAP_REG_FLAG_I, NULL, HFILL }},
        { &hf_lisp_mnot_flags_rtr,
            { "R bit (Built for an RTR)", "lisp.mnot.flags.rtr",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), MAP_REG_FLAG_R, NULL, HFILL }},
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
        { &hf_lisp_info_afi,
            { "AFI", "lisp.info.afi",
            FT_UINT16, BASE_DEC, VALS(afn_vals), 0x0, "Address Family Indicator", HFILL }},
        { &hf_lisp_mapping_res,
            { "Reserved", "lisp.mapping.res",
            FT_UINT16, BASE_HEX, NULL, 0xF000, NULL, HFILL }},
        { &hf_lisp_mapping_ver,
            { "Mapping Version", "lisp.mapping.ver",
            FT_UINT16, BASE_DEC, NULL, 0x0FFF, NULL, HFILL }},
        { &hf_lisp_ecm_res,
            { "Reserved bits", "lisp.ecm_res",
            FT_UINT32, BASE_HEX, NULL, 0x0FFFFFFF, NULL, HFILL }},
        { &hf_lisp_lcaf_res1,
            { "Reserved bits", "lisp.lcaf.res1",
            FT_UINT8, BASE_HEX, NULL, 0xFF, NULL, HFILL }},
        { &hf_lisp_lcaf_flags,
            { "Flags", "lisp.lcaf.flags",
            FT_UINT8, BASE_HEX, NULL, 0xFF, NULL, HFILL }},
        { &hf_lisp_lcaf_type,
            { "Type", "lisp.lcaf.type",
            FT_UINT8, BASE_DEC, VALS(lcaf_typevals), 0xFF, "LISP LCAF Type", HFILL }},
        { &hf_lisp_lcaf_res2,
            { "Reserved bits", "lisp.lcaf.res2",
            FT_UINT8, BASE_HEX, NULL, 0xFF, NULL, HFILL }},
        { &hf_lisp_lcaf_length,
            { "Length", "lisp.lcaf.length",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_iid,
            { "Instance ID", "lisp.lcaf.iid",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_natt_msport,
            { "MS UDP Port Number", "lisp.lcaf.natt.msport",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_lcaf_natt_etrport,
            { "ETR UDP Port Number", "lisp.lcaf.natt.etrport",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_lisp,
        &ett_lisp_mr,
        &ett_lisp_mapping,
        &ett_lisp_itr,
        &ett_lisp_record,
        &ett_lisp_lcaf,
        &ett_lisp_elp
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
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
