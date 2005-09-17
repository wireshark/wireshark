/* packet-mip6.c
 *
 * $Id$
 *
 * Routines for Mobile IPv6 dissection (draft-ietf-mobileip-ipv6-20.txt)
 * Copyright 2003 Oy L M Ericsson Ab <teemu.rinta-aho@ericsson.fi>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
#include "config.h"
#endif

#include <epan/packet.h>

#include <epan/ipproto.h>
#include <epan/ip_opts.h>
#include "packet-mip6.h"

/* Initialize the protocol and registered header fields */
static int proto_mip6 = -1;
static int hf_mip6_proto = -1;
static int hf_mip6_hlen = -1;
static int hf_mip6_mhtype = -1;
static int hf_mip6_reserved = -1;
static int hf_mip6_csum = -1;

static int hf_mip6_hoti_cookie = -1;

static int hf_mip6_coti_cookie = -1;

static int hf_mip6_hot_nindex = -1;
static int hf_mip6_hot_cookie = -1;
static int hf_mip6_hot_token = -1;

static int hf_mip6_cot_nindex = -1;
static int hf_mip6_cot_cookie = -1;
static int hf_mip6_cot_token = -1;

static int hf_mip6_bu_seqnr = -1;
static int hf_mip6_bu_a_flag = -1;
static int hf_mip6_bu_h_flag = -1;
static int hf_mip6_bu_l_flag = -1;
static int hf_mip6_bu_k_flag = -1;
static int hf_mip6_bu_lifetime = -1;

static int hf_mip6_ba_status = -1;
static int hf_mip6_ba_k_flag = -1;
static int hf_mip6_ba_seqnr = -1;
static int hf_mip6_ba_lifetime = -1;

static int hf_mip6_be_status = -1;
static int hf_mip6_be_haddr = -1;

static int hf_mip6_bra_interval = -1;

static int hf_mip6_acoa_acoa = -1;

static int hf_mip6_ni_hni = -1;
static int hf_mip6_ni_cni = -1;

static int hf_mip6_bad_auth = -1;

/* Initialize the subtree pointers */
static gint ett_mip6 = -1;
static gint ett_mip6_opt_padn = -1;
static gint ett_mip6_opt_bra = -1;
static gint ett_mip6_opt_acoa = -1;
static gint ett_mip6_opt_ni = -1;
static gint ett_mip6_opt_bad = -1;

/* Functions to dissect the mobility headers */

static int
dissect_mip6_brr(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo)
{
    proto_tree *data_tree = NULL;
    proto_item *ti;

    if (check_col(pinfo->cinfo, COL_INFO))
        col_set_str(pinfo->cinfo, COL_INFO, "Binding Refresh Request");

    if (mip6_tree) {
        ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF, 
                                 MIP6_BRR_LEN, "Binding Refresh Request");
        data_tree = proto_item_add_subtree(ti, ett_mip6);
    }

    return MIP6_DATA_OFF+MIP6_BRR_LEN;
}

static int
dissect_mip6_hoti(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo)
{
    proto_tree *data_tree = NULL;
    proto_item *ti;

    if (check_col(pinfo->cinfo, COL_INFO))
        col_set_str(pinfo->cinfo, COL_INFO, "Home Test Init");

    if (mip6_tree) {
        ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF, 
                                 MIP6_HOTI_LEN, "Home Test Init");
        data_tree = proto_item_add_subtree(ti, ett_mip6);

        proto_tree_add_item(data_tree, hf_mip6_hoti_cookie, tvb,
                            MIP6_HOTI_COOKIE_OFF, MIP6_HOTI_COOKIE_LEN, FALSE);
    }

    return MIP6_DATA_OFF+MIP6_HOTI_LEN;
}

static int
dissect_mip6_coti(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo)
{
    proto_tree *data_tree = NULL;
    proto_item *ti;

    if (check_col(pinfo->cinfo, COL_INFO))
        col_set_str(pinfo->cinfo, COL_INFO, "Care-of Test Init");

    if (mip6_tree) {
        ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF, 
                                 MIP6_COTI_LEN, "Care-of Test Init");
        data_tree = proto_item_add_subtree(ti, ett_mip6);

        proto_tree_add_item(data_tree, hf_mip6_coti_cookie, tvb,
                            MIP6_COTI_COOKIE_OFF, MIP6_COTI_COOKIE_LEN, FALSE);
    }

    return MIP6_DATA_OFF+MIP6_COTI_LEN;
}

static int
dissect_mip6_hot(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo)
{
    proto_tree *data_tree = NULL;
    proto_item *ti;

    if (check_col(pinfo->cinfo, COL_INFO))
        col_set_str(pinfo->cinfo, COL_INFO, "Home Test");

    if (mip6_tree) {
        ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF, 
                                 MIP6_HOT_LEN, "Home Test");
        data_tree = proto_item_add_subtree(ti, ett_mip6);

        proto_tree_add_item(data_tree, hf_mip6_hot_nindex, tvb,
                            MIP6_HOT_INDEX_OFF, MIP6_HOT_INDEX_LEN, FALSE);
        proto_tree_add_item(data_tree, hf_mip6_hot_cookie, tvb,
                            MIP6_HOT_COOKIE_OFF, MIP6_HOT_COOKIE_LEN, FALSE);
        proto_tree_add_item(data_tree, hf_mip6_hot_token, tvb,
                            MIP6_HOT_TOKEN_OFF, MIP6_HOT_TOKEN_LEN, FALSE);
    }

    return MIP6_DATA_OFF+MIP6_HOT_LEN;
}

static int
dissect_mip6_cot(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo)
{
    proto_tree *data_tree = NULL;
    proto_item *ti;

    if (check_col(pinfo->cinfo, COL_INFO))
        col_set_str(pinfo->cinfo, COL_INFO, "Care-of Test");

    if (mip6_tree) {
        ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF, 
                                 MIP6_COT_LEN, "Care-of Test");
        data_tree = proto_item_add_subtree(ti, ett_mip6);

        proto_tree_add_item(data_tree, hf_mip6_cot_nindex, tvb,
                            MIP6_COT_INDEX_OFF, MIP6_COT_INDEX_LEN, FALSE);
        proto_tree_add_item(data_tree, hf_mip6_cot_cookie, tvb,
                            MIP6_COT_COOKIE_OFF, MIP6_COT_COOKIE_LEN, FALSE);
        proto_tree_add_item(data_tree, hf_mip6_hot_token, tvb,
                            MIP6_COT_TOKEN_OFF, MIP6_COT_TOKEN_LEN, FALSE);
    }

    return MIP6_DATA_OFF+MIP6_COT_LEN;
}

static int
dissect_mip6_bu(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo)
{
    proto_tree *data_tree = NULL;
    proto_item *ti;
    int lifetime;

    if (check_col(pinfo->cinfo, COL_INFO))
        col_set_str(pinfo->cinfo, COL_INFO, "Binding Update");

    if (mip6_tree) {
        ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF, 
                                 MIP6_BU_LEN, "Binding Update");
        data_tree = proto_item_add_subtree(ti, ett_mip6);

        proto_tree_add_item(data_tree, hf_mip6_bu_seqnr, tvb,
                            MIP6_BU_SEQNR_OFF, MIP6_BU_SEQNR_LEN, FALSE);

        proto_tree_add_item(data_tree, hf_mip6_bu_a_flag, tvb, 
                            MIP6_BU_FLAGS_OFF, MIP6_BU_FLAGS_LEN, FALSE);
        proto_tree_add_item(data_tree, hf_mip6_bu_h_flag, tvb, 
                            MIP6_BU_FLAGS_OFF, MIP6_BU_FLAGS_LEN, FALSE);
        proto_tree_add_item(data_tree, hf_mip6_bu_l_flag, tvb, 
                            MIP6_BU_FLAGS_OFF, MIP6_BU_FLAGS_LEN, FALSE);
        proto_tree_add_item(data_tree, hf_mip6_bu_k_flag, tvb, 
                            MIP6_BU_FLAGS_OFF, MIP6_BU_FLAGS_LEN, FALSE);

        lifetime = tvb_get_ntohs(tvb, MIP6_BU_LIFETIME_OFF);
        proto_tree_add_uint_format(data_tree, hf_mip6_bu_lifetime, tvb,
                                   MIP6_BU_LIFETIME_OFF, 
                                   MIP6_BU_LIFETIME_LEN, lifetime,
                                   "Lifetime: %d (%ld seconds)",
                                   lifetime, (long)lifetime * 4);
    }

    return MIP6_DATA_OFF+MIP6_BU_LEN;
}

static int
dissect_mip6_ba(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo)
{
    proto_tree *data_tree = NULL;
    proto_item *ti;
    int lifetime;

    if (check_col(pinfo->cinfo, COL_INFO))
        col_set_str(pinfo->cinfo, COL_INFO, "Binding Acknowledgement");

    if (mip6_tree) {
        ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF, 
                                 MIP6_BA_LEN, "Binding Acknowledgement");
        data_tree = proto_item_add_subtree(ti, ett_mip6);

        proto_tree_add_item(data_tree, hf_mip6_ba_status, tvb,
                            MIP6_BA_STATUS_OFF, MIP6_BA_STATUS_LEN, FALSE);
        proto_tree_add_item(data_tree, hf_mip6_ba_k_flag, tvb, 
                            MIP6_BA_FLAGS_OFF, MIP6_BA_FLAGS_LEN, FALSE);
        proto_tree_add_item(data_tree, hf_mip6_ba_seqnr, tvb,
                            MIP6_BA_SEQNR_OFF, MIP6_BA_SEQNR_LEN, FALSE);
        lifetime = tvb_get_ntohs(tvb, MIP6_BA_LIFETIME_OFF);
        proto_tree_add_uint_format(data_tree, hf_mip6_ba_lifetime, tvb,
                                   MIP6_BA_LIFETIME_OFF, 
                                   MIP6_BA_LIFETIME_LEN, lifetime,
                                   "Lifetime: %d (%ld seconds)",
                                   lifetime, (long)lifetime * 4);
    }

    return MIP6_DATA_OFF+MIP6_BA_LEN;
}

static int
dissect_mip6_be(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo)
{
    proto_tree *data_tree = NULL;
    proto_item *ti;
    
    if (check_col(pinfo->cinfo, COL_INFO))
        col_set_str(pinfo->cinfo, COL_INFO, "Binding Error");

    if (mip6_tree) {
        ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF, 
                                 MIP6_BE_LEN, "Binding Error");
        data_tree = proto_item_add_subtree(ti, ett_mip6);

        proto_tree_add_item(data_tree, hf_mip6_be_status, tvb,
                            MIP6_BE_STATUS_OFF, MIP6_BE_STATUS_LEN, FALSE);
        proto_tree_add_item(data_tree, hf_mip6_be_haddr, tvb,
                            MIP6_BE_HOA_OFF, MIP6_BE_HOA_LEN, FALSE);
    }

    return MIP6_DATA_OFF+MIP6_BE_LEN;
}

static int
dissect_mip6_unknown(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo)
{
    proto_tree *data_tree = NULL;
    proto_item *ti;

    if (check_col(pinfo->cinfo, COL_INFO))
        col_set_str(pinfo->cinfo, COL_INFO, "Unknown MH Type");

    if (mip6_tree) {
        ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF, 
                                 MIP6_DATA_OFF+1, "Unknown MH Type");
        data_tree = proto_item_add_subtree(ti, ett_mip6);
    }

    return MIP6_DATA_OFF+1;
}

/* Functions to dissect the mobility options */

static void
dissect_mip6_opt_padn(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
                      guint optlen, packet_info *pinfo _U_,
                      proto_tree *opt_tree)
{
    proto_tree_add_text(opt_tree, tvb, offset, optlen,
                        "%s: %u bytes", optp->name, optlen);
}

static void
dissect_mip6_opt_bra(const ip_tcp_opt *optp _U_, tvbuff_t *tvb, int offset,
                     guint optlen, packet_info *pinfo _U_,
                     proto_tree *opt_tree)
{
    int ri;

    ri = tvb_get_ntohs(tvb, offset + MIP6_BRA_RI_OFF);
    proto_tree_add_uint_format(opt_tree, hf_mip6_bra_interval, tvb,
                               offset, optlen,
                               ri, "Refresh interval: %d (%ld seconds)",
                               ri, (long)ri * 4);
}

static void
dissect_mip6_opt_acoa(const ip_tcp_opt *optp _U_, tvbuff_t *tvb, int offset,
                      guint optlen, packet_info *pinfo _U_,
                      proto_tree *opt_tree)
{
    proto_tree_add_ipv6(opt_tree, hf_mip6_acoa_acoa, tvb,
                        offset, optlen,
                        tvb_get_ptr(tvb, offset + MIP6_ACOA_ACOA_OFF, MIP6_ACOA_ACOA_LEN));
}

static void
dissect_mip6_opt_ni(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
                    guint optlen, packet_info *pinfo _U_,
                    proto_tree *opt_tree)
{
    proto_tree *field_tree = NULL;
    proto_item *tf;

    tf = proto_tree_add_text(opt_tree, tvb, offset,      optlen, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

    proto_tree_add_item(field_tree, hf_mip6_ni_hni, tvb,
                        offset + MIP6_NI_HNI_OFF, MIP6_NI_HNI_LEN, FALSE);
    proto_tree_add_item(field_tree, hf_mip6_ni_cni, tvb,
                        offset + MIP6_NI_CNI_OFF, MIP6_NI_CNI_LEN, FALSE);
}

static void
dissect_mip6_opt_bad(const ip_tcp_opt *optp _U_, tvbuff_t *tvb, int offset,
                     guint optlen, packet_info *pinfo _U_,
                     proto_tree *opt_tree)
{
    proto_tree *field_tree = NULL;
    proto_item *tf;

    tf = proto_tree_add_text(opt_tree, tvb, offset,      optlen, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

    proto_tree_add_item(field_tree, hf_mip6_bad_auth, tvb,
                        offset + MIP6_BAD_AUTH_OFF,
                        optlen - MIP6_BAD_AUTH_OFF, FALSE);
}

static const ip_tcp_opt mip6_opts[] = {
  {
    PAD1,
    "Pad1",
    NULL,
    NO_LENGTH,
    0,
    NULL,
  },
  {
    PADN,
    "PadN",
    &ett_mip6_opt_padn,
    VARIABLE_LENGTH,
    0,
    dissect_mip6_opt_padn
  },
  {
    BRA,
    "Binding Refresh Advice",
    &ett_mip6_opt_bra,
    FIXED_LENGTH,
    MIP6_BRA_LEN,
    dissect_mip6_opt_bra
  },
  {
    ACOA,
    "Alternate Care-of Address",
    &ett_mip6_opt_acoa,
    FIXED_LENGTH,
    MIP6_ACOA_LEN,
    dissect_mip6_opt_acoa
  },
  {
    NI,
    "Nonce Indices",
    &ett_mip6_opt_ni,
    FIXED_LENGTH,
    MIP6_NI_LEN,
    dissect_mip6_opt_ni
  },
  {
    BAD,
    "Binding Authorization Data",
    &ett_mip6_opt_bad,
    VARIABLE_LENGTH,
    0,
    dissect_mip6_opt_bad
  },
};

#define N_MIP6_OPTS	(sizeof mip6_opts / sizeof mip6_opts[0])

/* Function to dissect mobility options */
static int
dissect_mip6_options(tvbuff_t *tvb, proto_tree *mip6_tree, int offset, int len,
                     packet_info *pinfo)
{
    proto_tree *opts_tree = NULL;
    proto_item *ti;

    if (!mip6_tree)
        return len;

    ti = proto_tree_add_text(mip6_tree, tvb, offset, len, 
                             "Mobility Options");
    opts_tree = proto_item_add_subtree(ti, ett_mip6);

    dissect_ipv6_options(tvb, offset, len,
       mip6_opts, N_MIP6_OPTS, -1, pinfo, opts_tree);

    return len;
}

/* Function that dissects the whole MIPv6 packet */
static void
dissect_mip6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *mip6_tree = NULL;
    proto_item *ti;
    guint8     type;
    guint      len, offset = 0, start_offset = offset;

    /* Make entries in Protocol column and Info column on summary display */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "MIPv6");
    if (check_col(pinfo->cinfo, COL_INFO))
        col_clear(pinfo->cinfo, COL_INFO);

    len = (tvb_get_guint8(tvb, MIP6_HLEN_OFF) + 1) * 8;
    if (tree) {
        ti = proto_tree_add_item(tree, proto_mip6, tvb, 0, len, FALSE);
        mip6_tree = proto_item_add_subtree(ti, ett_mip6);

        /* Process header fields */
        proto_tree_add_uint_format(mip6_tree, hf_mip6_proto, tvb,
                                   MIP6_PROTO_OFF, 1,
                                   tvb_get_guint8(tvb, MIP6_PROTO_OFF),
                                   "Payload protocol: %s (0x%02x)",
                                   ipprotostr(
                                       tvb_get_guint8(tvb, MIP6_PROTO_OFF)), 
                                   tvb_get_guint8(tvb, MIP6_PROTO_OFF));

        proto_tree_add_uint_format(mip6_tree, hf_mip6_hlen, tvb,
                                   MIP6_HLEN_OFF, 1,
                                   tvb_get_guint8(tvb, MIP6_HLEN_OFF),
                                   "Header length: %u (%u bytes)",
                                   tvb_get_guint8(tvb, MIP6_HLEN_OFF),
                                   len);

        proto_tree_add_item(mip6_tree, hf_mip6_mhtype, tvb,
                            MIP6_TYPE_OFF, 1, FALSE);

        proto_tree_add_item(mip6_tree, hf_mip6_reserved, tvb,
                            MIP6_RES_OFF, 1, FALSE);

        proto_tree_add_item(mip6_tree, hf_mip6_csum, tvb,
                            MIP6_CSUM_OFF, 2, FALSE);
    }

    /* Process mobility header */
    type = tvb_get_guint8(tvb, MIP6_TYPE_OFF);
    switch (type) {
    case BRR:
        offset = dissect_mip6_brr(tvb, mip6_tree, pinfo);
        break;
    case HOTI:
        offset = dissect_mip6_hoti(tvb, mip6_tree, pinfo);
        break;
    case COTI:
        offset = dissect_mip6_coti(tvb, mip6_tree, pinfo);
        break;
    case HOT:
        offset = dissect_mip6_hot(tvb, mip6_tree, pinfo);
        break;
    case COT:
        offset = dissect_mip6_cot(tvb, mip6_tree, pinfo);
        break;
    case BU:
        offset = dissect_mip6_bu(tvb, mip6_tree, pinfo);
        break;
    case BA:
        offset = dissect_mip6_ba(tvb, mip6_tree, pinfo);
        break;
    case BE:
        offset = dissect_mip6_be(tvb, mip6_tree, pinfo);
        break;
    default:
        dissect_mip6_unknown(tvb, mip6_tree, pinfo);
        offset = len;
        break;
    }

    /* Process mobility options */
    if (offset < len) {
        if (len < (offset - start_offset)) {
            proto_tree_add_text(tree, tvb, 0, 0, "Bogus header length");
            return;
        }
        len -= (offset - start_offset);
        tvb_ensure_bytes_exist(tvb, offset, len);
        dissect_mip6_options(tvb, mip6_tree, offset, len, pinfo);
    }
}

/* Register the protocol with Ethereal */
void 
proto_register_mip6(void)
{    
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_mip6_proto,        { "Payload protocol", "mip6.proto",
                                   FT_UINT8, BASE_DEC, NULL, 0,
                                   "Payload protocol", HFILL }},
        { &hf_mip6_hlen,         { "Header length", "mip6.hlen",
                                   FT_UINT8, BASE_DEC, NULL, 0,
                                   "Header length", HFILL }},
        { &hf_mip6_mhtype,       { "Mobility Header Type", "mip6.mhtype",
                                   FT_UINT8, BASE_DEC, VALS(mip6_mh_types), 0,
                                   "Mobility Header Type", HFILL }},
        { &hf_mip6_reserved,     { "Reserved", "mip6.reserved",
                                   FT_UINT8, BASE_HEX, NULL, 0,
                                   "Reserved", HFILL }},
        { &hf_mip6_csum,         { "Checksum", "mip6.csum",
                                   FT_UINT16, BASE_HEX, NULL, 0,
                                   "Header Checksum", HFILL }},
        
        { &hf_mip6_hoti_cookie,  { "Home Init Cookie", "mip6.hoti.cookie",
                                   FT_UINT64, BASE_HEX, NULL, 0,
                                   "Home Init Cookie", HFILL }},
        
        { &hf_mip6_coti_cookie,  { "Care-of Init Cookie", "mip6.coti.cookie",
                                   FT_UINT64, BASE_HEX, NULL, 0,
                                   "Care-of Init Cookie", HFILL }},
        
        { &hf_mip6_hot_nindex,   { "Home Nonce Index", "mip6.hot.nindex",
                                   FT_UINT16, BASE_DEC, NULL, 0,
                                   "Home Nonce Index", HFILL }},
        { &hf_mip6_hot_cookie,   { "Home Init Cookie", "mip6.hot.cookie",
                                   FT_UINT64, BASE_HEX, NULL, 0,
                                   "Home Init Cookie", HFILL }},
        { &hf_mip6_hot_token,    { "Home Keygen Token", "mip6.hot.token",
                                   FT_UINT64, BASE_HEX, NULL, 0,
                                   "Home Keygen Token", HFILL }},
        
        { &hf_mip6_cot_nindex,   { "Care-of Nonce Index", "mip6.cot.nindex",
                                   FT_UINT16, BASE_DEC, NULL, 0,
                                   "Care-of Nonce Index", HFILL }},
        { &hf_mip6_cot_cookie,   { "Care-of Init Cookie", "mip6.cot.cookie",
                                   FT_UINT64, BASE_HEX, NULL, 0,
                                   "Care-of Init Cookie", HFILL }},
        { &hf_mip6_cot_token,    { "Care-of Keygen Token", "mip6.cot.token",
                                   FT_UINT64, BASE_HEX, NULL, 0,
                                   "Care-of Keygen Token", HFILL }},
        
        { &hf_mip6_bu_seqnr,     { "Sequence number", "mip6.bu.seqnr",
                                   FT_UINT16, BASE_DEC, NULL, 0,
                                   "Sequence number", HFILL }},
        { &hf_mip6_bu_a_flag,    { "Acknowledge (A) flag", "mip6.bu.a_flag",
                                   FT_BOOLEAN, 8, TFS(&mip6_bu_a_flag_value),
                                   0x80, "Acknowledge (A) flag", HFILL }},
        { &hf_mip6_bu_h_flag,    { "Home Registration (H) flag", 
                                   "mip6.bu.h_flag",
                                   FT_BOOLEAN, 8, TFS(&mip6_bu_h_flag_value),
                                   0x40, "Home Registration (H) flag", HFILL }},
        { &hf_mip6_bu_l_flag,    { "Link-Local Compatibility (L) flag", 
                                   "mip6.bu.l_flag",
                                   FT_BOOLEAN, 8, TFS(&mip6_bu_l_flag_value),
                                   0x20, "Home Registration (H) flag", HFILL }},
        { &hf_mip6_bu_k_flag,    { "Key Management Compatibility (K) flag", 
                                   "mip6.bu.k_flag",
                                   FT_BOOLEAN, 8, TFS(&mip6_bu_k_flag_value),
                                   0x10, "Key Management Compatibility (K) flag", 
                                   HFILL }},
        { &hf_mip6_bu_lifetime,  { "Lifetime", "mip6.bu.lifetime",
                                   FT_UINT16, BASE_DEC, NULL, 0,
                                   "Lifetime", HFILL }},
        
        { &hf_mip6_ba_status,    { "Status", "mip6.ba.status",
                                   FT_UINT8, BASE_DEC,
                                   VALS(&mip6_ba_status_value), 0,
                                   "Binding Acknowledgement status", HFILL }},
        { &hf_mip6_ba_k_flag,    { "Key Management Compatibility (K) flag", 
                                   "mip6.ba.k_flag",
                                   FT_BOOLEAN, 8, TFS(&mip6_bu_k_flag_value),
                                   0x80, "Key Management Compatibility (K) flag", 
                                   HFILL }},
        { &hf_mip6_ba_seqnr,     { "Sequence number", "mip6.ba.seqnr",
                                   FT_UINT16, BASE_DEC, NULL, 0,
                                   "Sequence number", HFILL }},
        { &hf_mip6_ba_lifetime,  { "Lifetime", "mip6.ba.lifetime",
                                   FT_UINT16, BASE_DEC, NULL, 0,
                                   "Lifetime", HFILL }},
        
        { &hf_mip6_be_status,    { "Status", "mip6.be.status",
                                   FT_UINT8, BASE_DEC,
                                   VALS(&mip6_be_status_value), 0,
                                   "Binding Error status", HFILL }},
        { &hf_mip6_be_haddr,     { "Home Address", "mip6.be.haddr",
                                   FT_IPv6, BASE_HEX, NULL, 0,
                                   "Home Address", HFILL }},
        
        { &hf_mip6_bra_interval, { "Refresh interval", "mip6.bra.interval",
                                   FT_UINT16, BASE_DEC, NULL, 0,
                                   "Refresh interval", HFILL }},

        { &hf_mip6_acoa_acoa,    { "Alternate care-of address", "mip6.acoa.acoa",
                                   FT_IPv6, BASE_HEX, NULL, 0,
                                   "Alternate Care-of address", HFILL }},
        
        { &hf_mip6_ni_hni,       { "Home nonce index", "mip6.ni.hni",
                                   FT_UINT16, BASE_DEC, NULL, 0,
                                   "Home nonce index", HFILL }},
        { &hf_mip6_ni_cni,       { "Care-of nonce index", "mip6.ni.cni",
                                   FT_UINT16, BASE_DEC, NULL, 0,
                                   "Care-of nonce index", HFILL }},

        { &hf_mip6_bad_auth,     { "Authenticator", "mip6.bad.auth",
                                   FT_BYTES, BASE_HEX, NULL, 0,
                                   "Care-of nonce index", HFILL }}
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_mip6,
        &ett_mip6_opt_padn,
        &ett_mip6_opt_bra,
        &ett_mip6_opt_acoa,
        &ett_mip6_opt_ni,
        &ett_mip6_opt_bad,
    };
    
    /* Register the protocol name and description */
    proto_mip6 = proto_register_protocol("Mobile IPv6", "MIPv6", "mipv6");
    
    /* Register the dissector by name */
    /* register_dissector("mipv6", dissect_mip6, proto_mip6); */
    
    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_mip6, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_mip6(void)
{
    dissector_handle_t mip6_handle;
    
    /* mip6_handle = find_dissector("mipv6"); */
    mip6_handle = create_dissector_handle(dissect_mip6, proto_mip6);
    dissector_add("ip.proto", IP_PROTO_MIPV6_OLD, mip6_handle);
    dissector_add("ip.proto", IP_PROTO_MIPV6, mip6_handle);
}
