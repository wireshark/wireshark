/* packet-mip6.c
 *
 * $Id$
 *
 * Routines for Mobile IPv6 dissection (RFC 3775)
 * Copyright 2003 Oy L M Ericsson Ab <teemu.rinta-aho@ericsson.fi>
 *
 * FMIPv6 (RFC 4068) support added by Martin Andre <andre@clarinet.u-strasbg.fr>
 * Copyright 2006, Nicolas DICHTEL - 6WIND - <nicolas.dichtel@6wind.com>
 *
 * Modifications for NEMO packets (RFC 3963): Bruno Deniaud
 * (bdeniaud@irisa.fr, nono@chez.com) 12 Oct 2005
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
#include "config.h"
#endif

#include <epan/packet.h>

#include <epan/ipproto.h>
#include <epan/ip_opts.h>
#include "packet-mip6.h"
#include "packet-ntp.h"

static dissector_table_t ip_dissector_table;

/* Initialize the protocol and registered header fields */
static int proto_mip6 = -1;
int proto_nemo = -1;
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
static int hf_mip6_bu_m_flag = -1;
static int hf_nemo_bu_r_flag = -1;
static int hf_proxy_bu_p_flag = -1;
static int hf_mip6_bu_lifetime = -1;

static int hf_mip6_ba_status = -1;
static int hf_mip6_ba_k_flag = -1;
static int hf_nemo_ba_r_flag = -1;
static int hf_proxy_ba_p_flag = -1;
static int hf_mip6_ba_seqnr = -1;
static int hf_mip6_ba_lifetime = -1;

static int hf_mip6_be_status = -1;
static int hf_mip6_be_haddr = -1;

static int hf_fmip6_fbu_seqnr = -1;
static int hf_fmip6_fbu_a_flag = -1;
static int hf_fmip6_fbu_h_flag = -1;
static int hf_fmip6_fbu_l_flag = -1;
static int hf_fmip6_fbu_k_flag = -1;
static int hf_fmip6_fbu_lifetime = -1;

static int hf_fmip6_fback_status = -1;
static int hf_fmip6_fback_k_flag = -1;
static int hf_fmip6_fback_seqnr = -1;
static int hf_fmip6_fback_lifetime = -1;

static int hf_mip6_bra_interval = -1;

static int hf_mip6_acoa_acoa = -1;
static int hf_nemo_mnp_mnp = -1;
static int hf_nemo_mnp_pfl = -1;

static int hf_mip6_ni_hni = -1;
static int hf_mip6_ni_cni = -1;

static int hf_mip6_bad_auth = -1;

static int hf_fmip6_lla_optcode = -1;

static int hf_mip6_mnid_subtype = -1;

static int hf_pmip6_timestamp = -1;
static int hf_mip6_mobility_opt = -1;

/* Initialize the subtree pointers */
static gint ett_mip6 = -1;
static gint ett_mip6_opt_padn = -1;
static gint ett_mip6_opt_bra = -1;
static gint ett_mip6_opt_acoa = -1;
static gint ett_mip6_opt_ni = -1;
static gint ett_mip6_opt_bad = -1;
static gint ett_nemo_opt_mnp = -1;
static gint ett_fmip6_opt_lla = -1;
static gint ett_mip6_opt_mnid = -1;
static gint ett_pmip6_opt_hnp = -1;
static gint ett_pmip6_opt_ts = -1;

/* Functions to dissect the mobility headers */

static int
dissect_mip6_brr(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo)
{
	proto_tree *data_tree = NULL;
	proto_item *ti;

	col_set_str(pinfo->cinfo, COL_INFO, "Binding Refresh Request");

	if (mip6_tree) {
		ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF, 
				MIP6_BRR_LEN, "Binding Refresh Request");
		data_tree = proto_item_add_subtree(ti, ett_mip6);
	}

	return MIP6_DATA_OFF + MIP6_BRR_LEN;
}

static int
dissect_mip6_hoti(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo)
{
	proto_tree *data_tree = NULL;
	proto_item *ti;

	col_set_str(pinfo->cinfo, COL_INFO, "Home Test Init");

	if (mip6_tree) {
		ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF, 
				MIP6_HOTI_LEN, "Home Test Init");
		data_tree = proto_item_add_subtree(ti, ett_mip6);

		proto_tree_add_item(data_tree, hf_mip6_hoti_cookie, tvb,
				MIP6_HOTI_COOKIE_OFF, MIP6_HOTI_COOKIE_LEN, FALSE);
	}

	return MIP6_DATA_OFF + MIP6_HOTI_LEN;
}

static int
dissect_mip6_coti(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo)
{
	proto_tree *data_tree = NULL;
	proto_item *ti;

	col_set_str(pinfo->cinfo, COL_INFO, "Care-of Test Init");

	if (mip6_tree) {
		ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF, 
				MIP6_COTI_LEN, "Care-of Test Init");
		data_tree = proto_item_add_subtree(ti, ett_mip6);

		proto_tree_add_item(data_tree, hf_mip6_coti_cookie, tvb,
				MIP6_COTI_COOKIE_OFF, MIP6_COTI_COOKIE_LEN, FALSE);
	}

	return MIP6_DATA_OFF + MIP6_COTI_LEN;
}

static int
dissect_mip6_hot(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo)
{
	proto_tree *data_tree = NULL;
	proto_item *ti;

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

	return MIP6_DATA_OFF + MIP6_HOT_LEN;
}

static int
dissect_mip6_cot(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo)
{
	proto_tree *data_tree = NULL;
	proto_item *ti;

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

	return MIP6_DATA_OFF + MIP6_COT_LEN;
}

static int
dissect_mip6_bu(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo)
{
	proto_tree *data_tree = NULL;
	proto_item *ti;
	int lifetime;

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
		proto_tree_add_item(data_tree, hf_mip6_bu_m_flag, tvb, 
				MIP6_BU_FLAGS_OFF, MIP6_BU_FLAGS_LEN, FALSE);
		proto_tree_add_item(data_tree, hf_nemo_bu_r_flag, tvb, 
				MIP6_BU_FLAGS_OFF, MIP6_BU_FLAGS_LEN, FALSE);
		proto_tree_add_item(data_tree, hf_proxy_bu_p_flag, tvb, 
				MIP6_BU_FLAGS_OFF, MIP6_BU_FLAGS_LEN, FALSE);

		if ((tvb_get_guint8(tvb, MIP6_BU_FLAGS_OFF) & 0x0004 ) == 0x0004)
			proto_nemo = 1;

		lifetime = tvb_get_ntohs(tvb, MIP6_BU_LIFETIME_OFF);
		proto_tree_add_uint_format(data_tree, hf_mip6_bu_lifetime, tvb,
				MIP6_BU_LIFETIME_OFF, 
				MIP6_BU_LIFETIME_LEN, lifetime,
				"Lifetime: %d (%ld seconds)",
				lifetime, (long)lifetime * 4);
	}

	return MIP6_DATA_OFF + MIP6_BU_LEN;
}

static int
dissect_mip6_ba(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo)
{
	proto_tree *data_tree = NULL;
	proto_item *ti;
	int lifetime;

	col_set_str(pinfo->cinfo, COL_INFO, "Binding Acknowledgement");

	if (mip6_tree) {
		ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF, 
				MIP6_BA_LEN, "Binding Acknowledgement");
		data_tree = proto_item_add_subtree(ti, ett_mip6);

		proto_tree_add_item(data_tree, hf_mip6_ba_status, tvb,
				MIP6_BA_STATUS_OFF, MIP6_BA_STATUS_LEN, FALSE);
		proto_tree_add_item(data_tree, hf_mip6_ba_k_flag, tvb, 
				MIP6_BA_FLAGS_OFF, MIP6_BA_FLAGS_LEN, FALSE);
		proto_tree_add_item(data_tree, hf_nemo_ba_r_flag, tvb, 
				MIP6_BA_FLAGS_OFF, MIP6_BA_FLAGS_LEN, FALSE);
		proto_tree_add_item(data_tree, hf_proxy_ba_p_flag, tvb, 
				MIP6_BA_FLAGS_OFF, MIP6_BA_FLAGS_LEN, FALSE);

		if ((tvb_get_guint8(tvb, MIP6_BA_FLAGS_OFF) & 0x0040 ) == 0x0040)
			proto_nemo = 1;

		proto_tree_add_item(data_tree, hf_mip6_ba_seqnr, tvb,
				MIP6_BA_SEQNR_OFF, MIP6_BA_SEQNR_LEN, FALSE);

		lifetime = tvb_get_ntohs(tvb, MIP6_BA_LIFETIME_OFF);
		proto_tree_add_uint_format(data_tree, hf_mip6_ba_lifetime, tvb,
				MIP6_BA_LIFETIME_OFF, 
				MIP6_BA_LIFETIME_LEN, lifetime,
				"Lifetime: %d (%ld seconds)",
				lifetime, (long)lifetime * 4);
	}

	return MIP6_DATA_OFF + MIP6_BA_LEN;
}

static int
dissect_mip6_be(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo)
{
	proto_tree *data_tree = NULL;
	proto_item *ti;

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

	return MIP6_DATA_OFF + MIP6_BE_LEN;
}

static int
dissect_mip6_unknown(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo)
{
	proto_tree *data_tree = NULL;
	proto_item *ti;

	col_set_str(pinfo->cinfo, COL_INFO, "Unknown MH Type");

	if (mip6_tree) {
		ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF, 
				MIP6_DATA_OFF + 1, "Unknown MH Type");
		data_tree = proto_item_add_subtree(ti, ett_mip6);
	}

	return MIP6_DATA_OFF + 1;
}

static int
dissect_fmip6_fbu(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo)
{
	proto_tree *data_tree = NULL;
	proto_item *ti;
	int lifetime;

	col_set_str(pinfo->cinfo, COL_INFO, "Fast Binding Update");

	if (mip6_tree) {
		ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF, 
				MIP6_BU_LEN, "Fast Binding Update");
		data_tree = proto_item_add_subtree(ti, ett_mip6);

		proto_tree_add_item(data_tree, hf_fmip6_fbu_seqnr, tvb,
				FMIP6_FBU_SEQNR_OFF, FMIP6_FBU_SEQNR_LEN, FALSE);

		proto_tree_add_item(data_tree, hf_fmip6_fbu_a_flag, tvb, 
				FMIP6_FBU_FLAGS_OFF, FMIP6_FBU_FLAGS_LEN, FALSE);
		proto_tree_add_item(data_tree, hf_fmip6_fbu_h_flag, tvb, 
				FMIP6_FBU_FLAGS_OFF, FMIP6_FBU_FLAGS_LEN, FALSE);
		proto_tree_add_item(data_tree, hf_fmip6_fbu_l_flag, tvb, 
				FMIP6_FBU_FLAGS_OFF, FMIP6_FBU_FLAGS_LEN, FALSE);
		proto_tree_add_item(data_tree, hf_fmip6_fbu_k_flag, tvb, 
				FMIP6_FBU_FLAGS_OFF, FMIP6_FBU_FLAGS_LEN, FALSE);

		lifetime = tvb_get_ntohs(tvb, FMIP6_FBU_LIFETIME_OFF);
		proto_tree_add_uint_format(data_tree, hf_fmip6_fbu_lifetime, tvb,
				FMIP6_FBU_LIFETIME_OFF, 
				FMIP6_FBU_LIFETIME_LEN, lifetime,
				"Lifetime: %d (%ld seconds)",
				lifetime, (long)lifetime * 4);
	}

	return MIP6_DATA_OFF + FMIP6_FBU_LEN;
}

static int
dissect_fmip6_fback(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo)
{
	proto_tree *data_tree = NULL;
	proto_item *ti;
	int lifetime;

	col_set_str(pinfo->cinfo, COL_INFO, "Fast Binding Acknowledgement");

	if (mip6_tree) {
		ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF, 
				FMIP6_FBACK_LEN, "Fast Binding Acknowledgement");
		data_tree = proto_item_add_subtree(ti, ett_mip6);

		proto_tree_add_item(data_tree, hf_fmip6_fback_status, tvb,
				FMIP6_FBACK_STATUS_OFF, FMIP6_FBACK_STATUS_LEN, FALSE);
		proto_tree_add_item(data_tree, hf_fmip6_fback_k_flag, tvb, 
				FMIP6_FBACK_FLAGS_OFF, FMIP6_FBACK_FLAGS_LEN, FALSE);
		proto_tree_add_item(data_tree, hf_fmip6_fback_seqnr, tvb,
				FMIP6_FBACK_SEQNR_OFF, FMIP6_FBACK_SEQNR_LEN, FALSE);
		lifetime = tvb_get_ntohs(tvb, FMIP6_FBACK_LIFETIME_OFF);
		proto_tree_add_uint_format(data_tree, hf_fmip6_fback_lifetime, tvb,
				FMIP6_FBACK_LIFETIME_OFF, 
				FMIP6_FBACK_LIFETIME_LEN, lifetime,
				"Lifetime: %d (%ld seconds)",
				lifetime, (long)lifetime * 4);
	}

	return MIP6_DATA_OFF + FMIP6_FBACK_LEN;
}

static int
dissect_fmip6_fna(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo)
{
	proto_tree *data_tree = NULL;
	proto_item *ti;

	col_set_str(pinfo->cinfo, COL_INFO, "Fast Neighbor Advertisement");

	if (mip6_tree) {
		ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF, 
				FMIP6_FNA_LEN, "Fast Neighbor Advertisement");
		data_tree = proto_item_add_subtree(ti, ett_mip6);
	}

	return MIP6_DATA_OFF + FMIP6_FNA_LEN;
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
	proto_tree_add_ipv6(opt_tree, hf_mip6_acoa_acoa, tvb, offset, optlen,
			tvb_get_ptr(tvb, offset + MIP6_ACOA_ACOA_OFF, MIP6_ACOA_ACOA_LEN));
}

static void
dissect_nemo_opt_mnp(const ip_tcp_opt *optp _U_, tvbuff_t *tvb, int offset,
                      guint optlen, packet_info *pinfo _U_,
                      proto_tree *opt_tree)
{
	proto_tree *field_tree = NULL;
	proto_item *tf;
	tf = proto_tree_add_text(opt_tree, tvb, offset, optlen, "%s", optp->name);
	field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
	proto_tree_add_item(field_tree, hf_nemo_mnp_pfl, tvb,
			offset + NEMO_MNP_PL_OFF, 1, FALSE);

	proto_tree_add_item(field_tree, hf_nemo_mnp_mnp, tvb,
			offset + NEMO_MNP_MNP_OFF, NEMO_MNP_MNP_LEN, FALSE);
}

static void
dissect_mip6_opt_ni(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
                    guint optlen, packet_info *pinfo _U_,
                    proto_tree *opt_tree)
{
	proto_tree *field_tree = NULL;
	proto_item *tf;

	tf = proto_tree_add_text(opt_tree, tvb, offset, optlen, "%s", optp->name);
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

	tf = proto_tree_add_text(opt_tree, tvb, offset, optlen, "%s", optp->name);
	field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

	proto_tree_add_item(field_tree, hf_mip6_bad_auth, tvb,
			offset + MIP6_BAD_AUTH_OFF,
			optlen - MIP6_BAD_AUTH_OFF, FALSE);
}

static void
dissect_fmip6_opt_lla(const ip_tcp_opt *optp _U_, tvbuff_t *tvb, int offset,
                     guint optlen, packet_info *pinfo _U_,
                     proto_tree *opt_tree)
{
	proto_tree *field_tree = NULL;
	proto_item *tf;
	int len, p;

	tf = proto_tree_add_text(opt_tree, tvb, offset, optlen, "%s", optp->name);
	field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

	proto_tree_add_item(field_tree, hf_fmip6_lla_optcode, tvb,
			offset + FMIP6_LLA_OPTCODE_OFF, FMIP6_LLA_OPTCODE_LEN, FALSE);

	p = offset + FMIP6_LLA_LLA_OFF;
	len = optlen - FMIP6_LLA_LLA_OFF;

	if (len > 0) {
		/*
		 * I'm not sure what "The format of the option when the LLA is 6
		 * bytes is shown in Figure 15.  When the LLA size is different,
		 * the option MUST be aligned appropriately.  See Section 6.2 in
		 * [3]." in RFC 4068 says should be done with an LLA size other
		 * than 6 bytes; section 6.2 in RFC 3775 (reference 3 in RFC 4068)
		 * says "Mobility options may have alignment requirements.  Following
		 * the convention in IPv6, these options are aligned in a packet so
		 * that multi-octet values within the Option Data field of each
		 * option fall on natural boundaries (i.e., fields of width n octets
		 * are placed at an integer multiple of n octets from the start of
		 * the header, for n = 1, 2, 4, or 8) [11]."
		 *
		 * Reference 11 in RFC 3775 is RFC 2460, the IPv6 spec; nothing
		 * in there seems to talk about inserting padding *inside* the
		 * data value of an option, so I'm not sure what the extra pad0
		 * is doing there, unless the idea is to arrange that the LLA is
		 * at least aligned on a 2-byte boundary, in which case presumably
		 * it's always present.  We'll assume that.
		 */
		if (len > 1) {
			/* Skip padding. */
			p += 1;
			len -= 1;
			proto_tree_add_text(field_tree, tvb,
					p, len, "Link-layer address: %s",
					bytestring_to_str(tvb_get_ptr(tvb, p, len), len, ':'));
		}
	}
}

static void
dissect_mip6_opt_mnid(const ip_tcp_opt *optp _U_, tvbuff_t *tvb, int offset,
                     guint optlen, packet_info *pinfo _U_, proto_tree *opt_tree)
{
	proto_tree *field_tree = NULL;
	proto_item *tf;
	int len, p;

	tf = proto_tree_add_text(opt_tree, tvb, offset, optlen, "%s", optp->name);
	field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

	proto_tree_add_item(field_tree, hf_mip6_mnid_subtype, tvb,
			offset + MIP6_MNID_SUBTYPE_OFF, MIP6_MNID_SUBTYPE_LEN, FALSE);

	p = offset + MIP6_MNID_MNID_OFF;
	len = optlen - MIP6_MNID_MNID_OFF;

	if (len > 0)
		proto_tree_add_text(field_tree, tvb, p, len, "Identifier: %s", tvb_format_text(tvb, p, len));
}

static void
dissect_pmip6_opt_ts(const ip_tcp_opt *optp _U_, tvbuff_t *tvb, int offset,
                     guint optlen, packet_info *pinfo _U_, proto_tree *opt_tree)
{
	const guint8 *reftime;

	reftime = tvb_get_ptr(tvb, offset + 2, optlen);
	proto_tree_add_bytes_format(opt_tree, hf_pmip6_timestamp, tvb, offset , 10,
			reftime, "Timestamp: %s", ntp_fmt_ts(reftime));
}

static const ip_tcp_opt mip6_opts[] = {
{
	PAD1,						/* 0 Pad1 [RFC3775] */
	"Pad1",
	NULL,
	NO_LENGTH,
	0,
	NULL,
},
{
	PADN,						/* 1 PadN [RFC3775] */
	"PadN",
	&ett_mip6_opt_padn,
	VARIABLE_LENGTH,
	0,
	dissect_mip6_opt_padn
},
{
	BRA,						/* 2 Binding Refresh Advice */
	"Binding Refresh Advice",
	&ett_mip6_opt_bra,
	FIXED_LENGTH,
	MIP6_BRA_LEN,
	dissect_mip6_opt_bra
},
{
	ACOA,						/*3  Alternate Care-of Address */
	"Alternate Care-of Address",
	&ett_mip6_opt_acoa,
	FIXED_LENGTH,
	MIP6_ACOA_LEN,
	dissect_mip6_opt_acoa
},
{
	MNP,						/* 6 Mobile Network Prefix Option */
	"Mobile Network Prefix",
	&ett_nemo_opt_mnp,
	FIXED_LENGTH,
	NEMO_MNP_LEN,
	dissect_nemo_opt_mnp
},
{
	NI,							/* 4 Nonce Indices */
	"Nonce Indices",
	&ett_mip6_opt_ni,
	FIXED_LENGTH,
	MIP6_NI_LEN,
	dissect_mip6_opt_ni
},
{
	AUTD,						/* 5 Authorization Data */
	"Authorization Data",
	&ett_mip6_opt_bad,
	VARIABLE_LENGTH,
	0,
	dissect_mip6_opt_bad
},
{
	MHLLA,						/* 7 Mobility Header Link-Layer Address option [RFC5568] */
	"Mobility Header Link-Layer Address option",
	&ett_fmip6_opt_lla,
	VARIABLE_LENGTH,
	FMIP6_LLA_MINLEN,
	dissect_fmip6_opt_lla
},
{
	MNID,						/* 8 MN-ID-OPTION-TYPE */
	"Mobile Node Identifier",
	&ett_mip6_opt_mnid,
	VARIABLE_LENGTH,
	MIP6_MNID_MINLEN,
	dissect_mip6_opt_mnid
},
{
	HNP,
	"Home Network Prefix",
	&ett_pmip6_opt_hnp,
	FIXED_LENGTH,
	NEMO_MNP_LEN,
	dissect_nemo_opt_mnp
},
{
	TS,
	"Timestamp",
	&ett_pmip6_opt_ts,
	FIXED_LENGTH,
	PMIP6_TS_LEN,
	dissect_pmip6_opt_ts
},
};

#define N_MIP6_OPTS	(sizeof mip6_opts / sizeof mip6_opts[0])

/* Mobility Option types 
 * http://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml
 */

static const value_string nas_eps_emm_lcs_ind_vals[] = {
	{ 0,	"Pad1"},										/* RFC3775 */ 
	{ 1,	"PadN"},										/* RFC3775 */ 
	{ 2,	"Binding Refresh Advice"},						/* RFC3775 */ 
	{ 3,	"Alternate Care-of Address"},					/* RFC3775 */ 
	{ 4,	"Nonce Indices"},								/* RFC3775 */ 
	{ 5,	"Authorization Data"},							/* RFC3775 */ 
	{ 6,	"Mobile Network Prefix Option"},				/* RFC3963 */ 
	{ 7,	"Mobility Header Link-Layer Address option"},	/* RFC5568 */ 
	{ 8,	"MN-ID-OPTION-TYPE"},							/* RFC4283 */ 
	{ 9,	"AUTH-OPTION-TYPE"},							/* RFC4285 */ 
	{ 10,	"MESG-ID-OPTION-TYPE"},							/* RFC4285 */ 
	{ 11,	"CGA Parameters Request"},						/* RFC4866 */ 
	{ 12,	"CGA Parameters"},								/* RFC4866 */ 
	{ 13,	"Signature"},									/* RFC4866 */ 
	{ 14,	"Permanent Home Keygen Token"},					/* RFC4866 */ 
	{ 15,	"Care-of Test Init"},							/* RFC4866 */ 
	{ 16,	"Care-of Test"},								/* RFC4866 */ 
	{ 17,	"DNS-UPDATE-TYPE"},								/* RFC5026 */ 
	{ 18,	"Experimental Mobility Option"},				/* RFC5096 */ 
	{ 19,	"Vendor Specific Mobility Option"},				/* RFC5094 */ 
	{ 20,	"Service Selection Mobility Option"},			/* RFC5149 */ 
	{ 21,	"Binding Authorization Data for FMIPv6 (BADF)"}, /* RFC5568 */ 
	{ 22,	"Home Network Prefix Option"},					/* RFC5213 */ 
	{ 23,	"Handoff Indicator Option"},					/* RFC5213 */ 
	{ 24,	"Access Technology Type Option"},				/* RFC5213 */ 
	{ 25,	"Mobile Node Link-layer Identifier Option"},	/* RFC5213 */ 
	{ 26,	"Link-local Address Option"},					/* RFC5213 */ 
	{ 27,	"Timestamp Option"},							/* RFC5213 */ 
	{ 28,	"Restart Counter"},								/* RFC-ietf-netlmm-pmipv6-heartbeat-07 */ 
	{ 29,	"IPv4 Home Address"},							/* RFC5555 */ 
	{ 30,	"IPv4 Address Acknowledgement"},				/* RFC5555 */ 
	{ 31,	"NAT Detection"},								/* RFC5555 */ 
	{ 32,	"IPv4 Care-of Address"},						/* RFC5555 */ 
	{ 33,	"GRE Key Option"},								/* RFC-ietf-netlmm-grekey-option-09 */ 
	{ 34,	"Mobility Header IPv6 Address/Prefix"},			/* RFC5568 */ 
	{ 35,	"Binding Identifier"},							/* RFC-ietf-monami6-multiplecoa-14 */ 
	{ 0, NULL }
};

/* Like "dissect_ip_tcp_options()", but assumes the length of an option
 * *doesn't* include the type and length bytes.  The option parsers,
 * however, are passed a length that *does* include them.
 */
static void
dissect_mipv6_options(tvbuff_t *tvb, int offset, guint length,
                      const ip_tcp_opt *opttab, int nopts, int eol,
                      packet_info *pinfo, proto_tree *opt_tree)
{
	proto_item		 *ti;
	guchar            opt;
	const ip_tcp_opt  *optp;
	opt_len_type      len_type;
	unsigned int      optlen;
	const char        *name;
	char              name_str[7+1+1+2+2+1+1];	/* "Unknown (0x%02x)" */
	void              (*dissect)(const struct ip_tcp_opt *, tvbuff_t *,
			             int, guint, packet_info *, proto_tree *);
	guint             len;

	while (length > 0) {
		opt = tvb_get_guint8(tvb, offset);
		for (optp = &opttab[0]; optp < &opttab[nopts]; optp++) {
			if (optp->optcode == opt)
				break;
		}
		if (optp == &opttab[nopts]) {
			/* We assume that the only NO_LENGTH options are Pad1 options,
			 * so that we can treat unknown options as VARIABLE_LENGTH with a
			 * minimum of 0, and at least be able to move on to the next option
			 * by using the length in the option.
			 */
			optp = NULL;	/* indicate that we don't know this option */
			len_type = VARIABLE_LENGTH;
			optlen = 0;
			g_snprintf(name_str, sizeof name_str, "Unknown (0x%02x)", opt);
			name = name_str;
			dissect = NULL;
		} else {
			len_type = optp->len_type;
			optlen = optp->optlen;
			name = optp->name;
			dissect = optp->dissect;
		}
		--length;      /* account for type byte */
		if (len_type != NO_LENGTH) {
			/* Option has a length. Is it in the packet? */
			if (length == 0) {
				/* Bogus - packet must at least include
				 * option code byte and length byte!
				 */
				proto_tree_add_text(opt_tree, tvb, offset,      1,
						"%s (length byte past end of options)", name);
				return;
			}
			len = tvb_get_guint8(tvb, offset + 1);  /* Size specified in option */
			--length;    /* account for length byte */
			if (len > length) {
				/* Bogus - option goes past the end of the header. */
				proto_tree_add_text(opt_tree, tvb, offset,      length,
						"%s (option length = %u byte%s says option goes past end of options)",
						name, len, plurality(len, "", "s"));
				return;
			} else if (len_type == FIXED_LENGTH && len != optlen) {
				/* Bogus - option length isn't what it's supposed to be for this
				   option. */
				proto_tree_add_text(opt_tree, tvb, offset, len + 2,
						"%s (with option length = %u byte%s; should be %u)", name,
						len, plurality(len, "", "s"), optlen);
				return;
			} else if (len_type == VARIABLE_LENGTH && len < optlen) {
				/* Bogus - option length is less than what it's supposed to be for
				   this option. */
				proto_tree_add_text(opt_tree, tvb, offset, len + 2,
						"%s (with option length = %u byte%s; should be >= %u)", name,
						len, plurality(len, "", "s"), optlen);
				return;
			} else {
				ti = proto_tree_add_item(opt_tree, hf_mip6_mobility_opt, tvb, offset, 1, FALSE);
				if (optp == NULL) {
					proto_item_append_text(ti, "(%u byte%s)",len, plurality(len, "", "s"));
					proto_tree_add_text(opt_tree, tvb, offset+2,len,"[Not disseted yet]");
				} else {
					if (dissect != NULL) {
						/* Option has a dissector. */
						if (opt == MHLLA)
							(*dissect)(optp, tvb, offset,
								   len + 2 + FMIP6_LLA_OPTCODE_LEN, pinfo, opt_tree);
						else
							(*dissect)(optp, tvb, offset, len + 2, pinfo, opt_tree);
					}
				}
				/* RFC4068 Section 6.4.4
				 *   Length         The size of this option in octets not including the
				 *                  Type, Length, and Option-Code fields.
				 */
				if (opt == MHLLA)
					offset += len + 2 + FMIP6_LLA_OPTCODE_LEN;
				else
					offset += len + 2;
			}
			if (opt == MHLLA)
				length -= (len + FMIP6_LLA_OPTCODE_LEN);
			else
				length -= len;
		} else {
			proto_tree_add_text(opt_tree, tvb, offset, 1, "%s", name);
			offset += 1;
		}
		if (opt == eol)
			break;
	}
}

/* Function to dissect mobility options */
static int
dissect_mip6_options(tvbuff_t *tvb, proto_tree *mip6_tree, int offset, int len,
                     packet_info *pinfo)
{
	proto_tree *opts_tree = NULL;
	proto_item *ti;

	if (!mip6_tree)
		return len;

	ti = proto_tree_add_text(mip6_tree, tvb, offset, len, "Mobility Options");
	opts_tree = proto_item_add_subtree(ti, ett_mip6);

	dissect_mipv6_options(tvb, offset, len, mip6_opts, N_MIP6_OPTS, -1, pinfo, opts_tree);

	return len;
}

/* Function that dissects the whole MIPv6 packet */
static void
dissect_mip6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *mip6_tree = NULL;
	proto_item *ti;
	guint8     type, pproto;
	guint      len, offset = 0, start_offset = offset;

	/* Make entries in Protocol column and Info column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MIPv6");
	col_clear(pinfo->cinfo, COL_INFO);

	len = (tvb_get_guint8(tvb, MIP6_HLEN_OFF) + 1) * 8;
	pproto = tvb_get_guint8(tvb, MIP6_PROTO_OFF);
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
		if (proto_nemo == 1) {
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "NEMO");
		}
		break;
	case BA:
		offset = dissect_mip6_ba(tvb, mip6_tree, pinfo);
		if (proto_nemo == 1) {
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "NEMO");
		}
		break;
	case BE:
		offset = dissect_mip6_be(tvb, mip6_tree, pinfo);
		break;
	case FBU:
		offset = dissect_fmip6_fbu(tvb, mip6_tree, pinfo);
		break;
	case FBACK:
		offset = dissect_fmip6_fback(tvb, mip6_tree, pinfo);
		break;
	case FNA:
		offset = dissect_fmip6_fna(tvb, mip6_tree, pinfo);
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
		dissect_mip6_options(tvb, mip6_tree, offset, len, pinfo);
	}

	if (type == FNA && pproto == IP_PROTO_IPV6) {
		tvbuff_t *ipv6_tvb;

		ipv6_tvb = tvb_new_subset_remaining(tvb, len + 8);

		/* Call the IPv6 dissector */
		dissector_try_port(ip_dissector_table, pproto, ipv6_tvb, pinfo, tree);

		col_set_str(pinfo->cinfo, COL_INFO, "Fast Neighbor Advertisement[Fast Binding Update]");
	}
}

/* Register the protocol with Wireshark */
void 
proto_register_mip6(void)
{
	/* Setup list of header fields */
	static hf_register_info hf[] = {

	{ &hf_mip6_proto,           { "Payload protocol", "mip6.proto",
	                              FT_UINT8, BASE_DEC, NULL, 0,
	                              NULL, HFILL }},
	{ &hf_mip6_hlen,            { "Header length", "mip6.hlen",
	                              FT_UINT8, BASE_DEC, NULL, 0,
	                              NULL, HFILL }},
	{ &hf_mip6_mhtype,          { "Mobility Header Type", "mip6.mhtype",
	                              FT_UINT8, BASE_DEC, VALS(mip6_mh_types), 0,
	                              NULL, HFILL }},
	{ &hf_mip6_reserved,        { "Reserved", "mip6.reserved",
	                              FT_UINT8, BASE_HEX, NULL, 0,
	                              NULL, HFILL }},
	{ &hf_mip6_csum,            { "Checksum", "mip6.csum",
	                              FT_UINT16, BASE_HEX, NULL, 0,
	                              "Header Checksum", HFILL }},

	{ &hf_mip6_hoti_cookie,     { "Home Init Cookie", "mip6.hoti.cookie",
	                              FT_UINT64, BASE_HEX, NULL, 0,
	                              NULL, HFILL }},

	{ &hf_mip6_coti_cookie,     { "Care-of Init Cookie", "mip6.coti.cookie",
	                              FT_UINT64, BASE_HEX, NULL, 0,
	                              NULL, HFILL }},

	{ &hf_mip6_hot_nindex,      { "Home Nonce Index", "mip6.hot.nindex",
	                              FT_UINT16, BASE_DEC, NULL, 0,
	                              NULL, HFILL }},
	{ &hf_mip6_hot_cookie,      { "Home Init Cookie", "mip6.hot.cookie",
	                              FT_UINT64, BASE_HEX, NULL, 0,
	                              NULL, HFILL }},
	{ &hf_mip6_hot_token,       { "Home Keygen Token", "mip6.hot.token",
	                               FT_UINT64, BASE_HEX, NULL, 0,
	                               NULL, HFILL }},

	{ &hf_mip6_cot_nindex,      { "Care-of Nonce Index", "mip6.cot.nindex",
	                              FT_UINT16, BASE_DEC, NULL, 0,
	                              NULL, HFILL }},
	{ &hf_mip6_cot_cookie,      { "Care-of Init Cookie", "mip6.cot.cookie",
	                              FT_UINT64, BASE_HEX, NULL, 0,
	                              NULL, HFILL }},
	{ &hf_mip6_cot_token,       { "Care-of Keygen Token", "mip6.cot.token",
	                              FT_UINT64, BASE_HEX, NULL, 0,
	                              NULL, HFILL }},

	{ &hf_mip6_bu_seqnr,        { "Sequence number", "mip6.bu.seqnr",
	                              FT_UINT16, BASE_DEC, NULL, 0,
	                              NULL, HFILL }},
	{ &hf_mip6_bu_a_flag,       { "Acknowledge (A) flag", "mip6.bu.a_flag",
	                              FT_BOOLEAN, 8, TFS(&mip6_bu_a_flag_value),
	                              0x80, NULL, HFILL }},
	{ &hf_mip6_bu_h_flag,       { "Home Registration (H) flag",
	                              "mip6.bu.h_flag",
	                              FT_BOOLEAN, 8, TFS(&mip6_bu_h_flag_value),
	                              0x40, NULL, HFILL }},
	{ &hf_mip6_bu_l_flag,       { "Link-Local Compatibility (L) flag",
	                              "mip6.bu.l_flag",
	                              FT_BOOLEAN, 8, TFS(&mip6_bu_l_flag_value),
	                              0x20, "Home Registration (H) flag", HFILL }},
	{ &hf_mip6_bu_k_flag,       { "Key Management Compatibility (K) flag",
	                              "mip6.bu.k_flag",
	                              FT_BOOLEAN, 8, TFS(&mip6_bu_k_flag_value),
	                              0x10, NULL,
	                              HFILL }},
	{ &hf_mip6_bu_m_flag,       { "MAP Registration Compatibility (M) flag",
	                              "mip6.bu.m_flag",
	                              FT_BOOLEAN, 8, TFS(&mip6_bu_m_flag_value),
	                              0x08, NULL,
	                              HFILL }},
	{ &hf_nemo_bu_r_flag,       { "Mobile Router (R) flag", 
	                              "nemo.bu.r_flag",
	                              FT_BOOLEAN, 8, TFS(&nemo_bu_r_flag_value),
	                              0x04, NULL,
	                              HFILL }},
	{ &hf_proxy_bu_p_flag,      { "Proxy Registration (P) flag", 
	                              "mip6.bu.p_flag",
	                              FT_BOOLEAN, 8, TFS(&proxy_bu_p_flag_value),
	                              0x02, NULL,
	                              HFILL }},
	{ &hf_mip6_bu_lifetime,     { "Lifetime", "mip6.bu.lifetime",
	                              FT_UINT16, BASE_DEC, NULL, 0,
	                              NULL, HFILL }},

	{ &hf_mip6_ba_status,       { "Status", "mip6.ba.status",
	                              FT_UINT8, BASE_DEC,
	                              VALS(&mip6_ba_status_value), 0,
	                              "Binding Acknowledgement status", HFILL }},
	{ &hf_mip6_ba_k_flag,       { "Key Management Compatibility (K) flag", 
	                              "mip6.ba.k_flag",
	                              FT_BOOLEAN, 8, TFS(&mip6_bu_k_flag_value),
	                              0x80, NULL,
	                              HFILL }},
	{ &hf_nemo_ba_r_flag,       { "Mobile Router (R) flag",
	                              "nemo.ba.r_flag",
	                              FT_BOOLEAN, 8, TFS(&nemo_bu_r_flag_value),
	                              0x40, NULL,
	                              HFILL }},
	{ &hf_proxy_ba_p_flag,      { "Proxy Registration (P) flag",
	                              "proxy.ba.p_flag",
	                              FT_BOOLEAN, 8, TFS(&proxy_bu_p_flag_value),
	                              0x20, NULL,
	                              HFILL }},

	{ &hf_mip6_ba_seqnr,        { "Sequence number", "mip6.ba.seqnr",
	                              FT_UINT16, BASE_DEC, NULL, 0,
	                              NULL, HFILL }},
	{ &hf_mip6_ba_lifetime,     { "Lifetime", "mip6.ba.lifetime",
	                              FT_UINT16, BASE_DEC, NULL, 0,
	                              NULL, HFILL }},

	{ &hf_mip6_be_status,       { "Status", "mip6.be.status",
	                              FT_UINT8, BASE_DEC,
	                              VALS(&mip6_be_status_value), 0,
	                              "Binding Error status", HFILL }},
	{ &hf_mip6_be_haddr,        { "Home Address", "mip6.be.haddr",
	                              FT_IPv6, BASE_NONE, NULL, 0,
	                              NULL, HFILL }},

	{ &hf_fmip6_fbu_seqnr,      { "Sequence number", "fmip6.fbu.seqnr",
	                              FT_UINT16, BASE_DEC, NULL, 0,
	                              NULL, HFILL }},
	{ &hf_fmip6_fbu_a_flag,     { "Acknowledge (A) flag", "fmip6.fbu.a_flag",
	                              FT_BOOLEAN, 8, TFS(&fmip6_fbu_a_flag_value),
	                              0x80, NULL, HFILL }},
	{ &hf_fmip6_fbu_h_flag,     { "Home Registration (H) flag",
	                              "fmip6.fbu.h_flag",
	                              FT_BOOLEAN, 8, TFS(&fmip6_fbu_h_flag_value),
	                              0x40, NULL, HFILL }},
	{ &hf_fmip6_fbu_l_flag,     { "Link-Local Compatibility (L) flag",
	                              "fmip6.fbu.l_flag",
	                              FT_BOOLEAN, 8, TFS(&fmip6_fbu_l_flag_value),
	                              0x20, "Home Registration (H) flag", HFILL }},
	{ &hf_fmip6_fbu_k_flag,     { "Key Management Compatibility (K) flag",
	                              "fmip6.fbu.k_flag",
	                              FT_BOOLEAN, 8, TFS(&fmip6_fbu_k_flag_value),
	                              0x10, NULL,
	                              HFILL }},
	{ &hf_fmip6_fbu_lifetime,   { "Lifetime", "fmip6.fbu.lifetime",
	                              FT_UINT16, BASE_DEC, NULL, 0,
	                              NULL, HFILL }},

	{ &hf_fmip6_fback_status,   { "Status", "fmip6.fback.status",
	                              FT_UINT8, BASE_DEC,
	                              VALS(&fmip6_fback_status_value), 0,
	                              "Fast Binding Acknowledgement status", HFILL }},
	{ &hf_fmip6_fback_k_flag,   { "Key Management Compatibility (K) flag",
	                              "fmip6.fback.k_flag",
	                              FT_BOOLEAN, 8, TFS(&fmip6_fbu_k_flag_value),
	                              0x80, NULL,
	                              HFILL }},
	{ &hf_fmip6_fback_seqnr,    { "Sequence number", "fmip6.fback.seqnr",
	                             FT_UINT16, BASE_DEC, NULL, 0,
	                             NULL, HFILL }},
	{ &hf_fmip6_fback_lifetime, { "Lifetime", "fmip6.fback.lifetime",
	                              FT_UINT16, BASE_DEC, NULL, 0,
	                              NULL, HFILL }},

	{ &hf_mip6_bra_interval,    { "Refresh interval", "mip6.bra.interval",
	                              FT_UINT16, BASE_DEC, NULL, 0,
	                             NULL, HFILL }},

	{ &hf_mip6_acoa_acoa,       { "Alternate care-of address", "mip6.acoa.acoa",
	                              FT_IPv6, BASE_NONE, NULL, 0,
	                              "Alternate Care-of address", HFILL }},

	{ &hf_mip6_ni_hni,          { "Home nonce index", "mip6.ni.hni",
	                              FT_UINT16, BASE_DEC, NULL, 0,
	                              NULL, HFILL }},
	{ &hf_mip6_ni_cni,          { "Care-of nonce index", "mip6.ni.cni",
	                              FT_UINT16, BASE_DEC, NULL, 0,
	                              NULL, HFILL }},

	{ &hf_mip6_bad_auth,        { "Authenticator", "mip6.bad.auth",
	                              FT_BYTES, BASE_NONE, NULL, 0,
	                              NULL, HFILL }},

	{ &hf_fmip6_lla_optcode,    { "Option-Code", "mip6.lla.optcode",
	                              FT_UINT8, BASE_DEC, VALS(&fmip6_lla_optcode_value), 0,
	                              NULL, HFILL }},

	{ &hf_nemo_mnp_pfl,         { "Mobile Network Prefix Length", "nemo.mnp.pfl",
	                              FT_UINT8, BASE_DEC, NULL, 0,
	                              NULL, HFILL }},

	{ &hf_nemo_mnp_mnp,         { "Mobile Network Prefix", "nemo.mnp.mnp",
	                              FT_IPv6, BASE_NONE, NULL, 0,
	                              NULL, HFILL }},

	{ &hf_mip6_mnid_subtype,    { "Subtype", "mip6.mnid.subtype",
                                      FT_UINT8, BASE_DEC, VALS(&mip6_mnid_subtype_value), 0,
                                      NULL, HFILL }},

	{ &hf_pmip6_timestamp,      { "Timestamp", "pmip6.timestamp",
                                      FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

	{ &hf_mip6_mobility_opt,      { "Mobility Options", "pmip6.mobility_opt",
                                      FT_UINT8, BASE_DEC, VALS(nas_eps_emm_lcs_ind_vals), 0, NULL, HFILL }},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_mip6,
		&ett_mip6_opt_padn,
		&ett_mip6_opt_bra,
		&ett_mip6_opt_acoa,
		&ett_mip6_opt_ni,
		&ett_mip6_opt_bad,
		&ett_fmip6_opt_lla,
		&ett_nemo_opt_mnp,
		&ett_mip6_opt_mnid,
		&ett_pmip6_opt_hnp,
		&ett_pmip6_opt_ts
	};

	/* Register the protocol name and description */
	proto_mip6 = proto_register_protocol("Mobile IPv6 / Network Mobility", "MIPv6", "mipv6");

	/* Register the dissector by name */
	/* register_dissector("mipv6", dissect_nemo, proto_nemo); */

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
        ip_dissector_table = find_dissector_table("ip.proto");
}
