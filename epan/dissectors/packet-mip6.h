/* packet-mip6.h
 *
 * $Id$
 *
 * Definitions for Mobile IPv6 dissection (RFC 3775)
 * and Fast Handover for Mobile IPv6 (FMIPv6, RFC 4068)
 * Copyright 2003 Oy L M Ericsson Ab <teemu.rinta-aho@ericsson.fi>
 *
 * FMIPv6 support added by Martin Andre <andre@clarinet.u-strasbg.fr>
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

#ifndef __PACKET_MIP6_H_DEFINED__
#define __PACKET_MIP6_H_DEFINED__

/* Mobility Header types */
typedef enum {
	BRR  = 0,
	HOTI = 1,
	COTI = 2,
	HOT  = 3,
	COT  = 4,
	BU   = 5,
	BA   = 6,
	BE    = 7,
	FBU   = 8,
	FBACK = 9,
	FNA   = 10
} mhTypes;

static const value_string mip6_mh_types[] = {
	{BRR,   "Binding Refresh Request"},
	{HOTI,  "Home Test Init"},
	{COTI,  "Care-of Test Init"},
	{HOT,   "Home Test"},
	{COT,   "Care-of Test"},
	{BU,    "Binding Update"},
	{BA,    "Binding Acknowledgement"},
	{BE,    "Binding Error"},
	{FBU,   "Fast Binding Update"},
	{FBACK, "Fast Binding Acknowledgment"},
	{FNA,   "Fast Neighbor Advertisement"},
	{0,     NULL}
};

/* Mobility Option types 
 * http://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml
 */
typedef enum {
	PAD1 = 0,	/* 0 Pad1 [RFC3775] */
	PADN = 1,	/* 1 PadN [RFC3775] */
	BRA  = 2,	/* 2 Binding Refresh Advice */
	ACOA = 3,	/* 3 Alternate Care-of Address */
	NI   = 4,	/* 4 Nonce Indices */
	AUTD = 5,	/* 5 Authorization Data */
	MNP  = 6,	/* 6 Mobile Network Prefix Option */
	MHLLA  = 7,	/* 7 Mobility Header Link-Layer Address option [RFC5568] */
	MNID = 8,	/* 8 MN-ID-OPTION-TYPE */
				/* 9 AUTH-OPTION-TYPE */
				/* 10 MESG-ID-OPTION-TYPE [RFC4285]  */
				/* 11 CGA Parameters Request [RFC4866]  */
				/* 12 CGA Parameters [RFC4866]  */
				/* 13 Signature [RFC4866]  */
				/* 14 Permanent Home Keygen Token [RFC4866]  */ 
				/* 15 Care-of Test Init [RFC4866]  */
				/* 16 Care-of Test [RFC4866]  */
				/* 17 DNS-UPDATE-TYPE [RFC5026]  */
				/* 18 Experimental Mobility Option [RFC5096]  */
				/* 19 Vendor Specific Mobility Option [RFC5094]  */
				/* 20 Service Selection Mobility Option [RFC5149]  */
				/* 21 Binding Authorization Data for FMIPv6 (BADF) [RFC5568]  */
	HNP  = 22,	/* Home Network Prefix  */
				/* 22 Home Network Prefix Option [RFC5213]   */
				/* 23 Handoff Indicator Option [RFC5213]   */
				/* 24 Access Technology Type Option [RFC5213]  */ 
				/* 25 Mobile Node Link-layer Identifier Option [RFC5213]  */ 
				/* 26 Link-local Address Option [RFC5213   */
	TS   = 27	/* Timestamp */
				/* 28 Restart Counter [RFC-ietf-netlmm-pmipv6-heartbeat-07] */ 
				/* 29 IPv4 Home Address [RFC5555]  */
				/* 30 IPv4 Address Acknowledgement [RFC5555] */ 
				/* 31 NAT Detection [RFC5555]  */
				/* 32 IPv4 Care-of Address [RFC5555]  */
				/* 33 GRE Key Option [RFC-ietf-netlmm-grekey-option-09]  */
				/* 34 Mobility Header IPv6 Address/Prefix [RFC5568]  */
				/* 35 Binding Identifier [RFC-ietf-monami6-multiplecoa-14]  */

} optTypes;

/* Binding Update flag description */
static const true_false_string mip6_bu_a_flag_value = {
	"Binding Acknowledgement requested",
	"Binding Acknowledgement not requested"
};

static const true_false_string mip6_bu_h_flag_value = {
	"Home Registration",
	"No Home Registration"
};

static const true_false_string mip6_bu_l_flag_value = {
	"Link-Local Address Compatibility",
	"No Link-Local Address Compatibility"
};

static const true_false_string mip6_bu_k_flag_value = {
	"Key Management Mobility Compatibility",
	"No Key Management Mobility Compatibility"
};

static const true_false_string mip6_bu_m_flag_value = {
	"MAP Registration Compatibility",
	"No MAP Registration Compatibility",
};

static const true_false_string nemo_bu_r_flag_value = {
	"Mobile Router Compatibility",
	"No Mobile Router Compatibility"
};

static const true_false_string proxy_bu_p_flag_value = {
	"Proxy Registration",
	"No Proxy Registration"
};

/* Binding Acknowledgement status values */
static const value_string mip6_ba_status_value[] = {
	{   0, "Binding Update accepted" },
	{   1, "Accepted but prefix discovery necessary" },
	{ 128, "Reason unspecified" },
	{ 129, "Administratively prohibited" },
	{ 130, "Insufficient resources" },
	{ 131, "Home registration not supported" },
	{ 132, "Not home subnet" },
	{ 133, "Not home agent for this mobile node" },
	{ 134, "Duplicate Address Detection failed" },
	{ 135, "Sequence number out of window" },
	{ 136, "Expired home nonce index" },
	{ 137, "Expired care-of nonce index" },
	{ 138, "Expired nonces" },
	{ 139, "Registration type change disallowed" },
	{ 140, "Mobile Router Operation not permitted" },
	{ 141, "Invalid Prefix" },
	{ 142, "Not Authorized for Prefix" },
	{ 143, "Mobile Network Prefix information unavailable" },
	{ 145, "Proxy Registration not supported by the LMA" },
	{ 146, "Proxy Registrations from this MAG not allowed" },
	{ 147, "No home address for this NAI" },
	{ 148, "Invalid Time Stamp Option" },
	{   0, NULL }
};

/* Binding Error status values */
static const value_string mip6_be_status_value[] = {
	{ 1, "Unknown binding for Home Address destination option" },
	{ 2, "Unrecognized MH type value" },
	{ 0, NULL }
};

/* Fast Binding Update flag description */
static const true_false_string fmip6_fbu_a_flag_value = {
	"Fast Binding Acknowledgement requested",
	"Fast Binding Acknowledgement not requested"
};

static const true_false_string fmip6_fbu_h_flag_value = {
	"Home Registration",
	"No Home Registration"
};

static const true_false_string fmip6_fbu_l_flag_value = {
	"Link-Local Address Compatibility",
	"No Link-Local Address Compatibility"
};

static const true_false_string fmip6_fbu_k_flag_value = {
	"Key Management Mobility Compatibility",
	"No Key Management Mobility Compatibility"
};

/* Fast Binding Acknowledgement status values */
static const value_string fmip6_fback_status_value[] = {
	{   0, "Fast Binding Update accepted" },
	{   1, "Accepted but use supplied NCoA" },
	{ 128, "Reason unspecified" },
	{ 129, "Administratively prohibited" },
	{ 130, "Insufficient resources" },
	{ 131, "Incorrect interface identifier length" },
	{   0, NULL }
};

/* MH LLA Option code */
static const value_string fmip6_lla_optcode_value[] = {
	{   2, "Link Layer Address of the MN" },
	{   0, NULL }
};

/* Mobile Node Identifier Option code */
static const value_string mip6_mnid_subtype_value[] = {
	{   1, "Network Access Identifier (NAI)" },
	{   0, NULL }
};

/* Message lengths */
#define MIP6_BRR_LEN          2
#define MIP6_HOTI_LEN        10
#define MIP6_COTI_LEN        10
#define MIP6_HOT_LEN         18
#define MIP6_COT_LEN         18
#define MIP6_BU_LEN           6
#define MIP6_BA_LEN           6
#define MIP6_BE_LEN          18
#define FMIP6_FBU_LEN         6
#define FMIP6_FBACK_LEN       6
#define FMIP6_FNA_LEN         2

/* Field offsets & lengths for mobility headers */
#define MIP6_PROTO_OFF        0
#define MIP6_HLEN_OFF         1
#define MIP6_TYPE_OFF         2
#define MIP6_RES_OFF          3
#define MIP6_CSUM_OFF         4
#define MIP6_DATA_OFF         6
#define MIP6_PROTO_LEN        1
#define MIP6_HLEN_LEN         1
#define MIP6_TYPE_LEN         1
#define MIP6_RES_LEN          1
#define MIP6_CSUM_LEN         2

#define MIP6_BRR_RES_OFF      6
#define MIP6_BRR_OPTS_OFF     8
#define MIP6_BRR_RES_LEN      2

#define MIP6_HOTI_RES_OFF     6
#define MIP6_HOTI_COOKIE_OFF  8
#define MIP6_HOTI_OPTS_OFF   16
#define MIP6_HOTI_RES_LEN     2
#define MIP6_HOTI_COOKIE_LEN  8

#define MIP6_COTI_RES_OFF     6
#define MIP6_COTI_COOKIE_OFF  8
#define MIP6_COTI_OPTS_OFF   16
#define MIP6_COTI_RES_LEN     2
#define MIP6_COTI_COOKIE_LEN  8

#define MIP6_HOT_INDEX_OFF    6
#define MIP6_HOT_COOKIE_OFF   8
#define MIP6_HOT_TOKEN_OFF   16
#define MIP6_HOT_OPTS_OFF    24
#define MIP6_HOT_INDEX_LEN    2
#define MIP6_HOT_COOKIE_LEN   8
#define MIP6_HOT_TOKEN_LEN    8

#define MIP6_COT_INDEX_OFF    6
#define MIP6_COT_COOKIE_OFF   8
#define MIP6_COT_TOKEN_OFF   16
#define MIP6_COT_OPTS_OFF    24
#define MIP6_COT_INDEX_LEN    2
#define MIP6_COT_COOKIE_LEN   8
#define MIP6_COT_TOKEN_LEN    8

#define MIP6_BU_SEQNR_OFF     6
#define MIP6_BU_FLAGS_OFF     8
#define MIP6_BU_RES_OFF       9
#define MIP6_BU_LIFETIME_OFF 10
#define MIP6_BU_OPTS_OFF     12
#define MIP6_BU_SEQNR_LEN     2
#define MIP6_BU_FLAGS_LEN     1
#define MIP6_BU_RES_LEN       1
#define MIP6_BU_LIFETIME_LEN  2

#define MIP6_BA_STATUS_OFF    6
#define MIP6_BA_FLAGS_OFF     7
#define MIP6_BA_SEQNR_OFF     8
#define MIP6_BA_LIFETIME_OFF 10
#define MIP6_BA_OPTS_OFF     12
#define MIP6_BA_STATUS_LEN    1
#define MIP6_BA_FLAGS_LEN     1
#define MIP6_BA_SEQNR_LEN     2
#define MIP6_BA_LIFETIME_LEN  2

#define MIP6_BE_STATUS_OFF    6
#define MIP6_BE_RES_OFF       7
#define MIP6_BE_HOA_OFF       8
#define MIP6_BE_OPTS_OFF     24
#define MIP6_BE_STATUS_LEN    1
#define MIP6_BE_RES_LEN       1
#define MIP6_BE_HOA_LEN      16

#define FMIP6_FBU_SEQNR_OFF     6
#define FMIP6_FBU_FLAGS_OFF     8
#define FMIP6_FBU_RES_OFF       9
#define FMIP6_FBU_LIFETIME_OFF 10
#define FMIP6_FBU_OPTS_OFF     12
#define FMIP6_FBU_SEQNR_LEN     2
#define FMIP6_FBU_FLAGS_LEN     1
#define FMIP6_FBU_RES_LEN       1
#define FMIP6_FBU_LIFETIME_LEN  2

#define FMIP6_FBACK_STATUS_OFF    6
#define FMIP6_FBACK_FLAGS_OFF     7
#define FMIP6_FBACK_SEQNR_OFF     8
#define FMIP6_FBACK_LIFETIME_OFF 10
#define FMIP6_FBACK_OPTS_OFF     12
#define FMIP6_FBACK_STATUS_LEN    1
#define FMIP6_FBACK_FLAGS_LEN     1
#define FMIP6_FBACK_SEQNR_LEN     2
#define FMIP6_FBACK_LIFETIME_LEN  2

#define FMIP6_FNA_RES_OFF     6
#define FMIP6_FNA_OPTS_OFF    8
#define FMIP6_FNA_RES_LEN     2

/* Field offsets & field and option lengths for mobility options.
 * The option length does *not* include the option type and length
 * fields.  The field offsets, however, do include the type and
 * length fields. */
#define MIP6_BRA_LEN          2
#define MIP6_BRA_RI_OFF       2
#define MIP6_BRA_RI_LEN       2

#define MIP6_ACOA_LEN        16
#define MIP6_ACOA_ACOA_OFF    2
#define MIP6_ACOA_ACOA_LEN   16

#define NEMO_MNP_LEN         18
#define NEMO_MNP_PL_OFF       3
#define NEMO_MNP_MNP_OFF      4
#define NEMO_MNP_MNP_LEN     16

#define MIP6_NI_LEN           4
#define MIP6_NI_HNI_OFF       2
#define MIP6_NI_CNI_OFF       4
#define MIP6_NI_HNI_LEN       2
#define MIP6_NI_CNI_LEN       2

#define MIP6_BAD_AUTH_OFF     2

#define FMIP6_LLA_MINLEN      1
#define FMIP6_LLA_OPTCODE_OFF 2
#define FMIP6_LLA_LLA_OFF     3
#define FMIP6_LLA_OPTCODE_LEN 1

#define MIP6_MNID_MINLEN      2
#define MIP6_MNID_SUBTYPE_OFF 2
#define MIP6_MNID_SUBTYPE_LEN 1
#define MIP6_MNID_MNID_OFF    3

#define PMIP6_TS_LEN          8

#endif /* __PACKET_MIP6_H_DEFINED__ */
