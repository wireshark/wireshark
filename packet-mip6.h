/* packet-mip6.h
 *
 * $Id: packet-mip6.h,v 1.1 2003/02/04 20:16:57 guy Exp $
 *
 * Definitions for Mobile IPv6 dissection (draft-ietf-mobileip-ipv6-20.txt)
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
    BE   = 7
} mhTypes;

static const value_string mip6_mh_types[] = {
    {BRR,  "Binding Refresh Request"},
    {HOTI, "Home Test Init"},
    {COTI, "Care-of Test Init"},
    {HOT,  "Home Test"},
    {COT,  "Care-of Test"},
    {BU,   "Binding Update"},
    {BA,   "Binding Acknowledgement"},
    {BE,   "Binding Error"},
    {0,    NULL}
};

/* Mobility Option types */
typedef enum {
    PAD1 = 0,
    PADN = 1,
    BRA  = 2,
    ACOA = 3,
    NI   = 4,
    BAD  = 5
} optTypes;

static const value_string mip6_opt_types[]= {
    {PAD1, "Pad1"},
    {PADN, "PadN"},
    {BRA,  "Binding Refresh Advice"},
    {ACOA, "Alternate Care-of Address"},
    {NI,   "Nonce Indices"},
    {BAD,  "Binding Authorization Data"},
    {0,    NULL}
};

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

/* Binding Acknowledgement status values */
static const value_string mip6_ba_status_value[] = {
    {   0, "Binding Update accepted" },
    { 128, "Reason unspecified" },
    { 129, "Adminstratively prohibited" },
    { 130, "Insufficient resources" },
    { 131, "Home registration not supported" },
    { 132, "Not home subnet" },
    { 133, "Not home agent for this mobile node" },
    { 134, "Duplicate address detection failed" },
    { 135, "Sequence number out of window" },
    { 136, "Expired home nonce index" },
    { 137, "Expired care-of nonce index" },
    { 138, "Expired nonces" },
    {   0, NULL }
};

/* Binding Error status values */
static const value_string mip6_be_status_value[] = {
    { 1, "Unknown binding for Home Address destination option" },
    { 2, "Unrecognized MH type value" },
    { 0, NULL }
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

/* Field offsets & lengths for mobility options */
#define MIP6_BRA_RI_OFF       2
#define MIP6_BRA_RI_LEN       2

#define MIP6_ACOA_ACOA_OFF    2
#define MIP6_ACOA_ACOA_LEN   16

#define MIP6_NI_HNI_OFF       2
#define MIP6_NI_CNI_OFF       4
#define MIP6_NI_HNI_LEN       2
#define MIP6_NI_CNI_LEN       2

#define MIP6_BAD_AUTH_OFF     2
#define MIP6_BAD_AUTH_LEN    12

#endif /* __PACKET_MIP6_H_DEFINED__ */
