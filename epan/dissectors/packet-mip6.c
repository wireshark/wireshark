/* packet-mip6.c
 *
 * $Id$
 *
 * Definitions and Routines for Mobile IPv6 dissection (RFC 3775)
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
#include <epan/expert.h>
#include <epan/sminmpec.h>

/* Mobility Header types */
typedef enum {
    MIP6_BRR    =  0,
    MIP6_HOTI   =  1,
    MIP6_MHCOTI =  2,
    MIP6_HOT    =  3,
    MIP6_MHCOT  =  4,
    MIP6_BU     =  5,
    MIP6_BA     =  6,
    MIP6_BE     =  7,
    MIP6_FBU    =  8,
    MIP6_FBACK  =  9,
    MIP6_FNA    = 10,
    MIP6_EMH    = 11,
    MIP6_HAS    = 12,
    MIP6_HB     = 13,
    MIP6_HI     = 14,
    MIP6_HAck   = 15,
    MIP6_BR     = 16,
} mhTypes;

/* http://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml */
static const value_string mip6_mh_types[] = {
    {MIP6_BRR,    "Binding Refresh Request"},           /* [RFC3775] */
    {MIP6_HOTI,   "Home Test Init"},                    /* [RFC3775] */
    {MIP6_MHCOTI, "Care-of Test Init"},                 /* [RFC3775] */
    {MIP6_HOT,    "Home Test"},                         /* [RFC3775] */
    {MIP6_MHCOT,  "Care-of Test"},                      /* [RFC3775] */
    {MIP6_BU,     "Binding Update"},                    /* [RFC3775] */
    {MIP6_BA,     "Binding Acknowledgement"},           /* [RFC3775] */
    {MIP6_BE,     "Binding Error"},                     /* [RFC3775] */
    {MIP6_FBU,    "Fast Binding Update"},               /* [RFC5568] */
    {MIP6_FBACK,  "Fast Binding Acknowledgment"},       /* [RFC5568] */
    {MIP6_FNA,    "Fast Neighbor Advertisement"},       /* [RFC5568] */
    {MIP6_EMH,    "Experimental Mobility Header"},      /* [RFC5096] */
    {MIP6_HAS,    "Home Agent Switch"},                 /* [RFC5142] */
    {MIP6_HB,     "Heartbeat"},                         /* [RFC5847] */
    {MIP6_HI,     "Handover Initiate"},                 /* [RFC5568] */
    {MIP6_HAck,   "Handover Acknowledge"},              /* [RFC5568] */
    {MIP6_BR,     "Binding Revocation"},                /* [RFC5846] */
    {0,      NULL}
};


/* Mobility Option types
 * http://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml
 */
typedef enum {
    MIP6_PAD1      =  0,        /*  0 Pad1 [RFC3775] */
    MIP6_PADN      =  1,        /*  1 PadN [RFC3775] */
    MIP6_BRA       =  2,        /*  2 Binding Refresh Advice */
    MIP6_ACOA      =  3,        /*  3 Alternate Care-of Address */
    MIP6_NI        =  4,        /*  4 Nonce Indices */
    MIP6_AUTD      =  5,        /*  5 Authorization Data */
    MIP6_MNP       =  6,        /*  6 Mobile Network Prefix Option */
    MIP6_MHLLA     =  7,        /*  7 Mobility Header Link-Layer Address option [RFC5568] */
    MIP6_MNID      =  8,        /*  8 MN-ID-OPTION-TYPE */
    MIP6_AUTH      =  9,        /*  9 AUTH-OPTION-TYPE */
    MIP6_MESGID    = 10,        /* 10 MESG-ID-OPTION-TYPE [RFC4285]  */
    MIP6_CGAPR     = 11,        /* 11 CGA Parameters Request [RFC4866]  */
    MIP6_CGAR      = 12,        /* 12 CGA Parameters [RFC4866]  */
    MIP6_SIGN      = 13,        /* 13 Signature [RFC4866]  */
    MIP6_PHKT      = 14,        /* 14 Permanent Home Keygen Token [RFC4866]  */
    MIP6_MOCOTI    = 15,        /* 15 Care-of Test Init [RFC4866]  */
    MIP6_MOCOT     = 16,        /* 16 Care-of Test [RFC4866]  */
    MIP6_DNSU      = 17,        /* 17 DNS-UPDATE-TYPE [RFC5026]  */
    MIP6_EM        = 18,        /* 18 Experimental Mobility Option [RFC5096]  */
    MIP6_VSM       = 19,        /* 19 Vendor Specific Mobility Option [RFC5094]  */
    MIP6_SSM       = 20,        /* 20 Service Selection Mobility Option [RFC5149]  */
    MIP6_BADFF     = 21,        /* 21 Binding Authorization Data for FMIPv6 (BADF) [RFC5568]  */
    MIP6_HNP       = 22,        /* 22 Home Network Prefix Option [RFC5213]   */
    MIP6_MOHI      = 23,        /* 23 Handoff Indicator Option [RFC5213]   */
    MIP6_ATT       = 24,        /* 24 Access Technology Type Option [RFC5213]  */
    MIP6_MNLLI     = 25,        /* 25 Mobile Node Link-layer Identifier Option [RFC5213]  */
    MIP6_LLA       = 26,        /* 26 Link-local Address Option [RFC5213   */
    MIP6_TS        = 27,        /* 27 Timestamp */
    MIP6_RC        = 28,        /* 28 Restart Counter [RFC5847] */
    MIP6_IPV4HA    = 29,        /* 29 IPv4 Home Address [RFC5555]  */
    MIP6_IPV4AA    = 30,        /* 30 IPv4 Address Acknowledgement [RFC5555] */
    MIP6_NATD      = 31,        /* 31 NAT Detection [RFC5555]  */
    MIP6_IPV4COA   = 32,        /* 32 IPv4 Care-of Address [RFC5555]  */
    MIP6_GREK      = 33,        /* 33 GRE Key Option [RFC5845]  */
    MIP6_MHIPV6AP  = 34,        /* 34 Mobility Header IPv6 Address/Prefix [RFC5568]  */
    MIP6_BI        = 35,        /* 35 Binding Identifier [RFC5648]  */
    MIP6_IPV4HAREQ = 36,        /* 36 IPv4 Home Address Request [RFC5844] */
    MIP6_IPV4HAREP = 37,        /* 37 IPv4 Home Address Reply [RFC5844] */
    MIP6_IPV4DRA   = 38,        /* 38 IPv4 Default-Router Address [RFC5844] */
    MIP6_IPV4DSM   = 39,        /* 39 IPv4 DHCP Support Mode [RFC5844] */
    MIP6_CR        = 40,        /* 40 Context Request Option [RFC5949] */
    MIP6_LMAA      = 41,        /* 41 Local Mobility Anchor Address Option [RFC5949] */
    MIP6_MNLLAII   = 42,        /* 42 Mobile Node Link-local Address Interface Identifier Option [RFC5949] */
    MIP6_TB        = 43,        /* 43 Transient Binding [RFC-ietf-mipshop-transient-bce-pmipv6-07] */
    MIP6_FS        = 44,        /* 44 Flow Summary Mobility Option [RFC-ietf-mext-flow-binding-11] */
    MIP6_FI        = 45,        /* 45 Flow Identification Mobility Option [RFC-ietf-mext-flow-binding-11]] */

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

static const true_false_string mip6_nemo_bu_r_flag_value = {
    "Mobile Router Compatibility",
    "No Mobile Router Compatibility"
};

static const true_false_string pmip6_bu_p_flag_value = {
    "Proxy Registration",
    "No Proxy Registration"
};

static const true_false_string mip6_bu_f_flag_value = {
    "Forcing UDP encapsulation used",
    "No Forcing UDP encapsulation"
};

static const true_false_string pmip6_bu_t_flag_value = {
    "TLV-header format used",
    "No TLV-header format"
};

/* Binding Acknowledgement status values
 * http://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml
 */
static const value_string mip6_ba_status_value[] = {
    {   0, "Binding Update accepted" },
    {   1, "Accepted but prefix discovery necessary" },
    {   2, "GRE_KEY_OPTION_NOT_REQUIRED" },                 /* [RFC5845] */
    {   3, "GRE_TUNNELING_BUT_TLV_HEADER_NOT_SUPPORTED" },  /* [RFC5845] */
    {   4, "MCOA NOTCOMPLETE" },                            /* [RFC5648] */
    {   5, "MCOA RETURNHOME WO/NDP" },                      /* [RFC5648] */
    {   6, "PBU_ACCEPTED_TB_IGNORED_SETTINGSMISMATCH" },    /* [RFC-ietf-mipshop-transient-bce-pmipv6-07] */
    /* 7-127 Unassigned */

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
    { 149, "Permanent home keygen token exists" },                  /* [RFC4866] */
    { 150, "Non-null home nonce index expected" },                  /* [RFC4866] */
    { 151, "SERVICE_AUTHORIZATION_FAILED" },                        /* [RFC5149] */
    { 152, "PROXY_REG_NOT_ENABLED" },                               /* [RFC5213] */
    { 153, "NOT_LMA_FOR_THIS_MOBILE_NODE" },                        /* [RFC5213] */
    { 154, "MAG_NOT_AUTHORIZED_FOR_PROXY_REG" },                    /* [RFC5213] */
    { 155, "NOT_AUTHORIZED_FOR_HOME_NETWORK_PREFIX" },              /* [RFC5213] */
    { 156, "TIMESTAMP_MISMATCH" },                                  /* [RFC5213] */
    { 157, "TIMESTAMP_LOWER_THAN_PREV_ACCEPTED" },                  /* [RFC5213] */
    { 158, "MISSING_HOME_NETWORK_PREFIX_OPTION" },                  /* [RFC5213] */
    { 159, "BCE_PBU_PREFIX_SET_DO_NOT_MATCH" },                     /* [RFC5213] */
    { 160, "MISSING_MN_IDENTIFIER_OPTION" },                        /* [RFC5213] */
    { 161, "MISSING_HANDOFF_INDICATOR_OPTION" },                    /* [RFC5213] */
    { 162, "MISSING_ACCESS_TECH_TYPE_OPTION" },                     /* [RFC5213] */
    { 163, "GRE_KEY_OPTION_REQUIRED" },                             /* [RFC5845] */
    { 164, "MCOA MALFORMED" },                                      /* [RFC5648] */
    { 165, "MCOA NON-MCOA BINDING EXISTS" },                        /* [RFC5648] */
    { 166, "MCOA PROHIBITED" },                                     /* [RFC5648] */
    { 167, "MCOA UNKNOWN COA" },                                    /* [RFC5648] */
    { 168, "MCOA BULK REGISTRATION PROHIBITED" },                   /* [RFC5648] */
    { 169, "MCOA SIMULTANEOUS HOME AND FOREIGN PROHIBITED" },       /* [RFC5648] */
    { 170, "NOT_AUTHORIZED_FOR_IPV4_MOBILITY_SERVICE" },            /* [RFC5844] */
    { 171, "NOT_AUTHORIZED_FOR_IPV4_HOME_ADDRESS" },                /* [RFC5844] */
    { 172, "NOT_AUTHORIZED_FOR_IPV6_MOBILITY_SERVICE" },            /* [RFC5844] */
    { 173, "MULTIPLE_IPV4_HOME_ADDRESS_ASSIGNMENT_NOT_SUPPORTED" }, /* [RFC5844] */

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

/* Heartbeat flag description */
static const true_false_string mip6_hb_u_flag_value = {
    "Unsolicited Heartbeat Response",
    "Otherwise"
};

static const true_false_string mip6_hb_r_flag_value = {
    "Heartbeat Response",
    "Heartbeat Request"
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

/* mobile network prefix flag description */
static const true_false_string mip6_ipv4ha_p_flag_value = {
    "mobile network prefixt requested",
    "mobile network prefix not requested"
};

/* Vendor-Specific Mobility Option */
static const value_string mip6_vsm_subtype_value[] = {
    {   0, NULL }
};

/* Vendor-Specific Mobility Option (3GPP TS29.282) */
static const value_string mip6_vsm_subtype_3gpp_value[] = {
    {   1, "Protocol Configuration Options" },
    {   2, "3GPP Specific PMIPv6 Error Code" },
    {   3, "PMIPv6 PDN GW IP Address" },
    {   4, "PMIPv6 DHCPv4 Address Allocation Procedure Indication" },
    {   5, "PMIPv6 Fully Qualified PDN Connection Set Identifier" },
    {   6, "PMIPv6 PDN type indication" },
    {   7, "Charging ID" },
    {   8, "Selection Mode" },
    {   9, "I-WLAN Mobility Access Point Name (APN)" },
    {  10, "Charging Characteristics" },
    {  11, "Mobile Equipment Identity (MEI)" },
    {  12, "MSISDN" },
    {  13, "Serving Network" },
    {  14, "APN Restriction" },
    {  15, "Maximum APN Restriction" },
    {  16, "Unauthenticated IMSI" },
    {  17, "PDN Connection ID" },
    {   0, NULL }
};

/* Handoff Indicator Option type */
static const value_string pmip6_hi_opttype_value[] = {
    {   0, "Reserved" },
    {   1, "Attachment over a new interface" },
    {   2, "Handoff between two different interfaces of the mobile node" },
    {   3, "Handoff between mobile access gateways for the same interface" },
    {   4, "Handoff state unknown" },
    {   5, "Handoff state not changed (Re-registration)" },
    {   0, NULL }
};

/* Access Technology Type Option type */
static const value_string pmip6_att_opttype_value[] = {
    {   0, "Reserved" },
    {   1, "Virtual" },
    {   2, "PPP" },
    {   3, "IEEE 802.3" },
    {   4, "IEEE 802.11a/b/g" },
    {   5, "IEEE 802.16e" },
    {   6, "3GPP GERAN" },
    {   7, "3GPP UTRAN" },
    {   8, "3GPP E-UTRAN" },
    {   9, "3GPP2 eHRPD" },
    {  10, "3GPP2 HRPD" },
    {  11, "3GPP2 1xRTT" },
    {  12, "3GPP2 UMB" },
    {   0, NULL }
};

/* PMIP6 BRI R. Trigger values */
static const value_string pmip6_bri_rtrigger[] = {
    { 0x00, "Unspecified"},
    { 0x01,     "Administrative Reason"},
    { 0x02,     "Inter-MAG Handover - same Access Type"},
    { 0x03,     "Inter-MAG Handover - different Access Type"},
    { 0x04,     "Inter-MAG Handover - Unknown"},
    { 0x05,     "User Initiated Session(s) Termination"},
    { 0x06,     "Access Network Session(s) Termination"},
    { 0x07,     "Possible Out-of Sync BCE State"},
    /* 8-127 Unassigned  */
    { 0x128,    "Per-Peer Policy"},
    { 0x129,    "Revoking Mobility Node Local Policy"},
    /* 130-249 Unassigned  */
    /* 250-255 Reserved for Testing Purposes Only */
    { 0,        NULL},
};

/* PMIP6 BRI Status values */
static const value_string pmip6_bri_status[] = {
    { 0x00,     "Success"},
    { 0x01,     "Partial Success"},
    { 0x02,     "Binding Does NOT Exist"},
    { 0x03,     "IPv4 HoA Binding Does NOT Exist"},
    { 0x04,     "Global Revocation NOT Authorized"},
    { 0x05,     "CAN NOT Identify Binding"},
    { 0x06,     "Revocation Failed, MN is Attached"},
    { 0,        NULL},
};

/* Handoff Indicator values */
static const range_string handoff_indicator[] = {
    { 0x00, 0x00,   "Reserved"                              },
    { 0x01, 0x01,   "Attachment over a new interface"       },
    { 0x02, 0x02,   "Handoff between two different interfaces of the mobile node"   },
    { 0x03, 0x03,   "Handoff between mobile access gateways for the same interface" },
    { 0x04, 0x04,   "Handoff state unknown"                                         },
    { 0x05, 0x05,   "Handoff state not changed (Re-registration)"                   },
    { 0x06, 0xff,   "Unassigned"                                                    },
    { 0,    0,      NULL                                                            }
};

/* Mobility Option types
 * http://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml
 */

static const value_string mip6_mobility_options[] = {
    { MIP6_PAD1,   "Pad1"},                                         /* RFC3775 */
    { MIP6_PADN,   "PadN"},                                         /* RFC3775 */
    { MIP6_BRA,    "Binding Refresh Advice"},                       /* RFC3775 */
    { MIP6_ACOA,   "Alternate Care-of Address"},                    /* RFC3775 */
    { MIP6_NI,     "Nonce Indices"},                                /* RFC3775 */
    { MIP6_AUTD,   "Authorization Data"},                           /* RFC3775 */
    { MIP6_MNP,    "Mobile Network Prefix Option"},                 /* RFC3963 */
    { MIP6_MHLLA,  "Mobility Header Link-Layer Address option"},    /* RFC5568 */
    { MIP6_MNID,   "MN-ID-OPTION-TYPE"},                            /* RFC4283 */
    { MIP6_AUTH,   "AUTH-OPTION-TYPE"},                             /* RFC4285 */
    { MIP6_MESGID, "MESG-ID-OPTION-TYPE"},                          /* RFC4285 */
    { MIP6_CGAPR,  "CGA Parameters Request"},                       /* RFC4866 */
    { MIP6_CGAR,   "CGA Parameters"},                               /* RFC4866 */
    { MIP6_SIGN,   "Signature"},                                    /* RFC4866 */
    { MIP6_PHKT,   "Permanent Home Keygen Token"},                  /* RFC4866 */
    { MIP6_MOCOTI, "Care-of Test Init"},                            /* RFC4866 */
    { MIP6_MOCOT,  "Care-of Test"},                                 /* RFC4866 */
    { MIP6_DNSU,   "DNS-UPDATE-TYPE"},                              /* RFC5026 */
    { MIP6_EM,     "Experimental Mobility Option"},                 /* RFC5096 */
    { MIP6_VSM,    "Vendor Specific Mobility Option"},              /* RFC5094 */
    { MIP6_SSM,    "Service Selection Mobility Option"},            /* RFC5149 */
    { MIP6_BADFF,  "Binding Authorization Data for FMIPv6 (BADF)"}, /* RFC5568 */
    { MIP6_HNP,    "Home Network Prefix Option"},                   /* RFC5213 */
    { MIP6_MOHI,   "Handoff Indicator Option"},                     /* RFC5213 */
    { MIP6_ATT,    "Access Technology Type Option"},                /* RFC5213 */
    { MIP6_MNLLI,  "Mobile Node Link-layer Identifier Option"},     /* RFC5213 */
    { MIP6_LLA,    "Link-local Address Option"},                    /* RFC5213 */
    { MIP6_TS,     "Timestamp Option"},                             /* RFC5213 */
    { MIP6_RC,     "Restart Counter"},                              /* RFC5847 */
    { MIP6_IPV4HA, "IPv4 Home Address"},                            /* RFC5555 */
    { MIP6_IPV4AA, "IPv4 Address Acknowledgement"},                 /* RFC5555 */
    { MIP6_NATD,   "NAT Detection"},                                /* RFC5555 */
    { MIP6_IPV4COA,"IPv4 Care-of Address"},                         /* RFC5555 */
    { MIP6_GREK,   "GRE Key Option"},                               /* RFC5845 */
    { MIP6_MHIPV6AP,  "Mobility Header IPv6 Address/Prefix"},       /* RFC5568 */
    { MIP6_BI,        "Binding Identifier"},                        /* RFC5648 */
    { MIP6_IPV4HAREQ, "IPv4 Home Address Request"},                 /* RFC5844 */
    { MIP6_IPV4HAREP, "IPv4 Home Address Reply"},                   /* RFC5844 */
    { MIP6_IPV4DRA,   "IPv4 Default-Router Address"},               /* RFC5844 */
    { MIP6_IPV4DSM,   "IPv4 DHCP Support Mode"},                    /* RFC5844 */
    { MIP6_CR,        "Context Request Option"},                    /* RFC5949 */
    { MIP6_LMAA,      "Local Mobility Anchor Address Option"},      /* RFC5949 */
    { MIP6_MNLLAII,   "Mobile Node Link-local Address Interface Identifier Option"}, /* RFC5949 */
    { MIP6_TB,        "Transient Binding"},                         /* [RFC-ietf-mipshop-transient-bce-pmipv6-07] */
    { MIP6_FS,        "Flow Summary"},                              /* [RFC-ietf-mext-flow-binding-11] */
    { MIP6_FI,        "Flow Identification"},                       /* [RFC-ietf-mext-flow-binding-11]] */

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
#define FMIP6_FBU_LEN         6
#define FMIP6_FBACK_LEN       6
#define FMIP6_FNA_LEN         2
#define MIP6_EMH_LEN          0
#define MIP6_HAS_LEN         18
#define MIP6_HB_LEN           6
#define MIP6_HI_LEN           4
#define MIP6_HAck_LEN         4
#define MIP6_BR_LEN           6
/* PMIP BRI */
#define PMIP6_BRI_LEN         6

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
#define MIP6_BU_FLAGS_LEN     2
#define MIP6_BU_RES_LEN       0
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

#define MIP6_HAS_NRADR_OFF    6
#define MIP6_HAS_RES_OFF      7
#define MIP6_HAS_HAA_OFF      8
#define MIP6_HAS_OPTS_OFF    24
#define MIP6_HAS_NRADR_LEN    1
#define MIP6_HAS_RES_LEN      1
#define MIP6_HAS_HAA_LEN     16

#define MIP6_HB_RES_OFF       6
#define MIP6_HB_FLAGS_OFF     7
#define MIP6_HB_SEQNR_OFF     8
#define MIP6_HB_OPTS_OFF     12
#define MIP6_HB_RES_LEN       1
#define MIP6_HB_FLAGS_LEN     1
#define MIP6_HB_SEQNR_LEN     4

#define MIP6_HI_SEQNR_OFF     6
#define MIP6_HI_FLAGS_OFF     8
#define MIP6_HI_CODE_OFF      9
#define MIP6_HI_OPTS_OFF     10
#define MIP6_HI_SEQNR_LEN     2
#define MIP6_HI_FLAGS_LEN     1
#define MIP6_HI_CODE_LEN      1

#define MIP6_HAck_SEQNR_OFF   6
#define MIP6_HAck_RES_OFF     8
#define MIP6_HAck_CODE_OFF    9
#define MIP6_HAck_OPTS_OFF   10
#define MIP6_HAck_SEQNR_LEN   2
#define MIP6_HAck_RES_LEN     1
#define MIP6_HAck_CODE_LEN    1

#define MIP6_BR_TYPE_OFF      6
#define MIP6_BR_TRGR_OFF      7
#define MIP6_BR_SEQNR_OFF     8
#define MIP6_BR_FLAGS_OFF    10
#define MIP6_BR_RES_OFF      11
#define MIP6_BR_OPTS_OFF     12
#define MIP6_BR_TYPE_LEN      1
#define MIP6_BR_TRGR_LEN      1
#define MIP6_BR_SEQNR_LEN     2
#define MIP6_BR_FLAGS_LEN     1
#define MIP6_BR_RES_LEN       1

/* PMIP BRI */
#define PMIP6_BRI_BRTYPE_OFF     6
#define PMIP6_BRI_RTRIGGER_OFF   7
#define PMIP6_BRI_STATUS_OFF     7
#define PMIP6_BRI_SEQNR_OFF      8
#define PMIP6_BRI_FLAGS_OFF     10
#define PMIP6_BRI_RES_OFF       11
#define PMIP6_BRI_BRTYPE_LEN     1
#define PMIP6_BRI_RTRIGGER_LEN   1
#define PMIP6_BRI_STATUS_LEN     1
#define PMIP6_BRI_SEQNR_LEN      2
#define PMIP6_BRI_FLAGS_LEN      1
#define PMIP6_BRI_RES_LEN        1

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

#define MIP6_NEMO_MNP_LEN         18
#define MIP6_NEMO_MNP_PL_OFF       3
#define MIP6_NEMO_MNP_MNP_OFF      4
#define MIP6_NEMO_MNP_MNP_LEN     16

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

#define MIP6_VSM_MINLEN       2
#define MIP6_VSM_VID_OFF      2
#define MIP6_VSM_VID_LEN      4
#define MIP6_VSM_SUBTYPE_OFF  6
#define MIP6_VSM_SUBTYPE_LEN  1
#define MIP6_VSM_DATA_OFF     7


#define MIP6_SSM_MINLEN       2
#define MIP6_SSM_SSM_OFF      2

#define PMIP6_HI_LEN          2
#define PMIP6_HI_HI_OFF       3
#define PMIP6_HI_HI_LEN       1

#define PMIP6_ATT_LEN         2
#define PMIP6_ATT_ATT_OFF     3
#define PMIP6_ATT_ATT_LEN     1

#define PMIP6_LLA_LEN         16

#define PMIP6_TS_LEN          8

#define PMIP6_RC_LEN          4
#define PMIP6_RC_RC_OFF       2
#define PMIP6_RC_RC_LEN       4

#define MIP6_IPV4HA_LEN         6
#define MIP6_IPV4HA_PREFIXL_OFF 2
#define MIP6_IPV4HA_PREFIXL_LEN 1
#define MIP6_IPV4HA_HA_OFF      4
#define MIP6_IPV4HA_HA_LEN      4

#define MIP6_IPV4AA_LEN         6
#define MIP6_IPV4AA_STATUS_OFF  2
#define MIP6_IPV4AA_STATUS_LEN  1
#define MIP6_IPV4AA_PREFIXL_OFF 3
#define MIP6_IPV4AA_PREFIXL_LEN 1
#define MIP6_IPV4AA_HA_OFF      4
#define MIP6_IPV4AA_HA_LEN      4

#define PMIP6_GREK_LEN        6
#define PMIP6_GREK_ID_OFF     4
#define PMIP6_GREK_ID_LEN     4

#define MIP6_IPV4HAREQ_LEN         6
#define MIP6_IPV4HAREQ_PREFIXL_OFF 2
#define MIP6_IPV4HAREQ_PREFIXL_LEN 1
#define MIP6_IPV4HAREQ_HA_OFF      4
#define MIP6_IPV4HAREQ_HA_LEN      4

#define MIP6_IPV4HAREP_LEN         6
#define MIP6_IPV4HAREP_STATUS_OFF  2
#define MIP6_IPV4HAREP_STATUS_LEN  1
#define MIP6_IPV4HAREP_PREFIXL_OFF 3
#define MIP6_IPV4HAREP_PREFIXL_LEN 1
#define MIP6_IPV4HAREP_HA_OFF      4
#define MIP6_IPV4HAREP_HA_LEN      4

#define MIP6_IPV4DRA_LEN      6
#define MIP6_IPV4DRA_RES_OFF  2
#define MIP6_IPV4DRA_RES_LEN  2
#define MIP6_IPV4DRA_DRA_OFF  4
#define MIP6_IPV4DRA_DRA_LEN  4

static dissector_table_t ip_dissector_table;

/* Initialize the protocol and registered header fields */
static int proto_mip6 = -1;
static int proto_nemo = -1;
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
static int hf_mip6_nemo_bu_r_flag = -1;
static int hf_pmip6_bu_p_flag = -1;
static int hf_mip6_bu_f_flag = -1;
static int hf_pmip6_bu_t_flag = -1;
static int hf_mip6_bu_lifetime = -1;

static int hf_mip6_ba_status = -1;
static int hf_mip6_ba_k_flag = -1;
static int hf_mip6_nemo_ba_r_flag = -1;
static int hf_pmip6_ba_p_flag = -1;
static int hf_pmip6_ba_t_flag = -1;
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

static int hf_mip6_hb_u_flag = -1;
static int hf_mip6_hb_r_flag = -1;
static int hf_mip6_hb_seqnr = -1;

static int hf_mip6_bra_interval = -1;

static int hf_mip6_acoa_acoa = -1;
static int hf_mip6_nemo_mnp_mnp = -1;
static int hf_mip6_nemo_mnp_pfl = -1;

static int hf_mip6_ni_hni = -1;
static int hf_mip6_ni_cni = -1;

static int hf_mip6_bad_auth = -1;

static int hf_fmip6_lla_optcode = -1;

static int hf_mip6_mnid_subtype = -1;
static int hf_mip6_vsm_vid = -1;
static int hf_mip6_vsm_subtype = -1;
static int hf_mip6_vsm_subtype_3gpp = -1;

static int hf_pmip6_hi_opttype = -1;
static int hf_pmip6_att_opttype = -1;

static int hf_pmip6_timestamp = -1;
static int hf_pmip6_rc = -1;
static int hf_mip6_ipv4ha_preflen = -1;
static int hf_mip6_ipv4ha_p_flag = -1;
static int hf_mip6_ipv4ha_ha = -1;
static int hf_mip6_ipv4aa_status = -1;
static int hf_pmip6_gre_key = -1;
static int hf_mip6_ipv4dra_dra = -1;
static int hf_mip6_mobility_opt = -1;

/* PMIP BRI */
static int hf_pmip6_bri_brtype = -1;
static int hf_pmip6_bri_rtrigger = -1;
static int hf_pmip6_bri_status = -1;
static int hf_pmip6_bri_seqnr = -1;
static int hf_pmip6_bri_ip_flag = -1;
static int hf_pmip6_bri_ap_flag = -1;
static int hf_pmip6_bri_ia_flag = -1;
static int hf_pmip6_bri_ig_flag = -1;
static int hf_pmip6_bri_ag_flag = -1;
static int hf_pmip6_bri_res = -1;

static int hf_pmip6_opt_lila_lla = -1;

/* Initialize the subtree pointers */
static gint ett_mip6 = -1;
static gint ett_mip6_opt_padn = -1;
static gint ett_mip6_opt_bra = -1;
static gint ett_mip6_opt_acoa = -1;
static gint ett_mip6_opt_ni = -1;
static gint ett_mip6_opt_bad = -1;
static gint ett_mip6_nemo_opt_mnp = -1;
static gint ett_fmip6_opt_lla = -1;
static gint ett_mip6_opt_mnid = -1;
static gint ett_mip6_opt_vsm = -1;
static gint ett_mip6_opt_ssm = -1;
static gint ett_pmip6_opt_hnp = -1;
static gint ett_pmip6_opt_hi = -1;
static gint ett_pmip6_opt_att = -1;
static gint ett_pmip6_opt_lla = -1;
static gint ett_pmip6_opt_ts = -1;
static gint ett_pmip6_opt_rc = -1;
static gint ett_mip6_opt_ipv4ha = -1;
static gint ett_mip6_opt_ipv4aa = -1;
static gint ett_pmip6_opt_grek = -1;
static gint ett_mip6_opt_ipv4hareq = -1;
static gint ett_mip6_opt_ipv4harep = -1;
static gint ett_mip6_opt_ipv4dra = -1;

/* Functions to dissect the mobility headers */

static int
dissect_mip6_brr(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo)
{
    /*proto_tree *data_tree = NULL;*/
    /*proto_item *ti;*/

    col_set_str(pinfo->cinfo, COL_INFO, "Binding Refresh Request");

    if (mip6_tree) {
        /*ti = */proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF,
                                     MIP6_BRR_LEN, "Binding Refresh Request");
        /*data_tree = proto_item_add_subtree(ti, ett_mip6);*/
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

/* RFC3775 */
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
        proto_tree_add_item(data_tree, hf_mip6_nemo_bu_r_flag, tvb,
                MIP6_BU_FLAGS_OFF, MIP6_BU_FLAGS_LEN, FALSE);
        proto_tree_add_item(data_tree, hf_pmip6_bu_p_flag, tvb,
                MIP6_BU_FLAGS_OFF, MIP6_BU_FLAGS_LEN, FALSE);
        proto_tree_add_item(data_tree, hf_mip6_bu_f_flag, tvb,
                MIP6_BU_FLAGS_OFF, MIP6_BU_FLAGS_LEN, FALSE);
        proto_tree_add_item(data_tree, hf_pmip6_bu_t_flag, tvb,
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
        proto_tree_add_item(data_tree, hf_mip6_nemo_ba_r_flag, tvb,
                MIP6_BA_FLAGS_OFF, MIP6_BA_FLAGS_LEN, FALSE);
        proto_tree_add_item(data_tree, hf_pmip6_ba_p_flag, tvb,
                MIP6_BA_FLAGS_OFF, MIP6_BA_FLAGS_LEN, FALSE);
        proto_tree_add_item(data_tree, hf_pmip6_ba_t_flag, tvb,
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
dissect_mip6_hb(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo)
{
    proto_tree *data_tree = NULL;
    proto_item *ti;

    col_set_str(pinfo->cinfo, COL_INFO, "Heartbeat");

    if (mip6_tree) {
        ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF,
                MIP6_HB_LEN, "Heartbeat");
        data_tree = proto_item_add_subtree(ti, ett_mip6);

        proto_tree_add_item(data_tree, hf_mip6_hb_u_flag, tvb,
                MIP6_HB_FLAGS_OFF, MIP6_HB_FLAGS_LEN, FALSE);
        proto_tree_add_item(data_tree, hf_mip6_hb_r_flag, tvb,
                MIP6_HB_FLAGS_OFF, MIP6_HB_FLAGS_LEN, FALSE);

        proto_tree_add_item(data_tree, hf_mip6_hb_seqnr, tvb,
                MIP6_HB_SEQNR_OFF, MIP6_HB_SEQNR_LEN, FALSE);

    }

    return MIP6_DATA_OFF + MIP6_HB_LEN;
}

static int
dissect_mip6_unknown(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo)
{
    /*proto_tree *data_tree = NULL;*/
    /*proto_item *ti;*/

    col_set_str(pinfo->cinfo, COL_INFO, "Unknown MH Type");

    if (mip6_tree) {
        /*ti = */proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF,
                MIP6_DATA_OFF + 1, "Unknown MH Type");
        /*data_tree = proto_item_add_subtree(ti, ett_mip6);*/
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
    /*proto_tree *data_tree = NULL;*/
    /*proto_item *ti;*/

    col_set_str(pinfo->cinfo, COL_INFO, "Fast Neighbor Advertisement");

    if (mip6_tree) {
        /*ti = */proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF,
                FMIP6_FNA_LEN, "Fast Neighbor Advertisement");
        /*data_tree = proto_item_add_subtree(ti, ett_mip6);*/
    }

    return MIP6_DATA_OFF + FMIP6_FNA_LEN;
}

/* PMIP Binding Revocation Indication / Acknowledge */
static int
dissect_pmip6_bri(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo)
{
#define INDICATION  1
#define ACKNOWLEDGE     2

    proto_item  *ti;
    proto_tree  *field_tree;
    guint8      br_type;

    br_type = tvb_get_guint8(tvb, PMIP6_BRI_BRTYPE_OFF);

    /* Branch between BR Indication and BR Acknowledge */
    if ( br_type == INDICATION )
    {
        col_set_str(pinfo->cinfo, COL_INFO, "Binding Revocation Indication");

        if (mip6_tree)
        {
            ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF,
                PMIP6_BRI_LEN, "Binding Revocation Indication");

            field_tree = proto_item_add_subtree(ti, ett_mip6);

            proto_tree_add_item(field_tree, hf_pmip6_bri_brtype, tvb,
                PMIP6_BRI_BRTYPE_OFF, PMIP6_BRI_BRTYPE_LEN, FALSE);

            proto_tree_add_item(field_tree, hf_pmip6_bri_rtrigger, tvb,
                PMIP6_BRI_RTRIGGER_OFF, PMIP6_BRI_RTRIGGER_LEN, FALSE);

            proto_tree_add_item(field_tree, hf_pmip6_bri_seqnr, tvb,
                PMIP6_BRI_SEQNR_OFF, PMIP6_BRI_SEQNR_LEN, FALSE);

            proto_tree_add_item(field_tree, hf_pmip6_bri_ip_flag, tvb,
                PMIP6_BRI_FLAGS_OFF, PMIP6_BRI_FLAGS_LEN, FALSE);

            proto_tree_add_item(field_tree, hf_pmip6_bri_ia_flag, tvb,
                PMIP6_BRI_FLAGS_OFF, PMIP6_BRI_FLAGS_LEN, FALSE);

            proto_tree_add_item(field_tree, hf_pmip6_bri_ig_flag, tvb,
                PMIP6_BRI_FLAGS_OFF, PMIP6_BRI_FLAGS_LEN, FALSE);

            proto_tree_add_item(field_tree, hf_pmip6_bri_res, tvb,
                PMIP6_BRI_RES_OFF, PMIP6_BRI_RES_LEN, FALSE);
        }
    } else if ( br_type == ACKNOWLEDGE ) {
        if (check_col(pinfo->cinfo, COL_INFO))
        col_set_str(pinfo->cinfo, COL_INFO, "Binding Revocation Acknowledge");

        if (mip6_tree)
        {
            ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF,
                PMIP6_BRI_LEN, "Binding Revocation Acknowledge");

            field_tree = proto_item_add_subtree(ti, ett_mip6);

            proto_tree_add_item(field_tree, hf_pmip6_bri_brtype, tvb,
                PMIP6_BRI_BRTYPE_OFF, PMIP6_BRI_BRTYPE_LEN, FALSE);

            proto_tree_add_item(field_tree, hf_pmip6_bri_status, tvb,
                PMIP6_BRI_STATUS_OFF, PMIP6_BRI_STATUS_LEN, FALSE);

            proto_tree_add_item(field_tree, hf_pmip6_bri_seqnr, tvb,
                PMIP6_BRI_SEQNR_OFF, PMIP6_BRI_SEQNR_LEN, FALSE);

            proto_tree_add_item(field_tree, hf_pmip6_bri_ap_flag, tvb,
                PMIP6_BRI_FLAGS_OFF, PMIP6_BRI_FLAGS_LEN, FALSE);

            proto_tree_add_item(field_tree, hf_pmip6_bri_ag_flag, tvb,
                PMIP6_BRI_FLAGS_OFF, PMIP6_BRI_FLAGS_LEN, FALSE);

            proto_tree_add_item(field_tree, hf_pmip6_bri_res, tvb,
                PMIP6_BRI_RES_OFF, PMIP6_BRI_RES_LEN, FALSE);
        }
    }

    return MIP6_DATA_OFF + PMIP6_BRI_LEN;
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
dissect_mip6_nemo_opt_mnp(const ip_tcp_opt *optp _U_, tvbuff_t *tvb, int offset,
              guint optlen, packet_info *pinfo _U_,
              proto_tree *opt_tree)
{
    proto_tree *field_tree = NULL;
    proto_item *tf;
    tf = proto_tree_add_text(opt_tree, tvb, offset, optlen, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    proto_tree_add_item(field_tree, hf_mip6_nemo_mnp_pfl, tvb,
            offset + MIP6_NEMO_MNP_PL_OFF, 1, FALSE);

    proto_tree_add_item(field_tree, hf_mip6_nemo_mnp_mnp, tvb,
            offset + MIP6_NEMO_MNP_MNP_OFF, MIP6_NEMO_MNP_MNP_LEN, FALSE);
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

/* 5 Authorization Data */
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
            optlen - MIP6_BAD_AUTH_OFF, ENC_NA);
}

/* 7 Mobility Header Link-Layer Address option [RFC5568] */
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
                    tvb_bytes_to_str_punct(tvb, p, len, ':'));
        }
    }
}

/* 8 MN-ID-OPTION-TYPE */
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

/* 19 Vendor Specific Mobility Option [RFC5094]  */
static void
dissect_mip6_opt_vsm(const ip_tcp_opt *optp _U_, tvbuff_t *tvb, int offset,
             guint optlen, packet_info *pinfo _U_, proto_tree *opt_tree)
{
    proto_tree *field_tree = NULL;
    proto_item *tf;
    int len, p;
    guint32 vendorid;
    int hf_mip6_vsm_subtype_local;

    tf = proto_tree_add_text(opt_tree, tvb, offset, optlen, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

    proto_tree_add_item(field_tree, hf_mip6_vsm_vid, tvb,
            offset + MIP6_VSM_VID_OFF, MIP6_VSM_VID_LEN, FALSE);

    vendorid = tvb_get_ntohl(tvb, offset+MIP6_VSM_VID_OFF);
    switch (vendorid) {
    case VENDOR_THE3GPP:
        hf_mip6_vsm_subtype_local = hf_mip6_vsm_subtype_3gpp;
        break;
    default:
        hf_mip6_vsm_subtype_local = hf_mip6_vsm_subtype;
        break;
    }
    proto_tree_add_item(field_tree, hf_mip6_vsm_subtype_local, tvb,
            offset + MIP6_VSM_SUBTYPE_OFF, MIP6_VSM_SUBTYPE_LEN, FALSE);

    p = offset + MIP6_VSM_DATA_OFF;
    len = optlen - MIP6_VSM_DATA_OFF;
    if (len > 0)
        proto_tree_add_text(field_tree, tvb, p, len, "Data");

}

/* 20 Service Selection Mobility Option [RFC5149]  */
static void
dissect_mip6_opt_ssm(const ip_tcp_opt *optp _U_, tvbuff_t *tvb, int offset,
             guint optlen, packet_info *pinfo _U_, proto_tree *opt_tree)
{
    int len, p;

    p = offset + MIP6_SSM_SSM_OFF;
    len = optlen - MIP6_SSM_SSM_OFF;

    if (len > 0)
        proto_tree_add_text(opt_tree, tvb, p, len, "Identifier: %s", tvb_format_text(tvb, p, len));
}

 /* 23 Handoff Indicator Option [RFC5213]   */
static void
dissect_pmip6_opt_hi(const ip_tcp_opt *optp _U_, tvbuff_t *tvb, int offset,
             guint optlen _U_, packet_info *pinfo _U_, proto_tree *opt_tree)
{

    proto_tree_add_item(opt_tree, hf_pmip6_hi_opttype, tvb,
            offset + PMIP6_HI_HI_OFF, PMIP6_HI_HI_LEN, FALSE);
}

/* 24 Access Technology Type Option [RFC5213]  */
static void
dissect_pmip6_opt_att(const ip_tcp_opt *optp _U_, tvbuff_t *tvb, int offset,
              guint optlen _U_, packet_info *pinfo _U_, proto_tree *opt_tree)
{

    proto_tree_add_item(opt_tree, hf_pmip6_att_opttype, tvb,
            offset + PMIP6_ATT_ATT_OFF, PMIP6_ATT_ATT_LEN, FALSE);
}

/* 26 Link-local Address Option [RFC5213   */
static void dissect_pmip6_opt_lla(const ip_tcp_opt *optp _U_, tvbuff_t *tvb, int offset,
                        guint optlen, packet_info *pinfo _U_, proto_tree *opt_tree)
{
    proto_item      *ti;
    proto_tree      *field_tree;

    if (opt_tree){
    ti = proto_tree_add_text(opt_tree, tvb, offset, optlen, "%s", optp->name);
        field_tree = proto_item_add_subtree(ti, *optp->subtree_index);

        proto_tree_add_item(field_tree, hf_pmip6_opt_lila_lla, tvb, offset + 2, 16, FALSE);
   }
}

/* 27 Timestamp */
static void
dissect_pmip6_opt_ts(const ip_tcp_opt *optp _U_, tvbuff_t *tvb, int offset,
             guint optlen _U_, packet_info *pinfo _U_, proto_tree *opt_tree)
{
    proto_tree_add_item(opt_tree, hf_pmip6_timestamp, tvb, offset+2, 8,
                ENC_TIME_NTP|ENC_BIG_ENDIAN);
}

 /* 28 Restart Counter [RFC5847] */
static void
dissect_pmip6_opt_rc(const ip_tcp_opt *optp _U_, tvbuff_t *tvb, int offset,
             guint optlen _U_, packet_info *pinfo _U_, proto_tree *opt_tree)
{
    proto_tree_add_item(opt_tree, hf_pmip6_rc, tvb,
            offset + PMIP6_RC_RC_OFF, PMIP6_RC_RC_LEN, FALSE);

}

/* 29 IPv4 Home Address [RFC5555]  */
static void
dissect_pmip6_opt_ipv4ha(const ip_tcp_opt *optp _U_, tvbuff_t *tvb, int offset,
             guint optlen, packet_info *pinfo _U_, proto_tree *opt_tree)
{
    proto_tree *field_tree = NULL;
    proto_item *tf;
    int len, p;

    tf = proto_tree_add_text(opt_tree, tvb, offset, optlen, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

    p = offset + MIP6_IPV4HA_PREFIXL_OFF;
    len = MIP6_IPV4HA_PREFIXL_LEN;

    proto_tree_add_item(field_tree, hf_mip6_ipv4ha_preflen, tvb, p, len, FALSE);
    proto_tree_add_item(field_tree, hf_mip6_ipv4ha_p_flag, tvb, p, len+1, FALSE);

    proto_tree_add_item(field_tree, hf_mip6_ipv4ha_ha, tvb,
            offset + MIP6_IPV4HA_HA_OFF, MIP6_IPV4HA_HA_LEN, FALSE);

}

/* 30 IPv4 Address Acknowledgement [RFC5555] */
static void
dissect_pmip6_opt_ipv4aa(const ip_tcp_opt *optp _U_, tvbuff_t *tvb, int offset,
             guint optlen, packet_info *pinfo _U_, proto_tree *opt_tree)
{
    proto_tree *field_tree = NULL;
    proto_item *tf;

    tf = proto_tree_add_text(opt_tree, tvb, offset, optlen, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

    proto_tree_add_item(field_tree, hf_mip6_ipv4aa_status, tvb,
            offset + MIP6_IPV4AA_STATUS_OFF, MIP6_IPV4AA_STATUS_LEN, FALSE);

    proto_tree_add_item(field_tree, hf_mip6_ipv4ha_preflen, tvb,
            offset + MIP6_IPV4AA_PREFIXL_OFF, MIP6_IPV4AA_PREFIXL_LEN, FALSE);

    proto_tree_add_item(field_tree, hf_mip6_ipv4ha_ha, tvb,
            offset + MIP6_IPV4AA_HA_OFF, MIP6_IPV4AA_HA_LEN, FALSE);

}

/* 33 GRE Key Option [RFC5845]  */
static void
dissect_pmip6_opt_grek(const ip_tcp_opt *optp _U_, tvbuff_t *tvb, int offset,
               guint optlen _U_, packet_info *pinfo _U_, proto_tree *opt_tree)
{
    proto_tree_add_item(opt_tree, hf_pmip6_gre_key, tvb,
            offset + PMIP6_GREK_ID_OFF, PMIP6_GREK_ID_LEN, FALSE);

}

/* 36 IPv4 Home Address Request [RFC5844] */
static void
dissect_pmip6_opt_ipv4hareq(const ip_tcp_opt *optp _U_, tvbuff_t *tvb, int offset,
                guint optlen, packet_info *pinfo _U_, proto_tree *opt_tree)
{
    proto_tree *field_tree = NULL;
    proto_item *tf;

    tf = proto_tree_add_text(opt_tree, tvb, offset, optlen, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

    proto_tree_add_item(field_tree, hf_mip6_ipv4ha_preflen, tvb,
            offset + MIP6_IPV4HAREQ_PREFIXL_OFF, MIP6_IPV4HAREQ_PREFIXL_LEN, FALSE);

    proto_tree_add_item(field_tree, hf_mip6_ipv4ha_ha, tvb,
            offset + MIP6_IPV4HAREQ_HA_OFF, MIP6_IPV4HAREQ_HA_LEN, FALSE);

}

/* 37 IPv4 Home Address Reply [RFC5844] */
static void
dissect_pmip6_opt_ipv4harep(const ip_tcp_opt *optp _U_, tvbuff_t *tvb, int offset,
                guint optlen, packet_info *pinfo _U_, proto_tree *opt_tree)
{
    proto_tree *field_tree = NULL;
    proto_item *tf;

    tf = proto_tree_add_text(opt_tree, tvb, offset, optlen, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

    proto_tree_add_item(field_tree, hf_mip6_ipv4aa_status, tvb,
            offset + MIP6_IPV4HAREP_STATUS_OFF, MIP6_IPV4HAREP_STATUS_LEN, FALSE);

    proto_tree_add_item(field_tree, hf_mip6_ipv4ha_preflen, tvb,
            offset + MIP6_IPV4HAREP_PREFIXL_OFF, MIP6_IPV4HAREP_PREFIXL_LEN, FALSE);

    proto_tree_add_item(field_tree, hf_mip6_ipv4ha_ha, tvb,
            offset + MIP6_IPV4HAREP_HA_OFF, MIP6_IPV4HAREP_HA_LEN, FALSE);

}

/* 38 IPv4 Default-Router Address [RFC5844] */
static void
dissect_pmip6_opt_ipv4dra(const ip_tcp_opt *optp _U_, tvbuff_t *tvb, int offset,
              guint optlen, packet_info *pinfo _U_, proto_tree *opt_tree)
{
    proto_tree *field_tree = NULL;
    proto_item *tf;

    tf = proto_tree_add_text(opt_tree, tvb, offset, optlen, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

    proto_tree_add_item(field_tree, hf_mip6_ipv4dra_dra, tvb,
            offset + MIP6_IPV4DRA_DRA_OFF, MIP6_IPV4DRA_DRA_LEN, FALSE);

}

static const ip_tcp_opt mip6_opts[] = {
{
    MIP6_PAD1,                  /* 0 Pad1 [RFC3775] */
    "Pad1",
    NULL,
    NO_LENGTH,
    0,
    NULL,
},
{
    MIP6_PADN,                  /* 1 PadN [RFC3775] */
    "PadN",
    &ett_mip6_opt_padn,
    VARIABLE_LENGTH,
    0,
    dissect_mip6_opt_padn
},
{
    MIP6_BRA,                   /* 2 Binding Refresh Advice */
    "Binding Refresh Advice",
    &ett_mip6_opt_bra,
    FIXED_LENGTH,
    MIP6_BRA_LEN,
    dissect_mip6_opt_bra
},
{
    MIP6_ACOA,                  /*3  Alternate Care-of Address */
    "Alternate Care-of Address",
    &ett_mip6_opt_acoa,
    FIXED_LENGTH,
    MIP6_ACOA_LEN,
    dissect_mip6_opt_acoa
},
{
    MIP6_NI,                    /* 4 Nonce Indices */
    "Nonce Indices",
    &ett_mip6_opt_ni,
    FIXED_LENGTH,
    MIP6_NI_LEN,
    dissect_mip6_opt_ni
},
{
    MIP6_AUTD,                  /* 5 Authorization Data */
    "Authorization Data",
    &ett_mip6_opt_bad,
    VARIABLE_LENGTH,
    0,
    dissect_mip6_opt_bad
},
{
    MIP6_MNP,                   /* 6 Mobile Network Prefix Option */
    "Mobile Network Prefix",
    &ett_mip6_nemo_opt_mnp,
    FIXED_LENGTH,
    MIP6_NEMO_MNP_LEN,
    dissect_mip6_nemo_opt_mnp
},
{
    MIP6_MHLLA,                 /* 7 Mobility Header Link-Layer Address option [RFC5568] */
    "Mobility Header Link-Layer Address option",
    &ett_fmip6_opt_lla,
    VARIABLE_LENGTH,
    FMIP6_LLA_MINLEN,
    dissect_fmip6_opt_lla
},
{
    MIP6_MNID,                  /* 8 MN-ID-OPTION-TYPE */
    "Mobile Node Identifier",
    &ett_mip6_opt_mnid,
    VARIABLE_LENGTH,
    MIP6_MNID_MINLEN,
    dissect_mip6_opt_mnid
},
{
    MIP6_VSM,                   /* 19 Vendor Specific Mobility Option [RFC5094]  */
    "Vendor Specific Mobility",
    &ett_mip6_opt_vsm,
    VARIABLE_LENGTH,
    MIP6_VSM_MINLEN,
    dissect_mip6_opt_vsm
},
{
    MIP6_SSM,                   /* 20 Service Selection Mobility Option [RFC5149]  */
    "Service Selection Mobility",
    &ett_mip6_opt_ssm,
    VARIABLE_LENGTH,
    MIP6_SSM_MINLEN,
    dissect_mip6_opt_ssm
},
{
    MIP6_HNP,                   /* 22 Home Network Prefix Option [RFC5213]   */
    "Home Network Prefix",
    &ett_pmip6_opt_hnp,
    FIXED_LENGTH,
    MIP6_NEMO_MNP_LEN,
    dissect_mip6_nemo_opt_mnp
},
{
    MIP6_MOHI,                  /* 23 Handoff Indicator Option [RFC5213]   */
    "Handoff Indicator Option",
    &ett_pmip6_opt_hi,
    FIXED_LENGTH,
    PMIP6_HI_LEN,
    dissect_pmip6_opt_hi
},
{
    MIP6_ATT,                   /* 24 Access Technology Type Option [RFC5213]  */
    "Access Technology Type Option",
    &ett_pmip6_opt_att,
    FIXED_LENGTH,
    PMIP6_ATT_LEN,
    dissect_pmip6_opt_att
},
{
    MIP6_LLA,                        /* 26 Link-local Address Option [RFC5213   */
    "Link-local Address",
    &ett_pmip6_opt_lla,
    FIXED_LENGTH,
    PMIP6_LLA_LEN,
    dissect_pmip6_opt_lla
},

{
    MIP6_TS,                    /* 27 Timestamp */
    "Timestamp",
    &ett_pmip6_opt_ts,
    FIXED_LENGTH,
    PMIP6_TS_LEN,
    dissect_pmip6_opt_ts
},
{
    MIP6_RC,                    /* 28 Restart Counter [RFC5847] */
    "Restart Counter",
    &ett_pmip6_opt_rc,
    FIXED_LENGTH,
    PMIP6_RC_LEN,
    dissect_pmip6_opt_rc
},
{
    MIP6_IPV4HA,                /* 29 IPv4 Home Address [RFC5555]  */
    "IPv4 Home Address",
    &ett_mip6_opt_ipv4ha,
    FIXED_LENGTH,
    MIP6_IPV4HA_LEN,
    dissect_pmip6_opt_ipv4ha
},
{
    MIP6_IPV4AA,                /* 30 IPv4 Address Acknowledgement [RFC5555] */
    "IPv4 Address Acknowledgement",
    &ett_mip6_opt_ipv4aa,
    FIXED_LENGTH,
    MIP6_IPV4AA_LEN,
    dissect_pmip6_opt_ipv4aa
},
{
    MIP6_GREK,                  /* 33 GRE Key Option [RFC5845]  */
    "GRE Key",
    &ett_pmip6_opt_grek,
    FIXED_LENGTH,
    PMIP6_GREK_LEN,
    dissect_pmip6_opt_grek
},
{
    MIP6_IPV4HAREQ,             /* 36 IPv4 Home Address Request [RFC5844] */
    "IPv4 Home Address Request",
    &ett_mip6_opt_ipv4hareq,
    FIXED_LENGTH,
    MIP6_IPV4HAREQ_LEN,
    dissect_pmip6_opt_ipv4hareq
},
{
    MIP6_IPV4HAREP,            /* 37 IPv4 Home Address Reply [RFC5844] */
    "IPv4 Home Address Reply",
    &ett_mip6_opt_ipv4harep,
    FIXED_LENGTH,
    MIP6_IPV4HAREP_LEN,
    dissect_pmip6_opt_ipv4harep
},
{
    MIP6_IPV4DRA,               /* 38 IPv4 Default-Router Address [RFC5844] */
    "IPv4 Default-Router Address",
    &ett_mip6_opt_ipv4dra,
    FIXED_LENGTH,
    MIP6_IPV4DRA_LEN,
    dissect_pmip6_opt_ipv4dra
},
};

#define N_MIP6_OPTS (sizeof mip6_opts / sizeof mip6_opts[0])


/* Like "dissect_ip_tcp_options()", but assumes the length of an option
 * *doesn't* include the type and length bytes.  The option parsers,
 * however, are passed a length that *does* include them.
 */
static void
dissect_mipv6_options(tvbuff_t *tvb, int offset, guint length,
              const ip_tcp_opt *opttab, int nopts, int eol,
              packet_info *pinfo, proto_tree *opt_tree)
{
    proto_item       *ti;
    guchar            opt;
    const ip_tcp_opt  *optp;
    opt_len_type      len_type;
    unsigned int      optlen;
    const char        *name;
    char              name_str[7+1+1+2+2+1+1];  /* "Unknown (0x%02x)" */
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
            optp = NULL;    /* indicate that we don't know this option */
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
                    proto_item *expert_item;
                    proto_item_append_text(ti, "(%u byte%s)",len, plurality(len, "", "s"));
                    expert_item = proto_tree_add_text(opt_tree, tvb,  offset+2, len, "IE data not dissected yet");
                    expert_add_info_format(pinfo, expert_item, PI_PROTOCOL, PI_NOTE, "IE data not dissected yet");
                    PROTO_ITEM_SET_GENERATED(expert_item);
                } else {
                    if (dissect != NULL) {
                        /* Option has a dissector. */
                        if (opt == MIP6_MHLLA)
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
                if (opt == MIP6_MHLLA)
                    offset += len + 2 + FMIP6_LLA_OPTCODE_LEN;
                else
                    offset += len + 2;
            }
            if (opt == MIP6_MHLLA)
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
    case MIP6_BRR:
        /* Binding Refresh Request */
        offset = dissect_mip6_brr(tvb, mip6_tree, pinfo);
        break;
    case MIP6_HOTI:
        /* Home Test Init */
        offset = dissect_mip6_hoti(tvb, mip6_tree, pinfo);
        break;
    case MIP6_MHCOTI:
        /* Care-of Test Init */
        offset = dissect_mip6_coti(tvb, mip6_tree, pinfo);
        break;
    case MIP6_HOT:
        /* Home Test */
        offset = dissect_mip6_hot(tvb, mip6_tree, pinfo);
        break;
    case MIP6_MHCOT:
        /* Care-of Test */
        offset = dissect_mip6_cot(tvb, mip6_tree, pinfo);
        break;
    case MIP6_BU:
        /* Binding Update */
        offset = dissect_mip6_bu(tvb, mip6_tree, pinfo);
        if (proto_nemo == 1) {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "NEMO");
        }
        break;
    case MIP6_BA:
        /* Binding Acknowledgement */
        offset = dissect_mip6_ba(tvb, mip6_tree, pinfo);
        if (proto_nemo == 1) {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "NEMO");
        }
        break;
    case MIP6_BE:
        /* Binding Error */
        offset = dissect_mip6_be(tvb, mip6_tree, pinfo);
        break;
    case MIP6_FBU:
        /* Fast Binding Update */
        offset = dissect_fmip6_fbu(tvb, mip6_tree, pinfo);
        break;
    case MIP6_FBACK:
        /* Fast Binding Acknowledgment */
        offset = dissect_fmip6_fback(tvb, mip6_tree, pinfo);
        break;
    case MIP6_FNA:
        /* Fast Neighbor Advertisement */
        offset = dissect_fmip6_fna(tvb, mip6_tree, pinfo);
        break;
    case MIP6_HB:
        /* Heartbeat */
        offset = dissect_mip6_hb(tvb, mip6_tree, pinfo);
        break;
    case MIP6_BR:
        /* Binding Revocation Indication / Acknowledge */
        offset = dissect_pmip6_bri(tvb, mip6_tree, pinfo);
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

    if (type == MIP6_FNA && pproto == IP_PROTO_IPV6) {
        tvbuff_t *ipv6_tvb;

        ipv6_tvb = tvb_new_subset_remaining(tvb, len + 8);

        /* Call the IPv6 dissector */
        dissector_try_uint(ip_dissector_table, pproto, ipv6_tvb, pinfo, tree);

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
                                  FT_BOOLEAN, 16, TFS(&mip6_bu_a_flag_value),
                                  0x8000, NULL, HFILL }},
    { &hf_mip6_bu_h_flag,       { "Home Registration (H) flag",
                                  "mip6.bu.h_flag",
                                  FT_BOOLEAN, 16, TFS(&mip6_bu_h_flag_value),
                                  0x4000, NULL, HFILL }},
    { &hf_mip6_bu_l_flag,       { "Link-Local Compatibility (L) flag",
                                  "mip6.bu.l_flag",
                                  FT_BOOLEAN, 16, TFS(&mip6_bu_l_flag_value),
                                  0x2000, "Home Registration (H) flag", HFILL }},
    { &hf_mip6_bu_k_flag,       { "Key Management Compatibility (K) flag",
                                  "mip6.bu.k_flag",
                                  FT_BOOLEAN, 16, TFS(&mip6_bu_k_flag_value),
                                  0x1000, NULL,
                                  HFILL }},
    { &hf_mip6_bu_m_flag,       { "MAP Registration Compatibility (M) flag",
                                  "mip6.bu.m_flag",
                                  FT_BOOLEAN, 16, TFS(&mip6_bu_m_flag_value),
                                  0x0800, NULL,
                                  HFILL }},
    { &hf_mip6_nemo_bu_r_flag,  { "Mobile Router (R) flag",
                                  "mip6.nemo.bu.r_flag",
                                  FT_BOOLEAN, 16, TFS(&mip6_nemo_bu_r_flag_value),
                                  0x0400, NULL,
                                  HFILL }},
    { &hf_pmip6_bu_p_flag,      { "Proxy Registration (P) flag",
                                  "mip6.bu.p_flag",
                                  FT_BOOLEAN, 16, TFS(&pmip6_bu_p_flag_value),
                                  0x0200, NULL,
                                  HFILL }},
    { &hf_mip6_bu_f_flag,       { "Forcing UDP encapsulation (F) flag",
                                  "mip6.bu.f_flag",
                                  FT_BOOLEAN, 16, TFS(&mip6_bu_f_flag_value),
                                  0x0100, NULL,
                                  HFILL }},
    { &hf_pmip6_bu_t_flag,      { "TLV-header format (T) flag",
                                  "mip6.bu.t_flag",
                                  FT_BOOLEAN, 16, TFS(&pmip6_bu_t_flag_value),
                                  0x0080, NULL,
                                  HFILL }},
    { &hf_mip6_bu_lifetime,     { "Lifetime", "mip6.bu.lifetime",
                                  FT_UINT16, BASE_DEC, NULL, 0,
                                  NULL, HFILL }},

    { &hf_mip6_ba_status,       { "Status", "mip6.ba.status",
                                  FT_UINT8, BASE_DEC,
                                  VALS(mip6_ba_status_value), 0,
                                  "Binding Acknowledgement status", HFILL }},
    { &hf_mip6_ba_k_flag,       { "Key Management Compatibility (K) flag",
                                  "mip6.ba.k_flag",
                                  FT_BOOLEAN, 8, TFS(&mip6_bu_k_flag_value),
                                  0x80, NULL,
                                  HFILL }},
    { &hf_mip6_nemo_ba_r_flag,  { "Mobile Router (R) flag",
                                  "mip6.nemo.ba.r_flag",
                                  FT_BOOLEAN, 8, TFS(&mip6_nemo_bu_r_flag_value),
                                  0x40, NULL,
                                  HFILL }},
    { &hf_pmip6_ba_p_flag,      { "Proxy Registration (P) flag",
                                  "mip6.ba.p_flag",
                                  FT_BOOLEAN, 8, TFS(&pmip6_bu_p_flag_value),
                                  0x20, NULL,
                                  HFILL }},
    { &hf_pmip6_ba_t_flag,      { "TLV-header format (T) flag",
                                  "mip6.ba.t_flag",
                                  FT_BOOLEAN, 8, TFS(&pmip6_bu_t_flag_value),
                                  0x10, NULL,
                                  HFILL }},

    { &hf_mip6_ba_seqnr,        { "Sequence number", "mip6.ba.seqnr",
                                  FT_UINT16, BASE_DEC, NULL, 0,
                                  NULL, HFILL }},
    { &hf_mip6_ba_lifetime,     { "Lifetime", "mip6.ba.lifetime",
                                  FT_UINT16, BASE_DEC, NULL, 0,
                                  NULL, HFILL }},

    { &hf_mip6_be_status,       { "Status", "mip6.be.status",
                                  FT_UINT8, BASE_DEC,
                                  VALS(mip6_be_status_value), 0,
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
                                  VALS(fmip6_fback_status_value), 0,
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

    { &hf_mip6_hb_u_flag,       { "Unsolicited (U) flag", "mip6.hb.u_flag",
                                  FT_BOOLEAN, 8, TFS(&mip6_hb_u_flag_value),
                                  0x02, NULL, HFILL }},
    { &hf_mip6_hb_r_flag,       { "Response (R) flag", "mip6.hb.r_flag",
                                  FT_BOOLEAN, 8, TFS(&mip6_hb_r_flag_value),
                                  0x01, NULL, HFILL }},
    { &hf_mip6_hb_seqnr,        { "Sequence number", "mip6.hb.seqnr",
                                  FT_UINT32, BASE_DEC, NULL, 0,
                                  NULL, HFILL }},

    { &hf_mip6_bra_interval,    { "Refresh interval", "mip6.bra.interval",
                                  FT_UINT16, BASE_DEC, NULL, 0,
                                 NULL, HFILL }},

    { &hf_mip6_acoa_acoa,       { "Alternate care-of address", "mip6.acoa.acoa",
                                  FT_IPv6, BASE_NONE, NULL, 0,
                                  NULL, HFILL }},

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
                                  FT_UINT8, BASE_DEC, VALS(fmip6_lla_optcode_value), 0,
                                  NULL, HFILL }},

    { &hf_mip6_nemo_mnp_pfl,    { "Mobile Network Prefix Length", "mip6.nemo.mnp.pfl",
                                  FT_UINT8, BASE_DEC, NULL, 0,
                                  NULL, HFILL }},

    { &hf_mip6_nemo_mnp_mnp,    { "Mobile Network Prefix", "mip6.nemo.mnp.mnp",
                                  FT_IPv6, BASE_NONE, NULL, 0,
                                  NULL, HFILL }},

    { &hf_mip6_mnid_subtype,    { "Subtype", "mip6.mnid.subtype",
                      FT_UINT8, BASE_DEC, VALS(mip6_mnid_subtype_value), 0,
                      NULL, HFILL }},

    { &hf_mip6_vsm_vid,         { "VendorId", "mip6.vsm.vendorId",
                      FT_UINT32, BASE_DEC|BASE_EXT_STRING, &sminmpec_values_ext, 0x0,
                      NULL, HFILL }},

    { &hf_mip6_vsm_subtype,     { "Subtype", "mip6.vsm.subtype",
                      FT_UINT8, BASE_DEC, VALS(mip6_vsm_subtype_value), 0,
                      NULL, HFILL }},

    { &hf_mip6_vsm_subtype_3gpp, { "Subtype", "mip6.vsm.subtype",
                       FT_UINT8, BASE_DEC, VALS(mip6_vsm_subtype_3gpp_value), 0,
                       NULL, HFILL }},

    { &hf_pmip6_hi_opttype,     { "Handoff Indicator Option type", "mip6.hi",
                      FT_UINT8, BASE_DEC, VALS(pmip6_hi_opttype_value), 0,
                      NULL, HFILL }},

    { &hf_pmip6_att_opttype,    { "Access Technology Type Option type", "mip6.att",
                      FT_UINT8, BASE_DEC, VALS(pmip6_att_opttype_value), 0,
                      NULL, HFILL }},

    { &hf_pmip6_timestamp,      { "Timestamp", "mip6.timestamp",
                      FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }},

    { &hf_pmip6_opt_lila_lla,       { "Link-local Address", "mip6.lila_lla",
                                    FT_IPv6, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_pmip6_rc,             { "Restart Counter", "mip6.rc",
                      FT_UINT32, BASE_DEC, NULL, 0x0,
                      NULL, HFILL}},

    { &hf_mip6_ipv4ha_preflen,  { "Prefix-len", "mip6.ipv4ha.preflen",
                      FT_UINT8, BASE_DEC, NULL, 0xfc,
                      NULL, HFILL}},

    { &hf_mip6_ipv4ha_p_flag,   { "mobile network prefix (P) flag", "mip6.ipv4ha.p_flag",
                      FT_BOOLEAN, 16, TFS(&mip6_ipv4ha_p_flag_value), 0x0200,
                      NULL, HFILL }},

    { &hf_mip6_ipv4ha_ha,       { "IPv4 Home Address", "mip6.ipv4ha.ha",
                      FT_IPv4, BASE_NONE, NULL, 0x0,
                      NULL, HFILL }},

    { &hf_mip6_ipv4aa_status,   { "Status", "mip6.ipv4aa.sts",
                      FT_UINT8, BASE_DEC, NULL, 0x0,
                      NULL, HFILL}},

    { &hf_pmip6_gre_key,        { "GRE Key", "mip6.gre_key",
                      FT_UINT32, BASE_DEC, NULL, 0x0,
                      NULL, HFILL}},

    { &hf_mip6_ipv4dra_dra,       { "IPv4 Default-Router Address", "mip6.ipv4dra.dra",
                    FT_IPv4, BASE_NONE, NULL, 0x0,
                    NULL, HFILL }},

    { &hf_mip6_mobility_opt,    { "Mobility Options", "mip6.mobility_opt",
                      FT_UINT8, BASE_DEC, VALS(mip6_mobility_options), 0,
                      NULL, HFILL }},
    { &hf_pmip6_bri_brtype,     { "B.R. Type",  "mip6.bri_br.type",
                    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_pmip6_bri_rtrigger,   { "R. Trigger", "mip6.bri_r.trigger",
                    FT_UINT8, BASE_DEC, VALS(pmip6_bri_rtrigger), 0x0, NULL, HFILL }},

    { &hf_pmip6_bri_status,     { "Status", "mip6.bri_status",
                    FT_UINT8, BASE_DEC, VALS(pmip6_bri_status), 0x0, NULL, HFILL }},

    { &hf_pmip6_bri_seqnr,      { "Sequence Number", "mip6._bri_seqnr",
                    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_pmip6_bri_ip_flag,    { "Proxy Binding (P) Flag", "mip6.bri_ip",
                    FT_BOOLEAN, 8, TFS(&tfs_set_notset),
                    0x80, NULL, HFILL }},

    { &hf_pmip6_bri_ia_flag,    { "Acknowledge (A) Flag", "mip6.bri_ia",
                    FT_BOOLEAN, 8, TFS(&tfs_set_notset),
                    0x40, NULL, HFILL }},

    { &hf_pmip6_bri_ig_flag,    { "Global (G) Flag", "mip6.bri_ig",
                    FT_BOOLEAN, 8, TFS(&tfs_set_notset),
                    0x20, NULL, HFILL }},

    { &hf_pmip6_bri_ap_flag,    { "Proxy Binding (P) Flag", "mip6.bri_ap",
                    FT_BOOLEAN, 8, TFS(&tfs_set_notset),
                    0x80, NULL, HFILL }},

    { &hf_pmip6_bri_ag_flag,    { "Global (G) Flag", "mip6.bri_ag",
                    FT_BOOLEAN, 8, TFS(&tfs_set_notset),
                    0x40, NULL, HFILL }},

    { &hf_pmip6_bri_res,        { "Reserved: 1 byte", "mip6.bri_res",
                    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

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
        &ett_mip6_nemo_opt_mnp,
        &ett_mip6_opt_mnid,
        &ett_mip6_opt_vsm,
        &ett_mip6_opt_ssm,
        &ett_pmip6_opt_hnp,
        &ett_pmip6_opt_hi,
        &ett_pmip6_opt_att,
        &ett_pmip6_opt_lla,
        &ett_pmip6_opt_ts,
        &ett_pmip6_opt_rc,
        &ett_mip6_opt_ipv4ha,
        &ett_mip6_opt_ipv4aa,
        &ett_pmip6_opt_grek,
        &ett_mip6_opt_ipv4hareq,
        &ett_mip6_opt_ipv4harep,
        &ett_mip6_opt_ipv4dra,
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
    dissector_add_uint("ip.proto", IP_PROTO_MIPV6_OLD, mip6_handle);
    dissector_add_uint("ip.proto", IP_PROTO_MIPV6, mip6_handle);
    ip_dissector_table = find_dissector_table("ip.proto");
}
