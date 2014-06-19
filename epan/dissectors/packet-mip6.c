/* packet-mip6.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * References:
 * RFC 3775, Mobility Support in IPv6
 * RFC 4285, Authentication Protocol for Mobile IPv6
 * RFC 4866, Enhanced Route Optimization for Mobile IPv6
 * RFC 5026, Mobile IPv6 Bootstrapping in Split Scenario
 * RFC 5094, Mobile IPv6 Vendor Specific Option
 * RFC 5096, Mobile IPv6 Experimental Messages
 * RFC 5213, Proxy Mobile IPv6
 * RFC 5555, Mobile IPv6 Support for Dual Stack Hosts and Routers (Errata)
 * RFC 5568. Mobile IPv6 Fast Handovers
 * RFC 5648, Multiple Care-of Addresses Registration
 * RFC 5844, IPv4 Support for Proxy Mobile IPv6
 * RFC 5949, Fast Handovers for Proxy Mobile IPv6
 * RFC 6275, Mobility Support in IPv6 (Obsoletes RFC 3775).
 * RFC 6602, Bulk Binding Update Support for Proxy Mobile IPv6
 *
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/to_str.h>

#include <epan/ipproto.h>
#include <epan/expert.h>
#include <epan/ip_opts.h>
#include <epan/expert.h>
#include <epan/sminmpec.h>

#include "packet-ntp.h"
#include "packet-gtpv2.h"
#include "packet-e164.h"
#include "packet-e212.h"
#include "packet-gsm_a_common.h"

void proto_register_mip6(void);
void proto_reg_handoff_mip6(void);

#define UDP_PORT_PMIP6_CNTL 5436

static dissector_table_t mip6_vsm_dissector_table;

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
    MIP6_LRI    = 17,
    MIP6_LRA    = 18
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
    {MIP6_LRI,    "Localized Routing Initiation"},      /* [RFC6705] */
    {MIP6_LRA,    "Localized Routing Acknowledgment"},  /* [RFC6705] */

    {0,      NULL}
};
static value_string_ext mip6_mh_types_ext = VALUE_STRING_EXT_INIT(mip6_mh_types);

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
    MIP6_RECAP     = 46,        /* 46 Redirect-Capability Mobility Option [RFC6463] */
    MIP6_REDIR     = 47,        /* 47 Redirect Mobility Option [RFC6463] */
    MIP6_LOAD_INF  = 48,        /* 48 Load Information Mobility Option [RFC6463] */
    MIP6_ALT_IP4_CO= 49,        /* 49 Alternate IPv4 Care-of Address [RFC6463] */
    MIP6_MNG       = 50,        /* 50 Mobile Node Group Identifier [RFC6602] */
    MIP6_MAG_IPv6  = 51,        /* 51 MAG IPv6 Address [RFC6705] */
    MIP6_ACC_NET_ID= 52         /* 52 Access Network Identifier [RFC6757] */

} optTypes;

/* Mobility Option types
 * http://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml
 */

static const value_string mip6_mobility_options[] = {
    { MIP6_PAD1,       "Pad1"},                                         /* RFC3775 */
    { MIP6_PADN,       "PadN"},                                         /* RFC3775 */
    { MIP6_BRA,        "Binding Refresh Advice"},                       /* RFC3775 */
    { MIP6_ACOA,       "Alternate Care-of Address"},                    /* RFC3775 */
    { MIP6_NI,         "Nonce Indices"},                                /* RFC3775 */
    { MIP6_AUTD,       "Authorization Data"},                           /* RFC3775 */
    { MIP6_MNP,        "Mobile Network Prefix"},                        /* RFC3963 */
    { MIP6_MHLLA,      "Mobility Header Link-Layer Address"},           /* RFC5568 */
    { MIP6_MNID,       "Mobile Node Identifier"},                       /* RFC4283 MN-ID*/
    { MIP6_AUTH,       "AUTH"},                                         /* RFC4285 */
    { MIP6_MESGID,     "MESG-ID"},                                      /* RFC4285 */
    { MIP6_CGAPR,      "CGA Parameters Request"},                       /* RFC4866 */
    { MIP6_CGAR,       "CGA Parameters"},                               /* RFC4866 */
    { MIP6_SIGN,       "Signature"},                                    /* RFC4866 */
    { MIP6_PHKT,       "Permanent Home Keygen Token"},                  /* RFC4866 */
    { MIP6_MOCOTI,     "Care-of Test Init"},                            /* RFC4866 */
    { MIP6_MOCOT,      "Care-of Test"},                                 /* RFC4866 */
    { MIP6_DNSU,       "DNS-UPDATE-TYPE"},                              /* RFC5026 */
    { MIP6_EM,         "Experimental"},                                 /* RFC5096 */
    { MIP6_VSM,        "Vendor Specific"},                              /* RFC5094 */
    { MIP6_SSM,        "Service Selection"},                            /* RFC5149 */
    { MIP6_BADFF,      "Binding Authorization Data for FMIPv6 (BADF)"}, /* RFC5568 */
    { MIP6_HNP,        "Home Network Prefix"},                          /* RFC5213 */
    { MIP6_MOHI,       "Handoff Indicator"},                            /* RFC5213 */
    { MIP6_ATT,        "Access Technology Type"},                       /* RFC5213 */
    { MIP6_MNLLI,      "Mobile Node Link-layer Identifier"},            /* RFC5213 */
    { MIP6_LLA,        "Link-local Address"},                           /* RFC5213 */
    { MIP6_TS,         "Timestamp"},                                    /* RFC5213 */
    { MIP6_RC,         "Restart Counter"},                              /* RFC5847 */
    { MIP6_IPV4HA,     "IPv4 Home Address"},                            /* RFC5555 */
    { MIP6_IPV4AA,     "IPv4 Address Acknowledgement"},                 /* RFC5555 */
    { MIP6_NATD,       "NAT Detection"},                                /* RFC5555 */
    { MIP6_IPV4COA,    "IPv4 Care-of Address"},                         /* RFC5555 */
    { MIP6_GREK,       "GRE Key"},                                      /* RFC5845 */
    { MIP6_MHIPV6AP,   "Mobility Header IPv6 Address/Prefix"},          /* RFC5568 */
    { MIP6_BI,         "Binding Identifier"},                           /* RFC5648 */
    { MIP6_IPV4HAREQ,  "IPv4 Home Address Request"},                    /* RFC5844 */
    { MIP6_IPV4HAREP,  "IPv4 Home Address Reply"},                      /* RFC5844 */
    { MIP6_IPV4DRA,    "IPv4 Default-Router Address"},                  /* RFC5844 */
    { MIP6_IPV4DSM,    "IPv4 DHCP Support Mode"},                       /* RFC5844 */
    { MIP6_CR,         "Context Request"},                              /* RFC5949 */
    { MIP6_LMAA,       "Local Mobility Anchor Address"},                /* RFC5949 */
    { MIP6_MNLLAII,    "Mobile Node Link-local Address Interface Identifier"}, /* RFC5949 */
    { MIP6_TB,         "Transient Binding"},                            /* RFC6058 */
    { MIP6_FS,         "Flow Summary"},                                 /* RFC6089 */
    { MIP6_FI,         "Flow Identification"},                          /* RFC6089 */
    { MIP6_RECAP,      "Redirect-Capability"},                          /* RFC6463 */
    { MIP6_REDIR,      "Redirect"},                                     /* RFC6463 */
    { MIP6_LOAD_INF,   "Load Information"},                             /* RFC6463 */
    { MIP6_ALT_IP4_CO, "Alternate IPv4 Care-of Address"},               /* RFC6463 */
    { MIP6_MNG,        "Mobile Node Group Identifier"},                 /* RFC6602 */
    { MIP6_MAG_IPv6,   "MAG IPv6 Address"},                             /* RFC6705 */
    { MIP6_ACC_NET_ID, "Access Network Identifier"},                    /* RFC6757 */

    { 0, NULL }
};
static value_string_ext mip6_mobility_options_ext = VALUE_STRING_EXT_INIT(mip6_mobility_options);

/*
 * Status Codes (DNS Update Mobility Option)
 * http://www.iana.org/assignments/mobility-parameters/mobility-parameters.xml#mobility-parameters-3
 */

static const value_string mip6_dnsu_status_values[] = {
    { 0, "DNS update performed"},                    /* [RFC5026] */
    /* 1-127 Unassigned   */
    { 128, "Reason unspecified"},                    /* [RFC5026] */
    { 129, "Administratively prohibited"},           /* [RFC5026] */
    { 130, "DNS Update Failed"},                     /* [RFC5026] */
    /* 131-255 Unassigned  */

    {   0, NULL }
};

static const true_false_string mip6_dnsu_r_flag_value = {
    "Mobile Node is requesting the HA to remove the DNS entry",
    "Mobile Node is requesting the HA to create or update a DNS entry"
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

static const true_false_string pmip6_bu_b_flag_value = {
    "Enable bulk binding update support",
    "Disable bulk binding update support"
};

static const true_false_string pmip6_ba_b_flag_value = {
    "Enabled bulk binding update support",
    "Disabled bulk binding update support"
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
    { 174, "Invalid Care-of Address" },                             /* [RFC6275] */
    { 175, "INVALID_MOBILE_NODE_GROUP_IDENTIFIER" },                /* [RFC6602] */
    { 176, "REINIT_SA_WITH_HAC" },                                  /* [RFC6618] */

    {   0, NULL }
};
static value_string_ext mip6_ba_status_value_ext = VALUE_STRING_EXT_INIT(mip6_ba_status_value);

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


/* Enumerating Algorithms */
static const value_string mip6_auth_subtype_value[] = {
    {   0, "Reserved (not available for assignment)" },
    {   3, "HMAC_SHA1_SPI" },
    {   5, "Reserved for use by 3GPP2" },
    {   0, NULL }
};

/* mobile network prefix flag description */
static const true_false_string mip6_ipv4ha_p_flag_value = {
    "mobile network prefixt requested",
    "mobile network prefix not requested"
};

/* NAT Detection Option F flag values */
static const true_false_string mip6_natd_f_flag_value = {
    "MUST use UDP encapsulation",
    "Do not use UDP encapsulation"
};


/* NAT Detection Option F flag values */
static const true_false_string mip6_ipv4dsm_s_flag_value = {
    "DHCP Server",
    "DHCP Relay"
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
    {  18, "PGW Back-Off Time" },                          /* 3GPP TS 29.275 [7] */
    {  19, "Signalling Priority Indication" },             /* 3GPP TS 29.275 [7] */
    {  20, "Additional Protocol Configuration Options" },  /* 3GPP TS 29.275 [7] */
    {   0, NULL }
};
static value_string_ext mip6_vsm_subtype_3gpp_value_ext = VALUE_STRING_EXT_INIT(mip6_vsm_subtype_3gpp_value);


/* Handoff Indicator Option type
 * http://www.iana.org/assignments/mobility-parameters/mobility-parameters.xml#mobility-parameters-9
 */
static const value_string pmip6_hi_opttype_value[] = {
    {   0, "Reserved" },
    {   1, "Attachment over a new interface" },
    {   2, "Handoff between two different interfaces of the mobile node" },
    {   3, "Handoff between mobile access gateways for the same interface" },
    {   4, "Handoff state unknown" },
    {   5, "Handoff state not changed (Re-registration)" },
    {   0, NULL }
};

/* Access Technology Type Option type
 * http://www.iana.org/assignments/mobility-parameters/mobility-parameters.xml#mobility-parameters-10
 */
static const value_string pmip6_att_att_value[] = {
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
static value_string_ext pmip6_att_att_value_ext = VALUE_STRING_EXT_INIT(pmip6_att_att_value);

/* IPv4 Home Address Reply Status Codes [RFC5844]
 * http://www.iana.org/assignments/mobility-parameters/mobility-parameters.xml#home-address-reply
 */

static const value_string pmip6_ipv4aa_status_values[] = {
    {   0, "Success" },
    /* 1-127 Unassigned */
    {   128, "Virtual" },
    {   129, "PPP" },
    {   130, "IEEE 802.3" },
    {   131, "IEEE 802.11a/b/g" },
    {   132, "IEEE 802.16e" },
    /* 133-255 Unassigned  */
    {   0, NULL }
};

/* PMIP6 BRI R. Trigger values */
static const value_string pmip6_bri_rtrigger[] = {
    { 0x00,     "Unspecified"},
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

#if 0
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
#endif

/* Mobile Node Group Identifier Type
 * http://www.iana.org/assignments/mobility-parameters/mobility-parameters.xml#mobile-node-group-id-type
 */

static const value_string mip6_mng_id_type_vals[] = {
    { 0x00,     "Reserved"},
    { 0x01,     "Bulk Binding Update Group"},
    { 0,        NULL},
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
#define PMIP6_BRI_FLAGS_LEN      2

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

#define MIP6_AUTH_MINLEN      6
#define MIP6_CGAPR_MINLEN     0
#define MIP6_CGAR_MINLEN      1
#define MIP6_SIGN_MINLEN      1
#define MIP6_PHKT_MINLEN      1
#define MIP6_MOCOTI_MINLEN    0
#define MIP6_MOCOT_MINLEN     8
#define MIP6_DNSU_MINLEN      5
#define MIP6_EM_MINLEN        1

#define MIP6_VSM_MINLEN       2
#define MIP6_VSM_VID_OFF      2
#define MIP6_VSM_VID_LEN      4
#define MIP6_VSM_SUBTYPE_OFF  6
#define MIP6_VSM_SUBTYPE_LEN  1
#define MIP6_VSM_DATA_OFF     7


#define MIP6_SSM_MINLEN       1
#define MIP6_SSM_SSM_OFF      2

#define MIP6_BADFF_MINLEN     4

#define PMIP6_HI_LEN          2
#define PMIP6_HI_HI_OFF       3
#define PMIP6_HI_HI_LEN       1

#define PMIP6_ATT_LEN         2
#define PMIP6_ATT_ATT_OFF     3
#define PMIP6_ATT_ATT_LEN     1

#define PMIP6_MNLLI_MIN_LEN   1

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

#define MIP6_NATD_LEN              6

#define MIP6_IPV4COA_LEN           6

#define PMIP6_GREK_LEN             6
#define PMIP6_GREK_ID_OFF          4
#define PMIP6_GREK_ID_LEN          4

#define MIP6_MHIPV6AP_MIN_LEN      2

#define MIP6_BI_MIN_LEN            4

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

#define MIP6_IPV4DSM_LEN      2

#define MIP6_CR_MIN_LEN       4

#define MIP6_LMAA_MIN_LEN     6

#define MIP6_RECAP_LEN        2
#define MIP6_REDIR_MIN_LEN    6
#define MIP6_REDIR_FLAG_K     0x80
#define MIP6_REDIR_FLAG_N     0x40
#define MIP6_REDIR_FLAG_RSV   0x3F

#define MIP6_LOAD_INF_LEN     18
#define MIP6_ALT_IP4_LEN      4

#define MIP6_MNG_LEN          6

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
/* static int hf_mip6_cot_token = -1; */

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
static int hf_pmip6_bu_b_flag = -1;
static int hf_mip6_bu_lifetime = -1;

static int hf_mip6_ba_status = -1;
static int hf_mip6_ba_k_flag = -1;
static int hf_mip6_nemo_ba_r_flag = -1;
static int hf_pmip6_ba_p_flag = -1;
static int hf_pmip6_ba_t_flag = -1;
static int hf_pmip6_ba_b_flag = -1;
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

static int hf_mip6_hi_seqnr = -1;
static int hf_mip6_hi_s_flag = -1;
static int hf_mip6_hi_u_flag = -1;
static int hf_mip6_hi_code = -1;

static int hf_mip6_hack_seqnr = -1;
static int hf_mip6_hack_code = -1;

static int hf_mip6_opt_3gpp_reserved = -1;
static int hf_mip6_opt_3gpp_flag_m = -1;
static int hf_mip6_opt_3gpp_spec_pmipv6_err_code = -1;
static int hf_mip6_opt_3gpp_pdn_gw_ipv4_addr = -1;
static int hf_mip6_opt_3gpp_pdn_gw_ipv6_addr = -1;
static int hf_mip6_opt_3gpp_dhcpv4_addr_all_proc_ind = -1;
static int hf_mip6_opt_3gpp_pdn_type = -1;
static int hf_mip6_opt_3gpp_pdn_ind_cause = -1;
static int hf_mip6_opt_3gpp_chg_id = -1;
static int hf_mip6_opt_3gpp_charging_characteristic = -1;
static int hf_mip6_opt_3gpp_mei = -1;
static int hf_mip6_opt_3gpp_msisdn = -1;
static int hf_mip6_opt_3gpp_apn_rest = -1;
static int hf_mip6_opt_3gpp_max_apn_rest = -1;
static int hf_mip6_opt_3gpp_imsi = -1;
static int hf_mip6_opt_3gpp_pdn_conn_id = -1;
static int hf_hf_mip6_opt_3gpp_lapi = -1;

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

static int hf_mip6_opt_badff_spi = -1;
static int hf_mip6_opt_badff_auth = -1;

static int hf_mip6_opt_auth_sub_type = -1;
static int hf_mip6_opt_auth_mobility_spi = -1;
static int hf_mip6_opt_auth_auth_data = -1;

static int hf_mip6_opt_cgar_cga_par = -1;
static int hf_mip6_opt_sign_sign = -1;
static int hf_mip6_opt_phkt_phkt = -1;
static int hf_mip6_opt_mocot_co_keygen_tok = -1;

static int hf_mip6_opt_dnsu_status = -1;
static int hf_mip6_opt_dnsu_flag_r = -1;
static int hf_mip6_opt_dnsu_mn_id = -1;

static int hf_mip6_opt_em_data = -1;

static int hf_pmip6_hi_hi = -1;
static int hf_pmip6_hi_reserved = -1;

static int hf_pmip6_att_reserved = -1;
static int hf_pmip6_att_att = -1;

static int hf_mip6_opt_mnlli_reserved = -1;
static int hf_mip6_opt_mnlli_lli = -1;

static int hf_pmip6_timestamp = -1;
static int hf_pmip6_rc = -1;
static int hf_mip6_ipv4ha_preflen = -1;
static int hf_mip6_ipv4ha_p_flag = -1;
static int hf_mip6_ipv4ha_ha = -1;
static int hf_mip6_ipv4aa_status = -1;

static int hf_mip6_opt_natd_f_flag = -1;
static int hf_mip6_opt_natd_reserved = -1;
static int hf_mip6_opt_natd_refresh_t = -1;

static int hf_mip6_opt_ipv4coa_reserved = -1;
static int hf_mip6_opt_ipv4coa_addr = -1;

static int hf_pmip6_gre_key = -1;
static int hf_mip6_opt_mhipv6ap_opt_code = -1;
static int hf_mip6_opt_mhipv6ap_prefix_l = -1;
static int hf_mip6_ipv4dra_reserved = -1;
static int hf_mip6_ipv4dra_dra = -1;

static int hf_mip6_ipv4dsm_reserved = -1;
static int hf_mip6_ipv4dsm_s_flag = -1;
static int hf_mip6_cr_reserved = -1;
static int hf_mip6_cr_req_type = -1;
static int hf_mip6_cr_req_length = -1;

static int hf_mip6_lmaa_opt_code = -1;
static int hf_mip6_lmaa_reserved = -1;
static int hf_mip6_lmaa_ipv4 = -1;
static int hf_mip6_lmaa_ipv6 = -1;

static int hf_mip6_mobility_opt = -1;
static int hf_mip6_opt_len = -1;

static int hf_mip6_opt_bi_bid = -1;
static int hf_mip6_opt_bi_status = -1;
static int hf_mip6_bi_h_flag = -1;
static int hf_mip6_bi_coa_ipv4 = -1;
static int hf_mip6_bi_coa_ipv6 = -1;

/* PMIP BRI */
static int hf_pmip6_bri_brtype = -1;
static int hf_pmip6_bri_rtrigger = -1;
static int hf_pmip6_bri_status = -1;
static int hf_pmip6_bri_seqnr = -1;
static int hf_pmip6_bri_ip_flag = -1;
static int hf_pmip6_bri_ap_flag = -1;
static int hf_pmip6_bri_iv_flag = -1;
static int hf_pmip6_bri_av_flag = -1;
static int hf_pmip6_bri_ig_flag = -1;
static int hf_pmip6_bri_ag_flag = -1;
static int hf_pmip6_bri_res = -1;

static int hf_mip6_opt_recap_reserved = -1;
static int hf_mip6_opt_redir_k = -1;
static int hf_mip6_opt_redir_n = -1;
static int hf_mip6_opt_redir_reserved = -1;
static int hf_mip6_opt_redir_addr_r2LMA_ipv6 = -1;
static int hf_mip6_opt_redir_addr_r2LMA_ipv4 = -1;
static int hf_mip6_opt_load_inf_priority = -1;
static int hf_mip6_opt_load_inf_sessions_in_use = -1;
static int hf_mip6_opt_load_inf_maximum_sessions = -1;
static int hf_mip6_opt_load_inf_used_capacity = -1;
static int hf_mip6_opt_load_inf_maximum_capacity = -1;
static int hf_mip6_opt_alt_ip4 = -1;

/* Mobile Node Group Identifier Optionm */
static int hf_mip6_opt_mng_sub_type = -1;
static int hf_mip6_opt_mng_reserved = -1;
static int hf_mip6_opt_mng_mng_id = -1;

static int hf_pmip6_opt_lila_lla = -1;

/* Initialize the subtree pointers */
static gint ett_mip6 = -1;
static gint ett_mip6_opt_pad1 = -1;
static gint ett_mip6_opt_padn = -1;
static gint ett_mip6_opts = -1;
static gint ett_mip6_opt_bra = -1;
static gint ett_mip6_opt_acoa = -1;
static gint ett_mip6_opt_ni = -1;
static gint ett_mip6_opt_bad = -1;
static gint ett_mip6_nemo_opt_mnp = -1;
static gint ett_fmip6_opt_lla = -1;
static gint ett_mip6_opt_mnid = -1;
static gint ett_mip6_opt_auth = -1;
static gint ett_mip6_opt_mesgid = -1;
static gint ett_mip6_opt_cgapr = -1;
static gint ett_mip6_opt_cgar = -1;
static gint ett_mip6_opt_sign = -1;
static gint ett_mip6_opt_phkt = -1;
static gint ett_mip6_opt_mocoti = -1;
static gint ett_mip6_opt_mocot = -1;
static gint ett_mip6_opt_dnsu = -1;
static gint ett_mip6_opt_em = -1;
static gint ett_mip6_opt_vsm = -1;
static gint ett_mip6_opt_ssm = -1;
static gint ett_mip6_opt_badff = -1;
static gint ett_pmip6_opt_hnp = -1;
static gint ett_pmip6_opt_hi = -1;
static gint ett_pmip6_opt_att = -1;
static gint ett_pmip6_opt_mnlli = -1;
static gint ett_pmip6_opt_lla = -1;
static gint ett_pmip6_opt_ts = -1;
static gint ett_pmip6_opt_rc = -1;
static gint ett_mip6_opt_ipv4ha = -1;
static gint ett_mip6_opt_ipv4aa = -1;
static gint ett_mip6_opt_natd = -1;
static gint ett_mip6_opt_ipv4coa = -1;
static gint ett_pmip6_opt_grek = -1;
static gint ett_pmip6_opt_mhipv6ap = -1;
static gint ett_pmip6_opt_bi = -1;
static gint ett_mip6_opt_ipv4hareq = -1;
static gint ett_mip6_opt_ipv4harep = -1;
static gint ett_mip6_opt_ipv4dra = -1;
static gint ett_mip6_opt_ipv4dsm = -1;
static gint ett_mip6_opt_cr = -1;
static gint ett_mip6_opt_lmaa = -1;
static gint ett_mip6_opt_recap = -1;
static gint ett_mip6_opt_redir = -1;
static gint ett_mip6_opt_load_inf = -1;
static gint ett_mip6_opt_alt_ip4 = -1;
static gint ett_mip6_opt_mng = -1;

static expert_field ei_mip6_ie_not_dissected = EI_INIT;


typedef struct mip6_opt {
  int           optcode;            /**< code for option */
  const char   *name;               /**< name of option */
  int          *subtree_index;      /**< pointer to subtree index for option */
  opt_len_type  len_type;           /**< type of option length field */
  int           optlen;             /**< value length should be (minimum if VARIABLE) */
  void  (*dissect)(const struct mip6_opt *,
                   tvbuff_t *,
                   int,
                   guint,
                   packet_info *,
                   proto_tree *,
                   proto_item *);   /**< routine to dissect option */
} mip6_opt;

/* Functions to dissect the mobility headers */
static int
dissect_mip6_brr(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo _U_)
{
    if (mip6_tree) {
        /*proto_tree *data_tree;*/
        /*proto_item *ti;*/

        /*ti = */proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF,
                                     MIP6_BRR_LEN, "Binding Refresh Request");
        /*data_tree = proto_item_add_subtree(ti, ett_mip6);*/
    }

    return MIP6_DATA_OFF + MIP6_BRR_LEN;
}

static int
dissect_mip6_hoti(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo _U_)
{
    if (mip6_tree) {
        proto_tree *data_tree;
        proto_item *ti;

        ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF,
                MIP6_HOTI_LEN, "Home Test Init");
        data_tree = proto_item_add_subtree(ti, ett_mip6);

        proto_tree_add_item(data_tree, hf_mip6_hoti_cookie, tvb,
                MIP6_HOTI_COOKIE_OFF, MIP6_HOTI_COOKIE_LEN, ENC_BIG_ENDIAN);
    }

    return MIP6_DATA_OFF + MIP6_HOTI_LEN;
}

static int
dissect_mip6_coti(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo _U_)
{
    if (mip6_tree) {
        proto_tree *data_tree;
        proto_item *ti;

        ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF,
                MIP6_COTI_LEN, "Care-of Test Init");
        data_tree = proto_item_add_subtree(ti, ett_mip6);

        proto_tree_add_item(data_tree, hf_mip6_coti_cookie, tvb,
                MIP6_COTI_COOKIE_OFF, MIP6_COTI_COOKIE_LEN, ENC_BIG_ENDIAN);
    }

    return MIP6_DATA_OFF + MIP6_COTI_LEN;
}

static int
dissect_mip6_hot(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo _U_)
{
    if (mip6_tree) {
        proto_tree *data_tree;
        proto_item *ti;

        ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF,
                MIP6_HOT_LEN, "Home Test");
        data_tree = proto_item_add_subtree(ti, ett_mip6);

        proto_tree_add_item(data_tree, hf_mip6_hot_nindex, tvb,
                MIP6_HOT_INDEX_OFF, MIP6_HOT_INDEX_LEN, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_mip6_hot_cookie, tvb,
                MIP6_HOT_COOKIE_OFF, MIP6_HOT_COOKIE_LEN, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_mip6_hot_token, tvb,
                MIP6_HOT_TOKEN_OFF, MIP6_HOT_TOKEN_LEN, ENC_BIG_ENDIAN);
    }

    return MIP6_DATA_OFF + MIP6_HOT_LEN;
}

static int
dissect_mip6_cot(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo _U_)
{
    if (mip6_tree) {
        proto_tree *data_tree;
        proto_item *ti;

        ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF,
                MIP6_COT_LEN, "Care-of Test");
        data_tree = proto_item_add_subtree(ti, ett_mip6);

        proto_tree_add_item(data_tree, hf_mip6_cot_nindex, tvb,
                MIP6_COT_INDEX_OFF, MIP6_COT_INDEX_LEN, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_mip6_cot_cookie, tvb,
                MIP6_COT_COOKIE_OFF, MIP6_COT_COOKIE_LEN, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_mip6_hot_token, tvb,
                MIP6_COT_TOKEN_OFF, MIP6_COT_TOKEN_LEN, ENC_BIG_ENDIAN);
    }

    return MIP6_DATA_OFF + MIP6_COT_LEN;
}

/* RFC3775 */

/*
http://www.iana.org/assignments/mobility-parameters/mobility-parameters.xml#mobility-parameters-11
A 0x8000 [RFC6275]
H 0x4000 [RFC6275]
L 0x2000 [RFC6275]
K 0x1000 [RFC6275]
M 0x0800 [RFC4140]
R 0x0400 [RFC3963]
P 0x0200 [RFC5213]
F 0x0100 [RFC5555]
T 0x0080 [RFC5845]
B 0x0040 [RFC6602]
*/
static int
dissect_mip6_bu(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo _U_)
{
    if (mip6_tree) {
        proto_tree *data_tree;
        proto_item *ti;
        int         lifetime;

        ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF,
                MIP6_BU_LEN, "Binding Update");
        data_tree = proto_item_add_subtree(ti, ett_mip6);

        proto_tree_add_item(data_tree, hf_mip6_bu_seqnr, tvb,
                MIP6_BU_SEQNR_OFF, MIP6_BU_SEQNR_LEN, ENC_BIG_ENDIAN);

        proto_tree_add_item(data_tree, hf_mip6_bu_a_flag, tvb,
                MIP6_BU_FLAGS_OFF, MIP6_BU_FLAGS_LEN, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_mip6_bu_h_flag, tvb,
                MIP6_BU_FLAGS_OFF, MIP6_BU_FLAGS_LEN, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_mip6_bu_l_flag, tvb,
                MIP6_BU_FLAGS_OFF, MIP6_BU_FLAGS_LEN, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_mip6_bu_k_flag, tvb,
                MIP6_BU_FLAGS_OFF, MIP6_BU_FLAGS_LEN, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_mip6_bu_m_flag, tvb,
                MIP6_BU_FLAGS_OFF, MIP6_BU_FLAGS_LEN, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_mip6_nemo_bu_r_flag, tvb,
                MIP6_BU_FLAGS_OFF, MIP6_BU_FLAGS_LEN, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_pmip6_bu_p_flag, tvb,
                MIP6_BU_FLAGS_OFF, MIP6_BU_FLAGS_LEN, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_mip6_bu_f_flag, tvb,
                MIP6_BU_FLAGS_OFF, MIP6_BU_FLAGS_LEN, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_pmip6_bu_t_flag, tvb,
                MIP6_BU_FLAGS_OFF, MIP6_BU_FLAGS_LEN, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_pmip6_bu_b_flag, tvb,
                MIP6_BU_FLAGS_OFF, MIP6_BU_FLAGS_LEN, ENC_BIG_ENDIAN);

        if ((tvb_get_guint8(tvb, MIP6_BU_FLAGS_OFF) & 0x0004 ) == 0x0004)
            proto_nemo = 1;

        lifetime = tvb_get_ntohs(tvb, MIP6_BU_LIFETIME_OFF);
        proto_tree_add_uint_format_value(data_tree, hf_mip6_bu_lifetime, tvb,
                MIP6_BU_LIFETIME_OFF,
                MIP6_BU_LIFETIME_LEN, lifetime,
                "%d (%ld seconds)",
                lifetime, (long)lifetime * 4);
    }

    return MIP6_DATA_OFF + MIP6_BU_LEN;
}

static int
dissect_mip6_ba(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo _U_)
{
    if (mip6_tree) {
        proto_tree *data_tree;
        proto_item *ti;
        int         lifetime;

        ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF,
                MIP6_BA_LEN, "Binding Acknowledgement");
        data_tree = proto_item_add_subtree(ti, ett_mip6);

        proto_tree_add_item(data_tree, hf_mip6_ba_status, tvb,
                MIP6_BA_STATUS_OFF, MIP6_BA_STATUS_LEN, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_mip6_ba_k_flag, tvb,
                MIP6_BA_FLAGS_OFF, MIP6_BA_FLAGS_LEN, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_mip6_nemo_ba_r_flag, tvb,
                MIP6_BA_FLAGS_OFF, MIP6_BA_FLAGS_LEN, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_pmip6_ba_p_flag, tvb,
                MIP6_BA_FLAGS_OFF, MIP6_BA_FLAGS_LEN, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_pmip6_ba_t_flag, tvb,
                MIP6_BA_FLAGS_OFF, MIP6_BA_FLAGS_LEN, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_pmip6_ba_b_flag, tvb,
                MIP6_BA_FLAGS_OFF, MIP6_BA_FLAGS_LEN, ENC_BIG_ENDIAN);
        if ((tvb_get_guint8(tvb, MIP6_BA_FLAGS_OFF) & 0x0040 ) == 0x0040)
            proto_nemo = 1;

        proto_tree_add_item(data_tree, hf_mip6_ba_seqnr, tvb,
                MIP6_BA_SEQNR_OFF, MIP6_BA_SEQNR_LEN, ENC_BIG_ENDIAN);

        lifetime = tvb_get_ntohs(tvb, MIP6_BA_LIFETIME_OFF);
        proto_tree_add_uint_format_value(data_tree, hf_mip6_ba_lifetime, tvb,
                MIP6_BA_LIFETIME_OFF,
                MIP6_BA_LIFETIME_LEN, lifetime,
                "%d (%ld seconds)",
                lifetime, (long)lifetime * 4);
    }

    return MIP6_DATA_OFF + MIP6_BA_LEN;
}

static int
dissect_mip6_be(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo _U_)
{
    if (mip6_tree) {
        proto_tree *data_tree;
        proto_item *ti;

        ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF,
                MIP6_BE_LEN, "Binding Error");
        data_tree = proto_item_add_subtree(ti, ett_mip6);

        proto_tree_add_item(data_tree, hf_mip6_be_status, tvb,
                MIP6_BE_STATUS_OFF, MIP6_BE_STATUS_LEN, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_mip6_be_haddr, tvb,
                MIP6_BE_HOA_OFF, MIP6_BE_HOA_LEN, ENC_NA);
    }

    return MIP6_DATA_OFF + MIP6_BE_LEN;
}

static int
dissect_mip6_hb(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo _U_)
{
    if (mip6_tree) {
        proto_tree *data_tree;
        proto_item *ti;

        ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF,
                MIP6_HB_LEN, "Heartbeat");
        data_tree = proto_item_add_subtree(ti, ett_mip6);

        proto_tree_add_item(data_tree, hf_mip6_hb_u_flag, tvb,
                MIP6_HB_FLAGS_OFF, MIP6_HB_FLAGS_LEN, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_mip6_hb_r_flag, tvb,
                MIP6_HB_FLAGS_OFF, MIP6_HB_FLAGS_LEN, ENC_BIG_ENDIAN);

        proto_tree_add_item(data_tree, hf_mip6_hb_seqnr, tvb,
                MIP6_HB_SEQNR_OFF, MIP6_HB_SEQNR_LEN, ENC_BIG_ENDIAN);

    }

    return MIP6_DATA_OFF + MIP6_HB_LEN;
}
/*
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                     |           Sequence #          |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |S|U|  Reserved |      Code     |                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               .
     |                                                               |
     .                                                               .
     .                          Mobility options                     .
     .                                                               .
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                 Figure 6: Handover Initiate (HI) Message

*/
static int
dissect_mip6_hi(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo _U_)
{
    if (mip6_tree) {
        proto_tree *data_tree;
        proto_item *ti;

        ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF, 4, "Handover Initiate");
        data_tree = proto_item_add_subtree(ti, ett_mip6);

        proto_tree_add_item(data_tree, hf_mip6_hi_seqnr, tvb,
                MIP6_DATA_OFF, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(data_tree, hf_mip6_hi_s_flag, tvb,
                MIP6_DATA_OFF+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_mip6_hi_u_flag, tvb,
                MIP6_DATA_OFF+2, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(data_tree, hf_mip6_hi_code, tvb,
                MIP6_DATA_OFF+3, 1, ENC_BIG_ENDIAN);

    }

    return MIP6_DATA_OFF + 4;
}

/*
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                     |           Sequence #          |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |    Reserved   |      Code     |                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               .
     |                                                               |
     .                                                               .
     .                          Mobility options                     .
     .                                                               .
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

               Figure 7: Handover Acknowledge (HAck) Message

*/

static int
dissect_mip6_hack(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo _U_)
{
    if (mip6_tree) {
        proto_tree *data_tree;
        proto_item *ti;

        ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF, 4, "Handover Acknowledge ");
        data_tree = proto_item_add_subtree(ti, ett_mip6);

        proto_tree_add_item(data_tree, hf_mip6_hack_seqnr, tvb,
                MIP6_DATA_OFF, 2, ENC_BIG_ENDIAN);


        proto_tree_add_item(data_tree, hf_mip6_hack_code, tvb,
                MIP6_DATA_OFF+3, 1, ENC_BIG_ENDIAN);

    }

    return MIP6_DATA_OFF + 4;
}

static int
dissect_mip6_unknown(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo _U_)
{
    if (mip6_tree) {
        /*proto_tree *data_tree;*/
        /*proto_item *ti;*/

        /*ti = */proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF,
                MIP6_DATA_OFF + 1, "Unknown MH Type");
        /*data_tree = proto_item_add_subtree(ti, ett_mip6);*/
    }

    return MIP6_DATA_OFF + 1;
}

static int
dissect_fmip6_fbu(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo _U_)
{
    if (mip6_tree) {
        proto_tree *data_tree;
        proto_item *ti;
        int lifetime;

        ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF,
                MIP6_BU_LEN, "Fast Binding Update");
        data_tree = proto_item_add_subtree(ti, ett_mip6);

        proto_tree_add_item(data_tree, hf_fmip6_fbu_seqnr, tvb,
                FMIP6_FBU_SEQNR_OFF, FMIP6_FBU_SEQNR_LEN, ENC_BIG_ENDIAN);

        proto_tree_add_item(data_tree, hf_fmip6_fbu_a_flag, tvb,
                FMIP6_FBU_FLAGS_OFF, FMIP6_FBU_FLAGS_LEN, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_fmip6_fbu_h_flag, tvb,
                FMIP6_FBU_FLAGS_OFF, FMIP6_FBU_FLAGS_LEN, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_fmip6_fbu_l_flag, tvb,
                FMIP6_FBU_FLAGS_OFF, FMIP6_FBU_FLAGS_LEN, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_fmip6_fbu_k_flag, tvb,
                FMIP6_FBU_FLAGS_OFF, FMIP6_FBU_FLAGS_LEN, ENC_BIG_ENDIAN);

        lifetime = tvb_get_ntohs(tvb, FMIP6_FBU_LIFETIME_OFF);
        proto_tree_add_uint_format_value(data_tree, hf_fmip6_fbu_lifetime, tvb,
                FMIP6_FBU_LIFETIME_OFF,
                FMIP6_FBU_LIFETIME_LEN, lifetime,
                "%d (%ld seconds)",
                lifetime, (long)lifetime * 4);
    }

    return MIP6_DATA_OFF + FMIP6_FBU_LEN;
}

static int
dissect_fmip6_fback(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo _U_)
{
    if (mip6_tree) {
        proto_tree *data_tree;
        proto_item *ti;
        int         lifetime;

        ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF,
                FMIP6_FBACK_LEN, "Fast Binding Acknowledgement");
        data_tree = proto_item_add_subtree(ti, ett_mip6);

        proto_tree_add_item(data_tree, hf_fmip6_fback_status, tvb,
                FMIP6_FBACK_STATUS_OFF, FMIP6_FBACK_STATUS_LEN, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_fmip6_fback_k_flag, tvb,
                FMIP6_FBACK_FLAGS_OFF, FMIP6_FBACK_FLAGS_LEN, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_fmip6_fback_seqnr, tvb,
                FMIP6_FBACK_SEQNR_OFF, FMIP6_FBACK_SEQNR_LEN, ENC_BIG_ENDIAN);
        lifetime = tvb_get_ntohs(tvb, FMIP6_FBACK_LIFETIME_OFF);
        proto_tree_add_uint_format_value(data_tree, hf_fmip6_fback_lifetime, tvb,
                FMIP6_FBACK_LIFETIME_OFF,
                FMIP6_FBACK_LIFETIME_LEN, lifetime,
                "%d (%ld seconds)",
                lifetime, (long)lifetime * 4);
    }

    return MIP6_DATA_OFF + FMIP6_FBACK_LEN;
}

static int
dissect_fmip6_fna(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo _U_)
{
    if (mip6_tree) {
        /*proto_tree *data_tree;*/
        /*proto_item *ti;*/

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
#define ACKNOWLEDGE 2

    proto_item *ti;
    proto_tree *field_tree;
    guint8      br_type;

    br_type = tvb_get_guint8(tvb, PMIP6_BRI_BRTYPE_OFF);

    /* Branch between BR Indication and BR Acknowledge */
    if ( br_type == INDICATION )
    {
        col_append_str(pinfo->cinfo, COL_INFO, " Indication");

        if (mip6_tree)
        {
            ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF,
                PMIP6_BRI_LEN, "Binding Revocation Indication");

            field_tree = proto_item_add_subtree(ti, ett_mip6);

            proto_tree_add_item(field_tree, hf_pmip6_bri_brtype, tvb,
                PMIP6_BRI_BRTYPE_OFF, PMIP6_BRI_BRTYPE_LEN, ENC_BIG_ENDIAN);

            proto_tree_add_item(field_tree, hf_pmip6_bri_rtrigger, tvb,
                PMIP6_BRI_RTRIGGER_OFF, PMIP6_BRI_RTRIGGER_LEN, ENC_BIG_ENDIAN);

            proto_tree_add_item(field_tree, hf_pmip6_bri_seqnr, tvb,
                PMIP6_BRI_SEQNR_OFF, PMIP6_BRI_SEQNR_LEN, ENC_BIG_ENDIAN);

            proto_tree_add_item(field_tree, hf_pmip6_bri_ip_flag, tvb,
                PMIP6_BRI_FLAGS_OFF, PMIP6_BRI_FLAGS_LEN, ENC_BIG_ENDIAN);

            proto_tree_add_item(field_tree, hf_pmip6_bri_iv_flag, tvb,
                PMIP6_BRI_FLAGS_OFF, PMIP6_BRI_FLAGS_LEN, ENC_BIG_ENDIAN);

            proto_tree_add_item(field_tree, hf_pmip6_bri_ig_flag, tvb,
                PMIP6_BRI_FLAGS_OFF, PMIP6_BRI_FLAGS_LEN, ENC_BIG_ENDIAN);

            proto_tree_add_item(field_tree, hf_pmip6_bri_res, tvb,
                PMIP6_BRI_FLAGS_OFF, PMIP6_BRI_FLAGS_LEN, ENC_BIG_ENDIAN);
        }
    } else if ( br_type == ACKNOWLEDGE ) {

        col_append_str(pinfo->cinfo, COL_INFO, " Acknowledge");

        if (mip6_tree)
        {
            ti = proto_tree_add_text(mip6_tree, tvb, MIP6_DATA_OFF,
                PMIP6_BRI_LEN, "Binding Revocation Acknowledge");

            field_tree = proto_item_add_subtree(ti, ett_mip6);

            proto_tree_add_item(field_tree, hf_pmip6_bri_brtype, tvb,
                PMIP6_BRI_BRTYPE_OFF, PMIP6_BRI_BRTYPE_LEN, ENC_BIG_ENDIAN);

            proto_tree_add_item(field_tree, hf_pmip6_bri_status, tvb,
                PMIP6_BRI_STATUS_OFF, PMIP6_BRI_STATUS_LEN, ENC_BIG_ENDIAN);

            proto_tree_add_item(field_tree, hf_pmip6_bri_seqnr, tvb,
                PMIP6_BRI_SEQNR_OFF, PMIP6_BRI_SEQNR_LEN, ENC_BIG_ENDIAN);

            proto_tree_add_item(field_tree, hf_pmip6_bri_ap_flag, tvb,
                PMIP6_BRI_FLAGS_OFF, PMIP6_BRI_FLAGS_LEN, ENC_BIG_ENDIAN);

            proto_tree_add_item(field_tree, hf_pmip6_bri_av_flag, tvb,
                PMIP6_BRI_FLAGS_OFF, PMIP6_BRI_FLAGS_LEN, ENC_BIG_ENDIAN);

            proto_tree_add_item(field_tree, hf_pmip6_bri_ag_flag, tvb,
                PMIP6_BRI_FLAGS_OFF, PMIP6_BRI_FLAGS_LEN, ENC_BIG_ENDIAN);

            proto_tree_add_item(field_tree, hf_pmip6_bri_res, tvb,
                PMIP6_BRI_FLAGS_OFF, PMIP6_BRI_FLAGS_LEN, ENC_BIG_ENDIAN);
        }
    }

    return MIP6_DATA_OFF + PMIP6_BRI_LEN;
}

/* Functions to dissect the mobility options */
/*Dissect vendor option 3GPP
 * Ref  Mobile IPv6 vendor specific option format and usage within 3GPP
 * (3GPP TS 29.282 version 10.2.0 Release 10)
 */

/*

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                    |     Type      |   Length      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Vendor ID                             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   Sub-Type    |  Reserved   |M| 3GPP Specific IE Data Fragment
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

static int
dissect_mip6_opt_vsm_3gpp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *hdr_item = tree;
    int    len = tvb_reported_length(tvb);
    int offset = 0;
    guint8 sub_type, m_flag;
    tvbuff_t *next_tvb;
    const gchar *mei_str;
    const char *digit_str;
    gchar *mcc_mnc_str;
    const gchar *imsi_str;

    /* offset points to the sub type */
    sub_type = tvb_get_guint8(tvb,offset);
    proto_tree_add_item(tree, hf_mip6_vsm_subtype_3gpp, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(hdr_item, " %s", val_to_str_ext_const(sub_type, &mip6_vsm_subtype_3gpp_value_ext, "<unknown>"));
    offset++;
    m_flag = tvb_get_guint8(tvb,offset) & 0x01;
    proto_tree_add_item(tree, hf_mip6_opt_3gpp_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mip6_opt_3gpp_flag_m, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* set len to the length of the data section */
    len = len - 2;

    if(m_flag){
        proto_tree_add_text(tree, tvb, offset, len, "Data fragment, handling not implemented yet");
        return len;
    }

    /* see 3GPP TS 29.275 version 10.5.0 Release 10 */
    switch (sub_type) {
    /*  1, Protocol Configuration Options
     *     3GPP PCO data, in the format from 3GPP TS 24.008 [16] subclause 10.5.6.3, starting with octet 3
     *     de_sm_pco(tvb, tree, pinfo, 0, length, NULL, 0);
     *     Note needs pinfo->link_dir ?
     */
    case 1:
        /* pinfo->link_dir == P2P_DIR_UNKNOWN */
        de_sm_pco(tvb, tree, pinfo, offset, len, NULL, 0);
        break;
    /*  2, 3GPP Specific PMIPv6 Error Code */
    case 2:
        proto_tree_add_item(tree, hf_mip6_opt_3gpp_spec_pmipv6_err_code, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    /*  3, PMIPv6 PDN GW IP Address
     *     PDN GW IP address, as specified in subclause 12.1.1.4
     */
    case 3:
        if(len == 4){
            /* Ipv4 address */
            proto_tree_add_item(tree, hf_mip6_opt_3gpp_pdn_gw_ipv4_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
        }else if(len == 16){
            /* IPv6 address */
            proto_tree_add_item(tree, hf_mip6_opt_3gpp_pdn_gw_ipv6_addr, tvb, offset, 16, ENC_NA);
        }
        break;
    /*  4, PMIPv6 DHCPv4 Address Allocation Procedure Indication
     *     DHCPv4 Address Allocation Procedure Indication, as specified in subclause 12.1.1.5
     */
    case 4:
        proto_tree_add_item(tree, hf_mip6_opt_3gpp_dhcpv4_addr_all_proc_ind, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    /*  5, PMIPv6 Fully Qualified PDN Connection Set Identifier
     * FQ-CSID as specified in subclause 12.1.1.2
     */
    case 5:
        next_tvb = tvb_new_subset_length(tvb, offset, len);
        dissect_gtpv2_fq_csid(next_tvb, pinfo, tree, hdr_item, len, 0, 0);
        break;
    /*  6, PMIPv6 PDN type indication */
    case 6:
        proto_tree_add_item(tree, hf_mip6_opt_3gpp_pdn_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(tree, hf_mip6_opt_3gpp_pdn_ind_cause, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    /*  7, Charging ID
     *     Charging ID as specified in subclause 12.1.1.6
     */
    case 7:
        proto_tree_add_item(tree, hf_mip6_opt_3gpp_chg_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(hdr_item, " %u", tvb_get_ntohl(tvb, offset));
        break;
    /*  8, Selection Mode */
    case 8:
        next_tvb = tvb_new_subset_length(tvb, offset, len);
        dissect_gtpv2_selec_mode(next_tvb, pinfo, tree, hdr_item, len, 0, 0);
        break;
    /*  9, I-WLAN Mobility Access Point Name (APN) */
    /* 10, Charging Characteristics */
    case 10:
        proto_tree_add_item(tree, hf_mip6_opt_3gpp_charging_characteristic, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    /* 11, Mobile Equipment Identity (MEI) */
    case 11:
        mei_str = tvb_bcd_dig_to_wmem_packet_str( tvb, offset, len, NULL, FALSE);
        proto_tree_add_string(tree, hf_mip6_opt_3gpp_mei, tvb, offset, len, mei_str);
        proto_item_append_text(hdr_item, " %s", mei_str);
        break;
    /* 12, MSISDN */
    case 12:
        dissect_e164_cc(tvb, tree, offset, TRUE);
        digit_str = tvb_bcd_dig_to_wmem_packet_str( tvb, offset, len, NULL, FALSE);
        proto_tree_add_string(tree, hf_mip6_opt_3gpp_msisdn, tvb, offset, len, digit_str);
        proto_item_append_text(hdr_item, " %s", digit_str);
        break;
    /* 13, Serving Network */
    case 13:
        mcc_mnc_str = dissect_e212_mcc_mnc_wmem_packet_str(tvb, pinfo, tree, offset, TRUE);
        proto_item_append_text(hdr_item," %s", mcc_mnc_str);
        break;
    /* 14, APN Restriction */
    case 14:
         proto_tree_add_item(tree, hf_mip6_opt_3gpp_apn_rest, tvb, offset, 1, ENC_BIG_ENDIAN);
         break;
    /* 15, Maximum APN Restriction */
    case 15:
         proto_tree_add_item(tree, hf_mip6_opt_3gpp_max_apn_rest, tvb, offset, 1, ENC_BIG_ENDIAN);
         break;
    /* 16, Unauthenticated IMSI */
    case 16:
        imsi_str = tvb_bcd_dig_to_wmem_packet_str( tvb, offset, len, NULL, FALSE);
        proto_tree_add_string(tree, hf_mip6_opt_3gpp_imsi, tvb, offset, len, imsi_str);
        proto_item_append_text(hdr_item," %s", imsi_str);
        break;
    /* 17, PDN Connection ID */
    case 17:
         proto_tree_add_item(tree, hf_mip6_opt_3gpp_pdn_conn_id, tvb, offset, 1, ENC_BIG_ENDIAN);
         break;
    /* 18, PGW Back-Off Time */
    case 18:
        next_tvb = tvb_new_subset_length(tvb, offset, len);
        dissect_gtpv2_epc_timer(next_tvb, pinfo, tree, hdr_item, len, 0, 0);
        break;
    /* 19, Signalling Priority Indication */
    case 19:
         proto_tree_add_item(tree, hf_hf_mip6_opt_3gpp_lapi, tvb, offset, 1, ENC_BIG_ENDIAN);
         break;
    /* 20, Additional Protocol Configuration Options
     *     12.1.1.19 Additional Protocol Configuration Options
     *     The Additional Protocol Configuration Options IE contains additional 3GPP protocol configuration options
     *     information. The IE is in the same format as the PCO IE specified in 3GPP TS 24.008 [16] subclause 10.5.6.3, starting
     *     with octet 3.
     */
    default:
        proto_tree_add_text(tree, tvb, offset, len, "Data(Not dissected yet)");
        break;
    }

    return len;
}
/* 1 PadN [RFC3775] */
static void
dissect_mip6_opt_padn(const mip6_opt *optp, tvbuff_t *tvb, int offset,
              guint optlen _U_, packet_info *pinfo _U_,
              proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    guint8 len;

    /* offset points to tag(opt) */
    offset++;
    len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(opt_tree, hf_mip6_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if (len > 0) {
        proto_tree_add_text(opt_tree, tvb, offset, len,
                "%s: %u bytes", optp->name, len);
    }
}

/* 2 Binding Refresh Advice */
static void
dissect_mip6_opt_bra(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
             guint optlen, packet_info *pinfo _U_,
             proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    int ri;

    ri = tvb_get_ntohs(tvb, offset + MIP6_BRA_RI_OFF);
    proto_tree_add_uint_format_value(opt_tree, hf_mip6_bra_interval, tvb,
            offset, optlen,
            ri, "%d (%ld seconds)",
            ri, (long)ri * 4);
}

/*3  Alternate Care-of Address */
static void
dissect_mip6_opt_acoa(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
              guint optlen _U_, packet_info *pinfo _U_,
              proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    proto_tree_add_item(opt_tree, hf_mip6_acoa_acoa, tvb,
        offset + MIP6_ACOA_ACOA_OFF, MIP6_ACOA_ACOA_LEN, ENC_NA);
}

/* 4 Nonce Indices */
static void
dissect_mip6_opt_ni(const mip6_opt *optp, tvbuff_t *tvb, int offset,
            guint optlen, packet_info *pinfo _U_,
            proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    proto_tree *field_tree;
    proto_item *tf;

    tf = proto_tree_add_text(opt_tree, tvb, offset, optlen, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

    proto_tree_add_item(field_tree, hf_mip6_ni_hni, tvb,
            offset + MIP6_NI_HNI_OFF, MIP6_NI_HNI_LEN, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree, hf_mip6_ni_cni, tvb,
            offset + MIP6_NI_CNI_OFF, MIP6_NI_CNI_LEN, ENC_BIG_ENDIAN);
}

/* 5 Authorization Data */
static void
dissect_mip6_opt_bad(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
             guint optlen, packet_info *pinfo _U_,
             proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    proto_tree *field_tree;
    proto_item *tf;

    tf = proto_tree_add_text(opt_tree, tvb, offset, optlen, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

    proto_tree_add_item(field_tree, hf_mip6_bad_auth, tvb,
            offset + MIP6_BAD_AUTH_OFF,
            optlen - MIP6_BAD_AUTH_OFF, ENC_NA);
}

/* 6 Mobile Network Prefix Option */
static void
dissect_mip6_nemo_opt_mnp(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
              guint optlen, packet_info *pinfo _U_,
              proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    proto_tree *field_tree;
    proto_item *tf;

    tf = proto_tree_add_text(opt_tree, tvb, offset, optlen, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    proto_tree_add_item(opt_tree, hf_mip6_nemo_mnp_pfl, tvb,
            offset + MIP6_NEMO_MNP_PL_OFF, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(field_tree, hf_mip6_nemo_mnp_mnp, tvb,
            offset + MIP6_NEMO_MNP_MNP_OFF, MIP6_NEMO_MNP_MNP_LEN, ENC_NA);
}

/* 7 Mobility Header Link-Layer Address option [RFC5568] */
static void
dissect_fmip6_opt_lla(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
              guint optlen, packet_info *pinfo _U_,
              proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    proto_tree *field_tree;
    proto_item *tf;
    int         len, p;

    tf = proto_tree_add_text(opt_tree, tvb, offset, optlen, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

    proto_tree_add_item(field_tree, hf_mip6_opt_len, tvb, offset+1, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(field_tree, hf_fmip6_lla_optcode, tvb,
            offset + FMIP6_LLA_OPTCODE_OFF, FMIP6_LLA_OPTCODE_LEN, ENC_BIG_ENDIAN);

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
            p   += 1;
            len -= 1;
            proto_tree_add_text(field_tree, tvb,
                    p, len, "Link-layer address: %s",
                    tvb_bytes_to_ep_str_punct(tvb, p, len, ':'));
        }
    }
}

/* 8 MN-ID-OPTION-TYPE */
static void
dissect_mip6_opt_mnid(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
              guint optlen, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item)
{
    int    len;
    gchar *str;

    /* offset points to tag(opt) */
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(opt_tree, hf_mip6_mnid_subtype, tvb,
            offset, 1, ENC_BIG_ENDIAN);
    offset++;

    len = optlen - MIP6_MNID_MNID_OFF;

    if (len > 0) {
        str = tvb_format_text(tvb, offset, len);
        proto_tree_add_text(opt_tree, tvb, offset, len, "Identifier: %s", str);
        proto_item_append_text(hdr_item, ": %s", str);
    }
}

/*  9 AUTH-OPTION-TYPE
    http://tools.ietf.org/html/rfc4285

    0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |  Option Type  | Option Length |  Subtype      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                  Mobility SPI                                 |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                  Authentication Data ....
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       Figure 2: Mobility Message Authentication Option
 */
/*  10 MESG-ID-OPTION-TYPE [RFC4285]
 *       5.1.  MN-HA Mobility Message Authentication Option
 *       The format of the MN-HA mobility message authentication option is as
 *       defined in Figure 2.
 */
static void
dissect_mip6_opt_auth(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
              guint optlen _U_, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    /* offset points to tag(opt) */
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_auth_sub_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_auth_mobility_spi, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(opt_tree, hf_mip6_opt_auth_auth_data, tvb, offset, -1, ENC_NA);

}

/* 11 CGA Parameters Request [RFC4866]  */
/* Carries no data */

/* 12 CGA Parameters [RFC4866]  */
static void
dissect_mip6_opt_cgar(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
              guint optlen _U_, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    /* offset points to tag(opt) */
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(opt_tree, hf_mip6_opt_cgar_cga_par, tvb, offset, -1, ENC_NA);

}

/* 13 Signature [RFC4866]  */
static void
dissect_mip6_opt_sign(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
              guint optlen _U_, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    /* offset points to tag(opt) */
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(opt_tree, hf_mip6_opt_sign_sign, tvb, offset, -1, ENC_NA);

}

/* 14 Permanent Home Keygen Token [RFC4866]  */
static void
dissect_mip6_opt_phkt(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
              guint optlen _U_, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    /* offset points to tag(opt) */
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(opt_tree, hf_mip6_opt_phkt_phkt, tvb, offset, -1, ENC_NA);

}
/* 15 Care-of Test Init [RFC4866]
 * No data in this option.
 */

/* 16 Care-of Test [RFC4866]  */
static void
dissect_mip6_opt_mocot(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
              guint optlen _U_, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    /* offset points to tag(opt) */
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(opt_tree, hf_mip6_opt_mocot_co_keygen_tok, tvb, offset, -1, ENC_NA);

}

/* 17 DNS-UPDATE-TYPE [RFC5026]

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                    |  Option Type  | Option Length |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   Status      |R|  Reserved   |     MN identity (FQDN) ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Option Type

      DNS-UPDATE-TYPE (17)

*/
static void
dissect_mip6_opt_dnsu(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
              guint optlen _U_, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    /* offset points to tag(opt) */
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(opt_tree, hf_mip6_opt_dnsu_status, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(opt_tree, hf_mip6_opt_dnsu_flag_r, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(opt_tree, hf_mip6_opt_dnsu_mn_id, tvb, offset, -1, ENC_NA);
}

/* 18 Experimental Mobility Option [RFC5096] */
static void
dissect_mip6_opt_em(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
              guint optlen _U_, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    /* offset points to tag(opt) */
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(opt_tree, hf_mip6_opt_em_data, tvb, offset, -1, ENC_NA);

}

/* 19 Vendor Specific Mobility Option [RFC5094]  */
/*

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                    |     Type      |   Length      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Vendor ID                             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   Sub-Type    |             Data.......
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
static void
dissect_mip6_opt_vsm(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
             guint optlen, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    tvbuff_t *next_tvb;
    int     len;
    guint32 vendorid;

    /* offset points to tag(opt) */
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(opt_tree, hf_mip6_vsm_vid, tvb,
            offset, MIP6_VSM_VID_LEN, ENC_BIG_ENDIAN);
    vendorid = tvb_get_ntohl(tvb, offset);
    proto_item_append_text(hdr_item, ": %s", val_to_str_ext_const(vendorid, &sminmpec_values_ext, "<unknown>"));
    offset += 4;

    next_tvb = tvb_new_subset_length(tvb, offset, optlen-MIP6_VSM_SUBTYPE_OFF);
    if (!dissector_try_uint(mip6_vsm_dissector_table, vendorid, next_tvb, pinfo, opt_tree)){
        proto_tree_add_item(opt_tree, hf_mip6_vsm_subtype, tvb,
                offset, MIP6_VSM_SUBTYPE_LEN, ENC_BIG_ENDIAN);
        offset++;

        len = optlen - MIP6_VSM_DATA_OFF;
        if (len > 0){
            proto_tree_add_text(opt_tree, tvb, offset, len, "Data");
        }
    }
}

/* 20 Service Selection Mobility Option [RFC5149]  */
#define MAX_APN_LENGTH 100

static void
dissect_mip6_opt_ssm(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
             guint optlen, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    int    len;
    guint8 str[MAX_APN_LENGTH+1];
    int    curr_len;

    /* offset points to tag(opt) */
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    len = optlen - MIP6_SSM_SSM_OFF;

    /* 3GPP TS 29.275 version 10.5.0 Release 10, Table 5.1.1.1-2
     * Set to the EPS Access Point Name to which the UE
     * attaches the new PDN connection.
     * The encoding the APN field follows 3GPP TS 23.003
     * [12] subclause 9.1 but excluding the trailing zero byte.
     * The content of the APN field shall be the full APN with
     * both the APN Network Identifier and default APN
     * Operator Identifier being present as specified in 3GPP
     * TS 23.003 [12] subclauses 9.1.1 and 9.1.2
     * NOTE 4.
     * NOTE 4: The APN field is not encoded as a dotted string as commonly used in documentation
     */

    if (len > 0) {
        /* init buffer and copy it */
        memset(str, 0, MAX_APN_LENGTH);
        tvb_memcpy(tvb, str, offset, len<MAX_APN_LENGTH?len:MAX_APN_LENGTH);

        curr_len = 0;
        while ((curr_len < len) && (curr_len < MAX_APN_LENGTH))
        {
            guint step    = str[curr_len];
            str[curr_len] = '.';
            curr_len     += step+1;
        }
        /* High light bytes including the first lenght byte, excluded from str(str+1) */
        proto_tree_add_text(opt_tree, tvb, offset, len, "Identifier: %s", str+1);
        proto_item_append_text(hdr_item, ": %s", str+1);
    }
}

/* 21 Binding Authorization Data for FMIPv6 (BADF) [RFC5568]  */

static void
dissect_mip6_opt_badff(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
             guint optlen _U_, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    /* offset points to tag(opt) */
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(opt_tree, hf_mip6_opt_badff_spi, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(opt_tree, hf_mip6_opt_badff_auth, tvb, offset, -1, ENC_NA);

}

/* 22 Home Network Prefix Option [RFC5213]   */
/* see dissect_mip6_nemo_opt_mnp */

/* 23 Handoff Indicator Option [RFC5213]   */
/*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Type     |   Length      |  Reserved (R) |       HI      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
static void
dissect_pmip6_opt_hi(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
             guint optlen _U_, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    guint8 hi;

    /* offset points to tag(opt) */
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(opt_tree, hf_pmip6_hi_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    hi = tvb_get_guint8(tvb,offset);
    proto_tree_add_item(opt_tree, hf_pmip6_hi_hi, tvb,
            offset, PMIP6_HI_HI_LEN, ENC_BIG_ENDIAN);

    proto_item_append_text(hdr_item, ": %s", val_to_str_const(hi, pmip6_hi_opttype_value, "<unknown>"));

}

/* 24 Access Technology Type Option [RFC5213]  */
/*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Type     |   Length      |  Reserved (R) |      ATT      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
static void
dissect_pmip6_opt_att(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
              guint optlen _U_, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    guint8 att;

    /* offset points to tag(opt) */
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(opt_tree, hf_pmip6_att_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    att = tvb_get_guint8(tvb,offset);
    proto_tree_add_item(opt_tree, hf_pmip6_att_att, tvb,
            offset, PMIP6_ATT_ATT_LEN, ENC_BIG_ENDIAN);
    proto_item_append_text(hdr_item, ": %s", val_to_str_ext_const(att, &pmip6_att_att_value_ext, "<unknown>"));
}

/* 25 Mobile Node Link-layer Identifier Option [RFC5213]  */
/*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   Type        |    Length     |          Reserved             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                        Link-layer Identifier                  +
    .                              ...                              .
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
static void
dissect_pmip6_opt_mnlli(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
             guint optlen _U_, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    /* offset points to tag(opt) */
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(opt_tree, hf_mip6_opt_mnlli_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(opt_tree, hf_mip6_opt_mnlli_lli, tvb, offset, -1, ENC_NA);

}

/* 26 Link-local Address Option [RFC5213   */
/*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                    |   Type        |    Length     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                                                               +
    |                                                               |
    +                  Link-local Address                           +
    |                                                               |
    +                                                               +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
static void dissect_pmip6_opt_lla(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
                        guint optlen, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    proto_item *ti;
    proto_tree *field_tree;

    if (opt_tree) {
    ti = proto_tree_add_text(opt_tree, tvb, offset, optlen, "%s", optp->name);
        field_tree = proto_item_add_subtree(ti, *optp->subtree_index);

        proto_tree_add_item(field_tree, hf_pmip6_opt_lila_lla, tvb, offset + 2, 16, ENC_NA);
   }
}

/* 27 Timestamp */
/*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                    |      Type     |   Length      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                          Timestamp                            +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

     Timestamp

         A 64-bit unsigned integer field containing a timestamp.  The
         value indicates the number of seconds since January 1, 1970,
         00:00 UTC, by using a fixed point format.  In this format, the
         integer number of seconds is contained in the first 48 bits of
         the field, and the remaining 16 bits indicate the number of
         1/65536 fractions of a second.

*/
static void
dissect_pmip6_opt_ts(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
             guint optlen _U_, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    const gchar *str;

    /* offset points to tag(opt) */
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    str = tvb_mip6_fmt_ts(tvb,offset);
    proto_tree_add_string(opt_tree, hf_pmip6_timestamp, tvb, offset, 8, str);
    proto_item_append_text(hdr_item, ": %s", str);
}

 /* 28 Restart Counter [RFC5847] */
static void
dissect_pmip6_opt_rc(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
             guint optlen _U_, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    proto_tree_add_item(opt_tree, hf_pmip6_rc, tvb,
            offset + PMIP6_RC_RC_OFF, PMIP6_RC_RC_LEN, ENC_BIG_ENDIAN);

}

/* 29 IPv4 Home Address [RFC5555]  */
static void
dissect_pmip6_opt_ipv4ha(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
             guint optlen, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    proto_tree *field_tree;
    proto_item *tf;
    int         len, p;

    tf = proto_tree_add_text(opt_tree, tvb, offset, optlen, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

    p = offset + MIP6_IPV4HA_PREFIXL_OFF;
    len = MIP6_IPV4HA_PREFIXL_LEN;

    proto_tree_add_item(field_tree, hf_mip6_ipv4ha_preflen, tvb, p, len, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree, hf_mip6_ipv4ha_p_flag, tvb, p, len+1, ENC_BIG_ENDIAN);

    proto_tree_add_item(field_tree, hf_mip6_ipv4ha_ha, tvb,
            offset + MIP6_IPV4HA_HA_OFF, MIP6_IPV4HA_HA_LEN, ENC_BIG_ENDIAN);

}

/* 30 IPv4 Address Acknowledgement [RFC5555] */
static void
dissect_pmip6_opt_ipv4aa(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
             guint optlen, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    proto_tree *field_tree;
    proto_item *tf;

    tf = proto_tree_add_text(opt_tree, tvb, offset, optlen, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

    proto_tree_add_item(field_tree, hf_mip6_ipv4aa_status, tvb,
            offset + MIP6_IPV4AA_STATUS_OFF, MIP6_IPV4AA_STATUS_LEN, ENC_BIG_ENDIAN);

    proto_tree_add_item(field_tree, hf_mip6_ipv4ha_preflen, tvb,
            offset + MIP6_IPV4AA_PREFIXL_OFF, MIP6_IPV4AA_PREFIXL_LEN, ENC_BIG_ENDIAN);

    proto_tree_add_item(field_tree, hf_mip6_ipv4ha_ha, tvb,
            offset + MIP6_IPV4AA_HA_OFF, MIP6_IPV4AA_HA_LEN, ENC_BIG_ENDIAN);

}

/* 31 NAT Detection [RFC5555]  */
/*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |    Length     |F|          Reserved           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Refresh time                             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
static void
dissect_pmip6_opt_natd(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
             guint optlen _U_, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    proto_item *item;
    guint32     refresh_time;

    /* offset points to tag(opt) */
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(opt_tree, hf_mip6_opt_natd_f_flag, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(opt_tree, hf_mip6_opt_natd_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    refresh_time = tvb_get_ntohl(tvb, offset);
    item = proto_tree_add_item(opt_tree, hf_mip6_opt_natd_refresh_t, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_item_append_text(item, " seconds");
    if (refresh_time == 0) {
        proto_item_append_text(item, " (Ignore)");
    }
    if (refresh_time == 0xffffffff) {
        proto_item_append_text(item, " (keepalives are not needed, no NAT detected)");
    }

}
/* 32 IPv4 Care-of Address [RFC5555]  */
/*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   Type        |   Length      |         Reserved              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                     IPv4 Care-of address                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

static void
dissect_pmip6_opt_ipv4coa(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
             guint optlen _U_, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    /* offset points to tag(opt) */
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(opt_tree, hf_mip6_opt_ipv4coa_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(opt_tree, hf_mip6_opt_ipv4coa_addr, tvb, offset, 4, ENC_BIG_ENDIAN);

}

/* 33 GRE Key Option [RFC5845]  */
/*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Type     |   Length      |           Reserved            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      GRE Key Identifier                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
static void
dissect_pmip6_opt_grek(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
               guint optlen _U_, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    /* offset points to tag(opt) */
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(opt_tree, hf_mip6_ipv4dra_reserved, tvb,
            offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(opt_tree, hf_pmip6_gre_key, tvb,
            offset, PMIP6_GREK_ID_LEN, ENC_BIG_ENDIAN);

    proto_item_append_text(hdr_item, ": %u", tvb_get_ntohl(tvb,offset));


}

/* 34 Mobility Header IPv6 Address/Prefix [RFC5568]
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |   Length      | Option-Code   | Prefix Length |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                                                               +
    |                                                               |
    +                    IPv6 Address/Prefix                        +
    |                                                               |
    +                                                               +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 */

static void
dissect_pmip6_opt_mhipv6ap(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
              guint optlen _U_, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    guint8 prefix_l;

    /* offset points to tag(opt) */
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(opt_tree, hf_mip6_opt_mhipv6ap_opt_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    prefix_l = tvb_get_guint8(tvb,offset);
    proto_tree_add_item(opt_tree, hf_mip6_opt_mhipv6ap_prefix_l, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_text(opt_tree, tvb, offset, prefix_l, "IPv6 Address/Prefix");

}
/* 35 Binding Identifier [RFC5648]  */
/*
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                    |   Type = 35   |     Length    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |       Binding ID (BID)        |     Status    |H|   Reserved  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-------------------------------+
    +                                                               +
    :                 IPv4 or IPv6 care-of address (CoA)            :
    +                                                               +
    +---------------------------------------------------------------+

*/
static void
dissect_pmip6_opt_bi(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
              guint optlen, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    /* offset points to tag(opt) */
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(opt_tree, hf_mip6_opt_bi_bid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(opt_tree, hf_mip6_opt_bi_status, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(opt_tree, hf_mip6_bi_h_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if (optlen == 8) {
        /* IPv4 addr */
        proto_tree_add_item(opt_tree, hf_mip6_bi_coa_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
    }else if (optlen == 20) {
        /* Ipv6 Addr */
        proto_tree_add_item(opt_tree, hf_mip6_bi_coa_ipv6, tvb, offset, 16, ENC_NA);
    }
}


/* 36 IPv4 Home Address Request [RFC5844] */
/*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |   Length      |Prefix-len |      Reserved     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                     IPv4 home address                         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
static void
dissect_pmip6_opt_ipv4hareq(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
                guint optlen _U_, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    proto_item *item;
    guint32     dword;

    /* offset points to tag(opt) */
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(opt_tree, hf_mip6_ipv4ha_preflen, tvb,
            offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Reserved */
    offset++;

    dword = tvb_get_ntohl(tvb,offset);
    item = proto_tree_add_item(opt_tree, hf_mip6_ipv4ha_ha, tvb,
            offset, MIP6_IPV4HAREQ_HA_LEN, ENC_BIG_ENDIAN);
    if (dword == 0) {
        proto_item_append_text(item, " - Request that the local mobility anchor perform the address allocation");
    }

    proto_item_append_text(hdr_item, ": %s", tvb_ip_to_str(tvb,offset));
}

/* 37 IPv4 Home Address Reply [RFC5844] */
/*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |    Length     |   Status      |Pref-len   |Res|
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      IPv4 home address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
static void
dissect_pmip6_opt_ipv4harep(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
                guint optlen _U_, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    guint8 status;

    /* offset points to tag(opt) */
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    status = tvb_get_guint8(tvb,offset);
    proto_tree_add_item(opt_tree, hf_mip6_ipv4aa_status, tvb,
            offset, MIP6_IPV4HAREP_STATUS_LEN, ENC_BIG_ENDIAN);
    proto_item_append_text(hdr_item, ": %s ", val_to_str_const(status, pmip6_ipv4aa_status_values, "<unknown>"));
    offset++;

    proto_tree_add_item(opt_tree, hf_mip6_ipv4ha_preflen, tvb,
            offset, MIP6_IPV4HAREP_PREFIXL_LEN, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(opt_tree, hf_mip6_ipv4ha_ha, tvb,
            offset, MIP6_IPV4HAREP_HA_LEN, ENC_BIG_ENDIAN);

    proto_item_append_text(hdr_item, ": %s", tvb_ip_to_str(tvb,offset));

}

/* 38 IPv4 Default-Router Address [RFC5844] */
/*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Type     |   Length      |         Reserved (R)          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                  IPv4 Default-Router Address                  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
static void
dissect_pmip6_opt_ipv4dra(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
              guint optlen _U_, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    /* offset points to tag(opt) */
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(opt_tree, hf_mip6_ipv4dra_reserved, tvb,
            offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(opt_tree, hf_mip6_ipv4dra_dra, tvb,
            offset, MIP6_IPV4DRA_DRA_LEN, ENC_BIG_ENDIAN);

    proto_item_append_text(hdr_item, ": %s", tvb_ip_to_str(tvb,offset));

}

/* 39 IPv4 DHCP Support Mode [RFC5844] */
/*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Type     |   Length      |    Reserved (R)             |S|
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

static void
dissect_pmip6_opt_ipv4dsm(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
              guint optlen _U_, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    /* offset points to tag(opt) */
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(opt_tree, hf_mip6_ipv4dsm_reserved, tvb,
            offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(opt_tree, hf_mip6_ipv4dsm_s_flag, tvb, offset, 2, ENC_BIG_ENDIAN);
}

/* 40 Context Request Option [RFC5949] */
/*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +---------------+---------------+---------------+---------------+
    |  Option-Type  | Option-Length |           Reserved            |
    +---------------+---------------+-------------------------------+
    |  Req-type-1   | Req-length-1  |  Req-type-2   | Req-length-2  |
    +---------------------------------------------------------------+
    |  Req-type-3   | Req-length-3  |          Req-option-3         |
    +---------------------------------------------------------------+
    |                              ...                              |

*/

static void
dissect_pmip6_opt_cr(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
              guint optlen, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    int     len;
    guint8  req_type, req_length;
    guint32 vendorid;

    /* offset points to tag(opt) */
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(opt_tree, hf_mip6_cr_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    len = optlen - 3;

    while (len > 0) {
        req_type = tvb_get_guint8(tvb,offset);
        proto_tree_add_item(opt_tree, hf_mip6_cr_req_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        len--;
        req_length = tvb_get_guint8(tvb,offset);
        proto_tree_add_item(opt_tree, hf_mip6_cr_req_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        len--;
        if (req_length != 0) {
            if (req_type == MIP6_VSM) {
                /* vendor specific option */
                vendorid = tvb_get_ntohl(tvb, offset);
                proto_tree_add_item(opt_tree, hf_mip6_vsm_vid, tvb, offset, 4, ENC_BIG_ENDIAN);
                if (vendorid == VENDOR_THE3GPP) {
                    proto_tree_add_item(opt_tree, hf_mip6_vsm_subtype_3gpp, tvb, offset+4, 1, ENC_BIG_ENDIAN);
                } else {
                    proto_tree_add_item(opt_tree, hf_mip6_vsm_subtype, tvb, offset+4, 1, ENC_BIG_ENDIAN);
                }
            }else{
                proto_tree_add_text(opt_tree, tvb, offset, req_length, "Req-Data");
            }
            offset += req_length;
            len    -= req_length;
        }
    }
}

/* 41 Local Mobility Anchor Address Option [RFC5949] */
/*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Option-Type  | Option-Length |  Option-Code  |   Reserved    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |              Local Mobility Anchor Address ...                |

*/
static void
dissect_pmip6_opt_lmaa(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
              guint optlen _U_, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    guint8 opt_code;

    /* offset points to tag(opt) */
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    opt_code = tvb_get_guint8(tvb,offset);
    proto_tree_add_item(opt_tree, hf_mip6_lmaa_opt_code, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(opt_tree, hf_mip6_lmaa_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 1;

    if (opt_code == 1) {
        /* IPv4 addr */
        proto_tree_add_item(opt_tree, hf_mip6_lmaa_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(hdr_item, ": %s", tvb_ip_to_str(tvb,offset));
    }else if (opt_code == 2) {
        /* Ipv6 Addr */
        proto_tree_add_item(opt_tree, hf_mip6_lmaa_ipv6, tvb, offset, 16, ENC_NA);
        proto_item_append_text(hdr_item, ": %s", tvb_ip6_to_str(tvb,offset));
    }

}

static void
dissect_pmip6_opt_recap(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
              guint optlen _U_, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{

    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_recap_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    /*offset +=2;*/

}

static void
dissect_pmip6_opt_redir(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
              guint optlen _U_, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    guint16 flag;

    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_redir_k, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(opt_tree, hf_mip6_opt_redir_n, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(opt_tree, hf_mip6_opt_redir_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    flag = tvb_get_ntohs(tvb ,offset);
    offset +=2;

    if (flag & MIP6_REDIR_FLAG_K) {
        proto_tree_add_item(opt_tree, hf_mip6_opt_redir_addr_r2LMA_ipv6, tvb, offset, 16, ENC_NA);
        offset +=16;
    }


    if (flag & MIP6_REDIR_FLAG_N) {
        proto_tree_add_item(opt_tree, hf_mip6_opt_redir_addr_r2LMA_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        /*offset +=4;*/
    }

}

static void
dissect_pmip6_opt_load_inf(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
              guint optlen _U_, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{

    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_load_inf_priority, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset +=2;
    proto_tree_add_item(opt_tree, hf_mip6_opt_load_inf_sessions_in_use, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset +=4;
    proto_tree_add_item(opt_tree, hf_mip6_opt_load_inf_maximum_sessions, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset +=4;
    proto_tree_add_item(opt_tree, hf_mip6_opt_load_inf_used_capacity, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset +=4;
    proto_tree_add_item(opt_tree, hf_mip6_opt_load_inf_maximum_capacity, tvb, offset, 4, ENC_BIG_ENDIAN);
    /*offset +=4;*/
}


static void
dissect_pmip6_opt_alt_ip4(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
              guint optlen _U_, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{

    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_alt_ip4, tvb, offset, 4, ENC_BIG_ENDIAN);
    /*offset +=4;*/

}
/* RFC 6602
    The type value for this option is 50.

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Type     |   Length      |  Sub-type   |    Reserved     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                  Mobile Node Group Identifier                 |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 */

static void
dissect_pmip6_opt_mng(const mip6_opt *optp _U_, tvbuff_t *tvb, int offset,
              guint optlen _U_, packet_info *pinfo _U_, proto_tree *opt_tree, proto_item *hdr_item _U_ )
{
    proto_item *item;
    guint32     mng_id;

    /* offset points to tag(opt) */
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_mng_sub_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_mng_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    mng_id = tvb_get_ntohl(tvb, offset);
    item = proto_tree_add_item(opt_tree, hf_mip6_opt_mng_mng_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    if (mng_id == 1) {
        proto_item_append_text(item, " - ALL-SESSIONS");
    }

}

static const mip6_opt mip6_opts[] = {
{
    MIP6_PAD1,                  /* 0 Pad1 [RFC3775] */
    "Pad1",
    &ett_mip6_opt_pad1,
    OPT_LEN_NO_LENGTH,
    0,
    NULL,
},
{
    MIP6_PADN,                  /* 1 PadN [RFC3775] */
    "PadN",
    &ett_mip6_opt_padn,
    OPT_LEN_VARIABLE_LENGTH,
    0,
    dissect_mip6_opt_padn
},
{
    MIP6_BRA,                   /* 2 Binding Refresh Advice */
    "Binding Refresh Advice",
    &ett_mip6_opt_bra,
    OPT_LEN_FIXED_LENGTH,
    MIP6_BRA_LEN,
    dissect_mip6_opt_bra
},
{
    MIP6_ACOA,                  /*3  Alternate Care-of Address */
    "Alternate Care-of Address",
    &ett_mip6_opt_acoa,
    OPT_LEN_FIXED_LENGTH,
    MIP6_ACOA_LEN,
    dissect_mip6_opt_acoa
},
{
    MIP6_NI,                    /* 4 Nonce Indices */
    "Nonce Indices",
    &ett_mip6_opt_ni,
    OPT_LEN_FIXED_LENGTH,
    MIP6_NI_LEN,
    dissect_mip6_opt_ni
},
{
    MIP6_AUTD,                  /* 5 Authorization Data */
    "Authorization Data",
    &ett_mip6_opt_bad,
    OPT_LEN_VARIABLE_LENGTH,
    0,
    dissect_mip6_opt_bad
},
{
    MIP6_MNP,                   /* 6 Mobile Network Prefix Option */
    "Mobile Network Prefix",
    &ett_mip6_nemo_opt_mnp,
    OPT_LEN_FIXED_LENGTH,
    MIP6_NEMO_MNP_LEN,
    dissect_mip6_nemo_opt_mnp
},
{
    MIP6_MHLLA,                 /* 7 Mobility Header Link-Layer Address option [RFC5568] */
    "Mobility Header Link-Layer Address option",
    &ett_fmip6_opt_lla,
    OPT_LEN_VARIABLE_LENGTH,
    FMIP6_LLA_MINLEN,
    dissect_fmip6_opt_lla
},
{
    MIP6_MNID,                  /* 8 MN-ID-OPTION-TYPE */
    "Mobile Node Identifier",
    &ett_mip6_opt_mnid,
    OPT_LEN_VARIABLE_LENGTH,
    MIP6_MNID_MINLEN,
    dissect_mip6_opt_mnid
},
{
    MIP6_AUTH,                  /*  9 AUTH-OPTION-TYPE */
    "AUTH-OPTION-TYPE",
    &ett_mip6_opt_auth,
    OPT_LEN_VARIABLE_LENGTH,
    MIP6_AUTH_MINLEN,
    dissect_mip6_opt_auth
},
{
    MIP6_MESGID,                  /* 10 MESG-ID-OPTION-TYPE [RFC4285]  */
    "MESG-ID-OPTION-TYPE",
    &ett_mip6_opt_mesgid,
    OPT_LEN_VARIABLE_LENGTH,
    MIP6_AUTH_MINLEN,
    dissect_mip6_opt_auth
},
{
    MIP6_CGAPR,                  /* 11 CGA Parameters Request [RFC4866]  */
    " CGA Parameters Request ",
    &ett_mip6_opt_cgapr,
    OPT_LEN_FIXED_LENGTH,
    MIP6_CGAPR_MINLEN,
    NULL
},

{
    MIP6_CGAR,                  /* 12 CGA Parameters [RFC4866]  */
    "CGA Parameters",
    &ett_mip6_opt_cgar,
    OPT_LEN_VARIABLE_LENGTH,
    MIP6_CGAR_MINLEN,
    dissect_mip6_opt_cgar
},

{
    MIP6_SIGN,                  /* 13 Signature [RFC4866]  */
    "Signature",
    &ett_mip6_opt_sign,
    OPT_LEN_VARIABLE_LENGTH,
    MIP6_SIGN_MINLEN,
    dissect_mip6_opt_sign
},
{
    MIP6_PHKT,                  /* 14 Permanent Home Keygen Token [RFC4866]  */
    "Permanent Home Keygen Token",
    &ett_mip6_opt_phkt,
    OPT_LEN_VARIABLE_LENGTH,
    MIP6_PHKT_MINLEN,
    dissect_mip6_opt_phkt
},
{
    MIP6_MOCOTI,                  /* 15 Care-of Test Init [RFC4866]  */
    "Care-of Test Init",
    &ett_mip6_opt_mocoti,
    OPT_LEN_FIXED_LENGTH,
    MIP6_MOCOTI_MINLEN,
    NULL
},
{
    MIP6_MOCOT,                  /* 16 Care-of Test [RFC4866]  */
    "Care-of Test",
    &ett_mip6_opt_mocot,
    OPT_LEN_FIXED_LENGTH,
    MIP6_MOCOT_MINLEN,
    dissect_mip6_opt_mocot
},
{
    MIP6_DNSU,                  /* 17 DNS-UPDATE-TYPE [RFC5026]  */
    "DNS-UPDATE-TYPE",
    &ett_mip6_opt_dnsu,
    OPT_LEN_VARIABLE_LENGTH,
    MIP6_DNSU_MINLEN,
    dissect_mip6_opt_dnsu
},
{
    MIP6_EM,                 /* 18 Experimental Mobility Option [RFC5096]  */
    "Experimental",
    &ett_mip6_opt_em,
    OPT_LEN_VARIABLE_LENGTH,
    MIP6_EM_MINLEN,
    dissect_mip6_opt_em
},

{
    MIP6_VSM,                   /* 19 Vendor Specific Mobility Option [RFC5094]  */
    "Vendor Specific",
    &ett_mip6_opt_vsm,
    OPT_LEN_VARIABLE_LENGTH,
    MIP6_VSM_MINLEN,
    dissect_mip6_opt_vsm
},
{
    MIP6_SSM,                   /* 20 Service Selection Mobility Option [RFC5149]  */
    "Service Selection",
    &ett_mip6_opt_ssm,
    OPT_LEN_VARIABLE_LENGTH,
    MIP6_SSM_MINLEN,
    dissect_mip6_opt_ssm
},
{
    MIP6_BADFF,                   /* 21 Binding Authorization Data for FMIPv6 (BADF) [RFC5568]  */
    "Binding Authorization Data for FMIPv6 (BADF)",
    &ett_mip6_opt_badff,
    OPT_LEN_VARIABLE_LENGTH,
    MIP6_BADFF_MINLEN,
    dissect_mip6_opt_badff
},
{
    MIP6_HNP,                   /* 22 Home Network Prefix Option [RFC5213]   */
    "Home Network Prefix",
    &ett_pmip6_opt_hnp,
    OPT_LEN_FIXED_LENGTH,
    MIP6_NEMO_MNP_LEN,
    dissect_mip6_nemo_opt_mnp
},
{
    MIP6_MOHI,                  /* 23 Handoff Indicator Option [RFC5213]   */
    "Handoff Indicator",
    &ett_pmip6_opt_hi,
    OPT_LEN_FIXED_LENGTH,
    PMIP6_HI_LEN,
    dissect_pmip6_opt_hi
},
{
    MIP6_ATT,                   /* 24 Access Technology Type Option [RFC5213]  */
    "Access Technology Type Option",
    &ett_pmip6_opt_att,
    OPT_LEN_FIXED_LENGTH,
    PMIP6_ATT_LEN,
    dissect_pmip6_opt_att
},

{
    MIP6_MNLLI,                       /* 25 Mobile Node Link-layer Identifier Option [RFC5213]  */
    "Mobile Node Link-layer Identifier",
    &ett_pmip6_opt_mnlli,
    OPT_LEN_VARIABLE_LENGTH,
    PMIP6_MNLLI_MIN_LEN,
    dissect_pmip6_opt_mnlli
},

{
    MIP6_LLA,                        /* 26 Link-local Address Option [RFC5213   */
    "Link-local Address",
    &ett_pmip6_opt_lla,
    OPT_LEN_FIXED_LENGTH,
    PMIP6_LLA_LEN,
    dissect_pmip6_opt_lla
},

{
    MIP6_TS,                    /* 27 Timestamp */
    "Timestamp",
    &ett_pmip6_opt_ts,
    OPT_LEN_FIXED_LENGTH,
    PMIP6_TS_LEN,
    dissect_pmip6_opt_ts
},
{
    MIP6_RC,                    /* 28 Restart Counter [RFC5847] */
    "Restart Counter",
    &ett_pmip6_opt_rc,
    OPT_LEN_FIXED_LENGTH,
    PMIP6_RC_LEN,
    dissect_pmip6_opt_rc
},
{
    MIP6_IPV4HA,                /* 29 IPv4 Home Address [RFC5555]  */
    "IPv4 Home Address",
    &ett_mip6_opt_ipv4ha,
    OPT_LEN_FIXED_LENGTH,
    MIP6_IPV4HA_LEN,
    dissect_pmip6_opt_ipv4ha
},
{
    MIP6_IPV4AA,                /* 30 IPv4 Address Acknowledgement [RFC5555] */
    "IPv4 Address Acknowledgement",
    &ett_mip6_opt_ipv4aa,
    OPT_LEN_FIXED_LENGTH,
    MIP6_IPV4AA_LEN,
    dissect_pmip6_opt_ipv4aa
},
{
    MIP6_NATD,                /* 31 NAT Detection [RFC5555]  */
    "NAT Detection",
    &ett_mip6_opt_natd,
    OPT_LEN_FIXED_LENGTH,
    MIP6_NATD_LEN,
    dissect_pmip6_opt_natd
},

{
    MIP6_IPV4COA,                /* 32 IPv4 Care-of Address [RFC5555]  */
    "IPv4 Care-of Address",
    &ett_mip6_opt_ipv4coa,
    OPT_LEN_FIXED_LENGTH,
    MIP6_IPV4COA_LEN,
    dissect_pmip6_opt_ipv4coa
},

{
    MIP6_GREK,                  /* 33 GRE Key Option [RFC5845]  */
    "GRE Key",
    &ett_pmip6_opt_grek,
    OPT_LEN_FIXED_LENGTH,
    PMIP6_GREK_LEN,
    dissect_pmip6_opt_grek
},

{
    MIP6_MHIPV6AP,                 /* 34 Mobility Header IPv6 Address/Prefix [RFC5568] Note Errata to RFC */
    "Mobility Header IPv6 Address/Prefix",
    &ett_pmip6_opt_mhipv6ap,
    OPT_LEN_VARIABLE_LENGTH,
    MIP6_MHIPV6AP_MIN_LEN,
    dissect_pmip6_opt_mhipv6ap
},
{
    MIP6_BI,                 /* 35 Binding Identifier [RFC5648]  */
    "Binding Identifier",
    &ett_pmip6_opt_bi,
    OPT_LEN_VARIABLE_LENGTH,
    MIP6_BI_MIN_LEN,
    dissect_pmip6_opt_bi
},
{
    MIP6_IPV4HAREQ,             /* 36 IPv4 Home Address Request [RFC5844] */
    "IPv4 Home Address Request",
    &ett_mip6_opt_ipv4hareq,
    OPT_LEN_FIXED_LENGTH,
    MIP6_IPV4HAREQ_LEN,
    dissect_pmip6_opt_ipv4hareq
},
{
    MIP6_IPV4HAREP,            /* 37 IPv4 Home Address Reply [RFC5844] */
    "IPv4 Home Address Reply",
    &ett_mip6_opt_ipv4harep,
    OPT_LEN_FIXED_LENGTH,
    MIP6_IPV4HAREP_LEN,
    dissect_pmip6_opt_ipv4harep
},
{
    MIP6_IPV4DRA,               /* 38 IPv4 Default-Router Address [RFC5844] */
    "IPv4 Default-Router Address",
    &ett_mip6_opt_ipv4dra,
    OPT_LEN_FIXED_LENGTH,
    MIP6_IPV4DRA_LEN,
    dissect_pmip6_opt_ipv4dra
},
{
    MIP6_IPV4DSM,               /* 39 IPv4 DHCP Support Mode [RFC5844] */
    "IPv4 DHCP Support Mode",
    &ett_mip6_opt_ipv4dsm,
    OPT_LEN_FIXED_LENGTH,
    MIP6_IPV4DSM_LEN,
    dissect_pmip6_opt_ipv4dsm
},
{
    MIP6_CR,               /* 40 Context Request Option [RFC5949] */
    "Context Request",
    &ett_mip6_opt_cr,
    OPT_LEN_VARIABLE_LENGTH,
    MIP6_CR_MIN_LEN,
    dissect_pmip6_opt_cr
},
/* 41 Local Mobility Anchor Address Option [RFC5949] */
{
    MIP6_CR,               /* 40 Context Request Option [RFC5949] */
    "Context Request",
    &ett_mip6_opt_cr,
    OPT_LEN_VARIABLE_LENGTH,
    MIP6_CR_MIN_LEN,
    dissect_pmip6_opt_cr
},
{
    MIP6_LMAA,               /* 42 Mobile Node Link-local Address Interface Identifier Option [RFC5949] */
    "Mobile Node Link-local Address Interface Identifier",
    &ett_mip6_opt_lmaa,
    OPT_LEN_VARIABLE_LENGTH,
    MIP6_LMAA_MIN_LEN,
    dissect_pmip6_opt_lmaa
},
/* 43 Transient Binding [RFC-ietf-mipshop-transient-bce-pmipv6-07] */
/* 44 Flow Summary Mobility Option [RFC-ietf-mext-flow-binding-11] */
/* 45 Flow Identification Mobility Option [RFC-ietf-mext-flow-binding-11]] */

{
    MIP6_RECAP,               /* 46 Redirect-Capability Mobility Option [RFC6463] */
    "Redirect-Capability",
    &ett_mip6_opt_recap,
    OPT_LEN_FIXED_LENGTH,
    MIP6_RECAP_LEN,
    dissect_pmip6_opt_recap
},
{
    MIP6_REDIR,               /* 47 Redirect Mobility Option [RFC6463] */
    "Redirect",
    &ett_mip6_opt_redir,
    OPT_LEN_VARIABLE_LENGTH,
    MIP6_REDIR_MIN_LEN,
    dissect_pmip6_opt_redir
},
{
    MIP6_LOAD_INF,               /* 48 Load Information Mobility Option [RFC6463] */
    "Load Information",
    &ett_mip6_opt_load_inf,
    OPT_LEN_FIXED_LENGTH,
    MIP6_LOAD_INF_LEN,
    dissect_pmip6_opt_load_inf
},

{
    MIP6_ALT_IP4_CO,               /* 49 Alternate IPv4 Care-of Address [RFC6463] */
    "Alternate IPv4",
    &ett_mip6_opt_alt_ip4,
    OPT_LEN_FIXED_LENGTH,
    MIP6_ALT_IP4_LEN,
    dissect_pmip6_opt_alt_ip4
},


{
    MIP6_MNG,               /* 50 Mobile Node Group Identifier [RFC6602] */
    "Mobile Node Group Identifier",
    &ett_mip6_opt_mng,
    OPT_LEN_FIXED_LENGTH,
    MIP6_MNG_LEN,
    dissect_pmip6_opt_mng
},
/* 51 MAG IPv6 Address [RFC6705] */
/* 52 Access Network Identifier [RFC6757] */

};

#define N_MIP6_OPTS (sizeof mip6_opts / sizeof mip6_opts[0])


/* Like "dissect_ip_tcp_options()", but assumes the length of an option
 * *doesn't* include the type and length bytes.  The option parsers,
 * however, are passed a length that *does* include them.
 */
static void
dissect_mipv6_options(tvbuff_t *tvb, int offset, guint length,
              const mip6_opt *opttab, int nopts, int eol,
              packet_info *pinfo, proto_tree *opt_tree)
{
    proto_item     *ti;
    proto_tree     *opt_data_tree = NULL;
    guchar          opt;
    const mip6_opt *optp;
    opt_len_type    len_type;
    unsigned int    optlen;
    const char     *name;
    char            name_str[7+1+1+2+2+1+1]; /* "Unknown (0x%02x)" */
    void            (*dissect)(const struct mip6_opt *, tvbuff_t *,
                               int, guint, packet_info *, proto_tree *, proto_item *);
    guint           len;

    while ((gint)length > 0) {
        opt = tvb_get_guint8(tvb, offset);
        for (optp = &opttab[0]; optp < &opttab[nopts]; optp++) {
            if (optp->optcode == opt)
                break;
        }
        if (optp == &opttab[nopts]) {
            /* We assume that the only OPT_LEN_NO_LENGTH options are Pad1 options,
             * so that we can treat unknown options as OPT_LEN_VARIABLE_LENGTH with a
             * minimum of 0, and at least be able to move on to the next option
             * by using the length in the option.
             */
            optp     = NULL;    /* indicate that we don't know this option */
            len_type = OPT_LEN_VARIABLE_LENGTH;
            optlen   = 0;
            g_snprintf(name_str, sizeof name_str, "Unknown (0x%02x)", opt);
            name     = name_str;
            dissect  = NULL;
        } else {
            len_type = optp->len_type;
            optlen   = optp->optlen;
            name     = optp->name;
            dissect  = optp->dissect;
        }
        --length;      /* account for type byte */
        if (len_type != OPT_LEN_NO_LENGTH) {
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
            } else if (len_type == OPT_LEN_FIXED_LENGTH && len != optlen) {
                /* Bogus - option length isn't what it's supposed to be for this
                   option. */
                proto_tree_add_text(opt_tree, tvb, offset, len + 2,
                        "%s (with option length = %u byte%s; should be %u)", name,
                        len, plurality(len, "", "s"), optlen);
                return;
            } else if (len_type == OPT_LEN_VARIABLE_LENGTH && len < optlen) {
                /* Bogus - option length is less than what it's supposed to be for
                   this option. */
                proto_tree_add_text(opt_tree, tvb, offset, len + 2,
                        "%s (with option length = %u byte%s; should be >= %u)", name,
                        len, plurality(len, "", "s"), optlen);
                return;
            } else {
                ti = proto_tree_add_text(opt_tree, tvb, offset, len + 2, "%s",
                                         val_to_str_ext_const(opt, &mip6_mobility_options_ext, "<unknown>"));
                if (optp && *optp->subtree_index) {
                    opt_data_tree = proto_item_add_subtree(ti, *optp->subtree_index);
                }
                proto_tree_add_item(opt_data_tree, hf_mip6_mobility_opt, tvb, offset, 1, ENC_BIG_ENDIAN);
                if (optp == NULL) {
                    proto_item_append_text(ti, "(%u byte%s)",len, plurality(len, "", "s"));
                    expert_add_info(pinfo, ti, &ei_mip6_ie_not_dissected);
                } else {
                    if (dissect != NULL) {
                        /* Option has a dissector. */
                        if (opt == MIP6_MHLLA)
                            (*dissect)(optp, tvb, offset,
                                   len + 2 + FMIP6_LLA_OPTCODE_LEN, pinfo, opt_data_tree, ti);
                        else
                            (*dissect)(optp, tvb, offset, len + 2, pinfo, opt_data_tree, ti);
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
    proto_tree *opts_tree;
    proto_item *ti;

#if 0  /* dissect_mipv6_options() calls expert...() */
    if (!mip6_tree)
        return len;
#endif

    ti = proto_tree_add_text(mip6_tree, tvb, offset, len, "Mobility Options");
    opts_tree = proto_item_add_subtree(ti, ett_mip6);

    dissect_mipv6_options(tvb, offset, len, mip6_opts, N_MIP6_OPTS, -1, pinfo, opts_tree);

    return len;
}

/* Function that dissects the whole MIPv6 packet */
static void
dissect_mip6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *mip6_tree   = NULL;
    guint8      type, pproto;
    guint       len, offset = 0, start_offset = offset;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MIPv6");
    col_clear(pinfo->cinfo, COL_INFO);

    len = (tvb_get_guint8(tvb, MIP6_HLEN_OFF) + 1) * 8;
    pproto = tvb_get_guint8(tvb, MIP6_PROTO_OFF);
    if (tree) {
        proto_item *ti;
        ti = proto_tree_add_item(tree, proto_mip6, tvb, 0, len, ENC_NA);
        mip6_tree = proto_item_add_subtree(ti, ett_mip6);

        /* Process header fields */
        proto_tree_add_item(mip6_tree, hf_mip6_proto, tvb,
                MIP6_PROTO_OFF, 1, ENC_BIG_ENDIAN);

        proto_tree_add_uint_format_value(mip6_tree, hf_mip6_hlen, tvb,
                MIP6_HLEN_OFF, 1,
                tvb_get_guint8(tvb, MIP6_HLEN_OFF),
                "%u (%u bytes)",
                tvb_get_guint8(tvb, MIP6_HLEN_OFF),
                len);

        proto_tree_add_item(mip6_tree, hf_mip6_mhtype, tvb,
                MIP6_TYPE_OFF, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(mip6_tree, hf_mip6_reserved, tvb,
                MIP6_RES_OFF, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(mip6_tree, hf_mip6_csum, tvb,
                MIP6_CSUM_OFF, 2, ENC_BIG_ENDIAN);
    }

    /* Process mobility header */
    type = tvb_get_guint8(tvb, MIP6_TYPE_OFF);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str_ext_const(type, &mip6_mh_types_ext, "<unknown>"));
    switch (type) {
    case MIP6_BRR:
        /* 0 Binding Refresh Request */
        offset = dissect_mip6_brr(tvb, mip6_tree, pinfo);
        break;
    case MIP6_HOTI:
        /* 1 Home Test Init */
        offset = dissect_mip6_hoti(tvb, mip6_tree, pinfo);
        break;
    case MIP6_MHCOTI:
        /* 2 Care-of Test Init */
        offset = dissect_mip6_coti(tvb, mip6_tree, pinfo);
        break;
    case MIP6_HOT:
        /* 3 Home Test */
        offset = dissect_mip6_hot(tvb, mip6_tree, pinfo);
        break;
    case MIP6_MHCOT:
        /* 4 Care-of Test */
        offset = dissect_mip6_cot(tvb, mip6_tree, pinfo);
        break;
    case MIP6_BU:
        /* 5 Binding Update */
        pinfo->link_dir = P2P_DIR_UL;
        offset = dissect_mip6_bu(tvb, mip6_tree, pinfo);
        if (proto_nemo == 1) {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "NEMO");
        }
        break;
    case MIP6_BA:
        /* 6 Binding Acknowledgement */
        pinfo->link_dir = P2P_DIR_DL;
        offset = dissect_mip6_ba(tvb, mip6_tree, pinfo);
        if (proto_nemo == 1) {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "NEMO");
        }
        break;
    case MIP6_BE:
        /* 7 Binding Error */
        offset = dissect_mip6_be(tvb, mip6_tree, pinfo);
        break;
    case MIP6_FBU:
        /* 8 Fast Binding Update */
        offset = dissect_fmip6_fbu(tvb, mip6_tree, pinfo);
        break;
    case MIP6_FBACK:
        /* 9 Fast Binding Acknowledgment */
        offset = dissect_fmip6_fback(tvb, mip6_tree, pinfo);
        break;
    case MIP6_FNA:
        /* 10 Fast Neighbor Advertisement */
        offset = dissect_fmip6_fna(tvb, mip6_tree, pinfo);
        break;
    case MIP6_EMH:
        /* 11 Experimental Mobility Header RFC5096 */
        /* There are no fields in the message beyond the required fields
         * in the Mobility Header.
         */
        offset = MIP6_DATA_OFF;
        break;
    case MIP6_HAS:
        /* 12 Home Agent Switch */
        dissect_mip6_unknown(tvb, mip6_tree, pinfo);
        offset = len;
        break;
    case MIP6_HB:
        /* 13 Heartbeat */
        offset = dissect_mip6_hb(tvb, mip6_tree, pinfo);
        break;
    case MIP6_HI:
        /* 14 Handover Initiate RFC5568 */
        offset = dissect_mip6_hi(tvb, mip6_tree, pinfo);
        break;
    case MIP6_HAck:
        /* 14 Handover Acknowledge*/
        offset = dissect_mip6_hack(tvb, mip6_tree, pinfo);
        break;
    case MIP6_BR:
        /* 16 Binding Revocation Indication / Acknowledge */
        offset = dissect_pmip6_bri(tvb, mip6_tree, pinfo);
        break;
    case MIP6_LRI:
        /* 17 Localized Routing Initiation */
        /* Fall trough */
    case MIP6_LRA:
        /* 18 Localized Routing Acknowledgment */
        /* Fall trough */
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

    if ((type == MIP6_FNA) && (pproto == IP_PROTO_IPV6)) {
        tvbuff_t *ipv6_tvb;

        ipv6_tvb = tvb_new_subset_remaining(tvb, len + 8);

        /* Call the IPv6 dissector */
        dissector_try_uint(ip_dissector_table, pproto, ipv6_tvb, pinfo, tree);

        col_set_str(pinfo->cinfo, COL_INFO, "Fast Neighbor Advertisement[Fast Binding Update]");
    }

    if ((type == MIP6_FBACK) && (pproto == IP_PROTO_AH)) {
        tvbuff_t *ipv6_tvb;

        ipv6_tvb = tvb_new_subset_remaining(tvb, len + offset);

        /* Call the IPv6 dissector */
        dissector_try_uint(ip_dissector_table, pproto, ipv6_tvb, pinfo, tree);

        col_set_str(pinfo->cinfo, COL_INFO, "Fast Binding Acknowledgment");
    }
}

/* Register the protocol with Wireshark */
void
proto_register_mip6(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

    { &hf_mip6_proto,
      { "Payload protocol", "mip6.proto",
        FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ipproto_val_ext, 0,
        NULL, HFILL }
    },
    { &hf_mip6_hlen,
        { "Header length", "mip6.hlen",
                FT_UINT8, BASE_DEC, NULL, 0,
                NULL, HFILL }
    },
    { &hf_mip6_mhtype,
      { "Mobility Header Type", "mip6.mhtype",
        FT_UINT8, BASE_DEC | BASE_EXT_STRING, &mip6_mh_types_ext, 0,
        NULL, HFILL }
    },
    { &hf_mip6_reserved,
      { "Reserved", "mip6.reserved",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_csum,
      { "Checksum", "mip6.csum",
        FT_UINT16, BASE_HEX, NULL, 0,
        "Header Checksum", HFILL }
    },

    { &hf_mip6_hoti_cookie,
      { "Home Init Cookie", "mip6.hoti.cookie",
        FT_UINT64, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },

    { &hf_mip6_coti_cookie,
      { "Care-of Init Cookie", "mip6.coti.cookie",
        FT_UINT64, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },

    { &hf_mip6_hot_nindex,
      { "Home Nonce Index", "mip6.hot.nindex",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_hot_cookie,
      { "Home Init Cookie", "mip6.hot.cookie",
        FT_UINT64, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_hot_token,
      { "Home Keygen Token", "mip6.hot.token",
        FT_UINT64, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },

    { &hf_mip6_cot_nindex,
      { "Care-of Nonce Index", "mip6.cot.nindex",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_cot_cookie,
      { "Care-of Init Cookie", "mip6.cot.cookie",
        FT_UINT64, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },
#if 0
    { &hf_mip6_cot_token,
      { "Care-of Keygen Token", "mip6.cot.token",
        FT_UINT64, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },
#endif

    { &hf_mip6_bu_seqnr,
      { "Sequence number", "mip6.bu.seqnr",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_bu_a_flag,
      { "Acknowledge (A) flag", "mip6.bu.a_flag",
        FT_BOOLEAN, 16, TFS(&mip6_bu_a_flag_value), 0x8000,
        NULL, HFILL }
    },
    { &hf_mip6_bu_h_flag,
      { "Home Registration (H) flag", "mip6.bu.h_flag",
        FT_BOOLEAN, 16, TFS(&mip6_bu_h_flag_value), 0x4000,
        NULL, HFILL }
    },
    { &hf_mip6_bu_l_flag,
      { "Link-Local Compatibility (L) flag", "mip6.bu.l_flag",
        FT_BOOLEAN, 16, TFS(&mip6_bu_l_flag_value), 0x2000,
        "Home Registration (H) flag", HFILL }
    },
    { &hf_mip6_bu_k_flag,
      { "Key Management Compatibility (K) flag", "mip6.bu.k_flag",
        FT_BOOLEAN, 16, TFS(&mip6_bu_k_flag_value), 0x1000,
        NULL, HFILL }
    },
    { &hf_mip6_bu_m_flag,
      { "MAP Registration Compatibility (M) flag", "mip6.bu.m_flag",
        FT_BOOLEAN, 16, TFS(&mip6_bu_m_flag_value), 0x0800,
        NULL, HFILL }
    },
    { &hf_mip6_nemo_bu_r_flag,
      { "Mobile Router (R) flag", "mip6.nemo.bu.r_flag",
        FT_BOOLEAN, 16, TFS(&mip6_nemo_bu_r_flag_value), 0x0400,
        NULL, HFILL }
    },
    { &hf_pmip6_bu_p_flag,
      { "Proxy Registration (P) flag", "mip6.bu.p_flag",
        FT_BOOLEAN, 16, TFS(&pmip6_bu_p_flag_value), 0x0200,
        NULL, HFILL }
    },
    { &hf_mip6_bu_f_flag,
      { "Forcing UDP encapsulation (F) flag", "mip6.bu.f_flag",
        FT_BOOLEAN, 16, TFS(&mip6_bu_f_flag_value), 0x0100,
        NULL, HFILL }
    },
    { &hf_pmip6_bu_t_flag,
      { "TLV-header format (T) flag", "mip6.bu.t_flag",
        FT_BOOLEAN, 16, TFS(&pmip6_bu_t_flag_value), 0x0080,
        NULL, HFILL }
    },
    { &hf_pmip6_bu_b_flag,
      { "Bulk-Binding-Update flag (B)", "mip6.bu.b_flag",
        FT_BOOLEAN, 16, TFS(&pmip6_bu_b_flag_value), 0x0040,
        NULL, HFILL }
    },
    { &hf_mip6_bu_lifetime,
      { "Lifetime", "mip6.bu.lifetime",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_mip6_ba_status,
      { "Status", "mip6.ba.status",
        FT_UINT8, BASE_DEC | BASE_EXT_STRING, &mip6_ba_status_value_ext, 0,
        "Binding Acknowledgement status", HFILL }
    },
    { &hf_mip6_ba_k_flag,
      { "Key Management Compatibility (K) flag", "mip6.ba.k_flag",
        FT_BOOLEAN, 8, TFS(&mip6_bu_k_flag_value), 0x80,
        NULL, HFILL }
    },
    { &hf_mip6_nemo_ba_r_flag,
      { "Mobile Router (R) flag", "mip6.nemo.ba.r_flag",
        FT_BOOLEAN, 8, TFS(&mip6_nemo_bu_r_flag_value), 0x40,
        NULL, HFILL }
    },
    { &hf_pmip6_ba_p_flag,
      { "Proxy Registration (P) flag", "mip6.ba.p_flag",
        FT_BOOLEAN, 8, TFS(&pmip6_bu_p_flag_value), 0x20,
        NULL, HFILL }
    },
    { &hf_pmip6_ba_t_flag,
      { "TLV-header format (T) flag", "mip6.ba.t_flag",
        FT_BOOLEAN, 8, TFS(&pmip6_bu_t_flag_value), 0x10,
        NULL, HFILL }
    },
    { &hf_pmip6_ba_b_flag,
      { "Bulk-Binding-Update flag (B)", "mip6.ba.b_flag",
        FT_BOOLEAN, 8, TFS(&pmip6_ba_b_flag_value), 0x08,
        NULL, HFILL }
    },

    { &hf_mip6_ba_seqnr,
      { "Sequence number", "mip6.ba.seqnr",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_ba_lifetime,
      { "Lifetime", "mip6.ba.lifetime",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_mip6_be_status,
      { "Status", "mip6.be.status",
        FT_UINT8, BASE_DEC, VALS(mip6_be_status_value), 0,
        "Binding Error status", HFILL }
    },
    { &hf_mip6_be_haddr,
      { "Home Address", "mip6.be.haddr",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },

    { &hf_fmip6_fbu_seqnr,
      { "Sequence number", "fmip6.fbu.seqnr",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_fmip6_fbu_a_flag,
      { "Acknowledge (A) flag", "fmip6.fbu.a_flag",
        FT_BOOLEAN, 8, TFS(&fmip6_fbu_a_flag_value), 0x80,
        NULL, HFILL }
    },
    { &hf_fmip6_fbu_h_flag,
      { "Home Registration (H) flag", "fmip6.fbu.h_flag",
        FT_BOOLEAN, 8, TFS(&fmip6_fbu_h_flag_value), 0x40,
        NULL, HFILL }
    },
    { &hf_fmip6_fbu_l_flag,
      { "Link-Local Compatibility (L) flag", "fmip6.fbu.l_flag",
        FT_BOOLEAN, 8, TFS(&fmip6_fbu_l_flag_value), 0x20,
        "Home Registration (H) flag", HFILL }
    },
    { &hf_fmip6_fbu_k_flag,
      { "Key Management Compatibility (K) flag", "fmip6.fbu.k_flag",
        FT_BOOLEAN, 8, TFS(&fmip6_fbu_k_flag_value), 0x10,
        NULL, HFILL }
    },
    { &hf_fmip6_fbu_lifetime,
      { "Lifetime", "fmip6.fbu.lifetime",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_fmip6_fback_status,
      { "Status", "fmip6.fback.status",
        FT_UINT8, BASE_DEC, VALS(fmip6_fback_status_value), 0,
        "Fast Binding Acknowledgement status", HFILL }
    },
    { &hf_fmip6_fback_k_flag,
      { "Key Management Compatibility (K) flag", "fmip6.fback.k_flag",
        FT_BOOLEAN, 8, TFS(&fmip6_fbu_k_flag_value), 0x80,
        NULL, HFILL }
    },
    { &hf_fmip6_fback_seqnr,
      { "Sequence number", "fmip6.fback.seqnr",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_fmip6_fback_lifetime,
      { "Lifetime", "fmip6.fback.lifetime",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_mip6_hb_u_flag,
      { "Unsolicited (U) flag", "mip6.hb.u_flag",
        FT_BOOLEAN, 8, TFS(&mip6_hb_u_flag_value), 0x02,
        NULL, HFILL }
    },
    { &hf_mip6_hb_r_flag,
      { "Response (R) flag", "mip6.hb.r_flag",
        FT_BOOLEAN, 8, TFS(&mip6_hb_r_flag_value), 0x01,
        NULL, HFILL }
    },
    { &hf_mip6_hb_seqnr,
      { "Sequence number", "mip6.hb.seqnr",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_hi_seqnr,
      { "Sequence number", "mip6.hi.seqnr",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_hi_s_flag,
      { "Assigned address configuration flag (S) flag", "mip6.hi.s_flag",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }
    },
    { &hf_mip6_hi_u_flag,
      { "Buffer flag (U) flag", "mip6.hi.u_flag",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }
    },
    { &hf_mip6_hi_code,
      { "Code", "mip6.hi.code",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_hack_seqnr,
      { "Sequence number", "mip6.hack.seqnr",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_hack_code,
      { "Code", "mip6.hack.code",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_3gpp_reserved,
      { "Reserved", "mip6.3gpp.reserved",
        FT_UINT8, BASE_DEC, NULL, 0xfe,
        NULL, HFILL }
    },
    { &hf_mip6_opt_3gpp_flag_m,
      { "M flag", "mip6.3gpp.flag.m",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }
    },
    { &hf_mip6_opt_3gpp_spec_pmipv6_err_code,
      { "3GPP Specific PMIPv6 Error Code", "mip6.3gpp.spec_pmipv6_err_code",
        FT_UINT8, BASE_DEC|BASE_EXT_STRING, &gtpv2_cause_vals_ext, 0x0,
        "GTPv2 Cause values", HFILL }
    },
    { &hf_mip6_opt_3gpp_pdn_gw_ipv4_addr,
      { "PDN GW IPv4 address", "mip6.3gpp.pdn_gw_ipv4_addr",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_3gpp_pdn_gw_ipv6_addr,
      { "PDN GW IPv6 address", "mip6.3gpp.pdn_gw_ipv6_addr",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_3gpp_dhcpv4_addr_all_proc_ind,
      { "DHCPv4 Address Allocation Procedure Indication", "mip6.3gpp.dhcpv4_addr_all_proc_ind",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_3gpp_pdn_type,
      { "PDN type", "mip6.3gpp.pdn_type",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_3gpp_pdn_ind_cause,
      { "Cause", "mip6.3gpp.pdn_ind_cause",
        FT_UINT8, BASE_DEC|BASE_EXT_STRING, &gtpv2_cause_vals_ext, 0x0,
        "GTPv2 Cause values", HFILL }
    },
    { &hf_mip6_opt_3gpp_chg_id,
      { "Charging ID", "mip6.3gpp.chg_id",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_3gpp_charging_characteristic,
      {"Charging Characteristic", "mip6.3gpp.charging_characteristic",
        FT_UINT16, BASE_HEX, NULL, 0xffff,
        NULL, HFILL}
      },
    { &hf_mip6_opt_3gpp_mei,
      {"Mobile Equipment Identity (MEI)", "mip6.3gpp.mei",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL}
    },
    { &hf_mip6_opt_3gpp_msisdn,
      {"MSISDN", "mip6.3gpp.msisdn",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL}
    },
    { &hf_mip6_opt_3gpp_apn_rest,
      { "APN Restriction", "mip6.3gpp.apn_rest",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_3gpp_max_apn_rest,
      { "Maximum APN Restriction", "mip6.3gpp.max_apn_rest",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_3gpp_imsi,
      {"Unauthenticated IMSI", "mip6.3gpp.imsi",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL}
    },
    { &hf_mip6_opt_3gpp_pdn_conn_id,
      { "PDN Connection ID", "mip6.3gpp.pdn_conn_id",
        FT_UINT8, BASE_DEC, NULL, 0x0f,
        NULL, HFILL }
    },
    { &hf_hf_mip6_opt_3gpp_lapi,
        {"LAPI (Low Access Priority Indication)", "mip6.3gpp.lapi",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL}
    },

    { &hf_mip6_bra_interval,
      { "Refresh interval", "mip6.bra.interval",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_mip6_acoa_acoa,
      { "Alternate care-of address", "mip6.acoa.acoa",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },

    { &hf_mip6_ni_hni,
      { "Home nonce index", "mip6.ni.hni",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_ni_cni,
      { "Care-of nonce index", "mip6.ni.cni",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_mip6_bad_auth,
      { "Authenticator", "mip6.bad.auth",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },

    { &hf_fmip6_lla_optcode,
      { "Option-Code", "mip6.lla.optcode",
        FT_UINT8, BASE_DEC, VALS(fmip6_lla_optcode_value), 0,
        NULL, HFILL }
    },

    { &hf_mip6_nemo_mnp_pfl,
      { "Mobile Network Prefix Length", "mip6.nemo.mnp.pfl",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_mip6_nemo_mnp_mnp,
      { "Mobile Network Prefix", "mip6.nemo.mnp.mnp",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },


    { &hf_mip6_mnid_subtype,
      { "Subtype", "mip6.mnid.subtype",
        FT_UINT8, BASE_DEC, VALS(mip6_mnid_subtype_value), 0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_auth_sub_type,
      { "Subtype", "mip6.auth.subtype",
        FT_UINT8, BASE_DEC, VALS(mip6_auth_subtype_value), 0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_auth_mobility_spi,
      { "Mobility SPI", "mip6.auth.mobility_spi",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_auth_auth_data,
      { "Authentication Data", "mip6.auth.auth_data",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_cgar_cga_par,
      { "CGA Parameters", "mip6.cgar.cga_par",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_sign_sign,
      { "CGA Parameters", "mip6.sign.sign",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_phkt_phkt,
      { "Permanent Home Keygen Token", "mip6.phkt.phkt",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_mocot_co_keygen_tok,
      { "Care-of Keygen Token", "mip6.mocot.co_keygen_tok",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_dnsu_status,
      { "Status", "mip6.dnsu.status",
        FT_UINT8, BASE_DEC, VALS(mip6_dnsu_status_values), 0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_dnsu_flag_r,
      { "R flag", "mip6.dnsu.flag.r",
        FT_BOOLEAN, 8, TFS(&mip6_dnsu_r_flag_value), 0x80,
        NULL, HFILL }
    },
    { &hf_mip6_opt_dnsu_mn_id,
      { "MN identity (FQDN)", "mip6.dnsu.mn_id",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_em_data,
      { "Data", "mip6.em.data",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_vsm_vid,
      { "Vendor Id", "mip6.vsm.vendorId",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &sminmpec_values_ext, 0x0,
        NULL, HFILL }
    },
    { &hf_mip6_vsm_subtype,
      { "Subtype", "mip6.vsm.subtype",
        FT_UINT8, BASE_DEC, VALS(mip6_vsm_subtype_value), 0,
        NULL, HFILL }
    },
    { &hf_mip6_vsm_subtype_3gpp,
      { "Subtype", "mip6.vsm.subtype",
        FT_UINT8, BASE_DEC | BASE_EXT_STRING, &mip6_vsm_subtype_3gpp_value_ext, 0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_badff_spi,
      { "SPI", "mip6.badff.spi",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_badff_auth,
      { "Authenticator", "mip6.badff.auth",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pmip6_hi_hi,
      { "Handoff Indicator", "mip6.hi",
        FT_UINT8, BASE_DEC, VALS(pmip6_hi_opttype_value), 0,
        NULL, HFILL }
    },
    { &hf_pmip6_hi_reserved,
      { "Reserved", "mip6.hi.reserved",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_pmip6_att_reserved,
      { "Reserved", "mip6.att.reserved",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_pmip6_att_att,
      { "Access Technology Type", "mip6.att",
        FT_UINT8, BASE_DEC | BASE_EXT_STRING, &pmip6_att_att_value_ext, 0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_mnlli_reserved,
      { "Reserved", "mip6.mnlli.reserved",
        FT_UINT16, BASE_DEC, NULL, 0xffff,
        NULL, HFILL }
    },
    { &hf_mip6_opt_mnlli_lli,
      { "Link-layer Identifier", "mip6.mnlli.lli",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pmip6_timestamp,
      { "Timestamp", "mip6.timestamp_tmp",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_pmip6_opt_lila_lla,
      { "Link-local Address", "mip6.lila_lla",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pmip6_rc,
      { "Restart Counter", "mip6.rc",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_mip6_ipv4ha_preflen,
      { "Prefix-len", "mip6.ipv4ha.preflen",
        FT_UINT8, BASE_DEC, NULL, 0xfc,
        NULL, HFILL}
    },

    { &hf_mip6_ipv4ha_p_flag,
      { "mobile network prefix (P) flag", "mip6.ipv4ha.p_flag",
        FT_BOOLEAN, 16, TFS(&mip6_ipv4ha_p_flag_value), 0x0200,
        NULL, HFILL }
    },

    { &hf_mip6_ipv4ha_ha,
      { "IPv4 Home Address", "mip6.ipv4ha.ha",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_mip6_ipv4aa_status,
      { "Status", "mip6.ipv4aa.sts",
        FT_UINT8, BASE_DEC, VALS(pmip6_ipv4aa_status_values), 0x0,
        NULL, HFILL}
    },
    { &hf_mip6_opt_natd_f_flag,
      { "(F) flag", "mip6.natd.f_flag",
        FT_BOOLEAN, 16, TFS(&mip6_natd_f_flag_value), 0x8000,
        NULL, HFILL }
    },
    { &hf_mip6_opt_natd_reserved,
      { "Reserved", "mip6.natd.reserved",
        FT_UINT16, BASE_DEC, NULL, 0x7fff,
        NULL, HFILL }
    },
    { &hf_mip6_opt_natd_refresh_t,
      { "Refresh time", "mip6.natd.refresh_t",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_ipv4coa_reserved,
      { "Reserved", "mip6.ipv4coa.reserved",
        FT_UINT16, BASE_DEC, NULL, 0xffff,
        NULL, HFILL }
    },
    { &hf_mip6_opt_ipv4coa_addr,
      { "IPv4 Care-of address", "mip6.ipv4coa.addr",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_pmip6_gre_key,
      { "GRE Key", "mip6.gre_key",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },

    { &hf_mip6_opt_mhipv6ap_opt_code,
      { "Option-Code", "mip6.mhipv6ap.opt_code",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_mhipv6ap_prefix_l,
      { "Prefix Length", "mip6.mhipv6ap.len",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_bi_bid,
      { "Binding ID (BID)", "mip6.bi.bid",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_bi_status,
      { "Status", "mip6.bi.status",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_bi_h_flag,
      { "Simultaneous Home and Foreign Binding (H)", "mip6.bi.h_flag",
        FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x80,
        NULL, HFILL }
    },
    { &hf_mip6_bi_coa_ipv4,
      { "IPv4 care-of address (CoA)", "mip6.bi.coa_ipv4",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_mip6_bi_coa_ipv6,
      { "IPv6 care-of address (CoA)", "mip6.bi.coa_ipv6",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_mip6_ipv4dra_reserved,
      { "Reserved", "mip6.ipv4dra.reserved",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_ipv4dra_dra,
      { "IPv4 Default-Router Address", "mip6.ipv4dra.dra",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_mip6_ipv4dsm_reserved,
      { "Reserved", "mip6.ipv4dsm.reserved",
        FT_UINT16, BASE_DEC, NULL, 0xfffe,
        NULL, HFILL }
    },
    { &hf_mip6_ipv4dsm_s_flag,
      { "DHCP Support Mode (S)", "mip6.ipv4dsm.s_flag",
        FT_BOOLEAN, 16, TFS(&mip6_ipv4dsm_s_flag_value), 0x0001,
        NULL, HFILL }
    },

    { &hf_mip6_cr_reserved,
      { "Reserved", "mip6.cr.reserved",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_mip6_cr_req_type,
      { "Req-type", "mmip6.cr.req_type",
        FT_UINT8, BASE_DEC | BASE_EXT_STRING, &mip6_mobility_options_ext, 0,
        NULL, HFILL }
    },
    { &hf_mip6_cr_req_length,
      { "Req-type", "mmip6.cr.req_length",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_lmaa_opt_code,
      { "Option-Code", "mmip6.lmaa.opt_code",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_lmaa_reserved,
      { "Reserved", "mmip6.lmaa.reserved",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_lmaa_ipv4,
      { "Local Mobility Anchor Address", "mip6.lmaa.ipv4",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_mip6_lmaa_ipv6,
      { "Local Mobility Anchor Address", "mip6.lmaa.ipv6",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_mip6_mobility_opt,
      { "Mobility Option", "mip6.mobility_opt",
        FT_UINT8, BASE_DEC | BASE_EXT_STRING, &mip6_mobility_options_ext, 0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_len,
      { "Length", "mip6.mobility_opt.len",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_pmip6_bri_brtype,
      { "B.R. Type", "mip6.bri_br.type",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_pmip6_bri_rtrigger,
      { "R. Trigger", "mip6.bri_r.trigger",
        FT_UINT8, BASE_DEC, VALS(pmip6_bri_rtrigger), 0x0,
        NULL, HFILL }
    },

    { &hf_pmip6_bri_status,
      { "Status", "mip6.bri_status",
        FT_UINT8, BASE_DEC, VALS(pmip6_bri_status), 0x0,
        NULL, HFILL }
    },

    { &hf_pmip6_bri_seqnr,
      { "Sequence Number", "mip6.bri_seqnr",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_pmip6_bri_ip_flag,
      { "Proxy Binding (P) Flag", "mip6.bri_ip",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x8000,
        NULL, HFILL }
    },

    { &hf_pmip6_bri_iv_flag,
      { "IPv4 HoA Binding Only (V) Flag", "mip6.bri_iv",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x4000,
        NULL, HFILL }
    },

    { &hf_pmip6_bri_ig_flag,
      { "Global (G) Flag", "mip6.bri_ig",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x2000,
        NULL, HFILL }
    },

    { &hf_pmip6_bri_ap_flag,
      { "Proxy Binding (P) Flag", "mip6.bri_ap",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x8000,
        NULL, HFILL }
    },
    { &hf_pmip6_bri_av_flag,
      { "IPv4 HoA Binding Only (V) Flag", "mip6.bri_av",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x4000,
        NULL, HFILL }
    },

    { &hf_pmip6_bri_ag_flag,
      { "Global (G) Flag", "mip6.bri_ag",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x2000,
        NULL, HFILL }
    },

    { &hf_pmip6_bri_res,
      { "Reserved", "mip6.bri_res",
        FT_UINT16, BASE_HEX, NULL, 0x1FFF,
        "Must be zero", HFILL }
    },

    { &hf_mip6_opt_recap_reserved,
      { "Reserved", "mip6.recap.reserved",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        "Must be zero", HFILL }
    },

    { &hf_mip6_opt_redir_k,
      { "K", "mip6.redir.k",
        FT_BOOLEAN, 16, NULL, MIP6_REDIR_FLAG_K,
        "bit is set (1) if the Optional IPv6 r2LMA Address is included in the mobility option", HFILL }
    },
    { &hf_mip6_opt_redir_n,
      { "N", "mip6.redir.n",
        FT_BOOLEAN, 16, NULL, MIP6_REDIR_FLAG_K,
        "bit is set (1) if the Optional IPv4 r2LMA Address is included in the mobility option", HFILL }
    },
    { &hf_mip6_opt_redir_reserved,
      { "Reserved", "mip6.redir.reserved",
        FT_UINT16, BASE_HEX, NULL, MIP6_REDIR_FLAG_RSV,
        "Must be zero", HFILL }
    },
    { &hf_mip6_opt_redir_addr_r2LMA_ipv6,
      { "IPv6 r2LMA Address", "mip6.redir.addr_r2lma_ipv6",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_redir_addr_r2LMA_ipv4,
      { "IPv4 r2LMA Address", "mip6.redir.addr_r2lma_ipv4",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_mip6_opt_load_inf_priority,
      { "Priority", "mip6.load_inf.priority",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_load_inf_sessions_in_use,
      { "Sessions in Use", "mip6.load_inf.sessions_in_use",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_load_inf_maximum_sessions,
      { "Maximum Sessions", "mip6.load_inf.maximum_sessions",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_load_inf_used_capacity,
      { "Used Capacity", "mip6.load_inf.used_capacity",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_load_inf_maximum_capacity,
      { "Maximum Capacity", "mip6.load_inf.maximum_capacity",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_mip6_opt_alt_ip4,
      { "Alternate IPv4 Care-of Address", "mip6.alt_ip4",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_mip6_opt_mng_sub_type,
      { "Sub Type", "mip6.mng.sub_type",
        FT_UINT8, BASE_DEC, VALS(mip6_mng_id_type_vals), 0x0,
        NULL, HFILL }
    },

    { &hf_mip6_opt_mng_reserved,
      { "Reserved", "mip6.mng.reserved",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_mip6_opt_mng_mng_id,
      { "Mobile Node Group Identifier", "mip6.mng.mng_id",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
};

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_mip6,
        &ett_mip6_opts,
        &ett_mip6_opt_pad1,
        &ett_mip6_opt_padn,
        &ett_mip6_opt_bra,
        &ett_mip6_opt_acoa,
        &ett_mip6_opt_ni,
        &ett_mip6_opt_bad,
        &ett_fmip6_opt_lla,
        &ett_mip6_nemo_opt_mnp,
        &ett_mip6_opt_mnid,
        &ett_mip6_opt_auth,
        &ett_mip6_opt_mesgid,
        &ett_mip6_opt_cgapr,
        &ett_mip6_opt_cgar,
        &ett_mip6_opt_sign,
        &ett_mip6_opt_phkt,
        &ett_mip6_opt_mocoti,
        &ett_mip6_opt_mocot,
        &ett_mip6_opt_dnsu,
        &ett_mip6_opt_em,
        &ett_mip6_opt_vsm,
        &ett_mip6_opt_ssm,
        &ett_mip6_opt_badff,
        &ett_pmip6_opt_hnp,
        &ett_pmip6_opt_hi,
        &ett_pmip6_opt_att,
        &ett_pmip6_opt_mnlli,
        &ett_pmip6_opt_lla,
        &ett_pmip6_opt_ts,
        &ett_pmip6_opt_rc,
        &ett_mip6_opt_ipv4ha,
        &ett_mip6_opt_ipv4aa,
        &ett_mip6_opt_natd,
        &ett_mip6_opt_ipv4coa,
        &ett_pmip6_opt_grek,
        &ett_pmip6_opt_mhipv6ap,
        &ett_pmip6_opt_bi,
        &ett_mip6_opt_ipv4hareq,
        &ett_mip6_opt_ipv4harep,
        &ett_mip6_opt_ipv4dra,
        &ett_mip6_opt_ipv4dsm,
        &ett_mip6_opt_cr,
        &ett_mip6_opt_lmaa,
        &ett_mip6_opt_recap,
        &ett_mip6_opt_redir,
        &ett_mip6_opt_load_inf,
        &ett_mip6_opt_alt_ip4,
        &ett_mip6_opt_mng,
    };

    static ei_register_info ei[] = {
        { &ei_mip6_ie_not_dissected, { "mip6.ie_not_dissected", PI_UNDECODED, PI_NOTE, "IE data not dissected yet", EXPFILL }},
    };

    expert_module_t* expert_mip6;

    /* Register the protocol name and description */
    proto_mip6 = proto_register_protocol("Mobile IPv6 / Network Mobility", "MIPv6", "mipv6");

    /* Register the dissector by name */
    /* register_dissector("mipv6", dissect_nemo, proto_nemo); */

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_mip6, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_mip6 = expert_register_protocol(proto_mip6);
    expert_register_field_array(expert_mip6, ei, array_length(ei));

    mip6_vsm_dissector_table = register_dissector_table("mip6.vsm", "Mobile IPv6 vendor specific option", FT_UINT32, BASE_DEC);
}

void
proto_reg_handoff_mip6(void)
{
    dissector_handle_t mip6_handle;

    /* mip6_handle = find_dissector("mipv6"); */
    mip6_handle = create_dissector_handle(dissect_mip6, proto_mip6);
    dissector_add_uint("ip.proto", IP_PROTO_MIPV6_OLD, mip6_handle);
    dissector_add_uint("ip.proto", IP_PROTO_MIPV6, mip6_handle);
    /* Add support for PMIPv6 control messages over IPV4 */
    dissector_add_uint("udp.port", UDP_PORT_PMIP6_CNTL, mip6_handle);
    ip_dissector_table = find_dissector_table("ip.proto");

    dissector_add_uint("mip6.vsm", VENDOR_THE3GPP, new_create_dissector_handle(dissect_mip6_opt_vsm_3gpp, proto_mip6));
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
