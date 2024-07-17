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
 * SPDX-License-Identifier: GPL-2.0-or-later
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
 * RFC 6705, Localized Routing for Proxy Mobile IPv6
 * RFC 6757, Access Network Identifier (ANI) Option for Proxy Mobile IPv6
 * RFC 7148, Prefix Delegation Support for Proxy Mobile IPv6
 *
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/to_str.h>

#include <epan/ipproto.h>
#include <epan/expert.h>
#include <epan/ip_opts.h>
#include <epan/sminmpec.h>
#include <epan/addr_resolv.h>

#include <wsutil/str_util.h>

#include "packet-ntp.h"
#include "packet-gtpv2.h"
#include "packet-e164.h"
#include "packet-e212.h"
#include "packet-gsm_a_common.h"
#include "packet-ip.h"

void proto_register_mip6(void);
void proto_reg_handoff_mip6(void);

static dissector_handle_t mip6_handle;

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
    MIP6_ACC_NET_ID= 52,        /* 52 Access Network Identifier [RFC6757] */
    MIP6_DMNP      = 55         /* 55 Delegated Mobile Network Prefix Option [RFC7148] */

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
    { MIP6_DMNP,       "Delegated Mobile Network Prefix"},              /* RFC7148 */

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
    { 177, "NOT_AUTHORIZED_FOR_DELEGATED_MNP" },                    /* [RFC7148] */
    { 178, "REQUESTED_DMNP_IN_USE" },                               /* [RFC7148] */


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
    "mobile network prefix requested",
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
    {  21, "Static IP Address Allocation Indications" },   /* 3GPP TS 29.275 [7] */
    {  22, "MME / SGSN Identifier" },                      /* 3GPP TS 29.275 [7] */
    {  23, "End Marker Notification" },                    /* 3GPP TS 29.275 [7] */
    {  24, "Trusted WLAN Mode Indication" },               /* 3GPP TS 29.275 [7] */
    {  25, "UE Time Zone" },                               /* 3GPP TS 29.275 [7] */
    {  26, "Access Network Identifier Timestamp" },        /* 3GPP TS 29.275 [7] */
    {  27, "Logical Access ID" },                          /* 3GPP TS 29.275 [7] */
    {  28, "Origination Time Stamp" },                     /* 3GPP TS 29.275 [7] */
    {  29, "Maximum Wait Time" },                          /* 3GPP TS 29.275 [7] */
    {  30, "TWAN Capabilities" },                          /* 3GPP TS 29.275 [7] */

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
    { 0,     "Unspecified"},
    { 1,     "Administrative Reason"},
    { 2,     "Inter-MAG Handover - same Access Type"},
    { 3,     "Inter-MAG Handover - different Access Type"},
    { 4,     "Inter-MAG Handover - Unknown"},
    { 5,     "User Initiated Session(s) Termination"},
    { 6,     "Access Network Session(s) Termination"},
    { 7,     "Possible Out-of Sync BCE State"},
    /* 8-127 Unassigned  */
    { 128,   "Per-Peer Policy"},
    { 129,   "Revoking Mobility Node Local Policy"},
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

static const value_string pmip6_lra_status_vals[] = {
    { 0,     "Success"},
    { 128,   "Localized Routing Not Allowed"},
    { 129,   "MN Not Attached"},
    { 0,        NULL},
};

/* Delegated Mobile Network Prefix V Flag Values */
static const true_false_string mip6_dmnp_v_flag_value = {
    "IPv4 Prefix",
    "IPv6 Prefix"
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
#define MIP6_BRA_RI_LEN       2

#define MIP6_ACOA_LEN        16
#define MIP6_ACOA_ACOA_LEN   16

#define MIP6_NEMO_MNP_LEN         18
#define MIP6_NEMO_MNP_MNP_LEN     16

#define MIP6_NI_LEN           4
#define MIP6_NI_HNI_LEN       2
#define MIP6_NI_CNI_LEN       2

#define FMIP6_LLA_MINLEN      1
#define FMIP6_LLA_OPTCODE_LEN 1

#define MIP6_MNID_MINLEN      2
#define MIP6_MNID_SUBTYPE_LEN 1

#define MIP6_AUTH_MINLEN      6
#define MIP6_CGAPR_MINLEN     0
#define MIP6_CGAR_MINLEN      1
#define MIP6_SIGN_MINLEN      1
#define MIP6_PHKT_MINLEN      1
#define MIP6_MOCOTI_MINLEN    0
#define MIP6_MOCOT_MINLEN     8
#define MIP6_DNSU_MINLEN      5
#define MIP6_EM_MINLEN        1
#define MIP6_MESG_ID_LEN      8

#define MIP6_VSM_MINLEN       2
#define MIP6_VSM_VID_LEN      4
#define MIP6_VSM_SUBTYPE_LEN  1

#define MIP6_SSM_MINLEN       1

#define MIP6_BADFF_MINLEN     4

#define PMIP6_HI_LEN          2
#define PMIP6_HI_HI_LEN       1

#define PMIP6_ATT_LEN         2
#define PMIP6_ATT_ATT_LEN     1

#define PMIP6_MNLLI_MIN_LEN   1

#define PMIP6_LLA_LEN         16

#define PMIP6_TS_LEN          8

#define PMIP6_RC_LEN          4
#define PMIP6_RC_RC_LEN       4

#define MIP6_IPV4HA_LEN         6
#define MIP6_IPV4HA_PREFIXL_LEN 1
#define MIP6_IPV4HA_HA_LEN      4

#define MIP6_IPV4AA_LEN         6
#define MIP6_IPV4AA_STATUS_LEN  1
#define MIP6_IPV4AA_PREFIXL_LEN 1
#define MIP6_IPV4AA_HA_LEN      4

#define MIP6_NATD_LEN              6

#define MIP6_IPV4COA_LEN           6

#define PMIP6_GREK_MIN_LEN         2
#define PMIP6_GREK_ID_LEN          4

#define MIP6_MHIPV6AP_LEN      18

#define MIP6_BI_MIN_LEN            4

#define MIP6_IPV4HAREQ_LEN         6
#define MIP6_IPV4HAREQ_PREFIXL_LEN 1
#define MIP6_IPV4HAREQ_HA_LEN      4

#define MIP6_IPV4HAREP_LEN         6
#define MIP6_IPV4HAREP_STATUS_LEN  1
#define MIP6_IPV4HAREP_PREFIXL_LEN 1
#define MIP6_IPV4HAREP_HA_LEN      4

#define MIP6_IPV4DRA_LEN      6
#define MIP6_IPV4DRA_RES_LEN  2
#define MIP6_IPV4DRA_DRA_LEN  4

#define MIP6_IPV4DSM_LEN      2

#define MIP6_CR_MIN_LEN       4

#define MIP6_LMAA_MIN_LEN     6

#define MIP6_RECAP_LEN        2
#define MIP6_REDIR_MIN_LEN    6
#define MIP6_REDIR_FLAG_K     0x8000
#define MIP6_REDIR_FLAG_N     0x4000
#define MIP6_REDIR_FLAG_RSV   0x3FFF

#define MIP6_LOAD_INF_LEN     18
#define MIP6_ALT_IP4_LEN      4

#define MIP6_MNG_LEN          6

#define MIP6_MAG_IPv6_LEN    16

#define MIP6_ACC_NET_ID_MIN_LEN    3

#define MIP6_DMNP_MIN_LEN     6

static dissector_table_t ip_dissector_table;

/* Initialize the protocol and registered header fields */
static int proto_mip6;
static int proto_nemo;
static int proto_mip6_option_pad1;
static int proto_mip6_option_padn;
static int proto_mip6_option_bra;
static int proto_mip6_option_acoa;
static int proto_mip6_option_ni;
static int proto_mip6_option_bad_auth;
static int proto_mip6_option_mnp;
static int proto_mip6_option_mhlla;
static int proto_mip6_option_mnid;
static int proto_mip6_option_auth;
static int proto_mip6_option_mseg_id;
static int proto_mip6_option_cgapr;
static int proto_mip6_option_cgar;
static int proto_mip6_option_sign;
static int proto_mip6_option_phkt;
static int proto_mip6_option_coti;
static int proto_mip6_option_cot;
static int proto_mip6_option_dnsu;
static int proto_mip6_option_em;
static int proto_mip6_option_vsm;
static int proto_mip6_option_ssm;
static int proto_mip6_option_badff;
static int proto_mip6_option_hnp;
static int proto_mip6_option_hi;
static int proto_mip6_option_att;
static int proto_mip6_option_mnlli;
static int proto_mip6_option_lla;
static int proto_mip6_option_ts;
static int proto_mip6_option_rc;
static int proto_mip6_option_ipv4ha;
static int proto_mip6_option_ipv4aa;
static int proto_mip6_option_natd;
static int proto_mip6_option_ipv4coa;
static int proto_mip6_option_grek;
static int proto_mip6_option_mhipv6ap;
static int proto_mip6_option_bi;
static int proto_mip6_option_ipv4hareq;
static int proto_mip6_option_ipv4harep;
static int proto_mip6_option_ipv4dra;
static int proto_mip6_option_ipv4dsm;
static int proto_mip6_option_cr;
static int proto_mip6_option_lmaa;
static int proto_mip6_option_recap;
static int proto_mip6_option_redir;
static int proto_mip6_option_load_inf;
static int proto_mip6_option_alt_ip4;
static int proto_mip6_option_mng;
static int proto_mip6_option_mag_ipv6;
static int proto_mip6_option_acc_net_id;
static int proto_mip6_option_dmnp;

static int hf_mip6_proto;
static int hf_mip6_hlen;
static int hf_mip6_mhtype;
static int hf_mip6_reserved;
static int hf_mip6_csum;

static int hf_mip6_hoti_cookie;

static int hf_mip6_coti_cookie;

static int hf_mip6_hot_nindex;
static int hf_mip6_hot_cookie;
static int hf_mip6_hot_token;

static int hf_mip6_cot_nindex;
static int hf_mip6_cot_cookie;
/* static int hf_mip6_cot_token; */

static int hf_mip6_bu_seqnr;
static int hf_mip6_bu_a_flag;
static int hf_mip6_bu_h_flag;
static int hf_mip6_bu_l_flag;
static int hf_mip6_bu_k_flag;
static int hf_mip6_bu_m_flag;
static int hf_mip6_nemo_bu_r_flag;
static int hf_pmip6_bu_p_flag;
static int hf_mip6_bu_f_flag;
static int hf_pmip6_bu_t_flag;
static int hf_pmip6_bu_b_flag;
static int hf_mip6_bu_lifetime;

static int hf_mip6_ba_status;
static int hf_mip6_ba_k_flag;
static int hf_mip6_nemo_ba_r_flag;
static int hf_pmip6_ba_p_flag;
static int hf_pmip6_ba_t_flag;
static int hf_pmip6_ba_b_flag;
static int hf_mip6_ba_seqnr;
static int hf_mip6_ba_lifetime;

static int hf_mip6_be_status;
static int hf_mip6_be_haddr;

static int hf_fmip6_fbu_seqnr;
static int hf_fmip6_fbu_a_flag;
static int hf_fmip6_fbu_h_flag;
static int hf_fmip6_fbu_l_flag;
static int hf_fmip6_fbu_k_flag;
static int hf_fmip6_fbu_lifetime;

static int hf_fmip6_fback_status;
static int hf_fmip6_fback_k_flag;
static int hf_fmip6_fback_seqnr;
static int hf_fmip6_fback_lifetime;

static int hf_mip6_has_num_addrs;
static int hf_mip6_has_reserved;
static int hf_mip6_has_address;

static int hf_mip6_hb_u_flag;
static int hf_mip6_hb_r_flag;
static int hf_mip6_hb_seqnr;

static int hf_mip6_hi_seqnr;
static int hf_mip6_hi_s_flag;
static int hf_mip6_hi_u_flag;
static int hf_mip6_hi_code;

static int hf_mip6_hack_seqnr;
static int hf_mip6_hack_code;

static int hf_mip6_opt_3gpp_reserved;
static int hf_mip6_opt_3gpp_flag_m;
static int hf_mip6_opt_3gpp_spec_pmipv6_err_code;
static int hf_mip6_opt_3gpp_pdn_gw_ipv4_addr;
static int hf_mip6_opt_3gpp_pdn_gw_ipv6_addr;
static int hf_mip6_opt_3gpp_dhcpv4_addr_all_proc_ind;
static int hf_mip6_opt_3gpp_pdn_type;
static int hf_mip6_opt_3gpp_pdn_ind_cause;
static int hf_mip6_opt_3gpp_chg_id;
static int hf_mip6_opt_3gpp_charging_characteristic;
static int hf_mip6_opt_3gpp_mei;
static int hf_mip6_opt_3gpp_msisdn;
static int hf_mip6_opt_3gpp_apn_rest;
static int hf_mip6_opt_3gpp_max_apn_rest;
static int hf_mip6_opt_3gpp_imsi;
static int hf_mip6_opt_3gpp_pdn_conn_id;
static int hf_mip6_opt_3gpp_lapi;

static int hf_mip6_bra_interval;

static int hf_mip6_acoa_acoa;
static int hf_mip6_nemo_mnp_mnp;
static int hf_mip6_nemo_mnp_pfl;

static int hf_mip6_ni_hni;
static int hf_mip6_ni_cni;

static int hf_mip6_bad_auth;

static int hf_fmip6_lla;
static int hf_fmip6_lla_optcode;

static int hf_mip6_mnid_subtype;
static int hf_mip6_mnid_identifier;
static int hf_mip6_vsm_vid;
static int hf_mip6_vsm_subtype;
static int hf_mip6_vsm_subtype_3gpp;

static int hf_mip6_opt_ss_identifier;

static int hf_mip6_opt_badff_spi;
static int hf_mip6_opt_badff_auth;

static int hf_mip6_opt_auth_sub_type;
static int hf_mip6_opt_auth_mobility_spi;
static int hf_mip6_opt_auth_auth_data;
static int hf_mip6_opt_mseg_id_timestamp;

static int hf_mip6_opt_cgar_cga_par;
static int hf_mip6_opt_sign_sign;
static int hf_mip6_opt_phkt_phkt;
static int hf_mip6_opt_mocot_co_keygen_tok;

static int hf_mip6_opt_dnsu_status;
static int hf_mip6_opt_dnsu_flag_r;
static int hf_mip6_opt_dnsu_mn_id;

static int hf_mip6_opt_em_data;

static int hf_pmip6_hi_hi;
static int hf_pmip6_hi_reserved;

static int hf_pmip6_att_reserved;
static int hf_pmip6_att_att;

static int hf_mip6_opt_mnlli_reserved;
static int hf_mip6_opt_mnlli_lli;

static int hf_pmip6_timestamp;
static int hf_pmip6_rc;
static int hf_mip6_ipv4ha_preflen;
static int hf_mip6_ipv4ha_p_flag;
static int hf_mip6_ipv4ha_ha;
static int hf_mip6_ipv4ha_reserved;
static int hf_mip6_ipv4aa_status;

static int hf_mip6_opt_natd_f_flag;
static int hf_mip6_opt_natd_reserved;
static int hf_mip6_opt_natd_refresh_t;

static int hf_mip6_opt_ipv4coa_reserved;
static int hf_mip6_opt_ipv4coa_addr;

static int hf_pmip6_gre_key;
static int hf_mip6_opt_mhipv6ap_opt_code;
static int hf_mip6_opt_mhipv6ap_prefix_l;
static int hf_mip6_opt_mhipv6ap_ipv6_address;
static int hf_mip6_opt_mhipv6ap_ipv6_address_prefix;
static int hf_mip6_ipv4dra_reserved;
static int hf_mip6_ipv4dra_dra;

static int hf_mip6_ipv4dsm_reserved;
static int hf_mip6_ipv4dsm_s_flag;
static int hf_mip6_cr_reserved;
static int hf_mip6_cr_req_type;
static int hf_mip6_cr_req_length;

static int hf_mip6_lmaa_opt_code;
static int hf_mip6_lmaa_reserved;
static int hf_mip6_lmaa_ipv4;
static int hf_mip6_lmaa_ipv6;

static int hf_mip6_mobility_opt;
static int hf_mip6_opt_len;

static int hf_mip6_opt_bi_bid;
static int hf_mip6_opt_bi_status;
static int hf_mip6_bi_h_flag;
static int hf_mip6_bi_coa_ipv4;
static int hf_mip6_bi_coa_ipv6;

static int hf_mip6_binding_refresh_request;
static int hf_mip6_unknown_type_data;
static int hf_mip6_fast_neighbor_advertisement;
static int hf_mip6_vsm_data;
static int hf_mip6_vsm_req_data;
static int hf_mip6_opt_padn;

/* PMIP BRI */
static int hf_pmip6_bri_brtype;
static int hf_pmip6_bri_rtrigger;
static int hf_pmip6_bri_status;
static int hf_pmip6_bri_seqnr;
static int hf_pmip6_bri_ip_flag;
static int hf_pmip6_bri_ap_flag;
static int hf_pmip6_bri_iv_flag;
static int hf_pmip6_bri_av_flag;
static int hf_pmip6_bri_ig_flag;
static int hf_pmip6_bri_ag_flag;
static int hf_pmip6_bri_res;

static int hf_pmip6_lri_sequence;
static int hf_pmip6_lri_reserved;
static int hf_pmip6_lri_lifetime;

static int hf_pmip6_lra_sequence;
static int hf_pmip6_lra_u;
static int hf_pmip6_lra_reserved;
static int hf_pmip6_lra_status;
static int hf_pmip6_lra_lifetime;

static int hf_mip6_opt_recap_reserved;
static int hf_mip6_opt_redir_k;
static int hf_mip6_opt_redir_n;
static int hf_mip6_opt_redir_reserved;
static int hf_mip6_opt_redir_addr_r2LMA_ipv6;
static int hf_mip6_opt_redir_addr_r2LMA_ipv4;
static int hf_mip6_opt_load_inf_priority;
static int hf_mip6_opt_load_inf_sessions_in_use;
static int hf_mip6_opt_load_inf_maximum_sessions;
static int hf_mip6_opt_load_inf_used_capacity;
static int hf_mip6_opt_load_inf_maximum_capacity;
static int hf_mip6_opt_alt_ip4;

/* Mobile Node Group Identifier Optionm */
static int hf_mip6_opt_mng_sub_type;
static int hf_mip6_opt_mng_reserved;
static int hf_mip6_opt_mng_mng_id;

static int hf_mip6_opt_mag_ipv6_reserved;
static int hf_mip6_opt_mag_ipv6_address_length;
static int hf_mip6_opt_mag_ipv6_address;

static int hf_mip6_opt_acc_net_id_sub;
static int hf_mip6_opt_acc_net_id_sub_opt;
static int hf_mip6_opt_acc_net_id_sub_opt_len;
static int hf_mip6_opt_acc_net_id_sub_opt_e_bit;
static int hf_mip6_opt_acc_net_id_sub_opt_net_name_len;
static int hf_mip6_opt_acc_net_id_sub_opt_net_name;
static int hf_mip6_opt_acc_net_id_sub_opt_net_name_data;
static int hf_mip6_opt_acc_net_id_sub_opt_ap_name_len;
static int hf_mip6_opt_acc_net_id_sub_opt_ap_name;
static int hf_mip6_opt_acc_net_id_sub_opt_geo_latitude_degrees;
static int hf_mip6_opt_acc_net_id_sub_opt_geo_longitude_degrees;
static int hf_mip6_opt_acc_net_id_sub_opt_op_id_type;
static int hf_mip6_opt_acc_net_id_sub_opt_op_id;

static int hf_pmip6_opt_lila_lla;

/* Delegated Mobile Network Prefix Option */
static int hf_mip6_opt_dmnp_v_flag;
static int hf_mip6_opt_dmnp_reserved;
static int hf_mip6_opt_dmnp_prefix_len;
static int hf_mip6_opt_dmnp_dmnp_ipv4;
static int hf_mip6_opt_dmnp_dmnp_ipv6;

/* Initialize the subtree pointers */
static int ett_mip6;
static int ett_mip6_opt_pad1;
static int ett_mip6_opt_padn;
static int ett_mip6_opts;
static int ett_mip6_opt_bra;
static int ett_mip6_opt_acoa;
static int ett_mip6_opt_ni;
static int ett_mip6_opt_bad;
static int ett_mip6_nemo_opt_mnp;
static int ett_fmip6_opt_lla;
static int ett_mip6_opt_mnid;
static int ett_mip6_opt_auth;
static int ett_mip6_opt_mesgid;
static int ett_mip6_opt_cgapr;
static int ett_mip6_opt_cgar;
static int ett_mip6_opt_sign;
static int ett_mip6_opt_phkt;
static int ett_mip6_opt_mocoti;
static int ett_mip6_opt_mocot;
static int ett_mip6_opt_dnsu;
static int ett_mip6_opt_em;
static int ett_mip6_opt_vsm;
static int ett_mip6_opt_ssm;
static int ett_mip6_opt_badff;
static int ett_mip6_opt_unknown;
static int ett_pmip6_opt_hnp;
static int ett_pmip6_opt_hi;
static int ett_pmip6_opt_att;
static int ett_pmip6_opt_mnlli;
static int ett_pmip6_opt_lla;
static int ett_pmip6_opt_ts;
static int ett_pmip6_opt_rc;
static int ett_mip6_opt_ipv4ha;
static int ett_mip6_opt_ipv4aa;
static int ett_mip6_opt_natd;
static int ett_mip6_opt_ipv4coa;
static int ett_pmip6_opt_grek;
static int ett_pmip6_opt_mhipv6ap;
static int ett_pmip6_opt_bi;
static int ett_mip6_opt_ipv4hareq;
static int ett_mip6_opt_ipv4harep;
static int ett_mip6_opt_ipv4dra;
static int ett_mip6_opt_ipv4dsm;
static int ett_mip6_opt_cr;
static int ett_mip6_opt_lmaa;
static int ett_mip6_opt_recap;
static int ett_mip6_opt_redir;
static int ett_mip6_opt_load_inf;
static int ett_mip6_opt_alt_ip4;
static int ett_mip6_opt_mng;
static int ett_mip6_opt_mag_ipv6;
static int ett_mip6_opt_acc_net_id;
static int ett_mip6_sub_opt_acc_net_id;
static int ett_mip6_opt_dmnp;

static expert_field ei_mip6_ie_not_dissected;
static expert_field ei_mip6_ani_type_not_dissected;
static expert_field ei_mip6_opt_len_invalid;
static expert_field ei_mip6_vsm_data_not_dissected;
static expert_field ei_mip6_bogus_header_length;

static dissector_table_t mip6_option_table;

/* Functions to dissect the mobility headers */
static int
dissect_mip6_brr(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo _U_)
{
    proto_tree_add_item(mip6_tree, hf_mip6_binding_refresh_request, tvb, MIP6_DATA_OFF, MIP6_BRR_LEN, ENC_NA);

    return MIP6_DATA_OFF + MIP6_BRR_LEN;
}

static int
dissect_mip6_hoti(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo _U_)
{
    if (mip6_tree) {
        proto_tree *data_tree;

        data_tree = proto_tree_add_subtree(mip6_tree, tvb, MIP6_DATA_OFF,
                MIP6_HOTI_LEN, ett_mip6, NULL, "Home Test Init");

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

        data_tree = proto_tree_add_subtree(mip6_tree, tvb, MIP6_DATA_OFF,
                MIP6_COTI_LEN, ett_mip6, NULL, "Care-of Test Init");

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

        data_tree = proto_tree_add_subtree(mip6_tree, tvb, MIP6_DATA_OFF,
                MIP6_HOT_LEN, ett_mip6, NULL, "Home Test");

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

        data_tree = proto_tree_add_subtree(mip6_tree, tvb, MIP6_DATA_OFF,
                MIP6_COT_LEN, ett_mip6, NULL, "Care-of Test");

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
        int         lifetime;

        data_tree = proto_tree_add_subtree(mip6_tree, tvb, MIP6_DATA_OFF,
                MIP6_BU_LEN, ett_mip6, NULL, "Binding Update");

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

        if ((tvb_get_uint8(tvb, MIP6_BU_FLAGS_OFF) & 0x0004 ) == 0x0004)
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
        int         lifetime;

        data_tree = proto_tree_add_subtree(mip6_tree, tvb, MIP6_DATA_OFF,
                MIP6_BA_LEN, ett_mip6, NULL, "Binding Acknowledgement");

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
        if ((tvb_get_uint8(tvb, MIP6_BA_FLAGS_OFF) & 0x0040 ) == 0x0040)
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

        data_tree = proto_tree_add_subtree(mip6_tree, tvb, MIP6_DATA_OFF,
                MIP6_BE_LEN, ett_mip6, NULL, "Binding Error");

        proto_tree_add_item(data_tree, hf_mip6_be_status, tvb,
                MIP6_BE_STATUS_OFF, MIP6_BE_STATUS_LEN, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_mip6_be_haddr, tvb,
                MIP6_BE_HOA_OFF, MIP6_BE_HOA_LEN, ENC_NA);
    }

    return MIP6_DATA_OFF + MIP6_BE_LEN;
}

/* Home Agent Switch Message */
/*
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                      |# of Addresses |   Reserved    |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      +                                                               +
      .                                                               .
      .                      Home Agent Addresses                     .
      .                                                               .
      +                                                               +
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      +                                                               +
      .                                                               .
      .                        Mobility Options                       .
      .                                                               .
      +                                                               +
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

static int
dissect_mip6_has(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo _U_)
{
    unsigned num_addrs, len;

    num_addrs = tvb_get_uint8(tvb, MIP6_DATA_OFF);
    len = 2 + num_addrs * 16;

    if (mip6_tree) {
        proto_tree *data_tree;
        int off;
        unsigned i;

        data_tree = proto_tree_add_subtree(mip6_tree, tvb, MIP6_DATA_OFF,
                len, ett_mip6, NULL, "Home Agent Switch");

        proto_tree_add_item(data_tree, hf_mip6_has_num_addrs, tvb,
                MIP6_DATA_OFF, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(data_tree, hf_mip6_has_reserved, tvb,
                MIP6_DATA_OFF + 1, 1, ENC_BIG_ENDIAN);

        for (i = 0, off = MIP6_DATA_OFF + 2; i < num_addrs; i++, off += 16) {
            proto_tree_add_item(data_tree, hf_mip6_has_address, tvb, off, 16, ENC_NA);
        }
    }

    return len;
}

static int
dissect_mip6_hb(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo _U_)
{
    if (mip6_tree) {
        proto_tree *data_tree;

        data_tree = proto_tree_add_subtree(mip6_tree, tvb, MIP6_DATA_OFF,
                MIP6_HB_LEN, ett_mip6, NULL, "Heartbeat");

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

        data_tree = proto_tree_add_subtree(mip6_tree, tvb, MIP6_DATA_OFF, 4, ett_mip6, NULL, "Handover Initiate");

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

        data_tree = proto_tree_add_subtree(mip6_tree, tvb, MIP6_DATA_OFF, 4, ett_mip6, NULL, "Handover Acknowledge ");

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
    unsigned hdr_len, data_len;

    hdr_len = (tvb_get_uint8(tvb, MIP6_HLEN_OFF) + 1) * 8;
    data_len = hdr_len - MIP6_DATA_OFF;

    proto_tree_add_item(mip6_tree, hf_mip6_unknown_type_data, tvb, MIP6_DATA_OFF, data_len, ENC_NA);

    return hdr_len;
}

static int
dissect_fmip6_fbu(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo _U_)
{
    if (mip6_tree) {
        proto_tree *data_tree;
        int lifetime;

        data_tree = proto_tree_add_subtree(mip6_tree, tvb, MIP6_DATA_OFF,
                MIP6_BU_LEN, ett_mip6, NULL, "Fast Binding Update");

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
        int         lifetime;

        data_tree = proto_tree_add_subtree(mip6_tree, tvb, MIP6_DATA_OFF,
                FMIP6_FBACK_LEN, ett_mip6, NULL, "Fast Binding Acknowledgement");

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
    proto_tree_add_item(mip6_tree, hf_mip6_fast_neighbor_advertisement, tvb, MIP6_DATA_OFF, FMIP6_FNA_LEN, ENC_NA);

    return MIP6_DATA_OFF + FMIP6_FNA_LEN;
}

/* PMIP Binding Revocation Indication / Acknowledge */
static int
dissect_pmip6_bri(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo)
{
#define INDICATION  1
#define ACKNOWLEDGE 2

    proto_tree *field_tree;
    uint8_t     br_type;

    br_type = tvb_get_uint8(tvb, PMIP6_BRI_BRTYPE_OFF);

    /* Branch between BR Indication and BR Acknowledge */
    if ( br_type == INDICATION )
    {
        col_append_str(pinfo->cinfo, COL_INFO, " Indication");

        if (mip6_tree)
        {
            field_tree = proto_tree_add_subtree(mip6_tree, tvb, MIP6_DATA_OFF,
                PMIP6_BRI_LEN, ett_mip6, NULL, "Binding Revocation Indication");

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
            field_tree = proto_tree_add_subtree(mip6_tree, tvb, MIP6_DATA_OFF,
                PMIP6_BRI_LEN, ett_mip6, NULL, "Binding Revocation Acknowledge");

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

/*

    10.1. Localized Routing Initiation (LRI)

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                    |           Sequence #          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Reserved              |           Lifetime            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    .                                                               .
    .                        Mobility options                       .
    .                                                               .
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

static int
dissect_pmip6_lri(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo _U_, int offset)
{
    proto_tree_add_item(mip6_tree, hf_pmip6_lri_sequence, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(mip6_tree, hf_pmip6_lri_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(mip6_tree, hf_pmip6_lri_lifetime, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

/*

    10.2. Localized Routing Acknowledgment (LRA)

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                    |           Sequence #          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |U|  Reserved   |   Status      |           Lifetime            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    .                                                               .
    .                        Mobility options                       .
    .                                                               .
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

static int
dissect_pmip6_lra(tvbuff_t *tvb, proto_tree *mip6_tree, packet_info *pinfo _U_, int offset)
{
    proto_tree_add_item(mip6_tree, hf_pmip6_lra_sequence, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(mip6_tree, hf_pmip6_lra_u, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(mip6_tree, hf_pmip6_lra_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(mip6_tree, hf_pmip6_lra_status, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(mip6_tree, hf_pmip6_lra_lifetime, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
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
    uint8_t sub_type, m_flag;
    tvbuff_t *next_tvb;
    char *mei_str;
    char *digit_str;
    char *mcc_mnc_str;
    char *imsi_str;

    /* offset points to the sub type */
    sub_type = tvb_get_uint8(tvb,offset);
    proto_tree_add_item(tree, hf_mip6_vsm_subtype_3gpp, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(hdr_item, " %s", val_to_str_ext_const(sub_type, &mip6_vsm_subtype_3gpp_value_ext, "<unknown>"));
    offset++;
    m_flag = tvb_get_uint8(tvb,offset) & 0x01;
    proto_tree_add_item(tree, hf_mip6_opt_3gpp_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mip6_opt_3gpp_flag_m, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* set len to the length of the data section */
    len = len - 2;

    if(m_flag){
        proto_tree_add_expert_format(tree, pinfo, &ei_mip6_vsm_data_not_dissected, tvb, offset, len, "Data fragment, handling not implemented yet");
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
        pinfo->link_dir = P2P_DIR_DL;
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
        dissect_gtpv2_fq_csid(next_tvb, pinfo, tree, hdr_item, len, 0, 0, NULL);
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
        dissect_gtpv2_selec_mode(next_tvb, pinfo, tree, hdr_item, len, 0, 0, NULL);
        break;
    /*  9, I-WLAN Mobility Access Point Name (APN) */
    /* 10, Charging Characteristics */
    case 10:
        proto_tree_add_item(tree, hf_mip6_opt_3gpp_charging_characteristic, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    /* 11, Mobile Equipment Identity (MEI) */
    case 11:
        proto_tree_add_item_ret_display_string(tree, hf_mip6_opt_3gpp_mei, tvb, offset, len, ENC_BCD_DIGITS_0_9|ENC_LITTLE_ENDIAN, pinfo->pool, &mei_str);
        proto_item_append_text(hdr_item, " %s", mei_str);
        break;
    /* 12, MSISDN */
    case 12:
        dissect_e164_cc(tvb, tree, offset, E164_ENC_BCD);
        proto_tree_add_item_ret_display_string(tree, hf_mip6_opt_3gpp_msisdn, tvb, offset, len, ENC_BCD_DIGITS_0_9|ENC_LITTLE_ENDIAN, pinfo->pool, &digit_str);
        proto_item_append_text(hdr_item, " %s", digit_str);
        break;
    /* 13, Serving Network */
    case 13:
        mcc_mnc_str = dissect_e212_mcc_mnc_wmem_packet_str(tvb, pinfo, tree, offset, E212_NONE, true);
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
        proto_tree_add_item_ret_display_string(tree, hf_mip6_opt_3gpp_imsi, tvb, offset, len, ENC_BCD_DIGITS_0_9|ENC_LITTLE_ENDIAN, pinfo->pool, &imsi_str);
        proto_item_append_text(hdr_item," %s", imsi_str);
        break;
    /* 17, PDN Connection ID */
    case 17:
         proto_tree_add_item(tree, hf_mip6_opt_3gpp_pdn_conn_id, tvb, offset, 1, ENC_BIG_ENDIAN);
         break;
    /* 18, PGW Back-Off Time */
    case 18:
        next_tvb = tvb_new_subset_length(tvb, offset, len);
        dissect_gtpv2_epc_timer(next_tvb, pinfo, tree, hdr_item, len, 0, 0, NULL);
        break;
    /* 19, Signalling Priority Indication */
    case 19:
         proto_tree_add_item(tree, hf_mip6_opt_3gpp_lapi, tvb, offset, 1, ENC_BIG_ENDIAN);
         break;
    /* 20, Additional Protocol Configuration Options
     *     12.1.1.19 Additional Protocol Configuration Options
     *     The Additional Protocol Configuration Options IE contains additional 3GPP protocol configuration options
     *     information. The IE is in the same format as the PCO IE specified in 3GPP TS 24.008 [16] subclause 10.5.6.3, starting
     *     with octet 3.
     */
    default:
        proto_tree_add_expert(tree, pinfo, &ei_mip6_vsm_data_not_dissected, tvb, offset, len);
        break;
    }

    return len;
}

static proto_tree*
mip6_fixed_option_header(proto_tree* tree, packet_info *pinfo, tvbuff_t *tvb, int proto, int ett, proto_item** ti, unsigned len, unsigned optlen)
{
    proto_tree *field_tree;
    proto_item *tf;

    *ti = proto_tree_add_item(tree, proto, tvb, 0, -1, ENC_NA);
    field_tree = proto_item_add_subtree(*ti, ett);

    tf = proto_tree_add_item(field_tree, hf_mip6_opt_len, tvb, 1, 1, ENC_NA);

    if (len != optlen) {
        /* Bogus - option length isn't what it's supposed to be for this option. */
        expert_add_info_format(pinfo, tf, &ei_mip6_opt_len_invalid,
                            "%s (with option length = %u byte%s; should be %u)",
                            proto_get_protocol_short_name(find_protocol_by_id(proto)),
                            len, plurality(len, "", "s"), optlen);
    }

    return field_tree;
}

static proto_tree*
mip6_var_option_header(proto_tree* tree, packet_info *pinfo, tvbuff_t *tvb, int proto, int ett, proto_item** ti, unsigned len, unsigned optlen)
{
    proto_tree *field_tree;
    proto_item *tf;

    *ti = proto_tree_add_item(tree, proto, tvb, 0, -1, ENC_NA);
    field_tree = proto_item_add_subtree(*ti, ett);

    tf = proto_tree_add_item(field_tree, hf_mip6_opt_len, tvb, 1, 1, ENC_NA);
    if (len < optlen)
        expert_add_info_format(pinfo, tf, &ei_mip6_opt_len_invalid,
            "%s (with option length = %u byte%s; should be >= %u)", proto_get_protocol_short_name(find_protocol_by_id(proto)),
            len, plurality(len, "", "s"), optlen);

    return field_tree;
}



/* 1 PadN [RFC3775] */
static int
dissect_mip6_opt_padn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;

    opt_tree = mip6_var_option_header(tree, pinfo, tvb, proto_mip6_option_padn, ett_mip6_opt_padn, &ti, option_len, 0);

    if (option_len > 0) {
        proto_tree_add_item(opt_tree, hf_mip6_opt_padn, tvb, offset, option_len, ENC_NA);
    }

    return tvb_captured_length(tvb);
}

/* 2 Binding Refresh Advice */
static int
dissect_mip6_opt_bra(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_ )
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;
    int ri;

    opt_tree = mip6_fixed_option_header(tree, pinfo, tvb, proto_mip6_option_bra, ett_mip6_opt_bra, &ti, option_len, MIP6_BRA_LEN);

    ri = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint_format_value(opt_tree, hf_mip6_bra_interval, tvb,
            offset, 2,
            ri, "%d (%ld seconds)",
            ri, (long)ri * 4);

    return tvb_captured_length(tvb);
}

/*3  Alternate Care-of Address */
static int
dissect_mip6_opt_acoa(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_ )
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;

    opt_tree = mip6_fixed_option_header(tree, pinfo, tvb, proto_mip6_option_acoa, ett_mip6_opt_acoa, &ti, option_len, MIP6_ACOA_LEN);

    proto_tree_add_item(opt_tree, hf_mip6_acoa_acoa, tvb,
        offset, MIP6_ACOA_ACOA_LEN, ENC_NA);

    return tvb_captured_length(tvb);
}

/* 4 Nonce Indices */
static int
dissect_mip6_opt_ni(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_ )
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;

    opt_tree = mip6_fixed_option_header(tree, pinfo, tvb, proto_mip6_option_ni, ett_mip6_opt_ni, &ti, option_len, MIP6_NI_LEN);

    proto_tree_add_item(opt_tree, hf_mip6_ni_hni, tvb, offset, MIP6_NI_HNI_LEN, ENC_BIG_ENDIAN);
    offset += MIP6_NI_HNI_LEN;
    proto_tree_add_item(opt_tree, hf_mip6_ni_cni, tvb, offset, MIP6_NI_CNI_LEN, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

/* 5 Authorization Data */
static int
dissect_mip6_opt_bad(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_ )
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;

    opt_tree = mip6_var_option_header(tree, pinfo, tvb, proto_mip6_option_bad_auth, ett_mip6_opt_bad, &ti, option_len, 0);

    proto_tree_add_item(opt_tree, hf_mip6_bad_auth, tvb, offset, option_len, ENC_NA);

    return tvb_captured_length(tvb);
}

static int
dissect_mip6_network_prefix_option(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int proto, int ett, int optlen)
{
    proto_tree* field_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 3;
    uint32_t prefix_len;

    field_tree = mip6_fixed_option_header(tree, pinfo, tvb, proto, ett, &ti, option_len, optlen);

    proto_tree_add_item_ret_uint(field_tree, hf_mip6_nemo_mnp_pfl, tvb,
            offset, 1, ENC_BIG_ENDIAN, &prefix_len);

    offset++;
    proto_tree_add_item(field_tree, hf_mip6_nemo_mnp_mnp, tvb, offset, MIP6_NEMO_MNP_MNP_LEN, ENC_NA);
    proto_item_append_text(ti, ": %s/%u", tvb_ip6_to_str(pinfo->pool, tvb, offset), prefix_len);

    return tvb_captured_length(tvb);
}

/* 6 Mobile Network Prefix Option */
static int
dissect_mip6_nemo_opt_mnp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    return dissect_mip6_network_prefix_option(tvb, pinfo, tree, proto_mip6_option_mnp, ett_mip6_nemo_opt_mnp, MIP6_NEMO_MNP_LEN);
}

/* 7 Mobility Header Link-Layer Address option [RFC5568] */
static int
dissect_fmip6_opt_lla(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;

    opt_tree = mip6_var_option_header(tree, pinfo, tvb, proto_mip6_option_mhlla, ett_fmip6_opt_lla, &ti, option_len, FMIP6_LLA_MINLEN);

    proto_tree_add_item(opt_tree, hf_fmip6_lla_optcode, tvb,
            offset, FMIP6_LLA_OPTCODE_LEN, ENC_BIG_ENDIAN);
    offset += FMIP6_LLA_OPTCODE_LEN;

    if (option_len > FMIP6_LLA_OPTCODE_LEN) {
        proto_tree_add_item(opt_tree, hf_fmip6_lla, tvb, offset, option_len-FMIP6_LLA_OPTCODE_LEN, ENC_NA);
    }

    return tvb_captured_length(tvb);
}

/* 8 MN-ID-OPTION-TYPE RFC4283 MN-ID
   https://tools.ietf.org/html/rfc4283

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                    |  Option Type  | Option Length |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Subtype      |          Identifier ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :
    Option Length:

    8-bit unsigned integer, representing the length in octets of
    the Subtype and Identifier fields.

*/
static int
dissect_mip6_opt_mnid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;
    const uint8_t *str;

    opt_tree = mip6_var_option_header(tree, pinfo, tvb, proto_mip6_option_mnid, ett_mip6_opt_mnid, &ti, option_len, MIP6_MNID_MINLEN);

    proto_tree_add_item(opt_tree, hf_mip6_mnid_subtype, tvb,
            offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if (option_len - offset > 0) {
        proto_tree_add_item_ret_string(opt_tree, hf_mip6_mnid_identifier, tvb, offset, option_len - 1, ENC_UTF_8|ENC_NA, pinfo->pool, &str);
        proto_item_append_text(ti, ": %s", str);
    }

    return tvb_captured_length(tvb);
}

/*  9 AUTH-OPTION-TYPE
    https://tools.ietf.org/html/rfc4285

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
static int
dissect_mip6_opt_auth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;

    opt_tree = mip6_var_option_header(tree, pinfo, tvb, proto_mip6_option_auth, ett_mip6_opt_auth, &ti, option_len, MIP6_AUTH_MINLEN);

    proto_tree_add_item(opt_tree, hf_mip6_opt_auth_sub_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_auth_mobility_spi, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(opt_tree, hf_mip6_opt_auth_auth_data, tvb, offset, option_len-offset, ENC_NA);

    return tvb_captured_length(tvb);
}

/*  10 MESG-ID-OPTION-TYPE [RFC4285] */

static int
dissect_mip6_opt_mseg_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;

    opt_tree = mip6_fixed_option_header(tree, pinfo, tvb, proto_mip6_option_mseg_id, ett_mip6_opt_mesgid, &ti, option_len, MIP6_MESG_ID_LEN);

    proto_tree_add_item(opt_tree, hf_mip6_opt_mseg_id_timestamp, tvb, offset, 8, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}


/* 11 CGA Parameters Request [RFC4866]  */
/* Carries no data */
static int
dissect_mip6_opt_cgapr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int option_len = tvb_reported_length(tvb)-2;
    proto_item* ti;

    mip6_fixed_option_header(tree, pinfo, tvb, proto_mip6_option_cgapr, ett_mip6_opt_cgapr, &ti, option_len, MIP6_CGAPR_MINLEN);

    return tvb_captured_length(tvb);
}

/* 12 CGA Parameters [RFC4866]  */
static int
dissect_mip6_opt_cgar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;

    opt_tree = mip6_var_option_header(tree, pinfo, tvb, proto_mip6_option_cgar, ett_mip6_opt_cgar, &ti, option_len, MIP6_CGAR_MINLEN);

    proto_tree_add_item(opt_tree, hf_mip6_opt_cgar_cga_par, tvb, offset, option_len-2, ENC_NA);

    return tvb_captured_length(tvb);
}

/* 13 Signature [RFC4866]  */
static int
dissect_mip6_opt_sign(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;

    opt_tree = mip6_var_option_header(tree, pinfo, tvb, proto_mip6_option_sign, ett_mip6_opt_sign, &ti, option_len, MIP6_SIGN_MINLEN);

    proto_tree_add_item(opt_tree, hf_mip6_opt_sign_sign, tvb, offset, option_len-2, ENC_NA);

    return tvb_captured_length(tvb);
}

/* 14 Permanent Home Keygen Token [RFC4866]  */
static int
dissect_mip6_opt_phkt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;

    opt_tree = mip6_var_option_header(tree, pinfo, tvb, proto_mip6_option_phkt, ett_mip6_opt_phkt, &ti, option_len, MIP6_PHKT_MINLEN);

    proto_tree_add_item(opt_tree, hf_mip6_opt_phkt_phkt, tvb, offset, option_len-2, ENC_NA);

    return tvb_captured_length(tvb);
}

/* 15 Care-of Test Init [RFC4866]
 * No data in this option.
 */
static int
dissect_mip6_opt_coti(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int option_len = tvb_reported_length(tvb)-2;
    proto_item* ti;

    mip6_fixed_option_header(tree, pinfo, tvb, proto_mip6_option_coti, ett_mip6_opt_mocoti, &ti, option_len, MIP6_MOCOTI_MINLEN);

    return tvb_captured_length(tvb);
}

/* 16 Care-of Test [RFC4866]  */
static int
dissect_mip6_opt_mocot(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;

    opt_tree = mip6_fixed_option_header(tree, pinfo, tvb, proto_mip6_option_cot, ett_mip6_opt_mocot, &ti, option_len, MIP6_MOCOT_MINLEN);

    proto_tree_add_item(opt_tree, hf_mip6_opt_mocot_co_keygen_tok, tvb, offset, option_len-2, ENC_NA);

    return tvb_captured_length(tvb);
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
static int
dissect_mip6_opt_dnsu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;

    opt_tree = mip6_var_option_header(tree, pinfo, tvb, proto_mip6_option_dnsu, ett_mip6_opt_dnsu, &ti, option_len, MIP6_DNSU_MINLEN);

    proto_tree_add_item(opt_tree, hf_mip6_opt_dnsu_status, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(opt_tree, hf_mip6_opt_dnsu_flag_r, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(opt_tree, hf_mip6_opt_dnsu_mn_id, tvb, offset, option_len-2-2, ENC_NA);

    return tvb_captured_length(tvb);
}

/* 18 Experimental Mobility Option [RFC5096] */
static int
dissect_mip6_opt_em(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;

    opt_tree = mip6_var_option_header(tree, pinfo, tvb, proto_mip6_option_em, ett_mip6_opt_em, &ti, option_len, MIP6_EM_MINLEN);

    proto_tree_add_item(opt_tree, hf_mip6_opt_em_data, tvb, offset, option_len-2, ENC_NA);

    return tvb_captured_length(tvb);
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
static int
dissect_mip6_opt_vsm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;
    tvbuff_t *next_tvb;
    uint32_t vendorid;

    opt_tree = mip6_var_option_header(tree, pinfo, tvb, proto_mip6_option_vsm, ett_mip6_opt_vsm, &ti, option_len, MIP6_VSM_MINLEN);

    proto_tree_add_item_ret_uint(opt_tree, hf_mip6_vsm_vid, tvb,
            offset, MIP6_VSM_VID_LEN, ENC_BIG_ENDIAN, &vendorid);
    proto_item_append_text(ti, ": %s", enterprises_lookup(vendorid, "<unknown>"));
    offset += 4;

    next_tvb = tvb_new_subset_remaining(tvb, offset);
    if (!dissector_try_uint(mip6_vsm_dissector_table, vendorid, next_tvb, pinfo, opt_tree)){
        proto_tree_add_item(opt_tree, hf_mip6_vsm_subtype, tvb,
                offset, MIP6_VSM_SUBTYPE_LEN, ENC_BIG_ENDIAN);
        offset++;

        if (option_len-offset > 0){
            proto_tree_add_item(opt_tree, hf_mip6_vsm_data, tvb, offset, option_len-offset, ENC_NA);
        }
    }

    return tvb_captured_length(tvb);
}

/* 20 Service Selection Mobility Option [RFC5149]  */

static int
dissect_mip6_opt_ssm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;
    uint8_t *apn = NULL;
    int     name_len;

    opt_tree = mip6_var_option_header(tree, pinfo, tvb, proto_mip6_option_ssm, ett_mip6_opt_ssm, &ti, option_len, MIP6_SSM_MINLEN);
    /* RFC 5149 3. Service Selection Mobility Option
     * Identifier: A variable-length encoded service identifier string
     * used to identify the requested service.  The identifier string
     * length is between 1 and 255 octets.  This specification allows
     * international identifier strings that are based on the use of
     * Unicode characters, encoded as UTF-8, and formatted using
     * Normalization Form KC (NFKC).
     */

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

    if (option_len > 0) {
        name_len = tvb_get_uint8(tvb, offset);

        /* As can be seen above, RFC 5149 "allows" the use of UTF-8 encoded
         * strings, but the 3GPP chose to encode as other APN fields,
         * similar to RFC 1035 DNS labels (but without pointer compression).
         * As a heuristic, if the first byte is less than 0x20, interpret
         * it as a length (rather than a control code) and use APN encoding,
         * otherwise interpret as a string.
         */
        if (name_len < 0x20) {
            apn = tvb_get_string_enc(pinfo->pool, tvb, offset, option_len, ENC_APN_STR);
        }
        else {
            apn = tvb_get_string_enc(pinfo->pool, tvb, offset, option_len, ENC_UTF_8);
        }
        proto_tree_add_string(opt_tree, hf_mip6_opt_ss_identifier, tvb, offset, option_len, apn);
    }
    if(apn){
        proto_item_append_text(ti, ": %s", apn);
    }
    return tvb_captured_length(tvb);
}

/* 21 Binding Authorization Data for FMIPv6 (BADF) [RFC5568]  */

static int
dissect_mip6_opt_badff(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;

    opt_tree = mip6_var_option_header(tree, pinfo, tvb, proto_mip6_option_badff, ett_mip6_opt_badff, &ti, option_len, MIP6_BADFF_MINLEN);

    proto_tree_add_item(opt_tree, hf_mip6_opt_badff_spi, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(opt_tree, hf_mip6_opt_badff_auth, tvb, offset, option_len-offset, ENC_NA);

    return tvb_captured_length(tvb);
}

/* 22 Home Network Prefix Option [RFC5213]   */
static int
dissect_mip6_opt_hnp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    return dissect_mip6_network_prefix_option(tvb, pinfo, tree, proto_mip6_option_hnp, ett_pmip6_opt_hnp, MIP6_NEMO_MNP_LEN);
}

/* 23 Handoff Indicator Option [RFC5213]   */
/*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Type     |   Length      |  Reserved (R) |       HI      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
static int
dissect_pmip6_opt_hi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;
    uint32_t hi;

    opt_tree = mip6_fixed_option_header(tree, pinfo, tvb, proto_mip6_option_hi, ett_pmip6_opt_hi, &ti, option_len, PMIP6_HI_LEN);

    proto_tree_add_item(opt_tree, hf_pmip6_hi_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item_ret_uint(opt_tree, hf_pmip6_hi_hi, tvb,
            offset, PMIP6_HI_HI_LEN, ENC_BIG_ENDIAN, &hi);

    proto_item_append_text(ti, ": %s", val_to_str_const(hi, pmip6_hi_opttype_value, "<unknown>"));

    return tvb_captured_length(tvb);
}

/* 24 Access Technology Type Option [RFC5213]  */
/*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Type     |   Length      |  Reserved (R) |      ATT      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
static int
dissect_pmip6_opt_att(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;
    uint32_t att;

    opt_tree = mip6_fixed_option_header(tree, pinfo, tvb, proto_mip6_option_att, ett_pmip6_opt_att, &ti, option_len, PMIP6_ATT_LEN);

    proto_tree_add_item(opt_tree, hf_pmip6_att_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    att = tvb_get_uint8(tvb,offset);
    proto_tree_add_item_ret_uint(opt_tree, hf_pmip6_att_att, tvb,
            offset, PMIP6_ATT_ATT_LEN, ENC_BIG_ENDIAN, &att);
    proto_item_append_text(ti, ": %s", val_to_str_ext_const(att, &pmip6_att_att_value_ext, "<unknown>"));

    return tvb_captured_length(tvb);
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
static int
dissect_pmip6_opt_mnlli(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;

    opt_tree = mip6_var_option_header(tree, pinfo, tvb, proto_mip6_option_mnlli, ett_pmip6_opt_mnlli, &ti, option_len, PMIP6_MNLLI_MIN_LEN);

    proto_tree_add_item(opt_tree, hf_mip6_opt_mnlli_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(opt_tree, hf_mip6_opt_mnlli_lli, tvb, offset, option_len-2, ENC_NA);

    return tvb_captured_length(tvb);
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
static int
dissect_pmip6_opt_lla(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
    proto_tree* field_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;

    field_tree = mip6_fixed_option_header(tree, pinfo, tvb, proto_mip6_option_lla, ett_pmip6_opt_lla, &ti, option_len, PMIP6_LLA_LEN);

    proto_tree_add_item(field_tree, hf_pmip6_opt_lila_lla, tvb, offset, 16, ENC_NA);

    return tvb_captured_length(tvb);
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
static int
dissect_pmip6_opt_ts(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;
    char *str;

    opt_tree = mip6_fixed_option_header(tree, pinfo, tvb, proto_mip6_option_ts, ett_pmip6_opt_ts, &ti, option_len, PMIP6_TS_LEN);

    proto_tree_add_item_ret_time_string(opt_tree, hf_pmip6_timestamp, tvb, offset, 8, ENC_TIME_MIP6|ENC_BIG_ENDIAN, pinfo->pool, &str);
    proto_item_append_text(ti, ": %s", str);

    return tvb_captured_length(tvb);
}

 /* 28 Restart Counter [RFC5847] */
static int
dissect_pmip6_opt_rc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;

    opt_tree = mip6_fixed_option_header(tree, pinfo, tvb, proto_mip6_option_rc, ett_pmip6_opt_rc, &ti, option_len, PMIP6_RC_LEN);

    proto_tree_add_item(opt_tree, hf_pmip6_rc, tvb,
            offset, PMIP6_RC_RC_LEN, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

/* 29 IPv4 Home Address [RFC5555]  */
static int
dissect_pmip6_opt_ipv4ha(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
    proto_tree* field_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;

    field_tree = mip6_fixed_option_header(tree, pinfo, tvb, proto_mip6_option_ipv4ha, ett_mip6_opt_ipv4ha, &ti, option_len, MIP6_IPV4HA_LEN);

    proto_tree_add_item(field_tree, hf_mip6_ipv4ha_preflen, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree, hf_mip6_ipv4ha_p_flag, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(field_tree, hf_mip6_ipv4ha_ha, tvb,
            offset, MIP6_IPV4HA_HA_LEN, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

/* 30 IPv4 Address Acknowledgement [RFC5555] */
static int
dissect_pmip6_opt_ipv4aa(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
    proto_tree* field_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;

    field_tree = mip6_fixed_option_header(tree, pinfo, tvb, proto_mip6_option_ipv4aa, ett_mip6_opt_ipv4aa, &ti, option_len, MIP6_IPV4AA_LEN);

    proto_tree_add_item(field_tree, hf_mip6_ipv4aa_status, tvb,
            offset, MIP6_IPV4AA_STATUS_LEN, ENC_BIG_ENDIAN);
    offset += MIP6_IPV4AA_STATUS_LEN;

    proto_tree_add_item(field_tree, hf_mip6_ipv4ha_preflen, tvb,
            offset, MIP6_IPV4AA_PREFIXL_LEN, ENC_BIG_ENDIAN);
    offset += MIP6_IPV4AA_PREFIXL_LEN;

    proto_tree_add_item(field_tree, hf_mip6_ipv4ha_ha, tvb,
            offset, MIP6_IPV4AA_HA_LEN, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
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
static int
dissect_pmip6_opt_natd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;
    proto_item *item;
    uint32_t    refresh_time;

    opt_tree = mip6_fixed_option_header(tree, pinfo, tvb, proto_mip6_option_natd, ett_mip6_opt_natd, &ti, option_len, MIP6_NATD_LEN);

    proto_tree_add_item(opt_tree, hf_mip6_opt_natd_f_flag, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(opt_tree, hf_mip6_opt_natd_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    item = proto_tree_add_item_ret_uint(opt_tree, hf_mip6_opt_natd_refresh_t, tvb, offset, 4, ENC_BIG_ENDIAN, &refresh_time);
    if (refresh_time == 0) {
        proto_item_append_text(item, " (Ignore)");
    }
    if (refresh_time == 0xffffffff) {
        proto_item_append_text(item, " (keepalives are not needed, no NAT detected)");
    }

    return tvb_captured_length(tvb);
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

static int
dissect_pmip6_opt_ipv4coa(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;

    opt_tree = mip6_fixed_option_header(tree, pinfo, tvb, proto_mip6_option_ipv4coa, ett_mip6_opt_ipv4coa, &ti, option_len, MIP6_IPV4COA_LEN);

    proto_tree_add_item(opt_tree, hf_mip6_opt_ipv4coa_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(opt_tree, hf_mip6_opt_ipv4coa_addr, tvb, offset, 4, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
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
static int
dissect_pmip6_opt_grek(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;
    uint32_t key;

    opt_tree = mip6_var_option_header(tree, pinfo, tvb, proto_mip6_option_grek, ett_pmip6_opt_grek, &ti, option_len, PMIP6_GREK_MIN_LEN);

    proto_tree_add_item(opt_tree, hf_mip6_ipv4dra_reserved, tvb,
            offset, 2, ENC_BIG_ENDIAN);

    if (option_len == 6) {
        offset += 2;
        proto_tree_add_item_ret_uint(opt_tree, hf_pmip6_gre_key, tvb,
                            offset, PMIP6_GREK_ID_LEN, ENC_BIG_ENDIAN, &key);
        proto_item_append_text(ti, ": %u", key);
    }

    return tvb_captured_length(tvb);
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

static int
dissect_pmip6_opt_mhipv6ap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;
    uint8_t prefix_l;

    opt_tree = mip6_fixed_option_header(tree, pinfo, tvb, proto_mip6_option_mhipv6ap, ett_pmip6_opt_mhipv6ap, &ti, option_len, MIP6_MHIPV6AP_LEN);

    proto_tree_add_item(opt_tree, hf_mip6_opt_mhipv6ap_opt_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    prefix_l = tvb_get_uint8(tvb,offset);
    proto_tree_add_item(opt_tree, hf_mip6_opt_mhipv6ap_prefix_l, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(opt_tree, hf_mip6_opt_mhipv6ap_ipv6_address, tvb, offset, 16, ENC_NA);
    ti = proto_tree_add_string(opt_tree, hf_mip6_opt_mhipv6ap_ipv6_address_prefix, tvb, offset -1, 16+1, tvb_ip6_to_str(pinfo->pool, tvb, offset));
    proto_item_append_text(ti, "/%u", prefix_l);
    proto_item_set_generated(ti);

    return tvb_captured_length(tvb);
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
static int
dissect_pmip6_opt_bi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;

    opt_tree = mip6_var_option_header(tree, pinfo, tvb, proto_mip6_option_bi, ett_pmip6_opt_bi, &ti, option_len, MIP6_BI_MIN_LEN);

    proto_tree_add_item(opt_tree, hf_mip6_opt_bi_bid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(opt_tree, hf_mip6_opt_bi_status, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(opt_tree, hf_mip6_bi_h_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if (option_len == 8) {
        /* IPv4 addr */
        proto_tree_add_item(opt_tree, hf_mip6_bi_coa_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else if (option_len == 20) {
        /* Ipv6 Addr */
        proto_tree_add_item(opt_tree, hf_mip6_bi_coa_ipv6, tvb, offset, 16, ENC_NA);
    }

    return tvb_captured_length(tvb);
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
static int
dissect_pmip6_opt_ipv4hareq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;
    proto_item *item;
    uint32_t    dword;

    opt_tree = mip6_fixed_option_header(tree, pinfo, tvb, proto_mip6_option_ipv4hareq, ett_mip6_opt_ipv4hareq, &ti, option_len, MIP6_IPV4HAREQ_LEN);

    proto_tree_add_item(opt_tree, hf_mip6_ipv4ha_preflen, tvb,
            offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Reserved */
    proto_tree_add_item(opt_tree, hf_mip6_ipv4ha_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Field is an IPv4 address, so can't be retrieved by proto_tree_add_item_ret_uint */
    dword = tvb_get_ntohl(tvb,offset);
    item = proto_tree_add_item(opt_tree, hf_mip6_ipv4ha_ha, tvb,
            offset, MIP6_IPV4HAREQ_HA_LEN, ENC_BIG_ENDIAN);
    if (dword == 0) {
        proto_item_append_text(item, " - Request that the local mobility anchor perform the address allocation");
    }
    proto_item_append_text(ti, ": %s", tvb_ip_to_str(pinfo->pool, tvb,offset));

    return tvb_captured_length(tvb);
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
static int
dissect_pmip6_opt_ipv4harep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;
    uint32_t status;

    opt_tree = mip6_fixed_option_header(tree, pinfo, tvb, proto_mip6_option_ipv4harep, ett_mip6_opt_ipv4harep, &ti, option_len, MIP6_IPV4HAREP_LEN);

    proto_tree_add_item_ret_uint(opt_tree, hf_mip6_ipv4aa_status, tvb,
            offset, MIP6_IPV4HAREP_STATUS_LEN, ENC_BIG_ENDIAN, &status);
    proto_item_append_text(ti, ": %s ", val_to_str_const(status, pmip6_ipv4aa_status_values, "<unknown>"));
    offset++;

    proto_tree_add_item(opt_tree, hf_mip6_ipv4ha_preflen, tvb,
            offset, MIP6_IPV4HAREP_PREFIXL_LEN, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(opt_tree, hf_mip6_ipv4ha_ha, tvb,
            offset, MIP6_IPV4HAREP_HA_LEN, ENC_BIG_ENDIAN);

    proto_item_append_text(ti, ": %s", tvb_ip_to_str(pinfo->pool, tvb,offset));

    return tvb_captured_length(tvb);
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
static int
dissect_pmip6_opt_ipv4dra(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;

    opt_tree = mip6_fixed_option_header(tree, pinfo, tvb, proto_mip6_option_ipv4dra, ett_mip6_opt_ipv4dra, &ti, option_len, MIP6_IPV4DRA_LEN);

    proto_tree_add_item(opt_tree, hf_mip6_ipv4dra_reserved, tvb,
            offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(opt_tree, hf_mip6_ipv4dra_dra, tvb,
            offset, MIP6_IPV4DRA_DRA_LEN, ENC_BIG_ENDIAN);

    proto_item_append_text(ti, ": %s", tvb_ip_to_str(pinfo->pool, tvb,offset));

    return tvb_captured_length(tvb);
}

/* 39 IPv4 DHCP Support Mode [RFC5844] */
/*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Type     |   Length      |    Reserved (R)             |S|
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

static int
dissect_pmip6_opt_ipv4dsm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;

    opt_tree = mip6_fixed_option_header(tree, pinfo, tvb, proto_mip6_option_ipv4dsm, ett_mip6_opt_ipv4dsm, &ti, option_len, MIP6_IPV4DSM_LEN);

    proto_tree_add_item(opt_tree, hf_mip6_ipv4dsm_reserved, tvb,
            offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(opt_tree, hf_mip6_ipv4dsm_s_flag, tvb, offset, 2, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
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

static int
dissect_pmip6_opt_cr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;
    uint8_t req_type, req_length;
    uint32_t vendorid;

    opt_tree = mip6_var_option_header(tree, pinfo, tvb, proto_mip6_option_cr, ett_mip6_opt_cr, &ti, option_len, MIP6_CR_MIN_LEN);

    proto_tree_add_item(opt_tree, hf_mip6_cr_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    while (offset-2 < option_len) {
        req_type = tvb_get_uint8(tvb,offset);
        proto_tree_add_item(opt_tree, hf_mip6_cr_req_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        req_length = tvb_get_uint8(tvb,offset);
        proto_tree_add_item(opt_tree, hf_mip6_cr_req_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        if (req_length == 0)
            continue;

        if (req_type == MIP6_VSM) {
            /* vendor specific option */
            proto_tree_add_item_ret_uint(opt_tree, hf_mip6_vsm_vid, tvb, offset, 4, ENC_BIG_ENDIAN, &vendorid);
            if (vendorid == VENDOR_THE3GPP) {
                proto_tree_add_item(opt_tree, hf_mip6_vsm_subtype_3gpp, tvb, offset+4, 1, ENC_BIG_ENDIAN);
            }
            else {
                proto_tree_add_item(opt_tree, hf_mip6_vsm_subtype, tvb, offset+4, 1, ENC_BIG_ENDIAN);
            }
        }
        else {
            proto_tree_add_item(opt_tree, hf_mip6_vsm_req_data, tvb, offset, req_length, ENC_NA);
        }
        offset += req_length;
    }

    return tvb_captured_length(tvb);
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
static int
dissect_pmip6_opt_lmaa(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;
    uint8_t opt_code;

    opt_tree = mip6_var_option_header(tree, pinfo, tvb, proto_mip6_option_lmaa, ett_mip6_opt_lmaa, &ti, option_len, MIP6_LMAA_MIN_LEN);

    opt_code = tvb_get_uint8(tvb,offset);
    proto_tree_add_item(opt_tree, hf_mip6_lmaa_opt_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(opt_tree, hf_mip6_lmaa_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (opt_code == 1) {
        /* Ipv6 Addr */
        proto_tree_add_item(opt_tree, hf_mip6_lmaa_ipv6, tvb, offset, 16, ENC_NA);
        proto_item_append_text(ti, ": %s", tvb_ip6_to_str(pinfo->pool, tvb,offset));
    }else if (opt_code == 2) {
        /* IPv4 addr */
        proto_tree_add_item(opt_tree, hf_mip6_lmaa_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, ": %s", tvb_ip_to_str(pinfo->pool, tvb,offset));

    }

    return tvb_captured_length(tvb);
}

static int
dissect_pmip6_opt_recap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;

    opt_tree = mip6_fixed_option_header(tree, pinfo, tvb, proto_mip6_option_recap, ett_mip6_opt_recap, &ti, option_len, MIP6_RECAP_LEN);

    proto_tree_add_item(opt_tree, hf_mip6_opt_recap_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

static int
dissect_pmip6_opt_redir(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;
    uint16_t flag;

    opt_tree = mip6_var_option_header(tree, pinfo, tvb, proto_mip6_option_redir, ett_mip6_opt_redir, &ti, option_len, MIP6_REDIR_MIN_LEN);

    proto_tree_add_item(opt_tree, hf_mip6_opt_redir_k, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(opt_tree, hf_mip6_opt_redir_n, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(opt_tree, hf_mip6_opt_redir_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    flag = tvb_get_ntohs(tvb ,offset);
    offset += 2;

    if (flag & MIP6_REDIR_FLAG_K) {
        proto_tree_add_item(opt_tree, hf_mip6_opt_redir_addr_r2LMA_ipv6, tvb, offset, 16, ENC_NA);
        offset += 16;
    }

    if (flag & MIP6_REDIR_FLAG_N) {
        proto_tree_add_item(opt_tree, hf_mip6_opt_redir_addr_r2LMA_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        /*offset += 4;*/
    }

    return tvb_captured_length(tvb);
}

static int
dissect_pmip6_opt_load_inf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;

    opt_tree = mip6_fixed_option_header(tree, pinfo, tvb, proto_mip6_option_load_inf, ett_mip6_opt_load_inf, &ti, option_len, MIP6_LOAD_INF_LEN);

    proto_tree_add_item(opt_tree, hf_mip6_opt_load_inf_priority, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(opt_tree, hf_mip6_opt_load_inf_sessions_in_use, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(opt_tree, hf_mip6_opt_load_inf_maximum_sessions, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(opt_tree, hf_mip6_opt_load_inf_used_capacity, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(opt_tree, hf_mip6_opt_load_inf_maximum_capacity, tvb, offset, 4, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

static int
dissect_pmip6_opt_alt_ip4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;

    opt_tree = mip6_fixed_option_header(tree, pinfo, tvb, proto_mip6_option_alt_ip4, ett_mip6_opt_alt_ip4, &ti, option_len, MIP6_ALT_IP4_LEN);

    proto_tree_add_item(opt_tree, hf_mip6_opt_alt_ip4, tvb, offset, 4, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
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

static int
dissect_pmip6_opt_mng(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;
    proto_item *item;
    uint32_t    mng_id;

    opt_tree = mip6_fixed_option_header(tree, pinfo, tvb, proto_mip6_option_mng, ett_mip6_opt_mng, &ti, option_len, MIP6_MNG_LEN);

    proto_tree_add_item(opt_tree, hf_mip6_opt_mng_sub_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_mng_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    item = proto_tree_add_item_ret_uint(opt_tree, hf_mip6_opt_mng_mng_id, tvb, offset, 4, ENC_BIG_ENDIAN, &mng_id);
    if (mng_id == 1) {
        proto_item_append_text(item, " - ALL-SESSIONS");
    }

    return tvb_captured_length(tvb);
}

/*
11.1.  MAG IPv6 Address

   The MAG IPv6 address mobility option contains the IPv6 address of a
   MAG involved in localized routing.  The MAG IPv6 address option has
   an alignment requirement of 8n+4.

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Type     |   Length      |   Reserved    | Address Length|
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                                                               +
    |                                                               |
    +                       MAG IPv6 Address                        +
    |                                                               |
    +                                                               +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
static int
dissect_pmip6_opt_mag_ipv6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;

    opt_tree = mip6_fixed_option_header(tree, pinfo, tvb, proto_mip6_option_mag_ipv6, ett_mip6_opt_mag_ipv6, &ti, option_len, MIP6_MAG_IPv6_LEN);

    proto_tree_add_item(opt_tree, hf_mip6_opt_mag_ipv6_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_mag_ipv6_address_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_mag_ipv6_address, tvb, offset, 16, ENC_NA);

    return tvb_captured_length(tvb);
}

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Type     |   Length      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                  ...      ANI Sub-option(s) ...                   ~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

3.1.  Format of the Access Network Identifier Sub-Option

   The Access Network Identifier sub-options are used for carrying
   information elements related to the access network to which the
   mobile node is attached.  These sub-options can be included in the
   Access Network Identifier option defined in Section 3.  The format of
   this sub-option is as follows:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    ANI Type   | ANI Length    |         Option Data           ~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   ANI Type:  8-bit unsigned integer indicating the type of the Access
      Network Identifier sub-option.  This specification defines the
      following types:

      0 -  Reserved

      1 -  Network-Identifier sub-option

      2 -  Geo-Location sub-option

      3 -  Operator-Identifier sub-option

*/

static const value_string mmip6_opt_acc_net_id_sub_opt_vals[] = {
    {  0,    "Reserved"},
    {  1,    "Network-Identifier"},
    {  2,    "Geo-Location"},
    {  3,    "Operator-Identifier"},
    {  0,    NULL}
};

static const true_false_string mip6_opt_acc_net_id_sub_opt_e_bit_value = {
    "UTF-8",
    "Encoding is undefined"
};

static const value_string mip6_opt_acc_net_id_sub_opt_op_id_type[] = {
    {  0,    "Reserved"},
    {  1,    "Private Enterprise Number (PEN)"},
    {  2,    "Realm of the operator"},
    {  0,    NULL}
};

static float
degrees_convert_fixed_to_float(unsigned value)
{
    if (!value)
        return 0;

    /*
     * RFC 6757 section 3.1.2:
     *
     * "A 24-bit {latitude,longitude} degree value encoded as a two's
     * complement, fixed point number with 9 whole bits."
     *
     * "9 whole bits" presumably includes the sign bit; 1 sign bit
     * plus 8 more bits supports values between -256 and 255, which
     * is sufficient to cover -180 to 180.  9 bits plus a sign bit
     * would waste a bit.
     *
     * So we have 1 sign bit plus 8 bits of integral value, followed
     * by a binary point, followed by 15 bits of fractional value.
     * That means that to get the value, we treat the fixed-point
     * number as an integer and divide it by 2^15 = 32768.
     */

    /* Sign-extend to 32 bits */
    if (value & 0x800000) {
        value |= 0xFF000000;
    }

    /* Cast to a signed value, and divide by 32768; do a floating-point divide */
    return ((float)(int)value) / 32768.0f;
}

static void
degrees_base_custom(char *str, unsigned degrees)
{
    snprintf(str, ITEM_LABEL_LENGTH, "%f", degrees_convert_fixed_to_float(degrees) );
}

static int
dissect_pmip6_opt_acc_net_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* opt_tree;
    proto_item *ti;
    proto_tree *subopt_tree;
    int16_t sub_opt_len;
    uint8_t sub_opt, e_bit, net_name_len, ap_name_len;
    const uint8_t *ap_name;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;
    int offset_end = tvb_reported_length(tvb);

    opt_tree = mip6_var_option_header(tree, pinfo, tvb, proto_mip6_option_acc_net_id, ett_mip6_opt_acc_net_id, &ti, option_len, MIP6_ACC_NET_ID_MIN_LEN);

    while(offset < offset_end) {
        ti = proto_tree_add_item(opt_tree, hf_mip6_opt_acc_net_id_sub, tvb, offset, 2, ENC_NA);
        subopt_tree = proto_item_add_subtree(ti, ett_mip6_sub_opt_acc_net_id);

        proto_tree_add_item(subopt_tree, hf_mip6_opt_acc_net_id_sub_opt, tvb, offset, 1, ENC_BIG_ENDIAN);
        sub_opt = tvb_get_uint8(tvb,offset);
        offset++;

        proto_tree_add_item(subopt_tree, hf_mip6_opt_acc_net_id_sub_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
        sub_opt_len = tvb_get_uint8(tvb,offset);
        offset++;

        proto_item_append_text(ti, ": %s (t=%d,l=%d)", val_to_str(sub_opt, mmip6_opt_acc_net_id_sub_opt_vals, "Unknown ANI Type (%02d)"), sub_opt, sub_opt_len);
        proto_item_set_len(ti, sub_opt_len+2);

        switch(sub_opt){
        case 1: /* Network-Identifier */
            /*
                0                   1                   2                   3
                0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
               | ANI Type=1    |  ANI Length   |E|   Reserved  | Net-Name Len  |
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
               |                     Network Name (e.g., SSID or PLMNID)       ~
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
               | AP-Name Len   |        Access-Point Name                      ~
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            */
            e_bit = tvb_get_uint8(tvb,offset);
            proto_tree_add_item(subopt_tree, hf_mip6_opt_acc_net_id_sub_opt_e_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            net_name_len = tvb_get_uint8(tvb,offset);
            proto_tree_add_item(subopt_tree, hf_mip6_opt_acc_net_id_sub_opt_net_name_len, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            if(e_bit == 0x80){
                const uint8_t* name;
                proto_tree_add_item_ret_string(subopt_tree, hf_mip6_opt_acc_net_id_sub_opt_net_name, tvb, offset, net_name_len, ENC_BIG_ENDIAN|ENC_UTF_8, pinfo->pool, &name);
                proto_item_append_text(ti, " Network Name: %s", name);
            }else{
                proto_tree_add_item(subopt_tree, hf_mip6_opt_acc_net_id_sub_opt_net_name_data, tvb, offset, net_name_len, ENC_BIG_ENDIAN|ENC_UTF_8);
            };
            offset = offset+net_name_len;

            ap_name_len = tvb_get_uint8(tvb,offset);
            proto_tree_add_item(subopt_tree, hf_mip6_opt_acc_net_id_sub_opt_ap_name_len, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            proto_tree_add_item_ret_string(subopt_tree, hf_mip6_opt_acc_net_id_sub_opt_ap_name, tvb, offset, ap_name_len, ENC_BIG_ENDIAN|ENC_UTF_8, pinfo->pool, &ap_name);
            proto_item_append_text(ti, " AP Name: %s", ap_name);

            offset = offset+ap_name_len;
            break;

        case 2: /* Geo-Location */
            /*
                0                   1                   2                   3
                0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
               |  ANI Type=2   | ANI Length=6  |       Latitude Degrees
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                               |              Longitude Degrees                |
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            */
            proto_tree_add_item(subopt_tree, hf_mip6_opt_acc_net_id_sub_opt_geo_latitude_degrees, tvb, offset, 3, ENC_BIG_ENDIAN);
            offset +=3;

            proto_tree_add_item(subopt_tree, hf_mip6_opt_acc_net_id_sub_opt_geo_longitude_degrees, tvb, offset, 3, ENC_BIG_ENDIAN);
            offset +=3;
            break;

        case 3: /* Operator-Identifier */
            /*
                0                   1                   2                   3
                0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
               | ANI Type=3    |    ANI Length   |   Op-ID Type  |
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                        Operator-Identifier                    ~
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            */
            proto_tree_add_item(subopt_tree, hf_mip6_opt_acc_net_id_sub_opt_op_id_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(subopt_tree, hf_mip6_opt_acc_net_id_sub_opt_op_id, tvb, offset, sub_opt_len - 1, ENC_NA);
            offset = offset + sub_opt_len - 1;

            break;
        default:
            proto_tree_add_expert(subopt_tree, pinfo, &ei_mip6_ani_type_not_dissected, tvb, offset, sub_opt_len);
            offset = offset + sub_opt_len;
            break;
        }
    }

    return tvb_captured_length(tvb);
}

/* 55 Delegated Mobile Network Prefix Option [RFC7148]

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Type     |   Length      |V|  Reserved   | Prefix Length |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                                                               +
    |                                                               |
    .                                                               .
    +           IPv4 or IPv6 Delegated Mobile Network Prefix        +
    |                         (DMNP)                                |
    +                                                               +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

static int
dissect_mip6_opt_dmnp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* opt_tree;
    proto_item* ti;
    int option_len = tvb_reported_length(tvb)-2;
    int offset = 2;
    uint8_t prefix_len;

    opt_tree = mip6_var_option_header(tree, pinfo, tvb, proto_mip6_option_dmnp, ett_mip6_opt_dmnp, &ti, option_len, MIP6_DMNP_MIN_LEN);

    proto_tree_add_item(opt_tree, hf_mip6_opt_dmnp_v_flag, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(opt_tree, hf_mip6_opt_dmnp_reserved, tvb,
                        offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(opt_tree, hf_mip6_opt_dmnp_prefix_len, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    prefix_len = tvb_get_uint8(tvb, offset);

    offset++;

    switch (option_len) {
    case 6:
        /* IPv4 Prefix */
        proto_tree_add_item(opt_tree, hf_mip6_opt_dmnp_dmnp_ipv4, tvb,
                            offset, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, ": %s/%u",
                               tvb_ip_to_str(pinfo->pool, tvb, offset), prefix_len);
            break;

    case 18:
        /* IPv6 Prefix */
        proto_tree_add_item(opt_tree, hf_mip6_opt_dmnp_dmnp_ipv6, tvb,
                            offset, 16, ENC_NA);
        proto_item_append_text(ti, ": %s/%u",
                               tvb_ip6_to_str(pinfo->pool, tvb, offset), prefix_len);
        break;

    default:
        proto_tree_add_expert(opt_tree, pinfo, &ei_mip6_opt_len_invalid,
                              tvb, offset, -1);
        break;
    }

    return tvb_captured_length(tvb);
}

/* Like "dissect_ip_tcp_options()", but assumes the length of an option
 * *doesn't* include the type and length bytes.  The option parsers,
 * however, are passed a length that *does* include them.
 */
static void
dissect_mipv6_options(tvbuff_t *tvb, int offset, unsigned length,
              int eol, packet_info *pinfo, proto_tree *opt_tree)
{
    unsigned char   opt;
    const char     *name;
    unsigned        len;
    dissector_handle_t option_dissector;
    tvbuff_t       *next_tvb;
    proto_item     *ti;
    proto_tree     *unknown_tree;

    while ((int)length > 0) {
        opt = tvb_get_uint8(tvb, offset);
        --length;      /* account for type byte */

        if (opt == MIP6_PAD1) {
          /* We assume that the only option with no length is Pad1 option,
             so that we can treat unknown options as having a minimum length of 2,
             and at least be able to move on to the next option by using the length in the option. */

            proto_tree_add_item(opt_tree, proto_mip6_option_pad1, tvb, offset, 1, ENC_NA);
            offset += 1;
        } else {
            option_dissector = dissector_get_uint_handle(mip6_option_table, opt);
            if (option_dissector == NULL) {
                name = wmem_strdup_printf(pinfo->pool, "Unknown (0x%02x)", opt);
            } else {
                name = dissector_handle_get_protocol_short_name(option_dissector);
            }

            /* Option has a length. Is it in the packet? */
            if (length == 0) {
                /* Bogus - packet must at least include
                 * option code byte and length byte!
                 */
                proto_tree_add_expert_format(opt_tree, pinfo, &ei_mip6_opt_len_invalid, tvb, offset, 1,
                        "%s (length byte past end of options)", name);
                return;
            }

            len = tvb_get_uint8(tvb, offset + 1);  /* Size specified in option */
            --length;    /* account for length byte */

            if (len > length) {
                /* Bogus - option goes past the end of the header. */
                proto_tree_add_expert_format(opt_tree, pinfo, &ei_mip6_opt_len_invalid, tvb, offset, length,
                        "%s (option length = %u byte%s says option goes past end of options)",
                        name, len, plurality(len, "", "s"));
                return;
            }

            if (option_dissector == NULL) {
                unknown_tree = proto_tree_add_subtree(opt_tree, tvb, offset, len+2, ett_mip6_opt_unknown, &ti, name);
                proto_tree_add_item(unknown_tree, hf_mip6_mobility_opt, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(unknown_tree, hf_mip6_opt_len, tvb, 1, 1, ENC_NA);

                expert_add_info(pinfo, ti, &ei_mip6_ie_not_dissected);
            } else {
                next_tvb = tvb_new_subset_length(tvb, offset, len+2);
                call_dissector(option_dissector, next_tvb, pinfo, opt_tree);
            }

            length -= len;
            offset += (len + 2);
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

    opts_tree = proto_tree_add_subtree(mip6_tree, tvb, offset, len, ett_mip6, NULL, "Mobility Options");

    dissect_mipv6_options(tvb, offset, len, -1, pinfo, opts_tree);

    return len;
}

/* Function that dissects the whole MIPv6 packet */
static int
dissect_mip6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_tree *mip6_tree, *root_tree;
    uint8_t     type, pproto;
    unsigned    len, offset = 0, start_offset = offset;
    proto_item *ti, *header_item;
    tvbuff_t   *next_tvb;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MIPv6");
    col_clear(pinfo->cinfo, COL_INFO);

    len = (tvb_get_uint8(tvb, MIP6_HLEN_OFF) + 1) * 8;
    pproto = tvb_get_uint8(tvb, MIP6_PROTO_OFF);

    root_tree = p_ipv6_pinfo_select_root(pinfo, tree);
    p_ipv6_pinfo_add_len(pinfo, len);

    ti = proto_tree_add_item(root_tree, proto_mip6, tvb, 0, len, ENC_NA);
    mip6_tree = proto_item_add_subtree(ti, ett_mip6);

    /* Process header fields */
    proto_tree_add_item(mip6_tree, hf_mip6_proto, tvb,
            MIP6_PROTO_OFF, 1, ENC_BIG_ENDIAN);

    header_item = proto_tree_add_uint_format_value(mip6_tree, hf_mip6_hlen, tvb,
                MIP6_HLEN_OFF, 1,
                tvb_get_uint8(tvb, MIP6_HLEN_OFF),
                "%u (%u bytes)",
                tvb_get_uint8(tvb, MIP6_HLEN_OFF),
                len);

    proto_tree_add_item(mip6_tree, hf_mip6_mhtype, tvb,
            MIP6_TYPE_OFF, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(mip6_tree, hf_mip6_reserved, tvb,
            MIP6_RES_OFF, 1, ENC_BIG_ENDIAN);

    proto_tree_add_checksum(mip6_tree, tvb, MIP6_CSUM_OFF, hf_mip6_csum,
            -1, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);

    /* Process mobility header */
    type = tvb_get_uint8(tvb, MIP6_TYPE_OFF);
    col_add_str(pinfo->cinfo, COL_INFO, val_to_str_ext(type, &mip6_mh_types_ext, "Unknown Mobility Header (%u)"));
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
        if (len > 8) {
            proto_tree_add_item(mip6_tree, hf_mip6_opt_em_data, tvb, offset+MIP6_DATA_OFF, len-MIP6_DATA_OFF, ENC_NA);
        }
        offset = len;
        break;
    case MIP6_HAS:
        /* 12 Home Agent Switch */
        offset = dissect_mip6_has(tvb, mip6_tree, pinfo);
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
        offset = dissect_pmip6_lri(tvb, mip6_tree, pinfo, offset);
        break;
    case MIP6_LRA:
        /* 18 Localized Routing Acknowledgment */
        offset = dissect_pmip6_lra(tvb, mip6_tree, pinfo, offset);
        break;
    default:
        offset = dissect_mip6_unknown(tvb, mip6_tree, pinfo);
        break;
    }

    /* Process mobility options */
    if (offset < len) {
        if (len < (offset - start_offset)) {
            expert_add_info(pinfo, header_item, &ei_mip6_bogus_header_length);
            return offset;
        }
        len -= (offset - start_offset);
        dissect_mip6_options(tvb, mip6_tree, offset, len, pinfo);
    }

    if ((type == MIP6_FNA) && (pproto == IP_PROTO_IPV6)) {
        col_set_str(pinfo->cinfo, COL_INFO, "Fast Neighbor Advertisement[Fast Binding Update]");
        next_tvb = tvb_new_subset_remaining(tvb, len + 8);
        ipv6_dissect_next(pproto, next_tvb, pinfo, tree, (ws_ip6 *)data);
    }

    if ((type == MIP6_FBACK) && (pproto == IP_PROTO_AH)) {
        col_set_str(pinfo->cinfo, COL_INFO, "Fast Binding Acknowledgment");
        next_tvb = tvb_new_subset_remaining(tvb, len + offset);
        ipv6_dissect_next(pproto, next_tvb, pinfo, tree, (ws_ip6 *)data);
    }

    return tvb_captured_length(tvb);
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
      { "Sequence number", "mip6.fbu.seqnr",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_fmip6_fbu_a_flag,
      { "Acknowledge (A) flag", "mip6.fbu.a_flag",
        FT_BOOLEAN, 8, TFS(&fmip6_fbu_a_flag_value), 0x80,
        NULL, HFILL }
    },
    { &hf_fmip6_fbu_h_flag,
      { "Home Registration (H) flag", "mip6.fbu.h_flag",
        FT_BOOLEAN, 8, TFS(&fmip6_fbu_h_flag_value), 0x40,
        NULL, HFILL }
    },
    { &hf_fmip6_fbu_l_flag,
      { "Link-Local Compatibility (L) flag", "mip6.fbu.l_flag",
        FT_BOOLEAN, 8, TFS(&fmip6_fbu_l_flag_value), 0x20,
        "Home Registration (H) flag", HFILL }
    },
    { &hf_fmip6_fbu_k_flag,
      { "Key Management Compatibility (K) flag", "mip6.fbu.k_flag",
        FT_BOOLEAN, 8, TFS(&fmip6_fbu_k_flag_value), 0x10,
        NULL, HFILL }
    },
    { &hf_fmip6_fbu_lifetime,
      { "Lifetime", "mip6.fbu.lifetime",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_fmip6_fback_status,
      { "Status", "mip6.fback.status",
        FT_UINT8, BASE_DEC, VALS(fmip6_fback_status_value), 0,
        "Fast Binding Acknowledgement status", HFILL }
    },
    { &hf_fmip6_fback_k_flag,
      { "Key Management Compatibility (K) flag", "mip6.fback.k_flag",
        FT_BOOLEAN, 8, TFS(&fmip6_fbu_k_flag_value), 0x80,
        NULL, HFILL }
    },
    { &hf_fmip6_fback_seqnr,
      { "Sequence number", "mip6.fback.seqnr",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_fmip6_fback_lifetime,
      { "Lifetime", "mip6.fback.lifetime",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_has_num_addrs,
      { "Number of Addresses", "mip6.has.num_addrs",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_has_reserved,
      { "Reserved", "mip6.has.reserved",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_has_address,
      { "Address", "mip6.has.address",
        FT_IPv6, BASE_NONE, NULL, 0,
        "Home Agent Address", HFILL }
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
    { &hf_mip6_opt_3gpp_lapi,
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

    { &hf_fmip6_lla,
      { "Link-layer address", "mip6.lla",
        FT_BYTES, SEP_COLON, NULL, 0,
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
    { &hf_mip6_mnid_identifier,
      { "Identifier", "mip6.mnid.identifier",
        FT_STRING, BASE_NONE, NULL, 0x0,
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
    { &hf_mip6_opt_mseg_id_timestamp,
      { "Timestamp", "mip6.mseg_id.timestamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
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
        FT_UINT32, BASE_ENTERPRISES, STRINGS_ENTERPRISES, 0x0,
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
    { &hf_mip6_opt_ss_identifier,
      { "Identifier", "mip6.ss.identifier",
        FT_STRING, BASE_NONE, NULL, 0x0,
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
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_mnlli_lli,
      { "Link-layer Identifier", "mip6.mnlli.lli",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pmip6_timestamp,
      { "Timestamp", "mip6.timestamp_tmp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
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
    { &hf_mip6_ipv4ha_reserved,
      { "Reserved", "mip6.ipv4ha.reserved",
        FT_UINT8, BASE_HEX, NULL, 0x0,
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
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0x0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_ipv4coa_reserved,
      { "Reserved", "mip6.ipv4coa.reserved",
        FT_UINT16, BASE_DEC, NULL, 0x0,
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
    { &hf_mip6_opt_mhipv6ap_ipv6_address,
      { "IPv6 Address", "mip6.mhipv6ap.ipv6_address",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_mhipv6ap_ipv6_address_prefix,
      { "IPv6 Address/Prefix", "mip6.mhipv6ap.ipv6_address_prefix",
        FT_STRING, BASE_NONE, NULL, 0,
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
        FT_BOOLEAN, 8, NULL, 0x80,
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
    { &hf_mip6_binding_refresh_request,
      { "Binding Refresh Request", "mip6.binding_refresh_request",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_mip6_unknown_type_data,
      { "Message Data", "mip6.unknown_type_data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_mip6_fast_neighbor_advertisement,
      { "Fast Neighbor Advertisement", "mip6.fast_neighbor_advertisement",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_mip6_vsm_data,
      { "Data", "mip6.vsm.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_mip6_vsm_req_data,
      { "Req-Data", "mip6.vsm.req_data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_padn,
      { "PadN", "mip6.padn",
        FT_BYTES, BASE_NONE, NULL, 0x0,
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
      { "Req-type", "mip6.cr.req_type",
        FT_UINT8, BASE_DEC | BASE_EXT_STRING, &mip6_mobility_options_ext, 0,
        NULL, HFILL }
    },
    { &hf_mip6_cr_req_length,
      { "Req-length", "mip6.cr.req_length",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_lmaa_opt_code,
      { "Option-Code", "mip6.lmaa.opt_code",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_lmaa_reserved,
      { "Reserved", "mip6.lmaa.reserved",
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

    { &hf_pmip6_lri_sequence,
      { "Sequence", "mip6.lri.sequence",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "A monotonically increasing integer", HFILL }
    },

    { &hf_pmip6_lri_reserved,
      { "Reserved", "mip6.lri.reserved",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        "This field is unused and MUST be set to zero", HFILL }
    },

    { &hf_pmip6_lri_lifetime,
      { "Lifetime", "mip6.lri.lifetime",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        "The requested time, in seconds", HFILL }
    },

    { &hf_pmip6_lra_sequence,
      { "Sequence", "mip6.lra.sequence",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "A monotonically increasing integer", HFILL }
    },

    { &hf_pmip6_lra_u,
      { "unsolicited", "mip6.lri.unsolicited",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
        "When set to 1, the LRA message is sent unsolicited", HFILL }
    },

    { &hf_pmip6_lra_reserved,
      { "Reserved", "mip6.lra.reserved",
        FT_UINT8, BASE_HEX, NULL, 0x7F,
        "This field is unused and MUST be set to zero", HFILL }
    },

    { &hf_pmip6_lra_status,
      { "Status", "mip6.lra.status",
        FT_UINT8, BASE_DEC, VALS(pmip6_lra_status_vals), 0x0,
        "Indicating the result of processing the Localized Routing Acknowledgment message.", HFILL }
    },

    { &hf_pmip6_lra_lifetime,
      { "Lifetime", "mip6.lra.lifetime",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        "The requested time, in seconds", HFILL }
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
        FT_BOOLEAN, 16, NULL, MIP6_REDIR_FLAG_N,
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

    { &hf_mip6_opt_mag_ipv6_reserved,
      { "Reserved", "mip6.mag_ipv6.reserved",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_mip6_opt_mag_ipv6_address_length,
      { "Address Length", "mip6.mag_ipv6.address_length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "This field MUST be set to 128", HFILL }
    },

    { &hf_mip6_opt_mag_ipv6_address,
      { "Address", "mip6.mag_ipv6.address",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_mip6_opt_acc_net_id_sub,
      { "ANI", "mip6.acc_net_id",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },


    { &hf_mip6_opt_acc_net_id_sub_opt,
      { "ANI Type", "mip6.acc_net_id.ani",
        FT_UINT8, BASE_DEC, VALS(mmip6_opt_acc_net_id_sub_opt_vals), 0x0,
        NULL, HFILL }
    },

    { &hf_mip6_opt_acc_net_id_sub_opt_len,
      { "Length", "mip6.acc_net_id.sub_opt_len",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_mip6_opt_acc_net_id_sub_opt_e_bit,
      { "E(Encoding)", "mip6.acc_net_id.e_bit",
        FT_BOOLEAN, 8, TFS(&mip6_opt_acc_net_id_sub_opt_e_bit_value), 0x80,
        NULL, HFILL }
    },

    { &hf_mip6_opt_acc_net_id_sub_opt_net_name_len,
      { "Net-Name Length", "mip6.acc_net_id.net_name_len",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_mip6_opt_acc_net_id_sub_opt_net_name,
      { "Network Name", "mip6.acc_net_id.net_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_mip6_opt_acc_net_id_sub_opt_net_name_data,
      { "Network Name", "mip6.acc_net_id.net_name_data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Network Name with undefined format", HFILL }
    },

    { &hf_mip6_opt_acc_net_id_sub_opt_ap_name_len,
      { "AP-Name Length", "mip6.acc_net_id.ap_name_len",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_mip6_opt_acc_net_id_sub_opt_ap_name,
      { "Access-Point Name", "mip6.acc_net_id.ap_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_mip6_opt_acc_net_id_sub_opt_geo_latitude_degrees,
      { "Latitude Degrees", "mip6.acc_net_id.geo.latitude_degrees",
        FT_INT24, BASE_CUSTOM, CF_FUNC(degrees_base_custom), 0x0,
        NULL, HFILL }
    },

    { &hf_mip6_opt_acc_net_id_sub_opt_geo_longitude_degrees,
      { "Longitude Degrees", "mip6.acc_net_id.geo.longitude_degrees",
        FT_INT24, BASE_CUSTOM, CF_FUNC(degrees_base_custom), 0x0,
        NULL, HFILL }
    },

    { &hf_mip6_opt_acc_net_id_sub_opt_op_id_type,
      { "Op-ID Type", "mip6.acc_net_id.op_id.type",
        FT_UINT8, BASE_DEC, VALS(mip6_opt_acc_net_id_sub_opt_op_id_type), 0x0,
        NULL, HFILL }
    },

    { &hf_mip6_opt_acc_net_id_sub_opt_op_id,
      { "Op-ID", "mip6.acc_net_id.op_id",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_mip6_opt_dmnp_v_flag,
      { "IPv4 Prefix (V) flag", "mip6.dmnp.v_flag",
        FT_BOOLEAN, 8, TFS(&mip6_dmnp_v_flag_value), 0x80,
        NULL, HFILL }
    },

    { &hf_mip6_opt_dmnp_reserved,
      { "Reserved", "mip6.dmnp.reserved",
        FT_UINT8, BASE_DEC, NULL, 0x7F,
        NULL, HFILL }
    },

    { &hf_mip6_opt_dmnp_prefix_len,
      { "Prefix Length", "mip6.dmnp.prefix_len",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_dmnp_dmnp_ipv4,
      { "IPv4 Delegated Mobile Network Prefix", "mip6.dmnp.dmnp_ipv4",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_mip6_opt_dmnp_dmnp_ipv6,
      { "IPv6 Delegated Mobile Network Prefix", "mip6.dmnp.dmnp_ipv6",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },

};

    /* Setup protocol subtree array */
    static int *ett[] = {
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
        &ett_mip6_opt_unknown,
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
        &ett_mip6_opt_mag_ipv6,
        &ett_mip6_opt_acc_net_id,
        &ett_mip6_sub_opt_acc_net_id,
        &ett_mip6_opt_dmnp,
    };

    static ei_register_info ei[] = {
        { &ei_mip6_ie_not_dissected, { "mip6.ie_not_dissected", PI_UNDECODED, PI_NOTE, "IE data not dissected yet", EXPFILL }},
        { &ei_mip6_ani_type_not_dissected, { "mip6.acc_net_id.ani.unknown", PI_UNDECODED, PI_NOTE, "ANI Type not dissect yet", EXPFILL }},
        { &ei_mip6_opt_len_invalid, { "mip6.opt.len.invalid", PI_PROTOCOL, PI_WARN, "Invalid length for option", EXPFILL }},
        { &ei_mip6_vsm_data_not_dissected, { "mip6.vsm.data_not_dissected", PI_UNDECODED, PI_NOTE, "Data (Not dissected yet)", EXPFILL }},
        { &ei_mip6_bogus_header_length, { "mip6.bogus_header_length", PI_PROTOCOL, PI_WARN, "Bogus header length", EXPFILL }},
    };

    expert_module_t* expert_mip6;

    /* Register the protocol name and description */
    proto_mip6 = proto_register_protocol("Mobile IPv6", "MIPv6", "mipv6");

    /* Register the dissector by name */
    mip6_handle = register_dissector("mip6", dissect_mip6, proto_mip6);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_mip6, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_mip6 = expert_register_protocol(proto_mip6);
    expert_register_field_array(expert_mip6, ei, array_length(ei));

    mip6_vsm_dissector_table = register_dissector_table("mip6.vsm", "Mobile IPv6 vendor specific option", proto_mip6, FT_UINT32, BASE_DEC);
    mip6_option_table = register_dissector_table("mip6.option", "MIPv6 Options", proto_mip6, FT_UINT8, BASE_DEC);

    /* Register MIPv6 options as their own protocols so we can get the name of the option */
    proto_mip6_option_pad1 = proto_register_protocol_in_name_only("MIPv6 Option - Pad1", "Pad1", "mip6.options.pad1", proto_mip6, FT_BYTES);
    proto_mip6_option_padn = proto_register_protocol_in_name_only("MIPv6 Option - PadN", "PadN", "mip6.options.padn", proto_mip6, FT_BYTES);
    proto_mip6_option_bra = proto_register_protocol_in_name_only("MIPv6 Option - Binding Refresh Advice", "Binding Refresh Advice", "mip6.options.bra", proto_mip6, FT_BYTES);
    proto_mip6_option_acoa = proto_register_protocol_in_name_only("MIPv6 Option - Alternate Care-of Address", "Alternate Care-of Address", "mip6.options.acoa", proto_mip6, FT_BYTES);
    proto_mip6_option_ni = proto_register_protocol_in_name_only("MIPv6 Option - Nonce Indices", "Nonce Indices", "mip6.options.ni", proto_mip6, FT_BYTES);
    proto_mip6_option_bad_auth = proto_register_protocol_in_name_only("MIPv6 Option - Authorization Data", "Authorization Data", "mip6.options.bad_auth", proto_mip6, FT_BYTES);
    proto_mip6_option_mnp = proto_register_protocol_in_name_only("MIPv6 Option - Mobile Network Prefix", "Mobile Network Prefix", "mip6.options.mnp", proto_mip6, FT_BYTES);
    proto_mip6_option_mhlla = proto_register_protocol_in_name_only("MIPv6 Option - Mobility Header Link-Layer Address", "Mobility Header Link-Layer Address", "mip6.options.mhlla", proto_mip6, FT_BYTES);
    proto_mip6_option_mnid = proto_register_protocol_in_name_only("MIPv6 Option - Mobile Node Identifier", "Mobile Node Identifier", "mip6.options.mnid", proto_mip6, FT_BYTES);
    proto_mip6_option_auth = proto_register_protocol_in_name_only("MIPv6 Option - AUTH-OPTION-TYPE", "AUTH-OPTION-TYPE", "mip6.options.auth", proto_mip6, FT_BYTES);
    proto_mip6_option_mseg_id = proto_register_protocol_in_name_only("MIPv6 Option - MESG-ID-OPTION-TYPE", "MESG-ID-OPTION-TYPE", "mip6.options.mseg_id", proto_mip6, FT_BYTES);
    proto_mip6_option_cgapr = proto_register_protocol_in_name_only("MIPv6 Option - CGA Parameters Request", "CGA Parameters Request", "mip6.options.cgapr", proto_mip6, FT_BYTES);
    proto_mip6_option_cgar = proto_register_protocol_in_name_only("MIPv6 Option - CGA Parameters", "CGA Parameters", "mip6.options.cgar", proto_mip6, FT_BYTES);
    proto_mip6_option_sign = proto_register_protocol_in_name_only("MIPv6 Option - Signature", "Signature", "mip6.options.sign", proto_mip6, FT_BYTES);
    proto_mip6_option_phkt = proto_register_protocol_in_name_only("MIPv6 Option - Permanent Home Keygen Token", "Permanent Home Keygen Token", "mip6.options.phkt", proto_mip6, FT_BYTES);
    proto_mip6_option_coti = proto_register_protocol_in_name_only("MIPv6 Option - Care-of Test Init", "Care-of Test Init", "mip6.options.coti", proto_mip6, FT_BYTES);
    proto_mip6_option_cot = proto_register_protocol_in_name_only("MIPv6 Option - Care-of Test", "Care-of Test", "mip6.options.cot", proto_mip6, FT_BYTES);
    proto_mip6_option_dnsu = proto_register_protocol_in_name_only("MIPv6 Option - DNS-UPDATE-TYPE", "DNS-UPDATE-TYPE", "mip6.options.dnsu", proto_mip6, FT_BYTES);
    proto_mip6_option_em = proto_register_protocol_in_name_only("MIPv6 Option - Experimental", "Experimental", "mip6.options.em", proto_mip6, FT_BYTES);
    proto_mip6_option_vsm = proto_register_protocol_in_name_only("MIPv6 Option - Vendor Specific", "Vendor Specific", "mip6.options.vsm", proto_mip6, FT_BYTES);
    proto_mip6_option_ssm = proto_register_protocol_in_name_only("MIPv6 Option - Service Selection", "Service Selection", "mip6.options.ssm", proto_mip6, FT_BYTES);
    proto_mip6_option_badff = proto_register_protocol_in_name_only("MIPv6 Option - Binding Authorization Data for FMIPv6 (BADF)", "Binding Authorization Data for FMIPv6 (BADF)", "mip6.options.badff", proto_mip6, FT_BYTES);
    proto_mip6_option_hnp = proto_register_protocol_in_name_only("MIPv6 Option - Home Network Prefix", "Home Network Prefix", "mip6.options.hnp", proto_mip6, FT_BYTES);
    proto_mip6_option_hi = proto_register_protocol_in_name_only("MIPv6 Option - Handoff Indicator", "Handoff Indicator", "mip6.options.hi", proto_mip6, FT_BYTES);
    proto_mip6_option_att = proto_register_protocol_in_name_only("MIPv6 Option - Access Technology Type Option", "Access Technology Type Option", "mip6.options.att", proto_mip6, FT_BYTES);
    proto_mip6_option_mnlli = proto_register_protocol_in_name_only("MIPv6 Option - Mobile Node Link-layer Identifier", "Mobile Node Link-layer Identifier", "mip6.options.mnlli", proto_mip6, FT_BYTES);
    proto_mip6_option_lla = proto_register_protocol_in_name_only("MIPv6 Option - Link-local Address", "Link-local Address", "mip6.options.lla", proto_mip6, FT_BYTES);
    proto_mip6_option_ts = proto_register_protocol_in_name_only("MIPv6 Option - Timestamp", "Timestamp", "mip6.options.ts", proto_mip6, FT_BYTES);
    proto_mip6_option_rc = proto_register_protocol_in_name_only("MIPv6 Option - Restart Counter", "Restart Counter", "mip6.options.rc", proto_mip6, FT_BYTES);
    proto_mip6_option_ipv4ha = proto_register_protocol_in_name_only("MIPv6 Option - IPv4 Home Address", "IPv4 Home Address", "mip6.options.ipv4ha", proto_mip6, FT_BYTES);
    proto_mip6_option_ipv4aa = proto_register_protocol_in_name_only("MIPv6 Option - IPv4 Address Acknowledgement", "IPv4 Address Acknowledgement", "mip6.options.ipv4aa", proto_mip6, FT_BYTES);
    proto_mip6_option_natd = proto_register_protocol_in_name_only("MIPv6 Option - NAT Detection", "NAT Detection", "mip6.options.natd", proto_mip6, FT_BYTES);
    proto_mip6_option_ipv4coa = proto_register_protocol_in_name_only("MIPv6 Option - IPv4 Care-of Address", "IPv4 Care-of Address", "mip6.options.ipv4coa", proto_mip6, FT_BYTES);
    proto_mip6_option_grek = proto_register_protocol_in_name_only("MIPv6 Option - GRE Key", "GRE Key", "mip6.options.grek", proto_mip6, FT_BYTES);
    proto_mip6_option_mhipv6ap = proto_register_protocol_in_name_only("MIPv6 Option - Mobility Header IPv6 Address/Prefix", "Mobility Header IPv6 Address/Prefix", "mip6.options.mhipv6ap", proto_mip6, FT_BYTES);
    proto_mip6_option_bi = proto_register_protocol_in_name_only("MIPv6 Option - Binding Identifier", "Binding Identifier", "mip6.options.bi", proto_mip6, FT_BYTES);
    proto_mip6_option_ipv4hareq = proto_register_protocol_in_name_only("MIPv6 Option - IPv4 Home Address Request", "IPv4 Home Address Request", "mip6.options.ipv4hareq", proto_mip6, FT_BYTES);
    proto_mip6_option_ipv4harep = proto_register_protocol_in_name_only("MIPv6 Option - IPv4 Home Address Reply", "IPv4 Home Address Reply", "mip6.options.ipv4harep", proto_mip6, FT_BYTES);
    proto_mip6_option_ipv4dra = proto_register_protocol_in_name_only("MIPv6 Option - IPv4 Default-Router Address", "IPv4 Default-Router Address", "mip6.options.ipv4dra", proto_mip6, FT_BYTES);
    proto_mip6_option_ipv4dsm = proto_register_protocol_in_name_only("MIPv6 Option - IPv4 DHCP Support Mode", "IPv4 DHCP Support Mode", "mip6.options.ipv4dsm", proto_mip6, FT_BYTES);
    proto_mip6_option_cr = proto_register_protocol_in_name_only("MIPv6 Option - Context Request", "Context Request", "mip6.options.cr", proto_mip6, FT_BYTES);
    proto_mip6_option_lmaa = proto_register_protocol_in_name_only("MIPv6 Option - Mobile Node Link-local Address Interface Identifier", "Mobile Node Link-local Address Interface Identifier", "mip6.options.lmaa", proto_mip6, FT_BYTES);
    proto_mip6_option_recap = proto_register_protocol_in_name_only("MIPv6 Option - Redirect-Capability", "Redirect-Capability", "mip6.options.recap", proto_mip6, FT_BYTES);
    proto_mip6_option_redir = proto_register_protocol_in_name_only("MIPv6 Option - Redirect", "Redirect", "mip6.options.redir", proto_mip6, FT_BYTES);
    proto_mip6_option_load_inf = proto_register_protocol_in_name_only("MIPv6 Option - Load Information", "Load Information", "mip6.options.load_inf", proto_mip6, FT_BYTES);
    proto_mip6_option_alt_ip4 = proto_register_protocol_in_name_only("MIPv6 Option - Alternate IPv4", "Alternate IPv4", "mip6.options.alt_ip4", proto_mip6, FT_BYTES);
    proto_mip6_option_mng = proto_register_protocol_in_name_only("MIPv6 Option - Mobile Node Group Identifier", "Mobile Node Group Identifier", "mip6.options.mng", proto_mip6, FT_BYTES);
    proto_mip6_option_mag_ipv6 = proto_register_protocol_in_name_only("MIPv6 Option - MAG IPv6 Address", "MAG IPv6 Address", "mip6.options.mag_ipv6", proto_mip6, FT_BYTES);
    proto_mip6_option_acc_net_id = proto_register_protocol_in_name_only("MIPv6 Option - Access Network Identifier", "Access Network Identifier", "mip6.options.acc_net_id", proto_mip6, FT_BYTES);
    proto_mip6_option_dmnp = proto_register_protocol_in_name_only("MIPv6 Option - Delegated Mobile Network Prefix", "Delegated Mobile Network Prefix", "mip6.options.dmnp", proto_mip6, FT_BYTES);
}

void
proto_reg_handoff_mip6(void)
{
    dissector_add_uint("ip.proto", IP_PROTO_MIPV6_OLD, mip6_handle);
    dissector_add_uint("ip.proto", IP_PROTO_MIPV6, mip6_handle);

    /* Add support for PMIPv6 control messages over IPV4 */
    dissector_add_uint_with_preference("udp.port", UDP_PORT_PMIP6_CNTL, mip6_handle);
    ip_dissector_table = find_dissector_table("ip.proto");

    dissector_add_uint("mip6.vsm", VENDOR_THE3GPP, create_dissector_handle(dissect_mip6_opt_vsm_3gpp, proto_mip6));


    /* Create dissection function handles for all MIPv6 options */
    dissector_add_uint("mip6.option", MIP6_PADN, create_dissector_handle( dissect_mip6_opt_padn, proto_mip6_option_padn ));
    dissector_add_uint("mip6.option", MIP6_BRA, create_dissector_handle( dissect_mip6_opt_bra, proto_mip6_option_bra ));
    dissector_add_uint("mip6.option", MIP6_ACOA, create_dissector_handle( dissect_mip6_opt_acoa, proto_mip6_option_acoa ));
    dissector_add_uint("mip6.option", MIP6_NI, create_dissector_handle( dissect_mip6_opt_ni, proto_mip6_option_ni ));
    dissector_add_uint("mip6.option", MIP6_AUTD, create_dissector_handle( dissect_mip6_opt_bad, proto_mip6_option_bad_auth ));
    dissector_add_uint("mip6.option", MIP6_MNP, create_dissector_handle( dissect_mip6_nemo_opt_mnp, proto_mip6_option_mnp ));
    dissector_add_uint("mip6.option", MIP6_MHLLA, create_dissector_handle( dissect_fmip6_opt_lla, proto_mip6_option_mhlla ));
    dissector_add_uint("mip6.option", MIP6_MNID, create_dissector_handle( dissect_mip6_opt_mnid, proto_mip6_option_mnid ));
    dissector_add_uint("mip6.option", MIP6_AUTH, create_dissector_handle( dissect_mip6_opt_auth, proto_mip6_option_auth ));
    dissector_add_uint("mip6.option", MIP6_MESGID, create_dissector_handle( dissect_mip6_opt_mseg_id, proto_mip6_option_mseg_id ));
    dissector_add_uint("mip6.option", MIP6_CGAPR, create_dissector_handle( dissect_mip6_opt_cgapr, proto_mip6_option_cgapr ));
    dissector_add_uint("mip6.option", MIP6_CGAR, create_dissector_handle( dissect_mip6_opt_cgar, proto_mip6_option_cgar ));
    dissector_add_uint("mip6.option", MIP6_SIGN, create_dissector_handle( dissect_mip6_opt_sign, proto_mip6_option_sign ));
    dissector_add_uint("mip6.option", MIP6_PHKT, create_dissector_handle( dissect_mip6_opt_phkt, proto_mip6_option_phkt ));
    dissector_add_uint("mip6.option", MIP6_MOCOTI, create_dissector_handle( dissect_mip6_opt_coti, proto_mip6_option_coti ));
    dissector_add_uint("mip6.option", MIP6_MOCOT, create_dissector_handle( dissect_mip6_opt_mocot, proto_mip6_option_cot ));
    dissector_add_uint("mip6.option", MIP6_DNSU, create_dissector_handle( dissect_mip6_opt_dnsu, proto_mip6_option_dnsu ));
    dissector_add_uint("mip6.option", MIP6_EM, create_dissector_handle( dissect_mip6_opt_em, proto_mip6_option_em ));
    dissector_add_uint("mip6.option", MIP6_VSM, create_dissector_handle( dissect_mip6_opt_vsm, proto_mip6_option_vsm ));
    dissector_add_uint("mip6.option", MIP6_SSM, create_dissector_handle( dissect_mip6_opt_ssm, proto_mip6_option_ssm ));
    dissector_add_uint("mip6.option", MIP6_BADFF, create_dissector_handle( dissect_mip6_opt_badff, proto_mip6_option_badff ));
    dissector_add_uint("mip6.option", MIP6_HNP, create_dissector_handle( dissect_mip6_opt_hnp, proto_mip6_option_hnp ));
    dissector_add_uint("mip6.option", MIP6_MOHI, create_dissector_handle( dissect_pmip6_opt_hi, proto_mip6_option_hi ));
    dissector_add_uint("mip6.option", MIP6_ATT, create_dissector_handle( dissect_pmip6_opt_att, proto_mip6_option_att ));
    dissector_add_uint("mip6.option", MIP6_MNLLI, create_dissector_handle( dissect_pmip6_opt_mnlli, proto_mip6_option_mnlli ));
    dissector_add_uint("mip6.option", MIP6_LLA, create_dissector_handle( dissect_pmip6_opt_lla, proto_mip6_option_lla ));
    dissector_add_uint("mip6.option", MIP6_TS, create_dissector_handle( dissect_pmip6_opt_ts, proto_mip6_option_ts ));
    dissector_add_uint("mip6.option", MIP6_RC, create_dissector_handle( dissect_pmip6_opt_rc, proto_mip6_option_rc ));
    dissector_add_uint("mip6.option", MIP6_IPV4HA, create_dissector_handle( dissect_pmip6_opt_ipv4ha, proto_mip6_option_ipv4ha ));
    dissector_add_uint("mip6.option", MIP6_IPV4AA, create_dissector_handle( dissect_pmip6_opt_ipv4aa, proto_mip6_option_ipv4aa ));
    dissector_add_uint("mip6.option", MIP6_NATD, create_dissector_handle( dissect_pmip6_opt_natd, proto_mip6_option_natd ));
    dissector_add_uint("mip6.option", MIP6_IPV4COA, create_dissector_handle( dissect_pmip6_opt_ipv4coa, proto_mip6_option_ipv4coa ));
    dissector_add_uint("mip6.option", MIP6_GREK, create_dissector_handle( dissect_pmip6_opt_grek, proto_mip6_option_grek ));
    dissector_add_uint("mip6.option", MIP6_MHIPV6AP, create_dissector_handle( dissect_pmip6_opt_mhipv6ap, proto_mip6_option_mhipv6ap ));
    dissector_add_uint("mip6.option", MIP6_BI, create_dissector_handle( dissect_pmip6_opt_bi, proto_mip6_option_bi ));
    dissector_add_uint("mip6.option", MIP6_IPV4HAREQ, create_dissector_handle( dissect_pmip6_opt_ipv4hareq, proto_mip6_option_ipv4hareq ));
    dissector_add_uint("mip6.option", MIP6_IPV4HAREP, create_dissector_handle( dissect_pmip6_opt_ipv4harep, proto_mip6_option_ipv4harep ));
    dissector_add_uint("mip6.option", MIP6_IPV4DRA, create_dissector_handle( dissect_pmip6_opt_ipv4dra, proto_mip6_option_ipv4dra ));
    dissector_add_uint("mip6.option", MIP6_IPV4DSM, create_dissector_handle( dissect_pmip6_opt_ipv4dsm, proto_mip6_option_ipv4dsm ));
    dissector_add_uint("mip6.option", MIP6_CR, create_dissector_handle( dissect_pmip6_opt_cr, proto_mip6_option_cr ));
    dissector_add_uint("mip6.option", MIP6_LMAA, create_dissector_handle( dissect_pmip6_opt_lmaa, proto_mip6_option_lmaa ));
    dissector_add_uint("mip6.option", MIP6_RECAP, create_dissector_handle( dissect_pmip6_opt_recap, proto_mip6_option_recap ));
    dissector_add_uint("mip6.option", MIP6_REDIR, create_dissector_handle( dissect_pmip6_opt_redir, proto_mip6_option_redir ));
    dissector_add_uint("mip6.option", MIP6_LOAD_INF, create_dissector_handle( dissect_pmip6_opt_load_inf, proto_mip6_option_load_inf ));
    dissector_add_uint("mip6.option", MIP6_ALT_IP4_CO, create_dissector_handle( dissect_pmip6_opt_alt_ip4, proto_mip6_option_alt_ip4 ));
    dissector_add_uint("mip6.option", MIP6_MNG, create_dissector_handle( dissect_pmip6_opt_mng, proto_mip6_option_mng ));
    dissector_add_uint("mip6.option", MIP6_MAG_IPv6, create_dissector_handle( dissect_pmip6_opt_mag_ipv6, proto_mip6_option_mag_ipv6 ));
    dissector_add_uint("mip6.option", MIP6_ACC_NET_ID, create_dissector_handle( dissect_pmip6_opt_acc_net_id, proto_mip6_option_acc_net_id ));
    dissector_add_uint("mip6.option", MIP6_DMNP, create_dissector_handle( dissect_mip6_opt_dmnp, proto_mip6_option_dmnp ));
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
