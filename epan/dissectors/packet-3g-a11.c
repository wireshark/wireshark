/*
 * packet-3g-a11.c
 * Routines for CDMA2000 A11 packet trace
 * Copyright 2002, Ryuji Somegawa <somegawa@wide.ad.jp>
 * packet-3g-a11.c was written based on 'packet-mip.c'.
 *
 * packet-3g-a11.c updated by Ravi Valmikam for 3GPP2 TIA-878-A
 * Copyright 2005, Ravi Valmikam <rvalmikam@airvananet.com>
 *
 * packet-mip.c
 * Routines for Mobile IP dissection
 * Copyright 2000, Stefan Raab <sraab@cisco.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *Ref:
 * http://www.3gpp2.org/Public_html/specs/A.S0009-C_v3.0_100621.pdf
 * http://www.3gpp2.org/Public_html/specs/A.S0017-D_v1.0_070624.pdf (IOS 5.1)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
/* Include vendor id translation */
#include <epan/sminmpec.h>

static int registration_request_msg =0;

/* Initialize the protocol and registered fields */
static int proto_a11 = -1;
static int hf_a11_type = -1;
static int hf_a11_flags = -1;
static int hf_a11_s = -1;
static int hf_a11_b = -1;
static int hf_a11_d = -1;
static int hf_a11_m = -1;
static int hf_a11_g = -1;
static int hf_a11_v = -1;
static int hf_a11_t = -1;
static int hf_a11_code = -1;
static int hf_a11_status = -1;
static int hf_a11_life = -1;
static int hf_a11_homeaddr = -1;
static int hf_a11_haaddr = -1;
static int hf_a11_coa = -1;
static int hf_a11_ident = -1;
static int hf_a11_ext_type = -1;
static int hf_a11_ext_stype = -1;
static int hf_a11_ext_len = -1;
static int hf_a11_ext = -1;
static int hf_a11_aext_spi = -1;
static int hf_a11_aext_auth = -1;
static int hf_a11_next_nai = -1;

static int hf_a11_ses_key = -1;
static int hf_a11_ses_mnsrid = -1;
static int hf_a11_ses_sidver = -1;
static int hf_a11_ses_msid_type = -1;
static int hf_a11_ses_msid_len = -1;
static int hf_a11_ses_msid = -1;
static int hf_a11_ses_ptype = -1;

static int hf_a11_vse_vid = -1;
static int hf_a11_vse_apptype = -1;
static int hf_a11_vse_canid = -1;
static int hf_a11_vse_panid = -1;
static int hf_a11_vse_srvopt = -1;
static int hf_a11_vse_qosmode = -1;
static int hf_a11_vse_pdit = -1;
static int hf_a11_vse_code = -1;
static int hf_a11_vse_dormant = -1;
static int hf_a11_vse_ppaddr = -1;

/* Additional Session Information */
static int hf_a11_ase_len_type = -1;
static int hf_a11_ase_srid_type = -1;
static int hf_a11_ase_servopt_type = -1;
static int hf_a11_ase_gre_proto_type = -1;
static int hf_a11_ase_gre_key = -1;
static int hf_a11_ase_pcf_addr_key = -1;

static int hf_a11_ase_forward_rohc_info_len = -1;
static int hf_a11_ase_forward_maxcid = -1;
static int hf_a11_ase_forward_mrru = -1;
static int hf_a11_ase_forward_large_cids = -1;
static int hf_a11_ase_forward_profile_count = -1;
static int hf_a11_ase_forward_profile = -1;

static int hf_a11_ase_reverse_rohc_info_len = -1;
static int hf_a11_ase_reverse_maxcid = -1;
static int hf_a11_ase_reverse_mrru = -1;
static int hf_a11_ase_reverse_large_cids = -1;
static int hf_a11_ase_reverse_profile_count = -1;
static int hf_a11_ase_reverse_profile = -1;

/* Forward QoS Information */
static int hf_a11_fqi_srid = -1;
static int hf_a11_fqi_flags = -1;
static int hf_a11_fqi_flowcount = -1;
static int hf_a11_fqi_flowid = -1;
static int hf_a11_fqi_entrylen = -1;
static int hf_a11_fqi_dscp = -1;
static int hf_a11_fqi_flowstate = -1;
static int hf_a11_fqi_requested_qoslen = -1;
static int hf_a11_fqi_flow_priority = -1;
static int hf_a11_fqi_num_qos_attribute_set = -1;
static int hf_a11_fqi_qos_attribute_setlen = -1;
static int hf_a11_fqi_qos_attribute_setid = -1;
static int hf_a11_fqi_qos_granted_attribute_setid = -1;
static int hf_a11_fqi_verbose = -1;
static int hf_a11_fqi_flow_profileid = -1;
static int hf_a11_fqi_granted_qoslen = -1;

/* Reverse QoS Information */
static int hf_a11_rqi_srid = -1;
static int hf_a11_rqi_flowcount = -1;
static int hf_a11_rqi_flowid = -1;
static int hf_a11_rqi_entrylen = -1;
static int hf_a11_rqi_flowstate = -1;
static int hf_a11_rqi_requested_qoslen = -1;
static int hf_a11_rqi_flow_priority = -1;
static int hf_a11_rqi_num_qos_attribute_set = -1;
static int hf_a11_rqi_qos_attribute_setlen = -1;
static int hf_a11_rqi_qos_attribute_setid = -1;
static int hf_a11_rqi_qos_granted_attribute_setid = -1;
static int hf_a11_rqi_verbose = -1;
static int hf_a11_rqi_flow_profileid = -1;
static int hf_a11_rqi_requested_qos = -1;
static int hf_a11_rqi_granted_qoslen = -1;
static int hf_a11_rqi_granted_qos = -1;

/* QoS Update Information */
static int hf_a11_fqui_flowcount = -1;
static int hf_a11_rqui_flowcount = -1;
static int hf_a11_fqui_updated_qoslen = -1;
static int hf_a11_fqui_updated_qos = -1;
static int hf_a11_rqui_updated_qoslen = -1;
static int hf_a11_rqui_updated_qos = -1;
static int hf_a11_subsciber_profile = -1;
static int hf_a11_subsciber_profile_len = -1;

/* Initialize the subtree pointers */
static gint ett_a11 = -1;
static gint ett_a11_flags = -1;
static gint ett_a11_ext = -1;
static gint ett_a11_exts = -1;
static gint ett_a11_radius = -1;
static gint ett_a11_radiuses = -1;
static gint ett_a11_ase = -1;
static gint ett_a11_fqi_flowentry = -1;
static gint ett_a11_fqi_requestedqos = -1;
static gint ett_a11_fqi_qos_attribute_set = -1;
static gint ett_a11_fqi_grantedqos = -1;
static gint ett_a11_rqi_flowentry = -1;
static gint ett_a11_rqi_requestedqos = -1;
static gint ett_a11_rqi_qos_attribute_set = -1;
static gint ett_a11_rqi_grantedqos = -1;
static gint ett_a11_fqi_flags = -1;
static gint ett_a11_fqi_entry_flags = -1;
static gint ett_a11_rqi_entry_flags = -1;
static gint ett_a11_fqui_flowentry = -1;
static gint ett_a11_rqui_flowentry = -1;
static gint ett_a11_subscriber_profile = -1;
static gint ett_a11_forward_rohc = -1;
static gint ett_a11_reverse_rohc = -1;
static gint ett_a11_forward_profile = -1;
static gint ett_a11_reverse_profile = -1;


/* Port used for Mobile IP based Tunneling Protocol (A11) */
#define UDP_PORT_3GA11    699

typedef enum {
    REGISTRATION_REQUEST  = 1,
    REGISTRATION_REPLY    = 3,
    REGISTRATION_UPDATE   = 20,
    REGISTRATION_ACK      = 21,
    SESSION_UPDATE        = 22,
    SESSION_ACK           = 23,
    CAPABILITIES_INFO     = 24,
    CAPABILITIES_INFO_ACK = 25
} a11MessageTypes;

static const value_string a11_types[] = {
    {REGISTRATION_REQUEST,  "Registration Request"},
    {REGISTRATION_REPLY,    "Registration Reply"},
    {REGISTRATION_UPDATE,   "Registration Update"},
    {REGISTRATION_ACK,      "Registration Ack"},
    {SESSION_UPDATE,        "Session Update"},
    {SESSION_ACK,           "Session Update Ack"},
    {CAPABILITIES_INFO,     "Capabilities Info"},
    {CAPABILITIES_INFO_ACK, "Capabilities Info Ack"},
    {0, NULL},
};

static const value_string a11_ses_ptype_vals[] = {
    {0x8881, "Unstructured Byte Stream"},
    {0x88D2, "3GPP2 Packet"},
    {0, NULL},
};

static const value_string a11_reply_codes[]= {
    {0,  "Reg Accepted"},
    {9,  "Connection Update"},
#if 0
    {1,  "Reg Accepted, but Simultaneous Bindings Unsupported."},
    {64, "Reg Deny (FA)- Unspecified Reason"},
    {65, "Reg Deny (FA)- Administratively Prohibited"},
    {66, "Reg Deny (FA)- Insufficient Resources"},
    {67, "Reg Deny (FA)- MN failed Authentication"},
    {68, "Reg Deny (FA)- HA failed Authentication"},
    {69, "Reg Deny (FA)- Requested Lifetime too Long"},
    {70, "Reg Deny (FA)- Poorly Formed Request"},
    {71, "Reg Deny (FA)- Poorly Formed Reply"},
    {72, "Reg Deny (FA)- Requested Encapsulation Unavailable"},
    {73, "Reg Deny (FA)- VJ Compression Unavailable"},
    {74, "Reg Deny (FA)- Requested Reverse Tunnel Unavailable"},
    {75, "Reg Deny (FA)- Reverse Tunnel is Mandatory and 'T' Bit Not Set"},
    {76, "Reg Deny (FA)- Mobile Node Too Distant"},
    {79, "Reg Deny (FA)- Delivery Style Not Supported"},
    {80, "Reg Deny (FA)- Home Network Unreachable"},
    {81, "Reg Deny (FA)- HA Host Unreachable"},
    {82, "Reg Deny (FA)- HA Port Unreachable"},
    {88, "Reg Deny (FA)- HA Unreachable"},
    {96, "Reg Deny (FA)(NAI) - Non Zero Home Address Required"},
    {97, "Reg Deny (FA)(NAI) - Missing NAI"},
    {98, "Reg Deny (FA)(NAI) - Missing Home Agent"},
    {99, "Reg Deny (FA)(NAI) - Missing Home Address"},
#endif
    {128, "Reg Deny (HA)- Unspecified"},
    {129, "Reg Deny (HA)- Administratively Prohibited"},
    {130, "Reg Deny (HA)- Insufficient Resources"},
    {131, "Reg Deny (HA)- PCF Failed Authentication"},
    /* {132, "Reg Deny (HA)- FA Failed Authentication"}, */
    {133, "Reg Deny (HA)- Identification Mismatch"},
    {134, "Reg Deny (HA)- Poorly Formed Request"},
    /* {135, "Reg Deny (HA)- Too Many Simultaneous Bindings"}, */
    {136, "Reg Deny (HA)- Unknown PDSN Address"},
    {137, "Reg Deny (HA)- Requested Reverse Tunnel Unavailable"},
    {138, "Reg Deny (HA)- Reverse Tunnel is Mandatory and 'T' Bit Not Set"},
    {139, "Reg Deny (HA)- Requested Encapsulation Unavailable"},
    {140, "Registration Denied - no CID available"},
    {141, "Reg Deny (HA)- unsupported Vendor ID / Application Type in CVSE"},
    {142, "Registration Denied - nonexistent A10 or IP flow"},
    {0, NULL},
};


static const value_string a11_ack_status[]= {
    {0, "Update Accepted"},
    {1, "Partial QoS updated"},
    {128, "Update Deny - Unspecified"},
    {131, "Update Deny - Sending Node Failed Authentication"},
    {133, "Update Deny - Registration ID Mismatch"},
    {134, "Update Deny - Poorly Formed Request"},
    {193, "Update Deny - Session Parameter Not Updated"},
    {253, "Update Denied - QoS profileID not supported"},
    {254, "Update Denied - insufficient resources"},
    {255, "Update Denied - handoff in progress"},
    {0, NULL},
};

typedef enum {
    MH_AUTH_EXT      = 32,
    MF_AUTH_EXT      = 33,
    FH_AUTH_EXT      = 34,
    GEN_AUTH_EXT     = 36,  /* RFC 3012 */
    OLD_CVSE_EXT     = 37,  /* RFC 3115 */
    CVSE_EXT         = 38,  /* RFC 3115 */
    SS_EXT           = 39,  /* 3GPP2 IOS4.2 */
    RU_AUTH_EXT      = 40,  /* 3GPP2 IOS4.2 */
    MN_NAI_EXT       = 131,
    MF_CHALLENGE_EXT = 132, /* RFC 3012 */
    OLD_NVSE_EXT     = 133, /* RFC 3115 */
    NVSE_EXT         = 134  /* RFC 3115 */
} MIP_EXTS;


static const value_string a11_ext_types[]= {
    {MH_AUTH_EXT,      "Mobile-Home Authentication Extension"},
    {MF_AUTH_EXT,      "Mobile-Foreign Authentication Extension"},
    {FH_AUTH_EXT,      "Foreign-Home Authentication Extension"},
    {MN_NAI_EXT,       "Mobile Node NAI Extension"},
    {GEN_AUTH_EXT,     "Generalized Mobile-IP Authentication Extension"},
    {MF_CHALLENGE_EXT, "MN-FA Challenge Extension"},
    {CVSE_EXT,         "Critical Vendor/Organization Specific Extension"},
    {SS_EXT,           "Session Specific Extension"},
    {RU_AUTH_EXT,      "Registration Update Authentication Extension"},
    {OLD_CVSE_EXT,     "Critical Vendor/Organization Specific Extension (OLD)"},
    {NVSE_EXT,         "Normal Vendor/Organization Specific Extension"},
    {OLD_NVSE_EXT,     "Normal Vendor/Organization Specific Extension (OLD)"},
    {0, NULL},
};

static const value_string a11_ext_stypes[]= {
    {1, "MN AAA Extension"},
    {0, NULL},
};

static const value_string a11_ext_nvose_qosmode[]= {
    {0x00, "QoS Disabled"},
    {0x01, "QoS Enabled"},
    {0, NULL},
};

static const value_string a11_ext_nvose_srvopt[]= {
    {0x0021, "3G High Speed Packet Data"},
    {0x003B, "HRPD Main Service Connection"},
    {0x003C, "Link Layer Assisted Header Removal"},
    {0x003D, "Link Layer Assisted Robust Header Compression"},
    {0x0040, "HRPD Auxiliary Service Connection with higher layer framing for packet synchronization"},
    {0x0043, "HRPD Auxiliary Service Connection without higher layer framing for packet synchronization"},
    {0, NULL},
};

static const value_string a11_ext_nvose_pdsn_code[]= {
    {0xc1, "Connection Release - reason unspecified"},
    {0xc2, "Connection Release - PPP time-out"},
    {0xc3, "Connection Release - registration time-out"},
    {0xc4, "Connection Release - PDSN error"},
    {0xc5, "Connection Release - inter-PCF handoff"},
    {0xc6, "Connection Release - inter-PDSN handoff"},
    {0xc7, "Connection Release - PDSN OAM&P intervention"},
    {0xc8, "Connection Release - accounting error"},
    {0xca, "Connection Release - user (NAI) failed authentication"},
    {0x00, NULL},
};

static const value_string a11_ext_dormant[]= {
    {0x0000, "all MS packet data service instances are dormant"},
    {0, NULL},
};

static const value_string a11_ext_app[]= {
    {0x0101, "Accounting (RADIUS)"},
    {0x0102, "Accounting (DIAMETER)"},
    {0x0201, "Mobility Event Indicator (Mobility)"},
    {0x0301, "Data Available Indicator (Data Ready to Send)"},
    {0x0401, "Access Network Identifiers (ANID)"},
    {0x0501, "PDSN Identifiers (Anchor P-P Address)"},
    {0x0601, "Indicators (All Dormant Indicator)"},
    {0x0701, "PDSN Code (PDSN Code)"},
    {0x0801, "Session Parameter (RN-PDIT:Radio Network Packet Data Inactivity Timer)"},
    {0x0802, "Session Parameter (Always On)"},
    {0x0803, "Session Parameter (QoS Mode)"},
    {0x0901, "Service Option (Service Option Value)"},
    {0x0A01, "PDSN Enabled Features (Flow Control Enabled)"},
    {0x0A02, "PDSN Enabled Features (Packet Boundary Enabled)"},
    {0x0A03, "PDSN Enabled Features (GRE Segmentation Enabled)"},
    {0x0B01, "PCF Enabled Features (Short Data Indication Supported)"},
    {0x0B02, "PCF Enabled Features (GRE Segmentation Enabled)"},
    {0x0C01, "Additional Session Info"},
    {0x0D01, "QoS Information (Forward QoS Information)"},
    {0x0D02, "QoS Information (Reverse QoS Information)"},
    {0x0D03, "QoS Information (Subscriber QoS Profile)"},
    {0x0DFE, "QoS Information (Forward QoS Update Information)"},
    {0x0DFF, "QoS Information (Reverse QoS Update Information)"},
    {0x0E01, "Header Compression (ROHC Configuration Parameters)"},
    {0, NULL},
};

static const value_string a11_airlink_types[]= {
    {1, "Session Setup (Y=1)"},
    {2, "Active Start (Y=2)"},
    {3, "Active Stop (Y=3)"},
    {4, "Short Data Burst (Y=4)"},
    {0, NULL},
};


#define ATTRIBUTE_NAME_LEN_MAX 128
#define ATTR_TYPE_NULL 0
#define ATTR_TYPE_INT 1
#define ATTR_TYPE_STR 2
#define ATTR_TYPE_IPV4 3
#define ATTR_TYPE_TYPE 4
#define ATTR_TYPE_MSID 5
#define A11_MSG_MSID_ELEM_LEN_MAX 8
#define A11_MSG_MSID_LEN_MAX 15


struct radius_attribute {
    char attrname[ATTRIBUTE_NAME_LEN_MAX];
    int type;
    int subtype;
    int bytes;
    int data_type;
};

static const struct radius_attribute attrs[]={
    {"Airlink Record",          26, 40,  4, ATTR_TYPE_TYPE},
    {"R-P Session ID",          26, 41,  4, ATTR_TYPE_INT},
    {"Airlink Sequence Number", 26, 42,  4, ATTR_TYPE_INT},
#if 0
    {"MSID",                    31, -1, 15, ATTR_TYPE_MSID},
#endif
    {"Serving PCF",             26,  9,  4, ATTR_TYPE_IPV4},
    {"BSID",                    26, 10, 12, ATTR_TYPE_STR},
    {"ESN",                     26, 52, 15, ATTR_TYPE_STR},
    {"User Zone",               26, 11,  4, ATTR_TYPE_INT},
    {"Forward FCH Mux Option",  26, 12,  4, ATTR_TYPE_INT},
    {"Reverse FCH Mux Option",  26, 13,  4, ATTR_TYPE_INT},
    {"Forward Fundamental Rate (IOS 4.1)",26, 14,  4, ATTR_TYPE_INT},
    {"Reverse Fundamental Rate (IOS 4.1)",26, 15,  4, ATTR_TYPE_INT},
    {"Service Option",          26, 16,  4, ATTR_TYPE_INT},
    {"Forward Traffic Type",    26, 17,  4, ATTR_TYPE_INT},
    {"Reverse Traffic Type",    26, 18,  4, ATTR_TYPE_INT},
    {"FCH Frame Size",          26, 19,  4, ATTR_TYPE_INT},
    {"Forward FCH RC",          26, 20,  4, ATTR_TYPE_INT},
    {"Reverse FCH RC",          26, 21,  4, ATTR_TYPE_INT},
    {"DCCH Frame Size 0/5/20",  26, 50,  4, ATTR_TYPE_INT},
    {"Forward DCCH Mux Option", 26, 84,  4, ATTR_TYPE_INT},
    {"Reverse DCCH Mux Option", 26, 85,  4, ATTR_TYPE_INT},
    {"Forward DCCH RC",         26, 86,  4, ATTR_TYPE_INT},
    {"Reverse DCCH RC",         26, 87,  4, ATTR_TYPE_INT},
    {"Airlink Priority",        26, 39,  4, ATTR_TYPE_INT},
    {"Active Connection Time",  26, 49,  4, ATTR_TYPE_INT},
    {"Mobile Orig/Term Ind.",   26, 45,  4, ATTR_TYPE_INT},
    {"SDB Octet Count (Term.)", 26, 31,  4, ATTR_TYPE_INT},
    {"SDB Octet Count (Orig.)", 26, 32,  4, ATTR_TYPE_INT},
    {"ESN (Integer)",           26, 48,  4, ATTR_TYPE_INT},
    {"Sublink",                 26, 108,  4, ATTR_TYPE_STR},
    {"MEID",                    26, 116, 14, ATTR_TYPE_STR},
    {"Reverse PDCH RC",         26, 114,  2, ATTR_TYPE_INT},
    {"Flow ID Parameter",       26, 144,  4, ATTR_TYPE_INT},
    {"Granted QoS Parameters",  26, 132,  4, ATTR_TYPE_INT},
    {"Flow Status",             26, 145,  4, ATTR_TYPE_INT},
    {"Unknown",                 -1, -1, -1, ATTR_TYPE_NULL},
};

#define NUM_ATTR (sizeof(attrs)/sizeof(struct radius_attribute))

#define RADIUS_VENDOR_SPECIFIC 26
#define SKIP_HDR_LEN 6

/* decode MSID from SSE */

/* MSID is encoded in Binary Coded Decimal format
   First  Byte: [odd-indicator] [Digit 1]
   Second Byte: [Digit 3] [Digit 2]
   ..
   if[odd]
   Last Byte: [Digit N] [Digit N-1]
   else
   Last Byte: [F] [Digit N]
*/
static void
decode_sse(proto_tree* ext_tree, tvbuff_t* tvb, int offset, guint ext_len)
{
    guint8 msid_len;
    guint8 msid_start_offset;
    guint8 msid_num_digits;
    guint8 msid_index;
    char  *msid_digits;
    const char* p_msid;
    gboolean odd_even_ind;

    /* Decode Protocol Type */
    if (ext_len < 2)
    {
        proto_tree_add_text(ext_tree, tvb, offset, 0,
                    "Cannot decode Protocol Type - SSE too short");
        return;
    }
    proto_tree_add_item(ext_tree, hf_a11_ses_ptype, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    ext_len -= 2;

    /* Decode Session Key */
    if (ext_len < 4)
    {
        proto_tree_add_text(ext_tree, tvb, offset, 0,
                    "Cannot decode Session Key - SSE too short");
        return;
    }
    proto_tree_add_item(ext_tree, hf_a11_ses_key, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    ext_len -= 4;


    /* Decode Session Id Version */
    if (ext_len < 2)
    {
        proto_tree_add_text(ext_tree, tvb, offset, 0,
                    "Cannot decode Session Id Version - SSE too short");
        return;
    }
    proto_tree_add_item(ext_tree, hf_a11_ses_sidver, tvb, offset+1, 1, ENC_BIG_ENDIAN);
    offset += 2;
    ext_len -= 2;


    /* Decode SRID */
    if (ext_len < 2)
    {
        proto_tree_add_text(ext_tree, tvb, offset, 0,
                    "Cannot decode SRID - SSE too short");
        return;
    }
    proto_tree_add_item(ext_tree, hf_a11_ses_mnsrid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    ext_len -= 2;

    /* MSID Type */
    if (ext_len < 2)
    {
        proto_tree_add_text(ext_tree, tvb, offset, 0,
                    "Cannot decode MSID Type - SSE too short");
        return;
    }
    proto_tree_add_item(ext_tree, hf_a11_ses_msid_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    ext_len -= 2;


    /* MSID Len */
    if (ext_len < 1)
    {
        proto_tree_add_text(ext_tree, tvb, offset, 0,
                    "Cannot decode MSID Length - SSE too short");
        return;
    }
    msid_len =  tvb_get_guint8(tvb, offset);
    proto_tree_add_item(ext_tree, hf_a11_ses_msid_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    ext_len -= 1;

    /* Decode MSID */
    if (ext_len < msid_len)
    {
        proto_tree_add_text(ext_tree, tvb, offset, 0,
                    "Cannot decode MSID - SSE too short");
        return;
    }

    msid_digits = ep_alloc(A11_MSG_MSID_LEN_MAX+2);
    msid_start_offset = offset;

    if(msid_len > A11_MSG_MSID_ELEM_LEN_MAX)
    {
        p_msid = "MSID is too long";
    }else if(msid_len == 0)
    {
        p_msid = "MSID is too short";
    }else
    {
        /* Decode the BCD digits */
        for(msid_index=0; msid_index<msid_len; msid_index++)
        {
            guint8 msid_digit = tvb_get_guint8(tvb, offset);
            offset += 1;
            ext_len -= 1;

            msid_digits[msid_index*2] = (msid_digit & 0x0F) + '0';
            msid_digits[(msid_index*2) + 1] = ((msid_digit & 0xF0) >> 4) + '0';
        }

        odd_even_ind = (msid_digits[0] == '1');

        if(odd_even_ind)
        {
            msid_num_digits = ((msid_len-1) * 2) + 1;
        }else
        {
            msid_num_digits = (msid_len-1) * 2;
        }

        msid_digits[msid_num_digits + 1] = '\0';
        p_msid = msid_digits + 1;
    }


    proto_tree_add_string
        (ext_tree, hf_a11_ses_msid, tvb, msid_start_offset, msid_len, p_msid);

    return;
}


/* RADIUS attributed */
static void
dissect_a11_radius( tvbuff_t *tvb, int offset, proto_tree *tree, int app_len)
{
    proto_item *ti;
    proto_tree *radius_tree;
    gint       radius_len;
    guint8     radius_type;
    guint8     radius_subtype;
    int        attribute_type;
    gint       attribute_len;
    gint       offset0;
    gint       radius_offset;
    guint      i;
    guint8     *str_val;
    guint      radius_vendor_id;

    /* None of this really matters if we don't have a tree */
    if (!tree) return;

    offset0 = offset;

    /* return if length of extension is not valid */
    if (tvb_reported_length_remaining(tvb, offset)  < 12) {
        return;
    }

    ti = proto_tree_add_text(tree, tvb, offset - 2, app_len, "Airlink Record");

    radius_tree = proto_item_add_subtree(ti, ett_a11_radiuses);

    /* And, handle each record */
    while ((tvb_reported_length_remaining(tvb, offset) > 0)
           && ((offset-offset0) < (app_len-2)))
    {

        radius_type = tvb_get_guint8(tvb, offset);
        radius_len = tvb_get_guint8(tvb, offset + 1);
        if (radius_len < 2)
        {
            proto_tree_add_text(radius_tree, tvb, offset, 2,
                "Bogus RADIUS length %u, should be >= 2",
                radius_len);
            break;
        }

        if (radius_type == RADIUS_VENDOR_SPECIFIC)
        {
            if (radius_len < SKIP_HDR_LEN)
            {
                proto_tree_add_text(radius_tree, tvb, offset, radius_len,
                    "Bogus RADIUS length %u, should be >= %u",
                     radius_len, SKIP_HDR_LEN);
                offset += radius_len;
                continue;
            }
            radius_vendor_id = tvb_get_ntohl(tvb, offset +2);

            if(radius_vendor_id != VENDOR_THE3GPP2)
            {
                proto_tree_add_text(radius_tree, tvb, offset, radius_len,
                                    "Unknown Vendor-specific Attribute (Vendor Id: %x)", radius_vendor_id);
                offset += radius_len;
                continue;
            }
        }
        else
        {

            /**** ad-hoc ***/
            if(radius_type == 31)
            {
                str_val = tvb_get_ephemeral_string(tvb,offset+2,radius_len-2);
                proto_tree_add_text(radius_tree, tvb, offset, radius_len,
                                    "MSID: %s", str_val);
            }
            else if (radius_type == 46)
            {
                if (radius_len < (2+4))
                {
                    proto_tree_add_text(radius_tree, tvb, offset, radius_len,
                                        "Bogus RADIUS length %u, should be >= %u",
                                        radius_len, 2+4);
                }
                else
                {
                    proto_tree_add_text(radius_tree, tvb, offset, radius_len,
                                        "Acct Session Time: %d",tvb_get_ntohl(tvb,offset+2));
                }
            }
            else
            {
                proto_tree_add_text(radius_tree, tvb, offset, radius_len,
                                    "Unknown RADIUS Attributes (Type: %d)", radius_type);
            }

            offset += radius_len;
            continue;
        }

        offset += SKIP_HDR_LEN;
        radius_len -= SKIP_HDR_LEN;
        radius_offset = 0;

        /* Detect Airlink Record Type */

        while (radius_len > radius_offset)
        {
            if (radius_len < (radius_offset + 2))
            {
                proto_tree_add_text(radius_tree, tvb, offset + radius_offset, 2,
                                    "Bogus RADIUS length %u, should be >= %u",
                                    radius_len + SKIP_HDR_LEN,
                                    radius_offset + 2 + SKIP_HDR_LEN);
                return;
            }

            radius_subtype = tvb_get_guint8(tvb, offset + radius_offset);
            attribute_len = tvb_get_guint8(tvb, offset + radius_offset + 1);
            if (attribute_len < 2)
            {
                proto_tree_add_text(radius_tree, tvb, offset + radius_offset, 2,
                                    "Bogus attribute length %u, should be >= 2", attribute_len);
                return;
            }
            if (attribute_len > (radius_len - radius_offset))
            {
                proto_tree_add_text(radius_tree, tvb, offset + radius_offset, 2,
                                    "Bogus attribute length %u, should be <= %u",
                                    attribute_len, radius_len - radius_offset);
                return;
            }

            attribute_type = -1;
            for(i = 0; i < NUM_ATTR; i++) {
                if (attrs[i].subtype == radius_subtype) {
                    attribute_type = i;
                    break;
                }
            }

            if ((radius_subtype == 48) &&
                (attribute_len == 0x0a))
            {
                /*
                 * trying to compensate for Spec. screwups where
                 * certain versions had subtype 48 being a 4 octet integer
                 * and others had it being a 15 octet string!
                 */
                str_val = tvb_get_ephemeral_string(tvb,offset+radius_offset+2,attribute_len-2);
                proto_tree_add_text(radius_tree, tvb, offset+radius_offset,
                                    attribute_len,
                                    "3GPP2: ESN-48 (String) (%s)", str_val);
            }
            else if(attribute_type >= 0) {
                switch(attrs[attribute_type].data_type) {
                case ATTR_TYPE_INT:
                    proto_tree_add_text(radius_tree, tvb, offset + radius_offset,
                                        attribute_len, "3GPP2: %s (0x%04x)", attrs[attribute_type].attrname,
                                        tvb_get_ntohl(tvb,offset + radius_offset + 2));
                    break;
                case ATTR_TYPE_IPV4:
                    proto_tree_add_text(radius_tree, tvb, offset + radius_offset,
                                        attribute_len, "3GPP2: %s (%s)", attrs[attribute_type].attrname,
                                        tvb_ip_to_str(tvb, offset + radius_offset + 2));
                    break;
                case ATTR_TYPE_TYPE:
                    proto_tree_add_text(radius_tree, tvb, offset + radius_offset,
                                        attribute_len, "3GPP2: %s (%s)", attrs[attribute_type].attrname,
                                        val_to_str(tvb_get_ntohl(tvb,offset+radius_offset+2),
                                                   a11_airlink_types,"Unknown"));
                    break;
                case ATTR_TYPE_STR:
                    str_val = tvb_get_ephemeral_string(tvb,offset+radius_offset+2,attribute_len-2);
                    proto_tree_add_text(radius_tree, tvb, offset+radius_offset,
                                        attribute_len,
                                        "3GPP2: %s (%s)", attrs[attribute_type].attrname, str_val);
                    break;
                case ATTR_TYPE_NULL:
                    break;
                default:
                    proto_tree_add_text(radius_tree, tvb, offset+radius_offset, attribute_len,
                                        "RADIUS: %s", attrs[attribute_type].attrname);
                    break;
                }
            }
            else {
                proto_tree_add_text(radius_tree, tvb, offset+radius_offset, attribute_len,
                                    "RADIUS: Unknown 3GPP2 Attribute (Type:%d, SubType:%d)",
                                    radius_type,radius_subtype);
            }

            radius_offset += attribute_len;
        }
        offset += radius_len;

    }

}


/* Code to dissect Additional Session Info */
static void dissect_ase(tvbuff_t* tvb, int offset, guint ase_len, proto_tree* ext_tree)
{
   guint clen = 0; /* consumed length */

   while(clen < ase_len)
   {
      proto_tree* exts_tree;
      guint8 srid = tvb_get_guint8(tvb, offset+clen+1);
      guint16 service_option =tvb_get_ntohs(tvb,offset+clen+2);
      proto_item *ti;

      if(registration_request_msg && (service_option==64 || service_option==67)){
          if(service_option == 67){
              guint8 profile_count=tvb_get_guint8(tvb, offset+clen+20);
              guint8 reverse_profile_count=tvb_get_guint8(tvb, offset+clen+20+(profile_count*2)+1+6);

      	      ti = proto_tree_add_text(ext_tree, tvb, offset+clen, 0x0D+1+6+(profile_count*2)+1+6+(reverse_profile_count*2)+1,
                   "GRE Key Entry (SRID: %d)", srid);
      	  } else if(service_option== 64){
              ti = proto_tree_add_text(ext_tree, tvb, offset+clen, 0x0D+1+2, "GRE Key Entry (SRID: %d)", srid);
      	  } else {
              ti = proto_tree_add_text(ext_tree, tvb, 0, 0, "Unknown service option %u (SRID: %d)", service_option, srid);
          }
      }else{
          ti = proto_tree_add_text(ext_tree, tvb, offset+clen, 0x0D+1, "GRE Key Entry (SRID: %d)", srid);
      }

      exts_tree = proto_item_add_subtree(ti, ett_a11_ase);

      /* Entry Length */
      proto_tree_add_item(exts_tree, hf_a11_ase_len_type, tvb, offset+clen, 1, ENC_BIG_ENDIAN);
      clen++;

      /* SRID */
      proto_tree_add_item(exts_tree, hf_a11_ase_srid_type, tvb, offset+clen, 1, ENC_BIG_ENDIAN);
      clen++;

      /* Service Option */
      proto_tree_add_item(exts_tree, hf_a11_ase_servopt_type, tvb, offset+clen, 2, ENC_BIG_ENDIAN);
      clen+=2;

      /* GRE Protocol Type*/
      proto_tree_add_item(exts_tree, hf_a11_ase_gre_proto_type, tvb, offset+clen, 2, ENC_BIG_ENDIAN);
      clen+=2;

      /* GRE Key */
      proto_tree_add_item(exts_tree, hf_a11_ase_gre_key, tvb, offset+clen, 4, ENC_BIG_ENDIAN);
      clen+=4;

      /* PCF IP Address */
      proto_tree_add_item(exts_tree, hf_a11_ase_pcf_addr_key, tvb, offset+clen, 4, ENC_BIG_ENDIAN);
      clen+=4;

      if(registration_request_msg){
          if(service_option == 0x0043){
			  proto_item* tl;
			  proto_tree* extv_tree;
		      guint8 profile_count=tvb_get_guint8(tvb, offset+clen+6);
              guint8 profile_index=0;
			  guint8 reverse_profile_count;

              proto_item* tj = proto_tree_add_text(exts_tree, tvb, offset+clen,6+(profile_count*2)+1, "Forward ROHC Info");

              proto_tree* extt_tree = proto_item_add_subtree(tj, ett_a11_forward_rohc);

              proto_tree_add_item(extt_tree, hf_a11_ase_forward_rohc_info_len, tvb, offset+clen, 1, FALSE);
              clen++;


              proto_tree_add_item(extt_tree, hf_a11_ase_forward_maxcid, tvb, offset+clen, 2, FALSE);
              clen+=2;
              proto_tree_add_item(extt_tree, hf_a11_ase_forward_mrru, tvb, offset+clen, 2, FALSE);
              clen+=2;
              proto_tree_add_item(extt_tree, hf_a11_ase_forward_large_cids, tvb, offset+clen, 1, FALSE);
              clen++;
              profile_count=tvb_get_guint8(tvb, offset+clen);

              proto_tree_add_item(extt_tree, hf_a11_ase_forward_profile_count, tvb, offset+clen, 1, FALSE);
              clen++;


              for(profile_index=0; profile_index<profile_count; profile_index++){
      	          proto_item* tk = proto_tree_add_text (extt_tree, tvb, offset+clen, (2*profile_count), "Forward Profile : %d", profile_index);
                  proto_tree* extu_tree = proto_item_add_subtree(tk, ett_a11_forward_profile);
                  proto_tree_add_item(extu_tree, hf_a11_ase_forward_profile, tvb, offset+clen, 2, FALSE);
                  clen+=2;
              }/*for*/


              reverse_profile_count=tvb_get_guint8(tvb, offset+clen+6);

              tl = proto_tree_add_text(exts_tree, tvb, offset+clen,6+(reverse_profile_count*2)+1, "Reverse ROHC Info");

              extv_tree = proto_item_add_subtree(tl, ett_a11_reverse_rohc);

              proto_tree_add_item(extv_tree, hf_a11_ase_reverse_rohc_info_len, tvb, offset+clen, 1, FALSE);
              clen++;


              proto_tree_add_item(extv_tree, hf_a11_ase_reverse_maxcid, tvb, offset+clen, 2, FALSE);
              clen+=2;
              proto_tree_add_item(extv_tree, hf_a11_ase_reverse_mrru, tvb, offset+clen, 2, FALSE);
              clen+=2;
              proto_tree_add_item(extv_tree, hf_a11_ase_reverse_large_cids, tvb, offset+clen, 1, FALSE);
              clen++;

              profile_count=tvb_get_guint8(tvb, offset+clen);

              proto_tree_add_item(extv_tree, hf_a11_ase_reverse_profile_count, tvb, offset+clen, 1, FALSE);
              clen++;


              for(profile_index=0; profile_index<reverse_profile_count; profile_index++){
                  proto_item* tm = proto_tree_add_text(extv_tree, tvb, offset+clen, (2*profile_count), "Reverse Profile : %d", profile_index);

                  proto_tree* extw_tree = proto_item_add_subtree(tm, ett_a11_reverse_profile);

                  proto_tree_add_item(extw_tree, hf_a11_ase_reverse_profile, tvb, offset+clen, 2, FALSE);
                  clen+=2;


              }/*for*/
	   }else if(service_option==0x0040){
/*		guint8 zero =tvb_get_guint8(tvb,offset+clen);
		zero =0;
		proto_item* tj = proto_tree_add_text
                        (exts_tree, tvb, offset+clen,1, "Forward ROHC Info:0",zero);
		clen++;
		zero =tvb_get_guint8(tvb,offset+clen);
		proto_item* tl = proto_tree_add_text
                        (exts_tree, tvb, offset+clen,1, "Reverse ROHC Info:0",zero);
		clen++;
*/
		clen+=2;
	  }/*else-if*/

	}/* if */

   }/*while*/

registration_request_msg =0;
}


#define A11_FQI_IPFLOW_DISC_ENABLED 0x80
#define A11_FQI_DSCP_INCLUDED 0x40

static void dissect_fwd_qosinfo_flags
       (tvbuff_t* tvb, int offset, proto_tree* ext_tree, guint8* p_dscp_included)
{
    guint8 flags = tvb_get_guint8(tvb, offset);
    guint8 nbits = sizeof(flags) * 8;

    proto_item* ti = proto_tree_add_text(ext_tree, tvb, offset, sizeof(flags),
                                         "Flags: %#02x", flags);

    proto_tree* flags_tree = proto_item_add_subtree(ti, ett_a11_fqi_flags);

    proto_tree_add_text(flags_tree, tvb, offset, sizeof(flags), "%s",
                        decode_boolean_bitfield(flags, A11_FQI_IPFLOW_DISC_ENABLED, nbits,
                                                "IP Flow Discriminator Enabled", "IP Flow Discriminator Disabled"));

    proto_tree_add_text(flags_tree, tvb, offset, sizeof(flags), "%s",
                        decode_boolean_bitfield(flags, A11_FQI_DSCP_INCLUDED, nbits,
                                                "DSCP Included", "DSCP Not Included"));
    if(flags & A11_FQI_DSCP_INCLUDED)
    {
        *p_dscp_included = 1;
    }else
    {
        *p_dscp_included = 0;
    }
}


#define A11_FQI_DSCP 0x7E
#define A11_FQI_FLOW_STATE 0x01

static void dissect_fqi_entry_flags
       (tvbuff_t* tvb, int offset, proto_tree* ext_tree, guint8 dscp_enabled)
{
    guint8 dscp = tvb_get_guint8(tvb, offset);
    guint8 nbits = sizeof(dscp) * 8;

    proto_item* ti = proto_tree_add_text(ext_tree, tvb, offset, sizeof(dscp),
                                         "DSCP and Flow State: %#02x", dscp);

    proto_tree* flags_tree = proto_item_add_subtree(ti, ett_a11_fqi_entry_flags);

    if(dscp_enabled)
    {
        proto_tree_add_text(flags_tree, tvb, offset, sizeof(dscp), "%s",
                            decode_numeric_bitfield(dscp, A11_FQI_DSCP, nbits,
                                                    "DSCP: %u"));
    }

    proto_tree_add_text(flags_tree, tvb, offset, sizeof(dscp), "%s",
                        decode_boolean_bitfield(dscp, A11_FQI_FLOW_STATE, nbits,
                                                "Flow State: Active", "Flow State: Inactive"));
}


#define A11_RQI_FLOW_STATE 0x01

static void dissect_rqi_entry_flags
       (tvbuff_t* tvb, int offset, proto_tree* ext_tree)
{
    guint8 flags = tvb_get_guint8(tvb, offset);
    guint8 nbits = sizeof(flags) * 8;

    proto_item* ti = proto_tree_add_text(ext_tree, tvb, offset, sizeof(flags),
                                         "Flags: %#02x", flags);

    proto_tree* flags_tree = proto_item_add_subtree(ti, ett_a11_rqi_entry_flags);

    proto_tree_add_text(flags_tree, tvb, offset, sizeof(flags), "%s",
                        decode_boolean_bitfield(flags, A11_RQI_FLOW_STATE, nbits,
                                                "Flow State: Active", "Flow State: Inactive"));
}

/* Code to dissect Forward QoS Info */
static void dissect_fwd_qosinfo(tvbuff_t* tvb, int offset, proto_tree* ext_tree)
{
    int clen = 0; /* consumed length */
    guint8 flow_count;
    guint8 flow_index;
    guint8 dscp_enabled = 0;

    /* SR Id */
    proto_tree_add_item(ext_tree, hf_a11_fqi_srid, tvb, offset+clen, 1, ENC_BIG_ENDIAN);
    clen++;

    /* Flags */
    dissect_fwd_qosinfo_flags(tvb, offset+clen, ext_tree, &dscp_enabled);
    clen++;

    /* Flow Count */
    flow_count = tvb_get_guint8(tvb, offset+clen);
    flow_count &= 0x1F;
    proto_tree_add_item(ext_tree, hf_a11_fqi_flowcount, tvb, offset+clen, 1, ENC_BIG_ENDIAN);
    clen++;

    for(flow_index=0; flow_index<flow_count; flow_index++)
    {
        guint8 requested_qos_len = 0;
        guint8 granted_qos_len = 0;

        guint8 entry_len = tvb_get_guint8(tvb, offset+clen);
        guint8 flow_id = tvb_get_guint8(tvb, offset+clen+1);

        proto_item* ti = proto_tree_add_text
            (ext_tree, tvb, offset+clen, entry_len+1, "Forward Flow Entry (Flow Id: %d)", flow_id);

        proto_tree* exts_tree = proto_item_add_subtree(ti, ett_a11_fqi_flowentry);

        /* Entry Length */
        proto_tree_add_item(exts_tree, hf_a11_fqi_entrylen, tvb, offset+clen, 1, ENC_BIG_ENDIAN);
        clen++;

        /* Flow Id */
        proto_tree_add_item(exts_tree, hf_a11_fqi_flowid, tvb, offset+clen, 1, ENC_BIG_ENDIAN);
        clen++;

        /* DSCP and Flow State*/
        dissect_fqi_entry_flags(tvb, offset+clen, exts_tree, dscp_enabled);
        clen++;


        /* Requested QoS Length */
        requested_qos_len = tvb_get_guint8(tvb, offset+clen);
        proto_tree_add_item(exts_tree, hf_a11_fqi_requested_qoslen, tvb, offset+clen, 1, ENC_BIG_ENDIAN);
        clen++;

        /* Requested QoS Blob */
        if(requested_qos_len)
        {
            proto_item* ti2;
            proto_tree* exts_tree2;

      	    proto_item* ti1 = proto_tree_add_text(ext_tree, tvb, offset+clen,requested_qos_len, "Forward Requested QoS ");
      	    proto_tree* exts_tree1 = proto_item_add_subtree(ti1, ett_a11_fqi_requestedqos);

            proto_tree_add_text(exts_tree1, tvb, offset+clen, requested_qos_len, "Forward Requested QoS Sub Blob");

            /* Flow Priority */
            proto_tree_add_item(exts_tree1, hf_a11_fqi_flow_priority, tvb,offset+clen , 1, FALSE);
			
            /*  Num of QoS attribute sets */
            proto_tree_add_item(exts_tree1, hf_a11_fqi_num_qos_attribute_set, tvb, offset+clen, 1, FALSE);

            /* QoS attribute set length */
            proto_tree_add_item(exts_tree1, hf_a11_fqi_qos_attribute_setlen, tvb, offset+clen, 2, FALSE);
            clen++;

            /* QoS attribute set */
            ti2 = proto_tree_add_text(exts_tree1, tvb, offset+clen, 4, "QoS Attribute Set");
            exts_tree2 = proto_item_add_subtree(ti2, ett_a11_fqi_qos_attribute_set);
			
            /* QoS attribute setid */
            proto_tree_add_item(exts_tree2, hf_a11_fqi_qos_attribute_setid, tvb, offset+clen, 2, FALSE);
            clen++;

            /* verbose */
            proto_tree_add_item(exts_tree2, hf_a11_fqi_verbose, tvb,offset+clen, 1, FALSE);

            /* Flow profile id */
            proto_tree_add_item(exts_tree2, hf_a11_fqi_flow_profileid, tvb, offset+clen, 3, FALSE);
            clen += 3;

        }

        /* Granted QoS Length */
        granted_qos_len = tvb_get_guint8(tvb, offset+clen);
        proto_tree_add_item(exts_tree, hf_a11_fqi_granted_qoslen, tvb, offset+clen, 1, ENC_BIG_ENDIAN);
        clen++;

        /* Granted QoS Blob */
        if(granted_qos_len)
        {
            proto_item* ti3;
            proto_tree* exts_tree3;

            ti3 = proto_tree_add_text(ext_tree, tvb, offset+clen, granted_qos_len, "Forward Granted QoS ");

            exts_tree3 = proto_item_add_subtree(ti3, ett_a11_fqi_grantedqos);

            proto_tree_add_text(exts_tree3, tvb, offset+clen, granted_qos_len, "Forward Granted QoS Sub Blob");

            /* QoS attribute setid */
            proto_tree_add_item(exts_tree3, hf_a11_fqi_qos_granted_attribute_setid, tvb, offset+clen, 1, TRUE);
            clen++;
        }
    }
}

/* Code to dissect Reverse QoS Info */
static void dissect_rev_qosinfo(tvbuff_t* tvb, int offset, proto_tree* ext_tree)
{
    int clen = 0; /* consumed length */
    guint8 flow_count;
    guint8 flow_index;

    /* SR Id */
    proto_tree_add_item(ext_tree, hf_a11_rqi_srid, tvb, offset+clen, 1, ENC_BIG_ENDIAN);
    clen++;

    /* Flow Count */
    flow_count = tvb_get_guint8(tvb, offset+clen);
    flow_count &= 0x1F;
    proto_tree_add_item(ext_tree, hf_a11_rqi_flowcount, tvb, offset+clen, 1, ENC_BIG_ENDIAN);
    clen++;

    for(flow_index=0; flow_index<flow_count; flow_index++)
    {
        guint8 requested_qos_len;
        guint8 granted_qos_len;

        guint8 entry_len = tvb_get_guint8(tvb, offset+clen);
        guint8 flow_id = tvb_get_guint8(tvb, offset+clen+1);

        proto_item* ti = proto_tree_add_text
            (ext_tree, tvb, offset+clen, entry_len+1, "Reverse Flow Entry (Flow Id: %d)", flow_id);

        proto_tree* exts_tree = proto_item_add_subtree(ti, ett_a11_rqi_flowentry);

        /* Entry Length */
        proto_tree_add_item(exts_tree, hf_a11_rqi_entrylen, tvb, offset+clen, 1, ENC_BIG_ENDIAN);
        clen++;

        /* Flow Id */
        proto_tree_add_item(exts_tree, hf_a11_rqi_flowid, tvb, offset+clen, 1, ENC_BIG_ENDIAN);
        clen++;

        /* Flags */
        dissect_rqi_entry_flags(tvb, offset+clen, exts_tree);
        clen++;

        /* Requested QoS Length */
        requested_qos_len = tvb_get_guint8(tvb, offset+clen);
        proto_tree_add_item(exts_tree, hf_a11_rqi_requested_qoslen, tvb, offset+clen, 1, ENC_BIG_ENDIAN);
        clen++;

        /* Requested QoS Blob */
        if(requested_qos_len)
        {
            proto_item *ti1, *ti2;
            proto_tree *exts_tree1, *exts_tree2;

			ti1 = proto_tree_add_text(ext_tree, tvb, offset+clen,requested_qos_len , "Reverse Requested QoS ");

            exts_tree1 = proto_item_add_subtree(ti1, ett_a11_rqi_requestedqos);

            proto_tree_add_text(exts_tree1, tvb, offset+clen, requested_qos_len, "Reverse Requested QoS Sub Blob");

            /* Flow Priority */
            proto_tree_add_item(exts_tree1, hf_a11_rqi_flow_priority, tvb,offset+clen , 1, FALSE);

            /*  Num of QoS attribute sets */
            proto_tree_add_item(exts_tree1, hf_a11_rqi_num_qos_attribute_set, tvb, offset+clen, 1, FALSE);

            /* QoS attribute set length */
            proto_tree_add_item(exts_tree1, hf_a11_rqi_qos_attribute_setlen, tvb, offset+clen, 2, FALSE);
            clen++;

            /* QoS attribute set */
            ti2 = proto_tree_add_text(exts_tree1, tvb, offset+clen, 4, "QoS Attribute Set");
            exts_tree2 = proto_item_add_subtree(ti2, ett_a11_rqi_qos_attribute_set);

            /* QoS attribute setid */
            proto_tree_add_item(exts_tree2, hf_a11_rqi_qos_attribute_setid, tvb, offset+clen, 2, FALSE);
            clen++;

            /* verbose */
            proto_tree_add_item(exts_tree2, hf_a11_rqi_verbose, tvb,offset+clen, 1, FALSE);

            /* Flow profile id */
            proto_tree_add_item(exts_tree2, hf_a11_rqi_flow_profileid, tvb, offset+clen, 3, FALSE);
            clen += 3;
        }

        /* Granted QoS Length */
        granted_qos_len = tvb_get_guint8(tvb, offset+clen);
        proto_tree_add_item(exts_tree, hf_a11_rqi_granted_qoslen, tvb, offset+clen, 1, ENC_BIG_ENDIAN);
        clen++;

        /* Granted QoS Blob */
        if(granted_qos_len)
        {
            proto_item* ti3;
            proto_tree* exts_tree3;

            ti3 = proto_tree_add_text(ext_tree, tvb, offset+clen,granted_qos_len , "Reverse Granted QoS ");
            exts_tree3 = proto_item_add_subtree(ti3, ett_a11_rqi_grantedqos);

            proto_tree_add_text(exts_tree3, tvb, offset+clen, granted_qos_len, "Reverse Granted QoS Sub Blob");

            /* QoS attribute setid */
            proto_tree_add_item(exts_tree3, hf_a11_rqi_qos_granted_attribute_setid, tvb, offset+clen, 1, TRUE);
            clen++;
        }
    }
}


/* Code to dissect Subscriber QoS Profile */
static void dissect_subscriber_qos_profile(tvbuff_t* tvb, int offset, int ext_len, proto_tree* ext_tree)
{
    proto_tree* exts_tree;

    int qos_profile_len = ext_len;

    proto_item* ti =
        proto_tree_add_text (ext_tree, tvb, offset, 0,
                             "Subscriber Qos Profile (%d bytes)",
                             qos_profile_len);

    exts_tree = proto_item_add_subtree(ti, ett_a11_subscriber_profile);

    /* Subscriber QoS profile */
    if(qos_profile_len)
    {
        proto_tree_add_item
            (exts_tree,  hf_a11_subsciber_profile, tvb, offset,
             qos_profile_len, ENC_NA);
    }
}

/* Code to dissect Forward QoS Update Info */
static void dissect_fwd_qosupdate_info(tvbuff_t* tvb, int offset, proto_tree* ext_tree)
{
    int clen = 0; /* consumed length */
    guint8 flow_count;
    guint8 flow_index;

    /* Flow Count */
    flow_count = tvb_get_guint8(tvb, offset+clen);
    proto_tree_add_item(ext_tree, hf_a11_fqui_flowcount, tvb, offset+clen, 1, ENC_BIG_ENDIAN);
    clen++;

    for(flow_index=0; flow_index<flow_count; flow_index++)
    {
        proto_tree* exts_tree;
        guint8 granted_qos_len;

        guint8 flow_id = tvb_get_guint8(tvb, offset+clen);

        proto_item* ti = proto_tree_add_text
            (ext_tree, tvb, offset+clen, 1, "Forward Flow Entry (Flow Id: %d)", flow_id);

        clen++;
        exts_tree = proto_item_add_subtree(ti, ett_a11_fqui_flowentry);

        /* Forward QoS Sub Blob Length */
        granted_qos_len = tvb_get_guint8(tvb, offset+clen);
        proto_tree_add_item
            (exts_tree, hf_a11_fqui_updated_qoslen, tvb, offset+clen, 1, ENC_BIG_ENDIAN);
        clen++;

        /* Forward QoS Sub Blob */
        if(granted_qos_len)
        {
            proto_tree_add_item
                (exts_tree, hf_a11_fqui_updated_qos, tvb, offset+clen,
                 granted_qos_len, ENC_NA);
            clen += granted_qos_len;
        }
    }
}


/* Code to dissect Reverse QoS Update Info */
static void dissect_rev_qosupdate_info(tvbuff_t* tvb, int offset, proto_tree* ext_tree)
{
    int clen = 0; /* consumed length */
    guint8 flow_count;
    guint8 flow_index;

    /* Flow Count */
    flow_count = tvb_get_guint8(tvb, offset+clen);
    proto_tree_add_item(ext_tree, hf_a11_rqui_flowcount, tvb, offset+clen, 1, ENC_BIG_ENDIAN);
    clen++;

    for(flow_index=0; flow_index<flow_count; flow_index++)
    {
        proto_tree* exts_tree;
        guint8 granted_qos_len;

        guint8 flow_id = tvb_get_guint8(tvb, offset+clen);

        proto_item* ti = proto_tree_add_text
            (ext_tree, tvb, offset+clen, 1, "Reverse Flow Entry (Flow Id: %d)", flow_id);
        clen++;
        exts_tree = proto_item_add_subtree(ti, ett_a11_rqui_flowentry);

        /* Reverse QoS Sub Blob Length */
        granted_qos_len = tvb_get_guint8(tvb, offset+clen);
        proto_tree_add_item
            (exts_tree, hf_a11_rqui_updated_qoslen, tvb, offset+clen, 1, ENC_BIG_ENDIAN);
        clen++;

        /* Reverse QoS Sub Blob */
        if(granted_qos_len)
        {
            proto_tree_add_item
                (exts_tree, hf_a11_rqui_updated_qos, tvb, offset+clen,
                 granted_qos_len, ENC_NA);
            clen += granted_qos_len;
        }
    }
}

/* Code to dissect extensions */
static void
dissect_a11_extensions( tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_item   *ti;
    proto_tree   *exts_tree;
    proto_tree   *ext_tree;
    guint         ext_len;
    guint8        ext_type;
    guint8        ext_subtype = 0;
    guint         hdrLen;

    gint16       apptype = -1;

    /* None of this really matters if we don't have a tree */
    if (!tree) return;

    /* Add our tree, if we have extensions */
    ti = proto_tree_add_text(tree, tvb, offset, -1, "Extensions");
    exts_tree = proto_item_add_subtree(ti, ett_a11_exts);

    /* And, handle each extension */
    while (tvb_reported_length_remaining(tvb, offset) > 0) {

        /* Get our extension info */
        ext_type = tvb_get_guint8(tvb, offset);
        if (ext_type == GEN_AUTH_EXT) {
            /*
             * Very nasty . . breaks normal extensions, since the length is
             * in the wrong place :(
             */
            ext_subtype = tvb_get_guint8(tvb, offset + 1);
            ext_len = tvb_get_ntohs(tvb, offset + 2);
            hdrLen = 4;
        } else if ((ext_type == CVSE_EXT) || (ext_type == OLD_CVSE_EXT)) {
            ext_len = tvb_get_ntohs(tvb, offset + 2);
            ext_subtype = tvb_get_guint8(tvb, offset + 8);
            hdrLen = 4;
        } else {
            ext_len = tvb_get_guint8(tvb, offset + 1);
            hdrLen = 2;
        }

        ti = proto_tree_add_text(exts_tree, tvb, offset, ext_len + hdrLen,
                                 "Extension: %s",
                                 val_to_str(ext_type, a11_ext_types,
                                            "Unknown Extension %u"));
        ext_tree = proto_item_add_subtree(ti, ett_a11_ext);

        proto_tree_add_item(ext_tree, hf_a11_ext_type, tvb, offset, 1, ext_type);
        offset++;

        if (ext_type == SS_EXT) {
            proto_tree_add_uint(ext_tree, hf_a11_ext_len, tvb, offset, 1, ext_len);
            offset++;
        }
        else if((ext_type == CVSE_EXT) || (ext_type == OLD_CVSE_EXT)) {
            offset++;
            proto_tree_add_uint(ext_tree, hf_a11_ext_len, tvb, offset, 2, ext_len);
            offset+=2;
        }
        else if (ext_type != GEN_AUTH_EXT) {
            /* Another nasty hack since GEN_AUTH_EXT broke everything */
            proto_tree_add_uint(ext_tree, hf_a11_ext_len, tvb, offset, 1, ext_len);
            offset++;
        }

        switch(ext_type) {
        case SS_EXT:
            decode_sse(ext_tree, tvb, offset, ext_len);
            offset += ext_len;
            ext_len = 0;
            break;

        case MH_AUTH_EXT:
        case MF_AUTH_EXT:
        case FH_AUTH_EXT:
        case RU_AUTH_EXT:
            /* All these extensions look the same.  4 byte SPI followed by a key */
            if (ext_len < 4)
                break;
            proto_tree_add_item(ext_tree, hf_a11_aext_spi, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            ext_len -= 4;
            if (ext_len == 0)
                break;
            proto_tree_add_item(ext_tree, hf_a11_aext_auth, tvb, offset, ext_len,
                                ENC_NA);
            break;
        case MN_NAI_EXT:
            if (ext_len == 0)
                break;
            proto_tree_add_item(ext_tree, hf_a11_next_nai, tvb, offset,
                                ext_len, ENC_BIG_ENDIAN);
            break;

        case GEN_AUTH_EXT:      /* RFC 3012 */
            /*
             * Very nasty . . breaks normal extensions, since the length is
             * in the wrong place :(
             */
            proto_tree_add_uint(ext_tree, hf_a11_ext_stype, tvb, offset, 1, ext_subtype);
            offset++;
            proto_tree_add_uint(ext_tree, hf_a11_ext_len, tvb, offset, 2, ext_len);
            offset+=2;
            /* SPI */
            if (ext_len < 4)
                break;
            proto_tree_add_item(ext_tree, hf_a11_aext_spi, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            ext_len -= 4;
            /* Key */
            if (ext_len == 0)
                break;
            proto_tree_add_item(ext_tree, hf_a11_aext_auth, tvb, offset,
                                ext_len, ENC_NA);

            break;
        case OLD_CVSE_EXT:      /* RFC 3115 */
        case CVSE_EXT:          /* RFC 3115 */
            if (ext_len < 4)
                break;
            proto_tree_add_item(ext_tree, hf_a11_vse_vid, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            ext_len -= 4;
            if (ext_len < 2)
                break;
            apptype = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(ext_tree, hf_a11_vse_apptype, tvb, offset, 2, apptype);
            offset += 2;
            ext_len -= 2;
            if(apptype == 0x0101) {
                if (tvb_reported_length_remaining(tvb, offset) > 0) {
                    dissect_a11_radius(tvb, offset, ext_tree, ext_len + 2);
                }
            }
            break;
        case OLD_NVSE_EXT:      /* RFC 3115 */
        case NVSE_EXT:          /* RFC 3115 */
            if (ext_len < 6)
                break;
            proto_tree_add_item(ext_tree, hf_a11_vse_vid, tvb, offset+2, 4, ENC_BIG_ENDIAN);
            offset += 6;
            ext_len -= 6;
            proto_tree_add_item(ext_tree, hf_a11_vse_apptype, tvb, offset, 2, ENC_BIG_ENDIAN);

            if (ext_len < 2)
                break;
            apptype = tvb_get_ntohs(tvb, offset);
            offset += 2;
            ext_len -= 2;
            switch(apptype) {
            case 0x0401:
                if (ext_len < 5)
                    break;
                proto_tree_add_item(ext_tree, hf_a11_vse_panid, tvb, offset, 5, ENC_NA);
                offset += 5;
                ext_len -= 5;
                if (ext_len < 5)
                    break;
                proto_tree_add_item(ext_tree, hf_a11_vse_canid, tvb, offset, 5, ENC_NA);
                break;
            case 0x0501:
                if (ext_len < 4)
                    break;
                proto_tree_add_item(ext_tree, hf_a11_vse_ppaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
                break;
            case 0x0601:
                if (ext_len < 2)
                    break;
                proto_tree_add_item(ext_tree, hf_a11_vse_dormant, tvb, offset, 2, ENC_BIG_ENDIAN);
                break;
            case 0x0701:
                if (ext_len < 1)
                    break;
                proto_tree_add_item(ext_tree, hf_a11_vse_code, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;
            case 0x0801:
                if (ext_len < 1)
                    break;
                proto_tree_add_item(ext_tree, hf_a11_vse_pdit, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;
            case 0x0802:
                proto_tree_add_text(ext_tree, tvb, offset, -1, "Session Parameter - Always On");
                break;
            case 0x0803:
                proto_tree_add_item(ext_tree, hf_a11_vse_qosmode, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;
            case 0x0901:
                if (ext_len < 2)
                    break;
                proto_tree_add_item(ext_tree, hf_a11_vse_srvopt, tvb, offset, 2, ENC_BIG_ENDIAN);
                break;
            case 0x0C01:
                dissect_ase(tvb, offset, ext_len, ext_tree);
                break;
            case 0x0D01:
                dissect_fwd_qosinfo(tvb, offset, ext_tree);
                break;
            case 0x0D02:
                dissect_rev_qosinfo(tvb, offset, ext_tree);
                break;
            case 0x0D03:
                dissect_subscriber_qos_profile(tvb, offset, ext_len, ext_tree);
                break;
            case 0x0DFE:
                dissect_fwd_qosupdate_info(tvb, offset, ext_tree);
                break;
            case 0x0DFF:
                dissect_rev_qosupdate_info(tvb, offset, ext_tree);
                break;
            }

            break;
        case MF_CHALLENGE_EXT:  /* RFC 3012 */
            /* The default dissector is good here.  The challenge is all hex anyway. */
        default:
            proto_tree_add_item(ext_tree, hf_a11_ext, tvb, offset, ext_len, ENC_NA);
            break;
        } /* ext type */

        offset += ext_len;
    } /* while data remaining */

} /* dissect_a11_extensions */

/* Code to actually dissect the packets */
static int
dissect_a11( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Set up structures we will need to add the protocol subtree and manage it */
    proto_item   *ti;
    proto_tree   *a11_tree = NULL;
    proto_item   *tf;
    proto_tree   *flags_tree;
    guint8        type;
    guint8        flags;
    guint         offset=0;

    if (!tvb_bytes_exist(tvb, offset, 1))
        return 0;       /* not enough data to check message type */

    type = tvb_get_guint8(tvb, offset);
    if (match_strval(type, a11_types) == NULL)
        return 0;       /* not a known message type */

    /* Make entries in Protocol column and Info column on summary display */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "3GPP2 A11");
    col_clear(pinfo->cinfo, COL_INFO);

    if(type == REGISTRATION_REQUEST)
	    registration_request_msg =1;
    else
	    registration_request_msg =0;


  switch (type) {
  case REGISTRATION_REQUEST:

       registration_request_msg =1;
       col_add_fstr(pinfo->cinfo, COL_INFO, "Reg Request: PDSN=%s PCF=%s",
                     tvb_ip_to_str(tvb, 8),
                     tvb_ip_to_str(tvb, 12));

        if (tree) {
            ti = proto_tree_add_item(tree, proto_a11, tvb, offset, -1, ENC_BIG_ENDIAN);
            a11_tree = proto_item_add_subtree(ti, ett_a11);

            /* type */
            proto_tree_add_uint(a11_tree, hf_a11_type, tvb, offset, 1, type);
            offset++;

            /* flags */
            flags = tvb_get_guint8(tvb, offset);
            tf = proto_tree_add_uint(a11_tree, hf_a11_flags, tvb,
                                     offset, 1, flags);
            flags_tree = proto_item_add_subtree(tf, ett_a11_flags);
            proto_tree_add_boolean(flags_tree, hf_a11_s, tvb, offset, 1, flags);
            proto_tree_add_boolean(flags_tree, hf_a11_b, tvb, offset, 1, flags);
            proto_tree_add_boolean(flags_tree, hf_a11_d, tvb, offset, 1, flags);
            proto_tree_add_boolean(flags_tree, hf_a11_m, tvb, offset, 1, flags);
            proto_tree_add_boolean(flags_tree, hf_a11_g, tvb, offset, 1, flags);
            proto_tree_add_boolean(flags_tree, hf_a11_v, tvb, offset, 1, flags);
            proto_tree_add_boolean(flags_tree, hf_a11_t, tvb, offset, 1, flags);
            offset++;

            /* lifetime */
            proto_tree_add_item(a11_tree, hf_a11_life, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset +=2;

            /* home address */
            proto_tree_add_item(a11_tree, hf_a11_homeaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* home agent address */
            proto_tree_add_item(a11_tree, hf_a11_haaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Care of Address */
            proto_tree_add_item(a11_tree, hf_a11_coa, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Identifier - assumed to be an NTP time here */
            proto_tree_add_item(a11_tree, hf_a11_ident, tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
            offset += 8;

        } /* if tree */
        break;
    case REGISTRATION_REPLY:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Reg Reply:   PDSN=%s, Code=%u",
                      tvb_ip_to_str(tvb, 8), tvb_get_guint8(tvb,1));

        if (tree) {
            /* Add Subtree */
            ti = proto_tree_add_item(tree, proto_a11, tvb, offset, -1, ENC_BIG_ENDIAN);
            a11_tree = proto_item_add_subtree(ti, ett_a11);

            /* Type */
            proto_tree_add_uint(a11_tree, hf_a11_type, tvb, offset, 1, type);
            offset++;

            /* Reply Code */
            proto_tree_add_item(a11_tree, hf_a11_code, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            /* Registration Lifetime */
            proto_tree_add_item(a11_tree, hf_a11_life, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* Home address */
            proto_tree_add_item(a11_tree, hf_a11_homeaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Home Agent Address */
            proto_tree_add_item(a11_tree, hf_a11_haaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Identifier - assumed to be an NTP time here */
            proto_tree_add_item(a11_tree, hf_a11_ident, tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
            offset += 8;
        } /* if tree */

        break;
    case REGISTRATION_UPDATE:
        col_add_fstr(pinfo->cinfo, COL_INFO,"Reg Update:  PDSN=%s",
                     tvb_ip_to_str(tvb, 8));
        if (tree) {
            /* Add Subtree */
            ti = proto_tree_add_item(tree, proto_a11, tvb, offset, -1, ENC_BIG_ENDIAN);
            a11_tree = proto_item_add_subtree(ti, ett_a11);

            /* Type */
            proto_tree_add_uint(a11_tree, hf_a11_type, tvb, offset, 1, type);
            offset++;

            /* Reserved */
            offset+=3;

            /* Home address */
            proto_tree_add_item(a11_tree, hf_a11_homeaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Home Agent Address */
            proto_tree_add_item(a11_tree, hf_a11_haaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Identifier - assumed to be an NTP time here */
            proto_tree_add_item(a11_tree, hf_a11_ident, tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
            offset += 8;

        } /* if tree */
        break;
    case REGISTRATION_ACK:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Reg Ack:     PCF=%s Status=%u",
                     tvb_ip_to_str(tvb, 8),
                     tvb_get_guint8(tvb,3));
        if (tree) {
            /* Add Subtree */
            ti = proto_tree_add_item(tree, proto_a11, tvb, offset, -1, ENC_BIG_ENDIAN);
            a11_tree = proto_item_add_subtree(ti, ett_a11);

            /* Type */
            proto_tree_add_uint(a11_tree, hf_a11_type, tvb, offset, 1, type);
            offset++;

            /* Reserved */
            offset+=2;

            /* Ack Status */
            proto_tree_add_item(a11_tree, hf_a11_status, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            /* Home address */
            proto_tree_add_item(a11_tree, hf_a11_homeaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Care of Address */
            proto_tree_add_item(a11_tree, hf_a11_coa, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Identifier - assumed to be an NTP time here */
            proto_tree_add_item(a11_tree, hf_a11_ident, tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
            offset += 8;

        } /* if tree */
        break;
    case SESSION_UPDATE: /* IOS4.3 */
        col_add_fstr(pinfo->cinfo, COL_INFO,"Ses Update:  PDSN=%s",
                     tvb_ip_to_str(tvb, 8));
        if (tree) {
            /* Add Subtree */
            ti = proto_tree_add_item(tree, proto_a11, tvb, offset, -1, ENC_BIG_ENDIAN);
            a11_tree = proto_item_add_subtree(ti, ett_a11);

            /* Type */
            proto_tree_add_uint(a11_tree, hf_a11_type, tvb, offset, 1, type);
            offset++;

            /* Reserved */
            offset+=3;

            /* Home address */
            proto_tree_add_item(a11_tree, hf_a11_homeaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Home Agent Address */
            proto_tree_add_item(a11_tree, hf_a11_haaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Identifier - assumed to be an NTP time here */
            proto_tree_add_item(a11_tree, hf_a11_ident, tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
            offset += 8;

        } /* if tree */
        break;
    case SESSION_ACK: /* IOS4.3 */
        col_add_fstr(pinfo->cinfo, COL_INFO, "Ses Upd Ack: PCF=%s, Status=%u",
                     tvb_ip_to_str(tvb, 8),
                     tvb_get_guint8(tvb,3));
        if (tree) {
            /* Add Subtree */
            ti = proto_tree_add_item(tree, proto_a11, tvb, offset, -1, ENC_BIG_ENDIAN);
            a11_tree = proto_item_add_subtree(ti, ett_a11);

            /* Type */
            proto_tree_add_uint(a11_tree, hf_a11_type, tvb, offset, 1, type);
            offset++;

            /* Reserved */
            offset+=2;

            /* Ack Status */
            proto_tree_add_item(a11_tree, hf_a11_status, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            /* Home address */
            proto_tree_add_item(a11_tree, hf_a11_homeaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Care of Address */
            proto_tree_add_item(a11_tree, hf_a11_coa, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Identifier - assumed to be an NTP time here */
            proto_tree_add_item(a11_tree, hf_a11_ident, tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
            offset += 8;

        } /* if tree */
        break;
    case CAPABILITIES_INFO: /* IOS5.1 */
        col_add_fstr(pinfo->cinfo, COL_INFO, "Cap Info: PDSN=%s, PCF=%s",
                     tvb_ip_to_str(tvb, 8),
                     tvb_ip_to_str(tvb, 12));
        if (tree) {
            /* Add Subtree */
            ti = proto_tree_add_item(tree, proto_a11, tvb, offset, -1, ENC_BIG_ENDIAN);
            a11_tree = proto_item_add_subtree(ti, ett_a11);

            /* Type */
            proto_tree_add_uint(a11_tree, hf_a11_type, tvb, offset, 1, type);
            offset++;

            /* Reserved */
            offset+=3;

            /* Home address */
            proto_tree_add_item(a11_tree, hf_a11_homeaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Home Agent Address */
            proto_tree_add_item(a11_tree, hf_a11_haaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Care of Address */
            proto_tree_add_item(a11_tree, hf_a11_coa, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Identifier - assumed to be an NTP time here */
            proto_tree_add_item(a11_tree, hf_a11_ident, tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
            offset += 8;

        } /* if tree */
        break;
    case CAPABILITIES_INFO_ACK: /* IOS5.1 */
        col_add_fstr(pinfo->cinfo, COL_INFO, "Cap Info Ack: PCF=%s",
                     tvb_ip_to_str(tvb, 8));
        if (tree) {
            /* Add Subtree */
            ti = proto_tree_add_item(tree, proto_a11, tvb, offset, -1, ENC_BIG_ENDIAN);
            a11_tree = proto_item_add_subtree(ti, ett_a11);

            /* Type */
            proto_tree_add_uint(a11_tree, hf_a11_type, tvb, offset, 1, type);
            offset++;

            /* Reserved */
            offset+=3;

            /* Home address */
            proto_tree_add_item(a11_tree, hf_a11_homeaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Care of Address */
            proto_tree_add_item(a11_tree, hf_a11_coa, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Identifier - assumed to be an NTP time here */
            proto_tree_add_item(a11_tree, hf_a11_ident, tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
            offset += 8;

        } /* if tree */
        break;
    default:
        DISSECTOR_ASSERT_NOT_REACHED();
        break;
    } /* End switch */

    if (tree && a11_tree) {
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            dissect_a11_extensions(tvb, offset, a11_tree);
    }
    return tvb_length(tvb);
} /* dissect_a11 */

/* Register the protocol with Wireshark */
void
proto_register_a11(void)
{

/* Setup list of header fields */
    static hf_register_info hf[] = {
        { &hf_a11_type,
          { "Message Type",           "a11.type",
            FT_UINT8, BASE_DEC, VALS(a11_types), 0,
            "A11 Message type.", HFILL }
        },
        { &hf_a11_flags,
          {"Flags", "a11.flags",
           FT_UINT8, BASE_HEX, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_a11_s,
          {"Simultaneous Bindings",           "a11.s",
           FT_BOOLEAN, 8, NULL, 128,
           "Simultaneous Bindings Allowed", HFILL }
        },
        { &hf_a11_b,
          {"Broadcast Datagrams",           "a11.b",
           FT_BOOLEAN, 8, NULL, 64,
           "Broadcast Datagrams requested", HFILL }
        },
        { &hf_a11_d,
          { "Co-located Care-of Address",           "a11.d",
            FT_BOOLEAN, 8, NULL, 32,
            "MN using Co-located Care-of address", HFILL }
        },
        { &hf_a11_m,
          {"Minimal Encapsulation",           "a11.m",
           FT_BOOLEAN, 8, NULL, 16,
           "MN wants Minimal encapsulation", HFILL }
        },
        { &hf_a11_g,
          {"GRE",           "a11.g",
           FT_BOOLEAN, 8, NULL, 8,
           "MN wants GRE encapsulation", HFILL }
        },
        { &hf_a11_v,
          { "Van Jacobson",           "a11.v",
            FT_BOOLEAN, 8, NULL, 4,
            NULL, HFILL }
        },
        { &hf_a11_t,
          { "Reverse Tunneling",           "a11.t",
            FT_BOOLEAN, 8, NULL, 2,
            "Reverse tunneling requested", HFILL }
        },
        { &hf_a11_code,
          { "Reply Code",           "a11.code",
            FT_UINT8, BASE_DEC, VALS(a11_reply_codes), 0,
            "A11 Registration Reply code.", HFILL }
        },
        { &hf_a11_status,
          { "Reply Status",           "a11.ackstat",
            FT_UINT8, BASE_DEC, VALS(a11_ack_status), 0,
            "A11 Registration Ack Status.", HFILL }
        },
        { &hf_a11_life,
          { "Lifetime",           "a11.life",
            FT_UINT16, BASE_DEC, NULL, 0,
            "A11 Registration Lifetime.", HFILL }
        },
        { &hf_a11_homeaddr,
          { "Home Address",           "a11.homeaddr",
            FT_IPv4, BASE_NONE, NULL, 0,
            "Mobile Node's home address.", HFILL }
        },

        { &hf_a11_haaddr,
          { "Home Agent",           "a11.haaddr",
            FT_IPv4, BASE_NONE, NULL, 0,
            "Home agent IP Address.", HFILL }
        },
        { &hf_a11_coa,
          { "Care of Address",           "a11.coa",
            FT_IPv4, BASE_NONE, NULL, 0,
            "Care of Address.", HFILL }
        },
        { &hf_a11_ident,
          { "Identification",           "a11.ident",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
            "MN Identification.", HFILL }
        },
        { &hf_a11_ext_type,
          { "Extension Type",           "a11.ext.type",
            FT_UINT8, BASE_DEC, VALS(a11_ext_types), 0,
            "Mobile IP Extension Type.", HFILL }
        },
        { &hf_a11_ext_stype,
          { "Gen Auth Ext SubType",           "a11.ext.auth.subtype",
            FT_UINT8, BASE_DEC, VALS(a11_ext_stypes), 0,
            "Mobile IP Auth Extension Sub Type.", HFILL }
        },
        { &hf_a11_ext_len,
          { "Extension Length",         "a11.ext.len",
            FT_UINT16, BASE_DEC, NULL, 0,
            "Mobile IP Extension Length.", HFILL }
        },
        { &hf_a11_ext,
          { "Extension",                      "a11.extension",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_a11_aext_spi,
          { "SPI",                      "a11.auth.spi",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Authentication Header Security Parameter Index.", HFILL }
        },
        { &hf_a11_aext_auth,
          { "Authenticator",            "a11.auth.auth",
            FT_BYTES, BASE_NONE, NULL, 0,
            "Authenticator.", HFILL }
        },
        { &hf_a11_next_nai,
          { "NAI",                      "a11.nai",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_a11_ses_key,
          { "Key",                      "a11.ext.key",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Session Key.", HFILL }
        },
        { &hf_a11_ses_sidver,
          { "Session ID Version",         "a11.ext.sidver",
            FT_UINT8, BASE_DEC, NULL, 3,
            NULL, HFILL}
        },
        { &hf_a11_ses_mnsrid,
          { "MNSR-ID",                      "a11.ext.mnsrid",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_a11_ses_msid_type,
          { "MSID Type",                      "a11.ext.msid_type",
            FT_UINT16, BASE_DEC, NULL, 0,
            "MSID Type.", HFILL }
        },
        { &hf_a11_ses_msid_len,
          { "MSID Length",                      "a11.ext.msid_len",
            FT_UINT8, BASE_DEC, NULL, 0,
            "MSID Length.", HFILL }
        },
        { &hf_a11_ses_msid,
          { "MSID(BCD)",                      "a11.ext.msid",
            FT_STRING, BASE_NONE, NULL, 0,
            "MSID(BCD).", HFILL }
        },
        { &hf_a11_ses_ptype,
          { "Protocol Type",                      "a11.ext.ptype",
            FT_UINT16, BASE_HEX, VALS(a11_ses_ptype_vals), 0,
            "Protocol Type.", HFILL }
        },
        { &hf_a11_vse_vid,
          { "Vendor ID",                      "a11.ext.vid",
            FT_UINT32, BASE_HEX|BASE_EXT_STRING, &sminmpec_values_ext, 0,
            "Vendor ID.", HFILL }
        },
        { &hf_a11_vse_apptype,
          { "Application Type",                      "a11.ext.apptype",
            FT_UINT8, BASE_HEX, VALS(a11_ext_app), 0,
            "Application Type.", HFILL }
        },
        { &hf_a11_vse_ppaddr,
          { "Anchor P-P Address",           "a11.ext.ppaddr",
            FT_IPv4, BASE_NONE, NULL, 0,
            "Anchor P-P Address.", HFILL }
        },
        { &hf_a11_vse_dormant,
          { "All Dormant Indicator",           "a11.ext.dormant",
            FT_UINT16, BASE_HEX, VALS(a11_ext_dormant), 0,
            "All Dormant Indicator.", HFILL }
        },
        { &hf_a11_vse_code,
          { "Reply Code",           "a11.ext.code",
            FT_UINT8, BASE_DEC, VALS(a11_reply_codes), 0,
            "PDSN Code.", HFILL }
        },
        { &hf_a11_vse_pdit,
          { "PDSN Code",                      "a11.ext.code",
            FT_UINT8, BASE_HEX, VALS(a11_ext_nvose_pdsn_code), 0,
            "PDSN Code.", HFILL }
        },
        { &hf_a11_vse_srvopt,
          { "Service Option",                      "a11.ext.srvopt",
            FT_UINT16, BASE_HEX, VALS(a11_ext_nvose_srvopt), 0,
            "Service Option.", HFILL }
        },
        { &hf_a11_vse_panid,
          { "PANID",                      "a11.ext.panid",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_a11_vse_canid,
          { "CANID",                      "a11.ext.canid",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_a11_vse_qosmode,
          { "QoS Mode",       "a11.ext.qosmode",
            FT_UINT8, BASE_HEX, VALS(a11_ext_nvose_qosmode), 0,
            "QoS Mode.", HFILL }
        },
        { &hf_a11_ase_len_type,
          { "Entry Length",   "a11.ext.ase.len",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Entry Length.", HFILL }
        },
        { &hf_a11_ase_srid_type,
          { "Service Reference ID (SRID)",   "a11.ext.ase.srid",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Service Reference ID (SRID).", HFILL }
        },
        { &hf_a11_ase_servopt_type,
          { "Service Option", "a11.ext.ase.srvopt",
            FT_UINT16, BASE_HEX, VALS(a11_ext_nvose_srvopt), 0,
            "Service Option.", HFILL }
        },
        { &hf_a11_ase_gre_proto_type,
          { "GRE Protocol Type",   "a11.ext.ase.ptype",
            FT_UINT16, BASE_HEX, VALS(a11_ses_ptype_vals), 0,
            "GRE Protocol Type.", HFILL }
        },
        { &hf_a11_ase_gre_key,
          { "GRE Key",   "a11.ext.ase.key",
            FT_UINT32, BASE_HEX, NULL, 0,
            "GRE Key.", HFILL }
        },
        { &hf_a11_ase_pcf_addr_key,
          { "PCF IP Address",           "a11.ext.ase.pcfip",
            FT_IPv4, BASE_NONE, NULL, 0,
            "PCF IP Address.", HFILL }
        },
        { &hf_a11_fqi_srid,
          { "SRID",   "a11.ext.fqi.srid",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Forward Flow Entry SRID.", HFILL }
        },
        { &hf_a11_fqi_flags,
          { "Flags",   "a11.ext.fqi.flags",
            FT_UINT8, BASE_HEX, NULL, 0,
            "Forward Flow Entry Flags.", HFILL }
        },
        { &hf_a11_fqi_flowcount,
          { "Forward Flow Count",   "a11.ext.fqi.flowcount",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_a11_fqi_flowid,
          { "Forward Flow Id",   "a11.ext.fqi.flowid",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_a11_fqi_entrylen,
          { "Entry Length",   "a11.ext.fqi.entrylen",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Forward Entry Length.", HFILL }
        },
        { &hf_a11_fqi_dscp,
          { "Forward DSCP",   "a11.ext.fqi.dscp",
            FT_UINT8, BASE_HEX, NULL, 0,
            "Forward Flow DSCP.", HFILL }
        },
        { &hf_a11_fqi_flowstate,
          { "Forward Flow State",   "a11.ext.fqi.flowstate",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_a11_fqi_requested_qoslen,
          { "Requested QoS Length",   "a11.ext.fqi.reqqoslen",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Forward Requested QoS Length.", HFILL }
        },
	    { &hf_a11_fqi_flow_priority,
		 { "Flow Priority",   "a11.ext.fqi.flow_priority",
			FT_UINT8, BASE_DEC, NULL, 0xF0,
			NULL, HFILL }
	    },
	    { &hf_a11_fqi_num_qos_attribute_set,
		 { "Number of QoS Attribute Sets",   "a11.ext.fqi.num_qos_attribute_set",
			FT_UINT8, BASE_DEC, NULL, 0x0E,
			NULL, HFILL }
	    },
	    { &hf_a11_fqi_qos_attribute_setlen,
		 { "QoS Attribute Set Length",   "a11.ext.fqi.qos_attribute_setlen",
			FT_UINT16, BASE_DEC, NULL, 0x01E0,
			NULL, HFILL }
	    },
	    { &hf_a11_fqi_qos_attribute_setid,
		 { "QoS Attribute SetID",   "a11.ext.fqi.qos_attribute_setid",
			FT_UINT16, BASE_DEC, NULL, 0x1FC0,
			"QoS Attribute SetID.", HFILL }
	    },
	    { &hf_a11_fqi_verbose,
		 { "Verbose",   "a11.ext.fqi.verbose",
			FT_UINT8, BASE_DEC, NULL, 0x20,
			NULL, HFILL }
	    },
	    { &hf_a11_fqi_flow_profileid,
		 { "Flow Profile Id",   "a11.ext.fqi.flow_profileid",
			FT_UINT24, BASE_DEC, NULL, 0x1FFFE0,
			NULL, HFILL }
	    },
	    { &hf_a11_fqi_qos_granted_attribute_setid,
		 { "QoS Attribute SetID",   "a11.ext.fqi.qos_granted_attribute_setid",
			FT_UINT8, BASE_DEC, NULL, 0xFE,
			NULL, HFILL }
	    },
        { &hf_a11_fqi_granted_qoslen,
          { "Granted QoS Length",   "a11.ext.fqi.graqoslen",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Forward Granted QoS Length.", HFILL }
        },
        { &hf_a11_rqi_flow_priority,
          { "Flow Priority",   "a11.ext.rqi.flow_priority",
          FT_UINT8, BASE_DEC, NULL, 0xF0,
          NULL, HFILL }
        },
        { &hf_a11_rqi_num_qos_attribute_set,
          { "Number of QoS Attribute Sets",   "a11.ext.rqi.num_qos_attribute_set",
          FT_UINT8, BASE_DEC, NULL, 0x0E,
          NULL, HFILL }
        },
        { &hf_a11_rqi_qos_attribute_setlen,
          { "QoS Attribute Set Length",   "a11.ext.rqi.qos_attribute_setlen",
          FT_UINT16, BASE_DEC, NULL, 0x01E0,
          NULL, HFILL }
        },
        { &hf_a11_rqi_qos_attribute_setid,
          { "QoS Attribute SetID",   "a11.ext.rqi.qos_attribute_setid",
            FT_UINT16, BASE_DEC, NULL, 0x1FC0,
            NULL, HFILL }
        },
        { &hf_a11_rqi_verbose,
          { "Verbose",   "a11.ext.rqi.verbose",
            FT_UINT8, BASE_DEC, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_a11_rqi_flow_profileid,
          { "Flow Profile Id",   "a11.ext.rqi.flow_profileid",
            FT_UINT24, BASE_DEC, NULL, 0x1FFFE0,
            NULL, HFILL }
        },
        { &hf_a11_rqi_qos_granted_attribute_setid,
          { "QoS Attribute SetID",   "a11.ext.rqi.qos_granted_attribute_setid",
            FT_UINT8, BASE_DEC, NULL, 0xFE,
            "QoS Attribute SetID.", HFILL }
        },
        { &hf_a11_rqi_srid,
          { "SRID",   "a11.ext.rqi.srid",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Reverse Flow Entry SRID.", HFILL }
        },
        { &hf_a11_rqi_flowcount,
          { "Reverse Flow Count",   "a11.ext.rqi.flowcount",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Reverse Flow Count.", HFILL }
        },
        { &hf_a11_rqi_flowid,
          { "Reverse Flow Id",   "a11.ext.rqi.flowid",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Reverse Flow Id.", HFILL }
        },
        { &hf_a11_rqi_entrylen,
          { "Entry Length",   "a11.ext.rqi.entrylen",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Reverse Flow Entry Length.", HFILL }
        },
        { &hf_a11_rqi_flowstate,
          { "Flow State",   "a11.ext.rqi.flowstate",
            FT_UINT8, BASE_HEX, NULL, 0,
            "Reverse Flow State.", HFILL }
        },
        { &hf_a11_rqi_requested_qoslen,
          { "Requested QoS Length",   "a11.ext.rqi.reqqoslen",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Reverse Requested QoS Length.", HFILL }
        },
      { &hf_a11_rqi_requested_qos,
        { "Requested QoS",   "a11.ext.rqi.reqqos",
          FT_BYTES, BASE_NONE, NULL, 0,
          "Reverse Requested QoS.", HFILL }
      },
      { &hf_a11_rqi_granted_qoslen,
        { "Granted QoS Length",   "a11.ext.rqi.graqoslen",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Reverse Granted QoS Length.", HFILL }
      },
      { &hf_a11_rqi_granted_qos,
        { "Granted QoS",   "a11.ext.rqi.graqos",
          FT_BYTES, BASE_NONE, NULL, 0,
          "Reverse Granted QoS.", HFILL }
      },
      { &hf_a11_fqui_flowcount,
        { "Forward QoS Update Flow Count",   "a11.ext.fqui.flowcount",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Forward QoS Update Flow Count.", HFILL }
      },
      { &hf_a11_rqui_flowcount,
        { "Reverse QoS Update Flow Count",   "a11.ext.rqui.flowcount",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Reverse QoS Update Flow Count.", HFILL }
      },
      { &hf_a11_fqui_updated_qoslen,
        { "Forward Updated QoS Sub-Blob Length",   "a11.ext.fqui.updatedqoslen",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Forward Updated QoS Sub-Blob Length.", HFILL }
      },
      { &hf_a11_fqui_updated_qos,
        { "Forward Updated QoS Sub-Blob",   "a11.ext.fqui.updatedqos",
          FT_BYTES, BASE_NONE, NULL, 0,
         "Forward Updated QoS Sub-Blob.", HFILL }
      },
        { &hf_a11_rqui_updated_qoslen,
          { "Reverse Updated QoS Sub-Blob Length",   "a11.ext.rqui.updatedqoslen",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Reverse Updated QoS Sub-Blob Length.", HFILL }
        },
        { &hf_a11_rqui_updated_qos,
          { "Reverse Updated QoS Sub-Blob",   "a11.ext.rqui.updatedqos",
            FT_BYTES, BASE_NONE, NULL, 0,
            "Reverse Updated QoS Sub-Blob.", HFILL }
        },
        { &hf_a11_subsciber_profile_len,
          { "Subscriber QoS Profile Length",   "a11.ext.sqp.profilelen",
            FT_BYTES, BASE_NONE, NULL, 0,
            "Subscriber QoS Profile Length.", HFILL }
        },
        { &hf_a11_subsciber_profile,
          { "Subscriber QoS Profile",   "a11.ext.sqp.profile",
            FT_BYTES, BASE_NONE, NULL, 0,
            "Subscriber QoS Profile.", HFILL }
        },

        { &hf_a11_ase_forward_rohc_info_len,
          { "Forward ROHC Info Length",   "a11.ext.ase.forwardlen",
             FT_UINT8, BASE_DEC, NULL, 0,
             NULL, HFILL }
        },

        { &hf_a11_ase_forward_maxcid,
          { "Forward MAXCID",   "a11.ext.ase.maxcid",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },

        { &hf_a11_ase_forward_mrru,
          { "Forward MRRU",   "a11.ext.ase.mrru",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
           },

        { &hf_a11_ase_forward_large_cids,
          { "Forward Large CIDS",   "a11.ext.ase.forwardlargecids",
            FT_UINT8, BASE_DEC, NULL, 128,
            NULL, HFILL }
        },

        { &hf_a11_ase_forward_profile_count,
          { "Forward Profile Count",   "a11.ext.ase.profilecount",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
         },


        { &hf_a11_ase_forward_profile,
          { "Forward Profile",   "a11.ext.ase.forwardprofile",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },

        { &hf_a11_ase_reverse_rohc_info_len,
          { "Reverse ROHC Info Length",   "a11.ext.ase.reverselen",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },

        { &hf_a11_ase_reverse_maxcid,
          { "Reverse MAXCID",   "a11.ext.ase.revmaxcid",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },

        { &hf_a11_ase_reverse_mrru,
          { "Reverse MRRU",   "a11.ext.ase.revmrru",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },

        { &hf_a11_ase_reverse_large_cids,
          { "Reverse Large CIDS",   "a11.ext.ase.reverselargecids",
            FT_UINT8, BASE_DEC, NULL, 128,
            NULL, HFILL }
        },

        { &hf_a11_ase_reverse_profile_count,
          { "Reverse Profile Count",   "a11.ext.ase.revprofilecount",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
         },


         { &hf_a11_ase_reverse_profile,
           { "Reverse Profile",   "a11.ext.ase.reverseprofile",
             FT_UINT16, BASE_DEC, NULL, 0,
             NULL, HFILL }
         },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_a11,
        &ett_a11_flags,
        &ett_a11_ext,
        &ett_a11_exts,
        &ett_a11_radius,
        &ett_a11_radiuses,
        &ett_a11_ase,
        &ett_a11_fqi_flowentry,
        &ett_a11_fqi_requestedqos,
        &ett_a11_fqi_qos_attribute_set,
        &ett_a11_fqi_grantedqos,
        &ett_a11_rqi_flowentry,
        &ett_a11_rqi_requestedqos,
        &ett_a11_rqi_qos_attribute_set,
        &ett_a11_rqi_grantedqos,
        &ett_a11_fqi_flags,
        &ett_a11_fqi_entry_flags,
        &ett_a11_rqi_entry_flags,
        &ett_a11_fqui_flowentry,
        &ett_a11_rqui_flowentry,
        &ett_a11_subscriber_profile,
        &ett_a11_forward_rohc,
        &ett_a11_reverse_rohc,
        &ett_a11_forward_profile,
        &ett_a11_reverse_profile,
    };

    /* Register the protocol name and description */
    proto_a11 = proto_register_protocol("3GPP2 A11", "3GPP2 A11", "a11");

    /* Register the dissector by name */
    new_register_dissector("a11", dissect_a11, proto_a11);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_a11, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_a11(void)
{
    dissector_handle_t a11_handle;

    a11_handle = find_dissector("a11");
    dissector_add_uint("udp.port", UDP_PORT_3GA11, a11_handle);
}
