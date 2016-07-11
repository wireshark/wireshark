/* packet-ospf.c
 * Routines for OSPF packet disassembly
 * (c) Copyright Hannes R. Boehm <hannes@boehm.org>
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
 */
/*
 * At this time, this module is able to analyze OSPF
 * packets as specified in RFC2328. MOSPF (RFC1584) and other
 * OSPF Extensions which introduce new Packet types
 * (e.g the External Atributes LSA) are not supported.
 * Furthermore RFC2740 (OSPFv3 - OSPF for IPv6) is now supported
 *   - (c) 2001 Palle Lyckegaard <palle[AT]lyckegaard.dk>
 *
 * Added support to E-NNI routing (OIF2003.259.02)
 *   - (c) 2004 Roberto Morro <roberto.morro[AT]tilab.com>
 *
 * Added support for OSPF restart signaling:
 *       draft-nguyen-ospf-lls-05.txt
 *       draft-nguyen-ospf-oob-resync-05.txt
 *       draft-nguyen-ospf-restart-05.txt
 *   - (c) 2005 Michael Rozhavsky <mrozhavsky@fortinet.com>
 *
 * Added support of MPLS Diffserv-aware TE (RFC 4124); new BC sub-TLV
 *   - (c) 2006 (FF) <francesco.fondelli[AT]gmail.com>
 *
 * Added support for decoding the TLVs in a grace-LSA
 *   - (c) 2007 Todd J Martin <todd.martin@acm.org>
 *
 * Added support for draft-ietf-ospf-manet-or-02
 * Added support for draft-ietf-ospf-af-alt-06
 *   - (c) 2008 Cisco Systems
 *
 * Added support for Multi-Topology (MT) Routing (RFC4915)
 *   - (c) 2009 Stig Bjorlykke <stig@bjorlykke.org>, Thales Norway AS
 *
 * Added support for OSPFv2 & OSPFv3 Router Information (RI) Opaque LSA (RFC4970); RI Capabilities TLV
 * Added support for OSPFv2 & OSPFv3 Dynamic Hostname TLV in RI Opaque LSA (RFC5642)
 *   - (c) 2011 Salil Kanitkar <sskanitk@ncsu.edu>, North Carolina State University
 *
 * Added support for Type Classification of Experimental and Reserved sub-TLVs (RFC3630)
 *   - (c) 2013 Kaushal Shah <kshah3@ncsu.edu>, North Carolina State University
 *
 * Added support for Authentication Trailer for OSPFv3 (RFC6506)
 *   - (c) 2014 Alexis La Goutte (See AUTHORS)
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <epan/ipproto.h>
#include <epan/in_cksum.h>
#include <epan/expert.h>
#include <epan/addr_resolv.h>
#include "packet-rsvp.h"

void proto_register_ospf(void);
void proto_reg_handoff_ospf(void);

#define OSPF_VERSION_2 2
#define OSPF_VERSION_3 3
#define OSPF_AF_4 4
#define OSPF_AF_6 6
#define OSPF_VERSION_2_HEADER_LENGTH    24
#define OSPF_VERSION_3_HEADER_LENGTH    16


#define OSPF_HELLO      1
#define OSPF_DB_DESC    2
#define OSPF_LS_REQ     3
#define OSPF_LS_UPD     4
#define OSPF_LS_ACK     5
#define OSPF_LS_BASE    OSPF_HELLO

static const value_string pt_vals[] = {
    {OSPF_HELLO,   "Hello Packet"   },
    {OSPF_DB_DESC, "DB Description" },
    {OSPF_LS_REQ,  "LS Request"     },
    {OSPF_LS_UPD,  "LS Update"      },
    {OSPF_LS_ACK,  "LS Acknowledge" },
    {0,             NULL            }
};

static const value_string ospf_at_authentication_type_vals[] = {
    {0, "Reserved" },
    {1, "HMAC Cryptographic Authentication" },
    {0, NULL }
};

#define OSPF_AUTH_NONE          0
#define OSPF_AUTH_SIMPLE        1
#define OSPF_AUTH_CRYPT         2

static const value_string auth_vals[] = {
    {OSPF_AUTH_NONE,   "Null"            },
    {OSPF_AUTH_SIMPLE, "Simple password" },
    {OSPF_AUTH_CRYPT,  "Cryptographic"   },
    {0,                NULL              }
};

#define OSPF_V2_OPTIONS_MT              0x01
#define OSPF_V2_OPTIONS_E               0x02
#define OSPF_V2_OPTIONS_MC              0x04
#define OSPF_V2_OPTIONS_NP              0x08
#define OSPF_V2_OPTIONS_L               0x10
#define OSPF_V2_OPTIONS_DC              0x20
#define OSPF_V2_OPTIONS_O               0x40
#define OSPF_V2_OPTIONS_DN              0x80
#define OSPF_V3_OPTIONS_V6              0x01
#define OSPF_V3_OPTIONS_E               0x02
#define OSPF_V3_OPTIONS_MC              0x04
#define OSPF_V3_OPTIONS_N               0x08
#define OSPF_V3_OPTIONS_R               0x10
#define OSPF_V3_OPTIONS_DC              0x20
#define OSPF_V3_OPTIONS_AF              0x0100
#define OSPF_V3_OPTIONS_L               0x0200
#define OSPF_V3_OPTIONS_AT              0x0400

/* Bitmask definitions for the informational capabilities bits. */
#define OSPF_RI_OPTIONS_GRC             0x80
#define OSPF_RI_OPTIONS_GRH             0x40
#define OSPF_RI_OPTIONS_SRS             0x20
#define OSPF_RI_OPTIONS_TES             0x10
#define OSPF_RI_OPTIONS_P2PLAN          0x08
#define OSPF_RI_OPTIONS_ETE             0x04

#define OSPF_LLS_EXT_OPTIONS_LR         0x00000001
#define OSPF_LLS_EXT_OPTIONS_RS         0x00000002

#define OSPF_V3_LLS_EXT_OPTIONS_LR      0x00000001
#define OSPF_V3_LLS_EXT_OPTIONS_RS      0x00000002

#define OSPF_V3_LLS_STATE_OPTIONS_R     0x80
#define OSPF_V3_LLS_STATE_OPTIONS_A     0x40
#define OSPF_V3_LLS_STATE_OPTIONS_N     0x20
#define OSPF_V3_LLS_RELAY_OPTIONS_A     0x80
#define OSPF_V3_LLS_RELAY_OPTIONS_N     0x40

#define OSPF_DBD_FLAG_MS        1
#define OSPF_DBD_FLAG_M         2
#define OSPF_DBD_FLAG_I         4
#define OSPF_DBD_FLAG_R         8

#define OSPF_LS_REQ_LENGTH      12

#define OSPF_LSTYPE_ROUTER      1
#define OSPF_LSTYPE_NETWORK     2
#define OSPF_LSTYPE_SUMMARY     3
#define OSPF_LSTYPE_ASBR        4
#define OSPF_LSTYPE_ASEXT       5
#define OSPF_LSTYPE_GRPMEMBER   6
#define OSPF_LSTYPE_ASEXT7      7
#define OSPF_LSTYPE_EXTATTR     8
#define OSPF_LSTYPE_BASE        OSPF_LSTYPE_ROUTER
#define OSPF_V3_LSTYPE_ROUTER                0x2001
#define OSPF_V3_LSTYPE_NETWORK               0x2002
#define OSPF_V3_LSTYPE_INTER_AREA_PREFIX     0x2003
#define OSPF_V3_LSTYPE_INTER_AREA_ROUTER     0x2004
#define OSPF_V3_LSTYPE_AS_EXTERNAL           0x4005
#define OSPF_V3_LSTYPE_GROUP_MEMBERSHIP      0x2006
#define OSPF_V3_LSTYPE_NSSA                  0x2007
#define OSPF_V3_LSTYPE_LINK                  0x0008
#define OSPF_V3_LSTYPE_INTRA_AREA_PREFIX     0x2009
#define OSPF_V3_LSTYPE_OPAQUE_RI             0x800c

/* Opaque LSA types */
#define OSPF_LSTYPE_OP_BASE      8
#define OSPF_LSTYPE_OP_LINKLOCAL 9
#define OSPF_LSTYPE_OP_AREALOCAL 10
#define OSPF_LSTYPE_OP_ASWIDE    11

#define OSPF_V3_LSA_FUNCTION_CODE_ROUTER            1
#define OSPF_V3_LSA_FUNCTION_CODE_NETWORK           2
#define OSPF_V3_LSA_FUNCTION_CODE_INTER_AREA_PREFIX 3
#define OSPF_V3_LSA_FUNCTION_CODE_INTER_AREA_ROUTER 4
#define OSPF_V3_LSA_FUNCTION_CODE_AS_EXTERNAL       5
#define OSPF_V3_LSA_FUNCTION_CODE_GROUP_MEMBERSHIP  6
#define OSPF_V3_LSA_FUNCTION_CODE_NSSA              7
#define OSPF_V3_LSA_FUNCTION_CODE_LINK              8
#define OSPF_V3_LSA_FUNCTION_CODE_INTRA_AREA_PREFIX 9
#define OSPF_V3_LSA_FUNCTION_CODE_BASE              OSPF_V3_LSA_FUNCTION_CODE_ROUTER
#define OSPF_V3_LSA_FUNCTION_CODE_OPAQUE_RI         12
#define OSPF_V3_LSA_FUNCTION_CODE_OPAQUE_RI_BASE    9

#define OSPF_LINK_PTP           1
#define OSPF_LINK_TRANSIT       2
#define OSPF_LINK_STUB          3
#define OSPF_LINK_VIRTUAL       4

#define OSPF_V3_LINK_PTP        1
#define OSPF_V3_LINK_TRANSIT    2
#define OSPF_V3_LINK_RESERVED   3
#define OSPF_V3_LINK_VIRTUAL    4

#define OSPF_LSA_HEADER_LENGTH  20

#define OSPF_DNA_LSA            0x8000
/* Known opaque LSAs */
#define OSPF_LSA_MPLS_TE        1
#define OSPF_LSA_GRACE          3
/* The type field "4" indicates the Opaque RI LSA with Optional Router Capabilites
   advertized in the first TLV. (RFC4970) */
#define OSPF_LSA_OPAQUE_RI      4
#define OSPF_LSA_UNKNOWN        11
#define OSPF_RESTART_REASON_UNKNOWN   0
#define OSPF_RESTART_REASON_SWRESTART 1
#define OSPF_RESTART_REASON_SWRELOAD  2
#define OSPF_RESTART_REASON_SWITCH    3

static const value_string restart_reason_vals[] = {
    {OSPF_RESTART_REASON_UNKNOWN,     "Unknown"                  },
    {OSPF_RESTART_REASON_SWRESTART,   "Software Restart"         },
    {OSPF_RESTART_REASON_SWRELOAD,    "Software Reload/Upgrade"  },
    {OSPF_RESTART_REASON_SWITCH,      "Processor Switchover"     },
    {0, NULL}
};

/* grace-LSA TLV Types */
#define GRACE_TLV_PERIOD 1
#define GRACE_TLV_REASON 2
#define GRACE_TLV_IP 3

static const value_string grace_tlv_type_vals[] = {
    {GRACE_TLV_PERIOD,     "grace-LSA Grace Period"},
    {GRACE_TLV_REASON,     "grace-LSA Restart Reason"},
    {GRACE_TLV_IP,         "grace-LSA Restart IP"},
    {0, NULL}
};

/* Opaque-LSA - Router Informational Capabilities: TLV Types*/
#define OPT_RI_TLV       1
#define DYN_HOSTNAME_TLV 7

#if 0
/* The Opaque RI LSA TLV types definitions. */
static const value_string ri_tlv_type_vals[] = {
    {OPT_RI_TLV,          "Optional Router Informational Capabilities TLV"},
    {DYN_HOSTNAME_TLV,    "Dynamic Hostname TLV"},
    {0, NULL}
};
#endif

static const value_string ls_type_vals[] = {
    {OSPF_LSTYPE_ROUTER,                  "Router-LSA"                   },
    {OSPF_LSTYPE_NETWORK,                 "Network-LSA"                  },
    {OSPF_LSTYPE_SUMMARY,                 "Summary-LSA (IP network)"     },
    {OSPF_LSTYPE_ASBR,                    "Summary-LSA (ASBR)"           },
    {OSPF_LSTYPE_ASEXT,                   "AS-External-LSA (ASBR)"       },
    {OSPF_LSTYPE_GRPMEMBER,               "Group Membership LSA"         },
    {OSPF_LSTYPE_ASEXT7,                  "NSSA AS-External-LSA"         },
    {OSPF_LSTYPE_EXTATTR,                 "External Attributes LSA"      },
    {OSPF_LSTYPE_OP_LINKLOCAL,            "Opaque LSA, Link-local scope" },
    {OSPF_LSTYPE_OP_AREALOCAL,            "Opaque LSA, Area-local scope" },
    {0,                                   NULL                           }

};

static const value_string ls_opaque_type_vals[] = {
    {OSPF_LSA_MPLS_TE, "Traffic Engineering LSA"                },
    {2,                "Sycamore Optical Topology Descriptions" },
    {OSPF_LSA_GRACE,   "grace-LSA"                              },
    {OSPF_LSA_OPAQUE_RI, "Optional Router Capabilities Opaque RI LSA" },
    {0,                NULL                                     }
};

static const value_string v3_ls_type_vals[] = {
    {OSPF_V3_LSTYPE_ROUTER,               "Router-LSA"                   },
    {OSPF_V3_LSTYPE_NETWORK,              "Network-LSA"                  },
    {OSPF_V3_LSTYPE_INTER_AREA_PREFIX,    "Inter-Area-Prefix-LSA"        },
    {OSPF_V3_LSTYPE_INTER_AREA_ROUTER,    "Inter-Area-Router-LSA"        },
    {OSPF_V3_LSTYPE_AS_EXTERNAL,          "AS-External-LSA"              },
    {OSPF_V3_LSTYPE_GROUP_MEMBERSHIP,     "Group-Membership-LSA"         },
    {OSPF_V3_LSTYPE_NSSA,                 "NSSA-LSA"                     },
    {OSPF_V3_LSTYPE_LINK,                 "Link-LSA"                     },
    {OSPF_V3_LSTYPE_INTRA_AREA_PREFIX,    "Intra-Area-Prefix-LSA"        },
    {OSPF_V3_LSTYPE_OPAQUE_RI,            "Router Information Opaque-LSA"},
    {0,                                   NULL                           }
};

static const value_string lls_tlv_type_vals[] = {
    {1,                                   "Extended options TLV"         },
    {2,                                   "Crypto Authentication TLV"    },
    {0,                                   NULL                           }
};

/* OSPFv3 LLS TLV Types */
#define LLS_V3_EXT_OPT       1
#define LLS_V3_STATE_CHECK   3
#define LLS_V3_NBR_DROP      4
#define LLS_V3_RELAYS        7
#define LLS_V3_WILLING       8
#define LLS_V3_RQST_FROM     5
#define LLS_V3_FULL_STATE    6

static const value_string lls_v3_tlv_type_vals[] = {
    {LLS_V3_EXT_OPT,                      "Extended Options TLV"          },
    {LLS_V3_STATE_CHECK,                  "State Check Sequence TLV"      },
    {LLS_V3_NBR_DROP,                     "Neighbor Drop TLV"             },
    {LLS_V3_RELAYS,                       "Active Overlapping Relays TLV" },
    {LLS_V3_WILLING,                      "Willingness TLV"               },
    {LLS_V3_RQST_FROM,                    "Request From LTV"              },
    {LLS_V3_FULL_STATE,                   "Full State For TLV"            },
    {0,                                   NULL                            }
};

static const value_string mpls_link_stlv_ltype_str[] = {
    {1, "Point-to-point"},
    {2, "Multi-access"},
    {0, NULL}
};

/* FF: from www.iana.org/assignments/bandwidth-constraints-model-ids */
static const range_string mpls_link_stlv_bcmodel_rvals[] = {
    { 0,     0, "(Russian Dolls Model - RDM)"                       },
    { 1,     1, "(Maximum Allocation Model - MAM)"                  },
    { 2,     2, "(Maximum Allocation with Reservation Model - MAR)" },
    { 3,   239, "(Unassigned, Specification Required)"              },
    { 240, 255, "(Reserved, Private Use)"                           },
    { 0,     0, NULL                                                }
};

static const true_false_string tfs_arbitrary_standard = { "Arbitrary", "Standard" };

#define OSPF_V2_ROUTER_LSA_FLAG_B 0x01
#define OSPF_V2_ROUTER_LSA_FLAG_E 0x02
#define OSPF_V2_ROUTER_LSA_FLAG_V 0x04
#define OSPF_V2_ROUTER_LSA_FLAG_W 0x08
#define OSPF_V2_ROUTER_LSA_FLAG_N 0x10
#define OSPF_V3_ROUTER_LSA_FLAG_B 0x01
#define OSPF_V3_ROUTER_LSA_FLAG_E 0x02
#define OSPF_V3_ROUTER_LSA_FLAG_V 0x04
#define OSPF_V3_ROUTER_LSA_FLAG_W 0x08

#define OSPF_V3_PREFIX_OPTION_NU 0x01
#define OSPF_V3_PREFIX_OPTION_LA 0x02
#define OSPF_V3_PREFIX_OPTION_MC 0x04
#define OSPF_V3_PREFIX_OPTION_P  0x08

#define OSPF_V3_AS_EXTERNAL_FLAG_T 0x01
#define OSPF_V3_AS_EXTERNAL_FLAG_F 0x02
#define OSPF_V3_AS_EXTERNAL_FLAG_E 0x04


static int proto_ospf = -1;

static gint ett_ospf = -1;
static gint ett_ospf_at = -1;
static gint ett_ospf_hdr = -1;
static gint ett_ospf_hello = -1;
static gint ett_ospf_desc = -1;
static gint ett_ospf_lsr = -1;
static gint ett_ospf_lsa = -1;
static gint ett_ospf_lsa_router_link = -1;
static gint ett_ospf_lsa_upd = -1;
static gint ett_ospf_v2_options = -1;
static gint ett_ospf_ri_options = -1;
static gint ett_ospf_v3_options = -1;
static gint ett_ospf_dbd = -1;
static gint ett_ospf_lls_data_block = -1;
static gint ett_ospf_lls_tlv = -1;
static gint ett_ospf_lls_ext_options = -1;
static gint ett_ospf_v3_lls_ext_options_tlv = -1;
static gint ett_ospf_v3_lls_ext_options = -1;
static gint ett_ospf_v3_lls_state_tlv = -1;
static gint ett_ospf_v3_lls_state_scs = -1;
static gint ett_ospf_v3_lls_state_options = -1;
static gint ett_ospf_v3_lls_drop_tlv = -1;
static gint ett_ospf_v3_lls_relay_tlv = -1;
static gint ett_ospf_v3_lls_relay_added = -1;
static gint ett_ospf_v3_lls_relay_options = -1;
static gint ett_ospf_v3_lls_willingness_tlv = -1;
static gint ett_ospf_v3_lls_willingness = -1;
static gint ett_ospf_v3_lls_rf_tlv = -1;
static gint ett_ospf_v3_lls_fsf_tlv = -1;
static gint ett_ospf_v2_router_lsa_flags = -1;
static gint ett_ospf_v3_router_lsa_flags = -1;
static gint ett_ospf_v3_as_external_flags = -1;
static gint ett_ospf_v3_prefix_options = -1;
static gint ett_ospf_v3_router_interface = -1;
static gint ett_ospf_v3_router_interface_entry = -1;

/* Trees for opaque LSAs */
static gint ett_ospf_lsa_mpls = -1;
static gint ett_ospf_lsa_mpls_router = -1;
static gint ett_ospf_lsa_mpls_link = -1;
static gint ett_ospf_lsa_mpls_link_stlv = -1;
static gint ett_ospf_lsa_mpls_link_stlv_admingrp = -1;
static gint ett_ospf_lsa_oif_tna = -1;
static gint ett_ospf_lsa_oif_tna_stlv = -1;
static gint ett_ospf_lsa_grace_tlv = -1;
static gint ett_ospf_lsa_opaque_ri = -1;
static gint ett_ospf_lsa_ri_tlv = -1;
static gint ett_ospf_lsa_dyn_hostname_tlv = -1;
static gint ett_ospf_lsa_unknown_tlv = -1;


/* The Options field in the first TLV of the Opaque RI LSA with type field set to "4" for OSPFv2
   and type field set to "12" in OSPFv3, is interpreted as advertizing optional router capabilties.
   (RFC4970) */
static const true_false_string tfs_v3_as_external_flags_e = {
    "Type 2",
    "Type 1"
};

/*-----------------------------------------------------------------------
 * OSPF Filtering
 *-----------------------------------------------------------------------*/

/* OSPF MSG Type */
static int hf_ospf_msg_hello = -1;
static int hf_ospf_msg_db_desc = -1;
static int hf_ospf_msg_ls_req = -1;
static int hf_ospf_msg_ls_upd = -1;
static int hf_ospf_msg_ls_ack = -1;

static int *hf_ospf_msg_type_array[] = {
        &hf_ospf_msg_hello,
        &hf_ospf_msg_db_desc,
        &hf_ospf_msg_ls_req,
        &hf_ospf_msg_ls_upd,
        &hf_ospf_msg_ls_ack,
};

static int hf_ospf_ls_type = -1;
static int hf_ospf_ls_age = -1;
static int hf_ospf_ls_donotage = -1;
static int hf_ospf_ls_id = -1;
static int hf_ospf_ls_seqnum = -1;
static int hf_ospf_ls_chksum = -1;
static int hf_ospf_ls_length = -1;
static int hf_ospf_ls_opaque_type = -1;
static int hf_ospf_ls_mpls_te_instance = -1;

/* OSPF V2 LSA Type  */
static int hf_ospf_ls_router = -1;
static int hf_ospf_ls_router_linktype = -1;
static int hf_ospf_ls_router_linkid = -1;
static int hf_ospf_ls_router_linkdata = -1;
static int hf_ospf_ls_router_nummetrics = -1;
static int hf_ospf_ls_router_metric0 = -1;
static int hf_ospf_ls_network = -1;
static int hf_ospf_ls_network_netmask = -1;
static int hf_ospf_ls_network_attachrtr = -1;
static int hf_ospf_ls_summary = -1;
static int hf_ospf_ls_asbr = -1;
static int hf_ospf_ls_asbr_netmask = -1;
static int hf_ospf_ls_asext = -1;
static int hf_ospf_ls_asext_netmask = -1;
static int hf_ospf_ls_asext_fwdaddr = -1;
static int hf_ospf_ls_asext_extrtrtag = -1;
static int hf_ospf_ls_grpmember = -1;
static int hf_ospf_ls_asext7 = -1;
static int hf_ospf_ls_extattr = -1;
static int hf_ospf_ls_opaque = -1;

static int *hf_ospf_ls_type_array[] = {
        &hf_ospf_ls_router,
        &hf_ospf_ls_network,
        &hf_ospf_ls_summary,
        &hf_ospf_ls_asbr,
        &hf_ospf_ls_asext,
        &hf_ospf_ls_grpmember,
        &hf_ospf_ls_asext7,
        &hf_ospf_ls_extattr,
        &hf_ospf_ls_opaque
};

static int hf_ospf_v3_ls_type = -1;
/* OSPF V3 LSA Type */
static int hf_ospf_v3_ls_router = -1;
static int hf_ospf_v3_ls_network = -1;
static int hf_ospf_v3_ls_inter_area_prefix = -1;
static int hf_ospf_v3_ls_inter_area_router = -1;
static int hf_ospf_v3_ls_as_external = -1;
static int hf_ospf_v3_ls_group_membership = -1;
static int hf_ospf_v3_ls_nssa = -1;
static int hf_ospf_v3_ls_link = -1;
static int hf_ospf_v3_ls_intra_area_prefix = -1;
static int hf_ospf_v3_ls_opaque_ri = -1;

static int *hf_ospf_v3_ls_type_array[] = {
        &hf_ospf_v3_ls_router,
        &hf_ospf_v3_ls_network,
        &hf_ospf_v3_ls_inter_area_prefix,
        &hf_ospf_v3_ls_inter_area_router,
        &hf_ospf_v3_ls_as_external,
        &hf_ospf_v3_ls_group_membership,
        &hf_ospf_v3_ls_nssa,
        &hf_ospf_v3_ls_link,
        &hf_ospf_v3_ls_intra_area_prefix,
        &hf_ospf_v3_ls_opaque_ri
};

static int hf_ospf_adv_router = -1;
static int hf_ospf_ls_mpls = -1;
static int hf_ospf_ls_mpls_routerid = -1;
static int hf_ospf_ls_mpls_linktype = -1;
static int hf_ospf_ls_mpls_linkid = -1;
static int hf_ospf_ls_mpls_local_addr = -1;
static int hf_ospf_ls_mpls_remote_addr = -1;
static int hf_ospf_ls_mpls_local_ifid = -1;
static int hf_ospf_ls_mpls_remote_ifid = -1;
static int hf_ospf_ls_mpls_te_metric = -1;
static int hf_ospf_ls_mpls_linkcolor = -1;
static int hf_ospf_ls_mpls_group = -1;
static int hf_ospf_ls_mpls_link_max_bw = -1;
static int hf_ospf_ls_mpls_bc_model_id = -1;
static int hf_ospf_ls_oif_local_node_id = -1;
static int hf_ospf_ls_oif_remote_node_id = -1;
static int hf_ospf_v2_options = -1;
static int hf_ospf_v2_options_mt = -1;
static int hf_ospf_v2_options_e = -1;
static int hf_ospf_v2_options_mc = -1;
static int hf_ospf_v2_options_n = -1;
static int hf_ospf_v2_options_p = -1;
static int hf_ospf_v2_options_l = -1;
static int hf_ospf_v2_options_dc = -1;
static int hf_ospf_v2_options_o = -1;
static int hf_ospf_v2_options_dn = -1;

static int hf_ospf_ri_options = -1;
/* OSPF Router Informational Capabilities Options */
static int hf_ospf_ri_options_grc = -1;
static int hf_ospf_ri_options_grh = -1;
static int hf_ospf_ri_options_srs = -1;
static int hf_ospf_ri_options_tes = -1;
static int hf_ospf_ri_options_p2plan = -1;
static int hf_ospf_ri_options_ete = -1;

/* OSPF Dynamic Hostname support (RFC5642) */
static int hf_ospf_opaque_lsa_mbz = -1;
static int hf_ospf_v3_options = -1;
static int hf_ospf_v3_options_v6 = -1;
static int hf_ospf_v3_options_e = -1;
static int hf_ospf_v3_options_mc = -1;
static int hf_ospf_v3_options_n = -1;
static int hf_ospf_v3_options_r = -1;
static int hf_ospf_v3_options_dc = -1;
static int hf_ospf_v3_options_af = -1;
static int hf_ospf_v3_options_l = -1;
static int hf_ospf_v3_options_at = -1;
static int hf_ospf_dbd = -1;
static int hf_ospf_dbd_r = -1;
static int hf_ospf_dbd_i = -1;
static int hf_ospf_dbd_m = -1;
static int hf_ospf_dbd_ms = -1;
static int hf_ospf_lls_ext_options = -1;
static int hf_ospf_lls_ext_options_lr = -1;
static int hf_ospf_lls_ext_options_rs = -1;
static int hf_ospf_v2_router_lsa_flag = -1;
static int hf_ospf_v2_router_lsa_flag_b = -1;
static int hf_ospf_v2_router_lsa_flag_e = -1;
static int hf_ospf_v2_router_lsa_flag_v = -1;
static int hf_ospf_v2_router_lsa_flag_w = -1;
static int hf_ospf_v2_router_lsa_flag_n = -1;
static int hf_ospf_v3_router_lsa_flag = -1;
static int hf_ospf_v3_router_lsa_flag_b = -1;
static int hf_ospf_v3_router_lsa_flag_e = -1;
static int hf_ospf_v3_router_lsa_flag_v = -1;
static int hf_ospf_v3_router_lsa_flag_w = -1;
static int hf_ospf_v3_as_external_flag = -1;
static int hf_ospf_v3_as_external_flag_t = -1;
static int hf_ospf_v3_as_external_flag_f = -1;
static int hf_ospf_v3_as_external_flag_e = -1;
static int hf_ospf_v3_prefix_option = -1;
static int hf_ospf_v3_prefix_option_nu = -1;
static int hf_ospf_v3_prefix_option_la = -1;
static int hf_ospf_v3_prefix_option_mc = -1;
static int hf_ospf_v3_prefix_option_p = -1;
static int hf_ospf_dyn_hostname = -1;
static int hf_ospf_unknown_tlv_txt = -1;
static int hf_ospf_v2_grace_tlv = -1;
static int hf_ospf_v2_grace_period = -1;
static int hf_ospf_v2_grace_reason = -1;
static int hf_ospf_v2_grace_ip = -1;
static int hf_ospf_v3_lls_ext_options_tlv = -1;
static int hf_ospf_v3_lls_ext_options = -1;
static int hf_ospf_v3_lls_ext_options_lr = -1;
static int hf_ospf_v3_lls_ext_options_rs = -1;
static int hf_ospf_v3_lls_state_tlv = -1;
static int hf_ospf_v3_lls_state_scs = -1;
static int hf_ospf_v3_lls_state_options = -1;
static int hf_ospf_v3_lls_state_options_r = -1;
static int hf_ospf_v3_lls_state_options_a = -1;
static int hf_ospf_v3_lls_state_options_n = -1;
static int hf_ospf_v3_lls_drop_tlv = -1;
static int hf_ospf_v3_lls_relay_tlv = -1;
static int hf_ospf_v3_lls_relay_added = -1;
static int hf_ospf_v3_lls_relay_options = -1;
static int hf_ospf_v3_lls_relay_options_a = -1;
static int hf_ospf_v3_lls_relay_options_n = -1;
static int hf_ospf_v3_lls_willingness_tlv = -1;
static int hf_ospf_v3_lls_willingness = -1;
static int hf_ospf_v3_lls_rf_tlv = -1;
static int hf_ospf_v3_lls_fsf_tlv = -1;

static int hf_ospf_header = -1;
static int hf_ospf_header_version = -1;
static int hf_ospf_header_msg_type = -1;
static int hf_ospf_header_packet_length = -1;
static int hf_ospf_header_src_router = -1;
static int hf_ospf_header_area_id = -1;
static int hf_ospf_header_checksum = -1;
static int hf_ospf_tlv_type = -1;
static int hf_ospf_tlv_length = -1;


/* Header OSPF v2 auth */
static int hf_ospf_header_auth_type = -1;
static int hf_ospf_header_auth_data_none = -1;
static int hf_ospf_header_auth_data_simple = -1;
static int hf_ospf_header_auth_crypt_key_id = -1;
static int hf_ospf_header_auth_crypt_data_length = -1;
static int hf_ospf_header_auth_crypt_seq_nbr = -1;
static int hf_ospf_header_auth_crypt_data = -1;
static int hf_ospf_header_auth_data_unknown = -1;

/* Header OSPF v3 */
static int hf_ospf_header_instance_id = -1;
static int hf_ospf_header_reserved = -1;

/* Hello */
static int hf_ospf_hello = -1;
static int hf_ospf_hello_network_mask = -1;
static int hf_ospf_hello_interface_id = -1;
static int hf_ospf_hello_hello_interval = -1;
static int hf_ospf_hello_router_priority = -1;
static int hf_ospf_hello_router_dead_interval = -1;
static int hf_ospf_hello_designated_router = -1;
static int hf_ospf_hello_backup_designated_router = -1;
static int hf_ospf_hello_active_neighbor = -1;

/* Authentication Trailer RFC6506 */
static int hf_ospf_at = -1;
static int hf_ospf_at_auth_type = -1;
static int hf_ospf_at_auth_data_len = -1;
static int hf_ospf_at_reserved = -1;
static int hf_ospf_at_sa_id = -1;
static int hf_ospf_at_crypto_seq_nbr = -1;
static int hf_ospf_at_auth_data = -1;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_ospf_referenced_advertising_router = -1;
static int hf_ospf_v3_lsa_referenced_link_state_id = -1;
static int hf_ospf_mpls_protection_capability = -1;
static int hf_ospf_oif_encoding = -1;
static int hf_ospf_ls_id_te_lsa_reserved = -1;
static int hf_ospf_db_interface_mtu = -1;
static int hf_ospf_v3_lls_full_state_for = -1;
static int hf_ospf_v3_lsa_interface_id = -1;
static int hf_ospf_v3_lsa_router_priority = -1;
static int hf_ospf_v3_lsa_forwarding_address_ipv6 = -1;
static int hf_ospf_v3_lls_dropped_neighbor = -1;
static int hf_ospf_v3_lsa_external_route_tag = -1;
static int hf_ospf_tna_addr = -1;
static int hf_ospf_v3_lsa_neighbor_router_id = -1;
static int hf_ospf_mpls_switching_type = -1;
static int hf_ospf_oif_tna_addr_length = -1;
static int hf_ospf_oif_tna_addr_ipv4 = -1;
static int hf_ospf_link_state_id = -1;
static int hf_ospf_ls_id_opaque_id = -1;
static int hf_ospf_v2_lls_sequence_number = -1;
static int hf_ospf_v3_lsa_do_not_age = -1;
static int hf_ospf_lls_data_length = -1;
static int hf_ospf_mpls_shared_risk_link_group = -1;
static int hf_ospf_v3_lls_extended_options = -1;
static int hf_ospf_db_dd_sequence = -1;
static int hf_ospf_v3_lsa_destination_router_id = -1;
static int hf_ospf_tna_addr_ipv6 = -1;
static int hf_ospf_v3_lsa_link_local_interface_address = -1;
static int hf_ospf_mpls_interface_mtu = -1;
static int hf_ospf_v3_lsa_neighbor_interface_id = -1;
static int hf_ospf_lsa_number_of_links = -1;
static int hf_ospf_v2_lls_auth_data = -1;
static int hf_ospf_oif_switching_cap = -1;
static int hf_ospf_ls_number_of_lsas = -1;
static int hf_ospf_v3_lls_neighbor = -1;
static int hf_ospf_v3_lls_request_from = -1;
static int hf_ospf_lls_checksum = -1;
static int hf_ospf_v3_lsa_attached_router = -1;
static int hf_ospf_v3_lsa_referenced_ls_type = -1;
static int hf_ospf_mpls_encoding = -1;
static int hf_ospf_lsa_external_type = -1;
static int hf_ospf_lsa_tos = -1;
static int hf_ospf_lsa_external_tos = -1;
static int hf_ospf_v3_lsa_type = -1;
static int hf_ospf_metric = -1;
static int hf_ospf_prefix_length = -1;
static int hf_ospf_ls_mpls_pri = -1;
static int hf_ospf_ls_mpls_bc = -1;
static int hf_ospf_mpls_minimum_lsp_bandwidth = -1;
static int hf_ospf_mpls_sonet_sdh = -1;
static int hf_ospf_oif_signal_type = -1;
static int hf_ospf_tlv_value = -1;
static int hf_ospf_oif_node_id = -1;
static int hf_ospf_pad_bytes = -1;
static int hf_ospf_ls_metric = -1;
static int hf_ospf_v3_lsa_forwarding_address_ipv4 = -1;
static int hf_ospf_link_local_interface_address_ipv4 = -1;
static int hf_ospf_v3_lsa_num_prefixes = -1;
static int hf_ospf_v3_address_prefix_ipv6 = -1;
static int hf_ospf_v3_address_prefix_ipv4 = -1;

static expert_field ei_ospf_header_reserved = EI_INIT;
static expert_field ei_ospf_lsa_bad_length = EI_INIT;
static expert_field ei_ospf_lsa_constraint_missing = EI_INIT;
static expert_field ei_ospf_lsa_bc_error = EI_INIT;
static expert_field ei_ospf_lsa_unknown_type = EI_INIT;
static expert_field ei_ospf_unknown_link_subtype = EI_INIT;

static gint ospf_msg_type_to_filter (guint8 msg_type)
{
    if (msg_type >= OSPF_HELLO &&
        msg_type <= OSPF_LS_ACK)
        return msg_type - OSPF_LS_BASE;
    return -1;
}

static gint ospf_ls_type_to_filter (guint8 ls_type)
{
    if (ls_type >= OSPF_LSTYPE_ROUTER &&
        ls_type <= OSPF_LSTYPE_EXTATTR)
        return ls_type - OSPF_LSTYPE_BASE;
    else if (ls_type >= OSPF_LSTYPE_OP_LINKLOCAL &&
             ls_type <= OSPF_LSTYPE_OP_ASWIDE)
        return OSPF_LSTYPE_OP_BASE;
    else
        return -1;
}

static gint ospf_v3_ls_type_to_filter (guint16 ls_type)
{
    guint16 function_code;

    function_code = ls_type & 0x1fff;
    if (function_code >= OSPF_V3_LSA_FUNCTION_CODE_ROUTER &&
        function_code <= OSPF_V3_LSA_FUNCTION_CODE_INTRA_AREA_PREFIX)
        return function_code - OSPF_V3_LSA_FUNCTION_CODE_BASE;
    else if (function_code == OSPF_V3_LSA_FUNCTION_CODE_OPAQUE_RI)
        return OSPF_V3_LSA_FUNCTION_CODE_OPAQUE_RI_BASE;
    else
        return -1;
}

typedef struct _bitfield_info {
    int         *hfindex;
    gint        *ett;
    int         **idx;
    int         num;
} bitfield_info;

static int *bf_dbd[] = {
    &hf_ospf_dbd_r,
    &hf_ospf_dbd_i,
    &hf_ospf_dbd_m,
    &hf_ospf_dbd_ms
};
static int *bf_lls_ext_options[] = {
    &hf_ospf_lls_ext_options_rs,
    &hf_ospf_lls_ext_options_lr
};
static int *bf_v3_lls_ext_options[] = {
    &hf_ospf_v3_lls_ext_options_lr,
    &hf_ospf_v3_lls_ext_options_rs
};

static int *bf_v3_lls_state_options[] = {
    &hf_ospf_v3_lls_state_options_r,
    &hf_ospf_v3_lls_state_options_a,
    &hf_ospf_v3_lls_state_options_n
};
static int *bf_v3_lls_relay_options[] = {
    &hf_ospf_v3_lls_relay_options_a,
    &hf_ospf_v3_lls_relay_options_n
};
static int *bf_v2_router_lsa_flags[] = {
    &hf_ospf_v2_router_lsa_flag_v,
    &hf_ospf_v2_router_lsa_flag_e,
    &hf_ospf_v2_router_lsa_flag_b
};
static int *bf_v2_router_lsa_mt_flags[] = {
    &hf_ospf_v2_router_lsa_flag_n,
    &hf_ospf_v2_router_lsa_flag_w,
    &hf_ospf_v2_router_lsa_flag_v,
    &hf_ospf_v2_router_lsa_flag_e,
    &hf_ospf_v2_router_lsa_flag_b
};
static int *bf_v3_router_lsa_flags[] = {
    &hf_ospf_v3_router_lsa_flag_w,
    &hf_ospf_v3_router_lsa_flag_v,
    &hf_ospf_v3_router_lsa_flag_e,
    &hf_ospf_v3_router_lsa_flag_b
};
static int *bf_v3_as_external_flags[] = {
    &hf_ospf_v3_as_external_flag_e,
    &hf_ospf_v3_as_external_flag_f,
    &hf_ospf_v3_as_external_flag_t
};
static int *bf_v2_options[] = {
    &hf_ospf_v2_options_dn,
    &hf_ospf_v2_options_o,
    &hf_ospf_v2_options_dc,
    &hf_ospf_v2_options_l,
    &hf_ospf_v2_options_n,
    &hf_ospf_v2_options_mc,
    &hf_ospf_v2_options_e,
    &hf_ospf_v2_options_mt
};
static int *bf_v2_options_lsa7[] = {
    &hf_ospf_v2_options_dn,
    &hf_ospf_v2_options_o,
    &hf_ospf_v2_options_dc,
    &hf_ospf_v2_options_l,
    &hf_ospf_v2_options_p,
    &hf_ospf_v2_options_mc,
    &hf_ospf_v2_options_e,
    &hf_ospf_v2_options_mt
};
/* Structures for handling the bitfield of the Options field of Optional Router Capabilites LSA (RFC4970). */
static int *bf_ri_options[] = {
    &hf_ospf_ri_options_grc,
    &hf_ospf_ri_options_grh,
    &hf_ospf_ri_options_srs,
    &hf_ospf_ri_options_tes,
    &hf_ospf_ri_options_p2plan,
    &hf_ospf_ri_options_ete
};
static int *bf_v3_options[] = {
    &hf_ospf_v3_options_at,
    &hf_ospf_v3_options_l,
    &hf_ospf_v3_options_af,
    &hf_ospf_v3_options_dc,
    &hf_ospf_v3_options_r,
    &hf_ospf_v3_options_n,
    &hf_ospf_v3_options_mc,
    &hf_ospf_v3_options_e,
    &hf_ospf_v3_options_v6
};
static int *bf_v3_prefix_options[] = {
    &hf_ospf_v3_prefix_option_p,
    &hf_ospf_v3_prefix_option_mc,
    &hf_ospf_v3_prefix_option_la,
    &hf_ospf_v3_prefix_option_nu
};

static bitfield_info bfinfo_dbd = {
    &hf_ospf_dbd, &ett_ospf_dbd,
    bf_dbd, array_length(bf_dbd)
};
static bitfield_info bfinfo_lls_ext_options = {
    &hf_ospf_lls_ext_options, &ett_ospf_lls_ext_options,
    bf_lls_ext_options, array_length(bf_lls_ext_options)
};
static bitfield_info bfinfo_v3_lls_ext_options = {
    &hf_ospf_v3_lls_ext_options, &ett_ospf_v3_lls_ext_options,
    bf_v3_lls_ext_options, array_length(bf_v3_lls_ext_options)
};
static bitfield_info bfinfo_v3_lls_state_options = {
    &hf_ospf_v3_lls_state_options, &ett_ospf_v3_lls_state_options,
    bf_v3_lls_state_options, array_length(bf_v3_lls_state_options)
};
static bitfield_info bfinfo_v3_lls_relay_options = {
    &hf_ospf_v3_lls_relay_options, &ett_ospf_v3_lls_relay_options,
    bf_v3_lls_relay_options, array_length(bf_v3_lls_relay_options)
};
static bitfield_info bfinfo_v2_router_lsa_flags = {
    &hf_ospf_v2_router_lsa_flag, &ett_ospf_v2_router_lsa_flags,
    bf_v2_router_lsa_flags, array_length(bf_v2_router_lsa_flags)
};
static bitfield_info bfinfo_v2_router_lsa_mt_flags = {
    &hf_ospf_v2_router_lsa_flag, &ett_ospf_v2_router_lsa_flags,
    bf_v2_router_lsa_mt_flags, array_length(bf_v2_router_lsa_mt_flags)
};
static bitfield_info bfinfo_v3_router_lsa_flags = {
    &hf_ospf_v3_router_lsa_flag, &ett_ospf_v3_router_lsa_flags,
    bf_v3_router_lsa_flags, array_length(bf_v3_router_lsa_flags)
};
static bitfield_info bfinfo_v3_as_external_flags = {
    &hf_ospf_v3_as_external_flag, &ett_ospf_v3_as_external_flags,
    bf_v3_as_external_flags, array_length(bf_v3_as_external_flags)
};
static bitfield_info bfinfo_v2_options = {
    &hf_ospf_v2_options, &ett_ospf_v2_options,
    bf_v2_options, array_length(bf_v2_options)
};
static bitfield_info bfinfo_v2_options_lsa7 = {
    &hf_ospf_v2_options, &ett_ospf_v2_options,
    bf_v2_options_lsa7, array_length(bf_v2_options_lsa7)
};
static bitfield_info bfinfo_v3_options = {
    &hf_ospf_v3_options, &ett_ospf_v3_options,
    bf_v3_options, array_length(bf_v3_options)
};
static bitfield_info bfinfo_v3_prefix_options = {
    &hf_ospf_v3_prefix_option, &ett_ospf_v3_prefix_options,
    bf_v3_prefix_options, array_length(bf_v3_prefix_options)
};
/* Structure used for dissecting the Options bitfield of the Optional Router Informational
   Capabilities RI LSA. */
static bitfield_info bfinfo_ri_options = {
    &hf_ospf_ri_options, &ett_ospf_ri_options,
    bf_ri_options, array_length(bf_ri_options)
};

#define MAX_OPTIONS_LEN 128
static void
dissect_ospf_bitfield (proto_tree *parent_tree, tvbuff_t *tvb, int offset,
                        bitfield_info *bfinfo)
{
    proto_item *item = NULL;
    proto_tree *tree = NULL;
    guint32 flags;
    char *str;
    gint length, pos;
    gint i;
    header_field_info *hfinfo;
    int hfindex, idx;
    gint returned_length;

    hfindex = *(bfinfo->hfindex);
    hfinfo = proto_registrar_get_nth(hfindex);
    switch (hfinfo->type) {
    case FT_UINT8:
        flags = tvb_get_guint8(tvb, offset);
        length = 1;
        break;
    case FT_UINT16:
        flags = tvb_get_ntohs(tvb, offset);
        length = 2;
        break;
    case FT_UINT24:
        flags = tvb_get_ntoh24(tvb, offset);
        length = 3;
        break;
    case FT_UINT32:
        flags = tvb_get_ntohl(tvb, offset);
        length = 4;
        break;
    default:
        return;
    }

    if (parent_tree) {
        item = proto_tree_add_uint(parent_tree, hfindex, tvb, offset, length, flags);
        tree = proto_item_add_subtree(item, *bfinfo->ett);

        str = (char *)wmem_alloc(wmem_packet_scope(), MAX_OPTIONS_LEN);
        str[0] = 0;
        for (i = 0, pos = 0; i < bfinfo->num; i++) {
            idx = *(bfinfo->idx[i]);
            hfinfo = proto_registrar_get_nth(idx);
            if (flags & hfinfo->bitmask) {
                returned_length = g_snprintf(&str[pos], MAX_OPTIONS_LEN-pos, "%s%s",
                                  pos ? ", " : "",
                                  hfinfo->name);
                pos += MIN(returned_length, MAX_OPTIONS_LEN-pos);
            }
            proto_tree_add_boolean(tree, idx, tvb, offset, length, flags);
        }
        if (str[0]) {
            proto_item_append_text(item, " (%s)", str);
        }
    }
}

static void dissect_ospf_hello(tvbuff_t*, int, proto_tree*, guint8, guint16);
static void dissect_ospf_db_desc(tvbuff_t*, packet_info*, int, proto_tree*, guint8, guint16, guint8);
static void dissect_ospf_ls_req(tvbuff_t*, packet_info*, int, proto_tree*, guint8, guint16);
static void dissect_ospf_ls_upd(tvbuff_t*, packet_info*, int, proto_tree*, guint8, guint16, guint8);
static void dissect_ospf_ls_ack(tvbuff_t*, packet_info*, int, proto_tree*, guint8, guint16, guint8);
static int dissect_ospf_authentication_trailer(tvbuff_t*, int, proto_tree*);
static void dissect_ospf_lls_data_block(tvbuff_t*, packet_info*, int, proto_tree*, guint8);

/* dissect_ospf_v[23]lsa returns the offset of the next LSA
 * if disassemble_body is set to FALSE (e.g. in LSA ACK
 * packets), the offset is set to the offset of the next
 * LSA header
 */
static int dissect_ospf_v2_lsa(tvbuff_t*, packet_info*, int, proto_tree*, gboolean disassemble_body);
static int dissect_ospf_v3_lsa(tvbuff_t*, packet_info*, int, proto_tree*, gboolean disassemble_body,
                               guint8);

static void dissect_ospf_v3_address_prefix(tvbuff_t *, packet_info *, int, int, proto_tree *, guint8);

static int
ospf_has_lls_block(tvbuff_t *tvb, int offset, guint8 packet_type, guint8 version)
{
    guint8 flags;
    guint32 v3flags;

    /* LLS block can be found only in HELLO and DBDESC packets */
    switch (packet_type) {
    case OSPF_HELLO:
        switch (version) {
        case OSPF_VERSION_2:
            flags = tvb_get_guint8 (tvb, offset + 6);
            return flags & OSPF_V2_OPTIONS_L;
        case OSPF_VERSION_3:
            v3flags = tvb_get_ntohl(tvb, offset + 5);
            v3flags = v3flags >> 8;
            return v3flags & OSPF_V3_OPTIONS_L;
        }
        break;
    case OSPF_DB_DESC:
        switch (version) {
        case OSPF_VERSION_2:
            flags = tvb_get_guint8 (tvb, offset + 2);
            return flags & OSPF_V2_OPTIONS_L;
        case OSPF_VERSION_3:
            v3flags = tvb_get_ntohl(tvb, offset + 1);
            v3flags = v3flags >> 8;
            return v3flags & OSPF_V3_OPTIONS_L;
        }
        break;
    }

    return 0;
}

static int
ospf_has_at_block(tvbuff_t *tvb, int offset, guint8 packet_type, guint8 version)
{
    guint32 v3flags;

    /* AT (Authentication Trailer) block can be found only in OSPFv3 HELLO packets */
    switch (packet_type) {
    case OSPF_HELLO:
        switch (version) {
        case OSPF_VERSION_3:
            v3flags = tvb_get_ntohl(tvb, offset + 5);
            v3flags = v3flags >> 8;
            return v3flags & OSPF_V3_OPTIONS_AT;
        }
    }

    return 0;
}

static gboolean
capture_ospf(const guchar *pd _U_, int offset _U_, int len _U_, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header _U_)
{
    capture_dissector_increment_count(cpinfo, proto_ospf);
    return TRUE;
}

static int
dissect_ospf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *ospf_tree = NULL;
    proto_item *ti, *ti_sum, *hidden_item;
    proto_tree *ospf_header_tree;
    guint8  version;
    guint8  packet_type;
    guint16 ospflen;
    vec_t cksum_vec[4];
    int cksum_vec_len;
    guint32 phdr[2];
    guint16 cksum, computed_cksum;
    guint length, reported_length;
    guint16 auth_type;
    int crypto_len = 0;
    unsigned int ospf_header_length;
    guint8 instance_id;
    guint32 areaid;
    guint8  address_family = OSPF_AF_6;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "OSPF");
    col_clear(pinfo->cinfo, COL_INFO);

    version = tvb_get_guint8(tvb, 0);
    switch (version) {
    case OSPF_VERSION_2:
        ospf_header_length = OSPF_VERSION_2_HEADER_LENGTH;
        break;
    case OSPF_VERSION_3:
        ospf_header_length = OSPF_VERSION_3_HEADER_LENGTH;
        break;
    default:
        ospf_header_length = 14;
        break;
    }

    packet_type = tvb_get_guint8(tvb, 1);
    col_add_str(pinfo->cinfo, COL_INFO,
                val_to_str(packet_type, pt_vals, "Unknown (%u)"));

    ospflen = tvb_get_ntohs(tvb, 2);

    ti = proto_tree_add_item(tree, proto_ospf, tvb, 0, -1, ENC_NA);
    ospf_tree = proto_item_add_subtree(ti, ett_ospf);


    ti = proto_tree_add_item(ospf_tree, hf_ospf_header, tvb, 0, ospf_header_length, ENC_NA);
    ospf_header_tree = proto_item_add_subtree(ti, ett_ospf_hdr);

    proto_tree_add_item(ospf_header_tree, hf_ospf_header_version, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ospf_header_tree, hf_ospf_header_msg_type, tvb, 1, 1, ENC_BIG_ENDIAN);

    if (ospf_msg_type_to_filter(packet_type) != -1) {
        hidden_item = proto_tree_add_item(ospf_header_tree,
                                          *hf_ospf_msg_type_array[ospf_msg_type_to_filter(packet_type)],
                                          tvb, 1, 1, ENC_BIG_ENDIAN);
        PROTO_ITEM_SET_HIDDEN(hidden_item);
    }
    proto_tree_add_item(ospf_header_tree, hf_ospf_header_packet_length, tvb, 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ospf_header_tree, hf_ospf_header_src_router, tvb, 4, 4, ENC_BIG_ENDIAN);


    ti = proto_tree_add_item(ospf_header_tree, hf_ospf_header_area_id, tvb, 8, 4, ENC_BIG_ENDIAN);
    areaid = tvb_get_ntohl(tvb,8);
    if(areaid == 0){
        proto_item_append_text(ti, " (Backbone)");
    }

    ti_sum = proto_tree_add_item(ospf_header_tree, hf_ospf_header_checksum, tvb, 12, 2, ENC_BIG_ENDIAN);
    cksum = tvb_get_ntohs(tvb, 12);
    if(cksum == 0){
        proto_item_append_text(ti_sum, " (None)");
    }

    /* Quit at this point if it's an unknown OSPF version. */
    if(version != OSPF_VERSION_2 && version != OSPF_VERSION_3) {
        return 12;
    }

    length = tvb_captured_length(tvb);
    /* XXX - include only the length from the OSPF header? */
    reported_length = tvb_reported_length(tvb);
    if (cksum !=0 && !pinfo->fragmented && length >= reported_length
               && length >= ospf_header_length) {
        /* The packet isn't part of a fragmented datagram and isn't
           truncated, so we can checksum it. */

        switch (version) {

        case OSPF_VERSION_2:
            /* Header, not including the authentication data (the OSPFv2
               checksum excludes the 64-bit authentication field). */
            SET_CKSUM_VEC_TVB(cksum_vec[0], tvb, 0, 16);
            if (length > ospf_header_length) {
                /* Rest of the packet, again not including the
                   authentication data. */
                reported_length -= ospf_header_length;
                SET_CKSUM_VEC_TVB(cksum_vec[1], tvb, ospf_header_length, reported_length);
                cksum_vec_len = 2;
            } else {
                /* There's nothing but a header. */
                cksum_vec_len = 1;
            }
            break;

        case OSPF_VERSION_3:
            /* IPv6-style checksum, covering the entire OSPF packet
               and a prepended IPv6 pseudo-header. */

            /* Set up the fields of the pseudo-header. */
            SET_CKSUM_VEC_PTR(cksum_vec[0], (const guint8 *)pinfo->src.data, pinfo->src.len);
            SET_CKSUM_VEC_PTR(cksum_vec[1], (const guint8 *)pinfo->dst.data, pinfo->dst.len);
            phdr[0] = g_htonl(ospflen);
            phdr[1] = g_htonl(IP_PROTO_OSPF);
            SET_CKSUM_VEC_PTR(cksum_vec[2], (const guint8 *)&phdr, 8);
            SET_CKSUM_VEC_TVB(cksum_vec[3], tvb, 0, reported_length);
            cksum_vec_len = 4;
            break;

        default:
            DISSECTOR_ASSERT_NOT_REACHED();
            break;
        }
        computed_cksum = in_cksum(cksum_vec, cksum_vec_len);
        if (computed_cksum == 0) {
            proto_item_append_text(ti_sum, " [correct]");
        } else {
            proto_item_append_text(ti_sum, " [incorrect, should be 0x%04x]", in_cksum_shouldbe(cksum, computed_cksum));
        }
    }

    switch (version) {

    case OSPF_VERSION_2:
        /* Authentication is only valid for OSPFv2 */
        proto_tree_add_item(ospf_header_tree, hf_ospf_header_auth_type, tvb, 14, 2, ENC_BIG_ENDIAN);
        auth_type = tvb_get_ntohs(tvb, 14);
        switch (auth_type) {
        case OSPF_AUTH_NONE:
            proto_tree_add_item(ospf_header_tree, hf_ospf_header_auth_data_none, tvb, 16, 8, ENC_NA);
            break;

        case OSPF_AUTH_SIMPLE:
            proto_tree_add_item(ospf_header_tree, hf_ospf_header_auth_data_simple, tvb, 16, 8, ENC_ASCII|ENC_NA);
            break;

        case OSPF_AUTH_CRYPT:
            proto_tree_add_item(ospf_header_tree, hf_ospf_header_auth_crypt_key_id, tvb, 18, 1, ENC_BIG_ENDIAN);

            proto_tree_add_item(ospf_header_tree, hf_ospf_header_auth_crypt_data_length, tvb, 19, 1, ENC_BIG_ENDIAN);
            crypto_len = tvb_get_guint8(tvb, 19);

            proto_tree_add_item(ospf_header_tree, hf_ospf_header_auth_crypt_seq_nbr, tvb, 20, 4, ENC_BIG_ENDIAN);
               /* Show the message digest that was appended to the end of the
               OSPF message - but only if it's present (we don't want
               to get an exception before we've tried dissecting OSPF
               message). */
            if (tvb_bytes_exist(tvb, ospflen, crypto_len)) {
                proto_tree_add_item(ospf_header_tree, hf_ospf_header_auth_crypt_data, tvb, ospflen, crypto_len, ENC_NA);
                proto_tree_set_appendix(ospf_header_tree, tvb, ospflen, crypto_len);
            }
            break;

        default:
            proto_tree_add_item(ospf_header_tree, hf_ospf_header_auth_data_unknown, tvb, 16, 8, ENC_NA);
            break;
        }
        break;

    case OSPF_VERSION_3:
        /* Instance ID and "reserved" is OSPFv3-only */
        proto_tree_add_item(ospf_header_tree, hf_ospf_header_instance_id, tvb, 14, 1, ENC_BIG_ENDIAN);
        instance_id = tvb_get_guint8(tvb, 14);
        /* By default set address_family to OSPF_AF_6 */
        address_family = OSPF_AF_6;
        if(instance_id > 65 && instance_id < 128) {
            address_family = OSPF_AF_4;
        }

        ti = proto_tree_add_item(ospf_header_tree, hf_ospf_header_reserved, tvb, 15, 1, ENC_NA);
        if(tvb_get_guint8(tvb, 15)){
            expert_add_info(pinfo, ti, &ei_ospf_header_reserved);
        }
        break;

    default:
        DISSECTOR_ASSERT_NOT_REACHED();
        break;
    }

    switch (packet_type){

    case OSPF_HELLO:
        dissect_ospf_hello(tvb, ospf_header_length, ospf_tree, version,
                           (guint16)(ospflen - ospf_header_length));
        break;

    case OSPF_DB_DESC:
        dissect_ospf_db_desc(tvb, pinfo, (int)ospf_header_length, ospf_tree, version,
                             (guint16)(ospflen - ospf_header_length),
                                 address_family);
        break;

    case OSPF_LS_REQ:
        dissect_ospf_ls_req(tvb, pinfo, (int)ospf_header_length, ospf_tree, version,
                            (guint16)(ospflen - ospf_header_length));
        break;

    case OSPF_LS_UPD:
        dissect_ospf_ls_upd(tvb, pinfo, (int)ospf_header_length, ospf_tree, version,
                            (guint16)(ospflen - ospf_header_length),
                            address_family);
        break;

    case OSPF_LS_ACK:
        dissect_ospf_ls_ack(tvb, pinfo, (int)ospf_header_length, ospf_tree, version,
                            (guint16)(ospflen - ospf_header_length),
                            address_family);
        break;

    default:
        call_data_dissector(tvb_new_subset_remaining(tvb, ospf_header_length), pinfo, tree);
        break;
    }

    /* take care of the LLS data block */
    if (ospf_has_lls_block(tvb, ospf_header_length, packet_type, version)) {
        dissect_ospf_lls_data_block(tvb, pinfo, ospflen + crypto_len, ospf_tree,
                                    version);
    }

    /* take care of the AT (Authentication Trailer) data block */
    if (ospf_has_at_block(tvb, ospf_header_length, packet_type, version)) {
        dissect_ospf_authentication_trailer(tvb, ospflen + crypto_len, ospf_tree);
    }

    return tvb_captured_length(tvb);
}

static int
dissect_ospfv2_lls_tlv(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_tree *ospf_lls_tlv_tree;
    guint16 type;
    guint16 length;

    type = tvb_get_ntohs(tvb, offset);
    length = tvb_get_ntohs(tvb, offset + 2);

    ospf_lls_tlv_tree = proto_tree_add_subtree(tree, tvb, offset, length + 4, ett_ospf_lls_tlv,
                             NULL, val_to_str_const(type, lls_tlv_type_vals, "Unknown LLS TLV"));

    proto_tree_add_item(ospf_lls_tlv_tree, hf_ospf_tlv_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ospf_lls_tlv_tree, hf_ospf_tlv_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

    switch(type) {
    case 1:
        dissect_ospf_bitfield(ospf_lls_tlv_tree, tvb, offset + 4, &bfinfo_lls_ext_options);
        break;
    case 2:
        proto_tree_add_item(ospf_lls_tlv_tree, hf_ospf_v2_lls_sequence_number, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ospf_lls_tlv_tree, hf_ospf_v2_lls_auth_data, tvb, offset + 8, length - 4, ENC_NA);
        break;
    }

    return offset + length + 4;
}

static int
dissect_ospfv3_lls_tlv(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_tree *ospf_lls_tlv_tree = NULL;
    guint16 type;
    guint16 length;
    guint8 relays_added;
    int orig_offset;

    type = tvb_get_ntohs(tvb, offset);
    length = tvb_get_ntohs(tvb, offset + 2);

    switch(type) {
    case LLS_V3_EXT_OPT:
        ti = proto_tree_add_item(tree, hf_ospf_v3_lls_ext_options_tlv, tvb,
                                 offset, length + 4, ENC_NA);
       break;
    case LLS_V3_STATE_CHECK:
        ti = proto_tree_add_item(tree, hf_ospf_v3_lls_state_tlv, tvb,
                                 offset, length + 4, ENC_NA);
        break;
    case LLS_V3_NBR_DROP:
        ti = proto_tree_add_item(tree, hf_ospf_v3_lls_drop_tlv, tvb,
                                 offset, length + 4, ENC_NA);
        break;
    case LLS_V3_RELAYS:
        ti = proto_tree_add_item(tree, hf_ospf_v3_lls_relay_tlv, tvb,
                                 offset, length + 4, ENC_NA);
        break;
    case LLS_V3_WILLING:
        ti = proto_tree_add_item(tree, hf_ospf_v3_lls_willingness_tlv, tvb,
                                 offset, length + 4, ENC_NA);
        break;
    case LLS_V3_RQST_FROM:
         ti = proto_tree_add_item(tree, hf_ospf_v3_lls_rf_tlv, tvb,
                                  offset, length + 4, ENC_NA);
         break;
    case LLS_V3_FULL_STATE:
        ti = proto_tree_add_item(tree, hf_ospf_v3_lls_fsf_tlv, tvb,
                                 offset, length + 4, ENC_NA);
        break;
    default:
        ospf_lls_tlv_tree = proto_tree_add_subtree_format(tree, tvb, offset, length + 4, ett_ospf_lls_tlv, NULL,
                                 "%s", val_to_str_const(type, lls_v3_tlv_type_vals, "Unknown LLS TLV"));
    }

    if (ti != NULL)
        ospf_lls_tlv_tree = proto_item_add_subtree(ti, ett_ospf_lls_tlv);
    proto_tree_add_item(ospf_lls_tlv_tree, hf_ospf_tlv_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ospf_lls_tlv_tree, hf_ospf_tlv_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

    orig_offset = offset;

    switch (type) {
    case LLS_V3_EXT_OPT:
        proto_tree_add_item(ospf_lls_tlv_tree, hf_ospf_v3_lls_extended_options, tvb, offset + 4, 4, ENC_BIG_ENDIAN);

        dissect_ospf_bitfield(ospf_lls_tlv_tree, tvb, offset + 4, &bfinfo_v3_lls_ext_options);
        break;
    case LLS_V3_STATE_CHECK:
        proto_tree_add_item(ospf_lls_tlv_tree, hf_ospf_v3_lls_state_scs,
                            tvb, offset+4, 2, ENC_BIG_ENDIAN);

        dissect_ospf_bitfield(ospf_lls_tlv_tree, tvb, offset + 6,
                              &bfinfo_v3_lls_state_options);
        break;
    case LLS_V3_NBR_DROP:
        offset += 4;
        while (orig_offset + length >= offset) {
            proto_tree_add_item(ospf_lls_tlv_tree, hf_ospf_v3_lls_dropped_neighbor, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }
        offset = orig_offset;
        break;
    case LLS_V3_RELAYS:
        relays_added = tvb_get_guint8(tvb, offset+4);
        proto_tree_add_item(ospf_lls_tlv_tree, hf_ospf_v3_lls_relay_added,
                            tvb, offset+4, 1, ENC_BIG_ENDIAN);
        dissect_ospf_bitfield(ospf_lls_tlv_tree, tvb, offset + 5,
                              &bfinfo_v3_lls_relay_options);
        offset += 8;
        while (orig_offset + length >= offset) {
            ti = proto_tree_add_item(ospf_lls_tlv_tree, hf_ospf_v3_lls_neighbor, tvb, offset, 4, ENC_BIG_ENDIAN);
            if (relays_added > 0) {
                proto_item_append_text(ti, " Added");
            } else {
                proto_item_append_text(ti, " Deleted");
            }

            relays_added--;
            offset += 4;
        }
        break;
    case LLS_V3_WILLING:
        proto_tree_add_item(ospf_lls_tlv_tree, hf_ospf_v3_lls_willingness,
                            tvb, offset+4, 1, ENC_BIG_ENDIAN);

        break;
    case LLS_V3_RQST_FROM:
        offset += 4;
        while (orig_offset + length >= offset) {
            proto_tree_add_item(ospf_lls_tlv_tree, hf_ospf_v3_lls_request_from, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }
        offset = orig_offset;
        break;
    case LLS_V3_FULL_STATE:
           offset += 4;
        while (orig_offset + length >= offset) {
            proto_tree_add_item(ospf_lls_tlv_tree, hf_ospf_v3_lls_full_state_for, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }
        offset = orig_offset;
        break;
    }

    return offset + length + 4;
}


static void
dissect_ospf_lls_data_block(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree,
                            guint8 version)
{
    proto_tree *ospf_lls_data_block_tree;
    int ospf_lls_len;
    int orig_offset = offset;
    guint length_remaining;

    length_remaining = tvb_reported_length_remaining(tvb, offset);
    if (length_remaining < 4) {
        proto_tree_add_expert_format(tree, pinfo, &ei_ospf_lsa_bad_length,
            tvb, offset, length_remaining, "LLS option bit set but data block missing");
        return;
    }

    ospf_lls_len = tvb_get_ntohs(tvb, offset + 2) * 4;
    ospf_lls_data_block_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_ospf_lls_data_block, NULL, "OSPF LLS Data Block");

    /* TODO: verify checksum */
    proto_tree_add_checksum(ospf_lls_data_block_tree, tvb, offset, hf_ospf_lls_checksum, -1, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
    proto_tree_add_uint_format_value(ospf_lls_data_block_tree, hf_ospf_lls_data_length, tvb, offset + 2, 2,
                        ospf_lls_len, "%d bytes", ospf_lls_len);

    offset += 4;
    DISSECTOR_ASSERT((version == OSPF_VERSION_2) || (version == OSPF_VERSION_3));
    while (orig_offset + ospf_lls_len > offset) {
        if (version == OSPF_VERSION_2)
            offset = dissect_ospfv2_lls_tlv (tvb, offset, ospf_lls_data_block_tree);
        else
            offset = dissect_ospfv3_lls_tlv (tvb, offset, ospf_lls_data_block_tree);
    }
}

static int
dissect_ospf_authentication_trailer(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_tree *ospf_at_tree;
    proto_item *ti;
    guint32 auth_data_len;

    ti = proto_tree_add_item(tree, hf_ospf_at, tvb, offset, -1, ENC_NA);
    ospf_at_tree = proto_item_add_subtree(ti, ett_ospf_at);

    proto_tree_add_item(ospf_at_tree, hf_ospf_at_auth_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item_ret_uint(ospf_at_tree, hf_ospf_at_auth_data_len, tvb, offset, 2, ENC_BIG_ENDIAN, &auth_data_len);
    offset += 2;
    if (auth_data_len < (2 + 2 + 2 + 8)) {
        /* XXX - report an error here */
        proto_item_set_len(ti, 4);
        return offset;
    }
    proto_item_set_len(ti, auth_data_len);

    proto_tree_add_item(ospf_at_tree, hf_ospf_at_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(ospf_at_tree, hf_ospf_at_sa_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(ospf_at_tree, hf_ospf_at_crypto_seq_nbr, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    /* Add Check of Data ? */
    proto_tree_add_item(ospf_at_tree, hf_ospf_at_auth_data, tvb, offset, auth_data_len - ( 2 + 2 + 2 + 2 + 8), ENC_NA);
    offset = auth_data_len;

    return offset;
}

static void
dissect_ospf_hello(tvbuff_t *tvb, int offset, proto_tree *tree, guint8 version,
                   guint16 length)
{
    proto_tree *ospf_hello_tree;
    proto_item *ti;
    int orig_offset = offset;

    ti = proto_tree_add_item(tree, hf_ospf_hello, tvb, offset, length, ENC_NA);
    ospf_hello_tree = proto_item_add_subtree(ti, ett_ospf_hello);

    switch (version) {
    case OSPF_VERSION_2:
        proto_tree_add_item(ospf_hello_tree, hf_ospf_hello_network_mask, tvb, offset, 4, ENC_NA);
        proto_tree_add_item(ospf_hello_tree, hf_ospf_hello_hello_interval, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
        dissect_ospf_bitfield(ospf_hello_tree, tvb, offset + 6, &bfinfo_v2_options);
        proto_tree_add_item(ospf_hello_tree, hf_ospf_hello_router_priority, tvb, offset + 7, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ospf_hello_tree, hf_ospf_hello_router_dead_interval, tvb, offset + 8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ospf_hello_tree, hf_ospf_hello_designated_router, tvb, offset + 12, 4, ENC_NA);
        proto_tree_add_item(ospf_hello_tree, hf_ospf_hello_backup_designated_router, tvb, offset + 16, 4, ENC_NA);
        offset += 20;

        while (orig_offset + length > offset) {
            proto_tree_add_item(ospf_hello_tree, hf_ospf_hello_active_neighbor, tvb, offset, 4, ENC_NA);
            offset += 4;
        }
        break;
    case OSPF_VERSION_3:
        proto_tree_add_item(ospf_hello_tree, hf_ospf_hello_interface_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ospf_hello_tree, hf_ospf_hello_router_priority, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        dissect_ospf_bitfield(ospf_hello_tree, tvb, offset + 5, &bfinfo_v3_options);
        proto_tree_add_item(ospf_hello_tree, hf_ospf_hello_hello_interval, tvb, offset + 8, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(ospf_hello_tree, hf_ospf_hello_router_dead_interval, tvb, offset + 10, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(ospf_hello_tree, hf_ospf_hello_designated_router, tvb, offset + 12, 4, ENC_NA);
        proto_tree_add_item(ospf_hello_tree, hf_ospf_hello_backup_designated_router, tvb, offset + 16, 4, ENC_NA);
        offset += 20;

        while (orig_offset + length > offset) {
            proto_tree_add_item(ospf_hello_tree, hf_ospf_hello_active_neighbor, tvb, offset, 4, ENC_NA);
            offset += 4;
        }
        break;
    }
}

static void
dissect_ospf_db_desc(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree,
                     guint8 version, guint16 length, guint8 address_family)
{
    proto_tree *ospf_db_desc_tree;
    proto_item *ti;
    guint8 reserved;
    int orig_offset = offset;

    if (tree) {
        ospf_db_desc_tree = proto_tree_add_subtree(tree, tvb, offset, length, ett_ospf_desc, NULL, "OSPF DB Description");

        switch (version ) {

        case OSPF_VERSION_2:
            proto_tree_add_item(ospf_db_desc_tree, hf_ospf_db_interface_mtu, tvb, offset, 2, ENC_BIG_ENDIAN);

            dissect_ospf_bitfield(ospf_db_desc_tree, tvb, offset + 2, &bfinfo_v2_options);
            dissect_ospf_bitfield(ospf_db_desc_tree, tvb, offset + 3, &bfinfo_dbd);

            proto_tree_add_item(ospf_db_desc_tree, hf_ospf_db_dd_sequence, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
            break;

        case OSPF_VERSION_3:

            reserved = tvb_get_guint8(tvb, offset);
            ti = proto_tree_add_item(ospf_db_desc_tree, hf_ospf_header_reserved, tvb, offset, 1, ENC_NA);
            if (reserved != 0)
                expert_add_info(pinfo, ti, &ei_ospf_header_reserved);

            dissect_ospf_bitfield(ospf_db_desc_tree, tvb, offset + 1, &bfinfo_v3_options);

            proto_tree_add_item(ospf_db_desc_tree, hf_ospf_db_interface_mtu, tvb, offset + 4, 2, ENC_BIG_ENDIAN);

            reserved = tvb_get_guint8(tvb, offset + 6);
            ti = proto_tree_add_item(ospf_db_desc_tree, hf_ospf_header_reserved, tvb, offset + 6, 1, ENC_NA);
            if (reserved != 0)
                expert_add_info(pinfo, ti, &ei_ospf_header_reserved);

            dissect_ospf_bitfield(ospf_db_desc_tree, tvb, offset + 7, &bfinfo_dbd);

            proto_tree_add_item(ospf_db_desc_tree, hf_ospf_db_dd_sequence, tvb, offset + 8, 4, ENC_BIG_ENDIAN);
            break;
        }
    }
    switch (version ) {
    case OSPF_VERSION_2:
        offset += 8;
        break;
    case OSPF_VERSION_3:
        offset += 12;
        break;
    }

    /* LS Headers will be processed here */
    /* skip to the end of DB-Desc header */
    DISSECTOR_ASSERT((version == OSPF_VERSION_2) || (version == OSPF_VERSION_3));
    while (orig_offset + length > offset) {
        if ( version == OSPF_VERSION_2)
            offset = dissect_ospf_v2_lsa(tvb, pinfo, offset, tree, FALSE);
        else
            offset = dissect_ospf_v3_lsa(tvb, pinfo, offset, tree, FALSE, address_family);
    }

}

static void
dissect_ospf_ls_req(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree, guint8 version,
                    guint16 length)
{
    proto_item *ti;
    proto_tree *ospf_lsr_tree;
    guint16 reserved;
    int orig_offset = offset;

    /* zero or more LS requests may be within a LS Request */
    /* we place every request for a LSA in a single subtree */
    while (orig_offset + length > offset) {
        ospf_lsr_tree = proto_tree_add_subtree(tree, tvb, offset, OSPF_LS_REQ_LENGTH,
                                 ett_ospf_lsr, NULL, "Link State Request");

        switch ( version ) {

        case OSPF_VERSION_2:
            proto_tree_add_item(ospf_lsr_tree, hf_ospf_ls_type,
                                tvb, offset, 4, ENC_BIG_ENDIAN);
            break;
        case OSPF_VERSION_3:
            reserved = tvb_get_ntohs(tvb, offset);
            ti = proto_tree_add_item(ospf_lsr_tree, hf_ospf_header_reserved, tvb, offset, 2, ENC_NA);
            if (reserved != 0)
                expert_add_info(pinfo, ti, &ei_ospf_header_reserved);

            proto_tree_add_item(ospf_lsr_tree, hf_ospf_v3_ls_type,
                                tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            break;
        }


        proto_tree_add_item(ospf_lsr_tree, hf_ospf_link_state_id, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ospf_lsr_tree, hf_ospf_adv_router,
                            tvb, offset + 8, 4, ENC_BIG_ENDIAN);

        offset += 12;
    }
}

static void
dissect_ospf_ls_upd(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree, guint8 version,
                    guint16 length, guint8 address_family)
{
    proto_tree *ospf_lsa_upd_tree;
    guint32 lsa_nr;
    guint32 lsa_counter;

    ospf_lsa_upd_tree = proto_tree_add_subtree(tree, tvb, offset, length, ett_ospf_lsa_upd, NULL, "LS Update Packet");

    lsa_nr = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(ospf_lsa_upd_tree, hf_ospf_ls_number_of_lsas, tvb, offset, 4, ENC_BIG_ENDIAN);
    /* skip to the beginning of the first LSA */
    offset += 4; /* the LS Upd Packet contains only a 32 bit #LSAs field */

    DISSECTOR_ASSERT((version == OSPF_VERSION_2) || (version == OSPF_VERSION_3));
    lsa_counter = 0;
    while (lsa_counter < lsa_nr) {
        if (version == OSPF_VERSION_2)
            offset = dissect_ospf_v2_lsa(tvb, pinfo, offset, ospf_lsa_upd_tree, TRUE);
        else
            offset = dissect_ospf_v3_lsa(tvb, pinfo, offset, ospf_lsa_upd_tree, TRUE,
                                         address_family);
        lsa_counter += 1;
    }
}

static void
dissect_ospf_ls_ack(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree, guint8 version,
                    guint16 length, guint8 address_family)
{
    int orig_offset = offset;
    DISSECTOR_ASSERT((version == OSPF_VERSION_2) || (version == OSPF_VERSION_3));
    /* the body of a LS Ack packet simply contains zero or more LSA Headers */
    while (orig_offset + length > offset) {
        if (version == OSPF_VERSION_2)
            offset = dissect_ospf_v2_lsa(tvb, pinfo, offset, tree, FALSE);
        else
            offset = dissect_ospf_v3_lsa(tvb, pinfo, offset, tree, FALSE, address_family);
    }
}

/*
 * Returns if an LSA is opaque, i.e. requires special treatment
 */
static int
is_opaque(int lsa_type)
{
    return (lsa_type >= OSPF_LSTYPE_OP_LINKLOCAL &&
        lsa_type <= OSPF_LSTYPE_OP_ASWIDE);
}

/* MPLS/TE TLV types */
#define MPLS_TLV_ROUTER    1
#define MPLS_TLV_LINK      2
#define OIF_TLV_TNA    32768

/* MPLS/TE Link STLV types */
enum {
    MPLS_LINK_TYPE       = 1,           /* RFC 3630, OSPF-TE   */
    MPLS_LINK_ID,
    MPLS_LINK_LOCAL_IF,
    MPLS_LINK_REMOTE_IF,
    MPLS_LINK_TE_METRIC,
    MPLS_LINK_MAX_BW,
    MPLS_LINK_MAX_RES_BW,
    MPLS_LINK_UNRES_BW,
    MPLS_LINK_COLOR,
    MPLS_LINK_LOCAL_REMOTE_ID = 11,     /* RFC 4203, GMPLS     */
    MPLS_LINK_PROTECTION = 14,
    MPLS_LINK_IF_SWITCHING_DESC,
    MPLS_LINK_SHARED_RISK_GROUP,
    MPLS_LINK_BANDWIDTH_CONSTRAINT = 17 /* RFC 4124, OSPF-DSTE */
};


/* OIF TLV types */
enum {
    OIF_LOCAL_NODE_ID = 32773,
    OIF_REMOTE_NODE_ID,
    OIF_SONET_SDH_SWITCHING_CAPABILITY,
    OIF_TNA_IPv4_ADDRESS,
    OIF_NODE_ID,
    OIF_TNA_IPv6_ADDRESS,
    OIF_TNA_NSAP_ADDRESS
};

static const value_string mpls_link_stlv_str[] = {
    {MPLS_LINK_TYPE, "Link Type"},
    {MPLS_LINK_ID, "Link ID"},
    {MPLS_LINK_LOCAL_IF, "Local Interface IP Address"},
    {MPLS_LINK_REMOTE_IF, "Remote Interface IP Address"},
    {MPLS_LINK_TE_METRIC, "Traffic Engineering Metric"},
    {MPLS_LINK_MAX_BW, "Maximum Bandwidth"},
    {MPLS_LINK_MAX_RES_BW, "Maximum Reservable Bandwidth"},
    {MPLS_LINK_UNRES_BW, "Unreserved Bandwidth"},
    {MPLS_LINK_COLOR, "Resource Class/Color"},
    {MPLS_LINK_LOCAL_REMOTE_ID, "Link Local/Remote Identifier"},
    {MPLS_LINK_PROTECTION, "Link Protection Type"},
    {MPLS_LINK_IF_SWITCHING_DESC, "Interface Switching Capability Descriptor"},
    {MPLS_LINK_SHARED_RISK_GROUP, "Shared Risk Link Group"},
    {MPLS_LINK_BANDWIDTH_CONSTRAINT, "Bandwidth Constraints"},
    {OIF_LOCAL_NODE_ID, "Local Node ID"},
    {OIF_REMOTE_NODE_ID, "Remote Node ID"},
    {OIF_SONET_SDH_SWITCHING_CAPABILITY, "Sonet/SDH Interface Switching Capability"},
    {0, NULL},
};

static const range_string mpls_te_tlv_rvals[] = {
    { 3,     32767, "(Assigned via Standards Action)"},
    { 32768, 32777, "(For Experimental Use)"},
    { 32778, 65535, "(Not to be Assigned)"},
    { 0,         0, NULL}
};

static const range_string mpls_te_sub_tlv_rvals[] = {
    { 10,     32767, "(Assigned via Standards Action)"},
    { 32768, 32777, "(For Experimental Use)"},
    { 32778, 65535, "(Not to be Assigned)"},
    { 0,         0, NULL}
};

static const value_string oif_stlv_str[] = {
    {OIF_TNA_IPv4_ADDRESS, "TNA address"},
    {OIF_NODE_ID, "Node ID"},
    {OIF_TNA_IPv6_ADDRESS, "TNA address"},
    {OIF_TNA_NSAP_ADDRESS, "TNA address"},
    {0, NULL},
};

static const range_string ospf_instance_id_rvals[] = {
    { 0, 31, "IPv6 unicast AF" },
    { 32, 63, "IPv6 multicast AF" },
    { 64, 95, "IPv4 unicast AF" },
    { 96, 127, "IPv4 multicast AF" },
    { 128, 255, "Reserved" },
    { 0, 0, NULL },
};

/*
 * Dissect MPLS/TE opaque LSA
 */
static void
dissect_ospf_lsa_mpls(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree,
                      guint32 length)
{
    proto_item *ti, *hidden_item;
    proto_tree *mpls_tree;
    proto_tree *tlv_tree;
    proto_tree *stlv_tree;
    proto_tree *stlv_admingrp_tree = NULL;

    int tlv_type;
    int tlv_length;
    int tlv_end_offset;

    int stlv_type, stlv_len, stlv_offset;
    const char *stlv_name;
    guint32 stlv_admingrp, mask;
    int i;
    guint8 switch_cap;
    float tmp_float;

    const guint8 allzero[] = { 0x00, 0x00, 0x00 };
    guint num_bcs = 0;

    mpls_tree = proto_tree_add_subtree(tree, tvb, offset, length,
                             ett_ospf_lsa_mpls, NULL, "MPLS Traffic Engineering LSA");
    hidden_item = proto_tree_add_item(tree, hf_ospf_ls_mpls,
                                      tvb, offset, 2, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_HIDDEN(hidden_item);

    while (length != 0) {
        tlv_type = tvb_get_ntohs(tvb, offset);
        tlv_length = tvb_get_ntohs(tvb, offset + 2);
        tlv_end_offset = offset + tlv_length + 4;

        switch (tlv_type) {

        case MPLS_TLV_ROUTER:
            tlv_tree = proto_tree_add_subtree_format(mpls_tree, tvb, offset, tlv_length+4,
                                     ett_ospf_lsa_mpls_router, NULL, "Router Address: %s",
                                     tvb_ip_to_str(tvb, offset+4));
            proto_tree_add_uint_format_value(tlv_tree, hf_ospf_tlv_type, tvb, offset, 2, tlv_type, "1 - Router Address");
            proto_tree_add_item(tlv_tree, hf_ospf_tlv_length, tvb, offset+2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_ospf_ls_mpls_routerid,
                                tvb, offset+4, 4, ENC_BIG_ENDIAN);
            break;

        case MPLS_TLV_LINK:
            tlv_tree = proto_tree_add_subtree(mpls_tree, tvb, offset, tlv_length+4,
                                     ett_ospf_lsa_mpls_link, NULL, "Link Information");
            proto_tree_add_uint_format_value(tlv_tree, hf_ospf_tlv_type, tvb, offset, 2, tlv_type, "2 - Link Information");
            proto_tree_add_item(tlv_tree, hf_ospf_tlv_length, tvb, offset+2, 2, ENC_BIG_ENDIAN);
            stlv_offset = offset + 4;

            /* Walk down the sub-TLVs for link information */
            while (stlv_offset < tlv_end_offset) {
                stlv_type = tvb_get_ntohs(tvb, stlv_offset);
                stlv_len = tvb_get_ntohs(tvb, stlv_offset + 2);
                stlv_name = val_to_str_const(stlv_type, mpls_link_stlv_str, "Unknown sub-TLV");
                switch (stlv_type) {

                case MPLS_LINK_TYPE:
                    stlv_tree = proto_tree_add_subtree_format(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             ett_ospf_lsa_mpls_link_stlv, NULL, "%s: %u - %s", stlv_name,
                                             tvb_get_guint8(tvb, stlv_offset + 4),
                                             val_to_str_const(tvb_get_guint8(tvb, stlv_offset + 4),
                                                              mpls_link_stlv_ltype_str, "Unknown Link Type"));
                    proto_tree_add_uint_format_value(stlv_tree, hf_ospf_tlv_type, tvb, stlv_offset, 2,
                                        stlv_type, "%u: %s", stlv_type, stlv_name);
                    proto_tree_add_item(stlv_tree, hf_ospf_tlv_length, tvb, stlv_offset+2, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(stlv_tree, hf_ospf_ls_mpls_linktype,
                                        tvb, stlv_offset+4, 1,ENC_BIG_ENDIAN);
                    break;

                case MPLS_LINK_ID:
                    stlv_tree = proto_tree_add_subtree_format(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             ett_ospf_lsa_mpls_link_stlv, NULL, "%s: %s", stlv_name,
                                             tvb_ip_to_str(tvb, stlv_offset + 4));
                    proto_tree_add_uint_format_value(stlv_tree, hf_ospf_tlv_type, tvb, stlv_offset, 2,
                                        stlv_type, "%u: %s", stlv_type, stlv_name);
                    proto_tree_add_item(stlv_tree, hf_ospf_tlv_length, tvb, stlv_offset+2, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(stlv_tree, hf_ospf_ls_mpls_linkid,
                                        tvb, stlv_offset+4, 4, ENC_BIG_ENDIAN);
                    break;

                case MPLS_LINK_LOCAL_IF:
                case MPLS_LINK_REMOTE_IF:
                    stlv_tree = proto_tree_add_subtree_format(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             ett_ospf_lsa_mpls_link_stlv, NULL, "%s: %s", stlv_name,
                                             tvb_ip_to_str(tvb, stlv_offset + 4));
                    proto_tree_add_uint_format_value(stlv_tree, hf_ospf_tlv_type, tvb, stlv_offset, 2,
                                        stlv_type, "%u: %s", stlv_type, stlv_name);
                    proto_tree_add_item(stlv_tree, hf_ospf_tlv_length, tvb, stlv_offset+2, 2, ENC_BIG_ENDIAN);
                    /*   The Local/Remote Interface IP Address sub-TLV is TLV type 3/4, and is 4N
                         octets in length, where N is the number of neighbor addresses. */
                    for (i=0; i < stlv_len; i+=4)
                        proto_tree_add_item(stlv_tree,
                                            stlv_type==MPLS_LINK_LOCAL_IF ?
                                            hf_ospf_ls_mpls_local_addr :
                                            hf_ospf_ls_mpls_remote_addr,
                                            tvb, stlv_offset+4+i, 4, ENC_BIG_ENDIAN);
                    break;

                case MPLS_LINK_TE_METRIC:
                    stlv_tree = proto_tree_add_subtree_format(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             ett_ospf_lsa_mpls_link_stlv, NULL, "%s: %u", stlv_name,
                                             tvb_get_ntohl(tvb, stlv_offset + 4));
                    proto_tree_add_uint_format_value(stlv_tree, hf_ospf_tlv_type, tvb, stlv_offset, 2,
                                        stlv_type, "%u: %s", stlv_type, stlv_name);
                    proto_tree_add_item(stlv_tree, hf_ospf_tlv_length, tvb, stlv_offset+2, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_uint_format(stlv_tree, hf_ospf_ls_mpls_te_metric, tvb, stlv_offset+4, 4,
                                        tvb_get_ntohl(tvb, stlv_offset + 4), "%s: %u", stlv_name,
                                        tvb_get_ntohl(tvb, stlv_offset + 4));
                    break;

                case MPLS_LINK_COLOR:
                    stlv_tree = proto_tree_add_subtree_format(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             ett_ospf_lsa_mpls_link_stlv, NULL, "%s: 0x%08x", stlv_name,
                                             tvb_get_ntohl(tvb, stlv_offset + 4));
                    proto_tree_add_uint_format_value(stlv_tree, hf_ospf_tlv_type, tvb, stlv_offset, 2,
                                        stlv_type, "%u: %s", stlv_type, stlv_name);
                    proto_tree_add_item(stlv_tree, hf_ospf_tlv_length, tvb, stlv_offset+2, 2, ENC_BIG_ENDIAN);
                    stlv_admingrp = tvb_get_ntohl(tvb, stlv_offset + 4);
                    mask = 1;
                    ti = proto_tree_add_item(stlv_tree, hf_ospf_ls_mpls_linkcolor,
                                             tvb, stlv_offset+4, 4, ENC_BIG_ENDIAN);
                    stlv_admingrp_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link_stlv_admingrp);
                    if (stlv_admingrp_tree == NULL)
                        return;
                    for (i = 0 ; i < 32 ; i++) {
                        if ((stlv_admingrp & mask) != 0) {
                            proto_tree_add_uint_format(stlv_admingrp_tree, hf_ospf_ls_mpls_group, tvb, stlv_offset+4,
                                                4, 1 << i, "Group %d", i);
                        }
                        mask <<= 1;
                    }
                    break;

                case MPLS_LINK_MAX_BW:
                case MPLS_LINK_MAX_RES_BW:
                    stlv_tree = proto_tree_add_subtree_format(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             ett_ospf_lsa_mpls_link_stlv, NULL, "%s: %.10g bytes/s (%.0f bits/s)", stlv_name,
                                             tvb_get_ntohieee_float(tvb, stlv_offset + 4),
                                             tvb_get_ntohieee_float(tvb, stlv_offset + 4) * 8.0);
                    proto_tree_add_uint_format_value(stlv_tree, hf_ospf_tlv_type, tvb, stlv_offset, 2,
                                        stlv_type, "%u: %s", stlv_type, stlv_name);
                    proto_tree_add_item(stlv_tree, hf_ospf_tlv_length, tvb, stlv_offset+2, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_float_format(stlv_tree, hf_ospf_ls_mpls_link_max_bw, tvb, stlv_offset+4, 4,
                                        tvb_get_ntohieee_float(tvb, stlv_offset + 4), "%s: %.10g bytes/s (%.0f bits/s)", stlv_name,
                                        tvb_get_ntohieee_float(tvb, stlv_offset + 4),
                                        tvb_get_ntohieee_float(tvb, stlv_offset + 4) * 8.0);
                    break;

                case MPLS_LINK_UNRES_BW:
                    stlv_tree = proto_tree_add_subtree(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             ett_ospf_lsa_mpls_link_stlv, NULL, stlv_name);
                    proto_tree_add_uint_format_value(stlv_tree, hf_ospf_tlv_type, tvb, stlv_offset, 2,
                                        stlv_type, "%u: %s", stlv_type, stlv_name);
                    proto_tree_add_item(stlv_tree, hf_ospf_tlv_length, tvb, stlv_offset+2, 2, ENC_BIG_ENDIAN);
                    for (i = 0; i < 8; i++) {
                        tmp_float = tvb_get_ntohieee_float(tvb, stlv_offset + 4 + i*4);
                        proto_tree_add_float_format(stlv_tree, hf_ospf_ls_mpls_pri, tvb, stlv_offset+4+(i*4), 4,
                                            tmp_float, "Pri (or TE-Class) %d: %.10g bytes/s (%.0f bits/s)", i,
                                            tmp_float, tmp_float * 8.0);
                    }
                    break;

                case MPLS_LINK_BANDWIDTH_CONSTRAINT:
                    /*
                      The "Bandwidth Constraints" sub-TLV format is illustrated below:

                      0                   1                   2                   3
                      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                      | BC Model Id   |           Reserved                            |
                      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                      |                       BC0 value                               |
                      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                      //                       . . .                                 //
                      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                      |                       BCh value                               |
                      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    */

                    stlv_tree = proto_tree_add_subtree(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             ett_ospf_lsa_mpls_link_stlv, NULL, stlv_name);

                    proto_tree_add_uint_format_value(stlv_tree, hf_ospf_tlv_type, tvb, stlv_offset, 2,
                                        stlv_type, "%u: %s", stlv_type, stlv_name);

                    proto_tree_add_item(stlv_tree, hf_ospf_tlv_length, tvb, stlv_offset+2, 2, ENC_BIG_ENDIAN);

                    proto_tree_add_item(stlv_tree, hf_ospf_ls_mpls_bc_model_id,
                                        tvb, stlv_offset+4, 1, ENC_BIG_ENDIAN);

                    /* 3 octets reserved +5, +6 and +7 (all 0x00) */
                    if(tvb_memeql(tvb, stlv_offset+5, allzero, 3) == -1) {
                        proto_tree_add_expert_format(stlv_tree, pinfo, &ei_ospf_header_reserved,
                                            tvb, stlv_offset+5, 3,
                                            "These bytes are reserved and must be 0x00");
                    }

                    if(((stlv_len % 4)!=0)) {
                        proto_tree_add_expert_format(stlv_tree, pinfo, &ei_ospf_lsa_bad_length, tvb, stlv_offset+4, stlv_len,
                                            "Malformed Packet: Length must be N x 4 octets");
                        break;
                    }

                    /* stlv_len shound range from 4 to 36 bytes */
                    num_bcs = (stlv_len - 4)/4;

                    if(num_bcs>8) {
                        proto_tree_add_expert_format(stlv_tree, pinfo, &ei_ospf_lsa_bc_error, tvb, stlv_offset+4, stlv_len,
                                            "Malformed Packet: too many BC (%u)", num_bcs);
                        break;
                    }

                    if(num_bcs==0) {
                        proto_tree_add_expert_format(stlv_tree, pinfo, &ei_ospf_lsa_bc_error, tvb, stlv_offset+4, stlv_len,
                                            "Malformed Packet: Bandwidth Constraints sub-TLV with no BC?");
                        break;
                    }

                    for(i = 0; i < (int) num_bcs; i++) {
                        tmp_float = tvb_get_ntohieee_float(tvb, stlv_offset + 8 + i*4);
                        proto_tree_add_float_format(stlv_tree, hf_ospf_ls_mpls_bc, tvb, stlv_offset+8+(i*4), 4,
                                            tmp_float, "BC %d: %.10g bytes/s (%.0f bits/s)", i,
                                            tmp_float, tmp_float * 8.0);
                    }
                    break;

                case MPLS_LINK_LOCAL_REMOTE_ID:
                    stlv_tree = proto_tree_add_subtree_format(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             ett_ospf_lsa_mpls_link_stlv, NULL, "%s: %d (0x%x) - %d (0x%x)", stlv_name,
                                             tvb_get_ntohl(tvb, stlv_offset + 4),
                                             tvb_get_ntohl(tvb, stlv_offset + 4),
                                             tvb_get_ntohl(tvb, stlv_offset + 8),
                                             tvb_get_ntohl(tvb, stlv_offset + 8));

                    proto_tree_add_uint_format_value(stlv_tree, hf_ospf_tlv_type, tvb, stlv_offset, 2,
                                        stlv_type, "%u: %s", stlv_type, stlv_name);
                    proto_tree_add_item(stlv_tree, hf_ospf_tlv_length, tvb, stlv_offset+2, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(stlv_tree,
                                        hf_ospf_ls_mpls_local_ifid,
                                        tvb, stlv_offset+4, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(stlv_tree,
                                        hf_ospf_ls_mpls_remote_ifid,
                                        tvb, stlv_offset+8, 4, ENC_BIG_ENDIAN);
                    break;

                case MPLS_LINK_IF_SWITCHING_DESC:
                    stlv_tree = proto_tree_add_subtree(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             ett_ospf_lsa_mpls_link_stlv, NULL, stlv_name);
                    proto_tree_add_uint_format_value(stlv_tree, hf_ospf_tlv_type, tvb, stlv_offset, 2,
                                        stlv_type, "%u: %s", stlv_type, stlv_name);
                    proto_tree_add_item(stlv_tree, hf_ospf_tlv_length, tvb, stlv_offset+2, 2, ENC_BIG_ENDIAN);
                    switch_cap = tvb_get_guint8 (tvb, stlv_offset+4);
                    proto_tree_add_item(stlv_tree, hf_ospf_mpls_switching_type, tvb, stlv_offset+4, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(stlv_tree, hf_ospf_mpls_encoding, tvb, stlv_offset+5, 1, ENC_BIG_ENDIAN);
                    for (i = 0; i < 8; i++) {
                        tmp_float = tvb_get_ntohieee_float(tvb, stlv_offset + 8 + i*4);
                        proto_tree_add_float_format(stlv_tree, hf_ospf_ls_mpls_pri, tvb, stlv_offset+8+(i*4), 4,
                                            tmp_float, "Pri %d: %.10g bytes/s (%.0f bits/s)", i,
                                            tmp_float, tmp_float * 8.0);
                    }
                    if (switch_cap >=1 && switch_cap <=4) {           /* PSC-1 .. PSC-4 */
                        tmp_float = tvb_get_ntohieee_float(tvb, stlv_offset + 40);
                        proto_tree_add_float_format_value(stlv_tree, hf_ospf_mpls_minimum_lsp_bandwidth, tvb, stlv_offset+40, 4,
                                            tmp_float, "%.10g bytes/s (%.0f bits/s)",
                                            tmp_float, tmp_float * 8.0);
                        proto_tree_add_item(stlv_tree, hf_ospf_mpls_interface_mtu, tvb, stlv_offset+44, 2, ENC_BIG_ENDIAN);
                    }

                    if (switch_cap == 100) {                         /* TDM */
                        tmp_float = tvb_get_ntohieee_float(tvb, stlv_offset + 40);
                        proto_tree_add_float_format_value(stlv_tree, hf_ospf_mpls_minimum_lsp_bandwidth, tvb, stlv_offset+40, 4,
                                            tmp_float, "%.10g bytes/s (%.0f bits/s)",
                                            tmp_float, tmp_float * 8.0);
                        proto_tree_add_item(stlv_tree, hf_ospf_mpls_sonet_sdh, tvb, stlv_offset+44, 1, ENC_NA);
                    }
                    break;
                case MPLS_LINK_PROTECTION:
                    stlv_tree = proto_tree_add_subtree(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             ett_ospf_lsa_mpls_link_stlv, NULL, stlv_name);
                    proto_tree_add_uint_format_value(stlv_tree, hf_ospf_tlv_type, tvb, stlv_offset, 2,
                                        stlv_type, "%u: %s", stlv_type, stlv_name);
                    proto_tree_add_item(stlv_tree, hf_ospf_tlv_length, tvb, stlv_offset+2, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(stlv_tree, hf_ospf_mpls_protection_capability, tvb, stlv_offset+4, 1, ENC_BIG_ENDIAN);
                    break;

                case MPLS_LINK_SHARED_RISK_GROUP:
                    stlv_tree = proto_tree_add_subtree(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             ett_ospf_lsa_mpls_link_stlv, NULL, stlv_name);
                    proto_tree_add_uint_format_value(stlv_tree, hf_ospf_tlv_type, tvb, stlv_offset, 2,
                                        stlv_type, "%u: %s", stlv_type, stlv_name);
                    proto_tree_add_item(stlv_tree, hf_ospf_tlv_length, tvb, stlv_offset+2, 2, ENC_BIG_ENDIAN);
                    for (i=0; i < stlv_len; i+=4)
                        proto_tree_add_item(stlv_tree, hf_ospf_mpls_shared_risk_link_group, tvb, stlv_offset+4+i, 4, ENC_BIG_ENDIAN);
                    break;

                case OIF_LOCAL_NODE_ID:
                    stlv_tree = proto_tree_add_subtree_format(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             ett_ospf_lsa_mpls_link_stlv, NULL, "%s: %s", stlv_name,
                                             tvb_ip_to_str(tvb, stlv_offset + 4));
                    proto_tree_add_uint_format_value(stlv_tree, hf_ospf_tlv_type, tvb, stlv_offset, 2,
                                        stlv_type, "%u: %s", stlv_type, stlv_name);
                    proto_tree_add_item(stlv_tree, hf_ospf_tlv_length, tvb, stlv_offset+2, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(stlv_tree,
                                        hf_ospf_ls_oif_local_node_id,
                                        tvb, stlv_offset + 4, 4, ENC_BIG_ENDIAN);
                    break;

                case OIF_REMOTE_NODE_ID:
                    stlv_tree = proto_tree_add_subtree_format(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             ett_ospf_lsa_mpls_link_stlv, NULL, "%s: %s", stlv_name,
                                             tvb_ip_to_str(tvb, stlv_offset + 4));
                    proto_tree_add_uint_format_value(stlv_tree, hf_ospf_tlv_type, tvb, stlv_offset, 2,
                                        stlv_type, "%u: %s", stlv_type, stlv_name);
                    proto_tree_add_item(stlv_tree, hf_ospf_tlv_length, tvb, stlv_offset+2, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(stlv_tree,
                                        hf_ospf_ls_oif_remote_node_id,
                                        tvb, stlv_offset + 4, 4, ENC_BIG_ENDIAN);
                    break;

                case OIF_SONET_SDH_SWITCHING_CAPABILITY:
                    stlv_tree = proto_tree_add_subtree(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             ett_ospf_lsa_mpls_link_stlv, NULL, stlv_name);
                    proto_tree_add_uint_format_value(stlv_tree, hf_ospf_tlv_type, tvb, stlv_offset, 2,
                                        stlv_type, "%u: %s", stlv_type, stlv_name);
                    proto_tree_add_item(stlv_tree, hf_ospf_tlv_length, tvb, stlv_offset+2, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(stlv_tree, hf_ospf_oif_switching_cap, tvb, stlv_offset+4, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(stlv_tree, hf_ospf_oif_encoding, tvb, stlv_offset+5, 1, ENC_BIG_ENDIAN);
                    for (i = 0; i < (stlv_len - 4) / 4; i++) {
                        proto_tree_add_uint_format(stlv_tree, hf_ospf_oif_signal_type, tvb, stlv_offset+8+(i*4), 4,
                                            tvb_get_guint8(tvb, stlv_offset+8+(i*4)), "%s: %d free timeslots",
                                            val_to_str_ext(tvb_get_guint8(tvb, stlv_offset+8+(i*4)),
                                                           &gmpls_sonet_signal_type_str_ext,
                                                           "Unknown Signal Type (%d)"),
                                            tvb_get_ntoh24(tvb, stlv_offset + 9 + i*4));
                    }

                    break;
                default:
                    stlv_tree = proto_tree_add_subtree_format(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             ett_ospf_lsa_mpls_link_stlv, NULL, "Unknown Link sub-TLV: %u %s", stlv_type,
                                             rval_to_str(stlv_type, mpls_te_sub_tlv_rvals, "Unknown"));
                    proto_tree_add_uint_format_value(stlv_tree, hf_ospf_tlv_type, tvb, stlv_offset, 2,
                                        stlv_type, "%u: %s %s", stlv_type, stlv_name,
                                        rval_to_str(stlv_type, mpls_te_sub_tlv_rvals, "Unknown"));
                    proto_tree_add_item(stlv_tree, hf_ospf_tlv_length, tvb, stlv_offset+2, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(stlv_tree, hf_ospf_tlv_value, tvb, stlv_offset+4, stlv_len, ENC_NA);
                    break;
                }
                stlv_offset += ((stlv_len+4+3)/4)*4;
            }
            break;

        case OIF_TLV_TNA:
            tlv_tree = proto_tree_add_subtree(mpls_tree, tvb, offset, tlv_length+4,
                                     ett_ospf_lsa_oif_tna, NULL, "TNA Information");
            proto_tree_add_uint_format_value(tlv_tree, hf_ospf_tlv_type, tvb, offset, 2, 32768, "32768 - TNA Information");
            proto_tree_add_item(tlv_tree, hf_ospf_tlv_length, tvb, offset+2, 2, ENC_BIG_ENDIAN);
            stlv_offset = offset + 4;

            /* Walk down the sub-TLVs for TNA information */
            while (stlv_offset < tlv_end_offset) {
                stlv_type = tvb_get_ntohs(tvb, stlv_offset);
                stlv_len = tvb_get_ntohs(tvb, stlv_offset + 2);
                stlv_name = val_to_str_const(stlv_type, oif_stlv_str, "Unknown sub-TLV");
                switch (stlv_type) {

                case OIF_NODE_ID:
                    stlv_tree = proto_tree_add_subtree_format(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             ett_ospf_lsa_oif_tna_stlv, NULL, "%s: %s", stlv_name,
                                             tvb_ip_to_str(tvb, stlv_offset + 4));
                    proto_tree_add_uint_format_value(stlv_tree, hf_ospf_tlv_type, tvb, stlv_offset, 2,
                                        stlv_type, "%u: %s", stlv_type, stlv_name);
                    proto_tree_add_item(stlv_tree, hf_ospf_tlv_length, tvb, stlv_offset+2, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_ipv4_format(stlv_tree, hf_ospf_oif_node_id, tvb, stlv_offset+4, 4,
                                        tvb_get_ntohl(tvb, stlv_offset + 4), "%s: %s", stlv_name,
                                        tvb_ip_to_str(tvb, stlv_offset + 4));
                    break;

                case OIF_TNA_IPv4_ADDRESS:
                    stlv_tree = proto_tree_add_subtree_format(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             ett_ospf_lsa_oif_tna_stlv, NULL, "%s (IPv4): %s", stlv_name,
                                             tvb_ip_to_str(tvb, stlv_offset + 8));
                    proto_tree_add_uint_format_value(stlv_tree, hf_ospf_tlv_type, tvb, stlv_offset, 2,
                                        stlv_type, "%u: %s (IPv4)", stlv_type, stlv_name);
                    proto_tree_add_item(stlv_tree, hf_ospf_tlv_length, tvb, stlv_offset+2, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(stlv_tree, hf_ospf_oif_tna_addr_length, tvb, stlv_offset+4, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(stlv_tree, hf_ospf_oif_tna_addr_ipv4, tvb, stlv_offset+8, stlv_len - 4, ENC_BIG_ENDIAN);
                    break;

                case OIF_TNA_IPv6_ADDRESS:
                    stlv_tree = proto_tree_add_subtree_format(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             ett_ospf_lsa_oif_tna_stlv, NULL, "%s (IPv6): %s", stlv_name,
                                             tvb_ip6_to_str(tvb, stlv_offset + 8));
                    proto_tree_add_uint_format_value(stlv_tree, hf_ospf_tlv_type, tvb, stlv_offset, 2,
                                        stlv_type, "%u: %s (IPv6)", stlv_type, stlv_name);
                    proto_tree_add_item(stlv_tree, hf_ospf_tlv_length, tvb, stlv_offset+2, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(stlv_tree, hf_ospf_oif_tna_addr_length, tvb, stlv_offset+4, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(stlv_tree, hf_ospf_tna_addr_ipv6, tvb, stlv_offset+8, stlv_len - 4, ENC_NA);
                    break;

                case OIF_TNA_NSAP_ADDRESS:
                    stlv_tree = proto_tree_add_subtree_format(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             ett_ospf_lsa_oif_tna_stlv, NULL, "%s (NSAP): %s", stlv_name,
                                             tvb_bytes_to_str(wmem_packet_scope(), tvb, stlv_offset + 8, stlv_len - 4));
                    proto_tree_add_uint_format_value(stlv_tree, hf_ospf_tlv_type, tvb, stlv_offset, 2,
                                        stlv_type, "%u: %s (NSAP)", stlv_type, stlv_name);
                    proto_tree_add_item(stlv_tree, hf_ospf_tlv_length, tvb, stlv_offset+2, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(stlv_tree, hf_ospf_oif_tna_addr_length, tvb, stlv_offset+4, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(stlv_tree, hf_ospf_tna_addr, tvb, stlv_offset+8, stlv_len - 4, ENC_NA);
                    break;

                default:
                    proto_tree_add_expert_format(tlv_tree, pinfo, &ei_ospf_unknown_link_subtype, tvb, stlv_offset, stlv_len+4,
                                        "Unknown Link sub-TLV: %u", stlv_type);
                    break;
                }
                stlv_offset += ((stlv_len+4+3)/4)*4;
            }
            break;
        default:
            tlv_tree = proto_tree_add_subtree_format(mpls_tree, tvb, offset, tlv_length+4,
                                     ett_ospf_lsa_mpls_link, NULL, "Unknown LSA: %u %s", tlv_type,
                                     rval_to_str(tlv_type, mpls_te_tlv_rvals, "Unknown"));
            proto_tree_add_uint_format_value(tlv_tree, hf_ospf_tlv_type, tvb, offset, 2, tlv_type, "%u - Unknown %s",
                                tlv_type, rval_to_str(tlv_type, mpls_te_tlv_rvals, "Unknown"));
            proto_tree_add_item(tlv_tree, hf_ospf_tlv_length, tvb, offset+2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_ospf_tlv_value, tvb, offset+4, tlv_length, ENC_NA);
            break;
        }

        offset += tlv_length + 4;
        length -= tlv_length + 4;
    }
}

/*
 * Dissect the TLVs within a Grace-LSA as defined by RFC 3623
 */
static void dissect_ospf_lsa_grace_tlv (tvbuff_t *tvb, int offset,
                                        proto_tree *tree, guint32 length)
{
    guint16 tlv_type;
    guint16 tlv_length;
    int tlv_length_with_pad; /* The total length of the TLV including the type
                                and length fields and any padding */
    guint32 grace_period;
    guint8 restart_reason;
    proto_tree *tlv_tree;
    proto_item *tree_item;
    proto_item *grace_tree_item;

    if (!tree) { return; }

    while (length > 0)
    {
        tlv_type = tvb_get_ntohs(tvb, offset);
        tlv_length = tvb_get_ntohs(tvb, offset + 2);
        /* The total length of the TLV including the type, length, value and
         * pad bytes (TLVs are padded to 4 octet alignment).
         */
        tlv_length_with_pad = tlv_length + 4 + ((4 - (tlv_length % 4)) % 4);

        tree_item = proto_tree_add_item(tree, hf_ospf_v2_grace_tlv, tvb, offset,
                                        tlv_length_with_pad, ENC_NA);
        tlv_tree = proto_item_add_subtree(tree_item, ett_ospf_lsa_grace_tlv);
        proto_tree_add_uint_format_value(tlv_tree, hf_ospf_tlv_type, tvb, offset, 2, tlv_type, "%s (%u)",
                            val_to_str_const(tlv_type, grace_tlv_type_vals, "Unknown grace-LSA TLV"), tlv_type);
        proto_tree_add_item(tlv_tree, hf_ospf_tlv_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

        switch (tlv_type) {
        case GRACE_TLV_PERIOD:
            grace_period = tvb_get_ntohl(tvb, offset + 4);
            grace_tree_item = proto_tree_add_item(tlv_tree, hf_ospf_v2_grace_period, tvb,
                                                  offset + 4, tlv_length, ENC_BIG_ENDIAN);
            proto_item_append_text(grace_tree_item, " seconds");
            proto_item_set_text(tree_item, "Grace Period: %u seconds", grace_period);
            break;
        case GRACE_TLV_REASON:
            restart_reason = tvb_get_guint8(tvb, offset + 4);
            proto_tree_add_item(tlv_tree, hf_ospf_v2_grace_reason, tvb, offset + 4,
                                tlv_length, ENC_BIG_ENDIAN);
            proto_item_set_text(tree_item, "Restart Reason: %s (%u)",
                                val_to_str_const(restart_reason, restart_reason_vals, "Unknown Restart Reason"),
                                restart_reason);
            break;
        case GRACE_TLV_IP:
            proto_tree_add_item(tlv_tree, hf_ospf_v2_grace_ip, tvb, offset + 4,
                                tlv_length, ENC_BIG_ENDIAN);
            proto_item_set_text(tree_item, "Restart IP: %s",
                                tvb_address_with_resolution_to_str(wmem_packet_scope(), tvb, AT_IPv4, offset + 4));
            break;
        default:
            proto_item_set_text(tree_item, "Unknown grace-LSA TLV");
            break;
        }
        if (4 + tlv_length < tlv_length_with_pad) {
            proto_tree_add_item(tlv_tree, hf_ospf_pad_bytes, tvb, offset + 4 + tlv_length, tlv_length_with_pad - (4 + tlv_length), ENC_NA);
        }
        offset += tlv_length_with_pad;
        length -= tlv_length_with_pad;
    }
}

/*
 * This function dissects the Optional Router capabilities LSA.
 * In case of OSPFv2, the Router Capabilities would be advertized via the first TLV
 * of an RI LSA and in the case of OSPFv3, the router capabilities would be advertized
 * using a special purpose type field value. (RFC 4970)
 * Also, the Dynamic Hostname or FQDN is advertized via a special purpose TLV type.
 * The below function adds the support to handle this as well. (RFC5642).
 */
static void
dissect_ospf_lsa_opaque_ri(tvbuff_t *tvb, int offset, proto_tree *tree,
                           guint32 length)
{
    proto_tree *ri_tree;
    proto_tree *tlv_tree;

    int tlv_type;
    int tlv_length;

    ri_tree = proto_tree_add_subtree(tree, tvb, offset, length,
                             ett_ospf_lsa_opaque_ri, NULL, "Opaque Router Information LSA");

    while (length > 0) {
        tlv_type = tvb_get_ntohs(tvb, offset);
        tlv_length = tvb_get_ntohs(tvb, offset + 2);

        switch(tlv_type) {

        case OPT_RI_TLV:
           tlv_tree = proto_tree_add_subtree(ri_tree, tvb, offset, tlv_length+4,
                                    ett_ospf_lsa_ri_tlv, NULL, "RI TLV");

           proto_tree_add_uint_format_value(tlv_tree, hf_ospf_tlv_type, tvb, offset, 2,
                        tlv_type, "Router Informational Capabilities TLV (%u)", tlv_type);

           proto_tree_add_item(tlv_tree, hf_ospf_tlv_length, tvb, offset+2, 2, ENC_BIG_ENDIAN);

           dissect_ospf_bitfield(tlv_tree, tvb, offset + 4, &bfinfo_ri_options);
           break;

        case DYN_HOSTNAME_TLV:
           tlv_tree = proto_tree_add_subtree(ri_tree, tvb, offset, tlv_length+4,
                                    ett_ospf_lsa_dyn_hostname_tlv, NULL, "Dynamic Hostname TLV");

           proto_tree_add_uint_format_value(tlv_tree, hf_ospf_tlv_type, tvb, offset, 2,
                               tlv_type, "Dynamic Hostname TLV (%u)", tlv_type);

           proto_tree_add_item(tlv_tree, hf_ospf_tlv_length, tvb, offset+2, 2, ENC_BIG_ENDIAN);

           proto_tree_add_item(tlv_tree, hf_ospf_dyn_hostname, tvb, offset+4, tlv_length, ENC_ASCII|ENC_NA);
           break;

        default:
           tlv_tree = proto_tree_add_subtree(ri_tree, tvb, offset, tlv_length+4,
                                    ett_ospf_lsa_unknown_tlv, NULL, "Unknown Opaque RI LSA TLV");

           proto_tree_add_uint_format_value(tlv_tree, hf_ospf_tlv_length, tvb, offset, 2,
                               tlv_type, "Unknown TLV (%u)", tlv_type);

           proto_tree_add_item(tlv_tree, hf_ospf_tlv_length, tvb, offset+2, 2, ENC_BIG_ENDIAN);

           proto_tree_add_item(tlv_tree, hf_ospf_unknown_tlv_txt, tvb, offset+4, tlv_length, ENC_ASCII|ENC_NA);
           break;

        }

        offset += tlv_length + 4;
        length -= tlv_length + 4;
    }
}

/*
 * Dissect opaque LSAs
 */
static void
dissect_ospf_lsa_opaque(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree,
                        guint8 ls_id_type, guint32 length)
{
    switch (ls_id_type) {

    case OSPF_LSA_MPLS_TE:
        dissect_ospf_lsa_mpls(tvb, pinfo, offset, tree, length);
        break;
    case OSPF_LSA_OPAQUE_RI:
        dissect_ospf_lsa_opaque_ri(tvb, offset, tree, length);
        break;
    case OSPF_LSA_GRACE:
        dissect_ospf_lsa_grace_tlv(tvb, offset, tree, length);
        break;

    default:
        proto_tree_add_expert_format(tree, pinfo, &ei_ospf_lsa_unknown_type, tvb, offset, length,
                            "Unknown LSA Type %u", ls_id_type);
        break;
    } /* switch on opaque LSA id */
}

static const true_false_string tfs_lsa_external_type = { "Type 2 (metric is larger than any other link state path)",
                                                            "Type 1 (metric is specified in the same units as interface cost)" };

static const value_string ospf_v3_lsa_type_vals[] = {
    {OSPF_V3_LINK_PTP, "Point-to-point connection to another router"},
    {OSPF_V3_LINK_TRANSIT, "Connection to a transit network"},
    {OSPF_LINK_STUB, "Connection to a stub network"},
    {OSPF_V3_LINK_VIRTUAL, "Virtual link"},
    {0, NULL},
};

static const value_string ospf_v3_lsa_type_short_vals[] = {
    {OSPF_V3_LINK_PTP, "PTP"},
    {OSPF_V3_LINK_TRANSIT, "Transit"},
    {OSPF_LINK_STUB, "Stub"},
    {OSPF_V3_LINK_VIRTUAL, "Virtual"},
    {0, NULL},
};

static const value_string ospf_v3_lsa_link_id_vals[] = {
    {OSPF_V3_LINK_PTP, "Neighboring router's Router ID"},
    {OSPF_V3_LINK_TRANSIT, "IP address of Designated Router"},
    {OSPF_LINK_STUB, "IP network/subnet number"},
    {OSPF_V3_LINK_VIRTUAL, "Neighboring router's Router ID"},
    {0, NULL},
};

static int
dissect_ospf_v2_lsa(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree,
                    gboolean disassemble_body)
{
    proto_tree *ospf_lsa_tree;
    proto_item *ti, *lsa_ti, *hidden_item;

    guint8               ls_type;
    guint16              ls_length;
    int                  end_offset;
    guint16              nr_links;
    guint16              nr_metric;

    /* router LSA */
    guint8               link_type;
    guint16              link_counter;
    guint16              metric_counter;
    const char          *metric_type_str;

    /* AS-external LSA */
    guint8               options;

    /* opaque LSA */
    guint8               ls_id_type;
    guint8               ls_ri_opaque_field;

    guint8               ls_length_constraints[] = { 0, 24, 28, 28, 28, 36, 20, 36, 20, 20, 20, 20 };

    ls_type = tvb_get_guint8(tvb, offset + 3);
    ls_length = tvb_get_ntohs(tvb, offset + 18);
    end_offset = offset + ls_length;

    ospf_lsa_tree = proto_tree_add_subtree_format(tree, tvb, offset,
                        disassemble_body?ls_length:OSPF_LSA_HEADER_LENGTH,
                        ett_ospf_lsa, &lsa_ti, "LSA-type %d (%s), len %d",
                        ls_type, val_to_str_const(ls_type, ls_type_vals, "Unknown"),
                        ls_length);
    proto_tree_add_item(ospf_lsa_tree, hf_ospf_ls_age, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ospf_lsa_tree, hf_ospf_ls_donotage, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    options = tvb_get_guint8 (tvb, offset + 2);
    if (ls_type != 7)
        dissect_ospf_bitfield(ospf_lsa_tree, tvb, offset + 2, &bfinfo_v2_options);
    else
        dissect_ospf_bitfield(ospf_lsa_tree, tvb, offset + 2, &bfinfo_v2_options_lsa7);
    proto_tree_add_item(ospf_lsa_tree, hf_ospf_ls_type, tvb,
                        offset + 3, 1, ENC_BIG_ENDIAN);
    if (ospf_ls_type_to_filter(ls_type) != -1) {
        hidden_item = proto_tree_add_item(ospf_lsa_tree,
                                          *hf_ospf_ls_type_array[ospf_ls_type_to_filter(ls_type)], tvb,
                                          offset + 3, 1, ENC_BIG_ENDIAN);
        PROTO_ITEM_SET_HIDDEN(hidden_item);
    }

    if (options & OSPF_V2_OPTIONS_MT) {
        metric_type_str = "MT-ID";
    } else {
        metric_type_str = "TOS";
    }

    if (is_opaque(ls_type)) {
        ls_id_type = tvb_get_guint8(tvb, offset + 4);
        proto_tree_add_uint(ospf_lsa_tree, hf_ospf_ls_opaque_type,
                            tvb, offset + 4, 1, ls_id_type);

        switch (ls_id_type) {

        case OSPF_LSA_MPLS_TE:
            proto_tree_add_item(ospf_lsa_tree, hf_ospf_ls_id_te_lsa_reserved, tvb, offset + 5, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ospf_lsa_tree, hf_ospf_ls_mpls_te_instance,
                                tvb, offset + 6, 2, ENC_BIG_ENDIAN);
            break;

        case OSPF_LSA_OPAQUE_RI:
           ls_ri_opaque_field = tvb_get_guint8(tvb, offset + 5);
           if ( ls_ri_opaque_field != 0 )
                ls_id_type = OSPF_LSA_UNKNOWN;
           else
                proto_tree_add_item(ospf_lsa_tree, hf_ospf_opaque_lsa_mbz,
                                    tvb, offset + 5, 3, ENC_BIG_ENDIAN);
           break;

        default:
            proto_tree_add_item(ospf_lsa_tree, hf_ospf_ls_id_opaque_id, tvb, offset + 5, 3, ENC_BIG_ENDIAN);
            break;
        }
    } else {
        ls_id_type = 0;
        proto_tree_add_item(ospf_lsa_tree, hf_ospf_ls_id, tvb,
                            offset + 4, 4, ENC_BIG_ENDIAN);
    }

    proto_tree_add_item(ospf_lsa_tree, hf_ospf_adv_router,
                        tvb, offset + 8, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(ospf_lsa_tree, hf_ospf_ls_seqnum, tvb,
                        offset + 12, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(ospf_lsa_tree, hf_ospf_ls_chksum, tvb,
                        offset + 16, 2, ENC_BIG_ENDIAN);
    ti = proto_tree_add_item(ospf_lsa_tree, hf_ospf_ls_length, tvb,
                        offset + 18, 2, ENC_BIG_ENDIAN);

    if(ls_type && ls_type <= OSPF_LSTYPE_OP_ASWIDE) {
        if(ls_length < ls_length_constraints[ls_type]) {
            expert_add_info_format(pinfo, ti, &ei_ospf_lsa_bad_length, "Invalid LSA length (%u) for type %s, expected >= (%u)",
                                ls_length, val_to_str_const(ls_type, ls_type_vals, "Unknown"), ls_length_constraints[ls_type]);
            return -1;
        }
    } else if(ls_length < 20) { /* As type is unknown, we check for a minimum length of 20 */
        expert_add_info_format(pinfo, ti, &ei_ospf_lsa_bad_length, "Invalid LSA length (%u) for unknown LSA type (%u), expected minimum of (20)", ls_length, ls_type);
        return -1;
    }

    /* skip past the LSA header to the body */
    offset += OSPF_LSA_HEADER_LENGTH;
    if (ls_length <= OSPF_LSA_HEADER_LENGTH)
        return offset;  /* no data, or bogus length */
    ls_length -= OSPF_LSA_HEADER_LENGTH;

    if (!disassemble_body)
        return offset;

    switch (ls_type){

    case OSPF_LSTYPE_ROUTER:
        /* flags field in an router-lsa */
        if (options & OSPF_V2_OPTIONS_MT) {
            dissect_ospf_bitfield(ospf_lsa_tree, tvb, offset, &bfinfo_v2_router_lsa_mt_flags);
        } else {
            dissect_ospf_bitfield(ospf_lsa_tree, tvb, offset, &bfinfo_v2_router_lsa_flags);
        }

        nr_links = tvb_get_ntohs(tvb, offset + 2);
        proto_tree_add_item(ospf_lsa_tree, hf_ospf_lsa_number_of_links, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

        offset += 4;

        /* nr_links links follow
         * maybe we should put each of the links into its own subtree ???
         */
        for (link_counter = 0; link_counter < nr_links; link_counter++) {
            proto_tree *ospf_lsa_router_link_tree;
            proto_item *ti_item;


            /* check the Link Type and ID */
            link_type = tvb_get_guint8(tvb, offset + 8);
            nr_metric = tvb_get_guint8(tvb, offset + 9);

            ospf_lsa_router_link_tree = proto_tree_add_subtree_format(ospf_lsa_tree, tvb, offset, 12 + 4 * nr_metric,
                                           ett_ospf_lsa_router_link, NULL, "Type: %-8s ID: %-15s Data: %-15s Metric: %d",
                                           val_to_str_const(link_type, ospf_v3_lsa_type_short_vals, "Unknown"),
                                           tvb_ip_to_str(tvb, offset),
                                           tvb_ip_to_str(tvb, offset + 4),
                                           tvb_get_ntohs(tvb, offset + 10));

            ti_item = proto_tree_add_item(ospf_lsa_router_link_tree, hf_ospf_ls_router_linkid,
                        tvb, offset, 4, ENC_BIG_ENDIAN);
            proto_item_append_text(ti_item, " - %s", val_to_str_const(link_type, ospf_v3_lsa_link_id_vals, "Unknown link ID"));

            /* link_data should be specified in detail (e.g. network mask) (depends on link type)*/
            proto_tree_add_item(ospf_lsa_router_link_tree, hf_ospf_ls_router_linkdata,
                        tvb, offset +4, 4, ENC_BIG_ENDIAN);

            ti_item = proto_tree_add_item(ospf_lsa_router_link_tree, hf_ospf_ls_router_linktype,
                        tvb, offset + 8, 1, ENC_BIG_ENDIAN);
            proto_item_append_text(ti_item, " - %s", val_to_str_const(link_type, ospf_v3_lsa_type_vals, "Unknown link type"));

            ti_item = proto_tree_add_item(ospf_lsa_router_link_tree, hf_ospf_ls_router_nummetrics,
                                tvb, offset + 9, 1, ENC_BIG_ENDIAN);
            proto_item_append_text(ti_item, " - %s", metric_type_str);
            proto_tree_add_item(ospf_lsa_router_link_tree, hf_ospf_ls_router_metric0,
                                tvb, offset + 10, 2, ENC_BIG_ENDIAN);

            offset += 12;

            /* nr_metric metrics may follow each link
             * According to RFC4915 the TOS metrics was never deployed and was subsequently deprecated,
             * but decoding still present because MT-ID use the same structure.
             */
            for (metric_counter = 0; metric_counter < nr_metric; metric_counter++) {
                proto_tree_add_uint_format(ospf_lsa_router_link_tree, hf_ospf_ls_metric, tvb, offset, 4,
                                    tvb_get_ntohs(tvb, offset + 2), "%s: %u, Metric: %u",
                                    metric_type_str,
                                    tvb_get_guint8(tvb, offset),
                                    tvb_get_ntohs(tvb, offset + 2));
                offset += 4;
            }
        }
        break;

    case OSPF_LSTYPE_NETWORK:
        proto_tree_add_item(ospf_lsa_tree, hf_ospf_ls_network_netmask,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        if (offset == end_offset)
                proto_tree_add_expert_format(ospf_lsa_tree, pinfo, &ei_ospf_lsa_constraint_missing, tvb, offset - 4, 4, "1 or more router-IDs required");

        while (offset < end_offset) {
            proto_tree_add_item(ospf_lsa_tree, hf_ospf_ls_network_attachrtr,
                                tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }
        break;

    case OSPF_LSTYPE_SUMMARY:
        /* Type 3 and 4 LSAs have the same format */
    case OSPF_LSTYPE_ASBR:
        proto_tree_add_item(ospf_lsa_tree, hf_ospf_ls_asbr_netmask,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        if ((offset+4) > end_offset)
                expert_add_info_format(pinfo, lsa_ti, &ei_ospf_lsa_constraint_missing, "1 or more TOS metrics required");

        while (offset < end_offset) {
            proto_tree_add_item(ospf_lsa_tree, hf_ospf_lsa_tos, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(ospf_lsa_tree, hf_ospf_metric, tvb, offset, 3,
                                ENC_BIG_ENDIAN);
            offset += 3;
        }
        break;

    case OSPF_LSTYPE_ASEXT:
    case OSPF_LSTYPE_ASEXT7:
        proto_tree_add_item(ospf_lsa_tree, hf_ospf_ls_asext_netmask,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        if ((offset+12) > end_offset)
                expert_add_info_format(pinfo, lsa_ti, &ei_ospf_lsa_constraint_missing, "1 or more TOS forwarding blocks required");

        while (offset < end_offset) {
            proto_tree_add_item(ospf_lsa_tree, hf_ospf_lsa_external_type, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(ospf_lsa_tree, hf_ospf_lsa_external_tos, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(ospf_lsa_tree, hf_ospf_metric, tvb, offset, 3, ENC_BIG_ENDIAN);
            offset += 3;

            proto_tree_add_item(ospf_lsa_tree, hf_ospf_ls_asext_fwdaddr,
                                tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(ospf_lsa_tree, hf_ospf_ls_asext_extrtrtag,
                                tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }
        break;

    case OSPF_LSTYPE_OP_LINKLOCAL:
    case OSPF_LSTYPE_OP_AREALOCAL:
    case OSPF_LSTYPE_OP_ASWIDE:
        /*
         * RFC 2370 opaque LSAs.
         */
        dissect_ospf_lsa_opaque(tvb, pinfo, offset, ospf_lsa_tree, ls_id_type,
                                ls_length);
        offset += ls_length;
        break;

    default:
        /* unknown LSA type */
        expert_add_info(pinfo, ti, &ei_ospf_lsa_unknown_type);
        offset += ls_length;
        break;
    }
    /* return the offset of the next LSA */
    return offset;
}

static int
dissect_ospf_v3_lsa(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree,
                    gboolean disassemble_body, guint8 address_family)
{
    proto_tree *ospf_lsa_tree, *router_tree = NULL, *router_entry_tree;
    proto_item *ti, *hidden_item, *type_item;

    guint16              ls_type;
    guint16              ls_length;
    int                  end_offset;
    guint8               reserved;

    /* router LSA */
    guint32              number_prefixes;
    guint8               prefix_length;
    guint16              reserved16;

    guint16              referenced_ls_type;
    guint16              entry_count = 0;

    guint8               flags;


    ls_type = tvb_get_ntohs(tvb, offset + 2);
    ls_length = tvb_get_ntohs(tvb, offset + 18);
    end_offset = offset + ls_length;

    ospf_lsa_tree = proto_tree_add_subtree_format(tree, tvb, offset,
                        disassemble_body?ls_length:OSPF_LSA_HEADER_LENGTH,
                        ett_ospf_lsa, &type_item, "LSA-type %d (%s), len %d",
                        ls_type, val_to_str_const(ls_type, v3_ls_type_vals, "Unknown"),
                        ls_length);
    proto_tree_add_item(ospf_lsa_tree, hf_ospf_ls_age, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ospf_lsa_tree, hf_ospf_v3_lsa_do_not_age, tvb, offset, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(ospf_lsa_tree, hf_ospf_v3_ls_type, tvb,
                        offset + 2, 2, ENC_BIG_ENDIAN);
    if (ospf_v3_ls_type_to_filter(ls_type) != -1) {
        hidden_item = proto_tree_add_item(ospf_lsa_tree,
                                          *hf_ospf_v3_ls_type_array[ospf_v3_ls_type_to_filter(ls_type)], tvb,
                                          offset + 2, 2, ENC_BIG_ENDIAN);
        PROTO_ITEM_SET_HIDDEN(hidden_item);
    }

    proto_tree_add_item(ospf_lsa_tree, hf_ospf_link_state_id, tvb, offset + 4, 4, ENC_BIG_ENDIAN);

    proto_tree_add_item(ospf_lsa_tree, hf_ospf_adv_router,
                        tvb, offset + 8, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(ospf_lsa_tree, hf_ospf_ls_seqnum, tvb,
                        offset + 12, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(ospf_lsa_tree, hf_ospf_ls_chksum, tvb,
                        offset + 16, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ospf_lsa_tree, hf_ospf_ls_length, tvb,
                        offset + 18, 2, ENC_BIG_ENDIAN);

    /* skip past the LSA header to the body */
    offset += OSPF_LSA_HEADER_LENGTH;
    ls_length -= OSPF_LSA_HEADER_LENGTH;

    if (!disassemble_body)
        return offset;

    switch (ls_type){


    case OSPF_V3_LSTYPE_ROUTER:
        /* flags field in an router-lsa */
        dissect_ospf_bitfield(ospf_lsa_tree, tvb, offset, &bfinfo_v3_router_lsa_flags);

        /* options field in an router-lsa */
        dissect_ospf_bitfield(ospf_lsa_tree, tvb, offset + 1, &bfinfo_v3_options);

        /* skip the router-lsa flags and options */
        offset+=4;
        ls_length-=4;

        if (ls_length > 0)
            router_tree = proto_tree_add_subtree(ospf_lsa_tree, tvb, offset, ls_length,
                                ett_ospf_v3_router_interface, NULL, "Router Interfaces");

        /* scan all router-lsa router interfaces */
        while (ls_length > 0 ) {
            entry_count++;
            router_entry_tree = proto_tree_add_subtree_format(router_tree, tvb, offset, 16,
                ett_ospf_v3_router_interface_entry, NULL, "Entry #%d", entry_count);

            proto_tree_add_item(router_entry_tree, hf_ospf_v3_lsa_type, tvb, offset, 1, ENC_BIG_ENDIAN);

            /* reserved field */
            reserved = tvb_get_guint8(tvb, offset+1);
            ti = proto_tree_add_item(router_entry_tree, hf_ospf_header_reserved, tvb, offset+1, 1, ENC_NA);
            if (reserved != 0)
                expert_add_info(pinfo, ti, &ei_ospf_header_reserved);

            /* metric */
            proto_tree_add_item(router_entry_tree, hf_ospf_metric, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

            /* Interface ID */
            proto_tree_add_item(router_entry_tree, hf_ospf_v3_lsa_interface_id, tvb, offset + 4, 4, ENC_BIG_ENDIAN);

            /* Neighbor Interface ID */
            proto_tree_add_item(router_entry_tree, hf_ospf_v3_lsa_neighbor_interface_id, tvb, offset + 8, 4, ENC_BIG_ENDIAN);

            /* Neighbor Router ID */
            proto_tree_add_item(router_entry_tree, hf_ospf_v3_lsa_neighbor_router_id, tvb, offset + 12, 4, ENC_BIG_ENDIAN);

            /* skip to the (possible) next entry */
            offset+=16;
            ls_length-=16;

        }
        break;

    case OSPF_V3_LSTYPE_NETWORK:

        /* reserved field */
        reserved = tvb_get_guint8(tvb, offset);
        ti = proto_tree_add_item(ospf_lsa_tree, hf_ospf_header_reserved, tvb, offset, 1, ENC_NA);
        if (reserved != 0)
            expert_add_info(pinfo, ti, &ei_ospf_header_reserved);

        /* options field in an network-lsa */
        dissect_ospf_bitfield(ospf_lsa_tree, tvb, offset + 1, &bfinfo_v3_options);

        offset += 4;
        ls_length-=4;

        while (ls_length > 0 ) {
            proto_tree_add_item(ospf_lsa_tree, hf_ospf_v3_lsa_attached_router, tvb, offset, 4, ENC_BIG_ENDIAN);
            ls_length-=4;
            offset += 4;
        }
        break;


    case OSPF_V3_LSTYPE_INTER_AREA_PREFIX:

        /* reserved field */
        reserved = tvb_get_guint8(tvb, offset);
        ti = proto_tree_add_item(ospf_lsa_tree, hf_ospf_header_reserved, tvb, offset, 1, ENC_NA);
        if (reserved != 0)
            expert_add_info(pinfo, ti, &ei_ospf_header_reserved);

        /* metric */
        proto_tree_add_item(ospf_lsa_tree, hf_ospf_metric, tvb, offset + 1, 3, ENC_BIG_ENDIAN);

        /* prefix length */
        prefix_length=tvb_get_guint8(tvb, offset+4);
        proto_tree_add_item(ospf_lsa_tree, hf_ospf_prefix_length, tvb, offset+4, 1, ENC_BIG_ENDIAN);

        /* prefix options */
        dissect_ospf_bitfield(ospf_lsa_tree, tvb, offset+5, &bfinfo_v3_prefix_options);

        /* 16 bits reserved */
        reserved16=tvb_get_ntohs(tvb, offset+6);
        ti = proto_tree_add_item(ospf_lsa_tree, hf_ospf_header_reserved, tvb, offset+6, 2, ENC_NA);
        if (reserved16 != 0)
            expert_add_info(pinfo, ti, &ei_ospf_header_reserved);

        offset+=8;

        /* address_prefix */
        dissect_ospf_v3_address_prefix(tvb, pinfo, offset, prefix_length, ospf_lsa_tree, address_family);

        offset+=(prefix_length+31)/32*4;

        break;


    case OSPF_V3_LSTYPE_INTER_AREA_ROUTER:

        /* reserved field */
        reserved = tvb_get_guint8(tvb, offset);
        ti = proto_tree_add_item(ospf_lsa_tree, hf_ospf_header_reserved, tvb, offset, 1, ENC_NA);
        if (reserved != 0)
            expert_add_info(pinfo, ti, &ei_ospf_header_reserved);

        /* options field in an inter-area-router-lsa */
        dissect_ospf_bitfield(ospf_lsa_tree, tvb, offset + 1, &bfinfo_v3_options);

        /* reserved field */
        reserved = tvb_get_guint8(tvb, offset+4);
        ti = proto_tree_add_item(ospf_lsa_tree, hf_ospf_header_reserved, tvb, offset+4, 1, ENC_NA);
        if (reserved != 0)
            expert_add_info(pinfo, ti, &ei_ospf_header_reserved);

        /* metric */
        proto_tree_add_item(ospf_lsa_tree, hf_ospf_metric, tvb, offset + 5, 3, ENC_BIG_ENDIAN);

        /* Destination Router ID */
        proto_tree_add_item(ospf_lsa_tree, hf_ospf_v3_lsa_destination_router_id, tvb, offset + 8, 4, ENC_BIG_ENDIAN);

        offset+=12;
        break;


    case OSPF_V3_LSTYPE_NSSA:
    case OSPF_V3_LSTYPE_AS_EXTERNAL:

        /* flags */
        dissect_ospf_bitfield(ospf_lsa_tree, tvb, offset, &bfinfo_v3_as_external_flags);
        flags=tvb_get_guint8(tvb, offset);

        /* 24 bits metric */
        proto_tree_add_item(ospf_lsa_tree, hf_ospf_metric, tvb, offset+1, 3, ENC_BIG_ENDIAN);

        /* prefix length */
        prefix_length=tvb_get_guint8(tvb, offset+4);
        proto_tree_add_item(ospf_lsa_tree, hf_ospf_prefix_length, tvb, offset+4, 1, ENC_BIG_ENDIAN);

        /* prefix options */
        dissect_ospf_bitfield(ospf_lsa_tree, tvb, offset+5, &bfinfo_v3_prefix_options);

        /* referenced LS type */
        referenced_ls_type=tvb_get_ntohs(tvb, offset+6);
        proto_tree_add_item(ospf_lsa_tree, hf_ospf_v3_lsa_referenced_ls_type, tvb, offset+6, 2, ENC_BIG_ENDIAN);

        offset+=8;

        /* address_prefix */
        dissect_ospf_v3_address_prefix(tvb, pinfo, offset, prefix_length, ospf_lsa_tree, address_family);

        offset+=(prefix_length+31)/32*4;

        /* Forwarding Address (optional - only if F-flag is on) */
        if ( (offset < end_offset) && (flags & OSPF_V3_AS_EXTERNAL_FLAG_F) ) {
            if (address_family == OSPF_AF_6) {
                proto_tree_add_item(ospf_lsa_tree, hf_ospf_v3_lsa_forwarding_address_ipv6, tvb, offset, 16, ENC_NA);
            } else {
                proto_tree_add_item(ospf_lsa_tree, hf_ospf_v3_lsa_forwarding_address_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
            }

            offset+=16;
        }

        /* External Route Tag (optional - only if T-flag is on) */
        if ( (offset < end_offset) && (flags & OSPF_V3_AS_EXTERNAL_FLAG_T) ) {
            proto_tree_add_item(ospf_lsa_tree, hf_ospf_v3_lsa_external_route_tag, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
        }

        /* Referenced Link State ID (optional - only if Referenced LS type is non-zero */
        if ( (offset < end_offset) && (referenced_ls_type != 0) ) {
            proto_tree_add_item(ospf_lsa_tree, hf_ospf_v3_lsa_referenced_link_state_id, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
        }

        break;

    case OSPF_V3_LSTYPE_LINK:

        /* router priority */
        proto_tree_add_item(ospf_lsa_tree, hf_ospf_v3_lsa_router_priority, tvb, offset, 1, ENC_BIG_ENDIAN);

        /* options field in an link-lsa */
        dissect_ospf_bitfield(ospf_lsa_tree, tvb, offset + 1, &bfinfo_v3_options);

        /* Link-local Interface Address */
        if (address_family == OSPF_AF_6) {
            proto_tree_add_item(ospf_lsa_tree, hf_ospf_v3_lsa_link_local_interface_address, tvb, offset + 4, 16, ENC_NA);
        } else {
            proto_tree_add_item(ospf_lsa_tree, hf_ospf_link_local_interface_address_ipv4, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
        }
        /* Number prefixes */
        proto_tree_add_item_ret_uint(ospf_lsa_tree, hf_ospf_v3_lsa_num_prefixes, tvb, offset+20, 4, ENC_BIG_ENDIAN, &number_prefixes);

        offset+=24;

        while (number_prefixes > 0) {

            /* prefix length */
            prefix_length=tvb_get_guint8(tvb, offset);
            proto_tree_add_item(ospf_lsa_tree, hf_ospf_prefix_length, tvb, offset, 1, ENC_BIG_ENDIAN);

            /* prefix options */
            dissect_ospf_bitfield(ospf_lsa_tree, tvb, offset+1, &bfinfo_v3_prefix_options);

            /* 16 bits reserved */
            reserved16=tvb_get_ntohs(tvb, offset+2);
            ti = proto_tree_add_item(ospf_lsa_tree, hf_ospf_header_reserved, tvb, offset+2, 2, ENC_NA);
            if (reserved16 != 0)
                expert_add_info(pinfo, ti, &ei_ospf_header_reserved);

            offset+=4;

            /* address_prefix */
            dissect_ospf_v3_address_prefix(tvb, pinfo, offset, prefix_length, ospf_lsa_tree, address_family);

            offset+=(prefix_length+31)/32*4;

            number_prefixes--;

        }
        break;

    case OSPF_V3_LSTYPE_INTRA_AREA_PREFIX:

        /* # prefixes */
        proto_tree_add_item_ret_uint(ospf_lsa_tree, hf_ospf_v3_lsa_num_prefixes, tvb, offset, 2, ENC_BIG_ENDIAN, &number_prefixes);

        /* referenced LS type */
        proto_tree_add_item(ospf_lsa_tree, hf_ospf_v3_lsa_referenced_ls_type, tvb, offset+2, 2, ENC_BIG_ENDIAN);

        /* Referenced Link State ID */
        proto_tree_add_item(ospf_lsa_tree, hf_ospf_v3_lsa_referenced_link_state_id, tvb, offset + 4, 4, ENC_BIG_ENDIAN);

        /* Referenced Advertising Router */
        proto_tree_add_item(ospf_lsa_tree, hf_ospf_referenced_advertising_router, tvb, offset + 8, 4, ENC_BIG_ENDIAN);

        offset+=12;

        while (number_prefixes > 0) {

            /* prefix length */
            prefix_length=tvb_get_guint8(tvb, offset);
            proto_tree_add_item(ospf_lsa_tree, hf_ospf_prefix_length, tvb, offset, 1, ENC_BIG_ENDIAN);

            /* prefix options */
            dissect_ospf_bitfield(ospf_lsa_tree, tvb, offset+1, &bfinfo_v3_prefix_options);

            /* 16 bits metric */
            proto_tree_add_item(ospf_lsa_tree, hf_ospf_metric, tvb, offset+2, 2, ENC_BIG_ENDIAN);

            offset+=4;

            /* address_prefix */
            dissect_ospf_v3_address_prefix(tvb, pinfo, offset, prefix_length, ospf_lsa_tree, address_family);

            offset+=(prefix_length+31)/32*4;

            number_prefixes--;
        }
        break;

    case OSPF_V3_LSTYPE_OPAQUE_RI:
        dissect_ospf_lsa_opaque_ri(tvb, offset, ospf_lsa_tree, ls_length);
        break;

    default:
        /* unknown LSA type */
        expert_add_info_format(pinfo, type_item, &ei_ospf_lsa_unknown_type,
                            "Unknown LSA Type 0x%04x",ls_type);
        offset += ls_length;
        break;
    }
    /* return the offset of the next LSA */
    return offset;
}

static void dissect_ospf_v3_address_prefix(tvbuff_t *tvb, packet_info *pinfo, int offset, int prefix_length, proto_tree *tree,
                                           guint8 address_family)
{

    int bytes_to_process;
    struct e_in6_addr prefix;

    bytes_to_process=((prefix_length+31)/32)*4;

    if (prefix_length > 128) {
        proto_tree_add_expert_format(tree, pinfo, &ei_ospf_lsa_bad_length, tvb, offset, bytes_to_process,
            "Address Prefix: length is invalid (%d, should be <= 128)",
            prefix_length);
        return;
    }

    memset(prefix.bytes, 0, sizeof prefix.bytes);
    if (bytes_to_process != 0) {
        tvb_memcpy(tvb, prefix.bytes, offset, bytes_to_process);
        if (prefix_length % 8) {
            prefix.bytes[bytes_to_process - 1] &=
                ((0xff00 >> (prefix_length % 8)) & 0xff);
        }
    }
    if (address_family == OSPF_AF_6) {
        proto_tree_add_ipv6(tree, hf_ospf_v3_address_prefix_ipv6, tvb, offset, bytes_to_process,
                            &prefix);
    } else {
        proto_tree_add_item(tree, hf_ospf_v3_address_prefix_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
    }

}


void
proto_register_ospf(void)
{
    static hf_register_info ospff_info[] = {

        {&hf_ospf_header,
         { "OSPF Header", "ospf.header", FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_header_version,
         { "Version", "ospf.version", FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL }},
        /* Message type number */
        {&hf_ospf_header_msg_type,
         { "Message Type", "ospf.msg", FT_UINT8, BASE_DEC, VALS(pt_vals), 0x0,
           NULL, HFILL }},
        {&hf_ospf_header_packet_length,
         { "Packet Length", "ospf.packet_length", FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_header_src_router,
         { "Source OSPF Router", "ospf.srcrouter", FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_header_area_id,
         { "Area ID", "ospf.area_id", FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_header_checksum,
         { "Checksum", "ospf.checksum", FT_UINT16, BASE_HEX, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_tlv_type,
         { "TLV Type", "ospf.tlv_type", FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_tlv_length,
         { "TLV Length", "ospf.tlv_length", FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL }},
        /* OSPF Header v2 (Auth) */
        {&hf_ospf_header_auth_type,
         { "Auth Type", "ospf.auth.type", FT_UINT16, BASE_DEC, VALS(auth_vals), 0x0,
           NULL, HFILL }},
        {&hf_ospf_header_auth_data_none,
         { "Auth Data (none)", "ospf.auth.none", FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_header_auth_data_simple,
         { "Auth Data (Simple)", "ospf.auth.simple", FT_STRING, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_header_auth_crypt_key_id,
         { "Auth Crypt Key id", "ospf.auth.crypt.key_id", FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_header_auth_crypt_data_length,
         { "Auth Crypt Data Length", "ospf.auth.crypt.data_length", FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_header_auth_crypt_seq_nbr,
         { "Auth Crypt Sequence Number", "ospf.auth.crypt.seq_nbr", FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_header_auth_crypt_data,
         { "Auth Crypt Data", "ospf.auth.crypt.data", FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_header_auth_data_unknown,
         { "Auth Unknown", "ospf.auth.unknown", FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},

        /* OSPF Header v3 */
        {&hf_ospf_header_instance_id,
         { "Instance ID", "ospf.instance_id", FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(ospf_instance_id_rvals), 0x0,
           NULL, HFILL }},
        {&hf_ospf_header_reserved,
         { "Reserved", "ospf.reserved", FT_BYTES, BASE_NONE, NULL, 0x0,
           "Must be zero", HFILL }},

        /* Message types */
        {&hf_ospf_msg_hello,
         { "Hello", "ospf.msg.hello", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_msg_db_desc,
         { "Database Description", "ospf.msg.dbdesc", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_msg_ls_req,
         { "Link State Adv Request", "ospf.msg.lsreq", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_msg_ls_upd,
         { "Link State Adv Update", "ospf.msg.lsupdate", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_msg_ls_ack,
         { "Link State Adv Acknowledgement", "ospf.msg.lsack", FT_BOOLEAN,
           BASE_NONE, NULL, 0x0, NULL, HFILL }},

        /* Hello Packet */
        {&hf_ospf_hello,
         { "OSPF Hello Packet", "ospf.hello", FT_NONE,
           BASE_NONE, NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_hello_network_mask,
         { "Network Mask", "ospf.hello.network_mask", FT_IPv4,
           BASE_NETMASK, NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_hello_interface_id,
         { "Interface ID", "ospf.hello.interface_id", FT_UINT32,
           BASE_DEC, NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_hello_hello_interval,
         { "Hello Interval [sec]", "ospf.hello.hello_interval", FT_UINT32,
           BASE_DEC, NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_hello_router_priority,
         { "Router Priority", "ospf.hello.router_priority", FT_UINT8,
           BASE_DEC, NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_hello_router_dead_interval,
         { "Router Dead Interval [sec]", "ospf.hello.router_dead_interval", FT_UINT32,
           BASE_DEC, NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_hello_designated_router,
         { "Designated Router", "ospf.hello.designated_router", FT_IPv4,
           BASE_NONE, NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_hello_backup_designated_router,
         { "Backup Designated Router", "ospf.hello.backup_designated_router", FT_IPv4,
           BASE_NONE, NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_hello_active_neighbor,
         { "Active Neighbor", "ospf.hello.active_neighbor", FT_IPv4,
           BASE_NONE, NULL, 0x0, NULL, HFILL }},


        /* Authentication trailer */
        {&hf_ospf_at,
         { "OSPF Authentication Trailer", "ospf.at", FT_NONE,
           BASE_NONE, NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_at_auth_type,
         { "Authentication Type", "ospf.at.auth_type", FT_UINT16,
           BASE_DEC, VALS(ospf_at_authentication_type_vals), 0x0, "Identifying the type of authentication", HFILL }},
        {&hf_ospf_at_auth_data_len,
         { "Authentication Data Length", "ospf.at.auth_data_len", FT_UINT16,
           BASE_DEC, NULL, 0x0, "The length in octets of the Authentication Trailer (AT) including both the 16-octet fixed header and the variable length message digest", HFILL }},
        {&hf_ospf_at_reserved,
         { "Reserved", "ospf.at.reserved", FT_UINT16,
           BASE_HEX, NULL, 0x0, "It SHOULD be set to 0", HFILL }},
        {&hf_ospf_at_sa_id,
         { "Security Association Identifier (SA ID)", "ospf.at.sa_id", FT_UINT16,
           BASE_HEX, NULL, 0x0, "That maps to the authentication algorithm and the secret key used to create the message digest", HFILL }},
        {&hf_ospf_at_crypto_seq_nbr,
         { "Cryptographic Sequence Number", "ospf.at.cryto_seq_nbr", FT_UINT64,
           BASE_DEC, NULL, 0x0, "Increasing sequence number that is used to guard against replay attacks", HFILL }},
        {&hf_ospf_at_auth_data,
         { "Authentication Data", "ospf.at.auth_data", FT_BYTES,
           BASE_NONE, NULL, 0x0, "Variable data that is carrying the digest for the protocol packet and optional LLS data block", HFILL }},

        /* LS Types */
        {&hf_ospf_ls_type,
         { "LS Type", "ospf.lsa", FT_UINT8, BASE_DEC,
           VALS(ls_type_vals), 0x0, NULL, HFILL }},
        {&hf_ospf_ls_age,
         {"LS Age (seconds)", "ospf.lsa.age", FT_UINT16,
            BASE_DEC, NULL, ~OSPF_DNA_LSA, NULL, HFILL }},
        {&hf_ospf_ls_donotage,
         {"Do Not Age Flag", "ospf.lsa.donotage", FT_UINT16,
            BASE_DEC, NULL, OSPF_DNA_LSA, NULL, HFILL }},
        {&hf_ospf_ls_id,
         {"Link State ID", "ospf.lsa.id", FT_IPv4,
            BASE_NONE, NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_ls_seqnum,
         {"Sequence Number", "ospf.lsa.seqnum", FT_UINT32,
            BASE_HEX, NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_ls_chksum,
         {"Checksum", "ospf.lsa.chksum", FT_UINT16,
            BASE_HEX, NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_ls_length,
         {"Length", "ospf.lsa.length", FT_UINT16,
            BASE_DEC, NULL, 0x0, NULL, HFILL }},

        {&hf_ospf_ls_opaque_type,
         { "Link State ID Opaque Type", "ospf.lsid_opaque_type", FT_UINT8, BASE_DEC,
           VALS(ls_opaque_type_vals), 0x0, NULL, HFILL }},

        {&hf_ospf_ls_mpls_te_instance,
         { "Link State ID TE-LSA Instance", "ospf.lsid_te_lsa.instance", FT_UINT16, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

        {&hf_ospf_ls_router,
         { "Router LSA", "ospf.lsa.router", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_ls_router_linktype,
         { "Link Type", "ospf.lsa.router.linktype", FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_ls_router_linkid,
         { "Link ID", "ospf.lsa.router.linkid", FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_ls_router_linkdata,
         { "Link Data", "ospf.lsa.router.linkdata", FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_ls_router_nummetrics,
         { "Number of Metrics", "ospf.lsa.router.nummetrics", FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_ls_router_metric0,
         { "0 Metric", "ospf.lsa.router.metric0", FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL }},

        {&hf_ospf_ls_network,
         { "Network LSA", "ospf.lsa.network", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_ls_network_netmask,
         { "Netmask", "ospf.lsa.network.netmask", FT_IPv4, BASE_NETMASK, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_ls_network_attachrtr,
         { "Attached Router", "ospf.lsa.network.attchrtr", FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},

        {&hf_ospf_ls_summary,
         { "Summary LSA (IP Network)", "ospf.lsa.summary", FT_BOOLEAN, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_ls_asbr,
         { "Summary LSA (ASBR)", "ospf.lsa.asbr", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_ls_asbr_netmask,
         { "Netmask", "ospf.lsa.asbr.netmask", FT_IPv4, BASE_NETMASK, NULL, 0x0,
           NULL, HFILL }},

        {&hf_ospf_ls_asext,
         { "AS-External LSA (ASBR)", "ospf.lsa.asext", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_ls_asext_netmask,
         { "Netmask", "ospf.lsa.asext.netmask", FT_IPv4, BASE_NETMASK, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_ls_asext_fwdaddr,
         { "Forwarding Address", "ospf.lsa.asext.fwdaddr", FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_ls_asext_extrtrtag,
         { "External Route Tag", "ospf.lsa.asext.extrttag", FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL }},

        {&hf_ospf_ls_grpmember,
         { "Group Membership LSA", "ospf.lsa.member", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_ls_asext7,
         { "NSSA AS-External LSA", "ospf.lsa.nssa", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_ls_extattr,
         { "External Attributes LSA", "ospf.lsa.attr", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_ls_opaque,
         { "Opaque LSA", "ospf.lsa.opaque", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},

        /* OSPFv3 LS Types */
        {&hf_ospf_v3_ls_type,
         { "LS Type", "ospf.v3.lsa", FT_UINT16, BASE_HEX,
           VALS(v3_ls_type_vals), 0x0, NULL, HFILL }},

        {&hf_ospf_v3_ls_router,
         { "Router-LSA", "ospf.v3.lsa.router", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_v3_ls_network,
         { "Network-LSA", "ospf.v3.lsa.network", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_v3_ls_inter_area_prefix,
         { "Inter-Area-Prefix-LSA", "ospf.v3.lsa.interprefix", FT_BOOLEAN, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_v3_ls_inter_area_router,
         { "Inter-Area-Router-LSA", "ospf.v3.lsa.interrouter", FT_BOOLEAN, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_v3_ls_as_external,
         { "AS-External-LSA", "ospf.v3.lsa.asext", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_v3_ls_group_membership,
         { "Group-Membership-LSA", "ospf.v3.lsa.member", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_v3_ls_nssa,
         { "NSSA-LSA", "ospf.v3.lsa.nssa", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_v3_ls_link,
         { "Link-LSA", "ospf.v3.lsa.link", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_v3_ls_intra_area_prefix,
         { "Intra-Area-Prefix-LSA", "ospf.v3.lsa.intraprefix", FT_BOOLEAN, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_v3_ls_opaque_ri,
         { "Router Information Opaque-LSA", "ospf.v3.lsa.opaque", FT_BOOLEAN, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},

        /* Other interesting OSPF values */

        {&hf_ospf_adv_router,
         { "Advertising Router", "ospf.advrouter", FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},

        {&hf_ospf_ls_mpls,
         { "MPLS Traffic Engineering LSA", "ospf.lsa.mpls", FT_BOOLEAN,
           BASE_NONE, NULL, 0x0, NULL, HFILL }},

        {&hf_ospf_ls_mpls_routerid,
         { "MPLS/TE Router ID", "ospf.mpls.routerid", FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},

        {&hf_ospf_ls_mpls_linktype,
         { "MPLS/TE Link Type", "ospf.mpls.linktype", FT_UINT8, BASE_DEC,
           VALS(mpls_link_stlv_ltype_str), 0x0, NULL, HFILL }},
        {&hf_ospf_ls_mpls_linkid,
         { "MPLS/TE Link ID", "ospf.mpls.linkid", FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_ls_mpls_local_addr,
         { "MPLS/TE Local Interface Address", "ospf.mpls.local_addr", FT_IPv4,
           BASE_NONE, NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_ls_mpls_remote_addr,
         { "MPLS/TE Remote Interface Address", "ospf.mpls.remote_addr", FT_IPv4,
           BASE_NONE, NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_ls_mpls_te_metric,
         { "MPLS/TE Metric", "ospf.mpls.te_metric", FT_UINT32,
           BASE_DEC, NULL, 0x0, NULL, HFILL }},

        {&hf_ospf_ls_mpls_local_ifid,
         { "MPLS/TE Local Interface Index", "ospf.mpls.local_id", FT_UINT32,
           BASE_DEC, NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_ls_mpls_remote_ifid,
         { "MPLS/TE Remote Interface Index", "ospf.mpls.remote_id", FT_UINT32,
           BASE_DEC, NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_ls_mpls_linkcolor,
         { "MPLS/TE Link Resource Class/Color", "ospf.mpls.linkcolor", FT_UINT32,
           BASE_HEX, NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_ls_mpls_group,
         { "MPLS/TE Group", "ospf.mpls.group", FT_UINT32,
           BASE_HEX, NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_ls_mpls_link_max_bw,
         { "Link Max BW", "ospf.mpls.link_max_bw", FT_FLOAT,
           BASE_NONE, NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_ls_mpls_bc_model_id,
         { "MPLS/DSTE Bandwidth Constraints Model Id", "ospf.mpls.bc.model_id", FT_UINT8,
           BASE_RANGE_STRING | BASE_DEC, RVALS(mpls_link_stlv_bcmodel_rvals), 0x0,
           NULL, HFILL }},

        {&hf_ospf_ls_oif_local_node_id,
         { "Local Node ID", "ospf.oif.local_node_id", FT_IPv4,
           BASE_NONE, NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_ls_oif_remote_node_id,
         { "Remote Node ID", "ospf.oif.remote_node_id", FT_IPv4,
           BASE_NONE, NULL, 0x0, NULL, HFILL }},

        {&hf_ospf_v2_options,
         { "Options", "ospf.v2.options", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_v2_options_mt,
         { "(MT) Multi-Topology Routing", "ospf.v2.options.mt", FT_BOOLEAN, 8,
           TFS(&tfs_yes_no), OSPF_V2_OPTIONS_MT, NULL, HFILL }},
        {&hf_ospf_v2_options_e,
         { "(E) External Routing", "ospf.v2.options.e", FT_BOOLEAN, 8,
           TFS(&tfs_capable_not_capable), OSPF_V2_OPTIONS_E, NULL, HFILL }},
        {&hf_ospf_v2_options_mc,
         { "(MC) Multicast", "ospf.v2.options.mc", FT_BOOLEAN, 8,
           TFS(&tfs_capable_not_capable), OSPF_V2_OPTIONS_MC, NULL, HFILL }},
        {&hf_ospf_v2_options_n,
         { "(N) NSSA", "ospf.v2.options.n", FT_BOOLEAN, 8,
           TFS(&tfs_supported_not_supported), OSPF_V2_OPTIONS_NP, NULL, HFILL }},
        {&hf_ospf_v2_options_p,
         { "(P) Propagate", "ospf.v2.options.p", FT_BOOLEAN, 8,
           TFS(&tfs_set_notset), OSPF_V2_OPTIONS_NP, NULL, HFILL }},
        {&hf_ospf_v2_options_l,
         { "(L) LLS Data block", "ospf.v2.options.l", FT_BOOLEAN, 8,
           TFS(&tfs_present_not_present), OSPF_V2_OPTIONS_L, NULL, HFILL }},
        {&hf_ospf_v2_options_dc,
         { "(DC) Demand Circuits", "ospf.v2.options.dc", FT_BOOLEAN, 8,
           TFS(&tfs_supported_not_supported), OSPF_V2_OPTIONS_DC, NULL, HFILL }},
        {&hf_ospf_v2_options_o,
         { "O", "ospf.v2.options.o", FT_BOOLEAN, 8,
           TFS(&tfs_set_notset), OSPF_V2_OPTIONS_O, NULL, HFILL }},
        {&hf_ospf_v2_options_dn,
         { "DN", "ospf.v2.options.dn", FT_BOOLEAN, 8,
           TFS(&tfs_set_notset), OSPF_V2_OPTIONS_DN, NULL, HFILL }},

        {&hf_ospf_ri_options,
         { "RI Options", "ospf.ri.options", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_ri_options_grc,
         { "(GRC) Graceful Restart", "ospf.ri.options.grc", FT_BOOLEAN, 8,
           TFS(&tfs_capable_not_capable), OSPF_RI_OPTIONS_GRC, NULL, HFILL }},
        {&hf_ospf_ri_options_grh,
         { "(GRH) Graceful Restart Helper", "ospf.ri.options.grh", FT_BOOLEAN, 8,
           TFS(&tfs_enabled_disabled), OSPF_RI_OPTIONS_GRH, NULL, HFILL }},
        {&hf_ospf_ri_options_srs,
         { "Stub Router Support", "ospf.ri.options.srs", FT_BOOLEAN, 8,
           TFS(&tfs_yes_no), OSPF_RI_OPTIONS_SRS, NULL, HFILL }},
        {&hf_ospf_ri_options_tes,
         { "(TES) Traffic Engineering", "ospf.ri.options.tes", FT_BOOLEAN, 8,
           TFS(&tfs_supported_not_supported), OSPF_RI_OPTIONS_TES, NULL, HFILL }},
        {&hf_ospf_ri_options_p2plan,
         { "(P2PLAN) Point-to-point over LAN", "ospf.ri.options.p2plan", FT_BOOLEAN, 8,
           TFS(&tfs_capable_not_capable), OSPF_RI_OPTIONS_P2PLAN, NULL, HFILL }},
        {&hf_ospf_ri_options_ete,
         { "(ETE) Experimental TE", "ospf.ri.options.ete", FT_BOOLEAN, 8,
           TFS(&tfs_capable_not_capable), OSPF_RI_OPTIONS_ETE, NULL, HFILL }},

        /* An MBZ field for the 24-bits of type field of Opaque RI LSA */
        {&hf_ospf_opaque_lsa_mbz,
         { "MBZ", "ospf.ri.mbz", FT_UINT16, BASE_HEX,
            NULL, 0x0, "OSPF Opaque RI LSA - 24 bits of Type Field Must be Zero", HFILL }},

        {&hf_ospf_v3_options,
         { "Options", "ospf.v3.options", FT_UINT24, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_v3_options_v6,
         { "V6", "ospf.v3.options.v6", FT_BOOLEAN, 24,
           TFS(&tfs_set_notset), OSPF_V3_OPTIONS_V6, NULL, HFILL }},
        {&hf_ospf_v3_options_e,
         { "E", "ospf.v3.options.e", FT_BOOLEAN, 24,
           TFS(&tfs_set_notset), OSPF_V3_OPTIONS_E, NULL, HFILL }},
        {&hf_ospf_v3_options_mc,
         { "MC", "ospf.v3.options.mc", FT_BOOLEAN, 24,
           TFS(&tfs_set_notset), OSPF_V3_OPTIONS_MC, NULL, HFILL }},
        {&hf_ospf_v3_options_n,
         { "N", "ospf.v3.options.n", FT_BOOLEAN, 24,
           TFS(&tfs_set_notset), OSPF_V3_OPTIONS_N, NULL, HFILL }},
        {&hf_ospf_v3_options_r,
         { "R", "ospf.v3.options.r", FT_BOOLEAN, 24,
           TFS(&tfs_set_notset), OSPF_V3_OPTIONS_R, NULL, HFILL }},
        {&hf_ospf_v3_options_dc,
         { "DC", "ospf.v3.options.dc", FT_BOOLEAN, 24,
           TFS(&tfs_set_notset), OSPF_V3_OPTIONS_DC, NULL, HFILL }},
        {&hf_ospf_v3_options_af,
         { "AF", "ospf.v3.options.af", FT_BOOLEAN, 24,
           TFS(&tfs_set_notset), OSPF_V3_OPTIONS_AF, NULL, HFILL }},
        {&hf_ospf_v3_options_l,
         { "L", "ospf.v3.options.l", FT_BOOLEAN, 24,
           TFS(&tfs_set_notset), OSPF_V3_OPTIONS_L, NULL, HFILL }},
        {&hf_ospf_v3_options_at,
         { "AT", "ospf.v3.options.at", FT_BOOLEAN, 24,
           TFS(&tfs_set_notset), OSPF_V3_OPTIONS_AT, NULL, HFILL }},
        {&hf_ospf_dbd,
         { "DB Description", "ospf.dbd", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_dbd_r,
         { "(R) OOBResync", "ospf.dbd.r", FT_BOOLEAN, 8,
           TFS(&tfs_set_notset), OSPF_DBD_FLAG_R, NULL, HFILL }},
        {&hf_ospf_dbd_i,
         { "(I) Init", "ospf.dbd.i", FT_BOOLEAN, 8,
           TFS(&tfs_set_notset), OSPF_DBD_FLAG_I, NULL, HFILL }},
        {&hf_ospf_dbd_m,
         { "(M) More", "ospf.dbd.m", FT_BOOLEAN, 8,
           TFS(&tfs_set_notset), OSPF_DBD_FLAG_M, NULL, HFILL }},
        {&hf_ospf_dbd_ms,
         { "(MS) Master", "ospf.dbd.ms", FT_BOOLEAN, 8,
           TFS(&tfs_yes_no), OSPF_DBD_FLAG_MS, NULL, HFILL }},
        {&hf_ospf_lls_ext_options,
         { "Options", "ospf.lls.ext.options", FT_UINT32, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_lls_ext_options_lr,
         { "(LR) LSDB Resynchronization", "ospf.lls.ext.options.lr", FT_BOOLEAN, 32,
           TFS(&tfs_set_notset), OSPF_LLS_EXT_OPTIONS_LR, NULL, HFILL }},
        {&hf_ospf_lls_ext_options_rs,
         { "(RS) Restart Signal", "ospf.lls.ext.options.rs", FT_BOOLEAN, 32,
           TFS(&tfs_set_notset), OSPF_LLS_EXT_OPTIONS_RS, NULL, HFILL }},
        {&hf_ospf_v2_router_lsa_flag,
         { "Flags", "ospf.v2.router.lsa.flags", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_v2_router_lsa_flag_b,
         { "(B) Area border router", "ospf.v2.router.lsa.flags.b", FT_BOOLEAN, 8,
           TFS(&tfs_yes_no), OSPF_V2_ROUTER_LSA_FLAG_B, NULL, HFILL }},
        {&hf_ospf_v2_router_lsa_flag_e,
         { "(E) AS boundary router", "ospf.v2.router.lsa.flags.e", FT_BOOLEAN, 8,
           TFS(&tfs_yes_no), OSPF_V2_ROUTER_LSA_FLAG_E, NULL, HFILL }},
        {&hf_ospf_v2_router_lsa_flag_v,
         { "(V) Virtual link endpoint", "ospf.v2.router.lsa.flags.v", FT_BOOLEAN, 8,
           TFS(&tfs_yes_no), OSPF_V2_ROUTER_LSA_FLAG_V, NULL, HFILL }},
        {&hf_ospf_v2_router_lsa_flag_w,
         { "(W) Wild-card multicast receiver", "ospf.v2.router.lsa.flags.w", FT_BOOLEAN, 8,
           TFS(&tfs_yes_no), OSPF_V2_ROUTER_LSA_FLAG_W, NULL, HFILL }},
        {&hf_ospf_v2_router_lsa_flag_n,
         { "(N) flag", "ospf.v2.router.lsa.flags.n", FT_BOOLEAN, 8,
           TFS(&tfs_yes_no), OSPF_V2_ROUTER_LSA_FLAG_N, NULL, HFILL }},
        {&hf_ospf_v3_router_lsa_flag,
         { "Flags", "ospf.v3.router.lsa.flags", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_v3_router_lsa_flag_b,
         { "(B) Area border router", "ospf.v3.router.lsa.flags.b", FT_BOOLEAN, 8,
           TFS(&tfs_yes_no), OSPF_V3_ROUTER_LSA_FLAG_B, NULL, HFILL }},
        {&hf_ospf_v3_router_lsa_flag_e,
         { "(E) AS boundary router", "ospf.v3.router.lsa.flags.e", FT_BOOLEAN, 8,
           TFS(&tfs_yes_no), OSPF_V3_ROUTER_LSA_FLAG_E, NULL, HFILL }},
        {&hf_ospf_v3_router_lsa_flag_v,
         { "(V) Virtual link endpoint", "ospf.v3.router.lsa.flags.v", FT_BOOLEAN, 8,
           TFS(&tfs_yes_no), OSPF_V3_ROUTER_LSA_FLAG_V, NULL, HFILL }},
        {&hf_ospf_v3_router_lsa_flag_w,
         { "(W) Wild-card multicast receiver", "ospf.v3.router.lsa.flags.w", FT_BOOLEAN, 8,
           TFS(&tfs_yes_no), OSPF_V3_ROUTER_LSA_FLAG_W, NULL, HFILL }},
        {&hf_ospf_v3_as_external_flag,
         { "Flags", "ospf.v3.as.external.flags", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_v3_as_external_flag_t,
         { "(T) External Route Tag", "ospf.v3.as.external.flags.t", FT_BOOLEAN, 8,
           TFS(&tfs_present_not_present), OSPF_V3_AS_EXTERNAL_FLAG_T, NULL, HFILL }},
        {&hf_ospf_v3_as_external_flag_f,
         { "(F) Forwarding Address", "ospf.v3.as.external.flags.f", FT_BOOLEAN, 8,
           TFS(&tfs_present_absent), OSPF_V3_AS_EXTERNAL_FLAG_F, NULL, HFILL }},
        {&hf_ospf_v3_as_external_flag_e,
         { "(E) External Metric", "ospf.v3.as.external.flags.e", FT_BOOLEAN, 8,
           TFS(&tfs_v3_as_external_flags_e), OSPF_V3_AS_EXTERNAL_FLAG_E, NULL, HFILL }},
        {&hf_ospf_v3_prefix_option,
         { "PrefixOptions", "ospf.v3.prefix.options", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_v3_prefix_option_nu,
         { "(NU) NoUnicast", "ospf.v3.prefix.options.nu", FT_BOOLEAN, 8,
           TFS(&tfs_set_notset), OSPF_V3_PREFIX_OPTION_NU, NULL, HFILL }},
        {&hf_ospf_v3_prefix_option_la,
         { "(LA) Local Address", "ospf.v3.prefix.options.la", FT_BOOLEAN, 8,
           TFS(&tfs_set_notset), OSPF_V3_PREFIX_OPTION_LA, NULL, HFILL }},
        {&hf_ospf_v3_prefix_option_mc,
         { "(MC) Multicast", "ospf.v3.prefix.options.mc", FT_BOOLEAN, 8,
           TFS(&tfs_set_notset), OSPF_V3_PREFIX_OPTION_MC, NULL, HFILL }},
        {&hf_ospf_v3_prefix_option_p,
         { "(P) Propogate", "ospf.v3.prefix.options.p", FT_BOOLEAN, 8,
           TFS(&tfs_set_notset), OSPF_V3_PREFIX_OPTION_P, NULL, HFILL }},

        /* Dynamic Hostname contained in the Opaque RI LSA - dynamic hostname TLV*/
        {&hf_ospf_dyn_hostname,
         { "Dynamic Hostname", "ospf.dynhostname", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        /* text contained in the Unknown TLV of the Opaque RI LSA */
        {&hf_ospf_unknown_tlv_txt,
         { "Text in the Unknown TLV", "ospf.unknown_text", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        /* OSPF Restart TLVs  */
        {&hf_ospf_v2_grace_tlv,
         { "Grace TLV", "ospf.v2.grace", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_ospf_v2_grace_period,
         { "Grace Period", "ospf.v2.grace.period", FT_UINT32, BASE_DEC,
           NULL, 0x0,
           "The number of seconds neighbors should advertise the router as fully adjacent",
           HFILL }},
        {&hf_ospf_v2_grace_reason,
         { "Restart Reason", "ospf.v2.grace.reason", FT_UINT8, BASE_DEC,
           VALS(restart_reason_vals), 0x0, "The reason the router is restarting", HFILL }},
        {&hf_ospf_v2_grace_ip,
         { "Restart IP", "ospf.v2.grace.ip", FT_IPv4, BASE_NONE,
           NULL, 0x0, "The IP address of the interface originating this LSA", HFILL }},

        /* OSPFv3 LLS TLVs */
        {&hf_ospf_v3_lls_ext_options_tlv,
         { "Extended Options TLV", "ospf.v3.lls.ext.options.tlv", FT_NONE, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_v3_lls_ext_options,
         { "Options", "ospf.v3.lls.ext.options", FT_UINT32,  BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_v3_lls_ext_options_lr,
         { "(LR) LSDB Resynchronization", "ospf.v3.lls.ext.options.lr", FT_BOOLEAN, 32,
           TFS(&tfs_set_notset), OSPF_V3_LLS_EXT_OPTIONS_LR, NULL, HFILL }},
        {&hf_ospf_v3_lls_ext_options_rs,
         { "(RS) Restart Signal", "ospf.v3.lls.ext.options.rs", FT_BOOLEAN, 32,
           TFS(&tfs_set_notset), OSPF_V3_LLS_EXT_OPTIONS_RS, NULL, HFILL }},
        {&hf_ospf_v3_lls_state_tlv,
         { "State Check Sequence TLV", "ospf.v3.lls.state.tlv", FT_NONE, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_v3_lls_state_scs,
         { "SCS Number", "ospf.v3.lls.state.scs", FT_UINT16,  BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_v3_lls_state_options,
         { "Options", "ospf.v3.lls.state.options", FT_UINT8,  BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_v3_lls_state_options_r,
         { "(R) Resuest", "ospf.v3.lls.state.options.r", FT_BOOLEAN, 8,
           TFS(&tfs_set_notset), OSPF_V3_LLS_STATE_OPTIONS_R, NULL, HFILL }},
        {&hf_ospf_v3_lls_state_options_a,
         { "(A) Answer", "ospf.v3.lls.state.options.a", FT_BOOLEAN, 8,
           TFS(&tfs_set_notset), OSPF_V3_LLS_STATE_OPTIONS_A , NULL, HFILL }},
        {&hf_ospf_v3_lls_state_options_n,
         { "(N) Incomplete", "ospf.v3.lls.state.options.n", FT_BOOLEAN, 8,
           TFS(&tfs_set_notset), OSPF_V3_LLS_STATE_OPTIONS_N ,NULL, HFILL }},
        {&hf_ospf_v3_lls_drop_tlv,
         { "Neighbor Drop TLV", "ospf.v3.lls.drop.tlv", FT_NONE, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_v3_lls_relay_tlv,
         { "Active Overlapping Relays TLV", "ospf.v3.lls.relay.tlv", FT_NONE, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_v3_lls_relay_added,
         { "Relays Added", "ospf.v3.lls.relay.added", FT_UINT8,  BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_v3_lls_relay_options,
         { "Options", "ospf.v3.lls.relay.options", FT_UINT8,  BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_v3_lls_relay_options_a,
         { "(A) Always", "ospf.v3.lls.relay.options.a", FT_BOOLEAN, 8,
           TFS(&tfs_set_notset), OSPF_V3_LLS_RELAY_OPTIONS_A, NULL, HFILL }},
        {&hf_ospf_v3_lls_relay_options_n,
         { "(N) Never", "ospf.v3.lls.relay.options.n", FT_BOOLEAN, 8,
           TFS(&tfs_set_notset), OSPF_V3_LLS_RELAY_OPTIONS_N, NULL, HFILL }},
        {&hf_ospf_v3_lls_willingness_tlv,
         { "Willingness TLV", "ospf.v3.lls.willingness.tlv", FT_NONE, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_v3_lls_willingness,
         { "Willingness", "ospf.v3.lls.willingness", FT_UINT8,  BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_v3_lls_rf_tlv,
         { "Request From TLV", "ospf.v3.lls.rf.tlv", FT_NONE, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_v3_lls_fsf_tlv,
         { "Full State For TLV", "ospf.v3.lls.fsf.tlv", FT_NONE, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_ospf_v2_lls_sequence_number, { "Sequence number", "ospf.v2.lls.sequence_number", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_v2_lls_auth_data, { "Auth Data", "ospf.v2.lls.auth_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_v3_lls_extended_options, { "Extended Options", "ospf.v3.lls.extended_options", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_v3_lls_dropped_neighbor, { "Dropped Neighbor", "ospf.v3.lls.dropped_neighbor", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_v3_lls_neighbor, { "Neighbor", "ospf.v3.lls.neighbor", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_v3_lls_request_from, { "Request From", "ospf.v3.lls.request_from", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_v3_lls_full_state_for, { "Full State For", "ospf.v3.lls.full_state_for", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_lls_checksum, { "Checksum", "ospf.lls.checksum", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_lls_data_length, { "LLS Data Length", "ospf.lls.data_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_db_interface_mtu, { "Interface MTU", "ospf.db.interface_mtu", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_db_dd_sequence, { "DD Sequence", "ospf.db.dd_sequence", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_link_state_id, { "Link State ID", "ospf.link_state_id", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_ls_number_of_lsas, { "Number of LSAs", "ospf.ls.number_of_lsas", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_mpls_switching_type, { "Switching Type", "ospf.mpls.switching_type", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gmpls_switching_type_rvals), 0x0, NULL, HFILL }},
      { &hf_ospf_mpls_encoding, { "Encoding", "ospf.mpls.encoding", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gmpls_lsp_enc_rvals), 0x0, NULL, HFILL }},
      { &hf_ospf_mpls_interface_mtu, { "Interface MTU", "ospf.mpls.interface_mtu", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_mpls_protection_capability, { "Protection Capability", "ospf.mpls.protection_capability", FT_UINT8, BASE_HEX, VALS(gmpls_protection_cap_str), 0x0, NULL, HFILL }},
      { &hf_ospf_mpls_shared_risk_link_group, { "Shared Risk Link Group", "ospf.mpls.shared_risk_link_group", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_oif_switching_cap, { "Switching Cap", "ospf.oif.switching_cap", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gmpls_switching_type_rvals), 0x0, NULL, HFILL }},
      { &hf_ospf_oif_encoding, { "Encoding", "ospf.oif.encoding", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gmpls_lsp_enc_rvals), 0x0, NULL, HFILL }},
      { &hf_ospf_oif_tna_addr_length, { "Addr Length", "ospf.oif.tna_addr_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_oif_tna_addr_ipv4, { "TNA Addr", "ospf.oif.tna_addr.ipv4", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_tna_addr_ipv6, { "TNA Addr", "ospf.oif.tna_addr.ipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_tna_addr, { "TNA Addr", "ospf.oif.tna_addr", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_ls_id_te_lsa_reserved, { "Link State ID TE-LSA Reserved", "ospf.lsid_te_lsa.reserved", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_ls_id_opaque_id, { "Link State ID Opaque ID", "ospf.lsid.opaque_id", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_lsa_number_of_links, { "Number of Links", "ospf.lsa.number_of_links", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_v3_lsa_do_not_age, { "Do Not Age", "ospf.v3.lsa.do_not_age", FT_BOOLEAN, 16, TFS(&tfs_true_false), OSPF_DNA_LSA, NULL, HFILL }},
      { &hf_ospf_v3_lsa_interface_id, { "Interface ID", "ospf.v3.lsa.interface_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_v3_lsa_neighbor_interface_id, { "Neighbor Interface ID", "ospf.v3.lsa.neighbor_interface_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_v3_lsa_neighbor_router_id, { "Neighbor Router ID", "ospf.v3.lsa.neighbor_router_id", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_v3_lsa_attached_router, { "Attached Router", "ospf.v3.lsa.attached_router", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_v3_lsa_destination_router_id, { "Destination Router ID", "ospf.v3.lsa.destination_router_id", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_v3_lsa_referenced_ls_type, { "Referenced LS type", "ospf.v3.lsa.referenced_ls_type", FT_UINT16, BASE_HEX, VALS(v3_ls_type_vals), 0x0, NULL, HFILL }},
      { &hf_ospf_v3_lsa_forwarding_address_ipv6, { "Forwarding Address", "ospf.v3.lsa.forwarding_address.ipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_v3_lsa_external_route_tag, { "External Route Tag", "ospf.v3.lsa.external_route_tag", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_v3_lsa_referenced_link_state_id, { "Referenced Link State ID", "ospf.v3.lsa.referenced_link_state_id", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_v3_lsa_router_priority, { "Router Priority", "ospf.v3.lsa.router_priority", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_v3_lsa_link_local_interface_address, { "Link-local Interface Address", "ospf.v3.lsa.link_local_interface_address.ipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_referenced_advertising_router, { "Referenced Advertising Router", "ospf.v3.lsa.referenced_advertising_router", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_lsa_external_type, { "External Type", "ospf.lsa.asext.type", FT_BOOLEAN, 8, TFS(&tfs_lsa_external_type), 0x80, NULL, HFILL }},
      { &hf_ospf_lsa_tos, { "TOS", "ospf.lsa.tos", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_lsa_external_tos, { "TOS", "ospf.lsa.tos", FT_UINT8, BASE_DEC, NULL, 0x7f, NULL, HFILL }},
      { &hf_ospf_v3_lsa_type, { "Type", "ospf.v3.lsa.type", FT_UINT8, BASE_DEC, VALS(ospf_v3_lsa_type_vals), 0, NULL, HFILL }},
      { &hf_ospf_metric, { "Metric", "ospf.metric", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_ospf_prefix_length, { "PrefixLength", "ospf.prefix_length", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_ospf_ls_mpls_pri, { "Pri (or TE-Class)", "ospf.mpls.pri", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_ls_mpls_bc, { "BC", "ospf.mpls.bc", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_mpls_minimum_lsp_bandwidth, { "Minimum LSP bandwidth", "ospf.mpls.minimum_lsp_bandwidth", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_mpls_sonet_sdh, { "SONET/SDH", "ospf.mpls.sonet.sdh", FT_BOOLEAN, 8, TFS(&tfs_arbitrary_standard), 0x0, NULL, HFILL }},
      { &hf_ospf_oif_signal_type, { "Signal Type", "ospf.oif.signal_type", FT_UINT8, BASE_DEC|BASE_EXT_STRING, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_tlv_value, { "TLV Value", "ospf.tlv_value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_oif_node_id, { "Node ID", "ospf.oif.node_id", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_pad_bytes, { "Pad Bytes", "ospf.pad_bytes", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_ls_metric, { "Metric", "ospf.ls.metric", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_v3_lsa_forwarding_address_ipv4, { "Forwarding Address", "ospf.v3.lsa.forwarding_address.ipv4", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_link_local_interface_address_ipv4, { "Link-local Interface Address", "ospf.v3.lsa.link_local_interface_address.ipv4", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_v3_lsa_num_prefixes, { "# prefixes", "ospf.v3.lsa.num_prefixes", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_v3_address_prefix_ipv6, { "Address Prefix", "ospf.v3.address_prefix.ipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ospf_v3_address_prefix_ipv4, { "Address Prefix", "ospf.v3.address_prefix.ipv4", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_ospf,
        &ett_ospf_at,
        &ett_ospf_hdr,
        &ett_ospf_hello,
        &ett_ospf_desc,
        &ett_ospf_lsr,
        &ett_ospf_lsa,
        &ett_ospf_lsa_router_link,
        &ett_ospf_lsa_upd,
        &ett_ospf_lsa_mpls,
        &ett_ospf_lsa_mpls_router,
        &ett_ospf_lsa_mpls_link,
        &ett_ospf_lsa_mpls_link_stlv,
        &ett_ospf_lsa_mpls_link_stlv_admingrp,
        &ett_ospf_lsa_opaque_ri,
        &ett_ospf_lsa_ri_tlv,
        &ett_ospf_lsa_dyn_hostname_tlv,
        &ett_ospf_lsa_unknown_tlv,
        &ett_ospf_lsa_oif_tna,
        &ett_ospf_lsa_oif_tna_stlv,
        &ett_ospf_lsa_grace_tlv,
        &ett_ospf_v2_options,
        &ett_ospf_ri_options,
        &ett_ospf_v3_options,
        &ett_ospf_dbd,
        &ett_ospf_lls_data_block,
        &ett_ospf_lls_tlv,
        &ett_ospf_lls_ext_options,
        &ett_ospf_v3_router_interface,
        &ett_ospf_v3_router_interface_entry,
        &ett_ospf_v3_lls_ext_options_tlv,
        &ett_ospf_v3_lls_ext_options,
        &ett_ospf_v3_lls_state_tlv,
        &ett_ospf_v3_lls_state_scs,
        &ett_ospf_v3_lls_state_options,
        &ett_ospf_v3_lls_drop_tlv,
        &ett_ospf_v3_lls_relay_tlv,
        &ett_ospf_v3_lls_relay_added,
        &ett_ospf_v3_lls_relay_options,
        &ett_ospf_v3_lls_willingness_tlv,
        &ett_ospf_v3_lls_willingness,
        &ett_ospf_v3_lls_rf_tlv,
        &ett_ospf_v3_lls_fsf_tlv,
        &ett_ospf_v2_router_lsa_flags,
        &ett_ospf_v3_router_lsa_flags,
        &ett_ospf_v3_as_external_flags,
        &ett_ospf_v3_prefix_options
    };

    static ei_register_info ei[] = {
        { &ei_ospf_header_reserved, { "ospf.reserved.not_zero", PI_PROTOCOL, PI_WARN, "incorrect, should be 0", EXPFILL }},
        { &ei_ospf_lsa_bad_length, { "ospf.lsa.invalid_length", PI_MALFORMED, PI_ERROR, "Invalid length", EXPFILL }},
        { &ei_ospf_lsa_constraint_missing, { "ospf.lsa.tos_missing", PI_MALFORMED, PI_WARN, "Blocks missing", EXPFILL }},
        { &ei_ospf_lsa_bc_error, { "ospf.lsa.bc_error", PI_PROTOCOL, PI_WARN, "BC error", EXPFILL }},
        { &ei_ospf_lsa_unknown_type, { "ospf.lsa.unknown_type", PI_PROTOCOL, PI_WARN, "Unknown LSA Type", EXPFILL }},
        { &ei_ospf_unknown_link_subtype, { "ospf.unknown_link_subtype", PI_PROTOCOL, PI_WARN, "Unknown Link sub-TLV", EXPFILL }},
    };

    expert_module_t* expert_ospf;

    proto_ospf = proto_register_protocol("Open Shortest Path First",
                                         "OSPF", "ospf");
    proto_register_field_array(proto_ospf, ospff_info, array_length(ospff_info));
    proto_register_subtree_array(ett, array_length(ett));
    expert_ospf = expert_register_protocol(proto_ospf);
    expert_register_field_array(expert_ospf, ei, array_length(ei));
}

void
proto_reg_handoff_ospf(void)
{
    dissector_handle_t ospf_handle;

    ospf_handle = create_dissector_handle(dissect_ospf, proto_ospf);
    dissector_add_uint("ip.proto", IP_PROTO_OSPF, ospf_handle);
    register_capture_dissector("ip.proto", IP_PROTO_OSPF, capture_ospf, proto_ospf);
    register_capture_dissector("ipv6.nxt", IP_PROTO_OSPF, capture_ospf, proto_ospf);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
