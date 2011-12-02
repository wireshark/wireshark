/* packet-ospf.c
 * Routines for OSPF packet disassembly
 * (c) Copyright Hannes R. Boehm <hannes@boehm.org>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/ipproto.h>
#include <epan/in_cksum.h>
#include <epan/emem.h>
#include <epan/addr_resolv.h>
#include "packet-rsvp.h"

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

static const value_string pt_vals[] = {
    {OSPF_HELLO,   "Hello Packet"   },
    {OSPF_DB_DESC, "DB Description" },
    {OSPF_LS_REQ,  "LS Request"     },
    {OSPF_LS_UPD,  "LS Update"      },
    {OSPF_LS_ACK,  "LS Acknowledge" },
    {0,             NULL            }
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
#define OSPF_V3_OPTIONS_I               0x0400
#define OSPF_V3_OPTIONS_F               0x0800

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
#define OSPF_LSTYPE_SUMMERY     3
#define OSPF_LSTYPE_ASBR        4
#define OSPF_LSTYPE_ASEXT       5
#define OSPF_LSTYPE_GRPMEMBER   6
#define OSPF_LSTYPE_ASEXT7      7
#define OSPF_LSTYPE_EXTATTR     8
#define OSPF_V3_LSTYPE_ROUTER                0x2001
#define OSPF_V3_LSTYPE_NETWORK               0x2002
#define OSPF_V3_LSTYPE_INTER_AREA_PREFIX     0x2003
#define OSPF_V3_LSTYPE_INTER_AREA_ROUTER     0x2004
#define OSPF_V3_LSTYPE_AS_EXTERNAL           0x4005
#define OSPF_V3_LSTYPE_GROUP_MEMBERSHIP      0x2006
#define OSPF_V3_LSTYPE_TYPE_7                0x2007
#define OSPF_V3_LSTYPE_LINK                  0x0008
#define OSPF_V3_LSTYPE_INTRA_AREA_PREFIX     0x2009
/* The Opaque RI LSA has a type "12" for OSPFv3 */
#define OSPF_V3_LSTYPE_OPAQUE_RI             0x800c

/* Opaque LSA types */
#define OSPF_LSTYPE_OP_LINKLOCAL 9
#define OSPF_LSTYPE_OP_AREALOCAL 10
#define OSPF_LSTYPE_OP_ASWIDE    11

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
#define OSPF_V3_LSA_OPAQUE_RI   12
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

/* The Opaque RI LSA TLV types definitions. */
static const value_string ri_tlv_type_vals[] = {
    {OPT_RI_TLV,          "Optional Router Informational Capabilities TLV"},
    {DYN_HOSTNAME_TLV,    "Dynamic Hostname TLV"},
    {0, NULL}
};

static const value_string ls_type_vals[] = {
    {OSPF_LSTYPE_ROUTER,                  "Router-LSA"                   },
    {OSPF_LSTYPE_NETWORK,                 "Network-LSA"                  },
    {OSPF_LSTYPE_SUMMERY,                 "Summary-LSA (IP network)"     },
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
    {OSPF_V3_LSTYPE_TYPE_7,               "Type-LSA"                     },
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


static const true_false_string tfs_v2_options_dc = {
    "Demand Circuits are supported",
    "Demand Circuits are NOT supported"
};
static const true_false_string tfs_v2_options_l = {
    "The packet contains LLS data block",
    "The packet does NOT contain LLS data block"
};
static const true_false_string tfs_v2_options_np = {
    "NSSA is supported",
    "NSSA is NOT supported"
};
static const true_false_string tfs_v2_options_mc = {
    "Multicast Capable",
    "NOT Multicast Capable"
};
static const true_false_string tfs_v2_options_e = {
    "External Routing Capability",
    "NO External Routing Capability"
};
static const true_false_string tfs_v2_options_mt = {
    "Multi-Topology Routing",
    "NO Multi-Topology Routing"
};
static const true_false_string tfs_v2_options_o = {
    "O-bit is SET",
    "O-bit is NOT set"
};
static const true_false_string tfs_v2_options_dn = {
    "DN-bit is SET",
    "DN-bit is NOT set"
};

/* The Options field in the first TLV of the Opaque RI LSA with type field set to "4" for OSPFv2
   and type field set to "12" in OSPFv3, is interpreted as advertizing optional router capabilties. 
   (RFC4970) */
static const true_false_string tfs_ri_options_grc = {
    "OSPF Graceful Restart Capable",
    "NOT OSPF Graceful Restart Capable"
};
static const true_false_string tfs_ri_options_grh = {
    "OSPF Graceful Restart Helper",
    "NOT OSPF Graceful Restart Helper"
};
static const true_false_string tfs_ri_options_srs = {
    "OSPF Stub Router Support",
    "NOT OSPF Stub Router Support"
};
static const true_false_string tfs_ri_options_tes = {
    "OSPF Traffic Engineering Support",
    "NOT OSPF Traffic Engineering Support"
};
static const true_false_string tfs_ri_options_p2plan = {
    "OSPF point-to-point over LAN",
    "NOT OSPF point-to-point over LAN"
};
static const true_false_string tfs_ri_options_ete = {
    "OSPF Experimental TE",
    "NOT OSPF Experimental TE"
};

static const true_false_string tfs_v3_options_v6 = {
    "V6 is SET",
    "V6 is NOT set"
};
static const true_false_string tfs_v3_options_e = {
    "E is SET",
    "E is NOT set"
};
static const true_false_string tfs_v3_options_mc = {
    "MC is SET",
    "MC is NOT set"
};
static const true_false_string tfs_v3_options_n = {
    "N is SET",
    "N is NOT set"
};
static const true_false_string tfs_v3_options_r = {
    "R is SET",
    "R is NOT set"
};
static const true_false_string tfs_v3_options_dc = {
    "DC is SET",
    "DC is NOT set"
};
static const true_false_string tfs_v3_options_af = {
    "AF is SET",
    "AF is NOT set"
};
static const true_false_string tfs_v3_options_l = {
    "L is SET",
    "L is NOT set"
};
static const true_false_string tfs_v3_options_i = {
    "I is SET",
    "I is NOT set"
};
static const true_false_string tfs_v3_options_f = {
    "F is SET",
    "F is NOT set"
};
static const true_false_string tfs_dbd_i = {
    "Init bit is SET",
    "Init bit is NOT set"
};
static const true_false_string tfs_dbd_m = {
    "More bit is SET",
    "More bit is NOT set"
};
static const true_false_string tfs_dbd_ms = {
    "Master/Slave bit is SET",
    "Master/Slave bit is NOT set"
};
static const true_false_string tfs_dbd_r = {
    "OOBResync bit is SET",
    "OOBResync bit is NOT set"
};
static const true_false_string tfs_lls_ext_options_lr = {
    "LSDB Resynchronization (LR-bit) is SET",
    "LSDB Resynchronization (LR-bit) is NOT set"
};
static const true_false_string tfs_lls_ext_options_rs = {
    "Restart Signal (RS-bit) is SET",
    "Restart Signal (RS-bit) is NOT set"
};
static const true_false_string tfs_v3_lls_ext_options_lr = {
    "LSDB Resynchronization (LR-bit) is SET",
    "LSDB Resynchronization (LR-bit) is NOT set"
};
static const true_false_string tfs_v3_lls_ext_options_rs = {
    "Restart Signal (RS-bit) is SET",
    "Restart Signal (RS-bit) is NOT set"
};
static const true_false_string tfs_v3_lls_state_options_r = {
    "Request (R-bit) is SET",
    "Request (R-bit) is NOT set",
};
static const true_false_string tfs_v3_lls_state_options_a = {
    "Answer (A-bit) is SET",
    "Answer (A-bit) is NOT set",
};
static const true_false_string tfs_v3_lls_state_options_n = {
    "Incomplete (N-bit) is SET",
    "Incomplete (N-bit) is NOT set",
};
static const true_false_string tfs_v3_lls_relay_options_a = {
    "Always (A-bit) is SET",
    "Always (A-bit) is NOT set",
};
static const true_false_string tfs_v3_lls_relay_options_n = {
    "Never (N-bit) is SET",
    "Never (N-bit) is NOT set",
};
static const true_false_string tfs_v2_router_lsa_flags_b = {
    "Area border router",
    "NO Area border router"
};
static const true_false_string tfs_v2_router_lsa_flags_e = {
    "AS boundary router",
    "NO AS boundary router"
};
static const true_false_string tfs_v2_router_lsa_flags_v = {
    "Virtual link endpoint",
    "NO Virtual link endpoint"
};
static const true_false_string tfs_v2_router_lsa_flags_w = {
    "Wild-card multicast receiver",
    "NO Wild-card multicast receiver"
};
static const true_false_string tfs_v2_router_lsa_flags_n = {
    "N flag",
    "NO N flag"
};
static const true_false_string tfs_v3_router_lsa_flags_b = {
    "Area border router",
    "NO Area border router"
};
static const true_false_string tfs_v3_router_lsa_flags_e = {
    "AS boundary router",
    "NO AS boundary router"
};
static const true_false_string tfs_v3_router_lsa_flags_v = {
    "Virtual link endpoint",
    "NO Virtual link endpoint"
};
static const true_false_string tfs_v3_router_lsa_flags_w = {
    "Wild-card multicast receiver",
    "NO Wild-card multicast receiver"
};
static const true_false_string tfs_v3_as_external_flags_t = {
    "External Route Tag is included",
    "External Route Tag is NOT included"
};
static const true_false_string tfs_v3_as_external_flags_f = {
    "Forwarding Address is included",
    "Forwarding Address is NOT included"
};
static const true_false_string tfs_v3_as_external_flags_e = {
    "Type 2 external metric",
    "Type 1 external metric"
};
static const true_false_string tfs_v3_prefix_options_nu = {
    "NoUnicast capability bit is SET",
    "NoUnicast capability bit is NOT set"
};
static const true_false_string tfs_v3_prefix_options_la = {
    "LocalAddress capability bit is SET",
    "LocalAddress capability bit is NOT set"
};
static const true_false_string tfs_v3_prefix_options_mc = {
    "Multicast capability bit is SET",
    "Multicast capability bit is NOT set"
};
static const true_false_string tfs_v3_prefix_options_p = {
    "Propagate bit is SET",
    "Propagate bit is NOT set"
};

/*-----------------------------------------------------------------------
 * OSPF Filtering
 *-----------------------------------------------------------------------*/

/* The OSPF filtering keys */
enum {

    OSPFF_MSG_TYPE,

    OSPFF_MSG_MIN,
    OSPFF_MSG_HELLO,
    OSPFF_MSG_DB_DESC,
    OSPFF_MSG_LS_REQ,
    OSPFF_MSG_LS_UPD,
    OSPFF_MSG_LS_ACK,

    OSPFF_LS_TYPE,
    OSPFF_LS_OPAQUE_TYPE,

    OSPFF_LS_MPLS_TE_INSTANCE,

    OSPFF_LS_MIN,
    OSPFF_LS_ROUTER,
    OSPFF_LS_NETWORK,
    OSPFF_LS_SUMMARY,
    OSPFF_LS_ASBR,
    OSPFF_LS_ASEXT,
    OSPFF_LS_GRPMEMBER,
    OSPFF_LS_ASEXT7,
    OSPFF_LS_EXTATTR,
    OSPFF_LS_OPAQUE,

    OSPFF_SRC_ROUTER,
    OSPFF_ADV_ROUTER,
    OSPFF_LS_MPLS,
    OSPFF_LS_MPLS_ROUTERID,

    OSPFF_LS_MPLS_LINKTYPE,
    OSPFF_LS_MPLS_LINKID,
    OSPFF_LS_MPLS_LOCAL_ADDR,
    OSPFF_LS_MPLS_REMOTE_ADDR,
    OSPFF_LS_MPLS_LOCAL_IFID,
    OSPFF_LS_MPLS_REMOTE_IFID,
    OSPFF_LS_MPLS_LINKCOLOR,
    OSPFF_LS_MPLS_BC_MODEL_ID,
    OSPFF_LS_OIF_LOCAL_NODE_ID,
    OSPFF_LS_OIF_REMOTE_NODE_ID,

    OSPFF_V2_OPTIONS,
    OSPFF_V2_OPTIONS_MT,
    OSPFF_V2_OPTIONS_E,
    OSPFF_V2_OPTIONS_MC,
    OSPFF_V2_OPTIONS_NP,
    OSPFF_V2_OPTIONS_L,
    OSPFF_V2_OPTIONS_DC,
    OSPFF_V2_OPTIONS_O,
    OSPFF_V2_OPTIONS_DN,

    /* OSPF Filtering keys for Router Informational Capabilities Options field. */
    OSPFF_RI_OPTIONS,
    OSPFF_RI_OPTIONS_GRC,
    OSPFF_RI_OPTIONS_GRH,
    OSPFF_RI_OPTIONS_SRS,
    OSPFF_RI_OPTIONS_TES,
    OSPFF_RI_OPTIONS_P2PLAN,
    OSPFF_RI_OPTIONS_ETE,

    /* OSPF Filtering keys for Dynamic Hostname support (RFC5642) */
    OSPFF_DYN_HOSTNAME,
    OSPFF_OPAQUE_LSA_MBZ,

    OSPFF_UNKNOWN_TLV_TXT,

    OSPFF_V3_OPTIONS,
    OSPFF_V3_OPTIONS_V6,
    OSPFF_V3_OPTIONS_E,
    OSPFF_V3_OPTIONS_MC,
    OSPFF_V3_OPTIONS_N,
    OSPFF_V3_OPTIONS_R,
    OSPFF_V3_OPTIONS_DC,
    OSPFF_V3_OPTIONS_AF,
    OSPFF_V3_OPTIONS_L,
    OSPFF_V3_OPTIONS_I,
    OSPFF_V3_OPTIONS_F,
    OSPFF_DBD,
    OSPFF_DBD_R,
    OSPFF_DBD_I,
    OSPFF_DBD_M,
    OSPFF_DBD_MS,
    OSPFF_LLS_EXT_OPTIONS_TLV,
    OSPFF_LLS_EXT_OPTIONS,
    OSPFF_LLS_EXT_OPTIONS_LR,
    OSPFF_LLS_EXT_OPTIONS_RS,
    OSPFF_V3_LLS_EXT_OPTIONS_TLV,
    OSPFF_V3_LLS_EXT_OPTIONS,
    OSPFF_V3_LLS_EXT_OPTIONS_LR,
    OSPFF_V3_LLS_EXT_OPTIONS_RS,
    OSPFF_V3_LLS_STATE_TLV,
    OSPFF_V3_LLS_STATE_SCS,
    OSPFF_V3_LLS_STATE_OPTIONS,
    OSPFF_V3_LLS_STATE_OPTIONS_R,
    OSPFF_V3_LLS_STATE_OPTIONS_A,
    OSPFF_V3_LLS_STATE_OPTIONS_N,
    OSPFF_V3_LLS_DROP_TLV,
    OSPFF_V3_LLS_RELAY_TLV,
    OSPFF_V3_LLS_RELAY_ADDED,
    OSPFF_V3_LLS_RELAY_OPTIONS,
    OSPFF_V3_LLS_RELAY_OPTIONS_A,
    OSPFF_V3_LLS_RELAY_OPTIONS_N,
    OSPFF_V3_LLS_WILLINGNESS_TLV,
    OSPFF_V3_LLS_WILLINGNESS,
    OSPFF_V3_LLS_RF_TLV,
    OSPFF_V3_LLS_FSF_TLV,
    OSPFF_V2_ROUTER_LSA_FLAG,
    OSPFF_V2_ROUTER_LSA_FLAG_B,
    OSPFF_V2_ROUTER_LSA_FLAG_E,
    OSPFF_V2_ROUTER_LSA_FLAG_V,
    OSPFF_V2_ROUTER_LSA_FLAG_W,
    OSPFF_V2_ROUTER_LSA_FLAG_N,
    OSPFF_V3_ROUTER_LSA_FLAG,
    OSPFF_V3_ROUTER_LSA_FLAG_B,
    OSPFF_V3_ROUTER_LSA_FLAG_E,
    OSPFF_V3_ROUTER_LSA_FLAG_V,
    OSPFF_V3_ROUTER_LSA_FLAG_W,
    OSPFF_V3_AS_EXTERNAL_FLAG,
    OSPFF_V3_AS_EXTERNAL_FLAG_T,
    OSPFF_V3_AS_EXTERNAL_FLAG_F,
    OSPFF_V3_AS_EXTERNAL_FLAG_E,
    OSPFF_V3_PREFIX_OPTION,
    OSPFF_V3_PREFIX_OPTION_NU,
    OSPFF_V3_PREFIX_OPTION_LA,
    OSPFF_V3_PREFIX_OPTION_MC,
    OSPFF_V3_PREFIX_OPTION_P,

    OSPFF_V2_GRACE_TLV,
    OSPFF_V2_GRACE_PERIOD,
    OSPFF_V2_GRACE_REASON,
    OSPFF_V2_GRACE_IP,

    OSPFF_MAX
};

static int hf_ospf_filter[OSPFF_MAX];

static gint ospf_msg_type_to_filter (guint8 msg_type)
{
    if (msg_type >= OSPF_HELLO &&
        msg_type <= OSPF_LS_ACK)
        return msg_type + OSPFF_MSG_MIN;
    return -1;
}

static gint ospf_ls_type_to_filter (guint8 ls_type)
{
    if (ls_type >= OSPF_LSTYPE_ROUTER &&
        ls_type <= OSPF_LSTYPE_EXTATTR)
        return OSPFF_LS_MIN + ls_type;
    else if (ls_type >= OSPF_LSTYPE_OP_LINKLOCAL &&
             ls_type <= OSPF_LSTYPE_OP_ASWIDE)
        return OSPFF_LS_OPAQUE;
    else
        return -1;
}

typedef struct _bitfield_info {
    int         hfindex;
    gint        *ett;
    int         *idx;
    int         num;
} bitfield_info;

static int bf_dbd[] = {
    OSPFF_DBD_R,
    OSPFF_DBD_I,
    OSPFF_DBD_M,
    OSPFF_DBD_MS
};
static int bf_lls_ext_options[] = {
    OSPFF_LLS_EXT_OPTIONS_RS,
    OSPFF_LLS_EXT_OPTIONS_LR
};
static int bf_v3_lls_ext_options[] = {
    OSPFF_V3_LLS_EXT_OPTIONS_LR,
    OSPFF_V3_LLS_EXT_OPTIONS_RS
};

static int bf_v3_lls_state_options[] = {
    OSPFF_V3_LLS_STATE_OPTIONS_R,
    OSPFF_V3_LLS_STATE_OPTIONS_A,
    OSPFF_V3_LLS_STATE_OPTIONS_N
};
static int bf_v3_lls_relay_options[] = {
    OSPFF_V3_LLS_RELAY_OPTIONS_A,
    OSPFF_V3_LLS_RELAY_OPTIONS_N
};
static int bf_v2_router_lsa_flags[] = {
    OSPFF_V2_ROUTER_LSA_FLAG_V,
    OSPFF_V2_ROUTER_LSA_FLAG_E,
    OSPFF_V2_ROUTER_LSA_FLAG_B
};
static int bf_v2_router_lsa_mt_flags[] = {
    OSPFF_V2_ROUTER_LSA_FLAG_N,
    OSPFF_V2_ROUTER_LSA_FLAG_W,
    OSPFF_V2_ROUTER_LSA_FLAG_V,
    OSPFF_V2_ROUTER_LSA_FLAG_E,
    OSPFF_V2_ROUTER_LSA_FLAG_B
};
static int bf_v3_router_lsa_flags[] = {
    OSPFF_V3_ROUTER_LSA_FLAG_W,
    OSPFF_V3_ROUTER_LSA_FLAG_V,
    OSPFF_V3_ROUTER_LSA_FLAG_E,
    OSPFF_V3_ROUTER_LSA_FLAG_B
};
static int bf_v3_as_external_flags[] = {
    OSPFF_V3_AS_EXTERNAL_FLAG_E,
    OSPFF_V3_AS_EXTERNAL_FLAG_F,
    OSPFF_V3_AS_EXTERNAL_FLAG_T
};
static int bf_v2_options[] = {
    OSPFF_V2_OPTIONS_DN,
    OSPFF_V2_OPTIONS_O,
    OSPFF_V2_OPTIONS_DC,
    OSPFF_V2_OPTIONS_L,
    OSPFF_V2_OPTIONS_NP,
    OSPFF_V2_OPTIONS_MC,
    OSPFF_V2_OPTIONS_E,
    OSPFF_V2_OPTIONS_MT
};
/* Structures for handling the bitfield of the Options field of Optional Router Capabilites LSA (RFC4970). */
static int bf_ri_options[] = {
    OSPFF_RI_OPTIONS_GRC,
    OSPFF_RI_OPTIONS_GRH,
    OSPFF_RI_OPTIONS_SRS,
    OSPFF_RI_OPTIONS_TES,
    OSPFF_RI_OPTIONS_P2PLAN,
    OSPFF_RI_OPTIONS_ETE
};
static int bf_v3_options[] = {
    OSPFF_V3_OPTIONS_F,
    OSPFF_V3_OPTIONS_I,
    OSPFF_V3_OPTIONS_L,
    OSPFF_V3_OPTIONS_AF,
    OSPFF_V3_OPTIONS_DC,
    OSPFF_V3_OPTIONS_R,
    OSPFF_V3_OPTIONS_N,
    OSPFF_V3_OPTIONS_MC,
    OSPFF_V3_OPTIONS_E,
    OSPFF_V3_OPTIONS_V6
};
static int bf_v3_prefix_options[] = {
    OSPFF_V3_PREFIX_OPTION_P,
    OSPFF_V3_PREFIX_OPTION_MC,
    OSPFF_V3_PREFIX_OPTION_LA,
    OSPFF_V3_PREFIX_OPTION_NU
};

static bitfield_info bfinfo_dbd = {
    OSPFF_DBD, &ett_ospf_dbd,
    bf_dbd, array_length(bf_dbd)
};
static bitfield_info bfinfo_lls_ext_options = {
    OSPFF_LLS_EXT_OPTIONS, &ett_ospf_lls_ext_options,
    bf_lls_ext_options, array_length(bf_lls_ext_options)
};
static bitfield_info bfinfo_v3_lls_ext_options = {
    OSPFF_V3_LLS_EXT_OPTIONS, &ett_ospf_v3_lls_ext_options,
    bf_v3_lls_ext_options, array_length(bf_v3_lls_ext_options)
};
static bitfield_info bfinfo_v3_lls_state_options = {
    OSPFF_V3_LLS_STATE_OPTIONS, &ett_ospf_v3_lls_state_options,
    bf_v3_lls_state_options, array_length(bf_v3_lls_state_options)
};
static bitfield_info bfinfo_v3_lls_relay_options = {
    OSPFF_V3_LLS_RELAY_OPTIONS, &ett_ospf_v3_lls_relay_options,
    bf_v3_lls_relay_options, array_length(bf_v3_lls_relay_options)
};
static bitfield_info bfinfo_v2_router_lsa_flags = {
    OSPFF_V2_ROUTER_LSA_FLAG, &ett_ospf_v2_router_lsa_flags,
    bf_v2_router_lsa_flags, array_length(bf_v2_router_lsa_flags)
};
static bitfield_info bfinfo_v2_router_lsa_mt_flags = {
    OSPFF_V2_ROUTER_LSA_FLAG, &ett_ospf_v2_router_lsa_flags,
    bf_v2_router_lsa_mt_flags, array_length(bf_v2_router_lsa_mt_flags)
};
static bitfield_info bfinfo_v3_router_lsa_flags = {
    OSPFF_V3_ROUTER_LSA_FLAG, &ett_ospf_v3_router_lsa_flags,
    bf_v3_router_lsa_flags, array_length(bf_v3_router_lsa_flags)
};
static bitfield_info bfinfo_v3_as_external_flags = {
    OSPFF_V3_AS_EXTERNAL_FLAG, &ett_ospf_v3_as_external_flags,
    bf_v3_as_external_flags, array_length(bf_v3_as_external_flags)
};
static bitfield_info bfinfo_v2_options = {
    OSPFF_V2_OPTIONS, &ett_ospf_v2_options,
    bf_v2_options, array_length(bf_v2_options)
};
static bitfield_info bfinfo_v3_options = {
    OSPFF_V3_OPTIONS, &ett_ospf_v3_options,
    bf_v3_options, array_length(bf_v3_options)
};
static bitfield_info bfinfo_v3_prefix_options = {
    OSPFF_V3_PREFIX_OPTION, &ett_ospf_v3_prefix_options,
    bf_v3_prefix_options, array_length(bf_v3_prefix_options)
};
/* Structure used for dissecing the Options bitfield of the Optional Router Informational
   Capabilities RI LSA. */
static bitfield_info bfinfo_ri_options = {
    OSPFF_RI_OPTIONS, &ett_ospf_ri_options,
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

    hfindex = hf_ospf_filter[bfinfo->hfindex];
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

        str = ep_alloc(MAX_OPTIONS_LEN);
        str[0] = 0;
        for (i = 0, pos = 0; i < bfinfo->num; i++) {
            idx = hf_ospf_filter[bfinfo->idx[i]];
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

static dissector_handle_t data_handle;

static void dissect_ospf_hello(tvbuff_t*, int, proto_tree*, guint8, guint16);
static void dissect_ospf_db_desc(tvbuff_t*, int, proto_tree*, guint8, guint16, guint8);
static void dissect_ospf_ls_req(tvbuff_t*, int, proto_tree*, guint8, guint16);
static void dissect_ospf_ls_upd(tvbuff_t*, int, proto_tree*, guint8, guint16, guint8);
static void dissect_ospf_ls_ack(tvbuff_t*, int, proto_tree*, guint8, guint16, guint8);
static void dissect_ospf_lls_data_block(tvbuff_t*, int, proto_tree*, guint8);

/* dissect_ospf_v[23]lsa returns the offset of the next LSA
 * if disassemble_body is set to FALSE (e.g. in LSA ACK
 * packets), the offset is set to the offset of the next
 * LSA header
 */
static int dissect_ospf_v2_lsa(tvbuff_t*, int, proto_tree*, gboolean disassemble_body);
static int dissect_ospf_v3_lsa(tvbuff_t*, int, proto_tree*, gboolean disassemble_body,
                               guint8);

static void dissect_ospf_v3_address_prefix(tvbuff_t *, int, int, proto_tree *, guint8);

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

static void
dissect_ospf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *ospf_tree = NULL;
    proto_item *ti, *hidden_item;
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
    char auth_data[8+1];
    int crypto_len = 0;
    unsigned int ospf_header_length;
    guint8 instance_ID;
    guint8 reserved;
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

    if (tree) {
        ospflen = tvb_get_ntohs(tvb, 2);

        ti = proto_tree_add_item(tree, proto_ospf, tvb, 0, -1, ENC_NA);
        ospf_tree = proto_item_add_subtree(ti, ett_ospf);

        ti = proto_tree_add_text(ospf_tree, tvb, 0, ospf_header_length,
                                 "OSPF Header");
        ospf_header_tree = proto_item_add_subtree(ti, ett_ospf_hdr);

        proto_tree_add_text(ospf_header_tree, tvb, 0, 1, "OSPF Version: %u",
                            version);
        proto_tree_add_item(ospf_header_tree, hf_ospf_filter[OSPFF_MSG_TYPE],
                            tvb, 1, 1, ENC_BIG_ENDIAN);

        if (ospf_msg_type_to_filter(packet_type) != -1) {
            hidden_item = proto_tree_add_item(ospf_header_tree,
                                              hf_ospf_filter[ospf_msg_type_to_filter(packet_type)],
                                              tvb, 1, 1, FALSE);
            PROTO_ITEM_SET_HIDDEN(hidden_item);
        }
        proto_tree_add_text(ospf_header_tree, tvb, 2, 2, "Packet Length: %u",
                            ospflen);
        proto_tree_add_item(ospf_header_tree, hf_ospf_filter[OSPFF_SRC_ROUTER],
                            tvb, 4, 4, ENC_BIG_ENDIAN);

        areaid=tvb_get_ntohl(tvb,8);
        proto_tree_add_text(ospf_header_tree, tvb, 8, 4, "Area ID: %s%s",
                            tvb_ip_to_str(tvb, 8), areaid == 0 ? " (Backbone)" : "");

        /*
         * Quit at this point if it's an unknown OSPF version.
         */
        switch (version) {

        case OSPF_VERSION_2:
        case OSPF_VERSION_3:
            break;

        default:
            cksum = tvb_get_ntohs(tvb, 12);
            if (cksum == 0) {
                /* No checksum supplied in the packet. */
                proto_tree_add_text(ospf_header_tree, tvb, 12, 2,
                                    "Packet Checksum: 0x%04x (none)", cksum);
            } else {
                proto_tree_add_text(ospf_header_tree, tvb, 12, 2,
                                    "Packet Checksum: 0x%04x", cksum);
            }
            proto_tree_add_text(ospf_tree, tvb, 14, -1,
                                "Unknown OSPF version %u", version);
            return;
        }

        cksum = tvb_get_ntohs(tvb, 12);
        length = tvb_length(tvb);
        /* XXX - include only the length from the OSPF header? */
        reported_length = tvb_reported_length(tvb);
        if (cksum == 0) {
            /* No checksum supplied in the packet. */
            proto_tree_add_text(ospf_header_tree, tvb, 12, 2,
                                "Packet Checksum: 0x%04x (none)", cksum);
        } else if (!pinfo->fragmented && length >= reported_length
                   && length >= ospf_header_length) {
            /* The packet isn't part of a fragmented datagram and isn't
               truncated, so we can checksum it. */

            switch (version) {

            case OSPF_VERSION_2:
                /* Header, not including the authentication data (the OSPFv2
                   checksum excludes the 64-bit authentication field). */
                cksum_vec[0].ptr = tvb_get_ptr(tvb, 0, 16);
                cksum_vec[0].len = 16;
                if (length > ospf_header_length) {
                    /* Rest of the packet, again not including the
                       authentication data. */
                    reported_length -= ospf_header_length;
                    cksum_vec[1].ptr = tvb_get_ptr(tvb, ospf_header_length, reported_length);
                    cksum_vec[1].len = reported_length;
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
                cksum_vec[0].ptr = pinfo->src.data;
                cksum_vec[0].len = pinfo->src.len;
                cksum_vec[1].ptr = pinfo->dst.data;
                cksum_vec[1].len = pinfo->dst.len;
                cksum_vec[2].ptr = (const guint8 *)&phdr;
                phdr[0] = g_htonl(ospflen);
                phdr[1] = g_htonl(IP_PROTO_OSPF);
                cksum_vec[2].len = 8;

                cksum_vec[3].ptr = tvb_get_ptr(tvb, 0, reported_length);
                cksum_vec[3].len = reported_length;
                cksum_vec_len = 4;
                break;

            default:
                DISSECTOR_ASSERT_NOT_REACHED();
                cksum_vec_len = 0;
                break;
            }
            computed_cksum = in_cksum(cksum_vec, cksum_vec_len);
            if (computed_cksum == 0) {
                proto_tree_add_text(ospf_header_tree, tvb, 12, 2,
                                    "Packet Checksum: 0x%04x [correct]", cksum);
            } else {
                proto_tree_add_text(ospf_header_tree, tvb, 12, 2,
                                    "Packet Checksum: 0x%04x [incorrect, should be 0x%04x]",
                                    cksum, in_cksum_shouldbe(cksum, computed_cksum));
            }
        } else {
            proto_tree_add_text(ospf_header_tree, tvb, 12, 2,
                                "Packet Checksum: 0x%04x", cksum);
        }


        switch (version) {

        case OSPF_VERSION_2:
            /* Authentication is only valid for OSPFv2 */
            auth_type = tvb_get_ntohs(tvb, 14);
            proto_tree_add_text(ospf_header_tree, tvb, 14, 2, "Auth Type: %s",
                                val_to_str(auth_type, auth_vals, "Unknown (%u)"));
            switch (auth_type) {

            case OSPF_AUTH_NONE:
                proto_tree_add_text(ospf_header_tree, tvb, 16, 8, "Auth Data (none)");
                break;

            case OSPF_AUTH_SIMPLE:
                tvb_get_nstringz0(tvb, 16, 8+1, auth_data);
                proto_tree_add_text(ospf_header_tree, tvb, 16, 8, "Auth Data: %s", auth_data);
                break;

            case OSPF_AUTH_CRYPT:
                proto_tree_add_text(ospf_header_tree, tvb, 18, 1, "Auth Key ID: %u",
                                    tvb_get_guint8(tvb, 18));
                crypto_len = tvb_get_guint8(tvb, 19);
                proto_tree_add_text(ospf_header_tree, tvb, 19, 1, "Auth Data Length: %u",
                                    crypto_len);
                proto_tree_add_text(ospf_header_tree, tvb, 20, 4, "Auth Crypto Sequence Number: 0x%x",
                                    tvb_get_ntohl(tvb, 20));

                /* Show the message digest that was appended to the end of the
                   OSPF message - but only if it's present (we don't want
                   to get an exception before we've tried dissecting OSPF
                   message). */
                if (tvb_bytes_exist(tvb, ospflen, crypto_len)) {
                    proto_tree_add_text(ospf_header_tree, tvb, ospflen, crypto_len,
                                        "Auth Data: %s",
                                        tvb_bytes_to_str(tvb, ospflen, crypto_len));
                    proto_tree_set_appendix(ospf_header_tree, tvb, ospflen, crypto_len);
                }
                break;

            default:
                proto_tree_add_text(ospf_header_tree, tvb, 16, 8, "Auth Data (unknown)");
                break;
            }
            break;

        case OSPF_VERSION_3:
            /* Instance ID and "reserved" is OSPFv3-only */
            instance_ID = tvb_get_guint8(tvb, 14);
            ti = proto_tree_add_text(ospf_header_tree, tvb, 14, 1, "Instance ID: %u",
                                     instance_ID);

            if (instance_ID < 32) {
                proto_item_append_text(ti, " (IPv6 unicast AF)");
                address_family = OSPF_AF_6;
            } else if (instance_ID < 64) {
                proto_item_append_text(ti, " (IPv6 multicast AF)");
                address_family = OSPF_AF_6;
            } else if (instance_ID < 96) {
                proto_item_append_text(ti, " (IPv4 unicast AF)");
                address_family = OSPF_AF_4;
            } else if (instance_ID < 128) {
                proto_item_append_text(ti, " (IPv4 multicast AF)");
                address_family = OSPF_AF_4;
            } else {
                proto_item_append_text(ti, " (Reserved)");
                address_family = OSPF_AF_6;
            }

            reserved = tvb_get_guint8(tvb, 15);
            proto_tree_add_text(ospf_header_tree, tvb, 15, 1,
                                (reserved == 0 ? "Reserved: %u" : "Reserved: %u [incorrect, should be 0]"),
                                reserved);
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
            dissect_ospf_db_desc(tvb, (int)ospf_header_length, ospf_tree, version,
                                 (guint16)(ospflen - ospf_header_length),
                                 address_family);
            break;

        case OSPF_LS_REQ:
            dissect_ospf_ls_req(tvb, (int)ospf_header_length, ospf_tree, version,
                                (guint16)(ospflen - ospf_header_length));
            break;

        case OSPF_LS_UPD:
            dissect_ospf_ls_upd(tvb, (int)ospf_header_length, ospf_tree, version,
                                (guint16)(ospflen - ospf_header_length),
                                address_family);
            break;

        case OSPF_LS_ACK:
            dissect_ospf_ls_ack(tvb, (int)ospf_header_length, ospf_tree, version,
                                (guint16)(ospflen - ospf_header_length),
                                address_family);
            break;

        default:
            call_dissector(data_handle,
                           tvb_new_subset_remaining(tvb, ospf_header_length), pinfo, tree);
            break;
        }

        /* take care of the LLS data block */
        if (ospf_has_lls_block(tvb, ospf_header_length, packet_type, version)) {
            dissect_ospf_lls_data_block(tvb, ospflen + crypto_len, ospf_tree,
                                        version);
        }
    }
}

static int
dissect_ospfv2_lls_tlv(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *ospf_lls_tlv_tree;
    guint16 type;
    guint16 length;

    type = tvb_get_ntohs(tvb, offset);
    length = tvb_get_ntohs(tvb, offset + 2);

    ti = proto_tree_add_text(tree, tvb, offset, length + 4, "%s",
                             val_to_str(type, lls_tlv_type_vals, "Unknown TLV"));
    ospf_lls_tlv_tree = proto_item_add_subtree(ti, ett_ospf_lls_tlv);

    proto_tree_add_text(ospf_lls_tlv_tree, tvb, offset, 2,
                        "Type: %d", type);
    proto_tree_add_text(ospf_lls_tlv_tree, tvb, offset + 2, 2,
                        "Length: %d", length);

    switch(type) {
    case 1:
        dissect_ospf_bitfield(ospf_lls_tlv_tree, tvb, offset + 4, &bfinfo_lls_ext_options);
        break;
    case 2:
        proto_tree_add_text(ospf_lls_tlv_tree, tvb, offset + 4, 4,
                            "Sequence number 0x%08x",
                            tvb_get_ntohl(tvb, offset + 4));
        proto_tree_add_text(ospf_lls_tlv_tree, tvb, offset + 8, length - 4,
                            "Auth Data: %s",
                            tvb_bytes_to_str(tvb, offset + 8, length - 4));
        break;
    }

    return offset + length + 4;
}

static int
dissect_ospfv3_lls_tlv(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *ospf_lls_tlv_tree;
    guint16 type;
    guint16 length;
    guint8 relays_added;
    int orig_offset;

    type = tvb_get_ntohs(tvb, offset);
    length = tvb_get_ntohs(tvb, offset + 2);

    switch(type) {
    case LLS_V3_EXT_OPT:
        ti = proto_tree_add_item(tree, hf_ospf_filter[OSPFF_V3_LLS_EXT_OPTIONS_TLV], tvb,
                                 offset, length + 4, ENC_NA);
       break;
    case LLS_V3_STATE_CHECK:
        ti = proto_tree_add_item(tree, hf_ospf_filter[OSPFF_V3_LLS_STATE_TLV], tvb,
                                 offset, length + 4, ENC_NA);
        break;
    case LLS_V3_NBR_DROP:
        ti = proto_tree_add_item(tree, hf_ospf_filter[OSPFF_V3_LLS_DROP_TLV], tvb,
                                 offset, length + 4, ENC_NA);
        break;
    case LLS_V3_RELAYS:
        ti = proto_tree_add_item(tree, hf_ospf_filter[OSPFF_V3_LLS_RELAY_TLV], tvb,
                                 offset, length + 4, ENC_NA);
        break;
    case LLS_V3_WILLING:
        ti = proto_tree_add_item(tree, hf_ospf_filter[OSPFF_V3_LLS_WILLINGNESS_TLV], tvb,
                                 offset, length + 4, ENC_NA);
        break;
    case LLS_V3_RQST_FROM:
         ti = proto_tree_add_item(tree, hf_ospf_filter[OSPFF_V3_LLS_RF_TLV], tvb,
                                  offset, length + 4, ENC_NA);
         break;
    case LLS_V3_FULL_STATE:
        ti = proto_tree_add_item(tree, hf_ospf_filter[OSPFF_V3_LLS_FSF_TLV], tvb,
                                 offset, length + 4, ENC_NA);
        break;
    default:
        ti = proto_tree_add_text(tree, tvb, offset, length + 4, "%s",
                                 val_to_str(type, lls_v3_tlv_type_vals, "Unknown TLV"));
    }

    ospf_lls_tlv_tree = proto_item_add_subtree(ti, ett_ospf_lls_tlv);
    proto_tree_add_text(ospf_lls_tlv_tree, tvb, offset, 2,
                        "Type: %d", type);
    proto_tree_add_text(ospf_lls_tlv_tree, tvb, offset + 2, 2,
                        "Length: %d", length);

    orig_offset = offset;

    switch (type) {
    case LLS_V3_EXT_OPT:
        proto_tree_add_text(ospf_lls_tlv_tree, tvb, offset + 4, 4,
                            "Extended Options: 0x%08x",
                            tvb_get_ntohl(tvb, offset + 4));

        dissect_ospf_bitfield(ospf_lls_tlv_tree, tvb, offset + 4, &bfinfo_v3_lls_ext_options);
        break;
    case LLS_V3_STATE_CHECK:
        proto_tree_add_item(ospf_lls_tlv_tree, hf_ospf_filter[OSPFF_V3_LLS_STATE_SCS],
                            tvb, offset+4, 2, ENC_BIG_ENDIAN);

        dissect_ospf_bitfield(ospf_lls_tlv_tree, tvb, offset + 6,
                              &bfinfo_v3_lls_state_options);
        break;
    case LLS_V3_NBR_DROP:
        offset += 4;
        while (orig_offset + length >= offset) {
            proto_tree_add_text(ospf_lls_tlv_tree, tvb, offset, 4,
                                "Dropped Neighbor: %s",
                                tvb_ip_to_str(tvb, offset));
            offset += 4;
        }
        offset = orig_offset;
        break;
    case LLS_V3_RELAYS:
        relays_added = tvb_get_guint8(tvb, offset+4);
        proto_tree_add_item(ospf_lls_tlv_tree, hf_ospf_filter[OSPFF_V3_LLS_RELAY_ADDED],
                            tvb, offset+4, 1, ENC_BIG_ENDIAN);
        dissect_ospf_bitfield(ospf_lls_tlv_tree, tvb, offset + 5,
                              &bfinfo_v3_lls_relay_options);
        offset += 8;
        while (orig_offset + length >= offset) {
            ti = proto_tree_add_text(ospf_lls_tlv_tree, tvb, offset, 4,
                                "Neighbor: %s",
                                tvb_ip_to_str(tvb, offset));
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
        proto_tree_add_item(ospf_lls_tlv_tree, hf_ospf_filter[OSPFF_V3_LLS_WILLINGNESS],
                            tvb, offset+4, 1, ENC_BIG_ENDIAN);

        break;
    case LLS_V3_RQST_FROM:
        offset += 4;
        while (orig_offset + length >= offset) {
            proto_tree_add_text(ospf_lls_tlv_tree, tvb, offset, 4,
                                "Request From: %s",
                                tvb_ip_to_str(tvb, offset));
            offset += 4;
        }
        offset = orig_offset;
        break;
    case LLS_V3_FULL_STATE:
           offset += 4;
        while (orig_offset + length >= offset) {
            proto_tree_add_text(ospf_lls_tlv_tree, tvb, offset, 4,
                                "Full State For: %s",
                                tvb_ip_to_str(tvb, offset));
            offset += 4;
        }
        offset = orig_offset;
        break;
    }

    return offset + length + 4;
}


static void
dissect_ospf_lls_data_block(tvbuff_t *tvb, int offset, proto_tree *tree,
                            guint8 version)
{
    proto_tree *ospf_lls_data_block_tree;
    proto_item *ti;
    guint16 ospf_lls_len;
    int orig_offset = offset;

    ospf_lls_len = tvb_get_ntohs(tvb, offset + 2);
    ti = proto_tree_add_text(tree, tvb, offset, -1, "OSPF LLS Data Block");
    ospf_lls_data_block_tree = proto_item_add_subtree(ti,
                                                      ett_ospf_lls_data_block);

    /* TODO: verify checksum */
    proto_tree_add_text(ospf_lls_data_block_tree, tvb, offset, 2,
                        "Checksum: 0x%04x", tvb_get_ntohs(tvb, offset));
    proto_tree_add_text(ospf_lls_data_block_tree, tvb, offset + 2, 2,
                        "LLS Data Length: %d bytes", ospf_lls_len * 4);

    offset += 4;
    DISSECTOR_ASSERT((version == OSPF_VERSION_2) || (version == OSPF_VERSION_3));
    while (orig_offset + ospf_lls_len * 4 > offset) {
        if (version == OSPF_VERSION_2)
            offset = dissect_ospfv2_lls_tlv (tvb, offset, ospf_lls_data_block_tree);
        else
            offset = dissect_ospfv3_lls_tlv (tvb, offset, ospf_lls_data_block_tree);
    }
}

static void
dissect_ospf_hello(tvbuff_t *tvb, int offset, proto_tree *tree, guint8 version,
                   guint16 length)
{
    proto_tree *ospf_hello_tree;
    proto_item *ti;
    int orig_offset = offset;

    ti = proto_tree_add_text(tree, tvb, offset, length, "OSPF Hello Packet");
    ospf_hello_tree = proto_item_add_subtree(ti, ett_ospf_hello);

    switch (version ) {
    case OSPF_VERSION_2:
        proto_tree_add_text(ospf_hello_tree, tvb, offset, 4, "Network Mask: %s",
                            tvb_ip_to_str(tvb, offset));
        proto_tree_add_text(ospf_hello_tree, tvb, offset + 4, 2,
                            "Hello Interval: %u seconds",
                            tvb_get_ntohs(tvb, offset + 4));

        dissect_ospf_bitfield(ospf_hello_tree, tvb, offset + 6, &bfinfo_v2_options);
        proto_tree_add_text(ospf_hello_tree, tvb, offset + 7, 1, "Router Priority: %u",
                            tvb_get_guint8(tvb, offset + 7));
        proto_tree_add_text(ospf_hello_tree, tvb, offset + 8, 4, "Router Dead Interval: %u seconds",
                            tvb_get_ntohl(tvb, offset + 8));
        proto_tree_add_text(ospf_hello_tree, tvb, offset + 12, 4, "Designated Router: %s",
                            tvb_ip_to_str(tvb, offset + 12));
        proto_tree_add_text(ospf_hello_tree, tvb, offset + 16, 4, "Backup Designated Router: %s",
                            tvb_ip_to_str(tvb, offset + 16));

        offset += 20;
        while (orig_offset + length > offset) {
            proto_tree_add_text(ospf_hello_tree, tvb, offset, 4,
                                "Active Neighbor: %s",
                                tvb_ip_to_str(tvb, offset));
            offset += 4;
        }
        break;
    case OSPF_VERSION_3:
        proto_tree_add_text(ospf_hello_tree, tvb, offset + 0, 4, "Interface ID: %u",
                            tvb_get_ntohl(tvb, offset + 0));
        proto_tree_add_text(ospf_hello_tree, tvb, offset + 4, 1, "Router Priority: %u",
                            tvb_get_guint8(tvb, offset + 4));
        dissect_ospf_bitfield(ospf_hello_tree, tvb, offset + 5, &bfinfo_v3_options);
        proto_tree_add_text(ospf_hello_tree, tvb, offset + 8, 2,
                            "Hello Interval: %u seconds",
                            tvb_get_ntohs(tvb, offset + 8));
        proto_tree_add_text(ospf_hello_tree, tvb, offset + 10, 2, "Router Dead Interval: %u seconds",
                            tvb_get_ntohs(tvb, offset + 10));
        proto_tree_add_text(ospf_hello_tree, tvb, offset + 12, 4, "Designated Router: %s",
                            tvb_ip_to_str(tvb, offset + 12));
        proto_tree_add_text(ospf_hello_tree, tvb, offset + 16, 4, "Backup Designated Router: %s",
                            tvb_ip_to_str(tvb, offset + 16));
        offset += 20;
        while (orig_offset + length > offset) {
            proto_tree_add_text(ospf_hello_tree, tvb, offset, 4,
                                "Active Neighbor: %s",
                                tvb_ip_to_str(tvb, offset));
            offset += 4;
        }

        break;
    }
}

static void
dissect_ospf_db_desc(tvbuff_t *tvb, int offset, proto_tree *tree,
                     guint8 version, guint16 length, guint8 address_family)
{
    proto_tree *ospf_db_desc_tree=NULL;
    proto_item *ti;
    guint8 reserved;
    int orig_offset = offset;

    if (tree) {
        ti = proto_tree_add_text(tree, tvb, offset, length, "OSPF DB Description");
        ospf_db_desc_tree = proto_item_add_subtree(ti, ett_ospf_desc);

        switch (version ) {

        case OSPF_VERSION_2:
            proto_tree_add_text(ospf_db_desc_tree, tvb, offset, 2, "Interface MTU: %u",
                                tvb_get_ntohs(tvb, offset));

            dissect_ospf_bitfield(ospf_db_desc_tree, tvb, offset + 2, &bfinfo_v2_options);
            dissect_ospf_bitfield(ospf_db_desc_tree, tvb, offset + 3, &bfinfo_dbd);

            proto_tree_add_text(ospf_db_desc_tree, tvb, offset + 4, 4, "DD Sequence: %u",
                                tvb_get_ntohl(tvb, offset + 4));

            offset += 8;
            break;

        case OSPF_VERSION_3:

            reserved = tvb_get_guint8(tvb, offset);
            proto_tree_add_text(ospf_db_desc_tree, tvb, offset, 1,
                                (reserved == 0 ? "Reserved: %u" : "Reserved: %u [incorrect, should be 0]"),
                                reserved);

            dissect_ospf_bitfield(ospf_db_desc_tree, tvb, offset + 1, &bfinfo_v3_options);

            proto_tree_add_text(ospf_db_desc_tree, tvb, offset + 4, 2, "Interface MTU: %u",
                                tvb_get_ntohs(tvb, offset+4));

            reserved = tvb_get_guint8(tvb, offset + 6);
            proto_tree_add_text(ospf_db_desc_tree, tvb, offset + 6, 1,
                                (reserved == 0 ? "Reserved: %u" : "Reserved: %u [incorrect, should be 0]"),
                                reserved);

            dissect_ospf_bitfield(ospf_db_desc_tree, tvb, offset + 7, &bfinfo_dbd);

            proto_tree_add_text(ospf_db_desc_tree, tvb, offset + 8, 4, "DD Sequence: %u",
                                tvb_get_ntohl(tvb, offset + 8));

            offset += 12;
            break;
        }
    }

    /* LS Headers will be processed here */
    /* skip to the end of DB-Desc header */
    DISSECTOR_ASSERT((version == OSPF_VERSION_2) || (version == OSPF_VERSION_3));
    while (orig_offset + length > offset) {
        if ( version == OSPF_VERSION_2)
            offset = dissect_ospf_v2_lsa(tvb, offset, tree, FALSE);
        else
            offset = dissect_ospf_v3_lsa(tvb, offset, tree, FALSE, address_family);
    }

}

static void
dissect_ospf_ls_req(tvbuff_t *tvb, int offset, proto_tree *tree, guint8 version,
                    guint16 length)
{
    proto_tree *ospf_lsr_tree;
    proto_item *ti;
    guint32 ls_type;
    guint16 reserved;
    int orig_offset = offset;

    /* zero or more LS requests may be within a LS Request */
    /* we place every request for a LSA in a single subtree */
    while (orig_offset + length > offset) {
        ti = proto_tree_add_text(tree, tvb, offset, OSPF_LS_REQ_LENGTH,
                                 "Link State Request");
        ospf_lsr_tree = proto_item_add_subtree(ti, ett_ospf_lsr);

        switch ( version ) {

        case OSPF_VERSION_2:
            proto_tree_add_item(ospf_lsr_tree, hf_ospf_filter[OSPFF_LS_TYPE],
                                tvb, offset, 4, ENC_BIG_ENDIAN);
            break;
        case OSPF_VERSION_3:
            reserved = tvb_get_ntohs(tvb, offset);
            proto_tree_add_text(ospf_lsr_tree, tvb, offset, 2,
                                (reserved == 0 ? "Reserved: %u" :  "Reserved: %u [incorrect, should be 0]"), reserved);
            ls_type = tvb_get_ntohs(tvb, offset+2);
            proto_tree_add_text(ospf_lsr_tree, tvb, offset+2, 2, "LS Type: %s (0x%04x)",
                                val_to_str(ls_type, v3_ls_type_vals, "Unknown"),
                                ls_type);
            break;
        }


        proto_tree_add_text(ospf_lsr_tree, tvb, offset + 4, 4, "Link State ID: %s",
                            tvb_ip_to_str(tvb, offset + 4));
        proto_tree_add_item(ospf_lsr_tree, hf_ospf_filter[OSPFF_ADV_ROUTER],
                            tvb, offset + 8, 4, ENC_BIG_ENDIAN);

        offset += 12;
    }
}

static void
dissect_ospf_ls_upd(tvbuff_t *tvb, int offset, proto_tree *tree, guint8 version,
                    guint16 length, guint8 address_family)
{
    proto_tree *ospf_lsa_upd_tree=NULL;
    proto_item *ti;
    guint32 lsa_nr;
    guint32 lsa_counter;

    ti = proto_tree_add_text(tree, tvb, offset, length, "LS Update Packet");
    ospf_lsa_upd_tree = proto_item_add_subtree(ti, ett_ospf_lsa_upd);

    lsa_nr = tvb_get_ntohl(tvb, offset);
    proto_tree_add_text(ospf_lsa_upd_tree, tvb, offset, 4, "Number of LSAs: %u", lsa_nr);
    /* skip to the beginning of the first LSA */
    offset += 4; /* the LS Upd Packet contains only a 32 bit #LSAs field */

    DISSECTOR_ASSERT((version == OSPF_VERSION_2) || (version == OSPF_VERSION_3));
    lsa_counter = 0;
    while (lsa_counter < lsa_nr) {
        if (version == OSPF_VERSION_2)
            offset = dissect_ospf_v2_lsa(tvb, offset, ospf_lsa_upd_tree, TRUE);
        else
            offset = dissect_ospf_v3_lsa(tvb, offset, ospf_lsa_upd_tree, TRUE,
                                         address_family);
        lsa_counter += 1;
    }
}

static void
dissect_ospf_ls_ack(tvbuff_t *tvb, int offset, proto_tree *tree, guint8 version,
                    guint16 length, guint8 address_family)
{
    int orig_offset = offset;
    DISSECTOR_ASSERT((version == OSPF_VERSION_2) || (version == OSPF_VERSION_3));
    /* the body of a LS Ack packet simply contains zero or more LSA Headers */
    while (orig_offset + length > offset) {
        if (version == OSPF_VERSION_2)
            offset = dissect_ospf_v2_lsa(tvb, offset, tree, FALSE);
        else
            offset = dissect_ospf_v3_lsa(tvb, offset, tree, FALSE, address_family);
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

static const value_string oif_stlv_str[] = {
    {OIF_TNA_IPv4_ADDRESS, "TNA address"},
    {OIF_NODE_ID, "Node ID"},
    {OIF_TNA_IPv6_ADDRESS, "TNA address"},
    {OIF_TNA_NSAP_ADDRESS, "TNA address"},
    {0, NULL},
};

/*
 * Dissect MPLS/TE opaque LSA
 */
static void
dissect_ospf_lsa_mpls(tvbuff_t *tvb, int offset, proto_tree *tree,
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

    const guint8 allzero[] = { 0x00, 0x00, 0x00 };
    guint num_bcs = 0;

    ti = proto_tree_add_text(tree, tvb, offset, length,
                             "MPLS Traffic Engineering LSA");
    hidden_item = proto_tree_add_item(tree, hf_ospf_filter[OSPFF_LS_MPLS],
                                      tvb, offset, 2, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
    mpls_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls);

    while (length != 0) {
        tlv_type = tvb_get_ntohs(tvb, offset);
        tlv_length = tvb_get_ntohs(tvb, offset + 2);
        tlv_end_offset = offset + tlv_length + 4;

        switch (tlv_type) {

        case MPLS_TLV_ROUTER:
            ti = proto_tree_add_text(mpls_tree, tvb, offset, tlv_length+4,
                                     "Router Address: %s",
                                     tvb_ip_to_str(tvb, offset+4));
            tlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_router);
            proto_tree_add_text(tlv_tree, tvb, offset, 2, "TLV Type: 1 - Router Address");
            proto_tree_add_text(tlv_tree, tvb, offset+2, 2, "TLV Length: %u",
                                tlv_length);
            proto_tree_add_item(tlv_tree, hf_ospf_filter[OSPFF_LS_MPLS_ROUTERID],
                                tvb, offset+4, 4, ENC_BIG_ENDIAN);
            break;

        case MPLS_TLV_LINK:
            ti = proto_tree_add_text(mpls_tree, tvb, offset, tlv_length+4,
                                     "Link Information");
            tlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link);
            proto_tree_add_text(tlv_tree, tvb, offset, 2, "TLV Type: 2 - Link Information");
            proto_tree_add_text(tlv_tree, tvb, offset+2, 2, "TLV Length: %u",
                                tlv_length);
            stlv_offset = offset + 4;

            /* Walk down the sub-TLVs for link information */
            while (stlv_offset < tlv_end_offset) {
                stlv_type = tvb_get_ntohs(tvb, stlv_offset);
                stlv_len = tvb_get_ntohs(tvb, stlv_offset + 2);
                stlv_name = val_to_str(stlv_type, mpls_link_stlv_str, "Unknown sub-TLV");
                switch (stlv_type) {

                case MPLS_LINK_TYPE:
                    ti = proto_tree_add_text(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             "%s: %u - %s", stlv_name,
                                             tvb_get_guint8(tvb, stlv_offset + 4),
                                             val_to_str(tvb_get_guint8(tvb, stlv_offset + 4),
                                                        mpls_link_stlv_ltype_str, "Unknown Link Type"));
                    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link_stlv);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset, 2,
                                        "TLV Type: %u: %s", stlv_type, stlv_name);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+2, 2, "TLV Length: %u",
                                        stlv_len);
                    proto_tree_add_item(stlv_tree, hf_ospf_filter[OSPFF_LS_MPLS_LINKTYPE],
                                        tvb, stlv_offset+4, 1,ENC_BIG_ENDIAN);
                    break;

                case MPLS_LINK_ID:
                    ti = proto_tree_add_text(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             "%s: %s", stlv_name,
                                             tvb_ip_to_str(tvb, stlv_offset + 4));
                    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link_stlv);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset, 2,
                                        "TLV Type: %u: %s", stlv_type, stlv_name);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+2, 2, "TLV Length: %u",
                                        stlv_len);
                    proto_tree_add_item(stlv_tree, hf_ospf_filter[OSPFF_LS_MPLS_LINKID],
                                        tvb, stlv_offset+4, 4, ENC_BIG_ENDIAN);
                    break;

                case MPLS_LINK_LOCAL_IF:
                case MPLS_LINK_REMOTE_IF:
                    ti = proto_tree_add_text(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             "%s", stlv_name);
                    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link_stlv);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset, 2,
                                        "TLV Type: %u: %s", stlv_type, stlv_name);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+2, 2, "TLV Length: %u",
                                        stlv_len);
                    /*   The Local/Remote Interface IP Address sub-TLV is TLV type 3/4, and is 4N
                         octets in length, where N is the number of neighbor addresses. */
                    for (i=0; i < stlv_len; i+=4)
                        proto_tree_add_item(stlv_tree,
                                            stlv_type==MPLS_LINK_LOCAL_IF ?
                                            hf_ospf_filter[OSPFF_LS_MPLS_LOCAL_ADDR] :
                                            hf_ospf_filter[OSPFF_LS_MPLS_REMOTE_ADDR],
                                            tvb, stlv_offset+4+i, 4, ENC_BIG_ENDIAN);
                    break;

                case MPLS_LINK_TE_METRIC:
                    ti = proto_tree_add_text(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             "%s: %u", stlv_name,
                                             tvb_get_ntohl(tvb, stlv_offset + 4));
                    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link_stlv);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset, 2,
                                        "TLV Type: %u: %s", stlv_type, stlv_name);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+2, 2, "TLV Length: %u",
                                        stlv_len);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+4, 4, "%s: %u", stlv_name,
                                        tvb_get_ntohl(tvb, stlv_offset + 4));
                    break;

                case MPLS_LINK_COLOR:
                    ti = proto_tree_add_text(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             "%s: 0x%08x", stlv_name,
                                             tvb_get_ntohl(tvb, stlv_offset + 4));
                    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link_stlv);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset, 2,
                                        "TLV Type: %u: %s", stlv_type, stlv_name);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+2, 2, "TLV Length: %u",
                                        stlv_len);
                    stlv_admingrp = tvb_get_ntohl(tvb, stlv_offset + 4);
                    mask = 1;
                    ti = proto_tree_add_item(stlv_tree, hf_ospf_filter[OSPFF_LS_MPLS_LINKCOLOR],
                                             tvb, stlv_offset+4, 4, ENC_BIG_ENDIAN);
                    stlv_admingrp_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link_stlv_admingrp);
                    if (stlv_admingrp_tree == NULL)
                        return;
                    for (i = 0 ; i < 32 ; i++) {
                        if ((stlv_admingrp & mask) != 0) {
                            proto_tree_add_text(stlv_admingrp_tree, tvb, stlv_offset+4,
                                                4, "Group %d", i);
                        }
                        mask <<= 1;
                    }
                    break;

                case MPLS_LINK_MAX_BW:
                case MPLS_LINK_MAX_RES_BW:
                    ti = proto_tree_add_text(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             "%s: %.10g bytes/s (%.0f bits/s)", stlv_name,
                                             tvb_get_ntohieee_float(tvb, stlv_offset + 4),
                                             tvb_get_ntohieee_float(tvb, stlv_offset + 4) * 8.0);
                    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link_stlv);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset, 2,
                                        "TLV Type: %u: %s", stlv_type, stlv_name);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+2, 2, "TLV Length: %u",
                                        stlv_len);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+4, 4, "%s: %.10g bytes/s (%.0f bits/s)", stlv_name,
                                        tvb_get_ntohieee_float(tvb, stlv_offset + 4),
                                        tvb_get_ntohieee_float(tvb, stlv_offset + 4) * 8.0);
                    break;

                case MPLS_LINK_UNRES_BW:
                    ti = proto_tree_add_text(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             "%s", stlv_name);
                    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link_stlv);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset, 2,
                                        "TLV Type: %u: %s", stlv_type, stlv_name);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+2, 2, "TLV Length: %u",
                                        stlv_len);
                    for (i = 0; i < 8; i++) {
                        proto_tree_add_text(stlv_tree, tvb, stlv_offset+4+(i*4), 4,
                                            "Pri (or TE-Class) %d: %.10g bytes/s (%.0f bits/s)", i,
                                            tvb_get_ntohieee_float(tvb, stlv_offset + 4 + i*4),
                                            tvb_get_ntohieee_float(tvb, stlv_offset + 4 + i*4) * 8.0);
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

                    ti = proto_tree_add_text(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             "%s", stlv_name);

                    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link_stlv);

                    proto_tree_add_text(stlv_tree, tvb, stlv_offset, 2,
                                        "TLV Type: %u: %s", stlv_type, stlv_name);

                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+2, 2, "TLV Length: %u",
                                        stlv_len);

                    proto_tree_add_item(stlv_tree, hf_ospf_filter[OSPFF_LS_MPLS_BC_MODEL_ID],
                                        tvb, stlv_offset+4, 1, ENC_BIG_ENDIAN);

                    /* 3 octets reserved +5, +6 and +7 (all 0x00) */
                    if(tvb_memeql(tvb, stlv_offset+5, allzero, 3) == -1) {
                        proto_tree_add_text(stlv_tree, tvb, stlv_offset+5, 3,
                                            "Warning: these bytes are reserved and must be 0x00");
                    }

                    if(((stlv_len % 4)!=0)) {
                        proto_tree_add_text(stlv_tree, tvb, stlv_offset+4, stlv_len,
                                            "Malformed Packet: Length must be N x 4 octets");
                        break;
                    }

                    /* stlv_len shound range from 4 to 36 bytes */
                    num_bcs = (stlv_len - 4)/4;

                    if(num_bcs>8) {
                        proto_tree_add_text(stlv_tree, tvb, stlv_offset+4, stlv_len,
                                            "Malformed Packet: too many BC (%u)", num_bcs);
                        break;
                    }

                    if(num_bcs==0) {
                        proto_tree_add_text(stlv_tree, tvb, stlv_offset+4, stlv_len,
                                            "Malformed Packet: Bandwidth Constraints sub-TLV with no BC?");
                        break;
                    }

                    for(i = 0; i < (int) num_bcs; i++) {
                        proto_tree_add_text(stlv_tree, tvb, stlv_offset+8+(i*4), 4,
                                            "BC %d: %.10g bytes/s (%.0f bits/s)", i,
                                            tvb_get_ntohieee_float(tvb, stlv_offset + 8 + i*4),
                                            tvb_get_ntohieee_float(tvb, stlv_offset + 8 + i*4) * 8.0);
                    }
                    break;

                case MPLS_LINK_LOCAL_REMOTE_ID:
                    ti = proto_tree_add_text(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             "%s: %d (0x%x) - %d (0x%x)", stlv_name,
                                             tvb_get_ntohl(tvb, stlv_offset + 4),
                                             tvb_get_ntohl(tvb, stlv_offset + 4),
                                             tvb_get_ntohl(tvb, stlv_offset + 8),
                                             tvb_get_ntohl(tvb, stlv_offset + 8));
                    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link_stlv);

                    proto_tree_add_text(stlv_tree, tvb, stlv_offset, 2,
                                        "TLV Type: %u: %s", stlv_type, stlv_name);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+2, 2, "TLV Length: %u",
                                        stlv_len);
                    proto_tree_add_item(stlv_tree,
                                        hf_ospf_filter[OSPFF_LS_MPLS_LOCAL_IFID],
                                        tvb, stlv_offset+4, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(stlv_tree,
                                        hf_ospf_filter[OSPFF_LS_MPLS_REMOTE_IFID],
                                        tvb, stlv_offset+8, 4, ENC_BIG_ENDIAN);
                    break;

                case MPLS_LINK_IF_SWITCHING_DESC:
                    ti = proto_tree_add_text(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             "%s", stlv_name);
                    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link_stlv);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset, 2,
                                        "TLV Type: %u: %s", stlv_type, stlv_name);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+2, 2, "TLV Length: %u",
                                        stlv_len);
                    switch_cap = tvb_get_guint8 (tvb, stlv_offset+4);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+4, 1, "Switching Type: %s",
                                        rval_to_str(tvb_get_guint8(tvb,stlv_offset+4),
                                                    gmpls_switching_type_rvals, "Unknown (%d)"));
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+5, 1, "Encoding: %s",
                                        rval_to_str(tvb_get_guint8(tvb,stlv_offset+5),
                                                    gmpls_lsp_enc_rvals, "Unknown (%d)"));
                    for (i = 0; i < 8; i++) {
                        proto_tree_add_text(stlv_tree, tvb, stlv_offset+8+(i*4), 4,
                                            "Pri %d: %.10g bytes/s (%.0f bits/s)", i,
                                            tvb_get_ntohieee_float(tvb, stlv_offset + 8 + i*4),
                                            tvb_get_ntohieee_float(tvb, stlv_offset + 8 + i*4) * 8.0);
                    }
                    if (switch_cap >=1 && switch_cap <=4) {           /* PSC-1 .. PSC-4 */
                        proto_tree_add_text(stlv_tree, tvb, stlv_offset+40, 4,
                                            "Minimum LSP bandwidth: %.10g bytes/s (%.0f bits/s)",
                                            tvb_get_ntohieee_float(tvb, stlv_offset + 40),
                                            tvb_get_ntohieee_float(tvb, stlv_offset + 40) * 8.0);
                        proto_tree_add_text(stlv_tree, tvb, stlv_offset+44, 2,
                                            "Interface MTU: %d", tvb_get_ntohs(tvb, stlv_offset+44));
                    }

                    if (switch_cap == 100) {                         /* TDM */
                        proto_tree_add_text(stlv_tree, tvb, stlv_offset+40, 4,
                                            "Minimum LSP bandwidth: %.10g bytes/s (%.0f bits/s)",
                                            tvb_get_ntohieee_float(tvb, stlv_offset + 40),
                                            tvb_get_ntohieee_float(tvb, stlv_offset + 40) * 8.0);
                        proto_tree_add_text(stlv_tree, tvb, stlv_offset+44, 2,
                                            "SONET/SDH: %s",
                                            tvb_get_guint8(tvb, stlv_offset+44) ?
                                            "Arbitrary" : "Standard");
                    }
                    break;
                case MPLS_LINK_PROTECTION:
                    ti = proto_tree_add_text(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             "%s", stlv_name);
                    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link_stlv);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset, 2,
                                        "TLV Type: %u: %s", stlv_type, stlv_name);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+2, 2, "TLV Length: %u",
                                        stlv_len);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+4, 1, "Protection Capability: %s (0x%x)",
                                        val_to_str(tvb_get_guint8(tvb,stlv_offset+4),
                                                   gmpls_protection_cap_str,
                                                   "Unknown (%d)"),
                                        tvb_get_guint8(tvb,stlv_offset+4));
                    break;

                case MPLS_LINK_SHARED_RISK_GROUP:
                    ti = proto_tree_add_text(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             "%s", stlv_name);
                    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link_stlv);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset, 2,
                                        "TLV Type: %u: %s", stlv_type, stlv_name);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+2, 2, "TLV Length: %u",
                                        stlv_len);
                    for (i=0; i < stlv_len; i+=4)
                        proto_tree_add_text(stlv_tree, tvb, stlv_offset+4+i, 4, "Shared Risk Link Group: %u",
                                            tvb_get_ntohl(tvb,stlv_offset+4+i));
                    break;

                case OIF_LOCAL_NODE_ID:
                    ti = proto_tree_add_text(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             "%s: %s", stlv_name,
                                             tvb_ip_to_str(tvb, stlv_offset + 4));
                    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link_stlv);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset, 2,
                                        "TLV Type: %u: %s", stlv_type, stlv_name);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+2, 2, "TLV Length: %u",
                                        stlv_len);
                    proto_tree_add_item(stlv_tree,
                                        hf_ospf_filter[OSPFF_LS_OIF_LOCAL_NODE_ID],
                                        tvb, stlv_offset + 4, 4, ENC_BIG_ENDIAN);
                    break;

                case OIF_REMOTE_NODE_ID:
                    ti = proto_tree_add_text(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             "%s: %s", stlv_name,
                                             tvb_ip_to_str(tvb, stlv_offset + 4));
                    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link_stlv);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset, 2,
                                        "TLV Type: %u: %s", stlv_type, stlv_name);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+2, 2, "TLV Length: %u",
                                        stlv_len);
                    proto_tree_add_item(stlv_tree,
                                        hf_ospf_filter[OSPFF_LS_OIF_REMOTE_NODE_ID],
                                        tvb, stlv_offset + 4, 4, ENC_BIG_ENDIAN);
                    break;

                case OIF_SONET_SDH_SWITCHING_CAPABILITY:
                    ti = proto_tree_add_text(tlv_tree, tvb, stlv_offset, stlv_len+4, "%s", stlv_name);
                    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link_stlv);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset, 2,
                                        "TLV Type: %u: %s", stlv_type, stlv_name);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+2, 2, "TLV Length: %u",
                                        stlv_len);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+4, 1, "Switching Cap: %s",
                                        rval_to_str(tvb_get_guint8 (tvb, stlv_offset+4),
                                                    gmpls_switching_type_rvals, "Unknown (%d)"));
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+5, 1, "Encoding: %s",
                                        rval_to_str(tvb_get_guint8(tvb,stlv_offset+5),
                                                    gmpls_lsp_enc_rvals, "Unknown (%d)"));
                    for (i = 0; i < (stlv_len - 4) / 4; i++) {
                        proto_tree_add_text(stlv_tree, tvb, stlv_offset+8+(i*4), 4,
                                            "%s: %d free timeslots",
                                            val_to_str(tvb_get_guint8(tvb, stlv_offset+8+(i*4)),
                                                       gmpls_sonet_signal_type_str,
                                                       "Unknown Signal Type (%d)"),
                                            tvb_get_ntoh24(tvb, stlv_offset + 9 + i*4));
                    }

                    break;
                default:
                    ti = proto_tree_add_text(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             "Unknown Link sub-TLV: %u", stlv_type);
                    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link_stlv);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset, 2,
                                        "TLV Type: %u: %s", stlv_type, stlv_name);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+2, 2, "TLV Length: %u",
                                        stlv_len);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+4, stlv_len,
                                        "TLV Value");
                    break;
                }
                stlv_offset += ((stlv_len+4+3)/4)*4;
            }
            break;

        case OIF_TLV_TNA:
            ti = proto_tree_add_text(mpls_tree, tvb, offset, tlv_length+4,
                                     "TNA Information");
            tlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_oif_tna);
            proto_tree_add_text(tlv_tree, tvb, offset, 2, "TLV Type: 32768 - TNA Information");
            proto_tree_add_text(tlv_tree, tvb, offset+2, 2, "TLV Length: %u",
                                tlv_length);
            stlv_offset = offset + 4;

            /* Walk down the sub-TLVs for TNA information */
            while (stlv_offset < tlv_end_offset) {
                stlv_type = tvb_get_ntohs(tvb, stlv_offset);
                stlv_len = tvb_get_ntohs(tvb, stlv_offset + 2);
                stlv_name = val_to_str(stlv_type, oif_stlv_str, "Unknown sub-TLV");
                switch (stlv_type) {

                case OIF_NODE_ID:
                    ti = proto_tree_add_text(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             "%s: %s", stlv_name,
                                             tvb_ip_to_str(tvb, stlv_offset + 4));
                    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_oif_tna_stlv);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset, 2,
                                        "TLV Type: %u: %s", stlv_type, stlv_name);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+2, 2, "TLV Length: %u",
                                        stlv_len);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+4, 4, "%s: %s", stlv_name,
                                        tvb_ip_to_str(tvb, stlv_offset + 4));
                    break;

                case OIF_TNA_IPv4_ADDRESS:
                    ti = proto_tree_add_text(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             "%s (IPv4): %s", stlv_name,
                                             tvb_ip_to_str(tvb, stlv_offset + 8));
                    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_oif_tna_stlv);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset, 2,
                                        "TLV Type: %u: %s (IPv4)", stlv_type, stlv_name);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+2, 2, "TLV Length: %u", stlv_len);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+4, 1, "Addr Length: %u",
                                        tvb_get_guint8 (tvb, stlv_offset+4));
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+8, stlv_len - 4, "TNA Addr: %s",
                                        tvb_ip_to_str(tvb, stlv_offset + 8));
                    break;

                case OIF_TNA_IPv6_ADDRESS:
                    ti = proto_tree_add_text(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             "%s (IPv6): %s", stlv_name,
                                             tvb_ip6_to_str(tvb, stlv_offset + 8));
                    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_oif_tna_stlv);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset, 2,
                                        "TLV Type: %u: %s (IPv6)", stlv_type, stlv_name);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+2, 2, "TLV Length: %u", stlv_len);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+4, 1, "Addr Length: %u",
                                        tvb_get_guint8 (tvb, stlv_offset+4));
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+8, stlv_len - 4, "TNA Addr: %s",
                                        tvb_ip6_to_str(tvb, stlv_offset + 8));
                    break;

                case OIF_TNA_NSAP_ADDRESS:
                    ti = proto_tree_add_text(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                             "%s (NSAP): %s", stlv_name,
                                             tvb_bytes_to_str (tvb, stlv_offset + 8, stlv_len - 4));
                    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_oif_tna_stlv);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset, 2,
                                        "TLV Type: %u: %s (NSAP)", stlv_type, stlv_name);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+2, 2, "TLV Length: %u", stlv_len);
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+4, 1, "Addr Length: %u",
                                        tvb_get_guint8 (tvb, stlv_offset+4));
                    proto_tree_add_text(stlv_tree, tvb, stlv_offset+8, stlv_len - 4, "TNA Addr: %s",
                                        tvb_bytes_to_str(tvb, stlv_offset+8, stlv_len - 4));
                    break;

                default:
                    proto_tree_add_text(tlv_tree, tvb, stlv_offset, stlv_len+4,
                                        "Unknown Link sub-TLV: %u", stlv_type);
                    break;
                }
                stlv_offset += ((stlv_len+4+3)/4)*4;
            }
            break;
        default:
            ti = proto_tree_add_text(mpls_tree, tvb, offset, tlv_length+4,
                                     "Unknown LSA: %u", tlv_type);
            tlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link);
            proto_tree_add_text(tlv_tree, tvb, offset, 2, "TLV Type: %u - Unknown",
                                tlv_type);
            proto_tree_add_text(tlv_tree, tvb, offset+2, 2, "TLV Length: %u",
                                tlv_length);
            proto_tree_add_text(tlv_tree, tvb, offset+4, tlv_length, "TLV Data");
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
    guint32 restart_ip;
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

        tree_item = proto_tree_add_item(tree, hf_ospf_filter[OSPFF_V2_GRACE_TLV], tvb, offset,
                                        tlv_length_with_pad, ENC_NA);
        tlv_tree = proto_item_add_subtree(tree_item, ett_ospf_lsa_grace_tlv);
        proto_tree_add_text(tlv_tree, tvb, offset, 2, "Type: %s (%u)",
                            val_to_str(tlv_type, grace_tlv_type_vals, "Unknown grace-LSA TLV"), tlv_type);
        proto_tree_add_text(tlv_tree, tvb, offset + 2, 2, "Length: %u", tlv_length);

        switch (tlv_type) {
        case GRACE_TLV_PERIOD:
            grace_period = tvb_get_ntohl(tvb, offset + 4);
            grace_tree_item = proto_tree_add_item(tlv_tree, hf_ospf_filter[OSPFF_V2_GRACE_PERIOD], tvb,
                                                  offset + 4, tlv_length, ENC_BIG_ENDIAN);
            proto_item_append_text(grace_tree_item, " seconds");
            proto_item_set_text(tree_item, "Grace Period: %u seconds", grace_period);
            break;
        case GRACE_TLV_REASON:
            restart_reason = tvb_get_guint8(tvb, offset + 4);
            proto_tree_add_item(tlv_tree, hf_ospf_filter[OSPFF_V2_GRACE_REASON], tvb, offset + 4,
                                tlv_length, ENC_BIG_ENDIAN);
            proto_item_set_text(tree_item, "Restart Reason: %s (%u)",
                                val_to_str(restart_reason, restart_reason_vals, "Unknown Restart Reason"),
                                restart_reason);
            break;
        case GRACE_TLV_IP:
            restart_ip = tvb_get_ipv4(tvb, offset + 4);
            proto_tree_add_item(tlv_tree, hf_ospf_filter[OSPFF_V2_GRACE_IP], tvb, offset + 4,
                                tlv_length, ENC_BIG_ENDIAN);
            proto_item_set_text(tree_item, "Restart IP: %s (%s)",
                                get_hostname(restart_ip), ip_to_str((guint8 *)&restart_ip));
            break;
        default:
            proto_item_set_text(tree_item, "Unknown grace-LSA TLV");
            break;
        }
        if (4 + tlv_length < tlv_length_with_pad) {
            proto_tree_add_text(tlv_tree, tvb, offset + 4 + tlv_length,
                                tlv_length_with_pad - (4 + tlv_length), "Pad Bytes (%u)",
                                tlv_length_with_pad - (4 + tlv_length) );
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
    proto_item *ti;
    proto_tree *ri_tree;
    proto_tree *tlv_tree;

    guint8 *hostname_str;
    guint8 *unknown_str;

    int tlv_type;
    int tlv_length;
    int tlv_end_offset;

    ti = proto_tree_add_text(tree, tvb, offset, length,
                             "Opaque Router Information LSA");

    ri_tree = proto_item_add_subtree(ti, ett_ospf_lsa_opaque_ri);

    while (length > 0) {
        tlv_type = tvb_get_ntohs(tvb, offset);
        tlv_length = tvb_get_ntohs(tvb, offset + 2);
        tlv_end_offset = offset + tlv_length + 4;

        switch(tlv_type) {

        case OPT_RI_TLV:
           ti = proto_tree_add_text(ri_tree, tvb, offset, tlv_length+4, 
                                    "RI TLV");
           tlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_ri_tlv);

           proto_tree_add_text(tlv_tree, tvb, offset, 2, "TLV Type: %s (%u)",
                        "Router Informational Capabilities TLV", tlv_type);

           proto_tree_add_text(tlv_tree, tvb, offset + 2, 2, "TLV Length: %u", tlv_length);

           dissect_ospf_bitfield(tlv_tree, tvb, offset + 4, &bfinfo_ri_options); 
           break;

        case DYN_HOSTNAME_TLV:
           ti = proto_tree_add_text(ri_tree, tvb, offset, tlv_length+4,
                                    "Dynamic Hostname TLV");
           tlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_dyn_hostname_tlv);

           proto_tree_add_text(tlv_tree, tvb, offset, 2, "TLV Type: %s (%u)",
                               "Dynamic Hostname TLV", tlv_type);

           proto_tree_add_text(tlv_tree, tvb, offset + 2, 2, "TLV Length: %u", tlv_length);

           hostname_str = tvb_get_string(tvb, offset+4, tlv_length);
           proto_tree_add_string(tlv_tree, hf_ospf_filter[OSPFF_DYN_HOSTNAME], tvb, offset+4, tlv_length, hostname_str);
           g_free(hostname_str);
           break;

        default:
           ti = proto_tree_add_text(ri_tree, tvb, offset, tlv_length+4, 
                                    "Unknown Opaque RI LSA TLV");
           tlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_unknown_tlv);

           proto_tree_add_text(tlv_tree, tvb, offset, 2, "TLV Type: %s (%u)",
                               "Unknown TLV", tlv_type);

           proto_tree_add_text(tlv_tree, tvb, offset + 2, 2, "TLV Length: %u", tlv_length);

           unknown_str = tvb_get_string(tvb, offset+4, tlv_length);
           proto_tree_add_string(tlv_tree, hf_ospf_filter[OSPFF_UNKNOWN_TLV_TXT], tvb, offset+4, tlv_length, unknown_str);
           g_free(unknown_str);
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
dissect_ospf_lsa_opaque(tvbuff_t *tvb, int offset, proto_tree *tree,
                        guint8 ls_id_type, guint32 length)
{
    switch (ls_id_type) {

    case OSPF_LSA_MPLS_TE:
        dissect_ospf_lsa_mpls(tvb, offset, tree, length);
        break;
    case OSPF_LSA_OPAQUE_RI:
        dissect_ospf_lsa_opaque_ri(tvb, offset, tree, length);
        break;
    case OSPF_LSA_GRACE:
        dissect_ospf_lsa_grace_tlv(tvb, offset, tree, length);
        break;

    default:
        proto_tree_add_text(tree, tvb, offset, length,
                            "Unknown LSA Type %u", ls_id_type);
        break;
    } /* switch on opaque LSA id */
}

static int
dissect_ospf_v2_lsa(tvbuff_t *tvb, int offset, proto_tree *tree,
                    gboolean disassemble_body)
{
    proto_tree *ospf_lsa_tree;
    proto_item *ti, *hidden_item;

    guint8               ls_type;
    guint16              ls_length;
    int                  end_offset;
    guint16              nr_links;
    guint16              nr_metric;

    /* router LSA */
    guint8               link_type;
    guint16              link_counter;
    guint16              metric_counter;
    const char          *link_type_str;
    const char          *link_type_short_str;
    const char          *link_id;
    const char          *metric_type_str;

    /* AS-external LSA */
    guint8               options;

    /* opaque LSA */
    guint8               ls_id_type;
    guint8               ls_ri_opaque_field;

    ls_type = tvb_get_guint8(tvb, offset + 3);
    ls_length = tvb_get_ntohs(tvb, offset + 18);
    end_offset = offset + ls_length;

    if (disassemble_body) {
        ti = proto_tree_add_text(tree, tvb, offset, ls_length,
                                 "LS Type: %s",
                                 val_to_str(ls_type, ls_type_vals, "Unknown (%d)"));
    } else {
        ti = proto_tree_add_text(tree, tvb, offset, OSPF_LSA_HEADER_LENGTH,
                                 "LSA Header");
    }
    ospf_lsa_tree = proto_item_add_subtree(ti, ett_ospf_lsa);

    proto_tree_add_text(ospf_lsa_tree, tvb, offset, 2, "LS Age: %u seconds",
                        tvb_get_ntohs(tvb, offset) & ~OSPF_DNA_LSA);
    proto_tree_add_text(ospf_lsa_tree, tvb, offset, 2, "Do Not Age: %s",
                        (tvb_get_ntohs(tvb, offset) & OSPF_DNA_LSA) ? "True" : "False");
    options = tvb_get_guint8 (tvb, offset + 2);
    dissect_ospf_bitfield(ospf_lsa_tree, tvb, offset + 2, &bfinfo_v2_options);
    proto_tree_add_item(ospf_lsa_tree, hf_ospf_filter[OSPFF_LS_TYPE], tvb,
                        offset + 3, 1, ENC_BIG_ENDIAN);
    if (ospf_ls_type_to_filter(ls_type) != -1) {
        hidden_item = proto_tree_add_item(ospf_lsa_tree,
                                          hf_ospf_filter[ospf_ls_type_to_filter(ls_type)], tvb,
                                          offset + 3, 1, FALSE);
        PROTO_ITEM_SET_HIDDEN(hidden_item);
    }

    if (options & OSPF_V2_OPTIONS_MT) {
        metric_type_str = "MT-ID";
    } else {
        metric_type_str = "TOS";
    }

    if (is_opaque(ls_type)) {
        ls_id_type = tvb_get_guint8(tvb, offset + 4);
        proto_tree_add_uint(ospf_lsa_tree, hf_ospf_filter[OSPFF_LS_OPAQUE_TYPE],
                            tvb, offset + 4, 1, ls_id_type);

        switch (ls_id_type) {

        case OSPF_LSA_MPLS_TE:
            proto_tree_add_text(ospf_lsa_tree, tvb, offset + 5, 1, "Link State ID TE-LSA Reserved: %u",
                                tvb_get_guint8(tvb, offset + 5));
            proto_tree_add_item(ospf_lsa_tree, hf_ospf_filter[OSPFF_LS_MPLS_TE_INSTANCE],
                                tvb, offset + 6, 2, ENC_BIG_ENDIAN);
            break;

        case OSPF_LSA_OPAQUE_RI:
           ls_ri_opaque_field = tvb_get_guint8(tvb, offset + 5);	
           if ( ls_ri_opaque_field != 0 ) 
                ls_id_type = OSPF_LSA_UNKNOWN;
           else
                proto_tree_add_item(ospf_lsa_tree, hf_ospf_filter[OSPFF_OPAQUE_LSA_MBZ], 
                                    tvb, offset + 5, 3, ENC_BIG_ENDIAN);
           break;

        default:
            proto_tree_add_text(ospf_lsa_tree, tvb, offset + 5, 3, "Link State ID Opaque ID: %u",
                                tvb_get_ntoh24(tvb, offset + 5));
            break;
        }
    } else {
        ls_id_type = 0;
        proto_tree_add_text(ospf_lsa_tree, tvb, offset + 4, 4, "Link State ID: %s",
                            tvb_ip_to_str(tvb, offset + 4));
    }

    proto_tree_add_item(ospf_lsa_tree, hf_ospf_filter[OSPFF_ADV_ROUTER],
                        tvb, offset + 8, 4, ENC_BIG_ENDIAN);
    proto_tree_add_text(ospf_lsa_tree, tvb, offset + 12, 4, "LS Sequence Number: 0x%08x",
                        tvb_get_ntohl(tvb, offset + 12));
    proto_tree_add_text(ospf_lsa_tree, tvb, offset + 16, 2, "LS Checksum: 0x%04x",
                        tvb_get_ntohs(tvb, offset + 16));

    proto_tree_add_text(ospf_lsa_tree, tvb, offset + 18, 2, "Length: %u",
                        ls_length);

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
        proto_tree_add_text(ospf_lsa_tree, tvb, offset + 2, 2, "Number of Links: %u",
                            nr_links);
        offset += 4;
        /* nr_links links follow
         * maybe we should put each of the links into its own subtree ???
         */
        for (link_counter = 1; link_counter <= nr_links; link_counter++) {
            proto_tree *ospf_lsa_router_link_tree;
            proto_item *ti_local;


            /* check the Link Type and ID */
            link_type = tvb_get_guint8(tvb, offset + 8);
            switch (link_type) {

            case OSPF_LINK_PTP:
                link_type_str="Point-to-point connection to another router";
                link_type_short_str="PTP";
                link_id="Neighboring router's Router ID";
                break;

            case OSPF_LINK_TRANSIT:
                link_type_str="Connection to a transit network";
                link_type_short_str="Transit";
                link_id="IP address of Designated Router";
                break;

            case OSPF_LINK_STUB:
                link_type_str="Connection to a stub network";
                link_type_short_str="Stub";
                link_id="IP network/subnet number";
                break;

            case OSPF_LINK_VIRTUAL:
                link_type_str="Virtual link";
                link_type_short_str="Virtual";
                link_id="Neighboring router's Router ID";
                break;

            default:
                link_type_str="Unknown link type";
                link_type_short_str="Unknown";
                link_id="Unknown link ID";
                break;
            }

            nr_metric = tvb_get_guint8(tvb, offset + 9);


            ti_local = proto_tree_add_text(ospf_lsa_tree, tvb, offset, 12 + 4 * nr_metric,
                                           "Type: %-8s ID: %-15s Data: %-15s Metric: %d",
                                           link_type_short_str,
                                           tvb_ip_to_str(tvb, offset),
                                           tvb_ip_to_str(tvb, offset + 4),
                                           tvb_get_ntohs(tvb, offset + 10));

            ospf_lsa_router_link_tree = proto_item_add_subtree(ti_local, ett_ospf_lsa_router_link);

            proto_tree_add_text(ospf_lsa_router_link_tree, tvb, offset, 4, "%s: %s", link_id,
                                tvb_ip_to_str(tvb, offset));

            /* link_data should be specified in detail (e.g. network mask) (depends on link type)*/
            proto_tree_add_text(ospf_lsa_router_link_tree, tvb, offset + 4, 4, "Link Data: %s",
                                tvb_ip_to_str(tvb, offset + 4));

            proto_tree_add_text(ospf_lsa_router_link_tree, tvb, offset + 8, 1, "Link Type: %u - %s",
                                link_type, link_type_str);
            proto_tree_add_text(ospf_lsa_router_link_tree, tvb, offset + 9, 1, "Number of %s metrics: %u",
                                metric_type_str, nr_metric);
            proto_tree_add_text(ospf_lsa_router_link_tree, tvb, offset + 10, 2, "%s 0 metric: %u",
                                metric_type_str, tvb_get_ntohs(tvb, offset + 10));

            offset += 12;

            /* nr_metric metrics may follow each link
             * According to RFC4915 the TOS metrics was never deployed and was subsequently deprecated,
             * but decoding still present because MT-ID use the same structure.
             */
            for (metric_counter = 1; metric_counter <= nr_metric; metric_counter++) {
                proto_tree_add_text(ospf_lsa_router_link_tree, tvb, offset, 4, "%s: %u, Metric: %u",
                                    metric_type_str,
                                    tvb_get_guint8(tvb, offset),
                                    tvb_get_ntohs(tvb, offset + 2));
                offset += 4;
            }
        }
        break;

    case OSPF_LSTYPE_NETWORK:
        proto_tree_add_text(ospf_lsa_tree, tvb, offset, 4, "Netmask: %s",
                            tvb_ip_to_str(tvb, offset));
        offset += 4;

        while (offset < end_offset) {
            proto_tree_add_text(ospf_lsa_tree, tvb, offset, 4, "Attached Router: %s",
                                tvb_ip_to_str(tvb, offset));
            offset += 4;
        }
        break;

    case OSPF_LSTYPE_SUMMERY:
        /* Type 3 and 4 LSAs have the same format */
    case OSPF_LSTYPE_ASBR:
        proto_tree_add_text(ospf_lsa_tree, tvb, offset, 4, "Netmask: %s",
                            tvb_ip_to_str(tvb, offset));
        offset += 4;

        proto_tree_add_text(ospf_lsa_tree, tvb, offset, 4, "Metric: %u",
                            tvb_get_ntoh24(tvb, offset + 1));
        offset += 4;

        /* Metric specific information, if any */
        while (offset < end_offset) {
            proto_tree_add_text(ospf_lsa_tree, tvb, offset, 4, "%s: %u, Metric: %u",
                                metric_type_str,
                                tvb_get_guint8(tvb, offset),
                                tvb_get_ntoh24(tvb, offset + 1));
            offset += 4;
        }
        break;

    case OSPF_LSTYPE_ASEXT:
    case OSPF_LSTYPE_ASEXT7:
        proto_tree_add_text(ospf_lsa_tree, tvb, offset, 4, "Netmask: %s",
                            tvb_ip_to_str(tvb, offset));
        offset += 4;

        options = tvb_get_guint8(tvb, offset);
        if (options & 0x80) { /* check whether or not E bit is set */
            proto_tree_add_text(ospf_lsa_tree, tvb, offset, 1,
                                "External Type: Type 2 (metric is larger than any other link state path)");
        } else {
            proto_tree_add_text(ospf_lsa_tree, tvb, offset, 1,
                                "External Type: Type 1 (metric is specified in the same units as interface cost)");
        }
        /* the metric field of a AS-external LAS is specified in 3 bytes */
        proto_tree_add_text(ospf_lsa_tree, tvb, offset + 1, 3, "Metric: %u",
                            tvb_get_ntoh24(tvb, offset + 1));
        offset += 4;

        proto_tree_add_text(ospf_lsa_tree, tvb, offset, 4, "Forwarding Address: %s",
                            tvb_ip_to_str(tvb, offset));
        offset += 4;

        proto_tree_add_text(ospf_lsa_tree, tvb, offset, 4, "External Route Tag: %u",
                            tvb_get_ntohl(tvb, offset));
        offset += 4;

        /* Metric specific information, if any */
        while (offset < end_offset) {
            options = tvb_get_guint8(tvb, offset);
            if (options & 0x80) { /* check whether or not E bit is set */
                proto_tree_add_text(ospf_lsa_tree, tvb, offset, 1,
                                    "External Type: Type 2 (metric is larger than any other link state path)");
            } else {
                proto_tree_add_text(ospf_lsa_tree, tvb, offset, 1,
                                    "External Type: Type 1 (metric is specified in the same units as interface cost)");
            }
            proto_tree_add_text(ospf_lsa_tree, tvb, offset, 4, "%s: %u, Metric: %u",
                                metric_type_str, options & 0x7F,
                                tvb_get_ntoh24(tvb, offset + 1));
            offset += 4;

            proto_tree_add_text(ospf_lsa_tree, tvb, offset, 4, "Forwarding Address: %s",
                                tvb_ip_to_str(tvb, offset));
            offset += 4;

            proto_tree_add_text(ospf_lsa_tree, tvb, offset, 4, "External Route Tag: %u",
                                tvb_get_ntohl(tvb, offset));
            offset += 4;
        }
        break;

    case OSPF_LSTYPE_OP_LINKLOCAL:
    case OSPF_LSTYPE_OP_AREALOCAL:
    case OSPF_LSTYPE_OP_ASWIDE:
        /*
         * RFC 2370 opaque LSAs.
         */
        dissect_ospf_lsa_opaque(tvb, offset, ospf_lsa_tree, ls_id_type,
                                ls_length);
        offset += ls_length;
        break;

    default:
        /* unknown LSA type */
        proto_tree_add_text(ospf_lsa_tree, tvb, offset, ls_length,
                            "Unknown LSA Type");
        offset += ls_length;
        break;
    }
    /* return the offset of the next LSA */
    return offset;
}

static int
dissect_ospf_v3_lsa(tvbuff_t *tvb, int offset, proto_tree *tree,
                    gboolean disassemble_body, guint8 address_family)
{
    proto_tree *ospf_lsa_tree;
    proto_item *ti;

    guint16              ls_type;
    guint16              ls_length;
    int                  end_offset;
    guint8               reserved;

    /* router LSA */
    guint8               link_type;
    const char          *link_type_str;
    guint32              metric;

    guint8               router_priority;
    guint32              number_prefixes;
    guint8               prefix_length;
    guint16              reserved16;

    guint16              referenced_ls_type;

    guint8               flags;
    guint32              external_route_tag;


    ls_type = tvb_get_ntohs(tvb, offset + 2);
    ls_length = tvb_get_ntohs(tvb, offset + 18);
    end_offset = offset + ls_length;

    if (disassemble_body) {
        ti = proto_tree_add_text(tree, tvb, offset, ls_length,
                                 "%s (Type: 0x%04x)", val_to_str(ls_type, v3_ls_type_vals,"Unknown"), ls_type);
    } else {
        ti = proto_tree_add_text(tree, tvb, offset, OSPF_LSA_HEADER_LENGTH,
                                 "LSA Header");
    }
    ospf_lsa_tree = proto_item_add_subtree(ti, ett_ospf_lsa);

    proto_tree_add_text(ospf_lsa_tree, tvb, offset, 2, "LS Age: %u seconds",
                        tvb_get_ntohs(tvb, offset) & ~OSPF_DNA_LSA);
    proto_tree_add_text(ospf_lsa_tree, tvb, offset, 2, "Do Not Age: %s",
                        (tvb_get_ntohs(tvb, offset) & OSPF_DNA_LSA) ? "True" : "False");

    proto_tree_add_text(ospf_lsa_tree, tvb, offset + 2, 2, "LSA Type: 0x%04x (%s)",
                        ls_type, val_to_str(ls_type, v3_ls_type_vals,"Unknown"));

    proto_tree_add_text(ospf_lsa_tree, tvb, offset + 4, 4, "Link State ID: %s",
                        tvb_ip_to_str(tvb, offset + 4));

    proto_tree_add_item(ospf_lsa_tree, hf_ospf_filter[OSPFF_ADV_ROUTER],
                        tvb, offset + 8, 4, ENC_BIG_ENDIAN);
    proto_tree_add_text(ospf_lsa_tree, tvb, offset + 12, 4, "LS Sequence Number: 0x%08x",
                        tvb_get_ntohl(tvb, offset + 12));
    proto_tree_add_text(ospf_lsa_tree, tvb, offset + 16, 2, "LS Checksum: 0x%04x",
                        tvb_get_ntohs(tvb, offset + 16));

    proto_tree_add_text(ospf_lsa_tree, tvb, offset + 18, 2, "Length: %u",
                        ls_length);

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
            proto_tree_add_text(ospf_lsa_tree, tvb, offset, ls_length,
                                "Router Interfaces:");

        /* scan all router-lsa router interfaces */
        /* maybe we should put each of the links into its own subtree ??? */
        while (ls_length > 0 ) {

            /* check the type */
            link_type = tvb_get_guint8(tvb, offset);
            switch (link_type) {

            case OSPF_V3_LINK_PTP:
                link_type_str="Point-to-point connection to another router";
                break;

            case OSPF_V3_LINK_TRANSIT:
                link_type_str="Connection to a transit network";
                break;

            case OSPF_V3_LINK_RESERVED:
                link_type_str="Connection to a stub network";
                break;

            case OSPF_V3_LINK_VIRTUAL:
                link_type_str="Virtual link";
                break;

            default:
                link_type_str="Unknown link type";
                break;
            }

            proto_tree_add_text(ospf_lsa_tree, tvb, offset, 1, "Type: %u (%s)", link_type,link_type_str);

            /* reserved field */
            reserved = tvb_get_guint8(tvb, offset+1);
            proto_tree_add_text(ospf_lsa_tree, tvb, offset+1, 1,
                                (reserved == 0 ? "Reserved: %u" : "Reserved: %u [incorrect, should be 0]"),reserved);

            /* metric */
            metric=tvb_get_ntohs(tvb, offset+2);
            proto_tree_add_text(ospf_lsa_tree, tvb, offset + 2, 2,"Metric: %u",metric);

            /* Interface ID */
            proto_tree_add_text(ospf_lsa_tree, tvb, offset + 4, 4, "Interface ID: %u",
                                tvb_get_ntohl(tvb, offset + 4));

            /* Neighbor Interface ID */
            proto_tree_add_text(ospf_lsa_tree, tvb, offset + 8, 4, "Neighbor Interface ID: %u",
                                tvb_get_ntohl(tvb, offset + 8));

            /* Neighbor Router ID */
            proto_tree_add_text(ospf_lsa_tree, tvb, offset + 12, 4, "Neighbor Router ID: %s",
                                tvb_ip_to_str(tvb, offset + 12));

            /* skip to the (possible) next entry */
            offset+=16;
            ls_length-=16;

        }
        break;

    case OSPF_V3_LSTYPE_NETWORK:

        /* reserved field */
        reserved = tvb_get_guint8(tvb, offset);
        proto_tree_add_text(ospf_lsa_tree, tvb, offset, 1,
                            (reserved == 0 ? "Reserved: %u" : "Reserved: %u [incorrect, should be 0]"),reserved);

        /* options field in an network-lsa */
        dissect_ospf_bitfield(ospf_lsa_tree, tvb, offset + 1, &bfinfo_v3_options);

        offset += 4;
        ls_length-=4;

        while (ls_length > 0 ) {
            proto_tree_add_text(ospf_lsa_tree, tvb, offset, 4, "Attached Router: %s",
                                tvb_ip_to_str(tvb, offset));
            ls_length-=4;
            offset += 4;
        }
        break;


    case OSPF_V3_LSTYPE_INTER_AREA_PREFIX:

        /* reserved field */
        reserved = tvb_get_guint8(tvb, offset);
        proto_tree_add_text(ospf_lsa_tree, tvb, offset, 1,
                            (reserved == 0 ? "Reserved: %u" : "Reserved: %u [incorrect, should be 0]"),reserved);

        /* metric */
        metric=tvb_get_ntoh24(tvb, offset+1);
        proto_tree_add_text(ospf_lsa_tree, tvb, offset + 1, 3,"Metric: %u",metric);

        /* prefix length */
        prefix_length=tvb_get_guint8(tvb, offset+4);
        proto_tree_add_text(ospf_lsa_tree, tvb, offset+4, 1, "PrefixLength: %u",prefix_length);

        /* prefix options */
        dissect_ospf_bitfield(ospf_lsa_tree, tvb, offset+5, &bfinfo_v3_prefix_options);

        /* 16 bits reserved */
        reserved16=tvb_get_ntohs(tvb, offset+6);
        proto_tree_add_text(ospf_lsa_tree, tvb, offset+6, 2,
                            (reserved16 == 0 ? "Reserved: %u" : "Reserved: %u [incorrect, should be 0]"),reserved16);

        offset+=8;

        /* address_prefix */
        dissect_ospf_v3_address_prefix(tvb, offset, prefix_length, ospf_lsa_tree, address_family);

        offset+=(prefix_length+31)/32*4;

        break;


    case OSPF_V3_LSTYPE_INTER_AREA_ROUTER:

        /* reserved field */
        reserved = tvb_get_guint8(tvb, offset);
        proto_tree_add_text(ospf_lsa_tree, tvb, offset, 1,
                            (reserved == 0 ? "Reserved: %u" : "Reserved: %u [incorrect, should be 0]"),reserved);

        /* options field in an inter-area-router-lsa */
        dissect_ospf_bitfield(ospf_lsa_tree, tvb, offset + 1, &bfinfo_v3_options);

        /* reserved field */
        reserved = tvb_get_guint8(tvb, offset+4);
        proto_tree_add_text(ospf_lsa_tree, tvb, offset+4, 1,
                            (reserved == 0 ? "Reserved: %u" : "Reserved: %u [incorrect, should be 0]"),reserved);

        /* metric */
        metric=tvb_get_ntoh24(tvb, offset+5);
        proto_tree_add_text(ospf_lsa_tree, tvb, offset + 5, 3,"Metric: %u",metric);

        /* Destination Router ID */
        proto_tree_add_text(ospf_lsa_tree, tvb, offset + 8, 4, "Destination Router ID: %s",
                            tvb_ip_to_str(tvb, offset + 8));

        offset+=12;
        break;


    case OSPF_V3_LSTYPE_TYPE_7:
    case OSPF_V3_LSTYPE_AS_EXTERNAL:

        /* flags */
        dissect_ospf_bitfield(ospf_lsa_tree, tvb, offset, &bfinfo_v3_as_external_flags);
        flags=tvb_get_guint8(tvb, offset);

        /* 24 bits metric */
        metric=tvb_get_ntoh24(tvb, offset+1);
        proto_tree_add_text(ospf_lsa_tree, tvb, offset+1, 3,
                            "Metric: %u", metric);

        /* prefix length */
        prefix_length=tvb_get_guint8(tvb, offset+4);
        proto_tree_add_text(ospf_lsa_tree, tvb, offset+4, 1, "PrefixLength: %u",prefix_length);

        /* prefix options */
        dissect_ospf_bitfield(ospf_lsa_tree, tvb, offset+5, &bfinfo_v3_prefix_options);

        /* referenced LS type */
        referenced_ls_type=tvb_get_ntohs(tvb, offset+6);
        proto_tree_add_text(ospf_lsa_tree, tvb, offset+6, 2,"Referenced LS type 0x%04x (%s)",
                            referenced_ls_type, val_to_str(referenced_ls_type, v3_ls_type_vals, "Unknown"));

        offset+=8;

        /* address_prefix */
        dissect_ospf_v3_address_prefix(tvb, offset, prefix_length, ospf_lsa_tree, address_family);

        offset+=(prefix_length+31)/32*4;

        /* Forwarding Address (optional - only if F-flag is on) */
        if ( (offset < end_offset) && (flags & OSPF_V3_AS_EXTERNAL_FLAG_F) ) {
            if (address_family == OSPF_AF_6) {
                proto_tree_add_text(ospf_lsa_tree, tvb, offset, 16,"Forwarding Address: %s",
                                    tvb_ip6_to_str(tvb, offset));
            } else {
                proto_tree_add_text(ospf_lsa_tree, tvb, offset, 16,"Forwarding Address: %s",
                                    tvb_ip_to_str(tvb, offset));
            }

            offset+=16;
        }

        /* External Route Tag (optional - only if T-flag is on) */
        if ( (offset < end_offset) && (flags & OSPF_V3_AS_EXTERNAL_FLAG_T) ) {
            external_route_tag=tvb_get_ntohl(tvb, offset);
            proto_tree_add_text(ospf_lsa_tree, tvb, offset, 4,"External Route Tag: %u",
                                external_route_tag);

            offset+=4;
        }

        /* Referenced Link State ID (optional - only if Referenced LS type is non-zero */
        if ( (offset < end_offset) && (referenced_ls_type != 0) ) {
            proto_tree_add_text(ospf_lsa_tree, tvb, offset, 4, "Referenced Link State ID: %s",
                                tvb_ip_to_str(tvb, offset));
            offset+=4;
        }

        break;

    case OSPF_V3_LSTYPE_LINK:

        /* router priority */
        router_priority=tvb_get_guint8(tvb, offset);
        proto_tree_add_text(ospf_lsa_tree, tvb, offset, 1, "Router Priority: %u", router_priority);

        /* options field in an link-lsa */
        dissect_ospf_bitfield(ospf_lsa_tree, tvb, offset + 1, &bfinfo_v3_options);

        /* Link-local Interface Address */
        if (address_family == OSPF_AF_6) {
            proto_tree_add_text(ospf_lsa_tree, tvb, offset + 4, 16, "Link-local Interface Address: %s",
                                tvb_ip6_to_str(tvb, offset + 4));
        } else {
            proto_tree_add_text(ospf_lsa_tree, tvb, offset + 4, 16, "Link-local Interface Address: %s",
                                tvb_ip_to_str(tvb, offset + 4));
        }
        /* Number prefixes */
        number_prefixes=tvb_get_ntohl(tvb, offset + 20);
        proto_tree_add_text(ospf_lsa_tree, tvb, offset+20, 4, "# prefixes: %d",number_prefixes);

        offset+=24;

        while (number_prefixes > 0) {

            /* prefix length */
            prefix_length=tvb_get_guint8(tvb, offset);
            proto_tree_add_text(ospf_lsa_tree, tvb, offset, 1, "PrefixLength: %u",prefix_length);

            /* prefix options */
            dissect_ospf_bitfield(ospf_lsa_tree, tvb, offset+1, &bfinfo_v3_prefix_options);

            /* 16 bits reserved */
            reserved16=tvb_get_ntohs(tvb, offset+2);
            proto_tree_add_text(ospf_lsa_tree, tvb, offset+2, 2,
                                (reserved16 == 0 ? "Reserved: %u" : "Reserved: %u [incorrect, should be 0]"),reserved16);

            offset+=4;

            /* address_prefix */
            dissect_ospf_v3_address_prefix(tvb, offset, prefix_length, ospf_lsa_tree, address_family);

            offset+=(prefix_length+31)/32*4;

            number_prefixes--;

        }
        break;

    case OSPF_V3_LSTYPE_INTRA_AREA_PREFIX:

        /* # prefixes */
        number_prefixes=tvb_get_ntohs(tvb, offset);
        proto_tree_add_text(ospf_lsa_tree, tvb, offset, 2,"# prefixes: %u",number_prefixes);

        /* referenced LS type */
        referenced_ls_type=tvb_get_ntohs(tvb, offset+2);
        proto_tree_add_text(ospf_lsa_tree, tvb, offset+2, 2,"Referenced LS type 0x%04x (%s)",
                            referenced_ls_type, val_to_str(referenced_ls_type, v3_ls_type_vals, "Unknown"));

        /* Referenced Link State ID */
        proto_tree_add_text(ospf_lsa_tree, tvb, offset + 4, 4, "Referenced Link State ID: %s",
                            tvb_ip_to_str(tvb, offset + 4));

        /* Referenced Advertising Router */
        proto_tree_add_text(ospf_lsa_tree, tvb, offset + 8, 4, "Referenced Advertising Router: %s",
                            tvb_ip_to_str(tvb, offset + 8));

        offset+=12;

        while (number_prefixes > 0) {

            /* prefix length */
            prefix_length=tvb_get_guint8(tvb, offset);
            proto_tree_add_text(ospf_lsa_tree, tvb, offset, 1, "PrefixLength: %u",prefix_length);

            /* prefix options */
            dissect_ospf_bitfield(ospf_lsa_tree, tvb, offset+1, &bfinfo_v3_prefix_options);

            /* 16 bits metric */
            metric=tvb_get_ntohs(tvb, offset+2);
            proto_tree_add_text(ospf_lsa_tree, tvb, offset+2, 2,
                                "Metric: %u", metric);

            offset+=4;

            /* address_prefix */
            dissect_ospf_v3_address_prefix(tvb, offset, prefix_length, ospf_lsa_tree, address_family);

            offset+=(prefix_length+31)/32*4;

            number_prefixes--;
        }
        break;

    case OSPF_V3_LSTYPE_OPAQUE_RI:
        dissect_ospf_lsa_opaque_ri(tvb, offset, ospf_lsa_tree, ls_length);
        break;

    default:
        /* unknown LSA type */
        proto_tree_add_text(ospf_lsa_tree, tvb, offset, ls_length,
                            "Unknown LSA Type 0x%04x",ls_type);
        offset += ls_length;
        break;
    }
    /* return the offset of the next LSA */
    return offset;
}

static void dissect_ospf_v3_address_prefix(tvbuff_t *tvb, int offset, int prefix_length, proto_tree *tree,
                                           guint8 address_family)
{

    int bytes_to_process;
    struct e_in6_addr prefix;

    bytes_to_process=((prefix_length+31)/32)*4;

    if (prefix_length > 128) {
        proto_tree_add_text(tree, tvb, offset, bytes_to_process,
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
        proto_tree_add_text(tree, tvb, offset, bytes_to_process,
                            "Address Prefix: %s", ip6_to_str(&prefix));
    } else {
        proto_tree_add_text(tree, tvb, offset, bytes_to_process,
                            "Address Prefix: %s", tvb_ip_to_str(tvb, offset));
    }

}


void
proto_register_ospf(void)
{
    static hf_register_info ospff_info[] = {

        /* Message type number */
        {&hf_ospf_filter[OSPFF_MSG_TYPE],
         { "Message Type", "ospf.msg", FT_UINT8, BASE_DEC, VALS(pt_vals), 0x0,
           NULL, HFILL }},

        /* Message types */
        {&hf_ospf_filter[OSPFF_MSG_HELLO],
         { "Hello", "ospf.msg.hello", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_MSG_DB_DESC],
         { "Database Description", "ospf.msg.dbdesc", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_MSG_LS_REQ],
         { "Link State Adv Request", "ospf.msg.lsreq", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_MSG_LS_UPD],
         { "Link State Adv Update", "ospf.msg.lsupdate", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_MSG_LS_ACK],
         { "Link State Adv Acknowledgement", "ospf.msg.lsack", FT_BOOLEAN,
           BASE_NONE, NULL, 0x0, NULL, HFILL }},



        /* LS Types */
        {&hf_ospf_filter[OSPFF_LS_TYPE],
         { "Link-State Advertisement Type", "ospf.lsa", FT_UINT8, BASE_DEC,
           VALS(ls_type_vals), 0x0, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_LS_OPAQUE_TYPE],
         { "Link State ID Opaque Type", "ospf.lsid_opaque_type", FT_UINT8, BASE_DEC,
           VALS(ls_opaque_type_vals), 0x0, NULL, HFILL }},

        {&hf_ospf_filter[OSPFF_LS_MPLS_TE_INSTANCE],
         { "Link State ID TE-LSA Instance", "ospf.lsid_te_lsa.instance", FT_UINT16, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

        {&hf_ospf_filter[OSPFF_LS_ROUTER],
         { "Router LSA", "ospf.lsa.router", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_LS_NETWORK],
         { "Network LSA", "ospf.lsa.network", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_LS_SUMMARY],
         { "Summary LSA (IP Network)", "ospf.lsa.summary", FT_BOOLEAN, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_LS_ASBR],
         { "Summary LSA (ASBR)", "ospf.lsa.asbr", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_LS_ASEXT],
         { "AS-External LSA (ASBR)", "ospf.lsa.asext", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_LS_GRPMEMBER],
         { "Group Membership LSA", "ospf.lsa.member", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_LS_ASEXT7],
         { "NSSA AS-External LSA", "ospf.lsa.nssa", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_LS_EXTATTR],
         { "External Attributes LSA", "ospf.lsa.attr", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_LS_OPAQUE],
         { "Opaque LSA", "ospf.lsa.opaque", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},

        /* Other interesting OSPF values */
        {&hf_ospf_filter[OSPFF_SRC_ROUTER],
         { "Source OSPF Router", "ospf.srcrouter", FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},

        {&hf_ospf_filter[OSPFF_ADV_ROUTER],
         { "Advertising Router", "ospf.advrouter", FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},

        {&hf_ospf_filter[OSPFF_LS_MPLS],
         { "MPLS Traffic Engineering LSA", "ospf.lsa.mpls", FT_BOOLEAN,
           BASE_NONE, NULL, 0x0, NULL, HFILL }},

        {&hf_ospf_filter[OSPFF_LS_MPLS_ROUTERID],
         { "MPLS/TE Router ID", "ospf.mpls.routerid", FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},

        {&hf_ospf_filter[OSPFF_LS_MPLS_LINKTYPE],
         { "MPLS/TE Link Type", "ospf.mpls.linktype", FT_UINT8, BASE_DEC,
           VALS(mpls_link_stlv_ltype_str), 0x0, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_LS_MPLS_LINKID],
         { "MPLS/TE Link ID", "ospf.mpls.linkid", FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_LS_MPLS_LOCAL_ADDR],
         { "MPLS/TE Local Interface Address", "ospf.mpls.local_addr", FT_IPv4,
           BASE_NONE, NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_LS_MPLS_REMOTE_ADDR],
         { "MPLS/TE Remote Interface Address", "ospf.mpls.remote_addr", FT_IPv4,
           BASE_NONE, NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_LS_MPLS_LOCAL_IFID],
         { "MPLS/TE Local Interface Index", "ospf.mpls.local_id", FT_UINT32,
           BASE_DEC, NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_LS_MPLS_REMOTE_IFID],
         { "MPLS/TE Remote Interface Index", "ospf.mpls.remote_id", FT_UINT32,
           BASE_DEC, NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_LS_MPLS_LINKCOLOR],
         { "MPLS/TE Link Resource Class/Color", "ospf.mpls.linkcolor", FT_UINT32,
           BASE_HEX, NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_LS_MPLS_BC_MODEL_ID],
         { "MPLS/DSTE Bandwidth Constraints Model Id", "ospf.mpls.bc", FT_UINT8,
           BASE_RANGE_STRING | BASE_DEC, RVALS(&mpls_link_stlv_bcmodel_rvals), 0x0,
           NULL, HFILL }},

        {&hf_ospf_filter[OSPFF_LS_OIF_LOCAL_NODE_ID],
         { "Local Node ID", "ospf.oif.local_node_id", FT_IPv4,
           BASE_NONE, NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_LS_OIF_REMOTE_NODE_ID],
         { "Remote Node ID", "ospf.oif.remote_node_id", FT_IPv4,
           BASE_NONE, NULL, 0x0, NULL, HFILL }},

        {&hf_ospf_filter[OSPFF_V2_OPTIONS],
         { "Options", "ospf.v2.options", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V2_OPTIONS_MT],
         { "MT", "ospf.v2.options.mt", FT_BOOLEAN, 8,
           TFS(&tfs_v2_options_mt), OSPF_V2_OPTIONS_MT, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V2_OPTIONS_E],
         { "E", "ospf.v2.options.e", FT_BOOLEAN, 8,
           TFS(&tfs_v2_options_e), OSPF_V2_OPTIONS_E, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V2_OPTIONS_MC],
         { "MC", "ospf.v2.options.mc", FT_BOOLEAN, 8,
           TFS(&tfs_v2_options_mc), OSPF_V2_OPTIONS_MC, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V2_OPTIONS_NP],
         { "NP", "ospf.v2.options.np", FT_BOOLEAN, 8,
           TFS(&tfs_v2_options_np), OSPF_V2_OPTIONS_NP, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V2_OPTIONS_L],
         { "L", "ospf.v2.options.l", FT_BOOLEAN, 8,
           TFS(&tfs_v2_options_l), OSPF_V2_OPTIONS_L, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V2_OPTIONS_DC],
         { "DC", "ospf.v2.options.dc", FT_BOOLEAN, 8,
           TFS(&tfs_v2_options_dc), OSPF_V2_OPTIONS_DC, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V2_OPTIONS_O],
         { "O", "ospf.v2.options.o", FT_BOOLEAN, 8,
           TFS(&tfs_v2_options_o), OSPF_V2_OPTIONS_O, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V2_OPTIONS_DN],
         { "DN", "ospf.v2.options.dn", FT_BOOLEAN, 8,
           TFS(&tfs_v2_options_dn), OSPF_V2_OPTIONS_DN, NULL, HFILL }},

        {&hf_ospf_filter[OSPFF_RI_OPTIONS],
         { "RI Options", "ospf.ri.options", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_RI_OPTIONS_GRC],
         { "GRC", "ospf.ri.options.grc", FT_BOOLEAN, 8,
           TFS(&tfs_ri_options_grc), OSPF_RI_OPTIONS_GRC, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_RI_OPTIONS_GRH],
         { "GRH", "ospf.ri.options.grh", FT_BOOLEAN, 8,
           TFS(&tfs_ri_options_grh), OSPF_RI_OPTIONS_GRH, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_RI_OPTIONS_SRS],
         { "SRS", "ospf.ri.options.srs", FT_BOOLEAN, 8,
           TFS(&tfs_ri_options_srs), OSPF_RI_OPTIONS_SRS, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_RI_OPTIONS_TES],
         { "TES", "ospf.ri.options.tes", FT_BOOLEAN, 8,
           TFS(&tfs_ri_options_tes), OSPF_RI_OPTIONS_TES, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_RI_OPTIONS_P2PLAN],
         { "P2PLAN", "ospf.ri.options.p2plan", FT_BOOLEAN, 8,
           TFS(&tfs_ri_options_p2plan), OSPF_RI_OPTIONS_P2PLAN, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_RI_OPTIONS_ETE],
         { "ETE", "ospf.ri.options.ete", FT_BOOLEAN, 8,
           TFS(&tfs_ri_options_ete), OSPF_RI_OPTIONS_ETE, NULL, HFILL }},

        /* An MBZ field for the 24-bits of type field of Opaque RI LSA */
        {&hf_ospf_filter[OSPFF_OPAQUE_LSA_MBZ],
         { "MBZ", "ospf.ri.mbz", FT_UINT16, BASE_HEX, 
            NULL, 0x0, "OSPF Opaque RI LSA - 24 bits of Type Field Must be Zero", HFILL }},

        {&hf_ospf_filter[OSPFF_V3_OPTIONS],
         { "Options", "ospf.v3.options", FT_UINT24, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_OPTIONS_V6],
         { "V6", "ospf.v3.options.v6", FT_BOOLEAN, 24,
           TFS(&tfs_v3_options_v6), OSPF_V3_OPTIONS_V6, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_OPTIONS_E],
         { "E", "ospf.v3.options.e", FT_BOOLEAN, 24,
           TFS(&tfs_v3_options_e), OSPF_V3_OPTIONS_E, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_OPTIONS_MC],
         { "MC", "ospf.v3.options.mc", FT_BOOLEAN, 24,
           TFS(&tfs_v3_options_mc), OSPF_V3_OPTIONS_MC, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_OPTIONS_N],
         { "N", "ospf.v3.options.n", FT_BOOLEAN, 24,
           TFS(&tfs_v3_options_n), OSPF_V3_OPTIONS_N, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_OPTIONS_R],
         { "R", "ospf.v3.options.r", FT_BOOLEAN, 24,
           TFS(&tfs_v3_options_r), OSPF_V3_OPTIONS_R, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_OPTIONS_DC],
         { "DC", "ospf.v3.options.dc", FT_BOOLEAN, 24,
           TFS(&tfs_v3_options_dc), OSPF_V3_OPTIONS_DC, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_OPTIONS_AF],
         { "AF", "ospf.v3.options.af", FT_BOOLEAN, 24,
           TFS(&tfs_v3_options_af), OSPF_V3_OPTIONS_AF, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_OPTIONS_L],
         { "L", "ospf.v3.options.l", FT_BOOLEAN, 24,
           TFS(&tfs_v3_options_l), OSPF_V3_OPTIONS_L, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_OPTIONS_I],
         { "I", "ospf.v3.options.i", FT_BOOLEAN, 24,
           TFS(&tfs_v3_options_i), OSPF_V3_OPTIONS_I, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_OPTIONS_F],
         { "F", "ospf.v3.options.f", FT_BOOLEAN, 24,
           TFS(&tfs_v3_options_f), OSPF_V3_OPTIONS_F, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_DBD],
         { "DB Description", "ospf.dbd", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_DBD_R],
         { "R", "ospf.dbd.r", FT_BOOLEAN, 8,
           TFS(&tfs_dbd_r), OSPF_DBD_FLAG_R, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_DBD_I],
         { "I", "ospf.dbd.i", FT_BOOLEAN, 8,
           TFS(&tfs_dbd_i), OSPF_DBD_FLAG_I, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_DBD_M],
         { "M", "ospf.dbd.m", FT_BOOLEAN, 8,
           TFS(&tfs_dbd_m), OSPF_DBD_FLAG_M, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_DBD_MS],
         { "MS", "ospf.dbd.ms", FT_BOOLEAN, 8,
           TFS(&tfs_dbd_ms), OSPF_DBD_FLAG_MS, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_LLS_EXT_OPTIONS],
         { "Options", "ospf.lls.ext.options", FT_UINT32, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_LLS_EXT_OPTIONS_LR],
         { "LR", "ospf.lls.ext.options.lr", FT_BOOLEAN, 32,
           TFS(&tfs_lls_ext_options_lr), OSPF_LLS_EXT_OPTIONS_LR, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_LLS_EXT_OPTIONS_RS],
         { "RS", "ospf.lls.ext.options.rs", FT_BOOLEAN, 32,
           TFS(&tfs_lls_ext_options_rs), OSPF_LLS_EXT_OPTIONS_RS, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V2_ROUTER_LSA_FLAG],
         { "Flags", "ospf.v2.router.lsa.flags", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V2_ROUTER_LSA_FLAG_B],
         { "B", "ospf.v2.router.lsa.flags.b", FT_BOOLEAN, 8,
           TFS(&tfs_v2_router_lsa_flags_b), OSPF_V2_ROUTER_LSA_FLAG_B, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V2_ROUTER_LSA_FLAG_E],
         { "E", "ospf.v2.router.lsa.flags.e", FT_BOOLEAN, 8,
           TFS(&tfs_v2_router_lsa_flags_e), OSPF_V2_ROUTER_LSA_FLAG_E, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V2_ROUTER_LSA_FLAG_V],
         { "V", "ospf.v2.router.lsa.flags.v", FT_BOOLEAN, 8,
           TFS(&tfs_v2_router_lsa_flags_v), OSPF_V2_ROUTER_LSA_FLAG_V, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V2_ROUTER_LSA_FLAG_W],
         { "W", "ospf.v2.router.lsa.flags.w", FT_BOOLEAN, 8,
           TFS(&tfs_v2_router_lsa_flags_w), OSPF_V2_ROUTER_LSA_FLAG_W, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V2_ROUTER_LSA_FLAG_N],
         { "N", "ospf.v2.router.lsa.flags.n", FT_BOOLEAN, 8,
           TFS(&tfs_v2_router_lsa_flags_n), OSPF_V2_ROUTER_LSA_FLAG_N, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_ROUTER_LSA_FLAG],
         { "Flags", "ospf.v3.router.lsa.flags", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_ROUTER_LSA_FLAG_B],
         { "B", "ospf.v3.router.lsa.flags.b", FT_BOOLEAN, 8,
           TFS(&tfs_v3_router_lsa_flags_b), OSPF_V3_ROUTER_LSA_FLAG_B, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_ROUTER_LSA_FLAG_E],
         { "E", "ospf.v3.router.lsa.flags.e", FT_BOOLEAN, 8,
           TFS(&tfs_v3_router_lsa_flags_e), OSPF_V3_ROUTER_LSA_FLAG_E, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_ROUTER_LSA_FLAG_V],
         { "V", "ospf.v3.router.lsa.flags.v", FT_BOOLEAN, 8,
           TFS(&tfs_v3_router_lsa_flags_v), OSPF_V3_ROUTER_LSA_FLAG_V, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_ROUTER_LSA_FLAG_W],
         { "W", "ospf.v3.router.lsa.flags.w", FT_BOOLEAN, 8,
           TFS(&tfs_v3_router_lsa_flags_w), OSPF_V3_ROUTER_LSA_FLAG_W, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_AS_EXTERNAL_FLAG],
         { "Flags", "ospf.v3.as.external.flags", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_AS_EXTERNAL_FLAG_T],
         { "T", "ospf.v3.as.external.flags.t", FT_BOOLEAN, 8,
           TFS(&tfs_v3_as_external_flags_t), OSPF_V3_AS_EXTERNAL_FLAG_T, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_AS_EXTERNAL_FLAG_F],
         { "F", "ospf.v3.as.external.flags.f", FT_BOOLEAN, 8,
           TFS(&tfs_v3_as_external_flags_f), OSPF_V3_AS_EXTERNAL_FLAG_F, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_AS_EXTERNAL_FLAG_E],
         { "E", "ospf.v3.as.external.flags.e", FT_BOOLEAN, 8,
           TFS(&tfs_v3_as_external_flags_e), OSPF_V3_AS_EXTERNAL_FLAG_E, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_PREFIX_OPTION],
         { "PrefixOptions", "ospf.v3.prefix.options", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_PREFIX_OPTION_NU],
         { "NU", "ospf.v3.prefix.options.nu", FT_BOOLEAN, 8,
           TFS(&tfs_v3_prefix_options_nu), OSPF_V3_PREFIX_OPTION_NU, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_PREFIX_OPTION_LA],
         { "LA", "ospf.v3.prefix.options.la", FT_BOOLEAN, 8,
           TFS(&tfs_v3_prefix_options_la), OSPF_V3_PREFIX_OPTION_LA, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_PREFIX_OPTION_MC],
         { "MC", "ospf.v3.prefix.options.mc", FT_BOOLEAN, 8,
           TFS(&tfs_v3_prefix_options_mc), OSPF_V3_PREFIX_OPTION_MC, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_PREFIX_OPTION_P],
         { "P", "ospf.v3.prefix.options.p", FT_BOOLEAN, 8,
           TFS(&tfs_v3_prefix_options_p), OSPF_V3_PREFIX_OPTION_P, NULL, HFILL }},

        /* Dynamic Hostname contained in the Opaque RI LSA - dynamic hostname TLV*/
        {&hf_ospf_filter[OSPFF_DYN_HOSTNAME],
         { "Dynamic Hostname", "ospf.dynhostname", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        /* text contained in the Unknown TLV of the Opaque RI LSA */
        {&hf_ospf_filter[OSPFF_UNKNOWN_TLV_TXT],
         { "Text in the Unknown TLV", "ospf.unknown_text", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        /* OSPF Restart TLVs  */
        {&hf_ospf_filter[OSPFF_V2_GRACE_TLV],
         { "Grace TLV", "ospf.v2.grace", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_ospf_filter[OSPFF_V2_GRACE_PERIOD],
         { "Grace Period", "ospf.v2.grace.period", FT_UINT32, BASE_DEC,
           NULL, 0x0,
           "The number of seconds neighbors should advertise the router as fully adjacent",
           HFILL }},
        {&hf_ospf_filter[OSPFF_V2_GRACE_REASON],
         { "Restart Reason", "ospf.v2.grace.reason", FT_UINT8, BASE_DEC,
           VALS(restart_reason_vals), 0x0, "The reason the router is restarting", HFILL }},
        {&hf_ospf_filter[OSPFF_V2_GRACE_IP],
         { "Restart IP", "ospf.v2.grace.ip", FT_IPv4, BASE_NONE,
           NULL, 0x0, "The IP address of the interface originating this LSA", HFILL }},

        /* OSPFv3 LLS TLVs */
        {&hf_ospf_filter[OSPFF_V3_LLS_EXT_OPTIONS_TLV],
         { "Extended Options TLV", "ospf.v3.lls.ext.options.tlv", FT_NONE, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_LLS_EXT_OPTIONS],
         { "Options", "ospf.v3.lls.ext.options", FT_UINT32,  BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_LLS_EXT_OPTIONS_LR],
         { "LR", "ospf.v3.lls.ext.options.lr", FT_BOOLEAN, 32,
           TFS(&tfs_v3_lls_ext_options_lr), OSPF_V3_LLS_EXT_OPTIONS_LR, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_LLS_EXT_OPTIONS_RS],
         { "RS", "ospf.v3.lls.ext.options.rs", FT_BOOLEAN, 32,
           TFS(&tfs_v3_lls_ext_options_rs), OSPF_V3_LLS_EXT_OPTIONS_RS, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_LLS_STATE_TLV],
         { "State Check Sequence TLV", "ospf.v3.lls.state.tlv", FT_NONE, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_LLS_STATE_SCS],
         { "SCS Number", "ospf.v3.lls.state.scs", FT_UINT16,  BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_LLS_STATE_OPTIONS],
         { "Options", "ospf.v3.lls.state.options", FT_UINT8,  BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_LLS_STATE_OPTIONS_R],
         { "R", "ospf.v3.lls.state.options.r", FT_BOOLEAN, 8,
           TFS(&tfs_v3_lls_state_options_r), OSPF_V3_LLS_STATE_OPTIONS_R, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_LLS_STATE_OPTIONS_A],
         { "A", "ospf.v3.lls.state.options.a", FT_BOOLEAN, 8,
           TFS(&tfs_v3_lls_state_options_a), OSPF_V3_LLS_STATE_OPTIONS_A , NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_LLS_STATE_OPTIONS_N],
         { "N", "ospf.v3.lls.state.options.n", FT_BOOLEAN, 8,
           TFS(&tfs_v3_lls_state_options_n), OSPF_V3_LLS_STATE_OPTIONS_N ,NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_LLS_DROP_TLV],
         { "Neighbor Drop TLV", "ospf.v3.lls.drop.tlv", FT_NONE, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_LLS_RELAY_TLV],
         { "Active Overlapping Relays TLV", "ospf.v3.lls.relay.tlv", FT_NONE, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_LLS_RELAY_ADDED],
         { "Relays Added", "ospf.v3.lls.relay.added", FT_UINT8,  BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_LLS_RELAY_OPTIONS],
         { "Options", "ospf.v3.lls.relay.options", FT_UINT8,  BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_LLS_RELAY_OPTIONS_A],
         { "A", "ospf.v3.lls.relay.options.a", FT_BOOLEAN, 8,
           TFS(&tfs_v3_lls_relay_options_a), OSPF_V3_LLS_RELAY_OPTIONS_A , NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_LLS_RELAY_OPTIONS_N],
         { "N", "ospf.v3.lls.relay.options.n", FT_BOOLEAN, 8,
           TFS(&tfs_v3_lls_relay_options_n), OSPF_V3_LLS_RELAY_OPTIONS_N ,NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_LLS_WILLINGNESS_TLV],
         { "Willingness TLV", "ospf.v3.lls.willingness.tlv", FT_NONE, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_LLS_WILLINGNESS],
         { "Willingness", "ospf.v3.lls.willingness", FT_UINT8,  BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_LLS_RF_TLV],
         { "Request From TLV", "ospf.v3.lls.rf.tlv", FT_NONE, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ospf_filter[OSPFF_V3_LLS_FSF_TLV],
         { "Full State For TLV", "ospf.v3.lls.fsf.tlv", FT_NONE, BASE_NONE,
           NULL, 0x0, NULL, HFILL }}
    };

    static gint *ett[] = {
        &ett_ospf,
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

    proto_ospf = proto_register_protocol("Open Shortest Path First",
                                         "OSPF", "ospf");
    proto_register_field_array(proto_ospf, ospff_info, array_length(ospff_info));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ospf(void)
{
    dissector_handle_t ospf_handle;

    ospf_handle = create_dissector_handle(dissect_ospf, proto_ospf);
    dissector_add_uint("ip.proto", IP_PROTO_OSPF, ospf_handle);
    data_handle = find_dissector("data");
}
