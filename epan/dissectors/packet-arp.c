/* packet-arp.c
 * Routines for ARP packet disassembly (RFC 826)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * By Deepti Ragha <dlragha@ncsu.edu>
 * Copyright 2012 Deepti Ragha
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <epan/arptypes.h>
#include <epan/addr_resolv.h>
#include "packet-arp.h"
#include <epan/etypes.h>
#include <epan/arcnet_pids.h>
#include <epan/ax25_pids.h>
#include <epan/osi-utils.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/proto_data.h>

void proto_register_arp(void);
void proto_reg_handoff_arp(void);

static int proto_arp;
static int hf_arp_hard_type;
static int hf_arp_proto_type;
static int hf_arp_hard_size;
static int hf_atmarp_sht;
static int hf_atmarp_shl;
static int hf_atmarp_sst;
static int hf_atmarp_ssl;
static int hf_arp_proto_size;
static int hf_arp_opcode;
static int hf_arp_isgratuitous;
static int hf_arp_isprobe;
static int hf_arp_isannouncement;

static int proto_atmarp;
static int hf_atmarp_spln;
static int hf_atmarp_tht;
static int hf_atmarp_thl;
static int hf_atmarp_tst;
static int hf_atmarp_tsl;
static int hf_atmarp_tpln;
static int hf_arp_src_hw;
static int hf_arp_src_hw_mac;
static int hf_arp_src_proto;
static int hf_arp_src_proto_ipv4;
static int hf_arp_dst_hw;
static int hf_arp_dst_hw_mac;
static int hf_arp_dst_proto;
static int hf_arp_dst_proto_ipv4;
static int hf_drarp_error_status;
static int hf_arp_duplicate_ip_address_earlier_frame;
static int hf_arp_duplicate_ip_address_seconds_since_earlier_frame;

static int hf_atmarp_src_atm_num_e164;
static int hf_atmarp_src_atm_num_nsap;
static int hf_atmarp_src_atm_subaddr;
static int hf_atmarp_dst_atm_num_e164;
static int hf_atmarp_dst_atm_num_nsap;
static int hf_atmarp_dst_atm_subaddr;
/* Generated from convert_proto_tree_add_text.pl */
static int hf_atmarp_src_atm_data_country_code;
static int hf_atmarp_src_atm_data_country_code_group;
static int hf_atmarp_src_atm_e_164_isdn;
static int hf_atmarp_src_atm_e_164_isdn_group;
static int hf_atmarp_src_atm_rest_of_address;
static int hf_atmarp_src_atm_end_system_identifier;
static int hf_atmarp_src_atm_high_order_dsp;
static int hf_atmarp_src_atm_selector;
static int hf_atmarp_src_atm_international_code_designator;
static int hf_atmarp_src_atm_international_code_designator_group;
static int hf_atmarp_src_atm_afi;

static int hf_arp_dst_hw_ax25;
static int hf_arp_src_hw_ax25;

static int ett_arp;
static int ett_atmarp_nsap;
static int ett_atmarp_tl;
static int ett_arp_duplicate_address;

static expert_field ei_seq_arp_dup_ip;
static expert_field ei_seq_arp_storm;
static expert_field ei_atmarp_src_atm_unknown_afi;

static dissector_handle_t arp_handle;

static dissector_table_t arp_hw_table;

static capture_dissector_handle_t arp_cap_handle;

/* Used for determining if frequency of ARP requests constitute a storm */
#define STORM    1
#define NO_STORM 2

/* Preference settings */
static bool global_arp_detect_request_storm;
static uint32_t global_arp_detect_request_storm_packets = 30;
static uint32_t global_arp_detect_request_storm_period = 100;

static bool global_arp_detect_duplicate_ip_addresses = true;
static bool global_arp_register_network_address_binding = true;

static uint32_t arp_request_count;
static nstime_t time_at_start_of_count;


/* Map of (IP address -> MAC address) to detect duplicate IP addresses
   Key is unsigned32 */
static wmem_map_t *address_hash_table;

typedef struct address_hash_value {
  uint8_t   mac[6];
  unsigned  frame_num;
  time_t    time_of_entry;
} address_hash_value;

/* Map of ((frame Num, IP address) -> MAC address) */
static wmem_map_t *duplicate_result_hash_table;

typedef struct duplicate_result_key {
  uint32_t frame_number;
  uint32_t ip_address;
} duplicate_result_key;


/* Definitions taken from Linux "linux/if_arp.h" header file, and from

   http://www.iana.org/assignments/arp-parameters

*/


/* ARP / RARP structs and definitions */
#ifndef ARPOP_REQUEST
#define ARPOP_REQUEST  1       /* ARP request.  */
#endif
#ifndef ARPOP_REPLY
#define ARPOP_REPLY    2       /* ARP reply.  */
#endif
/* Some OSes have different names, or don't define these at all */
#ifndef ARPOP_RREQUEST
#define ARPOP_RREQUEST 3       /* RARP request.  */
#endif
#ifndef ARPOP_RREPLY
#define ARPOP_RREPLY   4       /* RARP reply.  */
#endif

/* Additional parameters as per https://www.iana.org/assignments/arp-parameters */
#ifndef ARPOP_DRARPREQUEST
#define ARPOP_DRARPREQUEST 5   /* DRARP request.  */
#endif

#ifndef ARPOP_DRARPREPLY
#define ARPOP_DRARPREPLY 6     /* DRARP reply.  */
#endif

#ifndef ARPOP_DRARPERROR
#define ARPOP_DRARPERROR 7     /* DRARP error.  */
#endif

#ifndef ARPOP_IREQUEST
#define ARPOP_IREQUEST 8       /* Inverse ARP (RFC 1293) request.  */
#endif
#ifndef ARPOP_IREPLY
#define ARPOP_IREPLY   9       /* Inverse ARP reply.  */
#endif
#ifndef ATMARPOP_NAK
#define ATMARPOP_NAK   10      /* ATMARP NAK.  */
#endif

/* Additional parameters as per https://www.iana.org/assignments/arp-parameters */
#ifndef ARPOP_MARS_REQUEST
#define ARPOP_MARS_REQUEST   11       /*MARS request message. */
#endif

#ifndef ARPOP_MARS_MULTI
#define ARPOP_MARS_MULTI   12       /*MARS-Multi message. */
#endif

#ifndef ARPOP_MARS_MSERV
#define ARPOP_MARS_MSERV   13       /*MARS-Mserv message. */
#endif

#ifndef ARPOP_MARS_JOIN
#define ARPOP_MARS_JOIN  14       /*MARS-Join request. */
#endif

#ifndef ARPOP_MARS_LEAVE
#define ARPOP_MARS_LEAVE   15       /*MARS Leave request. */
#endif

#ifndef ARPOP_MARS_NAK
#define ARPOP_MARS_NAK   16       /*MARS nak message.*/
#endif

#ifndef ARPOP_MARS_UNSERV
#define ARPOP_MARS_UNSERV   17       /*MARS Unserv message. */
#endif

#ifndef ARPOP_MARS_SJOIN
#define ARPOP_MARS_SJOIN   18       /*MARS Sjoin message. */
#endif

#ifndef ARPOP_MARS_SLEAVE
#define ARPOP_MARS_SLEAVE   19       /*MARS Sleave message. */
#endif

#ifndef ARPOP_MARS_GROUPLIST_REQUEST
#define ARPOP_MARS_GROUPLIST_REQUEST   20       /*MARS Grouplist request message. */
#endif

#ifndef ARPOP_MARS_GROUPLIST_REPLY
#define ARPOP_MARS_GROUPLIST_REPLY   21       /*MARS Grouplist reply message. */
#endif

#ifndef ARPOP_MARS_REDIRECT_MAP
#define ARPOP_MARS_REDIRECT_MAP   22       /*MARS Grouplist request message. */
#endif

#ifndef ARPOP_MAPOS_UNARP
#define ARPOP_MAPOS_UNARP   23 /*MAPOS UNARP*/
#endif

#ifndef ARPOP_EXP1
#define ARPOP_EXP1     24      /* Experimental 1 */
#endif
#ifndef ARPOP_EXP2
#define ARPOP_EXP2     25      /* Experimental 2 */
#endif

#ifndef ARPOP_RESERVED1
#define ARPOP_RESERVED1         0  /*Reserved opcode 1*/
#endif

#ifndef ARPOP_RESERVED2
#define ARPOP_RESERVED2         65535 /*Reserved opcode 2*/
#endif

#ifndef DRARPERR_RESTRICTED
#define DRARPERR_RESTRICTED      1
#endif

#ifndef DRARPERR_NOADDRESSES
#define DRARPERR_NOADDRESSES     2
#endif

#ifndef DRARPERR_SERVERDOWN
#define DRARPERR_SERVERDOWN     3
#endif

#ifndef DRARPERR_MOVED
#define DRARPERR_MOVED     4
#endif

#ifndef DRARPERR_FAILURE
#define DRARPERR_FAILURE     5
#endif



static const value_string op_vals[] = {
  {ARPOP_REQUEST,                "request"                },
  {ARPOP_REPLY,                  "reply"                  },
  {ARPOP_RREQUEST,               "reverse request"        },
  {ARPOP_RREPLY,                 "reverse reply"          },
  {ARPOP_DRARPREQUEST,           "drarp request"          },
  {ARPOP_DRARPREPLY,             "drarp reply"            },
  {ARPOP_DRARPERROR,             "drarp error"            },
  {ARPOP_IREQUEST,               "inverse request"        },
  {ARPOP_IREPLY,                 "inverse reply"          },
  {ATMARPOP_NAK,                 "arp nak"                },
  {ARPOP_MARS_REQUEST,           "mars request"           },
  {ARPOP_MARS_MULTI,             "mars multi"             },
  {ARPOP_MARS_MSERV,             "mars mserv"             },
  {ARPOP_MARS_JOIN,              "mars join"              },
  {ARPOP_MARS_LEAVE,             "mars leave"             },
  {ARPOP_MARS_NAK,               "mars nak"               },
  {ARPOP_MARS_UNSERV,            "mars unserv"            },
  {ARPOP_MARS_SJOIN,             "mars sjoin"             },
  {ARPOP_MARS_SLEAVE,            "mars sleave"            },
  {ARPOP_MARS_GROUPLIST_REQUEST, "mars grouplist request" },
  {ARPOP_MARS_GROUPLIST_REPLY,   "mars grouplist reply"   },
  {ARPOP_MARS_REDIRECT_MAP,      "mars redirect map"      },
  {ARPOP_MAPOS_UNARP,            "mapos unarp"            },
  {ARPOP_EXP1,                   "experimental 1"         },
  {ARPOP_EXP2,                   "experimental 2"         },
  {ARPOP_RESERVED1,              "reserved"               },
  {ARPOP_RESERVED2,              "reserved"               },
  {0, NULL}};

static const value_string drarp_status[]={
{DRARPERR_RESTRICTED,  "restricted" },
{DRARPERR_NOADDRESSES, "no address" },
{DRARPERR_SERVERDOWN,  "serverdown" },
{DRARPERR_MOVED,       "moved"      },
{DRARPERR_FAILURE,     "failure"    },
{0, NULL}};

static const value_string atmop_vals[] = {
  {ARPOP_REQUEST,                "request"                },
  {ARPOP_REPLY,                  "reply"                  },
  {ARPOP_IREQUEST,               "inverse request"        },
  {ARPOP_IREPLY,                 "inverse reply"          },
  {ATMARPOP_NAK,                 "nak"                    },
  {ARPOP_MARS_REQUEST,           "mars request"           },
  {ARPOP_MARS_MULTI,             "mars multi"             },
  {ARPOP_MARS_MSERV,             "mars mserv"             },
  {ARPOP_MARS_JOIN,              "mars join"              },
  {ARPOP_MARS_LEAVE,             "mars leave"             },
  {ARPOP_MARS_NAK,               "mars nak"               },
  {ARPOP_MARS_UNSERV,            "mars unserv"            },
  {ARPOP_MARS_SJOIN,             "mars sjoin"             },
  {ARPOP_MARS_SLEAVE,            "mars sleave"            },
  {ARPOP_MARS_GROUPLIST_REQUEST, "mars grouplist request" },
  {ARPOP_MARS_GROUPLIST_REPLY,   "mars grouplist reply"   },
  {ARPOP_MARS_REDIRECT_MAP,      "mars redirect map"      },
  {ARPOP_MAPOS_UNARP,            "mapos unarp"            },
  {ARPOP_EXP1,                   "experimental 1"         },
  {ARPOP_EXP2,                   "experimental 2"         },
  {ARPOP_RESERVED1,              "reserved"               },
  {ARPOP_RESERVED2,              "reserved"               },
  {0, NULL} };

#define ATMARP_IS_E164  0x40    /* bit in type/length for E.164 format */
#define ATMARP_LEN_MASK 0x3F    /* length of {sub}address in type/length */

/*
 * Given the hardware address type and length, check whether an address
 * is an Ethernet address - the address must be of type "Ethernet" or
 * "IEEE 802.x", and the length must be 6 bytes.
 */
#define ARP_HW_IS_ETHER(ar_hrd, ar_hln)                         \
  (((ar_hrd) == ARPHRD_ETHER || (ar_hrd) == ARPHRD_IEEE802)     \
   && (ar_hln) == 6)

/*
* Given the hardware address type and length, check whether an address
* is an AX.25 address - the address must be of type "AX.25" and the
* length must be 7 bytes.
*/
#define ARP_HW_IS_AX25(ar_hrd, ar_hln) \
  ((ar_hrd) == ARPHRD_AX25 && (ar_hln) == 7)

/*
 * Given the protocol address type and length, check whether an address
 * is an IPv4 address - the address must be of type "IP", and the length
 * must be 4 bytes.
 */
#define ARP_PRO_IS_IPv4(ar_pro, ar_pln)         \
  (((ar_pro) == ETHERTYPE_IP || (ar_pro) == AX25_P_IP) && (ar_pln) == 4)

const char *
tvb_arphrdaddr_to_str(wmem_allocator_t *scope, tvbuff_t *tvb, int offset, int ad_len, uint16_t type)
{
  if (ad_len == 0)
    return "<No address>";
  if (ARP_HW_IS_ETHER(type, ad_len)) {
    /* Ethernet address (or IEEE 802.x address, which is the same type of
       address). */
    return tvb_ether_to_str(scope, tvb, offset);
  }
  return tvb_bytes_to_str(scope, tvb, offset, ad_len);
}

static const char *
arpproaddr_to_str(wmem_allocator_t *scope, const uint8_t *ad, int ad_len, uint16_t type)
{
  address addr;

  if (ad_len == 0)
    return "<No address>";
  if (ARP_PRO_IS_IPv4(type, ad_len)) {
    /* IPv4 address.  */
    set_address(&addr, AT_IPv4, 4, ad);

    return address_to_str(scope, &addr);
  }
  if (ARP_HW_IS_AX25(type, ad_len)) {
    {
    /* AX.25 address */
    set_address(&addr, AT_AX25, AX25_ADDR_LEN, ad);

    return address_to_str(scope, &addr);
    }
  }
  return bytes_to_str(scope, ad, ad_len);
}

static const char *
tvb_arpproaddr_to_str(wmem_allocator_t *scope, tvbuff_t *tvb, int offset, int ad_len, uint16_t type)
{
    const uint8_t *ad = tvb_memdup(scope, tvb, offset, ad_len);
    return arpproaddr_to_str(scope, ad, ad_len, type);
}

static const char *
atmarpnum_to_str(wmem_allocator_t *scope, tvbuff_t *tvb, int offset, int ad_tl)
{
  int    ad_len = ad_tl & ATMARP_LEN_MASK;

  if (ad_len == 0)
    return "<No address>";

  if (ad_tl & ATMARP_IS_E164) {
    /*
     * I'm assuming this means it's an ASCII (IA5) string.
     */
    return (char *) tvb_get_string_enc(scope, tvb, offset, ad_len, ENC_ASCII|ENC_NA);
  } else {
    /*
     * NSAP.
     *
     * XXX - break down into subcomponents.
     */
    return tvb_bytes_to_str(scope, tvb, offset, ad_len);
  }
}

static const char *
atmarpsubaddr_to_str(wmem_allocator_t *scope, tvbuff_t *tvb, int offset, int ad_tl)
{
  int ad_len = ad_tl & ATMARP_LEN_MASK;

  if (ad_len == 0)
    return "<No address>";

  /*
   * E.164 isn't considered legal in subaddresses (RFC 2225 says that
   * a null or unknown ATM address is indicated by setting the length
   * to 0, in which case the type must be ignored; we've seen some
   * captures in which the length of a subaddress is 0 and the type
   * is E.164).
   *
   * XXX - break down into subcomponents?
   */
  return tvb_bytes_to_str(scope, tvb, offset, ad_len);
}

const value_string arp_hrd_vals[] = {
  {ARPHRD_NETROM,             "NET/ROM pseudo"             },
  {ARPHRD_ETHER,              "Ethernet"                   },
  {ARPHRD_EETHER,             "Experimental Ethernet"      },
  {ARPHRD_AX25,               "AX.25"                      },
  {ARPHRD_PRONET,             "ProNET"                     },
  {ARPHRD_CHAOS,              "Chaos"                      },
  {ARPHRD_IEEE802,            "IEEE 802"                   },
  {ARPHRD_ARCNET,             "ARCNET"                     },
  {ARPHRD_HYPERCH,            "Hyperchannel"               },
  {ARPHRD_LANSTAR,            "Lanstar"                    },
  {ARPHRD_AUTONET,            "Autonet Short Address"      },
  {ARPHRD_LOCALTLK,           "Localtalk"                  },
  {ARPHRD_LOCALNET,           "LocalNet"                   },
  {ARPHRD_ULTRALNK,           "Ultra link"                 },
  {ARPHRD_SMDS,               "SMDS"                       },
  {ARPHRD_DLCI,               "Frame Relay DLCI"           },
  {ARPHRD_ATM,                "ATM"                        },
  {ARPHRD_HDLC,               "HDLC"                       },
  {ARPHRD_FIBREC,             "Fibre Channel"              },
  {ARPHRD_ATM2225,            "ATM (RFC 2225)"             },
  {ARPHRD_SERIAL,             "Serial Line"                },
  {ARPHRD_ATM2,               "ATM"                        },
  {ARPHRD_MS188220,           "MIL-STD-188-220"            },
  {ARPHRD_METRICOM,           "Metricom STRIP"             },
  {ARPHRD_IEEE1394,           "IEEE 1394.1995"             },
  {ARPHRD_MAPOS,              "MAPOS"                      },
  {ARPHRD_TWINAX,             "Twinaxial"                  },
  {ARPHRD_EUI_64,             "EUI-64"                     },
  {ARPHRD_HIPARP,             "HIPARP"                     },
  {ARPHRD_IP_ARP_ISO_7816_3,  "IP and ARP over ISO 7816-3" },
  {ARPHRD_ARPSEC,             "ARPSec"                     },
  {ARPHRD_IPSEC_TUNNEL,       "IPsec tunnel"               },
  {ARPHRD_INFINIBAND,         "InfiniBand"                 },
  {ARPHRD_TIA_102_PRJ_25_CAI, "TIA-102 Project 25 CAI"     },
  {ARPHRD_WIEGAND_INTERFACE,  "Wiegand Interface"          },
  {ARPHRD_PURE_IP,            "Pure IP"                    },
  {ARPHRD_HW_EXP1,            "Experimental 1"             },
  {ARPHRD_HFI,                "HFI"                        },
  {ARPHRD_UB,                 "Unified Bus"                },
  {ARPHRD_HW_EXP2,            "Experimental 2"             },
  {ARPHRD_AETHERNET,          "AEthernet"                  },
  /* Virtual ARP types for non ARP hardware used in Linux cooked mode. */
  {ARPHRD_RSRVD,              "Notional KISS type"         },
  {ARPHRD_ADAPT,              "ADAPT"                      },
  {ARPHRD_ROSE,               "ROSE"                       },
  {ARPHRD_X25,                "CCITT X.25"                 },
  {ARPHRD_HWX25,              "Boards with X.25 in firmware"},
  {ARPHRD_CAN,                "Controller Area Network"    },
  {ARPHRD_PPP,                "PPP"                        },
  {ARPHRD_CISCO,              "Cisco HDLC"                 },
  {ARPHRD_LAPB,               "LAPB"                       },
  {ARPHRD_DDCMP,              "Digital's DDCMP protocol"   },
  {ARPHRD_RAWHDLC,            "Raw HDLC"                   },
  {ARPHRD_RAWIP,              "Raw IP"                     },

  {ARPHRD_TUNNEL,             "IPIP tunnel"                },
  {ARPHRD_TUNNEL6,            "IP6IP6 tunnel"              },
  {ARPHRD_FRAD,               "Frame Relay Access Device"  },
  {ARPHRD_SKIP,               "SKIP vif"                   },
  {ARPHRD_LOOPBACK,           "Loopback"                   },
  {ARPHRD_FDDI,               "Fiber Distributed Data Interface"},
  {ARPHRD_BIF,                "AP1000 BIF"                 },
  {ARPHRD_SIT,                "sit0 device - IPv6-in-IPv4" },
  {ARPHRD_IPDDP,              "IP over DDP tunneller"      },
  {ARPHRD_IPGRE,              "GRE over IP"                },
  {ARPHRD_PIMREG,             "PIMSM register interface"   },
  {ARPHRD_HIPPI,              "High Performance Parallel Interface"},
  {ARPHRD_ASH,                "Nexus 64Mbps Ash"           },
  {ARPHRD_ECONET,             "Acorn Econet"               },
  {ARPHRD_IRDA,               "Linux-IrDA"                 },
/* ARP works differently on different FC media .. so  */
  {ARPHRD_FCPP,               "Point to point fibrechannel" },
  {ARPHRD_FCAL,               "Fibrechannel arbitrated loop" },
  {ARPHRD_FCPL,               "Fibrechannel public loop"   },
  {ARPHRD_FCFABRIC, "Fibrechannel fabric"},
	/* 787->799 reserved for fibrechannel media types */
  {ARPHRD_IEEE802_TR,         "Magic type ident for TR"    },
  {ARPHRD_IEEE80211,          "IEEE 802.11"                },
  {ARPHRD_IEEE80211_PRISM,    "IEEE 802.11 + Prism2 header" },
  {ARPHRD_IEEE80211_RADIOTAP, "IEEE 802.11 + radiotap header" },
  {ARPHRD_IEEE802154,         "IEEE 802.15.4"              },
  {ARPHRD_IEEE802154_MONITOR, "IEEE 802.15.4 network monitor" },

  {ARPHRD_PHONET,             "PhoNet media type"          },
  {ARPHRD_PHONET_PIPE,        "PhoNet pipe header"         },
  {ARPHRD_CAIF,               "CAIF media type"            },
  {ARPHRD_IP6GRE,             "GRE over IPv6"              },
  {ARPHRD_NETLINK,            "Netlink"                    },
  {ARPHRD_6LOWPAN,            "IPv6 over LoWPAN"           },
  {ARPHRD_VSOCKMON,           "Vsock monitor header"       },

  {ARPHRD_VOID,               "Void type, nothing is known" },
  {ARPHRD_NONE,               "zero header length"         },
  {0, NULL                                                 }
};

/* Offsets of fields within an ARP packet. */
#define AR_HRD          0
#define AR_PRO          2
#define AR_HLN          4
#define AR_PLN          5
#define AR_OP           6
#define MIN_ARP_HEADER_SIZE     8

/* Offsets of fields within an ATMARP packet. */
#define ATM_AR_HRD       0
#define ATM_AR_PRO       2
#define ATM_AR_SHTL      4
#define ATM_AR_SSTL      5
#define ATM_AR_OP        6
#define ATM_AR_SPLN      8
#define ATM_AR_THTL      9
#define ATM_AR_TSTL     10
#define ATM_AR_TPLN     11
#define MIN_ATMARP_HEADER_SIZE  12

static void
dissect_atm_number(tvbuff_t *tvb, packet_info* pinfo, int offset, int tl, int hf_e164,
                   int hf_nsap, proto_tree *tree)
{
  int         len = tl & ATMARP_LEN_MASK;
  proto_item *ti;
  proto_tree *nsap_tree;

  if (tl & ATMARP_IS_E164)
    proto_tree_add_item(tree, hf_e164, tvb, offset, len, ENC_BIG_ENDIAN);
  else {
    ti = proto_tree_add_item(tree, hf_nsap, tvb, offset, len, ENC_BIG_ENDIAN);
    if (len >= 20) {
      nsap_tree = proto_item_add_subtree(ti, ett_atmarp_nsap);
      dissect_atm_nsap(tvb, pinfo, offset, len, nsap_tree);
    }
  }
}

static const value_string atm_nsap_afi_vals[] = {
    { NSAP_IDI_ISO_DCC_BIN,            "DCC ATM format"},
    { NSAP_IDI_ISO_DCC_BIN_GROUP,      "DCC ATM group format"},
    { NSAP_IDI_ISO_6523_ICD_BIN,       "ICD ATM format"},
    { NSAP_IDI_ISO_6523_ICD_BIN_GROUP, "ICD ATM group format"},
    { NSAP_IDI_E_164_BIN_FSD_NZ,       "E.164 ATM format"},
    { NSAP_IDI_E_164_BIN_FSD_NZ_GROUP, "E.164 ATM group format"},
    { 0,                               NULL}
};

/*
 * XXX - shouldn't there be a centralized routine for dissecting NSAPs?
 * See also "dissect_nsap()" in epan/dissectors/packet-isup.c and
 * "print_nsap_net()" in epan/osi-utils.c.
 */
void
dissect_atm_nsap(tvbuff_t *tvb, packet_info* pinfo, int offset, int len, proto_tree *tree)
{
  uint8_t afi;
  proto_item* ti;

  afi = tvb_get_uint8(tvb, offset);
  ti = proto_tree_add_item(tree, hf_atmarp_src_atm_afi, tvb, offset, 1, ENC_BIG_ENDIAN);
  switch (afi) {

    case NSAP_IDI_ISO_DCC_BIN:       /* DCC ATM format */
    case NSAP_IDI_ISO_DCC_BIN_GROUP: /* DCC ATM group format */
      proto_tree_add_item(tree, (afi == NSAP_IDI_ISO_DCC_BIN_GROUP) ? hf_atmarp_src_atm_data_country_code_group : hf_atmarp_src_atm_data_country_code,
                          tvb, offset + 1, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_atmarp_src_atm_high_order_dsp, tvb, offset + 3, 10, ENC_NA);
      proto_tree_add_item(tree, hf_atmarp_src_atm_end_system_identifier, tvb, offset + 13, 6, ENC_NA);
      proto_tree_add_item(tree, hf_atmarp_src_atm_selector, tvb, offset + 19, 1, ENC_BIG_ENDIAN);
      break;

    case NSAP_IDI_ISO_6523_ICD_BIN:       /* ICD ATM format */
    case NSAP_IDI_ISO_6523_ICD_BIN_GROUP: /* ICD ATM group format */
      proto_tree_add_item(tree, (afi == NSAP_IDI_ISO_6523_ICD_BIN_GROUP) ? hf_atmarp_src_atm_international_code_designator_group : hf_atmarp_src_atm_international_code_designator,
                          tvb, offset + 1, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_atmarp_src_atm_high_order_dsp, tvb, offset + 3, 10, ENC_NA);
      proto_tree_add_item(tree, hf_atmarp_src_atm_end_system_identifier, tvb, offset + 13, 6, ENC_NA);
      proto_tree_add_item(tree, hf_atmarp_src_atm_selector, tvb, offset + 19, 1, ENC_BIG_ENDIAN);
      break;

    case NSAP_IDI_E_164_BIN_FSD_NZ:       /* E.164 ATM format */
    case NSAP_IDI_E_164_BIN_FSD_NZ_GROUP: /* E.164 ATM group format */
      proto_tree_add_item(tree, (afi == NSAP_IDI_E_164_BIN_FSD_NZ_GROUP) ? hf_atmarp_src_atm_e_164_isdn_group : hf_atmarp_src_atm_e_164_isdn,
                          tvb, offset + 1, 8, ENC_NA);
      proto_tree_add_item(tree, hf_atmarp_src_atm_high_order_dsp, tvb, offset + 9, 4, ENC_NA);
      proto_tree_add_item(tree, hf_atmarp_src_atm_end_system_identifier, tvb, offset + 13, 6, ENC_NA);
      proto_tree_add_item(tree, hf_atmarp_src_atm_selector, tvb, offset + 19, 1, ENC_BIG_ENDIAN);
      break;

    default:
      expert_add_info(pinfo, ti, &ei_atmarp_src_atm_unknown_afi);
      proto_tree_add_item(tree, hf_atmarp_src_atm_rest_of_address, tvb, offset + 1, len - 1, ENC_NA);
      break;
  }
}

/* l.s. 32 bits are ipv4 address */
static unsigned
address_hash_func(const void *v)
{
  return GPOINTER_TO_UINT(v);
}

/* Compare 2 ipv4 addresses */
static int
address_equal_func(const void *v, const void *v2)
{
  return v == v2;
}

static unsigned
duplicate_result_hash_func(const void *v)
{
  const duplicate_result_key *key = (const duplicate_result_key*)v;
  return (key->frame_number + key->ip_address);
}

static int
duplicate_result_equal_func(const void *v, const void *v2)
{
  const duplicate_result_key *key1 = (const duplicate_result_key*)v;
  const duplicate_result_key *key2 = (const duplicate_result_key*)v2;

  return (memcmp(key1, key2, sizeof(duplicate_result_key)) == 0);
}




/* Check to see if this mac & ip pair represent 2 devices trying to share
   the same IP address - report if found (+ return true and set out param) */
static bool
check_for_duplicate_addresses(packet_info *pinfo, proto_tree *tree,
                                              tvbuff_t *tvb,
                                              const uint8_t *mac, uint32_t ip,
                                              uint32_t *duplicate_ip)
{
  address_hash_value   *value;
  address_hash_value   *result     = NULL;
  duplicate_result_key  result_key = {pinfo->num, ip};

  /* Look up existing result */
  if (pinfo->fd->visited) {
      result = (address_hash_value *)wmem_map_lookup(duplicate_result_hash_table,
                                   &result_key);
  }
  else {
      /* First time around, need to work out if represents duplicate and
         store result */

      /* Look up current assignment of IP address */
      value = (address_hash_value *)wmem_map_lookup(address_hash_table, GUINT_TO_POINTER(ip));

      /* If MAC matches table, just update details */
      if (value != NULL)
      {
        if (pinfo->num > value->frame_num)
        {
          if ((memcmp(value->mac, mac, 6) == 0))
          {
            /* Same MAC as before - update existing entry */
            value->frame_num = pinfo->num;
            value->time_of_entry = pinfo->abs_ts.secs;
          }
          else
          {
            /* Create result and store in result table */
            duplicate_result_key *persistent_key = wmem_new(wmem_file_scope(), duplicate_result_key);
            memcpy(persistent_key, &result_key, sizeof(duplicate_result_key));

            result = wmem_new(wmem_file_scope(), address_hash_value);
            memcpy(result, value, sizeof(address_hash_value));

            wmem_map_insert(duplicate_result_hash_table, persistent_key, result);
          }
        }
      }
      else
      {
        /* No existing entry. Prepare one */
        value = wmem_new(wmem_file_scope(), struct address_hash_value);
        memcpy(value->mac, mac, 6);
        value->frame_num = pinfo->num;
        value->time_of_entry = pinfo->abs_ts.secs;

        /* Add it */
        wmem_map_insert(address_hash_table, GUINT_TO_POINTER(ip), value);
      }
  }

  /* Add report to tree if we found a duplicate */
  if (result != NULL) {
    proto_tree *duplicate_tree;
    proto_item *ti;
    address mac_addr, result_mac_addr;

    set_address(&mac_addr, AT_ETHER, 6, mac);
    set_address(&result_mac_addr, AT_ETHER, 6, result->mac);

    /* Create subtree */
    duplicate_tree = proto_tree_add_subtree_format(tree, tvb, 0, 0, ett_arp_duplicate_address, &ti,
                                                "Duplicate IP address detected for %s (%s) - also in use by %s (frame %u)",
                                                arpproaddr_to_str(pinfo->pool, (uint8_t*)&ip, 4, ETHERTYPE_IP),
                                                address_to_str(pinfo->pool, &mac_addr),
                                                address_to_str(pinfo->pool, &result_mac_addr),
                                                result->frame_num);
    proto_item_set_generated(ti);

    /* Add item for navigating to earlier frame */
    ti = proto_tree_add_uint(duplicate_tree, hf_arp_duplicate_ip_address_earlier_frame,
                             tvb, 0, 0, result->frame_num);
    proto_item_set_generated(ti);
    expert_add_info_format(pinfo, ti,
                           &ei_seq_arp_dup_ip,
                           "Duplicate IP address configured (%s)",
                           arpproaddr_to_str(pinfo->pool, (uint8_t*)&ip, 4, ETHERTYPE_IP));

    /* Time since that frame was seen */
    ti = proto_tree_add_uint(duplicate_tree,
                             hf_arp_duplicate_ip_address_seconds_since_earlier_frame,
                             tvb, 0, 0,
                             (uint32_t)(pinfo->abs_ts.secs - result->time_of_entry));
    proto_item_set_generated(ti);

    /* Set out parameter */
    *duplicate_ip = ip;
  }


  return (result != NULL);
}



/* Take note that a request has been seen */
static void
request_seen(packet_info *pinfo)
{
  /* Don't count frame again after already recording first time around. */
  if (p_get_proto_data(wmem_file_scope(), pinfo, proto_arp, 0) == 0)
  {
    arp_request_count++;
  }
}

/* Has storm request rate been exceeded with this request? */
static void
check_for_storm_count(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  bool report_storm = false;

  if (p_get_proto_data(wmem_file_scope(), pinfo, proto_arp, 0) != 0)
  {
    /* Read any previous stored packet setting */
    report_storm = (p_get_proto_data(wmem_file_scope(), pinfo, proto_arp, 0) == (void*)STORM);
  }
  else
  {
    /* Seeing packet for first time - check against preference settings */
    int seconds_delta  = (int) (pinfo->abs_ts.secs - time_at_start_of_count.secs);
    int nseconds_delta = pinfo->abs_ts.nsecs - time_at_start_of_count.nsecs;
    int gap = (seconds_delta*1000) + (nseconds_delta / 1000000);

    /* Reset if gap exceeds period or -ve gap (indicates we're rescanning from start) */
    if ((gap > (int)global_arp_detect_request_storm_period) ||
        (gap < 0))
    {
      /* Time period elapsed without threshold being exceeded */
      arp_request_count = 1;
      time_at_start_of_count = pinfo->abs_ts;
      p_add_proto_data(wmem_file_scope(), pinfo, proto_arp, 0, (void*)NO_STORM);
      return;
    }
    else
      if (arp_request_count > global_arp_detect_request_storm_packets)
      {
        /* Storm detected, record and reset start time. */
        report_storm = true;
        p_add_proto_data(wmem_file_scope(), pinfo, proto_arp, 0, (void*)STORM);
        time_at_start_of_count = pinfo->abs_ts;
      }
      else
      {
        /* Threshold not exceeded yet - no storm */
        p_add_proto_data(wmem_file_scope(), pinfo, proto_arp, 0, (void*)NO_STORM);
      }
  }

  if (report_storm)
  {
    /* Report storm and reset counter */
    proto_tree_add_expert_format(tree, pinfo, &ei_seq_arp_storm, tvb, 0, 0,
                           "ARP packet storm detected (%u packets in < %u ms)",
                           global_arp_detect_request_storm_packets,
                           global_arp_detect_request_storm_period);
    arp_request_count = 0;
  }
}


/*
 * RFC 2225 ATMARP - it's just like ARP, except where it isn't.
 */
static int
dissect_atmarp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  uint16_t      ar_hrd;
  uint16_t      ar_pro;
  uint8_t       ar_shtl;
  uint8_t       ar_shl;
  uint8_t       ar_sstl;
  uint8_t       ar_ssl;
  uint16_t      ar_op;
  uint8_t       ar_spln;
  uint8_t       ar_thtl;
  uint8_t       ar_thl;
  uint8_t       ar_tstl;
  uint8_t       ar_tsl;
  uint8_t       ar_tpln;
  int           tot_len;
  proto_tree   *arp_tree;
  proto_item   *ti;
  const char   *op_str;
  int           sha_offset, ssa_offset, spa_offset;
  int           tha_offset, tsa_offset, tpa_offset;
  const char   *sha_str, *ssa_str, *spa_str;
  const char   *tha_str, *tsa_str, *tpa_str;
  proto_tree   *tl_tree;

  ar_hrd = tvb_get_ntohs(tvb, ATM_AR_HRD);
  ar_pro = tvb_get_ntohs(tvb, ATM_AR_PRO);
  ar_shtl = tvb_get_uint8(tvb, ATM_AR_SHTL);
  ar_shl = ar_shtl & ATMARP_LEN_MASK;
  ar_sstl = tvb_get_uint8(tvb, ATM_AR_SSTL);
  ar_ssl = ar_sstl & ATMARP_LEN_MASK;
  ar_op  = tvb_get_ntohs(tvb, AR_OP);
  ar_spln = tvb_get_uint8(tvb, ATM_AR_SPLN);
  ar_thtl = tvb_get_uint8(tvb, ATM_AR_THTL);
  ar_thl = ar_thtl & ATMARP_LEN_MASK;
  ar_tstl = tvb_get_uint8(tvb, ATM_AR_TSTL);
  ar_tsl = ar_tstl & ATMARP_LEN_MASK;
  ar_tpln = tvb_get_uint8(tvb, ATM_AR_TPLN);

  tot_len = MIN_ATMARP_HEADER_SIZE + ar_shl + ar_ssl + ar_spln +
    ar_thl + ar_tsl + ar_tpln;

  /* Adjust the length of this tvbuff to include only the ARP datagram.
     Our caller may use that to determine how much of its packet
     was padding. */
  tvb_set_reported_length(tvb, tot_len);

  /* Extract the addresses.  */
  sha_offset = MIN_ATMARP_HEADER_SIZE;
  sha_str = atmarpnum_to_str(pinfo->pool, tvb, sha_offset, ar_shtl);

  ssa_offset = sha_offset + ar_shl;
  if (ar_ssl != 0) {
    ssa_str = atmarpsubaddr_to_str(pinfo->pool, tvb, ssa_offset, ar_sstl);
  } else {
    ssa_str = NULL;
  }

  spa_offset = ssa_offset + ar_ssl;
  spa_str = tvb_arpproaddr_to_str(pinfo->pool, tvb, spa_offset, ar_spln, ar_pro);

  tha_offset = spa_offset + ar_spln;
  tha_str = atmarpnum_to_str(pinfo->pool, tvb, tha_offset, ar_thtl);

  tsa_offset = tha_offset + ar_thl;
  if (ar_tsl != 0) {
    tsa_str = atmarpsubaddr_to_str(pinfo->pool, tvb, tsa_offset, ar_tstl);
  } else {
    tsa_str = NULL;
  }

  tpa_offset = tsa_offset + ar_tsl;
  tpa_str = tvb_arpproaddr_to_str(pinfo->pool, tvb, tpa_offset, ar_tpln, ar_pro);

  switch (ar_op) {

  case ARPOP_REQUEST:
  case ARPOP_REPLY:
  case ATMARPOP_NAK:
  default:
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ATMARP");
    break;

  case ARPOP_RREQUEST:
  case ARPOP_RREPLY:
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ATMRARP");
    break;

  case ARPOP_IREQUEST:
  case ARPOP_IREPLY:
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Inverse ATMARP");
    break;

  case ARPOP_MARS_REQUEST:
  case ARPOP_MARS_MULTI:
  case ARPOP_MARS_MSERV:
  case ARPOP_MARS_JOIN:
  case ARPOP_MARS_LEAVE:
  case ARPOP_MARS_NAK:
  case ARPOP_MARS_UNSERV:
  case ARPOP_MARS_SJOIN:
  case ARPOP_MARS_SLEAVE:
  case ARPOP_MARS_GROUPLIST_REQUEST:
  case ARPOP_MARS_GROUPLIST_REPLY:
  case ARPOP_MARS_REDIRECT_MAP:
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MARS");
    break;

  case ARPOP_MAPOS_UNARP:
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MAPOS");
    break;

  }

  switch (ar_op) {
  case ARPOP_REQUEST:
    col_add_fstr(pinfo->cinfo, COL_INFO, "Who has %s? Tell %s",
                 tpa_str, spa_str);
    break;
  case ARPOP_REPLY:
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s is at %s%s%s", spa_str, sha_str,
                 ((ssa_str != NULL) ? "," : ""),
                 ((ssa_str != NULL) ? ssa_str : ""));
    break;
  case ARPOP_IREQUEST:
    col_add_fstr(pinfo->cinfo, COL_INFO, "Who is %s%s%s? Tell %s%s%s",
                 tha_str,
                 ((tsa_str != NULL) ? "," : ""),
                 ((tsa_str != NULL) ? tsa_str : ""),
                 sha_str,
                 ((ssa_str != NULL) ? "," : ""),
                 ((ssa_str != NULL) ? ssa_str : ""));
    break;
  case ARPOP_IREPLY:
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s%s%s is at %s",
                 sha_str,
                 ((ssa_str != NULL) ? "," : ""),
                 ((ssa_str != NULL) ? ssa_str : ""),
                 spa_str);
    break;
  case ATMARPOP_NAK:
    col_add_fstr(pinfo->cinfo, COL_INFO, "I don't know where %s is", spa_str);
    break;
  case ARPOP_MARS_REQUEST:
    col_add_fstr(pinfo->cinfo, COL_INFO, "MARS request from %s%s%s at %s",
                 sha_str,
                 ((ssa_str != NULL) ? "," : ""),
                 ((ssa_str != NULL) ? ssa_str : ""),
                 spa_str);
    break;

  case ARPOP_MARS_MULTI:
    col_add_fstr(pinfo->cinfo, COL_INFO, "MARS MULTI request from %s%s%s at %s",
                 sha_str,
                 ((ssa_str != NULL) ? "," : ""),
                 ((ssa_str != NULL) ? ssa_str : ""),
                 spa_str);
    break;

  case ARPOP_MARS_MSERV:
    col_add_fstr(pinfo->cinfo, COL_INFO, "MARS MSERV request from %s%s%s at %s",
                 sha_str,
                 ((ssa_str != NULL) ? "," : ""),
                 ((ssa_str != NULL) ? ssa_str : ""),
                 spa_str);
    break;

  case ARPOP_MARS_JOIN:
    col_add_fstr(pinfo->cinfo, COL_INFO, "MARS JOIN request from %s%s%s at %s",
                 sha_str,
                 ((ssa_str != NULL) ? "," : ""),
                 ((ssa_str != NULL) ? ssa_str : ""),
                 spa_str);
    break;

  case ARPOP_MARS_LEAVE:
    col_add_fstr(pinfo->cinfo, COL_INFO, "MARS LEAVE from %s%s%s at %s",
                 sha_str,
                 ((ssa_str != NULL) ? "," : ""),
                 ((ssa_str != NULL) ? ssa_str : ""),
                 spa_str);
    break;

  case ARPOP_MARS_NAK:
    col_add_fstr(pinfo->cinfo, COL_INFO, "MARS NAK from %s%s%s at %s",
                 sha_str,
                 ((ssa_str != NULL) ? "," : ""),
                 ((ssa_str != NULL) ? ssa_str : ""),
                 spa_str);
    break;

  case ARPOP_MARS_UNSERV:
    col_add_fstr(pinfo->cinfo, COL_INFO, "MARS UNSERV request from %s%s%s at %s",
                 sha_str,
                 ((ssa_str != NULL) ? "," : ""),
                 ((ssa_str != NULL) ? ssa_str : ""),
                 spa_str);
    break;

  case ARPOP_MARS_SJOIN:
    col_add_fstr(pinfo->cinfo, COL_INFO, "MARS SJOIN request from %s%s%s at %s",
                 sha_str,
                 ((ssa_str != NULL) ? "," : ""),
                 ((ssa_str != NULL) ? ssa_str : ""),
                 spa_str);
    break;

  case ARPOP_MARS_SLEAVE:
    col_add_fstr(pinfo->cinfo, COL_INFO, "MARS SLEAVE from %s%s%s at %s",
                 sha_str,
                 ((ssa_str != NULL) ? "," : ""),
                 ((ssa_str != NULL) ? ssa_str : ""),
                 spa_str);
    break;

  case ARPOP_MARS_GROUPLIST_REQUEST:
    col_add_fstr(pinfo->cinfo, COL_INFO, "MARS grouplist request from %s%s%s at %s",
                 sha_str,
                 ((ssa_str != NULL) ? "," : ""),
                 ((ssa_str != NULL) ? ssa_str : ""),
                 spa_str);
    break;

  case ARPOP_MARS_GROUPLIST_REPLY:
    col_add_fstr(pinfo->cinfo, COL_INFO, "MARS grouplist reply from %s%s%s at %s",
                 sha_str,
                 ((ssa_str != NULL) ? "," : ""),
                 ((ssa_str != NULL) ? ssa_str : ""),
                 spa_str);
    break;

  case ARPOP_MARS_REDIRECT_MAP:
    col_add_fstr(pinfo->cinfo, COL_INFO, "MARS redirect map from %s%s%s at %s",
                 sha_str,
                 ((ssa_str != NULL) ? "," : ""),
                 ((ssa_str != NULL) ? ssa_str : ""),
                 spa_str);
    break;

  case ARPOP_MAPOS_UNARP:
    col_add_fstr(pinfo->cinfo, COL_INFO, "MAPOS UNARP request from %s%s%s at %s",
                 sha_str,
                 ((ssa_str != NULL) ? "," : ""),
                 ((ssa_str != NULL) ? ssa_str : ""),
                 spa_str);
    break;

  case ARPOP_EXP1:
    col_add_fstr(pinfo->cinfo, COL_INFO, "Experimental 1 ( opcode %d )", ar_op);
    break;

  case ARPOP_EXP2:
    col_add_fstr(pinfo->cinfo, COL_INFO, "Experimental 2 ( opcode %d )", ar_op);
    break;

  case 0:
  case 65535:
    col_add_fstr(pinfo->cinfo, COL_INFO, "Reserved opcode %d", ar_op);
    break;

  default:
    col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown ATMARP opcode 0x%04x", ar_op);
    break;
  }

  if (tree) {
    if ((op_str = try_val_to_str(ar_op, atmop_vals)))
      ti = proto_tree_add_protocol_format(tree, proto_arp, tvb, 0, tot_len,
                                          "ATM Address Resolution Protocol (%s)",
                                          op_str);
    else
      ti = proto_tree_add_protocol_format(tree, proto_arp, tvb, 0, tot_len,
                                          "ATM Address Resolution Protocol (opcode 0x%04x)", ar_op);
    arp_tree = proto_item_add_subtree(ti, ett_arp);

    proto_tree_add_uint(arp_tree, hf_arp_hard_type, tvb, ATM_AR_HRD, 2, ar_hrd);

    proto_tree_add_uint(arp_tree, hf_arp_proto_type, tvb, ATM_AR_PRO, 2,ar_pro);

    tl_tree = proto_tree_add_subtree_format(arp_tree, tvb, ATM_AR_SHTL, 1,
                             ett_atmarp_tl, NULL,
                             "Sender ATM number type/length: %s/%u",
                             (ar_shtl & ATMARP_IS_E164) ?
                                  "E.164" :
                                  "ATM Forum NSAPA",
                             ar_shl);
    proto_tree_add_boolean(tl_tree, hf_atmarp_sht, tvb, ATM_AR_SHTL, 1, ar_shtl);
    proto_tree_add_uint(tl_tree, hf_atmarp_shl, tvb, ATM_AR_SHTL, 1, ar_shtl);

    tl_tree = proto_tree_add_subtree_format(arp_tree, tvb, ATM_AR_SSTL, 1,
                             ett_atmarp_tl, NULL,
                             "Sender ATM subaddress type/length: %s/%u",
                             (ar_sstl & ATMARP_IS_E164) ?
                                  "E.164" :
                                  "ATM Forum NSAPA",
                             ar_ssl);
    proto_tree_add_boolean(tl_tree, hf_atmarp_sst, tvb, ATM_AR_SSTL, 1, ar_sstl);
    proto_tree_add_uint(tl_tree, hf_atmarp_ssl, tvb, ATM_AR_SSTL, 1, ar_sstl);

    proto_tree_add_uint(arp_tree, hf_arp_opcode, tvb, AR_OP,  2, ar_op);


    proto_tree_add_uint(arp_tree, hf_atmarp_spln, tvb, ATM_AR_SPLN, 1, ar_spln);

    tl_tree = proto_tree_add_subtree_format(arp_tree, tvb, ATM_AR_THTL, 1,
                             ett_atmarp_tl, NULL,
                             "Target ATM number type/length: %s/%u",
                             (ar_thtl & ATMARP_IS_E164) ?
                                  "E.164" :
                                  "ATM Forum NSAPA",
                             ar_thl);
    proto_tree_add_boolean(tl_tree, hf_atmarp_tht, tvb, ATM_AR_THTL, 1, ar_thtl);
    proto_tree_add_uint(tl_tree, hf_atmarp_thl, tvb, ATM_AR_THTL, 1, ar_thtl);

    tl_tree = proto_tree_add_subtree_format(arp_tree, tvb, ATM_AR_TSTL, 1,
                             ett_atmarp_tl, NULL,
                             "Target ATM subaddress type/length: %s/%u",
                             (ar_tstl & ATMARP_IS_E164) ?
                                  "E.164" :
                                  "ATM Forum NSAPA",
                             ar_tsl);
    proto_tree_add_boolean(tl_tree, hf_atmarp_tst, tvb, ATM_AR_TSTL, 1, ar_tstl);
    proto_tree_add_uint(tl_tree, hf_atmarp_tsl, tvb, ATM_AR_TSTL, 1, ar_tstl);

    proto_tree_add_uint(arp_tree, hf_atmarp_tpln, tvb, ATM_AR_TPLN, 1, ar_tpln);

    if (ar_shl != 0)
      dissect_atm_number(tvb, pinfo, sha_offset, ar_shtl, hf_atmarp_src_atm_num_e164,
                         hf_atmarp_src_atm_num_nsap, arp_tree);

    if (ar_ssl != 0)
      proto_tree_add_bytes_format_value(arp_tree, hf_atmarp_src_atm_subaddr, tvb, ssa_offset,
                                  ar_ssl, NULL, "%s", ssa_str);

    if (ar_spln != 0) {
      proto_tree_add_item(arp_tree,
                          ARP_PRO_IS_IPv4(ar_pro, ar_spln) ? hf_arp_src_proto_ipv4
                          : hf_arp_src_proto,
                          tvb, spa_offset, ar_spln, ENC_BIG_ENDIAN);
    }

    if (ar_thl != 0)
      dissect_atm_number(tvb, pinfo, tha_offset, ar_thtl, hf_atmarp_dst_atm_num_e164,
                         hf_atmarp_dst_atm_num_nsap, arp_tree);

    if (ar_tsl != 0)
      proto_tree_add_bytes_format_value(arp_tree, hf_atmarp_dst_atm_subaddr, tvb, tsa_offset,
                                  ar_tsl, NULL, "%s", tsa_str);

    if (ar_tpln != 0) {
      proto_tree_add_item(arp_tree,
                          ARP_PRO_IS_IPv4(ar_pro, ar_tpln) ? hf_arp_dst_proto_ipv4
                          : hf_arp_dst_proto,
                          tvb, tpa_offset, ar_tpln, ENC_BIG_ENDIAN);
    }
  }
  return tvb_captured_length(tvb);
}

/*
 * AX.25 ARP - it's just like ARP, except where it isn't.
 */
static int
dissect_ax25arp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
#define ARP_AX25 204

  uint16_t     ar_hrd;
  uint16_t     ar_pro;
  uint8_t      ar_hln;
  uint8_t      ar_pln;
  uint16_t     ar_op;
  int          tot_len;
  proto_tree  *arp_tree = NULL;
  proto_item  *ti;
  const char *op_str;
  int          sha_offset, spa_offset, tha_offset, tpa_offset;
  const char *spa_str, *tpa_str;
  bool         is_gratuitous;

  /* Hardware Address Type */
  ar_hrd = tvb_get_ntohs(tvb, AR_HRD);
  /* Protocol Address Type */
  ar_pro = tvb_get_ntohs(tvb, AR_PRO);
  /* Hardware Address Size */
  ar_hln = tvb_get_uint8(tvb, AR_HLN);
  /* Protocol Address Size */
  ar_pln = tvb_get_uint8(tvb, AR_PLN);
  /* Operation */
  ar_op  = tvb_get_ntohs(tvb, AR_OP);

  tot_len = MIN_ARP_HEADER_SIZE + ar_hln*2 + ar_pln*2;

  /* Adjust the length of this tvbuff to include only the ARP datagram.
     Our caller may use that to determine how much of its packet
     was padding. */
  tvb_set_reported_length(tvb, tot_len);

  switch (ar_op) {

  case ARPOP_REQUEST:
    if (global_arp_detect_request_storm)
      request_seen(pinfo);
      /* fall-through */
  case ARPOP_REPLY:
  default:
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ARP");
    break;

  case ARPOP_RREQUEST:
  case ARPOP_RREPLY:
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RARP");
    break;

  case ARPOP_IREQUEST:
  case ARPOP_IREPLY:
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Inverse ARP");
    break;
  }

  /* Get the offsets of the addresses. */
  /* Source Hardware Address */
  sha_offset = MIN_ARP_HEADER_SIZE;
  /* Source Protocol Address */
  spa_offset = sha_offset + ar_hln;
  /* Target Hardware Address */
  tha_offset = spa_offset + ar_pln;
  /* Target Protocol Address */
  tpa_offset = tha_offset + ar_hln;

  spa_str = tvb_arpproaddr_to_str(pinfo->pool, tvb, spa_offset, ar_pln, ar_pro);
  tpa_str = tvb_arpproaddr_to_str(pinfo->pool, tvb, tpa_offset, ar_pln, ar_pro);

  /* ARP requests/replies with the same sender and target protocol
     address are flagged as "gratuitous ARPs", i.e. ARPs sent out as,
     in effect, an announcement that the machine has MAC address
     XX:XX:XX:XX:XX:XX and IPv4 address YY.YY.YY.YY. Requests are to
     provoke complaints if some other machine has the same IPv4 address,
     replies are used to announce relocation of network address, like
     in failover solutions. */
  if (((ar_op == ARPOP_REQUEST) || (ar_op == ARPOP_REPLY)) && (strcmp(spa_str, tpa_str) == 0))
    is_gratuitous = true;
  else
    is_gratuitous = false;

  switch (ar_op) {
    case ARPOP_REQUEST:
      if (is_gratuitous)
        col_add_fstr(pinfo->cinfo, COL_INFO, "Gratuitous ARP for %s (Request)", tpa_str);
      else
        col_add_fstr(pinfo->cinfo, COL_INFO, "Who has %s? Tell %s", tpa_str, spa_str);
      break;
    case ARPOP_REPLY:
      if (is_gratuitous)
        col_add_fstr(pinfo->cinfo, COL_INFO, "Gratuitous ARP for %s (Reply)", spa_str);
      else
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s is at %s",
                     spa_str,
                     tvb_arphrdaddr_to_str(pinfo->pool, tvb, sha_offset, ar_hln, ar_hrd));
      break;
    case ARPOP_RREQUEST:
    case ARPOP_IREQUEST:
      col_add_fstr(pinfo->cinfo, COL_INFO, "Who is %s? Tell %s",
                   tvb_arphrdaddr_to_str(pinfo->pool, tvb, tha_offset, ar_hln, ar_hrd),
                   tvb_arphrdaddr_to_str(pinfo->pool, tvb, sha_offset, ar_hln, ar_hrd));
      break;
    case ARPOP_RREPLY:
      col_add_fstr(pinfo->cinfo, COL_INFO, "%s is at %s",
                   tvb_arphrdaddr_to_str(pinfo->pool, tvb, tha_offset, ar_hln, ar_hrd),
                   tpa_str);
      break;
    case ARPOP_IREPLY:
      col_add_fstr(pinfo->cinfo, COL_INFO, "%s is at %s",
                   tvb_arphrdaddr_to_str(pinfo->pool, tvb, sha_offset, ar_hln, ar_hrd),
                   spa_str);
      break;
    default:
      col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown ARP opcode 0x%04x", ar_op);
      break;
  }

  if (tree) {
    if ((op_str = try_val_to_str(ar_op, op_vals))) {
      if (is_gratuitous && (ar_op == ARPOP_REQUEST))
        op_str = "request/gratuitous ARP";
      if (is_gratuitous && (ar_op == ARPOP_REPLY))
        op_str = "reply/gratuitous ARP";
      ti = proto_tree_add_protocol_format(tree, proto_arp, tvb, 0, tot_len,
                                        "Address Resolution Protocol (%s)", op_str);
    } else
      ti = proto_tree_add_protocol_format(tree, proto_arp, tvb, 0, tot_len,
                                      "Address Resolution Protocol (opcode 0x%04x)", ar_op);
    arp_tree = proto_item_add_subtree(ti, ett_arp);
    proto_tree_add_uint(arp_tree, hf_arp_hard_type, tvb, AR_HRD, 2, ar_hrd);
    proto_tree_add_uint(arp_tree, hf_arp_proto_type, tvb, AR_PRO, 2, ar_pro);
    proto_tree_add_uint(arp_tree, hf_arp_hard_size, tvb, AR_HLN, 1, ar_hln);
    proto_tree_add_uint(arp_tree, hf_arp_proto_size, tvb, AR_PLN, 1, ar_pln);
    proto_tree_add_uint(arp_tree, hf_arp_opcode, tvb, AR_OP,  2, ar_op);
    if (ar_hln != 0) {
      proto_tree_add_item(arp_tree,
        ARP_HW_IS_AX25(ar_hrd, ar_hln) ? hf_arp_src_hw_ax25 : hf_arp_src_hw,
        tvb, sha_offset, ar_hln, false);
    }
    if (ar_pln != 0) {
      proto_tree_add_item(arp_tree,
        ARP_PRO_IS_IPv4(ar_pro, ar_pln) ? hf_arp_src_proto_ipv4
                                        : hf_arp_src_proto,
        tvb, spa_offset, ar_pln, false);
    }
    if (ar_hln != 0) {
      proto_tree_add_item(arp_tree,
        ARP_HW_IS_AX25(ar_hrd, ar_hln) ? hf_arp_dst_hw_ax25 : hf_arp_dst_hw,
        tvb, tha_offset, ar_hln, false);
    }
    if (ar_pln != 0) {
      proto_tree_add_item(arp_tree,
        ARP_PRO_IS_IPv4(ar_pro, ar_pln) ? hf_arp_dst_proto_ipv4
                                        : hf_arp_dst_proto,
        tvb, tpa_offset, ar_pln, false);
    }
  }

  if (global_arp_detect_request_storm)
  {
    check_for_storm_count(tvb, pinfo, arp_tree);
  }
  return tvb_captured_length(tvb);
}

static bool
capture_arp(const unsigned char *pd _U_, int offset _U_, int len _U_, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header _U_)
{
  capture_dissector_increment_count(cpinfo, proto_arp);
  return true;
}

static const uint8_t mac_allzero[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

static int
dissect_arp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  uint16_t      ar_hrd;
  uint32_t      ar_pro, ar_hln, ar_pln, ar_op;
  int           tot_len;
  proto_tree   *arp_tree;
  proto_item   *arp_item, *item;
  const char   *op_str;
  int           sha_offset, spa_offset, tha_offset, tpa_offset;
  bool          is_gratuitous, is_probe = false, is_announcement = false;
  bool          duplicate_detected = false;
  uint32_t      duplicate_ip       = 0;
  dissector_handle_t hw_handle;

  /* Call it ARP, for now, so that if we throw an exception before
     we decide whether it's ARP or RARP or IARP or ATMARP, it shows
     up in the packet list as ARP.

     Clear the Info column so that, if we throw an exception, it
     shows up as a short or malformed ARP frame. */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ARP");
  col_clear(pinfo->cinfo, COL_INFO);

  /* Hardware Address Type */
  ar_hrd = tvb_get_ntohs(tvb, AR_HRD);

  /* See if there is a hardware type already registered */
  hw_handle = dissector_get_uint_handle(arp_hw_table, ar_hrd);
  if (hw_handle != NULL) {
    call_dissector(hw_handle, tvb, pinfo, tree);
    return tvb_captured_length(tvb);
  }

  /* Otherwise dissect as Ethernet hardware */

  arp_item = proto_tree_add_item(tree, proto_arp, tvb, 0, -1, ENC_NA);
  arp_tree = proto_item_add_subtree(arp_item, ett_arp);

  proto_tree_add_uint(arp_tree, hf_arp_hard_type, tvb, AR_HRD, 2, ar_hrd);
  /* Protocol Address Type */
  proto_tree_add_item_ret_uint(arp_tree, hf_arp_proto_type, tvb, AR_PRO, 2, ENC_BIG_ENDIAN, &ar_pro);
  /* Hardware Address Size */
  proto_tree_add_item_ret_uint(arp_tree, hf_arp_hard_size, tvb, AR_HLN, 1, ENC_NA, &ar_hln);
  /* Protocol Address Size */
  proto_tree_add_item_ret_uint(arp_tree, hf_arp_proto_size, tvb, AR_PLN, 1, ENC_NA, &ar_pln);
  /* Operation */
  proto_tree_add_item_ret_uint(arp_tree, hf_arp_opcode, tvb, AR_OP, 2, ENC_BIG_ENDIAN, &ar_op);

  tot_len = MIN_ARP_HEADER_SIZE + ar_hln*2 + ar_pln*2;
  proto_item_set_len(arp_item, tot_len);

  /* Adjust the length of this tvbuff to include only the ARP datagram.
     Our caller may use that to determine how much of its packet
     was padding. */
  tvb_set_reported_length(tvb, tot_len);

  switch (ar_op) {

    case ARPOP_REQUEST:
      if (global_arp_detect_request_storm)
      {
        request_seen(pinfo);
      }
      /* FALLTHRU */
    case ARPOP_REPLY:
    default:
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "ARP");
      break;

    case ARPOP_RREQUEST:
    case ARPOP_RREPLY:
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "RARP");
      break;

    case ARPOP_DRARPREQUEST:
    case ARPOP_DRARPREPLY:
    case ARPOP_DRARPERROR:
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "DRARP");
      break;

    case ARPOP_IREQUEST:
    case ARPOP_IREPLY:
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "Inverse ARP");
      break;

   case ARPOP_MARS_REQUEST:
   case ARPOP_MARS_MULTI:
   case ARPOP_MARS_MSERV:
   case ARPOP_MARS_JOIN:
   case ARPOP_MARS_LEAVE:
   case ARPOP_MARS_NAK:
   case ARPOP_MARS_UNSERV:
   case ARPOP_MARS_SJOIN:
   case ARPOP_MARS_SLEAVE:
   case ARPOP_MARS_GROUPLIST_REQUEST:
   case ARPOP_MARS_GROUPLIST_REPLY:
   case ARPOP_MARS_REDIRECT_MAP:
     col_set_str(pinfo->cinfo, COL_PROTOCOL, "MARS");
     break;

   case ARPOP_MAPOS_UNARP:
     col_set_str(pinfo->cinfo, COL_PROTOCOL, "MAPOS");
     break;
  }

  /* Get the offsets of the addresses. */
  /* Source Hardware Address */
  sha_offset = MIN_ARP_HEADER_SIZE;
  /* Source Protocol Address */
  spa_offset = sha_offset + ar_hln;
  /* Target Hardware Address */
  tha_offset = spa_offset + ar_pln;
  /* Target Protocol Address */
  tpa_offset = tha_offset + ar_hln;

  if ((ar_op == ARPOP_REPLY || ar_op == ARPOP_REQUEST) &&
      ARP_HW_IS_ETHER(ar_hrd, ar_hln) &&
      ARP_PRO_IS_IPv4(ar_pro, ar_pln)) {

    /* inform resolv.c module of the new discovered addresses */

    uint32_t ip;
    const uint8_t *mac;

    /* Add sender address if sender MAC address is neither a broadcast/
       multicast address nor an all-zero address and if sender IP address
       isn't all zeroes. */
    ip = tvb_get_ipv4(tvb, spa_offset);
    mac = (const uint8_t*)tvb_memdup(pinfo->pool, tvb, sha_offset, 6);
    if ((mac[0] & 0x01) == 0 && memcmp(mac, mac_allzero, 6) != 0 && ip != 0)
    {
      if (global_arp_register_network_address_binding)
      {
        add_ether_byip(ip, mac);
      }
      if (global_arp_detect_duplicate_ip_addresses)
      {
        duplicate_detected =
          check_for_duplicate_addresses(pinfo, tree, tvb, mac, ip,
                                        &duplicate_ip);
      }
    }

    /* Add target address if target MAC address is neither a broadcast/
       multicast address nor an all-zero address and if target IP address
       isn't all zeroes. */

    /* Do not add target address if the packet is a Request. According to the RFC,
       target addresses in requests have no meaning */


    ip = tvb_get_ipv4(tvb, tpa_offset);
    mac = (const uint8_t*)tvb_memdup(pinfo->pool, tvb, tha_offset, 6);
    if ((mac[0] & 0x01) == 0 && memcmp(mac, mac_allzero, 6) != 0 && ip != 0
        && ar_op != ARPOP_REQUEST)
    {
      if (global_arp_register_network_address_binding)
      {
        add_ether_byip(ip, mac);
      }
      /* If Gratuitous, don't report duplicate for same IP address twice */
      if (global_arp_detect_duplicate_ip_addresses && (duplicate_ip!=ip))
      {
        duplicate_detected =
          check_for_duplicate_addresses(pinfo, tree, tvb, mac, ip,
                                        &duplicate_ip);
      }
    }


  }

  /* ARP requests/replies with the same sender and target protocol
     address are flagged as "gratuitous ARPs", i.e. ARPs sent out as,
     in effect, an announcement that the machine has MAC address
     XX:XX:XX:XX:XX:XX and IPv4 address YY.YY.YY.YY. Requests are to
     provoke complaints if some other machine has the same IPv4 address,
     replies are used to announce relocation of network address, like
     in failover solutions. */
  if (((ar_op == ARPOP_REQUEST) || (ar_op == ARPOP_REPLY)) &&
      (tvb_memeql(tvb, spa_offset, tvb_get_ptr(tvb, tpa_offset, ar_pln), ar_pln) == 0)) {
    is_gratuitous = true;
    if ((ar_op == ARPOP_REQUEST) && (tvb_memeql(tvb, tha_offset, mac_allzero, 6) == 0))
      is_announcement = true;
  }
  else {
    is_gratuitous = false;
    if ((ar_op == ARPOP_REQUEST) && (tvb_memeql(tvb, tha_offset, mac_allzero, 6) == 0) && (tvb_get_ipv4(tvb, spa_offset) == 0))
      is_probe = true;
  }
  switch (ar_op) {
    case ARPOP_REQUEST:
      if (is_gratuitous) {
        if (is_announcement) {
          col_add_fstr(pinfo->cinfo, COL_INFO, "ARP Announcement for %s",
                     tvb_arpproaddr_to_str(pinfo->pool, tvb, tpa_offset, ar_pln, ar_pro));
        } else {
          col_add_fstr(pinfo->cinfo, COL_INFO, "Gratuitous ARP for %s (Request)",
                     tvb_arpproaddr_to_str(pinfo->pool, tvb, tpa_offset, ar_pln, ar_pro));
        }
      }
      else if (is_probe) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Who has %s? (ARP Probe)",
                     tvb_arpproaddr_to_str(pinfo->pool, tvb, tpa_offset, ar_pln, ar_pro));
      } else {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Who has %s? Tell %s",
          tvb_arpproaddr_to_str(pinfo->pool, tvb, tpa_offset, ar_pln, ar_pro),
          tvb_arpproaddr_to_str(pinfo->pool, tvb, spa_offset, ar_pln, ar_pro));
      }
      break;
    case ARPOP_REPLY:
      if (is_gratuitous)
        col_add_fstr(pinfo->cinfo, COL_INFO, "Gratuitous ARP for %s (Reply)",
                     tvb_arpproaddr_to_str(pinfo->pool, tvb, spa_offset, ar_pln, ar_pro));
      else
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s is at %s",
                     tvb_arpproaddr_to_str(pinfo->pool, tvb, spa_offset, ar_pln, ar_pro),
                     tvb_arphrdaddr_to_str(pinfo->pool, tvb, sha_offset, ar_hln, ar_hrd));
      break;
    case ARPOP_RREQUEST:
    case ARPOP_IREQUEST:
    case ARPOP_DRARPREQUEST:
      col_add_fstr(pinfo->cinfo, COL_INFO, "Who is %s? Tell %s",
                   tvb_arphrdaddr_to_str(pinfo->pool, tvb, tha_offset, ar_hln, ar_hrd),
                   tvb_arphrdaddr_to_str(pinfo->pool, tvb, sha_offset, ar_hln, ar_hrd));
      break;
    case ARPOP_RREPLY:
    case ARPOP_DRARPREPLY:
      col_add_fstr(pinfo->cinfo, COL_INFO, "%s is at %s",
                   tvb_arphrdaddr_to_str(pinfo->pool, tvb, tha_offset, ar_hln, ar_hrd),
                   tvb_arpproaddr_to_str(pinfo->pool, tvb, tpa_offset, ar_pln, ar_pro));
      break;

    case ARPOP_DRARPERROR:
      col_add_fstr(pinfo->cinfo, COL_INFO, "DRARP Error");
      break;

    case ARPOP_IREPLY:
      col_add_fstr(pinfo->cinfo, COL_INFO, "%s is at %s",
                   tvb_arphrdaddr_to_str(pinfo->pool, tvb, sha_offset, ar_hln, ar_hrd),
                   tvb_arpproaddr_to_str(pinfo->pool, tvb, spa_offset, ar_pln, ar_pro));
      break;

    case ATMARPOP_NAK:
      col_add_fstr(pinfo->cinfo, COL_INFO, "ARP NAK");
      break;

    case ARPOP_MARS_REQUEST:
      col_add_fstr(pinfo->cinfo, COL_INFO, "MARS request from %s at %s",
                   tvb_arphrdaddr_to_str(pinfo->pool, tvb, sha_offset, ar_hln, ar_hrd),
                   tvb_arpproaddr_to_str(pinfo->pool, tvb, spa_offset, ar_pln, ar_pro));
      break;

    case ARPOP_MARS_MULTI:
      col_add_fstr(pinfo->cinfo, COL_INFO, "MARS MULTI request from %s at %s",
                   tvb_arphrdaddr_to_str(pinfo->pool, tvb, sha_offset, ar_hln, ar_hrd),
                   tvb_arpproaddr_to_str(pinfo->pool, tvb, spa_offset, ar_pln, ar_pro));
      break;

    case ARPOP_MARS_MSERV:
      col_add_fstr(pinfo->cinfo, COL_INFO, "MARS MSERV request from %s at %s",
                   tvb_arphrdaddr_to_str(pinfo->pool, tvb, sha_offset, ar_hln, ar_hrd),
                   tvb_arpproaddr_to_str(pinfo->pool, tvb, spa_offset, ar_pln, ar_pro));
      break;

    case ARPOP_MARS_JOIN:
      col_add_fstr(pinfo->cinfo, COL_INFO, "MARS JOIN request from %s at %s",
                   tvb_arphrdaddr_to_str(pinfo->pool, tvb, sha_offset, ar_hln, ar_hrd),
                   tvb_arpproaddr_to_str(pinfo->pool, tvb, spa_offset, ar_pln, ar_pro));
      break;

    case ARPOP_MARS_LEAVE:
      col_add_fstr(pinfo->cinfo, COL_INFO, "MARS LEAVE from %s at %s",
                   tvb_arphrdaddr_to_str(pinfo->pool, tvb, sha_offset, ar_hln, ar_hrd),
                   tvb_arpproaddr_to_str(pinfo->pool, tvb, spa_offset, ar_pln, ar_pro));
      break;

    case ARPOP_MARS_NAK:
      col_add_fstr(pinfo->cinfo, COL_INFO, "MARS NAK from %s at %s",
                   tvb_arphrdaddr_to_str(pinfo->pool, tvb, sha_offset, ar_hln, ar_hrd),
                   tvb_arpproaddr_to_str(pinfo->pool, tvb, spa_offset, ar_pln, ar_pro));
      break;

    case ARPOP_MARS_UNSERV:
      col_add_fstr(pinfo->cinfo, COL_INFO, "MARS UNSERV request from %s at %s",
                   tvb_arphrdaddr_to_str(pinfo->pool, tvb, sha_offset, ar_hln, ar_hrd),
                   tvb_arpproaddr_to_str(pinfo->pool, tvb, spa_offset, ar_pln, ar_pro));
      break;

    case ARPOP_MARS_SJOIN:
      col_add_fstr(pinfo->cinfo, COL_INFO, "MARS SJOIN request from %s at %s",
                   tvb_arphrdaddr_to_str(pinfo->pool, tvb, sha_offset, ar_hln, ar_hrd),
                   tvb_arpproaddr_to_str(pinfo->pool, tvb, spa_offset, ar_pln, ar_pro));
      break;

    case ARPOP_MARS_SLEAVE:
      col_add_fstr(pinfo->cinfo, COL_INFO, "MARS SLEAVE from %s at %s",
                   tvb_arphrdaddr_to_str(pinfo->pool, tvb, sha_offset, ar_hln, ar_hrd),
                   tvb_arpproaddr_to_str(pinfo->pool, tvb, spa_offset, ar_pln, ar_pro));
      break;

    case ARPOP_MARS_GROUPLIST_REQUEST:
      col_add_fstr(pinfo->cinfo, COL_INFO, "MARS grouplist request from %s at %s",
                   tvb_arphrdaddr_to_str(pinfo->pool, tvb, sha_offset, ar_hln, ar_hrd),
                   tvb_arpproaddr_to_str(pinfo->pool, tvb, spa_offset, ar_pln, ar_pro));
      break;

    case ARPOP_MARS_GROUPLIST_REPLY:
      col_add_fstr(pinfo->cinfo, COL_INFO, "MARS grouplist reply from %s at %s",
                   tvb_arphrdaddr_to_str(pinfo->pool, tvb, sha_offset, ar_hln, ar_hrd),
                   tvb_arpproaddr_to_str(pinfo->pool, tvb, spa_offset, ar_pln, ar_pro));
      break;

    case ARPOP_MARS_REDIRECT_MAP:
      col_add_fstr(pinfo->cinfo, COL_INFO, "MARS redirect map from %s at %s",
                   tvb_arphrdaddr_to_str(pinfo->pool, tvb, sha_offset, ar_hln, ar_hrd),
                   tvb_arpproaddr_to_str(pinfo->pool, tvb, spa_offset, ar_pln, ar_pro));
      break;

    case ARPOP_MAPOS_UNARP:
      col_add_fstr(pinfo->cinfo, COL_INFO, "MAPOS UNARP request from %s at %s",
                   tvb_arphrdaddr_to_str(pinfo->pool, tvb, sha_offset, ar_hln, ar_hrd),
                   tvb_arpproaddr_to_str(pinfo->pool, tvb, spa_offset, ar_pln, ar_pro));
      break;

    case ARPOP_EXP1:
      col_add_fstr(pinfo->cinfo, COL_INFO, "Experimental 1 ( opcode %d )", ar_op);
      break;

    case ARPOP_EXP2:
      col_add_fstr(pinfo->cinfo, COL_INFO, "Experimental 2 ( opcode %d )", ar_op);
      break;

    case 0:
    case 65535:
      col_add_fstr(pinfo->cinfo, COL_INFO, "Reserved opcode %d", ar_op);
      break;

    default:
      col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown ARP opcode 0x%04x", ar_op);
      break;
  }

  if (tree) {
    if ((op_str = try_val_to_str(ar_op, op_vals)))  {
      if (is_gratuitous && (ar_op == ARPOP_REQUEST))
        op_str = "request/gratuitous ARP";
      if (is_gratuitous && (ar_op == ARPOP_REPLY))
        op_str = "reply/gratuitous ARP";
      if (is_probe)
        op_str = "ARP Probe";
      if (is_announcement)
        op_str = "ARP Announcement";

      proto_item_append_text(arp_item, " (%s)", op_str);
    } else {
      proto_item_append_text(arp_item, " (opcode 0x%04x)", ar_op);
    }

    if (is_gratuitous) {
      item = proto_tree_add_boolean(arp_tree, hf_arp_isgratuitous, tvb, 0, 0, is_gratuitous);
      proto_item_set_generated(item);
    }
    if (is_probe) {
      item = proto_tree_add_boolean(arp_tree, hf_arp_isprobe, tvb, 0, 0, is_probe);
      proto_item_set_generated(item);
    }
    if (is_announcement) {
      item = proto_tree_add_boolean(arp_tree, hf_arp_isannouncement, tvb, 0, 0, is_announcement);
      proto_item_set_generated(item);
    }
    if (ar_hln != 0) {
      proto_tree_add_item(arp_tree,
                          ARP_HW_IS_ETHER(ar_hrd, ar_hln) ?
                          hf_arp_src_hw_mac :
                          hf_arp_src_hw,
                          tvb, sha_offset, ar_hln, ENC_BIG_ENDIAN);
    }
    if (ar_pln != 0) {
      proto_tree_add_item(arp_tree,
                          ARP_PRO_IS_IPv4(ar_pro, ar_pln) ?
                          hf_arp_src_proto_ipv4 :
                          hf_arp_src_proto,
                          tvb, spa_offset, ar_pln, ENC_BIG_ENDIAN);
    }
    if (ar_hln != 0) {
      proto_tree_add_item(arp_tree,
                          ARP_HW_IS_ETHER(ar_hrd, ar_hln) ?
                          hf_arp_dst_hw_mac :
                          hf_arp_dst_hw,
                          tvb, tha_offset, ar_hln, ENC_BIG_ENDIAN);
    }
    if (ar_pln != 0 && ar_op != ARPOP_DRARPERROR) {     /*DISPLAYING ERROR NUMBER FOR DRARPERROR*/
      proto_tree_add_item(arp_tree,
                          ARP_PRO_IS_IPv4(ar_pro, ar_pln) ?
                          hf_arp_dst_proto_ipv4 :
                          hf_arp_dst_proto,
                          tvb, tpa_offset, ar_pln, ENC_BIG_ENDIAN);
    }
    else if (ar_pln != 0 && ar_op == ARPOP_DRARPERROR) {
       proto_tree_add_item(arp_tree, hf_drarp_error_status, tvb, tpa_offset, 1, ENC_BIG_ENDIAN); /*Adding the first byte of tpa field as drarp_error_status*/
    }
  }

  if (global_arp_detect_request_storm)
  {
    check_for_storm_count(tvb, pinfo, arp_tree);
  }

  if (duplicate_detected)
  {
    /* Also indicate in info column */
    col_append_fstr(pinfo->cinfo, COL_INFO, " (duplicate use of %s detected!)",
                    arpproaddr_to_str(pinfo->pool, (uint8_t*)&duplicate_ip, 4, ETHERTYPE_IP));
  }
  return tvb_captured_length(tvb);
}

void
proto_register_arp(void)
{
  static struct true_false_string tfs_type_bit = { "E.164", "ATM Forum NSAPA" };

  static hf_register_info hf[] = {
    { &hf_arp_hard_type,
      { "Hardware type",                "arp.hw.type",
        FT_UINT16,      BASE_DEC,       VALS(arp_hrd_vals), 0x0,
        NULL, HFILL }},

    { &hf_arp_proto_type,
      { "Protocol type",                "arp.proto.type",
        FT_UINT16,      BASE_HEX,       VALS(etype_vals),       0x0,
        NULL, HFILL }},

    { &hf_arp_hard_size,
      { "Hardware size",                "arp.hw.size",
        FT_UINT8,       BASE_DEC,       NULL,   0x0,
        NULL, HFILL }},

    { &hf_atmarp_sht,
      { "Sender ATM number type",       "arp.src.htype",
        FT_BOOLEAN,     8,              TFS(&tfs_type_bit),     ATMARP_IS_E164,
        NULL, HFILL }},

    { &hf_atmarp_shl,
      { "Sender ATM number length",     "arp.src.hlen",
        FT_UINT8,       BASE_DEC,       NULL,           ATMARP_LEN_MASK,
        NULL, HFILL }},

    { &hf_atmarp_sst,
      { "Sender ATM subaddress type",   "arp.src.stype",
        FT_BOOLEAN,     8,              TFS(&tfs_type_bit),     ATMARP_IS_E164,
        NULL, HFILL }},

    { &hf_atmarp_ssl,
      { "Sender ATM subaddress length", "arp.src.slen",
        FT_UINT8,       BASE_DEC,       NULL,           ATMARP_LEN_MASK,
        NULL, HFILL }},

    { &hf_arp_proto_size,
      { "Protocol size",                "arp.proto.size",
        FT_UINT8,       BASE_DEC,       NULL,   0x0,
        NULL, HFILL }},

    { &hf_arp_opcode,
      { "Opcode",                       "arp.opcode",
        FT_UINT16,      BASE_DEC,       VALS(op_vals),  0x0,
        NULL, HFILL }},

    { &hf_arp_isgratuitous,
      { "Is gratuitous",                "arp.isgratuitous",
        FT_BOOLEAN,     BASE_NONE,      NULL,   0x0,
        NULL, HFILL }},

    { &hf_arp_isprobe,
      { "Is probe",                "arp.isprobe",
        FT_BOOLEAN,     BASE_NONE,      NULL,   0x0,
        NULL, HFILL }},

    { &hf_arp_isannouncement,
      { "Is announcement",                "arp.isannouncement",
        FT_BOOLEAN,     BASE_NONE,      NULL,   0x0,
        NULL, HFILL }},

    { &hf_atmarp_spln,
      { "Sender protocol size",         "arp.src.pln",
        FT_UINT8,       BASE_DEC,       NULL,   0x0,
        NULL, HFILL }},

    { &hf_atmarp_tht,
      { "Target ATM number type",       "arp.dst.htype",
        FT_BOOLEAN,     8,              TFS(&tfs_type_bit),     ATMARP_IS_E164,
        NULL, HFILL }},

    { &hf_atmarp_thl,
      { "Target ATM number length",     "arp.dst.hlen",
        FT_UINT8,       BASE_DEC,       NULL,           ATMARP_LEN_MASK,
        NULL, HFILL }},

    { &hf_atmarp_tst,
      { "Target ATM subaddress type",   "arp.dst.stype",
        FT_BOOLEAN,     8,              TFS(&tfs_type_bit),     ATMARP_IS_E164,
        NULL, HFILL }},

    { &hf_atmarp_tsl,
      { "Target ATM subaddress length", "arp.dst.slen",
        FT_UINT8,       BASE_DEC,       NULL,           ATMARP_LEN_MASK,
        NULL, HFILL }},

    { &hf_atmarp_tpln,
      { "Target protocol size",         "arp.dst.pln",
        FT_UINT8,       BASE_DEC,       NULL,   0x0,
        NULL, HFILL }},

    { &hf_arp_src_hw,
      { "Sender hardware address",      "arp.src.hw",
        FT_BYTES,       BASE_NONE,      NULL,   0x0,
        NULL, HFILL }},

    { &hf_arp_src_hw_mac,
      { "Sender MAC address",           "arp.src.hw_mac",
        FT_ETHER,       BASE_NONE,      NULL,   0x0,
        NULL, HFILL }},

    { &hf_arp_src_hw_ax25,
      { "Sender AX.25 address",         "arp.src.hw_ax25",
        FT_AX25,        BASE_NONE,      NULL,   0x0,
        NULL, HFILL }},

    { &hf_atmarp_src_atm_num_e164,
      { "Sender ATM number (E.164)",    "arp.src.atm_num_e164",
        FT_STRING,      BASE_NONE,      NULL,   0x0,
        NULL, HFILL }},

    { &hf_atmarp_src_atm_num_nsap,
      { "Sender ATM number (NSAP)",     "arp.src.atm_num_nsap",
        FT_BYTES,       BASE_NONE,      NULL,   0x0,
        NULL, HFILL }},

    { &hf_atmarp_src_atm_subaddr,
      { "Sender ATM subaddress",        "arp.src.atm_subaddr",
        FT_BYTES,       BASE_NONE,      NULL,   0x0,
        NULL, HFILL }},

    { &hf_arp_src_proto,
      { "Sender protocol address",      "arp.src.proto",
        FT_BYTES,       BASE_NONE,      NULL,   0x0,
        NULL, HFILL }},

    { &hf_arp_src_proto_ipv4,
      { "Sender IP address",            "arp.src.proto_ipv4",
        FT_IPv4,        BASE_NONE,      NULL,   0x0,
        NULL, HFILL }},

    { &hf_arp_dst_hw,
      { "Target hardware address",      "arp.dst.hw",
        FT_BYTES,       BASE_NONE,      NULL,   0x0,
        NULL, HFILL }},

    { &hf_arp_dst_hw_mac,
      { "Target MAC address",           "arp.dst.hw_mac",
        FT_ETHER,       BASE_NONE,      NULL,   0x0,
        NULL, HFILL }},

    { &hf_arp_dst_hw_ax25,
      { "Target AX.25 address",         "arp.dst.hw_ax25",
        FT_AX25,        BASE_NONE,      NULL,   0x0,
        NULL, HFILL }},

    { &hf_atmarp_dst_atm_num_e164,
      { "Target ATM number (E.164)",    "arp.dst.atm_num_e164",
        FT_STRING,      BASE_NONE,      NULL,   0x0,
        NULL, HFILL }},

    { &hf_atmarp_dst_atm_num_nsap,
      { "Target ATM number (NSAP)",     "arp.dst.atm_num_nsap",
        FT_BYTES,       BASE_NONE,      NULL,   0x0,
        NULL, HFILL }},

    { &hf_atmarp_dst_atm_subaddr,
      { "Target ATM subaddress",        "arp.dst.atm_subaddr",
        FT_BYTES,       BASE_NONE,      NULL,   0x0,
        NULL, HFILL }},

    { &hf_arp_dst_proto,
      { "Target protocol address",      "arp.dst.proto",
        FT_BYTES,       BASE_NONE,      NULL,   0x0,
        NULL, HFILL }},

    { &hf_arp_dst_proto_ipv4,
      { "Target IP address",            "arp.dst.proto_ipv4",
        FT_IPv4,        BASE_NONE,      NULL,   0x0,
        NULL, HFILL }},

    { &hf_drarp_error_status,
      { "DRARP error status",    "arp.dst.drarp_error_status",
        FT_UINT16,      BASE_DEC,      VALS(drarp_status),   0x0,
        NULL, HFILL }},

    { &hf_arp_duplicate_ip_address_earlier_frame,
      { "Frame showing earlier use of IP address",      "arp.duplicate-address-frame",
        FT_FRAMENUM,    BASE_NONE,      NULL,   0x0,
        NULL, HFILL }},

    { &hf_arp_duplicate_ip_address_seconds_since_earlier_frame,
      { "Seconds since earlier frame seen",     "arp.seconds-since-duplicate-address-frame",
        FT_UINT32,      BASE_DEC,       NULL,   0x0,
        NULL, HFILL }},

      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_atmarp_src_atm_data_country_code, { "Data Country Code", "arp.src.atm_data_country_code", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_atmarp_src_atm_data_country_code_group, { "Data Country Code (group)", "arp.src.atm_data_country_code_group", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_atmarp_src_atm_high_order_dsp, { "High Order DSP", "arp.src.atm_high_order_dsp", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_atmarp_src_atm_end_system_identifier, { "End System Identifier", "arp.src.atm_end_system_identifier", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_atmarp_src_atm_selector, { "Selector", "arp.src.atm_selector", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_atmarp_src_atm_international_code_designator, { "International Code Designator", "arp.src.atm_international_code_designator", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_atmarp_src_atm_international_code_designator_group, { "International Code Designator (group)", "arp.src.atm_international_code_designator_group", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_atmarp_src_atm_e_164_isdn, { "E.164 ISDN", "arp.src.atm_e.164_isdn", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_atmarp_src_atm_e_164_isdn_group, { "E.164 ISDN", "arp.src.atm_e.164_isdn_group", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_atmarp_src_atm_rest_of_address, { "Rest of address", "arp.src.atm_rest_of_address", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_atmarp_src_atm_afi, { "AFI", "arp.src.atm_afi", FT_UINT8, BASE_HEX, VALS(atm_nsap_afi_vals), 0x0, NULL, HFILL }},
  };

  static int *ett[] = {
    &ett_arp,
    &ett_atmarp_nsap,
    &ett_atmarp_tl,
    &ett_arp_duplicate_address
  };

  static ei_register_info ei[] = {
     { &ei_seq_arp_dup_ip, { "arp.duplicate-address-detected", PI_SEQUENCE, PI_WARN, "Duplicate IP address configured", EXPFILL }},
     { &ei_seq_arp_storm, { "arp.packet-storm-detected", PI_SEQUENCE, PI_NOTE, "ARP packet storm detected", EXPFILL }},
     { &ei_atmarp_src_atm_unknown_afi, { "arp.src.atm_afi.unknown", PI_PROTOCOL, PI_WARN, "Unknown AFI", EXPFILL }},
  };

  module_t *arp_module;
  expert_module_t* expert_arp;

  proto_arp = proto_register_protocol("Address Resolution Protocol",
                                      "ARP/RARP", "arp");
  proto_atmarp = proto_register_protocol("ATM Address Resolution Protocol",
                                      "ATMARP", "atmarp");

  proto_register_field_array(proto_arp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  expert_arp = expert_register_protocol(proto_arp);
  expert_register_field_array(expert_arp, ei, array_length(ei));

  arp_handle = register_dissector( "arp" , dissect_arp, proto_arp );
  register_dissector("atm_arp", dissect_atmarp, proto_atmarp);
  register_dissector("ax25_arp", dissect_ax25arp, proto_arp);

  arp_hw_table = register_dissector_table("arp.hw.type", "ARP Hardware Type", proto_arp, FT_UINT16, BASE_DEC);

  /* Preferences */
  arp_module = prefs_register_protocol(proto_arp, NULL);

  prefs_register_bool_preference(arp_module, "detect_request_storms",
                                 "Detect ARP request storms",
                                 "Attempt to detect excessive rate of ARP requests",
                                 &global_arp_detect_request_storm);

  prefs_register_uint_preference(arp_module, "detect_storm_number_of_packets",
                                 "Number of requests to detect during period",
                                 "Number of requests needed within period to indicate a storm",
                                 10, &global_arp_detect_request_storm_packets);

  prefs_register_uint_preference(arp_module, "detect_storm_period",
                                 "Detection period (in ms)",
                                 "Period in milliseconds during which a packet storm may be detected",
                                 10, &global_arp_detect_request_storm_period);

  prefs_register_bool_preference(arp_module, "detect_duplicate_ips",
                                 "Detect duplicate IP address configuration",
                                 "Attempt to detect duplicate use of IP addresses",
                                 &global_arp_detect_duplicate_ip_addresses);

  prefs_register_bool_preference(arp_module, "register_network_address_binding",
                                 "Register network address mappings",
                                 "Try to resolve physical addresses to host names from ARP requests/responses",
                                 &global_arp_register_network_address_binding);

  /* TODO: define a minimum time between sightings that is worth reporting? */

  address_hash_table = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), address_hash_func, address_equal_func);
  duplicate_result_hash_table = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), duplicate_result_hash_func,
                                                 duplicate_result_equal_func);

  arp_cap_handle = register_capture_dissector("arp", capture_arp, proto_arp);
}

void
proto_reg_handoff_arp(void)
{
  dissector_handle_t atmarp_handle = find_dissector("atm_arp");
  dissector_handle_t ax25arp_handle = find_dissector("ax25_arp");

  dissector_add_uint("ethertype", ETHERTYPE_ARP, arp_handle);
  dissector_add_uint("ethertype", ETHERTYPE_REVARP, arp_handle);
  dissector_add_uint("arcnet.protocol_id", ARCNET_PROTO_ARP_1051, arp_handle);
  dissector_add_uint("arcnet.protocol_id", ARCNET_PROTO_ARP_1201, arp_handle);
  dissector_add_uint("arcnet.protocol_id", ARCNET_PROTO_RARP_1201, arp_handle);
  dissector_add_uint("ax25.pid", AX25_P_ARP, arp_handle);
  dissector_add_uint("gre.proto", ETHERTYPE_ARP, arp_handle);
  capture_dissector_add_uint("ethertype", ETHERTYPE_ARP, arp_cap_handle);
  capture_dissector_add_uint("ax25.pid", AX25_P_ARP, arp_cap_handle);

  dissector_add_uint("arp.hw.type", ARPHRD_ATM2225, atmarp_handle);
  dissector_add_uint("arp.hw.type", ARPHRD_AX25, ax25arp_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
