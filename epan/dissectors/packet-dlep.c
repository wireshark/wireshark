/* packet-dlep.c
 * Routines for DLEP protocol packet disassembly
 *
 * Copyright (C) 2019 Massachusetts Institute of Technology
 *
 * Original code from https://github.com/mit-ll/dlep-wireshark-dissector
 * Original Author: Jeffrey Wildman <jeffrey.wildman@ll.mit.edu>
 *
 * Extended and supplemented by Uli Heilmeier <uh@heilmeier.eu>, 2020
 * Extended by:
 * RFC 8757 Latency Range Extension
 * RFC 8629 Multi-Hop Forwarding Extension
 * RFC 8703 Link Identifier Extension
 * TODO: Decoding of RFC 8651 Control-Plane-Based Pause Extension needs to be implemented
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include "config.h"

#include <epan/ftypes/ftypes.h> /* for fieldtype lengths */
#include <epan/expert.h>
#include <epan/ipproto.h>       /* for IP_PROTO_TCP and IP_PROTO_UDP */
#include <epan/packet.h>
#include <epan/packet_info.h>   /* for struct packet_info */
#include <epan/prefs.h>
#include <epan/tvbuff.h>
#include <epan/to_str.h>
#include <epan/tfs.h>
#include <glib.h>

/* Section 13: DLEP Data Items */

/* DLEP Data Item Lengths (bytes) */
#define DLEP_DIT_STATUS_MINLEN      1     /* variable length */
#define DLEP_DIT_V4CONN_LEN         5
#define DLEP_DIT_V4CONN_WPORT_LEN   7
#define DLEP_DIT_V6CONN_LEN         17
#define DLEP_DIT_V6CONN_WPORT_LEN   19
#define DLEP_DIT_PEERTYPE_MINLEN    1     /* variable length */
#define DLEP_DIT_HEARTBEAT_LEN      4
/* EXTSUPP has variable, non-negative length */
#define DLEP_DIT_MACADDR_EUI48_LEN  6
#define DLEP_DIT_MACADDR_EUI64_LEN  8
#define DLEP_DIT_V4ADDR_LEN         5
#define DLEP_DIT_V6ADDR_LEN         17
#define DLEP_DIT_V4SUBNET_LEN       6
#define DLEP_DIT_V6SUBNET_LEN       18
#define DLEP_DIT_MDRR_LEN           8
#define DLEP_DIT_MDRT_LEN           8
#define DLEP_DIT_CDRR_LEN           8
#define DLEP_DIT_CDRT_LEN           8
#define DLEP_DIT_LAT_LEN            8
#define DLEP_DIT_RES_LEN            1
#define DLEP_DIT_RLQR_LEN           1
#define DLEP_DIT_RLQT_LEN           1
#define DLEP_DIT_MTU_LEN            2
#define DLEP_DIT_HOP_CNT_LEN        2
#define DLEP_DIT_HOP_CNTRL_LEN      2
#define DLEP_DIT_LI_LENGTH_LEN      2
#define DLEP_DIT_LAT_RANGE_LEN      16

/* DLEP Data Item Flags Lengths (bytes) */
#define DLEP_DIT_V4CONN_FLAGS_LEN   1
#define DLEP_DIT_V6CONN_FLAGS_LEN   1
#define DLEP_DIT_V4ADDR_FLAGS_LEN   1
#define DLEP_DIT_V6ADDR_FLAGS_LEN   1
#define DLEP_DIT_PEERTYPE_FLAGS_LEN 1
#define DLEP_DIT_V4SUBNET_FLAGS_LEN 1
#define DLEP_DIT_V6SUBNET_FLAGS_LEN 1


/* Section 15: IANA Considerations */

/* Section 15.2: DLEP Signal Type Codes */
#define DLEP_SIG_RESERVED         0
#define DLEP_SIG_PEERDISC         1
#define DLEP_SIG_PEEROFFR         2

/* Section 15.3: DLEP Message Type Codes */
#define DLEP_MSG_RESERVED         0
#define DLEP_MSG_SESSINIT         1
#define DLEP_MSG_SESSINITRESP     2
#define DLEP_MSG_SESSUPDATE       3
#define DLEP_MSG_SESSUPDATERESP   4
#define DLEP_MSG_SESSTERM         5
#define DLEP_MSG_SESSTERMRESP     6
#define DLEP_MSG_DESTUP           7
#define DLEP_MSG_DESTUPRESP       8
#define DLEP_MSG_DESTANN          9
#define DLEP_MSG_DESTANNRESP      10
#define DLEP_MSG_DESTDOWN         11
#define DLEP_MSG_DESTDOWNRESP     12
#define DLEP_MSG_DESTUPDATE       13
#define DLEP_MSG_LINKCHARRQST     14
#define DLEP_MSG_LINKCHARRESP     15
#define DLEP_MSG_HEARTBEAT        16

/* Section 15.4: DLEP Data Item Type Codes */
#define DLEP_DIT_RESERVED         0
#define DLEP_DIT_STATUS           1
#define DLEP_DIT_V4CONN           2
#define DLEP_DIT_V6CONN           3
#define DLEP_DIT_PEERTYPE         4
#define DLEP_DIT_HEARTBEAT        5
#define DLEP_DIT_EXTSUPP          6
#define DLEP_DIT_MACADDR          7
#define DLEP_DIT_V4ADDR           8
#define DLEP_DIT_V6ADDR           9
#define DLEP_DIT_V4SUBNET         10
#define DLEP_DIT_V6SUBNET         11
#define DLEP_DIT_MDRR             12
#define DLEP_DIT_MDRT             13
#define DLEP_DIT_CDRR             14
#define DLEP_DIT_CDRT             15
#define DLEP_DIT_LAT              16
#define DLEP_DIT_RES              17
#define DLEP_DIT_RLQR             18
#define DLEP_DIT_RLQT             19
#define DLEP_DIT_MTU              20
#define DLEP_DIT_HOP_CNT          21
#define DLEP_DIT_HOP_CNTRL        22
#define DLEP_DIT_QUEUE_PARA       23
#define DLEP_DIT_PAUSE            24
#define DLEP_DIT_RESTART          25
#define DLEP_DIT_LI_LENGTH        26
#define DLEP_DIT_LI               27
#define DLEP_DIT_LAT_RANGE        28

/* Section 15.5: DLEP Status Codes */
#define DLEP_SC_CONT_SUCCESS      0
#define DLEP_SC_CONT_NOTINT       1
#define DLEP_SC_CONT_RQSTDENIED   2
#define DLEP_SC_CONT_INCONSIST    3
#define DLEP_SC_TERM_UNKWNMSG     128
#define DLEP_SC_TERM_UNEXPMSG     129
#define DLEP_SC_TERM_INVDATA      130
#define DLEP_SC_TERM_INVDEST      131
#define DLEP_SC_TERM_TIMEDOUT     132
#define DLEP_SC_TERM_SHUTDOWN     255

/* Section 15.6: DLEP Extension Type Codes */
#define DLEP_EXT_RESERVED         0
#define DLEP_EXT_MULTIHOP         1
#define DLEP_EXT_CPB_PAUSE        2
#define DLEP_EXT_LI               3
#define DLEP_EXT_LR               4

/* Section 15.7: DLEP IPv4 Connection Point Flags */
#define DLEP_DIT_V4CONN_FLAGMASK_BITLEN     DLEP_DIT_V4CONN_FLAGS_LEN * 8
#define DLEP_DIT_V4CONN_FLAGMASK_TLS        0x01

/* Section 15.8: DLEP IPv6 Connection Point Flags */
#define DLEP_DIT_V6CONN_FLAGMASK_BITLEN     DLEP_DIT_V6CONN_FLAGS_LEN * 8
#define DLEP_DIT_V6CONN_FLAGMASK_TLS        0x01

/* Section 15.9: DLEP Peer Type Flags */
#define DLEP_DIT_PEERTYPE_FLAGMASK_BITLEN   DLEP_DIT_PEERTYPE_FLAGS_LEN * 8
#define DLEP_DIT_PEERTYPE_FLAGMASK_SMI      0x01

/* Section 15.10: DLEP IPv4 Address Flags */
#define DLEP_DIT_V4ADDR_FLAGMASK_BITLEN     DLEP_DIT_V4ADDR_FLAGS_LEN * 8
#define DLEP_DIT_V4ADDR_FLAGMASK_ADDDROP    0x01

/* Section 15.11: DLEP IPv6 Address Flags */
#define DLEP_DIT_V6ADDR_FLAGMASK_BITLEN     DLEP_DIT_V6ADDR_FLAGS_LEN * 8
#define DLEP_DIT_V6ADDR_FLAGMASK_ADDDROP    0x01

/* Section 15.12: DLEP IPv4 Attached Subnet Flags */
#define DLEP_DIT_V4SUBNET_FLAGMASK_BITLEN   DLEP_DIT_V4SUBNET_FLAGS_LEN * 8
#define DLEP_DIT_V4SUBNET_FLAGMASK_ADDDROP  0x01

/* Section 15.13: DLEP IPv6 Attached Subnet Flags */
#define DLEP_DIT_V6SUBNET_FLAGMASK_BITLEN   DLEP_DIT_V6SUBNET_FLAGS_LEN * 8
#define DLEP_DIT_V6SUBNET_FLAGMASK_ADDDROP  0x01

/* RFC 8629 Hop Count Flags */
#define DLEP_DIT_HOP_CNT_FLAGMASK_P         0x80
#define DLEP_DIT_HOP_CNT_FLAGMASK_RESERVED  0x7F

/* Section 15.14: DLEP Well-known Port */
#define DLEP_UDP_PORT "854"
#define DLEP_TCP_PORT "854"

/* Section 15.15: DLEP IPv4 Link-Local Multicast Address */
#define DLEP_IPV4_ADDR "224.0.0.117"

/* Section 15.16: DLEP IPv6 Link-Local Multicast Address */
#define DLEP_IPV6_ADDR "FF02:0:0:0:0:0:1:7"

static dissector_handle_t dlep_msg_handle;
static dissector_handle_t dlep_sig_handle;

void proto_register_dlep(void);
void proto_reg_handoff_dlep(void);

static gint proto_dlep = -1;

static gint ett_dlep = -1;
static gint ett_dlep_dataitem = -1;
static gint ett_dlep_flags = -1;

static gint hf_dlep_signal = -1;
static gint hf_dlep_signal_signature = -1;
static gint hf_dlep_signal_type = -1;
static gint hf_dlep_signal_length = -1;
static gint hf_dlep_message = -1;
static gint hf_dlep_message_type = -1;
static gint hf_dlep_message_length = -1;
static gint hf_dlep_dataitem = -1;
static gint hf_dlep_dataitem_type = -1;
static gint hf_dlep_dataitem_length = -1;
static gint hf_dlep_dataitem_value = -1;
static gint hf_dlep_dataitem_status = -1;
static gint hf_dlep_dataitem_status_code = -1;
static gint hf_dlep_dataitem_status_text = -1;
static gint hf_dlep_dataitem_v4conn = -1;
static gint hf_dlep_dataitem_v4conn_flags = -1;
static gint hf_dlep_dataitem_v4conn_flags_tls = -1;
static gint hf_dlep_dataitem_v4conn_addr = -1;
static gint hf_dlep_dataitem_v4conn_port = -1;
static gint hf_dlep_dataitem_v6conn = -1;
static gint hf_dlep_dataitem_v6conn_flags = -1;
static gint hf_dlep_dataitem_v6conn_flags_tls = -1;
static gint hf_dlep_dataitem_v6conn_addr = -1;
static gint hf_dlep_dataitem_v6conn_port = -1;
static gint hf_dlep_dataitem_peertype = -1;
static gint hf_dlep_dataitem_peertype_flags = -1;
static gint hf_dlep_dataitem_peertype_flags_smi = -1;
static gint hf_dlep_dataitem_peertype_description = -1;
static gint hf_dlep_dataitem_heartbeat = -1;
static gint hf_dlep_dataitem_extsupp = -1;
static gint hf_dlep_dataitem_extsupp_code = -1;
static gint hf_dlep_dataitem_macaddr_eui48 = -1;
static gint hf_dlep_dataitem_macaddr_eui64 = -1;
static gint hf_dlep_dataitem_v4addr = -1;
static gint hf_dlep_dataitem_v4addr_flags = -1;
static gint hf_dlep_dataitem_v4addr_flags_adddrop = -1;
static gint hf_dlep_dataitem_v4addr_addr = -1;
static gint hf_dlep_dataitem_v6addr = -1;
static gint hf_dlep_dataitem_v6addr_flags = -1;
static gint hf_dlep_dataitem_v6addr_flags_adddrop = -1;
static gint hf_dlep_dataitem_v6addr_addr = -1;
static gint hf_dlep_dataitem_v4subnet = -1;
static gint hf_dlep_dataitem_v4subnet_flags = -1;
static gint hf_dlep_dataitem_v4subnet_flags_adddrop = -1;
static gint hf_dlep_dataitem_v4subnet_subnet = -1;
static gint hf_dlep_dataitem_v4subnet_prefixlen = -1;
static gint hf_dlep_dataitem_v6subnet = -1;
static gint hf_dlep_dataitem_v6subnet_flags = -1;
static gint hf_dlep_dataitem_v6subnet_flags_adddrop = -1;
static gint hf_dlep_dataitem_v6subnet_subnet = -1;
static gint hf_dlep_dataitem_v6subnet_prefixlen = -1;
static gint hf_dlep_dataitem_mdrr = -1;
static gint hf_dlep_dataitem_mdrt = -1;
static gint hf_dlep_dataitem_cdrr = -1;
static gint hf_dlep_dataitem_cdrt = -1;
static gint hf_dlep_dataitem_latency = -1;
static gint hf_dlep_dataitem_resources = -1;
static gint hf_dlep_dataitem_rlqr = -1;
static gint hf_dlep_dataitem_rlqt = -1;
static gint hf_dlep_dataitem_mtu = -1;
static gint hf_dlep_dataitem_hop_count_flags = -1;
static gint hf_dlep_dataitem_hop_count_flags_p = -1;
static gint hf_dlep_dataitem_hop_count_flags_reserved = -1;
static gint hf_dlep_dataitem_hop_count = -1;
static gint hf_dlep_dataitem_hop_control = -1;
static gint hf_dlep_dataitem_li_length = -1;
static gint hf_dlep_dataitem_li = -1;
static gint hf_dlep_dataitem_max_lat = -1;
static gint hf_dlep_dataitem_min_lat = -1;

static const value_string signal_type_vals[] = {
  { DLEP_SIG_RESERVED,  "Reserved"        },
  { DLEP_SIG_PEERDISC,  "Peer Discovery"  },
  { DLEP_SIG_PEEROFFR,  "Peer Offer"      },
  { 0,                  NULL              }
};

static const value_string message_type_vals[] = {
  { DLEP_MSG_RESERVED,        "Reserved"                        },
  { DLEP_MSG_SESSINIT,        "Session Initialization"          },
  { DLEP_MSG_SESSINITRESP,    "Session Initialization Response" },
  { DLEP_MSG_SESSUPDATE,      "Session Update"                  },
  { DLEP_MSG_SESSUPDATERESP,  "Session Update Response"         },
  { DLEP_MSG_SESSTERM,        "Session Termination"             },
  { DLEP_MSG_SESSTERMRESP,    "Session Termination Response"    },
  { DLEP_MSG_DESTUP,          "Destination Up"                  },
  { DLEP_MSG_DESTUPRESP,      "Destination Up Response"         },
  { DLEP_MSG_DESTANN,         "Destination Announce"            },
  { DLEP_MSG_DESTANNRESP,     "Destination Announce Response"   },
  { DLEP_MSG_DESTDOWN,        "Destination Down"                },
  { DLEP_MSG_DESTDOWNRESP,    "Destination Down Response"       },
  { DLEP_MSG_DESTUPDATE,      "Destination Update"              },
  { DLEP_MSG_LINKCHARRQST,    "Link Characteristics Request"    },
  { DLEP_MSG_LINKCHARRESP,    "Link Characteristics Response"   },
  { DLEP_MSG_HEARTBEAT,       "Heartbeat"                       },
  { 0,                        NULL                              }
};

static const value_string dataitem_type_vals[] = {
  { DLEP_DIT_RESERVED,  "Reserved"                                },
  { DLEP_DIT_STATUS,    "Status"                                  },
  { DLEP_DIT_V4CONN,    "IPv4 Connection Point"                   },
  { DLEP_DIT_V6CONN,    "IPv6 Connection Point"                   },
  { DLEP_DIT_PEERTYPE,  "Peer Type"                               },
  { DLEP_DIT_HEARTBEAT, "Heartbeat Interval"                      },
  { DLEP_DIT_EXTSUPP,   "Extensions Supported"                    },
  { DLEP_DIT_MACADDR,   "MAC Address"                             },
  { DLEP_DIT_V4ADDR,    "IPv4 Address"                            },
  { DLEP_DIT_V6ADDR,    "IPv6 Address"                            },
  { DLEP_DIT_V4SUBNET,  "IPv4 Attached Subnet"                    },
  { DLEP_DIT_V6SUBNET,  "IPv6 Attached Subnet"                    },
  { DLEP_DIT_MDRR,      "Maximum Data Rate (Receive) (MDRR)"      },
  { DLEP_DIT_MDRT,      "Maximum Data Rate (Transmit) (MDRT)"     },
  { DLEP_DIT_CDRR,      "Current Data Rate (Receive) (CDRR)"      },
  { DLEP_DIT_CDRT,      "Current Data Rate (Transmit) (CDRT)"     },
  { DLEP_DIT_LAT,       "Latency"                                 },
  { DLEP_DIT_RES,       "Resources (RES)"                         },
  { DLEP_DIT_RLQR,      "Relative Link Quality (Receive) (RLQR)"  },
  { DLEP_DIT_RLQT,      "Relative Link Quality (Transmit) (RLQT)" },
  { DLEP_DIT_MTU,       "Maximum Transmission Unit (MTU)"         },
  { DLEP_DIT_HOP_CNT,   "Hop Count"                               },
  { DLEP_DIT_HOP_CNTRL, "Hop Control"                             },
  { DLEP_DIT_QUEUE_PARA,"Queue Parameters"                        },
  { DLEP_DIT_PAUSE,     "Pause"                                   },
  { DLEP_DIT_RESTART,   "Restart"                                 },
  { DLEP_DIT_LI_LENGTH, "Link Identifier Length"                  },
  { DLEP_DIT_LI,        "Link Identifier"                         },
  { DLEP_DIT_LAT_RANGE, "Latency Range"                           },
  { 0,                  NULL                                      }
};

static const value_string status_code_vals[] = {
  { DLEP_SC_CONT_SUCCESS,     "Success"             },
  { DLEP_SC_CONT_NOTINT,      "Not Interested"      },
  { DLEP_SC_CONT_RQSTDENIED,  "Request Denied"      },
  { DLEP_SC_CONT_INCONSIST,   "Inconsistent Data"   },
  { DLEP_SC_TERM_UNKWNMSG,    "Unknown Message"     },
  { DLEP_SC_TERM_UNEXPMSG,    "Unexpected Message"  },
  { DLEP_SC_TERM_INVDATA,     "Invalid Data"        },
  { DLEP_SC_TERM_INVDEST,     "Invalid Destination" },
  { DLEP_SC_TERM_TIMEDOUT,    "Timed Out"           },
  { DLEP_SC_TERM_SHUTDOWN,    "Shutting Down"       },
  { 0,                        NULL                  }
};

static const range_string extension_code_vals[] = {
  { DLEP_EXT_RESERVED,  DLEP_EXT_RESERVED,  "Reserved"                  },
  { DLEP_EXT_MULTIHOP,  DLEP_EXT_MULTIHOP,  "Multi-Hop Forwarding"      },
  { DLEP_EXT_CPB_PAUSE, DLEP_EXT_CPB_PAUSE, "Control-Plane-Based Pause" },
  { DLEP_EXT_LI,        DLEP_EXT_LI,        "Link Identifiers"          },
  { DLEP_EXT_LR,        DLEP_EXT_LR,        "Latency Range"             },
  { 5,                  65519,              "Unassigned"                },
  { 65520,              65534,              "Reserved for Private Use"  },
  { 0,                  0,                  NULL                        }
};

static const range_string hop_cntrl_action_vals[] = {
  { 0,     0,     "Reset"                  },
  { 1,     1,     "Terminate"              },
  { 2,     2,     "Direct Connection"      },
  { 3,     3,     "Suppress Forwarding"    },
  { 4,     65519, "Specification Required" },
  { 65520, 65534, "Private Use"            },
  { 65535, 65535, "Reserved"               },
  { 0,     0,     NULL                     }
};

static expert_field ei_dlep_signal_unexpected_length = EI_INIT;
static expert_field ei_dlep_message_unexpected_length = EI_INIT;
static expert_field ei_dlep_dataitem_unexpected_length = EI_INIT;
static expert_field ei_dlep_dataitem_macaddr_unexpected_length = EI_INIT;

/* Section 13.1: Status */
static int
decode_dataitem_status(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len, packet_info *pinfo)
{
  proto_item *tmp_pi = NULL;
  guint32 status_code;

  /* Add and hide the specific dataitem protocol item */
  tmp_pi = proto_tree_add_item(pt, hf_dlep_dataitem_status, tvb, offset, len, ENC_NA);
  PROTO_ITEM_SET_HIDDEN(tmp_pi);

  if (len < DLEP_DIT_STATUS_MINLEN) {
    expert_add_info(pinfo, pi, &ei_dlep_dataitem_unexpected_length);
    return offset;
  }

  proto_tree_add_item_ret_uint(pt, hf_dlep_dataitem_status_code, tvb, offset, 1, ENC_NA, &status_code);
  proto_item_append_text(pi, ", Code: %s (%u)", val_to_str(status_code, status_code_vals, "Unknown"), status_code);
  offset+=1;

  proto_tree_add_item(pt, hf_dlep_dataitem_status_text, tvb, offset, len-1, ENC_UTF_8|ENC_NA);
  proto_item_append_text(pi, ", Text: %s", tvb_get_string_enc(wmem_packet_scope(), tvb, offset, len-1, ENC_UTF_8));
  offset+=len-1;

  return offset;
}

/* Section 13.2: IPv4 Connection Point */
static int
decode_dataitem_v4conn(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len, packet_info *pinfo)
{
  proto_item* tmp_pi = NULL;
  proto_tree* flags_pt = NULL;
  guint32 v4conn_port;

  tmp_pi = proto_tree_add_item(pt, hf_dlep_dataitem_v4conn, tvb, offset, len, ENC_NA);
  PROTO_ITEM_SET_HIDDEN(tmp_pi);

  tmp_pi = proto_tree_add_item(pt, hf_dlep_dataitem_v4conn_flags, tvb, offset, DLEP_DIT_V4CONN_FLAGS_LEN, ENC_NA);
  flags_pt = proto_item_add_subtree(tmp_pi, ett_dlep_flags);
  proto_tree_add_item(flags_pt, hf_dlep_dataitem_v4conn_flags_tls, tvb, offset, DLEP_DIT_V4CONN_FLAGS_LEN, ENC_NA);
  offset+=DLEP_DIT_V4CONN_FLAGS_LEN;

  proto_tree_add_item(pt, hf_dlep_dataitem_v4conn_addr, tvb, offset, FT_IPv4_LEN, ENC_BIG_ENDIAN);
  proto_item_append_text(pi, ", Addr: %s", tvb_ip_to_str(tvb, offset));
  offset+=FT_IPv4_LEN;

  if (len == DLEP_DIT_V4CONN_WPORT_LEN) {
    proto_tree_add_item_ret_uint(pt, hf_dlep_dataitem_v4conn_port, tvb, offset, 2, ENC_BIG_ENDIAN, &v4conn_port);
    proto_item_append_text(pi, ", Port: %u", v4conn_port);
    offset+=2;
  }

  if (len != DLEP_DIT_V4CONN_LEN && len != DLEP_DIT_V4CONN_WPORT_LEN)
    expert_add_info(pinfo, pi, &ei_dlep_dataitem_unexpected_length);

  return offset;
}

/* Section 13.3: IPv6 Connection Point */
static int
decode_dataitem_v6conn(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len, packet_info *pinfo)
{
  proto_item* tmp_pi = NULL;
  proto_tree* flags_pt = NULL;
  guint32 v6conn_port;

  tmp_pi = proto_tree_add_item(pt, hf_dlep_dataitem_v6conn, tvb, offset, len, ENC_NA);
  PROTO_ITEM_SET_HIDDEN(tmp_pi);

  tmp_pi = proto_tree_add_item(pt, hf_dlep_dataitem_v6conn_flags, tvb, offset, DLEP_DIT_V6CONN_FLAGS_LEN, ENC_NA);
  flags_pt = proto_item_add_subtree(tmp_pi, ett_dlep_flags);
  proto_tree_add_item(flags_pt, hf_dlep_dataitem_v6conn_flags_tls, tvb, offset, DLEP_DIT_V6CONN_FLAGS_LEN, ENC_NA);
  offset+=DLEP_DIT_V6CONN_FLAGS_LEN;

  proto_tree_add_item(pt, hf_dlep_dataitem_v6conn_addr, tvb, offset, FT_IPv6_LEN, ENC_NA);
  proto_item_append_text(pi, ", Addr: %s", tvb_ip6_to_str(tvb, offset));
  offset+=FT_IPv6_LEN;

  if (len == DLEP_DIT_V6CONN_WPORT_LEN) {
    proto_tree_add_item_ret_uint(pt, hf_dlep_dataitem_v6conn_port, tvb, offset, 2, ENC_BIG_ENDIAN, &v6conn_port);
    proto_item_append_text(pi, ", Port: %u", v6conn_port);
    offset+=2;
  }

  if (len != DLEP_DIT_V6CONN_LEN && len != DLEP_DIT_V6CONN_WPORT_LEN)
    expert_add_info(pinfo, pi, &ei_dlep_dataitem_unexpected_length);

  return offset;
}

/* Section 13.4: Peer Type */
static int
decode_dataitem_peertype(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len, packet_info *pinfo)
{
  proto_item *tmp_pi = NULL;
  proto_tree * flags_pt = NULL;

  tmp_pi = proto_tree_add_item(pt, hf_dlep_dataitem_peertype, tvb, offset, len, ENC_NA);
  PROTO_ITEM_SET_HIDDEN(tmp_pi);

  if (len < DLEP_DIT_PEERTYPE_MINLEN) {
    expert_add_info(pinfo, pi, &ei_dlep_dataitem_unexpected_length);
    return offset;
  }

  tmp_pi = proto_tree_add_item(pt, hf_dlep_dataitem_peertype_flags, tvb, offset, DLEP_DIT_PEERTYPE_FLAGS_LEN, ENC_NA);
  flags_pt = proto_item_add_subtree(tmp_pi, ett_dlep_flags);
  proto_tree_add_item(flags_pt, hf_dlep_dataitem_peertype_flags_smi, tvb, offset, DLEP_DIT_PEERTYPE_FLAGS_LEN, ENC_NA);
  offset+=DLEP_DIT_PEERTYPE_FLAGS_LEN;

  proto_tree_add_item(pt, hf_dlep_dataitem_peertype_description, tvb, offset, len-DLEP_DIT_PEERTYPE_FLAGS_LEN, ENC_UTF_8|ENC_NA);
  proto_item_append_text(pi, ", Description: %s", tvb_get_string_enc(wmem_packet_scope(), tvb, offset, len-DLEP_DIT_PEERTYPE_FLAGS_LEN, ENC_UTF_8));
  offset+=len-DLEP_DIT_PEERTYPE_FLAGS_LEN;

  return offset;
}

/* Section 13.5: Heartbeat Interval */
static int
decode_dataitem_heartbeat(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len, packet_info *pinfo)
{
  guint32 heartbeat;

  proto_tree_add_item_ret_uint(pt, hf_dlep_dataitem_heartbeat, tvb, offset, DLEP_DIT_HEARTBEAT_LEN, ENC_BIG_ENDIAN, &heartbeat);
  proto_item_append_text(pi, ": %u (ms)", heartbeat);
  offset+=DLEP_DIT_HEARTBEAT_LEN;

  if (len != DLEP_DIT_HEARTBEAT_LEN)
    expert_add_info(pinfo, pi, &ei_dlep_dataitem_unexpected_length);

  return offset;
}

/* Section 13.6: Extensions Supported */
static int
decode_dataitem_extsupp(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len)
{
  guint32 extension_code;

  proto_item* tmp_pi = NULL;

  tmp_pi = proto_tree_add_item(pt, hf_dlep_dataitem_extsupp, tvb, offset, len, ENC_NA);
  PROTO_ITEM_SET_HIDDEN(tmp_pi);

  while(len > 0) {
    proto_tree_add_item_ret_uint(pt, hf_dlep_dataitem_extsupp_code, tvb, offset, 2, ENC_BIG_ENDIAN, &extension_code);
    proto_item_append_text(pi, ", Ext: %s (%u)", rval_to_str(extension_code, extension_code_vals, "Unknown"), extension_code);
    offset+=2;
    len-=2;
  }

  return offset;
}

/* Section 13.7: MAC Address */
static int
decode_dataitem_macaddr(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len)
{
  switch(len) {
    case FT_ETHER_LEN:
      proto_tree_add_item(pt, hf_dlep_dataitem_macaddr_eui48, tvb, offset, len, ENC_NA);
      proto_item_append_text(pi, ": %s", tvb_ether_to_str(tvb, offset));
      break;
    case FT_EUI64_LEN:
      proto_tree_add_item(pt, hf_dlep_dataitem_macaddr_eui64, tvb, offset, len, ENC_BIG_ENDIAN);
      proto_item_append_text(pi, ": %s", tvb_eui64_to_str(tvb, offset));
      break;
    default:
      proto_tree_add_expert(pt, NULL, &ei_dlep_dataitem_macaddr_unexpected_length, tvb, offset, len);
      break;
  }
  offset+=len;

  return offset;
}

/* Section 13.8: IPv4 Address */
static int
decode_dataitem_v4addr(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len, packet_info *pinfo)
{
  proto_item* tmp_pi = NULL;
  proto_tree* flags_pt = NULL;

  tmp_pi = proto_tree_add_item(pt, hf_dlep_dataitem_v4addr, tvb, offset, DLEP_DIT_V4ADDR_LEN, ENC_NA);
  PROTO_ITEM_SET_HIDDEN(tmp_pi);

  tmp_pi = proto_tree_add_item(pt, hf_dlep_dataitem_v4addr_flags, tvb, offset, DLEP_DIT_V4ADDR_FLAGS_LEN, ENC_NA);
  flags_pt = proto_item_add_subtree(tmp_pi, ett_dlep_flags);
  proto_tree_add_item(flags_pt, hf_dlep_dataitem_v4addr_flags_adddrop, tvb, offset, DLEP_DIT_V4ADDR_FLAGS_LEN, ENC_BIG_ENDIAN);
  proto_item_append_text(pi, ", %s:", tfs_get_string(tvb_get_guint8(tvb, offset) & DLEP_DIT_V4ADDR_FLAGMASK_ADDDROP, &tfs_add_drop));
  offset+=DLEP_DIT_V4ADDR_FLAGS_LEN;

  proto_tree_add_item(pt, hf_dlep_dataitem_v4addr_addr, tvb, offset, FT_IPv4_LEN, ENC_BIG_ENDIAN);
  proto_item_append_text(pi, " %s", tvb_ip_to_str(tvb, offset));
  offset+=FT_IPv4_LEN;

  if (len != DLEP_DIT_V4ADDR_LEN)
    expert_add_info(pinfo, pi, &ei_dlep_dataitem_unexpected_length);

  return offset;
}

/* Section 13.9: IPv6 Address */
static int
decode_dataitem_v6addr(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len, packet_info *pinfo)
{
  proto_item* tmp_pi = NULL;
  proto_tree* flags_pt = NULL;

  tmp_pi = proto_tree_add_item(pt, hf_dlep_dataitem_v6addr, tvb, offset, DLEP_DIT_V6ADDR_LEN, ENC_NA);
  PROTO_ITEM_SET_HIDDEN(tmp_pi);

  tmp_pi = proto_tree_add_item(pt, hf_dlep_dataitem_v6addr_flags, tvb, offset, DLEP_DIT_V6ADDR_FLAGS_LEN, ENC_NA);
  flags_pt = proto_item_add_subtree(tmp_pi, ett_dlep_flags);
  proto_tree_add_item(flags_pt, hf_dlep_dataitem_v6addr_flags_adddrop, tvb, offset, DLEP_DIT_V6ADDR_FLAGS_LEN, ENC_BIG_ENDIAN);
  proto_item_append_text(pi, ", %s:", tfs_get_string(tvb_get_guint8(tvb, offset) & DLEP_DIT_V6ADDR_FLAGMASK_ADDDROP, &tfs_add_drop));
  offset+=DLEP_DIT_V6ADDR_FLAGS_LEN;

  proto_tree_add_item(pt, hf_dlep_dataitem_v6addr_addr, tvb, offset, FT_IPv6_LEN, ENC_NA);
  proto_item_append_text(pi, " %s", tvb_ip6_to_str(tvb, offset));
  offset+=FT_IPv6_LEN;

  if (len != DLEP_DIT_V6ADDR_LEN)
    expert_add_info(pinfo, pi, &ei_dlep_dataitem_unexpected_length);

  return offset;
}

/* Section 13.10: IPv4 Attached Subnet */
static int
decode_dataitem_v4subnet(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len, packet_info *pinfo)
{
  proto_item* tmp_pi = NULL;
  proto_tree* flags_pt = NULL;
  guint32 prefixlen;

  tmp_pi = proto_tree_add_item(pt, hf_dlep_dataitem_v4subnet, tvb, offset, DLEP_DIT_V4SUBNET_LEN, ENC_NA);
  PROTO_ITEM_SET_HIDDEN(tmp_pi);

  tmp_pi = proto_tree_add_item(pt, hf_dlep_dataitem_v4subnet_flags, tvb, offset, DLEP_DIT_V4SUBNET_FLAGS_LEN, ENC_NA);
  flags_pt = proto_item_add_subtree(tmp_pi, ett_dlep_flags);
  proto_tree_add_item(flags_pt, hf_dlep_dataitem_v4subnet_flags_adddrop, tvb, offset, DLEP_DIT_V4SUBNET_FLAGS_LEN, ENC_BIG_ENDIAN);
  proto_item_append_text(pi, ", %s:", tfs_get_string(tvb_get_guint8(tvb, offset) & DLEP_DIT_V4SUBNET_FLAGMASK_ADDDROP, &tfs_add_drop));
  offset+=DLEP_DIT_V4SUBNET_FLAGS_LEN;

  proto_tree_add_item(pt, hf_dlep_dataitem_v4subnet_subnet, tvb, offset, FT_IPv4_LEN, ENC_BIG_ENDIAN);
  proto_item_append_text(pi, " %s", tvb_ip_to_str(tvb, offset));
  offset+=FT_IPv4_LEN;

  proto_tree_add_item_ret_uint(pt, hf_dlep_dataitem_v4subnet_prefixlen, tvb, offset, 1, ENC_BIG_ENDIAN, &prefixlen);
  proto_item_append_text(pi, "/%u", prefixlen);
  offset+=1;

  if (len != DLEP_DIT_V4SUBNET_LEN)
    expert_add_info(pinfo, pi, &ei_dlep_dataitem_unexpected_length);

  return offset;
}

/* Section 13.11: IPv6 Attached Subnet */
static int
decode_dataitem_v6subnet(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len, packet_info *pinfo)
{
  proto_item* tmp_pi = NULL;
  proto_tree* flags_pt = NULL;
  guint32 prefixlen;

  tmp_pi = proto_tree_add_item(pt, hf_dlep_dataitem_v6subnet, tvb, offset, DLEP_DIT_V6SUBNET_LEN, ENC_NA);
  PROTO_ITEM_SET_HIDDEN(tmp_pi);

  tmp_pi = proto_tree_add_item(pt, hf_dlep_dataitem_v6subnet_flags, tvb, offset, DLEP_DIT_V6SUBNET_FLAGS_LEN, ENC_NA);
  flags_pt = proto_item_add_subtree(tmp_pi, ett_dlep_flags);
  proto_tree_add_item(flags_pt, hf_dlep_dataitem_v6subnet_flags_adddrop, tvb, offset, DLEP_DIT_V6SUBNET_FLAGS_LEN, ENC_BIG_ENDIAN);
  proto_item_append_text(pi, ", %s:", tfs_get_string(tvb_get_guint8(tvb, offset) & DLEP_DIT_V6SUBNET_FLAGMASK_ADDDROP, &tfs_add_drop));
  offset+=DLEP_DIT_V6SUBNET_FLAGS_LEN;

  proto_tree_add_item(pt, hf_dlep_dataitem_v6subnet_subnet, tvb, offset, FT_IPv6_LEN, ENC_NA);
  proto_item_append_text(pi, " %s", tvb_ip6_to_str(tvb, offset));
  offset+=FT_IPv6_LEN;

  proto_tree_add_item_ret_uint(pt, hf_dlep_dataitem_v6subnet_prefixlen, tvb, offset, 1, ENC_BIG_ENDIAN, &prefixlen);
  proto_item_append_text(pi, "/%u", prefixlen);
  offset+=1;

  if (len != DLEP_DIT_V6SUBNET_LEN)
    expert_add_info(pinfo, pi, &ei_dlep_dataitem_unexpected_length);

  return offset;
}

/* Section 13.12: Maximum Data Rate (Receive) */
static int
decode_dataitem_mdrr(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len, packet_info *pinfo)
{
  guint64 mdrr;

  proto_tree_add_item_ret_uint64(pt, hf_dlep_dataitem_mdrr, tvb, offset, DLEP_DIT_MDRR_LEN, ENC_BIG_ENDIAN, &mdrr);
  proto_item_append_text(pi, ": %" G_GUINT64_FORMAT " (bps)", mdrr);
  offset+=DLEP_DIT_MDRR_LEN;

  if (len != DLEP_DIT_MDRR_LEN)
    expert_add_info(pinfo, pi, &ei_dlep_dataitem_unexpected_length);

  return offset;
}

/* Section 13.13: Maximum Data Rate (Transmit) */
static int
decode_dataitem_mdrt(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len, packet_info *pinfo)
{
  guint64 mdrt;

  proto_tree_add_item_ret_uint64(pt, hf_dlep_dataitem_mdrt, tvb, offset, DLEP_DIT_MDRT_LEN, ENC_BIG_ENDIAN, &mdrt);
  proto_item_append_text(pi, ": %" G_GUINT64_FORMAT " (bps)", mdrt);
  offset+=DLEP_DIT_MDRT_LEN;

  if (len != DLEP_DIT_MDRT_LEN)
    expert_add_info(pinfo, pi, &ei_dlep_dataitem_unexpected_length);

  return offset;
}

/* Section 13.14: Current Data Rate (Receive) */
  static int
decode_dataitem_cdrr(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len, packet_info *pinfo)
{
  guint64 cdrr;

  proto_tree_add_item_ret_uint64(pt, hf_dlep_dataitem_cdrr, tvb, offset, DLEP_DIT_CDRR_LEN, ENC_BIG_ENDIAN, &cdrr);
  proto_item_append_text(pi, ": %" G_GUINT64_FORMAT " (bps)", cdrr);
  offset+=DLEP_DIT_CDRR_LEN;

  if (len != DLEP_DIT_CDRR_LEN)
    expert_add_info(pinfo, pi, &ei_dlep_dataitem_unexpected_length);

  return offset;
}

/* Section 13.15: Current Data Rate (Transmit) */
  static int
decode_dataitem_cdrt(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len, packet_info *pinfo)
{
  guint64 cdrt;

  proto_tree_add_item_ret_uint64(pt, hf_dlep_dataitem_cdrt, tvb, offset, DLEP_DIT_CDRT_LEN, ENC_BIG_ENDIAN, &cdrt);
  proto_item_append_text(pi, ": %" G_GUINT64_FORMAT " (bps)", cdrt);
  offset+=DLEP_DIT_CDRT_LEN;

  if (len != DLEP_DIT_CDRT_LEN)
    expert_add_info(pinfo, pi, &ei_dlep_dataitem_unexpected_length);

  return offset;
}

/* Section 13.16: Latency */
  static int
decode_dataitem_latency(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len, packet_info *pinfo)
{
  guint64 latency;

  proto_tree_add_item_ret_uint64(pt, hf_dlep_dataitem_latency, tvb, offset, DLEP_DIT_LAT_LEN, ENC_BIG_ENDIAN, &latency);
  proto_item_append_text(pi, ": %" G_GUINT64_FORMAT " (us)", latency);
  offset+=DLEP_DIT_LAT_LEN;

  if (len != DLEP_DIT_LAT_LEN)
    expert_add_info(pinfo, pi, &ei_dlep_dataitem_unexpected_length);

  return offset;
}

/* Section 13.17: Resources */
  static int
decode_dataitem_resources(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len, packet_info *pinfo)
{
  guint32 resources;

  proto_tree_add_item_ret_uint(pt, hf_dlep_dataitem_resources, tvb, offset, DLEP_DIT_RES_LEN, ENC_BIG_ENDIAN, &resources);
  proto_item_append_text(pi, ": %u (%%)", resources);
  offset+=DLEP_DIT_RES_LEN;

  if (len != DLEP_DIT_RES_LEN)
    expert_add_info(pinfo, pi, &ei_dlep_dataitem_unexpected_length);

  return offset;
}

/* Section 13.18: Relative Link Quality (Receive) */
  static int
decode_dataitem_rlqr(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len, packet_info *pinfo)
{
  guint32 rlqr;

  proto_tree_add_item_ret_uint(pt, hf_dlep_dataitem_rlqr, tvb, offset, DLEP_DIT_RLQR_LEN, ENC_BIG_ENDIAN, &rlqr);
  proto_item_append_text(pi, ": %u (%%)", rlqr);
  offset+=DLEP_DIT_RLQR_LEN;

  if (len != DLEP_DIT_RLQR_LEN)
    expert_add_info(pinfo, pi, &ei_dlep_dataitem_unexpected_length);

  return offset;
}

/* Section 13.19: Relative Link Quality (Transmit) */
  static int
decode_dataitem_rlqt(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len, packet_info *pinfo)
{
  guint32 rlqt;

  proto_tree_add_item_ret_uint(pt, hf_dlep_dataitem_rlqt, tvb, offset, DLEP_DIT_RLQT_LEN, ENC_BIG_ENDIAN, &rlqt);
  proto_item_append_text(pi, ": %u (%%)", rlqt);
  offset+=DLEP_DIT_RLQT_LEN;

  if (len != DLEP_DIT_RLQT_LEN)
    expert_add_info(pinfo, pi, &ei_dlep_dataitem_unexpected_length);

  return offset;
}

/* Section 11.20: Maximum Transmission Unit (MTU) */
  static int
decode_dataitem_mtu(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len, packet_info *pinfo)
{
  guint32 mtu;

  proto_tree_add_item_ret_uint(pt, hf_dlep_dataitem_mtu, tvb, offset, DLEP_DIT_MTU_LEN, ENC_BIG_ENDIAN, &mtu);
  proto_item_append_text(pi, ": %u (bytes)", mtu);
  offset+=DLEP_DIT_MTU_LEN;

  if (len != DLEP_DIT_MTU_LEN)
    expert_add_info(pinfo, pi, &ei_dlep_dataitem_unexpected_length);

  return offset;
}

/* RFC 8629 Multi-Hop Extension Hop Count*/
  static int
decode_dataitem_hop_cnt(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len, packet_info *pinfo)
{
  proto_item *pi_field = NULL;
  static int * const hop_cnt_flags[] = {
      &hf_dlep_dataitem_hop_count_flags_p,
      &hf_dlep_dataitem_hop_count_flags_reserved,
      NULL
      };

  proto_tree_add_bitmask(pt, tvb, offset, hf_dlep_dataitem_hop_count_flags, ett_dlep_flags, hop_cnt_flags, ENC_BIG_ENDIAN);
  offset+=1;
  pi_field = proto_tree_add_item(pt, hf_dlep_dataitem_hop_count, tvb, offset, 1, ENC_NA);
  proto_item_append_text(pi, ": %s Hops", proto_item_get_display_repr(wmem_packet_scope(), pi_field));
  offset+=1;

  if (len != DLEP_DIT_HOP_CNT_LEN)
    expert_add_info(pinfo, pi, &ei_dlep_dataitem_unexpected_length);

  return offset;
}

/* RFC 8629 Multi-Hop Extension Hop Control*/
  static int
decode_dataitem_hop_cntrl(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len, packet_info *pinfo)
{
  proto_item *pi_field = NULL;

  pi_field = proto_tree_add_item(pt, hf_dlep_dataitem_hop_control, tvb, offset, DLEP_DIT_HOP_CNTRL_LEN, ENC_BIG_ENDIAN);
  proto_item_append_text(pi, ": %s", proto_item_get_display_repr(wmem_packet_scope(), pi_field));
  offset+=DLEP_DIT_HOP_CNTRL_LEN;

  if (len != DLEP_DIT_HOP_CNTRL_LEN)
    expert_add_info(pinfo, pi, &ei_dlep_dataitem_unexpected_length);

  return offset;
}

/* RFC 8703 Link Identifier Extension Length */
  static int
decode_dataitem_li_length(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len, packet_info *pinfo)
{
  proto_item *pi_field = NULL;

  pi_field = proto_tree_add_item(pt, hf_dlep_dataitem_li_length, tvb, offset, DLEP_DIT_LI_LENGTH_LEN, ENC_BIG_ENDIAN);
  proto_item_append_text(pi, ": %s Bytes", proto_item_get_display_repr(wmem_packet_scope(), pi_field));
  offset+=DLEP_DIT_LI_LENGTH_LEN;

  if (len != DLEP_DIT_LI_LENGTH_LEN)
    expert_add_info(pinfo, pi, &ei_dlep_dataitem_unexpected_length);

  return offset;
}

/* RFC 8703 Link Identifier Extension Data */
  static int
decode_dataitem_li(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len, packet_info *pinfo _U_)
{
  proto_tree_add_item(pt, hf_dlep_dataitem_li, tvb, offset, len, ENC_NA);
  proto_item_append_text(pi, ": %s", tvb_bytes_to_str(wmem_packet_scope(), tvb, offset, len));
  offset+=len;

  return offset;
}

/* RFC 8757 Latency Range Extension */
  static int
decode_dataitem_lat_range(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len, packet_info *pinfo)
{
  proto_item *max_lat = NULL;
  proto_item *min_lat = NULL;

  max_lat = proto_tree_add_item(pt, hf_dlep_dataitem_max_lat, tvb, offset, 8, ENC_BIG_ENDIAN);
  offset+=8;
  min_lat = proto_tree_add_item(pt, hf_dlep_dataitem_min_lat, tvb, offset, 8, ENC_BIG_ENDIAN);
  proto_item_append_text(pi, ": %s - %s (us)", proto_item_get_display_repr(wmem_packet_scope(), min_lat), proto_item_get_display_repr(wmem_packet_scope(), max_lat));
  offset+=8;

  if (len != DLEP_DIT_LAT_RANGE_LEN)
    expert_add_info(pinfo, pi, &ei_dlep_dataitem_unexpected_length);

  return offset;
}

/**
 * Section 11.3: DLEP Generic Data Item
 *
 * A note on dataitem decoding:
 *
 * When decoding a specific dataitem, we append information to the generic
 * dataitem's protocol display line using proto_item_append_test. This is
 * intended to provide a one-line summary of the specific dataitem without
 * needing to open the corresponding subtree. The pattern is to typically
 * augment the one-line summary as each piece of the specific dataitem is
 * decoded.
 *
 * Additionally, we often create a hidden proto_item under the generic
 * dataitem tree that can be used for filtering on the specific dataitem name.
 * Subfields of the specific dataitem are then placed under the generic
 * dataitem tree. For example, the following filter 'dlep.dataitem.status' is
 * valid, but the protocol tree display places 'dlep.dataitem.status.code'
 * under 'dlep.dataitem'. For very simple dataitems (e.g., Heartbeat Interval),
 * there is only one subfield, and this step is skipped.
 */
  static int
decode_dataitem(tvbuff_t *tvb, int offset, proto_tree *pt, packet_info *pinfo)
{
  proto_item *dataitem_pi = NULL;
  proto_tree *dataitem_pt = NULL;
  int dataitem_type       = 0;
  int dataitem_length     = 0;

  dataitem_type   = tvb_get_ntohs(tvb, offset);
  dataitem_length = tvb_get_ntohs(tvb, offset+2);

  dataitem_pi = proto_tree_add_item(pt, hf_dlep_dataitem, tvb, offset, 2+2+dataitem_length, ENC_NA);
  dataitem_pt = proto_item_add_subtree(dataitem_pi, ett_dlep_dataitem);

  /* Start the one-line description of the data item */
  proto_item_set_text(dataitem_pi, "%s Data Item", val_to_str(dataitem_type, dataitem_type_vals, "Unknown"));

  /* Add supporting fields underneath */
  proto_tree_add_item(dataitem_pt, hf_dlep_dataitem_type, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset+=2;

  proto_tree_add_item(dataitem_pt, hf_dlep_dataitem_length, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset+=2;

  switch(dataitem_type) {
    case DLEP_DIT_STATUS:
      offset=decode_dataitem_status(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length, pinfo);
      break;
    case DLEP_DIT_V4CONN:
      offset=decode_dataitem_v4conn(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length, pinfo);
      break;
    case DLEP_DIT_V6CONN:
      offset=decode_dataitem_v6conn(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length, pinfo);
      break;
    case DLEP_DIT_PEERTYPE:
      offset=decode_dataitem_peertype(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length, pinfo);
      break;
    case DLEP_DIT_HEARTBEAT:
      offset=decode_dataitem_heartbeat(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length, pinfo);
      break;
    case DLEP_DIT_EXTSUPP:
      offset=decode_dataitem_extsupp(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length);
      break;
    case DLEP_DIT_MACADDR:
      offset=decode_dataitem_macaddr(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length);
      break;
    case DLEP_DIT_V4ADDR:
      offset=decode_dataitem_v4addr(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length, pinfo);
      break;
    case DLEP_DIT_V6ADDR:
      offset=decode_dataitem_v6addr(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length, pinfo);
      break;
    case DLEP_DIT_V4SUBNET:
      offset=decode_dataitem_v4subnet(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length, pinfo);
      break;
    case DLEP_DIT_V6SUBNET:
      offset=decode_dataitem_v6subnet(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length, pinfo);
      break;
    case DLEP_DIT_MDRR:
      offset=decode_dataitem_mdrr(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length, pinfo);
      break;
    case DLEP_DIT_MDRT:
      offset=decode_dataitem_mdrt(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length, pinfo);
      break;
    case DLEP_DIT_CDRR:
      offset=decode_dataitem_cdrr(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length, pinfo);
      break;
    case DLEP_DIT_CDRT:
      offset=decode_dataitem_cdrt(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length, pinfo);
      break;
    case DLEP_DIT_LAT:
      offset=decode_dataitem_latency(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length, pinfo);
      break;
    case DLEP_DIT_RES:
      offset=decode_dataitem_resources(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length, pinfo);
      break;
    case DLEP_DIT_RLQR:
      offset=decode_dataitem_rlqr(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length, pinfo);
      break;
    case DLEP_DIT_RLQT:
      offset=decode_dataitem_rlqt(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length, pinfo);
      break;
    case DLEP_DIT_MTU:
      offset=decode_dataitem_mtu(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length, pinfo);
      break;
    case DLEP_DIT_HOP_CNT:
      offset=decode_dataitem_hop_cnt(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length, pinfo);
      break;
    case DLEP_DIT_HOP_CNTRL:
      offset=decode_dataitem_hop_cntrl(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length, pinfo);
      break;
    case DLEP_DIT_LI_LENGTH:
      offset=decode_dataitem_li_length(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length, pinfo);
      break;
    case DLEP_DIT_LI:
      offset=decode_dataitem_li(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length, pinfo);
      break;
    case DLEP_DIT_LAT_RANGE:
      offset=decode_dataitem_lat_range(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length, pinfo);
      break;
    default:
      proto_tree_add_item(dataitem_pt, hf_dlep_dataitem_value, tvb, offset, dataitem_length, ENC_NA);
      offset+=dataitem_length;
  };

  return offset;
}

/* Section 11.1: DLEP Signal Header */
static int
decode_signal_header(tvbuff_t *tvb, int offset, proto_item* pi, proto_tree *pt, packet_info *pinfo)
{
  proto_item *tmp_pi = NULL;
  guint32 signal_type;
  guint32 signal_length;

  tmp_pi = proto_tree_add_item(pt, hf_dlep_signal, tvb, offset, 0, ENC_NA);
  PROTO_ITEM_SET_HIDDEN(tmp_pi);

  proto_tree_add_item(pt, hf_dlep_signal_signature, tvb, offset, 4, ENC_ASCII|ENC_NA);
  offset+=4;

  proto_tree_add_item_ret_uint(pt, hf_dlep_signal_type, tvb, offset, 2, ENC_BIG_ENDIAN, &signal_type);
  proto_item_append_text(pi, ", Signal: %s (%u)", val_to_str(signal_type, signal_type_vals, "Unknown"), signal_type);
  col_add_fstr(pinfo->cinfo, COL_INFO, "Signal: %s (%u)", val_to_str(signal_type, signal_type_vals, "Unknown"), signal_type);
  offset+=2;

  tmp_pi = proto_tree_add_item_ret_uint(pt, hf_dlep_signal_length, tvb, offset, 2, ENC_BIG_ENDIAN, &signal_length);
  offset+=2;

  if (signal_length != (guint32)tvb_reported_length_remaining(tvb, offset))
    expert_add_info(pinfo, tmp_pi, &ei_dlep_signal_unexpected_length);

  return offset;
}

/* Section 11.2: DLEP Message Header */
static int
decode_message_header(tvbuff_t *tvb, int offset, proto_item* pi, proto_tree *pt, packet_info *pinfo)
{
  proto_item *tmp_pi = NULL;
  guint32 message_type;
  guint32 message_length;

  tmp_pi = proto_tree_add_item(pt, hf_dlep_message, tvb, offset, 0, ENC_NA);
  PROTO_ITEM_SET_HIDDEN(tmp_pi);

  proto_tree_add_item_ret_uint(pt, hf_dlep_message_type, tvb, offset, 2, ENC_BIG_ENDIAN, &message_type);
  proto_item_append_text(pi, ", Message: %s (%u)", val_to_str(message_type, message_type_vals, "Unknown"), message_type);
  col_add_fstr(pinfo->cinfo, COL_INFO, "Message: %s (%u)", val_to_str(message_type, message_type_vals, "Unknown"), message_type);
  offset+=2;

  tmp_pi = proto_tree_add_item_ret_uint(pt, hf_dlep_message_length, tvb, offset, 2, ENC_BIG_ENDIAN, &message_length);
  offset+=2;

  if (message_length != (guint32)tvb_reported_length_remaining(tvb, offset))
    expert_add_info(pinfo, tmp_pi, &ei_dlep_message_unexpected_length);

  return offset;
}

static int
dissect_dlep_sig(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pt, void *data _U_)
{
  int         offset            = 0;
  proto_item *dlep_pi           = NULL;
  proto_tree *dlep_pt           = NULL;

  /* init column strings */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "DLEP");
  col_clear(pinfo->cinfo, COL_INFO);

  dlep_pi = proto_tree_add_item(pt, proto_dlep, tvb, 0, -1, ENC_NA);
  dlep_pt = proto_item_add_subtree(dlep_pi, ett_dlep);

  /* decode dlep header */
  offset = decode_signal_header(tvb, offset, dlep_pi, dlep_pt, pinfo);

  /* decode dlep dataitems */
  while (tvb_reported_length_remaining(tvb, offset) > 0) {
    offset = decode_dataitem(tvb, offset, dlep_pt, pinfo);
  }

  return tvb_captured_length(tvb);
}

static int
dissect_dlep_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pt, void *data _U_)
{
  int         offset            = 0;
  proto_item *dlep_pi           = NULL;
  proto_tree *dlep_pt           = NULL;

  /* init column strings */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "DLEP");
  col_clear(pinfo->cinfo, COL_INFO);

  dlep_pi = proto_tree_add_item(pt, proto_dlep, tvb, 0, -1, ENC_NA);
  dlep_pt = proto_item_add_subtree(dlep_pi, ett_dlep);

  /* decode dlep header */
  offset = decode_message_header(tvb, offset, dlep_pi, dlep_pt, pinfo);

  /* decode dlep dataitems */
  while (tvb_reported_length_remaining(tvb, offset) > 0) {
    offset = decode_dataitem(tvb, offset, dlep_pt, pinfo);
  }

  return tvb_captured_length(tvb);
}

void
proto_register_dlep(void)
{
  expert_module_t* dlep_expert_module;

  static hf_register_info hf[] = {
    /* name, abbrev, type, display, strings, bitmask, blurb */
    { &hf_dlep_signal,
      { "Signal", "dlep.signal", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_signal_signature,
      { "Signature", "dlep.signal.signature", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_signal_type,
      { "Signal Type", "dlep.signal.type", FT_UINT16, BASE_DEC, VALS(signal_type_vals), 0x0, NULL, HFILL }
    },
    { &hf_dlep_signal_length,
      { "Signal Length (bytes)", "dlep.signal.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_message,
      { "Message", "dlep.message", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_message_type,
      { "Message Type", "dlep.message.type", FT_UINT16, BASE_DEC, VALS(message_type_vals), 0x0, NULL, HFILL }
    },
    { &hf_dlep_message_length,
      { "Message Length (bytes)", "dlep.message.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem,
      { "Data Item", "dlep.dataitem", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_type,
      { "Type", "dlep.dataitem.type", FT_UINT16, BASE_DEC, VALS(dataitem_type_vals), 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_length,
      { "Length (bytes)", "dlep.dataitem.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_value,
      { "Value", "dlep.dataitem.value", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_status,
      { "Status", "dlep.dataitem.status", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_status_code,
      { "Code", "dlep.dataitem.status.code", FT_UINT8, BASE_DEC, VALS(status_code_vals), 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_status_text,
      { "Text", "dlep.dataitem.status.text", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v4conn,
      { "IPv4 Connection Point", "dlep.dataitem.v4conn", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v4conn_flags,
      { "Flags", "dlep.dataitem.v4conn.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v4conn_flags_tls,
      { "Use TLS Indicator", "dlep.dataitem.v4conn.flags.tls", FT_BOOLEAN, DLEP_DIT_V4CONN_FLAGMASK_BITLEN, TFS(&tfs_set_notset), DLEP_DIT_V4CONN_FLAGMASK_TLS, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v4conn_addr,
      { "Address", "dlep.dataitem.v4conn.addr", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v4conn_port,
      { "Port", "dlep.dataitem.v4conn.port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v6conn,
      { "IPv6 Connection Point", "dlep.dataitem.v6conn", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v6conn_flags,
      { "Flags", "dlep.dataitem.v6conn.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v6conn_flags_tls,
      { "Use TLS Indicator", "dlep.dataitem.v6conn.flags.tls", FT_BOOLEAN, DLEP_DIT_V6CONN_FLAGMASK_BITLEN, TFS(&tfs_set_notset), DLEP_DIT_V6CONN_FLAGMASK_TLS, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v6conn_addr,
      { "Address", "dlep.dataitem.v6conn.addr", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v6conn_port,
      { "Port", "dlep.dataitem.v6conn.port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_peertype,
      { "Peer Type", "dlep.dataitem.peertype", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_peertype_flags,
      { "Flags", "dlep.dataitem.peertype.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_peertype_flags_smi,
      { "Secure Medium Indicator", "dlep.dataitem.peertype.flags.smi", FT_BOOLEAN, DLEP_DIT_PEERTYPE_FLAGMASK_BITLEN, TFS(&tfs_set_notset), DLEP_DIT_PEERTYPE_FLAGMASK_SMI, NULL, HFILL }
    },
    { &hf_dlep_dataitem_peertype_description,
      { "Text", "dlep.dataitem.peertype.description", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_heartbeat,
      { "Heartbeat Interval (ms)", "dlep.dataitem.heartbeat", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_extsupp,
      { "Extensions Supported", "dlep.dataitem.extsupp", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_extsupp_code,
      { "Code", "dlep.dataitem.extsupp.code", FT_UINT32, BASE_DEC|BASE_RANGE_STRING, RVALS(extension_code_vals), 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_macaddr_eui48,
      { "MAC Address", "dlep.dataitem.macaddr", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_macaddr_eui64,
      { "MAC Address", "dlep.dataitem.macaddr", FT_EUI64, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v4addr,
      { "IPv4 Address", "dlep.dataitem.v4addr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v4addr_flags,
      { "Flags", "dlep.dataitem.v4addr.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v4addr_flags_adddrop,
      { "Add/Drop Indicator", "dlep.dataitem.v4addr.flags.adddrop", FT_BOOLEAN, DLEP_DIT_V4ADDR_FLAGMASK_BITLEN, TFS(&tfs_add_drop), DLEP_DIT_V4ADDR_FLAGMASK_ADDDROP, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v4addr_addr,
      { "Address", "dlep.dataitem.v4addr.addr", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v6addr,
      { "IPv6 Address", "dlep.dataitem.v6addr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v6addr_flags,
      { "Flags", "dlep.dataitem.v6addr.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v6addr_flags_adddrop,
      { "Add/Drop Indicator", "dlep.dataitem.v6addr.flags.adddrop", FT_BOOLEAN, DLEP_DIT_V6ADDR_FLAGMASK_BITLEN, TFS(&tfs_add_drop), DLEP_DIT_V6ADDR_FLAGMASK_ADDDROP, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v6addr_addr,
      { "Address", "dlep.dataitem.v6addr.addr", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v4subnet,
      { "IPv4 Attached Subnet", "dlep.dataitem.v4subnet", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v4subnet_flags,
      { "Flags", "dlep.dataitem.v4subnet.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v4subnet_flags_adddrop,
      { "Add/Drop Indicator", "dlep.dataitem.v4subnet.flags.adddrop", FT_BOOLEAN, DLEP_DIT_V4SUBNET_FLAGMASK_BITLEN, TFS(&tfs_add_drop), DLEP_DIT_V4SUBNET_FLAGMASK_ADDDROP, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v4subnet_subnet,
      { "Subnet", "dlep.dataitem.v4subnet.subnet", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v4subnet_prefixlen,
      { "Prefix Length", "dlep.dataitem.v4subnet.prefixlen", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v6subnet,
      { "IPv6 Attached Subnet", "dlep.dataitem.v6subnet", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v6subnet_flags,
      { "Flags", "dlep.dataitem.v6subnet.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v6subnet_flags_adddrop,
      { "Add/Drop Indicator", "dlep.dataitem.v6subnet.flags.adddrop", FT_BOOLEAN, DLEP_DIT_V6SUBNET_FLAGMASK_BITLEN, TFS(&tfs_add_drop), DLEP_DIT_V6SUBNET_FLAGMASK_ADDDROP, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v6subnet_subnet,
      { "Subnet", "dlep.dataitem.v6subnet.subnet", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v6subnet_prefixlen,
      { "Prefix Length", "dlep.dataitem.v6subnet.prefixlen", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_mdrr,
      { "Maximum Data Rate (Receive) (bps)", "dlep.dataitem.mdrr", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_mdrt,
      { "Maximum Data Rate (Transmit) (bps)", "dlep.dataitem.mdrt", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_cdrr,
      { "Current Data Rate (Receive) (bps)", "dlep.dataitem.cdrr", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_cdrt,
      { "Current Data Rate (Transmit) (bps)", "dlep.dataitem.cdrt", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_latency,
      { "Latency (us)", "dlep.dataitem.latency", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_resources,
      { "Resources (%)", "dlep.dataitem.resources", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_rlqr,
      { "Relative Link Quality (Receive) (%)", "dlep.dataitem.rlqr", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_rlqt,
      { "Relative Link Quality (Transmit) (%)", "dlep.dataitem.rlqt", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_mtu,
      { "Maximum Transmission Unit (bytes)", "dlep.dataitem.mtu", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_hop_count_flags,
      { "Flags", "dlep.dataitem.hop_count_flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_hop_count_flags_p,
      { "P-Bit", "dlep.dataitem.hop_count_flags.p", FT_BOOLEAN, 8, TFS(&tfs_set_notset), DLEP_DIT_HOP_CNT_FLAGMASK_P, "Destination is potentially directly reachable", HFILL }
    },
    { &hf_dlep_dataitem_hop_count_flags_reserved,
      { "Reserved", "dlep.dataitem.hop_count_flags.reserved", FT_UINT8, BASE_HEX, NULL, DLEP_DIT_HOP_CNT_FLAGMASK_RESERVED, NULL, HFILL }
    },
    { &hf_dlep_dataitem_hop_count,
      { "Hop Count", "dlep.dataitem.hop_count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_hop_control,
      { "Hop Control", "dlep.dataitem.hop_control", FT_UINT16, BASE_DEC|BASE_RANGE_STRING, RVALS(hop_cntrl_action_vals), 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_li_length,
      { "Link Identifier Length", "dlep.dataitem.link_identifier_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_li,
      { "Link Identifier", "dlep.dataitem.link_identifier", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_max_lat,
      { "Maximum Latency (us)", "dlep.dataitem.max_latency", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_min_lat,
      { "Minimum Latency (us)", "dlep.dataitem.min_latency", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
    }
  };

  static gint *ett[] = {
    &ett_dlep,
    &ett_dlep_dataitem,
    &ett_dlep_flags
  };

  static ei_register_info ei[] = {
    { &ei_dlep_signal_unexpected_length, { "dlep.signal.unexpected_length", PI_PROTOCOL, PI_WARN, "Message length does not match reported length remaining", EXPFILL }},
    { &ei_dlep_message_unexpected_length, { "dlep.message.unexpected_length", PI_PROTOCOL, PI_WARN, "Signal length does not match reported length remaining", EXPFILL }},
    { &ei_dlep_dataitem_unexpected_length, { "dlep.dataitem.unexpected_length", PI_PROTOCOL, PI_WARN, "Unexpected Data Item length", EXPFILL }},
    { &ei_dlep_dataitem_macaddr_unexpected_length, { "dlep.dataitem.macaddr.unexpected_length", PI_PROTOCOL, PI_WARN, "Unexpected MAC Address length", EXPFILL }},
  };

  proto_dlep = proto_register_protocol("Dynamic Link Exchange Protocol", "DLEP", "dlep");
  dlep_msg_handle = register_dissector ("dlep.tcp", dissect_dlep_msg, proto_dlep);
  dlep_sig_handle = register_dissector ("dlep.udp", dissect_dlep_sig, proto_dlep);

  proto_register_field_array(proto_dlep, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  dlep_expert_module = expert_register_protocol(proto_dlep);
  expert_register_field_array(dlep_expert_module, ei, array_length(ei));
}

void
proto_reg_handoff_dlep(void)
{
  dissector_add_uint_range_with_preference("tcp.port", DLEP_TCP_PORT, dlep_msg_handle);
  dissector_add_uint_range_with_preference("udp.port", DLEP_UDP_PORT, dlep_sig_handle);
}
