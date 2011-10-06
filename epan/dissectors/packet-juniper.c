/* packet-juniper.c
 * Routines for Juniper Networks, Inc. packet disassembly
 * Copyright 2005 Hannes Gredler <hannes@juniper.net>
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/prefs.h>
#include <epan/addr_resolv.h>
#include <epan/ppptypes.h>
#include "packet-ppp.h"
#include "packet-ip.h"
#include <epan/nlpid.h>

#define JUNIPER_FLAG_PKT_OUT        0x00     /* Outgoing packet */
#define JUNIPER_FLAG_PKT_IN         0x01     /* Incoming packet */
#define JUNIPER_FLAG_NO_L2          0x02     /* L2 header stripped */
#define JUNIPER_FLAG_EXT            0x80     /* extensions present */
#define EXT_TLV_HEADER_SIZE 2
#define JUNIPER_ATM2_PKT_TYPE_MASK  0x70
#define JUNIPER_ATM2_GAP_COUNT_MASK 0x3F
#define JUNIPER_PCAP_MAGIC          0x4d4743

#define JUNIPER_PIC_ATM1   1
#define JUNIPER_PIC_ATM2   2
#define JUNIPER_PIC_MLPPP  3
#define JUNIPER_PIC_MLFR   4

#define JUNIPER_HDR_SNAP   0xaaaa03
#define JUNIPER_HDR_NLPID  0xfefe03
#define JUNIPER_HDR_LLC_UI 0x03
#define JUNIPER_HDR_PPP    0xff03

#define ML_PIC_COOKIE_LEN 2
#define LS_PIC_COOKIE_LEN 4
#define AS_PIC_COOKIE_LEN 8

#define GSP_SVC_REQ_APOLLO 0x40
#define GSP_SVC_REQ_LSQ    0x47

#define LSQ_COOKIE_RE         0x2
#define LSQ_COOKIE_DIR        0x1
#define LSQ_L3_PROTO_SHIFT     4
#define LSQ_L3_PROTO_MASK     0xf0
#define LSQ_L3_PROTO_IPV4     (0 << LSQ_L3_PROTO_SHIFT)
#define LSQ_L3_PROTO_IPV6     (1 << LSQ_L3_PROTO_SHIFT)
#define LSQ_L3_PROTO_MPLS     (2 << LSQ_L3_PROTO_SHIFT)
#define LSQ_L3_PROTO_ISO      (3 << LSQ_L3_PROTO_SHIFT)

#define EXT_TLV_IFD_IDX           1
#define EXT_TLV_IFD_NAME          2
#define EXT_TLV_IFD_MEDIATYPE     3
#define EXT_TLV_IFL_IDX           4
#define EXT_TLV_IFL_UNIT          5
#define EXT_TLV_IFL_ENCAPS        6
#define EXT_TLV_TTP_IFD_MEDIATYPE 7
#define EXT_TLV_TTP_IFL_ENCAPS    8

static const value_string ext_tlv_vals[] = {
  { EXT_TLV_IFD_IDX,           "Device Interface Index" },
  { EXT_TLV_IFD_NAME,          "Device Interface Name" },
  { EXT_TLV_IFD_MEDIATYPE,     "Device Media Type" },
  { EXT_TLV_IFL_IDX,           "Logical Interface Index" },
  { EXT_TLV_IFL_UNIT,          "Logical Unit Number" },
  { EXT_TLV_IFL_ENCAPS,        "Logical Interface Encapsulation" },
  { EXT_TLV_TTP_IFD_MEDIATYPE, "TTP derived Device Media Type" },
  { EXT_TLV_TTP_IFL_ENCAPS,    "TTP derived Logical Interface Encapsulation" },
  { 0,             NULL }
};

static const value_string juniper_direction_vals[] = {
  {JUNIPER_FLAG_PKT_OUT, "Out"},
  {JUNIPER_FLAG_PKT_IN,  "In"},
  {0,                    NULL}
};

static const value_string juniper_l2hdr_presence_vals[] = {
  { 0, "Present"},
  { 2, "none"},
  {0,                    NULL}
};

#define JUNIPER_IFML_ETHER              1
#define JUNIPER_IFML_FDDI               2
#define JUNIPER_IFML_TOKENRING          3
#define JUNIPER_IFML_PPP                4
#define JUNIPER_IFML_FRAMERELAY         5
#define JUNIPER_IFML_CISCOHDLC          6
#define JUNIPER_IFML_SMDSDXI            7
#define JUNIPER_IFML_ATMPVC             8
#define JUNIPER_IFML_PPP_CCC            9
#define JUNIPER_IFML_FRAMERELAY_CCC     10
#define JUNIPER_IFML_IPIP               11
#define JUNIPER_IFML_GRE                12
#define JUNIPER_IFML_PIM                13
#define JUNIPER_IFML_PIMD               14
#define JUNIPER_IFML_CISCOHDLC_CCC      15
#define JUNIPER_IFML_VLAN_CCC           16
#define JUNIPER_IFML_MLPPP              17
#define JUNIPER_IFML_MLFR               18
#define JUNIPER_IFML_ML                 19
#define JUNIPER_IFML_LSI                20
#define JUNIPER_IFML_DFE                21
#define JUNIPER_IFML_ATM_CELLRELAY_CCC  22
#define JUNIPER_IFML_CRYPTO             23
#define JUNIPER_IFML_GGSN               24
#define JUNIPER_IFML_LSI_PPP            25
#define JUNIPER_IFML_LSI_CISCOHDLC      26
#define JUNIPER_IFML_PPP_TCC            27
#define JUNIPER_IFML_FRAMERELAY_TCC     28
#define JUNIPER_IFML_CISCOHDLC_TCC      29
#define JUNIPER_IFML_ETHERNET_CCC       30
#define JUNIPER_IFML_VT                 31
#define JUNIPER_IFML_EXTENDED_VLAN_CCC  32
#define JUNIPER_IFML_ETHER_OVER_ATM     33
#define JUNIPER_IFML_MONITOR            34
#define JUNIPER_IFML_ETHERNET_TCC       35
#define JUNIPER_IFML_VLAN_TCC           36
#define JUNIPER_IFML_EXTENDED_VLAN_TCC  37
#define JUNIPER_IFML_CONTROLLER         38
#define JUNIPER_IFML_MFR                39
#define JUNIPER_IFML_LS                 40
#define JUNIPER_IFML_ETHERNET_VPLS      41
#define JUNIPER_IFML_ETHERNET_VLAN_VPLS 42
#define JUNIPER_IFML_ETHERNET_EXTENDED_VLAN_VPLS 43
#define JUNIPER_IFML_LT                 44
#define JUNIPER_IFML_SERVICES           45
#define JUNIPER_IFML_ETHER_VPLS_OVER_ATM 46
#define JUNIPER_IFML_FR_PORT_CCC        47
#define JUNIPER_IFML_FRAMERELAY_EXT_CCC 48
#define JUNIPER_IFML_FRAMERELAY_EXT_TCC 49
#define JUNIPER_IFML_FRAMERELAY_FLEX    50
#define JUNIPER_IFML_GGSNI              51
#define JUNIPER_IFML_ETHERNET_FLEX      52
#define JUNIPER_IFML_COLLECTOR          53
#define JUNIPER_IFML_AGGREGATOR         54
#define JUNIPER_IFML_LAPD               55
#define JUNIPER_IFML_PPPOE              56
#define JUNIPER_IFML_PPP_SUBORDINATE    57
#define JUNIPER_IFML_CISCOHDLC_SUBORDINATE  58
#define JUNIPER_IFML_DFC                59
#define JUNIPER_IFML_PICPEER            60

static const value_string juniper_ifmt_vals[] = {
  { JUNIPER_IFML_ETHER, "Ethernet" },
  { JUNIPER_IFML_FDDI, "FDDI" },
  { JUNIPER_IFML_TOKENRING, "Token-Ring" },
  { JUNIPER_IFML_PPP, "PPP" },
  { JUNIPER_IFML_PPP_SUBORDINATE, "PPP-Subordinate" },
  { JUNIPER_IFML_FRAMERELAY, "Frame-Relay" },
  { JUNIPER_IFML_CISCOHDLC, "Cisco-HDLC" },
  { JUNIPER_IFML_SMDSDXI, "SMDS-DXI" },
  { JUNIPER_IFML_ATMPVC, "ATM-PVC" },
  { JUNIPER_IFML_PPP_CCC, "PPP-CCC" },
  { JUNIPER_IFML_FRAMERELAY_CCC, "Frame-Relay-CCC" },
  { JUNIPER_IFML_FRAMERELAY_EXT_CCC, "Extended FR-CCC" },
  { JUNIPER_IFML_IPIP, "IP-over-IP" },
  { JUNIPER_IFML_GRE, "GRE" },
  { JUNIPER_IFML_PIM, "PIM-Encapsulator" },
  { JUNIPER_IFML_PIMD, "PIM-Decapsulator" },
  { JUNIPER_IFML_CISCOHDLC_CCC, "Cisco-HDLC-CCC" },
  { JUNIPER_IFML_VLAN_CCC, "VLAN-CCC" },
  { JUNIPER_IFML_EXTENDED_VLAN_CCC, "Extended-VLAN-CCC" },
  { JUNIPER_IFML_MLPPP, "Multilink-PPP" },
  { JUNIPER_IFML_MLFR, "Multilink-FR" },
  { JUNIPER_IFML_MFR, "Multilink-FR-UNI-NNI" },
  { JUNIPER_IFML_ML, "Multilink" },
  { JUNIPER_IFML_LS, "LinkService" },
  { JUNIPER_IFML_LSI, "LSI" },
  { JUNIPER_IFML_ATM_CELLRELAY_CCC, "ATM-CCC-Cell-Relay" },
  { JUNIPER_IFML_CRYPTO, "IPSEC-over-IP" },
  { JUNIPER_IFML_GGSN, "GGSN" },
  { JUNIPER_IFML_PPP_TCC, "PPP-TCC" },
  { JUNIPER_IFML_FRAMERELAY_TCC, "Frame-Relay-TCC" },
  { JUNIPER_IFML_FRAMERELAY_EXT_TCC, "Extended FR-TCC" },
  { JUNIPER_IFML_CISCOHDLC_TCC, "Cisco-HDLC-TCC" },
  { JUNIPER_IFML_ETHERNET_CCC, "Ethernet-CCC" },
  { JUNIPER_IFML_VT, "VPN-Loopback-tunnel" },
  { JUNIPER_IFML_ETHER_OVER_ATM, "Ethernet-over-ATM" },
  { JUNIPER_IFML_ETHER_VPLS_OVER_ATM, "Ethernet-VPLS-over-ATM" },
  { JUNIPER_IFML_MONITOR, "Monitor" },
  { JUNIPER_IFML_ETHERNET_TCC, "Ethernet-TCC" },
  { JUNIPER_IFML_VLAN_TCC, "VLAN-TCC" },
  { JUNIPER_IFML_EXTENDED_VLAN_TCC, "Extended-VLAN-TCC" },
  { JUNIPER_IFML_CONTROLLER, "Controller" },
  { JUNIPER_IFML_ETHERNET_VPLS, "VPLS" },
  { JUNIPER_IFML_ETHERNET_VLAN_VPLS, "VLAN-VPLS" },
  { JUNIPER_IFML_ETHERNET_EXTENDED_VLAN_VPLS, "Extended-VLAN-VPLS" },
  { JUNIPER_IFML_LT, "Logical-tunnel" },
  { JUNIPER_IFML_SERVICES, "General-Services" },
  { JUNIPER_IFML_PPPOE, "PPPoE" },
  { JUNIPER_IFML_ETHERNET_FLEX, "Flexible-Ethernet-Services" },
  { JUNIPER_IFML_FRAMERELAY_FLEX, "Flexible-FrameRelay" },
  { JUNIPER_IFML_COLLECTOR, "Flow-collection" },
  { JUNIPER_IFML_PICPEER, "PIC Peer" },
  { JUNIPER_IFML_DFC, "Dynamic-Flow-Capture" },
  {0,                    NULL}
};

#define JUNIPER_IFLE_ATM_SNAP           2
#define JUNIPER_IFLE_ATM_NLPID          3
#define JUNIPER_IFLE_ATM_VCMUX          4
#define JUNIPER_IFLE_ATM_LLC            5
#define JUNIPER_IFLE_ATM_PPP_VCMUX      6
#define JUNIPER_IFLE_ATM_PPP_LLC        7
#define JUNIPER_IFLE_ATM_PPP_FUNI       8
#define JUNIPER_IFLE_ATM_CCC            9
#define JUNIPER_IFLE_FR_NLPID           10
#define JUNIPER_IFLE_FR_SNAP            11
#define JUNIPER_IFLE_FR_PPP             12
#define JUNIPER_IFLE_FR_CCC             13
#define JUNIPER_IFLE_ENET2              14
#define JUNIPER_IFLE_IEEE8023_SNAP      15
#define JUNIPER_IFLE_IEEE8023_LLC       16
#define JUNIPER_IFLE_PPP                17
#define JUNIPER_IFLE_CISCOHDLC          18
#define JUNIPER_IFLE_PPP_CCC            19
#define JUNIPER_IFLE_IPIP_NULL          20
#define JUNIPER_IFLE_PIM_NULL           21
#define JUNIPER_IFLE_GRE_NULL           22
#define JUNIPER_IFLE_GRE_PPP            23
#define JUNIPER_IFLE_PIMD_DECAPS        24
#define JUNIPER_IFLE_CISCOHDLC_CCC      25
#define JUNIPER_IFLE_ATM_CISCO_NLPID    26
#define JUNIPER_IFLE_VLAN_CCC           27
#define JUNIPER_IFLE_MLPPP              28
#define JUNIPER_IFLE_MLFR               29
#define JUNIPER_IFLE_LSI_NULL           30
#define JUNIPER_IFLE_AGGREGATE_UNUSED   31
#define JUNIPER_IFLE_ATM_CELLRELAY_CCC  32
#define JUNIPER_IFLE_CRYPTO             33
#define JUNIPER_IFLE_GGSN               34
#define JUNIPER_IFLE_ATM_TCC            35
#define JUNIPER_IFLE_FR_TCC             36
#define JUNIPER_IFLE_PPP_TCC            37
#define JUNIPER_IFLE_CISCOHDLC_TCC      38
#define JUNIPER_IFLE_ETHERNET_CCC       39
#define JUNIPER_IFLE_VT                 40
#define JUNIPER_IFLE_ATM_EOA_LLC        41
#define JUNIPER_IFLE_EXTENDED_VLAN_CCC          42
#define JUNIPER_IFLE_ATM_SNAP_TCC       43
#define JUNIPER_IFLE_MONITOR            44
#define JUNIPER_IFLE_ETHERNET_TCC       45
#define JUNIPER_IFLE_VLAN_TCC           46
#define JUNIPER_IFLE_EXTENDED_VLAN_TCC  47
#define JUNIPER_IFLE_MFR                48
#define JUNIPER_IFLE_ETHERNET_VPLS      49
#define JUNIPER_IFLE_ETHERNET_VLAN_VPLS 50
#define JUNIPER_IFLE_ETHERNET_EXTENDED_VLAN_VPLS 51
#define JUNIPER_IFLE_SERVICES           52
#define JUNIPER_IFLE_ATM_ETHER_VPLS_ATM_LLC                53
#define JUNIPER_IFLE_FR_PORT_CCC        54
#define JUNIPER_IFLE_ATM_MLPPP_LLC      55
#define JUNIPER_IFLE_ATM_EOA_CCC        56
#define JUNIPER_IFLE_LT_VLAN            57
#define JUNIPER_IFLE_COLLECTOR          58
#define JUNIPER_IFLE_AGGREGATOR         59
#define JUNIPER_IFLE_LAPD               60
#define JUNIPER_IFLE_ATM_PPPOE_LLC          61
#define JUNIPER_IFLE_ETHERNET_PPPOE         62
#define JUNIPER_IFLE_PPPOE                  63
#define JUNIPER_IFLE_PPP_SUBORDINATE        64
#define JUNIPER_IFLE_CISCOHDLC_SUBORDINATE  65
#define JUNIPER_IFLE_DFC                    66
#define JUNIPER_IFLE_PICPEER                67

static const value_string juniper_ifle_vals[] = {
  { JUNIPER_IFLE_AGGREGATOR, "Aggregator" },
  { JUNIPER_IFLE_ATM_CCC, "CCC over ATM" },
  { JUNIPER_IFLE_ATM_CELLRELAY_CCC, "ATM CCC Cell Relay" },
  { JUNIPER_IFLE_ATM_CISCO_NLPID, "CISCO compatible NLPID" },
  { JUNIPER_IFLE_ATM_EOA_CCC, "Ethernet over ATM CCC" },
  { JUNIPER_IFLE_ATM_EOA_LLC, "Ethernet over ATM LLC" },
  { JUNIPER_IFLE_ATM_ETHER_VPLS_ATM_LLC, "Ethernet VPLS over ATM LLC" },
  { JUNIPER_IFLE_ATM_LLC, "ATM LLC" },
  { JUNIPER_IFLE_ATM_MLPPP_LLC, "MLPPP over ATM LLC" },
  { JUNIPER_IFLE_ATM_NLPID, "ATM NLPID" },
  { JUNIPER_IFLE_ATM_PPPOE_LLC, "PPPoE over ATM LLC" },
  { JUNIPER_IFLE_ATM_PPP_FUNI, "PPP over FUNI" },
  { JUNIPER_IFLE_ATM_PPP_LLC, "PPP over ATM LLC" },
  { JUNIPER_IFLE_ATM_PPP_VCMUX, "PPP over ATM VCMUX" },
  { JUNIPER_IFLE_ATM_SNAP, "ATM SNAP" },
  { JUNIPER_IFLE_ATM_SNAP_TCC, "ATM SNAP TCC" },
  { JUNIPER_IFLE_ATM_TCC, "ATM VCMUX TCC" },
  { JUNIPER_IFLE_ATM_VCMUX, "ATM VCMUX" },
  { JUNIPER_IFLE_CISCOHDLC, "C-HDLC" },
  { JUNIPER_IFLE_CISCOHDLC_CCC, "C-HDLC CCC" },
  { JUNIPER_IFLE_CISCOHDLC_SUBORDINATE, "C-HDLC via dialer" },
  { JUNIPER_IFLE_CISCOHDLC_TCC, "C-HDLC TCC" },
  { JUNIPER_IFLE_COLLECTOR, "Collector" },
  { JUNIPER_IFLE_CRYPTO, "Crypto" },
  { JUNIPER_IFLE_ENET2, "Ethernet" },
  { JUNIPER_IFLE_ETHERNET_CCC, "Ethernet CCC" },
  { JUNIPER_IFLE_ETHERNET_EXTENDED_VLAN_VPLS, "Extended VLAN VPLS" },
  { JUNIPER_IFLE_ETHERNET_PPPOE, "PPPoE over Ethernet" },
  { JUNIPER_IFLE_ETHERNET_TCC, "Ethernet TCC" },
  { JUNIPER_IFLE_ETHERNET_VLAN_VPLS, "VLAN VPLS" },
  { JUNIPER_IFLE_ETHERNET_VPLS, "VPLS" },
  { JUNIPER_IFLE_EXTENDED_VLAN_CCC, "Extended VLAN CCC" },
  { JUNIPER_IFLE_EXTENDED_VLAN_TCC, "Extended VLAN TCC" },
  { JUNIPER_IFLE_FR_CCC, "FR CCC" },
  { JUNIPER_IFLE_FR_NLPID, "FR NLPID" },
  { JUNIPER_IFLE_FR_PORT_CCC, "FR CCC" },
  { JUNIPER_IFLE_FR_PPP, "FR PPP" },
  { JUNIPER_IFLE_FR_SNAP, "FR SNAP" },
  { JUNIPER_IFLE_FR_TCC, "FR TCC" },
  { JUNIPER_IFLE_GGSN, "GGSN" },
  { JUNIPER_IFLE_GRE_NULL, "GRE NULL" },
  { JUNIPER_IFLE_GRE_PPP, "PPP over GRE" },
  { JUNIPER_IFLE_IPIP_NULL, "IPIP" },
  { JUNIPER_IFLE_LAPD, "LAPD" },
  { JUNIPER_IFLE_LSI_NULL, "LSI Null" },
  { JUNIPER_IFLE_LT_VLAN, "LT VLAN" },
  { JUNIPER_IFLE_MFR, "MFR" },
  { JUNIPER_IFLE_MLFR, "MLFR" },
  { JUNIPER_IFLE_MLPPP, "MLPPP" },
  { JUNIPER_IFLE_MONITOR, "Monitor" },
  { JUNIPER_IFLE_PIMD_DECAPS, "PIMd" },
  { JUNIPER_IFLE_PIM_NULL, "PIM Null" },
  { JUNIPER_IFLE_PPP, "PPP" },
  { JUNIPER_IFLE_PPPOE, "PPPoE" },
  { JUNIPER_IFLE_PPP_CCC, "PPP CCC" },
  { JUNIPER_IFLE_PPP_SUBORDINATE, "" },
  { JUNIPER_IFLE_PPP_TCC, "PPP TCC" },
  { JUNIPER_IFLE_SERVICES, "General Services" },
  { JUNIPER_IFLE_VLAN_CCC, "VLAN CCC" },
  { JUNIPER_IFLE_VLAN_TCC, "VLAN TCC" },
  { JUNIPER_IFLE_VT, "VT" },
  {0,                    NULL}
};


static int proto_juniper = -1;

static int hf_juniper_magic = -1;
static int hf_juniper_direction = -1;
static int hf_juniper_l2hdr_presence = -1;
static int hf_juniper_ext_total_len = -1;
static int hf_juniper_atm1_cookie = -1;
static int hf_juniper_atm2_cookie = -1;
static int hf_juniper_mlpic_cookie = -1;
static int hf_juniper_lspic_cookie = -1;
static int hf_juniper_aspic_cookie = -1;
static int hf_juniper_vlan = -1;
static int hf_juniper_proto = -1;
static int hf_juniper_ext_ifd = -1;
static int hf_juniper_ext_ifl = -1;
static int hf_juniper_ext_unit = -1;
static int hf_juniper_ext_ifmt = -1;
static int hf_juniper_ext_ifle = -1;
static int hf_juniper_ext_ttp_ifmt = -1;
static int hf_juniper_ext_ttp_ifle = -1;

static gint ett_juniper = -1;

static dissector_handle_t ipv4_handle;
static dissector_handle_t ipv6_handle;
static dissector_handle_t mpls_handle;
static dissector_handle_t llc_handle;
static dissector_handle_t eth_handle;
static dissector_handle_t ppp_handle;
static dissector_handle_t q933_handle;
static dissector_handle_t frelay_handle;
static dissector_handle_t chdlc_handle;
static dissector_handle_t data_handle;

static dissector_table_t osinl_subdissector_table;
static dissector_table_t osinl_excl_subdissector_table;

static int dissect_juniper_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *ti, guint8 *flags);
static int dissect_juniper_payload_proto(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,proto_item *ti, guint proto, guint offset);
static void dissect_juniper_atm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 atm_pictype);
static gboolean ppp_heuristic_guess(guint16 proto);
static guint ip_heuristic_guess(guint8 ip_header_byte);
static guint juniper_svc_cookie_len (guint64 cookie);
static guint juniper_svc_cookie_proto (guint64 cookie, guint16 pictype, guint8 flags);

/* values < 200 are JUNOS internal proto values
 * found in frames containing no link-layer header */
enum {
  PROTO_UNKNOWN = 0,
  PROTO_IP = 2,
  PROTO_MPLS_IP = 3,
  PROTO_IP_MPLS = 4,
  PROTO_MPLS = 5,
  PROTO_IP6 = 6,
  PROTO_MPLS_IP6 = 7,
  PROTO_IP6_MPLS = 8,
  PROTO_CLNP = 10,
  PROTO_CLNP_MPLS = 32,
  PROTO_MPLS_CLNP = 33,
  PROTO_PPP = 200,
  PROTO_ISO = 201,
  PROTO_LLC = 202,
  PROTO_LLC_SNAP = 203,
  PROTO_ETHER = 204,
  PROTO_OAM = 205,
  PROTO_Q933 = 206,
  PROTO_FRELAY = 207,
  PROTO_CHDLC = 208
};

static const value_string juniper_proto_vals[] = {
  {PROTO_IP, "IPv4"},
  {PROTO_MPLS_IP, "MPLS->IPv4"},
  {PROTO_IP_MPLS, "IPv4->MPLS"},
  {PROTO_IP6, "IPv6"},
  {PROTO_MPLS_IP6, "MPLS->IPv6"},
  {PROTO_IP6_MPLS, "IPv6->MPLS"},
  {PROTO_PPP, "PPP"},
  {PROTO_CLNP, "CLNP"},
  {PROTO_MPLS_CLNP, "MPLS->CLNP"},
  {PROTO_CLNP_MPLS, "CLNP->MPLS"},
  {PROTO_ISO, "OSI"},
  {PROTO_MPLS, "MPLS"},
  {PROTO_LLC, "LLC"},
  {PROTO_LLC_SNAP, "LLC/SNAP"},
  {PROTO_ETHER, "Ethernet"},
  {PROTO_OAM, "ATM OAM Cell"},
  {PROTO_Q933, "Q.933"},
  {PROTO_FRELAY, "Frame-Relay"},
  {PROTO_CHDLC, "C-HDLC"},
  {0,                    NULL}
};

/* the first subtree is accessed by several routines */
static proto_tree *juniper_subtree = NULL;

/* return a TLV value based on TLV length and TLV type (host/network order) */
static int
juniper_ext_get_tlv_value(tvbuff_t *tvb, guint tlv_type, guint tlv_len, guint offset) {

  int tlv_value;

  if (tlv_type < 128) {
    /* TLVs < 128 are little-endian / host order encoded */
    switch (tlv_len) {
    case 1:
      tlv_value = tvb_get_guint8(tvb, offset);
      break;
    case 2:
      tlv_value = tvb_get_letohs(tvb, offset);
      break;
    case 3:
      tlv_value = tvb_get_letoh24(tvb, offset);
      break;
    case 4:
      tlv_value = tvb_get_letohl(tvb, offset);
      break;
    default:
      tlv_value = -1;
      break;
    }
  } else {
    /* TLVs >= 128 are big-endian / network order encoded */
    switch (tlv_len) {
    case 1:
      tlv_value = tvb_get_guint8(tvb, offset);
      break;
    case 2:
      tlv_value = tvb_get_ntohs(tvb, offset);
      break;
    case 3:
      tlv_value = tvb_get_ntoh24(tvb, offset);
      break;
    case 4:
      tlv_value = tvb_get_ntohl(tvb, offset);
      break;
    default:
      tlv_value = -1;
      break;
    }
  }
  return tlv_value;
}

/* generic juniper header dissector  */
static int
dissect_juniper_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *ti, guint8 *flags)
{
  proto_item *tisub;
  guint8     direction,l2hdr_presence,proto,ext_type,ext_len;
  guint16    ext_total_len,ext_offset=6,hdr_len;
  guint32    magic_number,ext_val;

  proto_tree *juniper_ext_subtree = NULL, *juniper_ext_subtree_item = NULL;

  magic_number = tvb_get_ntoh24(tvb, 0);
  *flags = tvb_get_guint8(tvb, 3);
  direction = *flags & JUNIPER_FLAG_PKT_IN;
  l2hdr_presence = *flags & JUNIPER_FLAG_NO_L2;

  juniper_subtree = proto_item_add_subtree(ti, ett_juniper);

  /* be liberal with magic-number detection -
   * some older JUNOS releases (e.g. 6.4),
   * which are still in the field do not generate magic-numbers */
  if (magic_number != JUNIPER_PCAP_MAGIC) {
    proto_tree_add_text (juniper_subtree, tvb, 0, 0, "no Magic-Number found !");
    return 0;
  }

  proto_tree_add_text (juniper_subtree, tvb, 0, 3,
                       "Magic-Number: 0x%06x", magic_number);

  proto_tree_add_uint_format (juniper_subtree, hf_juniper_direction, tvb, 3, 1,
                              direction, "Direction: %s",
                              val_to_str(direction,juniper_direction_vals,"Unknown"));

  proto_tree_add_uint_format (juniper_subtree, hf_juniper_l2hdr_presence, tvb, 3, 1,
                              l2hdr_presence, "L2-header: %s",
                              val_to_str(l2hdr_presence,juniper_l2hdr_presence_vals,"Unknown"));

  /* calculate hdr_len before cookie, payload */

  /* meta-info extensions (JUNOS >= 7.5) ? */
  if ((*flags & JUNIPER_FLAG_EXT) == JUNIPER_FLAG_EXT) {
    ext_total_len = tvb_get_ntohs(tvb,4);
    hdr_len = 6 + ext_total_len; /* MGC,flags,ext_total_len */

    tisub = proto_tree_add_uint (juniper_subtree, hf_juniper_ext_total_len, tvb, 4, 2, ext_total_len);
    juniper_ext_subtree = proto_item_add_subtree(tisub, ett_juniper);

    while (ext_total_len > EXT_TLV_HEADER_SIZE) {
      ext_type = tvb_get_guint8(tvb, ext_offset);
      ext_len = tvb_get_guint8(tvb, ext_offset+1);

      if (ext_len == 0 || ext_len > (ext_total_len - EXT_TLV_HEADER_SIZE)) /* a few sanity checks */
        break;

      tisub = proto_tree_add_text (juniper_ext_subtree, tvb, ext_offset, EXT_TLV_HEADER_SIZE + ext_len,
                                   "%s Extension TLV #%u, length: %u",
                                   val_to_str(ext_type, ext_tlv_vals, "Unknown"),
                                   ext_type,
                                   ext_len);

      ext_val = juniper_ext_get_tlv_value(tvb, ext_type, ext_len, ext_offset+EXT_TLV_HEADER_SIZE);
      juniper_ext_subtree_item = proto_item_add_subtree(tisub, ett_juniper);

      switch (ext_type) {
      case EXT_TLV_IFD_MEDIATYPE:
        proto_tree_add_uint(juniper_ext_subtree_item, hf_juniper_ext_ifmt,
                                    tvb, ext_offset+EXT_TLV_HEADER_SIZE, ext_len, ext_val);
        break;
      case EXT_TLV_TTP_IFD_MEDIATYPE:
        proto_tree_add_uint(juniper_ext_subtree_item, hf_juniper_ext_ttp_ifmt,
                                    tvb, ext_offset+EXT_TLV_HEADER_SIZE, ext_len, ext_val);
        break;
      case EXT_TLV_IFL_ENCAPS:
        proto_tree_add_uint(juniper_ext_subtree_item, hf_juniper_ext_ifle,
                                    tvb, ext_offset+EXT_TLV_HEADER_SIZE, ext_len, ext_val);
        break;
      case EXT_TLV_TTP_IFL_ENCAPS:
        proto_tree_add_uint(juniper_ext_subtree_item, hf_juniper_ext_ttp_ifle,
                                    tvb, ext_offset+EXT_TLV_HEADER_SIZE, ext_len, ext_val);
        break;

      case EXT_TLV_IFL_IDX:
        proto_tree_add_uint(juniper_ext_subtree_item, hf_juniper_ext_ifl,
                            tvb, ext_offset+EXT_TLV_HEADER_SIZE, ext_len, ext_val);
        break;

      case EXT_TLV_IFL_UNIT:
        proto_tree_add_uint(juniper_ext_subtree_item, hf_juniper_ext_unit,
                            tvb, ext_offset+EXT_TLV_HEADER_SIZE, ext_len, ext_val);
        break;
      case EXT_TLV_IFD_IDX:
        proto_tree_add_uint(juniper_ext_subtree_item, hf_juniper_ext_ifd,
                            tvb, ext_offset+EXT_TLV_HEADER_SIZE, ext_len, ext_val);
        break;
      case EXT_TLV_IFD_NAME: /* FIXME print ifname string - lets fall-through for now */
      default:
        proto_item_append_text(tisub, "Unknown");
        break;
      }

      ext_offset += EXT_TLV_HEADER_SIZE + ext_len;
      ext_total_len -= EXT_TLV_HEADER_SIZE + ext_len;
    }

  } else
    hdr_len = 4; /* MGC,flags */

  if ((*flags & JUNIPER_FLAG_NO_L2) == JUNIPER_FLAG_NO_L2) { /* no link header present ? */
    proto = tvb_get_letohl(tvb,hdr_len); /* proto is stored in host-order */
    dissect_juniper_payload_proto(tvb, pinfo, tree, ti, proto, hdr_len + 4);
    return -1;
  }

  return hdr_len; /* bytes parsed */

}

/* print the payload protocol  */
static int
dissect_juniper_payload_proto(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                              proto_item *ti _U_, guint proto, guint offset)
{

  tvbuff_t   *next_tvb;
  guint8     nlpid;

  proto_tree_add_text (juniper_subtree, tvb, offset, 0, "[Payload Type: %s]",
                       val_to_str(proto,juniper_proto_vals,"Unknown"));

  next_tvb = tvb_new_subset_remaining(tvb, offset);

  switch (proto) {
  case PROTO_IP:
  case PROTO_MPLS_IP:
    call_dissector(ipv4_handle, next_tvb, pinfo, tree);
    break;
  case PROTO_IP6:
  case PROTO_MPLS_IP6:
    call_dissector(ipv6_handle, next_tvb, pinfo, tree);
    break;
  case PROTO_MPLS:
  case PROTO_IP_MPLS:
  case PROTO_IP6_MPLS:
  case PROTO_CLNP_MPLS:
    call_dissector(mpls_handle, next_tvb, pinfo, tree);
    break;
  case PROTO_PPP:
    call_dissector(ppp_handle, next_tvb, pinfo, tree);
    break;
  case PROTO_ETHER:
    call_dissector(eth_handle, next_tvb, pinfo, tree);
    break;
  case PROTO_LLC:
  case PROTO_LLC_SNAP:
    call_dissector(llc_handle, next_tvb, pinfo, tree);
    break;
  case PROTO_ISO:
  case PROTO_CLNP:
  case PROTO_MPLS_CLNP:
    nlpid = tvb_get_guint8(tvb, offset);
    if(dissector_try_uint(osinl_subdissector_table, nlpid, next_tvb, pinfo, tree))
      return 0;
    next_tvb = tvb_new_subset_remaining(tvb, offset+1);
    if(dissector_try_uint(osinl_excl_subdissector_table, nlpid, next_tvb, pinfo, tree))
      return 0;
    break;
  case PROTO_Q933:
    call_dissector(q933_handle, next_tvb, pinfo, tree);
    break;
  case PROTO_FRELAY:
    call_dissector(frelay_handle, next_tvb, pinfo, tree);
    break;
  case PROTO_CHDLC:
    call_dissector(chdlc_handle, next_tvb, pinfo, tree);
    break;
  case 0xa248:
	  proto_tree_add_text (juniper_subtree, tvb, offset, 4,"[Unknown data]");
	  next_tvb = tvb_new_subset_remaining(tvb, offset+4);
	  call_dissector(ipv4_handle, next_tvb, pinfo, tree);
	  break;
  case PROTO_OAM: /* FIXME call OAM disector without leading HEC byte */
  default:
    call_dissector(data_handle, next_tvb, pinfo, tree);
    break;
  }

  return 0;
}

/* MLFR dissector */
static void
dissect_juniper_mlfr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  guint      offset;
  int        bytes_processed;
  guint8     flags;
  guint64    aspic_cookie;
  guint32    lspic_cookie;
  guint16    mlpic_cookie;
  guint      proto,cookie_len;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Juniper MLFR");
  col_clear(pinfo->cinfo, COL_INFO);

  offset = 0;

  ti = proto_tree_add_text (tree, tvb, offset, 4, "Juniper Multi-Link Frame-Relay (FRF.15)");

  /* parse header, match mgc, extract flags and build first tree */
  bytes_processed = dissect_juniper_header(tvb, pinfo, tree, ti, &flags);

  if(bytes_processed == -1)
    return;
  else
    offset+=bytes_processed;

  aspic_cookie = tvb_get_ntoh64(tvb,offset);
  proto = juniper_svc_cookie_proto(aspic_cookie, JUNIPER_PIC_MLFR, flags);
  cookie_len = juniper_svc_cookie_len(aspic_cookie);

  if (cookie_len == AS_PIC_COOKIE_LEN)
    proto_tree_add_uint64(juniper_subtree, hf_juniper_aspic_cookie,
                          tvb, offset, AS_PIC_COOKIE_LEN, aspic_cookie);
  if (cookie_len == LS_PIC_COOKIE_LEN) {
    lspic_cookie = tvb_get_ntohl(tvb,offset);
    proto_tree_add_uint(juniper_subtree, hf_juniper_lspic_cookie,
                        tvb, offset, LS_PIC_COOKIE_LEN, lspic_cookie);
  }

  offset += cookie_len;

  mlpic_cookie = tvb_get_ntohs(tvb, offset);

  /* AS-PIC IS-IS */
  if (cookie_len == AS_PIC_COOKIE_LEN &&
      proto == PROTO_UNKNOWN &&
      tvb_get_guint8(tvb,offset) == JUNIPER_HDR_LLC_UI) {
    offset += 1;
    proto = PROTO_ISO;
  }

  /* LS-PIC IS-IS */
  if (cookie_len == LS_PIC_COOKIE_LEN) {
    if ( tvb_get_ntohs(tvb,offset) == JUNIPER_HDR_LLC_UI ||
         tvb_get_ntohs(tvb,offset) == (JUNIPER_HDR_LLC_UI<<8)) {
      offset += 2;
    }
  }

  /* LS-PIC ? */
  if (cookie_len == LS_PIC_COOKIE_LEN && tvb_get_guint8(tvb,offset) == JUNIPER_HDR_LLC_UI) {
    offset += 1;
  }

  /* child link of an LS-PIC bundle ? */
  if (cookie_len == 0 && tvb_get_ntohs(tvb,offset+ML_PIC_COOKIE_LEN) ==
      (JUNIPER_HDR_LLC_UI<<8 | NLPID_Q_933)) {
    cookie_len = ML_PIC_COOKIE_LEN;
    proto_tree_add_uint(juniper_subtree, hf_juniper_mlpic_cookie,
                        tvb, offset, ML_PIC_COOKIE_LEN, mlpic_cookie);
    offset += 3;
    proto = PROTO_Q933;
  }

  /* child link of an ML-, LS-, AS-PIC bundle / ML-PIC bundle ? */
  if (cookie_len == 0) {
    if (tvb_get_ntohs(tvb,offset+ML_PIC_COOKIE_LEN) == JUNIPER_HDR_LLC_UI ||
        tvb_get_ntohs(tvb,offset+ML_PIC_COOKIE_LEN) == (JUNIPER_HDR_LLC_UI<<8)) {
      cookie_len = ML_PIC_COOKIE_LEN;
      proto_tree_add_uint(juniper_subtree, hf_juniper_mlpic_cookie,
                          tvb, offset, ML_PIC_COOKIE_LEN, mlpic_cookie);
      offset += 4;
      proto = PROTO_ISO;
    }
  }

  /* ML-PIC bundle ? */
  if (cookie_len == 0 && tvb_get_guint8(tvb,offset+ML_PIC_COOKIE_LEN) == JUNIPER_HDR_LLC_UI) {
    cookie_len = ML_PIC_COOKIE_LEN;
    proto_tree_add_uint(juniper_subtree, hf_juniper_mlpic_cookie,
                        tvb, offset, ML_PIC_COOKIE_LEN, mlpic_cookie);
    offset += 3;
    proto = PROTO_ISO;
  }

  ti = proto_tree_add_text (juniper_subtree, tvb, offset, 0, "[Cookie length: %u]",cookie_len);
  dissect_juniper_payload_proto(tvb, pinfo, tree, ti, proto, offset);

}



/* MLPPP dissector */
static void
dissect_juniper_mlppp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  guint      offset;
  int        bytes_processed;
  guint8     flags;
  guint64    aspic_cookie;
  guint32    lspic_cookie;
  guint16    mlpic_cookie;
  guint      proto,cookie_len;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Juniper MLPPP");
  col_clear(pinfo->cinfo, COL_INFO);

  offset = 0;

  ti = proto_tree_add_text (tree, tvb, offset, 4, "Juniper MLPPP");

  /* parse header, match mgc, extract flags and build first tree */
  bytes_processed = dissect_juniper_header(tvb, pinfo, tree, ti, &flags);

  if(bytes_processed == -1)
    return;
  else
    offset+=bytes_processed;

  aspic_cookie = tvb_get_ntoh64(tvb,offset);
  proto = juniper_svc_cookie_proto(aspic_cookie, JUNIPER_PIC_MLPPP, flags);
  cookie_len = juniper_svc_cookie_len(aspic_cookie);

  if (cookie_len == AS_PIC_COOKIE_LEN)
    proto_tree_add_uint64(juniper_subtree, hf_juniper_aspic_cookie,
                          tvb, offset, AS_PIC_COOKIE_LEN, aspic_cookie);
  if (cookie_len == LS_PIC_COOKIE_LEN) {
    lspic_cookie = tvb_get_ntohl(tvb,offset);
    proto_tree_add_uint(juniper_subtree, hf_juniper_lspic_cookie,
                        tvb, offset, LS_PIC_COOKIE_LEN, lspic_cookie);
  }

  /* no cookie pattern identified - lets guess from now on */

  /* child link of an LS-PIC bundle ? */
  if (cookie_len == 0 && tvb_get_ntohs(tvb, offset) == JUNIPER_HDR_PPP) {
    proto = PROTO_PPP;
    offset += 2;
  }

  /* ML-PIC ? */
  if (cookie_len == 0 && ppp_heuristic_guess(tvb_get_ntohs(tvb, offset+2))) {
    proto = PROTO_PPP;
    cookie_len = 2;
    mlpic_cookie = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(juniper_subtree, hf_juniper_mlpic_cookie,
                        tvb, offset, ML_PIC_COOKIE_LEN, mlpic_cookie);
  }

  /* child link of an ML-PIC bundle ? */
  if (cookie_len == 0 && ppp_heuristic_guess(tvb_get_ntohs(tvb, offset))) {
    proto = PROTO_PPP;
  }

  ti = proto_tree_add_text (juniper_subtree, tvb, offset, 0, "[Cookie length: %u]",cookie_len);
  offset += cookie_len;

  dissect_juniper_payload_proto(tvb, pinfo, tree, ti, proto, offset);

}


/* PPPoE dissector */
static void
dissect_juniper_pppoe(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  guint      offset;
  int        bytes_processed;
  guint8     flags;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Juniper PPPoE");
  col_clear(pinfo->cinfo, COL_INFO);

  offset = 0;

  ti = proto_tree_add_text (tree, tvb, offset, 4, "Juniper PPPoE PIC");

  /* parse header, match mgc, extract flags and build first tree */
  bytes_processed = dissect_juniper_header(tvb, pinfo, tree, ti, &flags);

  if(bytes_processed == -1)
    return;
  else
    offset+=bytes_processed;

  dissect_juniper_payload_proto(tvb, pinfo, tree, ti, PROTO_ETHER, offset);

}

/* Ethernet dissector */
static void
dissect_juniper_ether(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  guint      offset;
  int        bytes_processed;
  guint8     flags;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Juniper Ethernet");
  col_clear(pinfo->cinfo, COL_INFO);

  offset = 0;

  ti = proto_tree_add_text (tree, tvb, offset, 4, "Juniper Ethernet");

  /* parse header, match mgc, extract flags and build first tree */
  bytes_processed = dissect_juniper_header(tvb, pinfo, tree, ti, &flags);

  if(bytes_processed == -1)
    return;
  else
    offset+=bytes_processed;

  dissect_juniper_payload_proto(tvb, pinfo, tree, ti, PROTO_ETHER, offset);

}

/* PPP dissector */
static void
dissect_juniper_ppp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  guint      offset;
  int        bytes_processed;
  guint8     flags;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Juniper PPP");
  col_clear(pinfo->cinfo, COL_INFO);

  offset = 0;

  ti = proto_tree_add_text (tree, tvb, offset, 4, "Juniper PPP");

  /* parse header, match mgc, extract flags and build first tree */
  bytes_processed = dissect_juniper_header(tvb, pinfo, tree, ti, &flags);

  if(bytes_processed == -1)
    return;
  else
    offset+=bytes_processed;

  dissect_juniper_payload_proto(tvb, pinfo, tree, ti, PROTO_PPP, offset+2);

}

/* Frame-Relay dissector */
static void
dissect_juniper_frelay(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  guint      offset;
  int        bytes_processed;
  guint8     flags;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Juniper Frame-Relay");
  col_clear(pinfo->cinfo, COL_INFO);

  offset = 0;

  ti = proto_tree_add_text (tree, tvb, offset, 4, "Juniper Frame-Relay");

  /* parse header, match mgc, extract flags and build first tree */
  bytes_processed = dissect_juniper_header(tvb, pinfo, tree, ti, &flags);

  if(bytes_processed == -1)
    return;
  else
    offset+=bytes_processed;

  dissect_juniper_payload_proto(tvb, pinfo, tree, ti, PROTO_FRELAY, offset);

}

/* C-HDLC dissector */
static void
dissect_juniper_chdlc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  guint      offset = 0;
  int        bytes_processed;
  guint8     flags;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Juniper C-HDLC");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_text (tree, tvb, offset, 4, "Juniper C-HDLC");

  /* parse header, match mgc, extract flags and build first tree */
  bytes_processed = dissect_juniper_header(tvb, pinfo, tree, ti, &flags);

  if(bytes_processed == -1)
    return;
  else
    offset+=bytes_processed;

  dissect_juniper_payload_proto(tvb, pinfo, tree, ti, PROTO_CHDLC, offset);

}



/* wrapper for passing the PIC type to the generic ATM dissector */
static void
dissect_juniper_atm1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_juniper_atm(tvb,pinfo,tree, JUNIPER_PIC_ATM1);
}

/* wrapper for passing the PIC type to the generic ATM dissector */
static void
dissect_juniper_atm2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_juniper_atm(tvb,pinfo,tree, JUNIPER_PIC_ATM2);
}

/* generic ATM dissector */
static void
dissect_juniper_atm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 atm_pictype)
{
  proto_item *ti;
  guint8     next_proto = PROTO_UNKNOWN,atm1_header_len,atm2_header_len,flags;
  guint32    cookie1, proto;
  guint64    cookie2;
  guint      offset = 0;
  int        bytes_processed;
  tvbuff_t   *next_tvb;

  col_clear(pinfo->cinfo, COL_INFO);

  switch (atm_pictype) {
  case JUNIPER_PIC_ATM1:
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Juniper ATM1");
    ti = proto_tree_add_text (tree, tvb, 0, 0 , "Juniper ATM1 PIC");
    break;
  case JUNIPER_PIC_ATM2:
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Juniper ATM2");
    ti = proto_tree_add_text (tree, tvb, 0, 0 , "Juniper ATM2 PIC");
    break;
  default: /* should not happen */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Juniper ATM unknown");
    proto_tree_add_text (tree, tvb, 0, 0 , "Juniper unknown ATM PIC");
    return;
  }

  /* parse header, match mgc, extract flags and build first tree */
  bytes_processed = dissect_juniper_header(tvb, pinfo, tree, ti, &flags);
  if(bytes_processed == -1)
    return;
  else
    offset+=bytes_processed;

  if ((flags & JUNIPER_FLAG_NO_L2) == JUNIPER_FLAG_NO_L2) {
    atm1_header_len = 4;
    atm2_header_len = 4;
  }
  else {
    atm1_header_len = 4;
    atm2_header_len = 8;
  }

  cookie1 = tvb_get_ntohl(tvb, offset);
  cookie2 = tvb_get_ntoh64(tvb, offset);

  if (atm_pictype == JUNIPER_PIC_ATM1) {
    proto_tree_add_uint(juniper_subtree, hf_juniper_atm1_cookie, tvb, offset, 4, cookie1);
    offset += atm1_header_len;
    if ((cookie1 >> 24) == 0x80) /* OAM cell ? */
      next_proto = PROTO_OAM;
  }
  else { /* JUNIPER_PIC_ATM2 */
    proto_tree_add_uint64(juniper_subtree, hf_juniper_atm2_cookie, tvb, offset, 8, cookie2);
    offset += atm2_header_len;
    if (cookie2 & 0x70) /* OAM cell ? */
      next_proto = PROTO_OAM;
  }

  next_tvb = tvb_new_subset_remaining(tvb, offset);

  if (next_proto == PROTO_OAM) {
    dissect_juniper_payload_proto(tvb, pinfo, tree, ti, PROTO_OAM, offset);
    return;
  }

  proto = tvb_get_ntoh24(tvb, offset); /* first try: 24-Bit guess */

  if (proto == JUNIPER_HDR_NLPID) {
    /*
     * This begins with something that appears to be an LLC header for
     * OSI; is this LLC-multiplexed traffic?
     */
    dissect_juniper_payload_proto(tvb, pinfo, tree, ti, PROTO_LLC, offset);
    return;
  }

  if (proto == JUNIPER_HDR_SNAP) {
    /*
     * This begins with something that appears to be an LLC header for
     * SNAP; is this LLC-multiplexed traffic?
     */
    dissect_juniper_payload_proto(tvb, pinfo, tree, ti, PROTO_LLC_SNAP, offset);
    return;
  }

  if ((flags & JUNIPER_FLAG_PKT_IN) != JUNIPER_FLAG_PKT_IN && /* ether-over-1483 encaps ? */
      (cookie1 & JUNIPER_ATM2_GAP_COUNT_MASK) &&
      atm_pictype != JUNIPER_PIC_ATM1) {
    dissect_juniper_payload_proto(tvb, pinfo, tree, ti, PROTO_ETHER, offset);
    return;
  }

  proto = tvb_get_ntohs(tvb, offset); /* second try: 16-Bit guess */

  if ( ppp_heuristic_guess( (guint16) proto) &&
       atm_pictype != JUNIPER_PIC_ATM1) {
    /*
     * This begins with something that appears to be a PPP protocol
     * type; is this VC-multiplexed PPPoA?
     * That's not supported on ATM1 PICs.
     */
    ti = proto_tree_add_text (juniper_subtree, tvb, offset, 0, "Encapsulation Type: VC-MUX");
    dissect_juniper_payload_proto(tvb, pinfo, tree, ti, PROTO_PPP , offset);
    return;
  }

  proto = tvb_get_guint8(tvb, offset); /* third try: 8-Bit guess */

  if ( proto == JUNIPER_HDR_LLC_UI ) {
    /*
     * Cisco style NLPID encaps?
     * Is the 0x03 an LLC UI control field?
     */
    ti = proto_tree_add_text (juniper_subtree, tvb, offset, 1, "Encapsulation Type: Cisco NLPID");
    dissect_juniper_payload_proto(tvb, pinfo, tree, ti, PROTO_ISO , offset+1);
    return;
  }

  next_proto = ip_heuristic_guess( (guint8) proto);
  if (next_proto != PROTO_UNKNOWN) { /* last resort: VC-MUX encaps ? */
    /*
     * This begins with something that might be the first byte of
     * an IPv4 or IPv6 packet; is this VC-multiplexed IP?
     */
    ti = proto_tree_add_text (juniper_subtree, tvb, offset, 0, "Encapsulation Type: VC-MUX");
    dissect_juniper_payload_proto(tvb, pinfo, tree, ti, next_proto , offset);
    return;
  }

  /* could not figure what it is */
  proto_tree_add_text (juniper_subtree, tvb, offset, -1, "Payload Type: unknown");
  call_dissector(data_handle, next_tvb, pinfo, tree);
}


static void dissect_juniper_ggsn(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree) {

  proto_item *ti;
  guint      offset = 0;
  int        bytes_processed;
  guint8     flags;
  guint16    proto;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Juniper GGSN");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_text (tree, tvb, offset, 4, "Juniper GGSN");

  /* parse header, match mgc, extract flags and build first tree */
  bytes_processed = dissect_juniper_header(tvb, pinfo, tree, ti, &flags);

  if(bytes_processed == -1)
    return;
  else
    offset+=bytes_processed;

  proto = tvb_get_letohs(tvb, offset); /* fetch protocol */

  proto_tree_add_uint(juniper_subtree, hf_juniper_proto, tvb, offset, 2, proto);
  proto_tree_add_item(juniper_subtree, hf_juniper_vlan, tvb, offset+2, 2, ENC_LITTLE_ENDIAN);
  offset += 4;

  dissect_juniper_payload_proto(tvb, pinfo, tree, ti, proto, offset);

}

static void dissect_juniper_vp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree) {

  proto_item *ti;
  guint      offset = 0;
  int        bytes_processed;
  guint8     flags;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Juniper Voice PIC");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_text (tree, tvb, offset, 4, "Juniper Voice PIC");

  /* parse header, match mgc, extract flags and build first tree */
  bytes_processed = dissect_juniper_header(tvb, pinfo, tree, ti, &flags);

  if(bytes_processed == -1)
    return;
  else
    offset+=bytes_processed;

  /*
   * Right know IPv4 is the only protocol we may encounter.
   * For the future there should be sufficient space in the 18-byte
   * empty header before payload starts.
   */
  dissect_juniper_payload_proto(tvb, pinfo, tree, ti, PROTO_IP, offset+18);
}


/* list of Juniper supported PPP proto IDs */
static gboolean
ppp_heuristic_guess(guint16 proto) {

  switch(proto) {
  case PPP_IP :
  case PPP_OSI :
  case PPP_MPLS_UNI :
  case PPP_MPLS_MULTI :
  case PPP_IPCP :
  case PPP_OSICP :
  case PPP_MPLSCP :
  case PPP_LCP :
  case PPP_PAP :
  case PPP_CHAP :
  case PPP_MP :
  case PPP_IPV6 :
  case PPP_IPV6CP :
    return TRUE;

  default:
    return FALSE; /* did not find a ppp header */
  }
}

/*
 * return the IP version number based on the first byte of the IP header
 * returns 0 if it does not match a valid first IPv4/IPv6 header byte
 */
static guint
ip_heuristic_guess(guint8 ip_header_byte) {

  switch(ip_header_byte) {
  case 0x45:
  case 0x46:
  case 0x47:
  case 0x48:
  case 0x49:
  case 0x4a:
  case 0x4b:
  case 0x4c:
  case 0x4d:
  case 0x4e:
  case 0x4f:
    return PROTO_IP;
  case 0x60:
  case 0x61:
  case 0x62:
  case 0x63:
  case 0x64:
  case 0x65:
  case 0x66:
  case 0x67:
  case 0x68:
  case 0x69:
  case 0x6a:
  case 0x6b:
  case 0x6c:
  case 0x6d:
  case 0x6e:
  case 0x6f:
    return PROTO_IP6;
  default:
    return PROTO_UNKNOWN; /* did not find a ip header */
  }
}

/* return cookie length dep. on cookie SVC id */
static
guint juniper_svc_cookie_len (guint64 cookie) {

  guint8 svc_cookie_id;
  svc_cookie_id = (guint8)(cookie >> 56) & 0xff;

  switch(svc_cookie_id) {
  case 0x54:
    return LS_PIC_COOKIE_LEN;
  case GSP_SVC_REQ_APOLLO:
  case GSP_SVC_REQ_LSQ:
    return AS_PIC_COOKIE_LEN;
  default:
    return 0;
  }
}

/* return the next-level protocol based on cookie input */
static guint
juniper_svc_cookie_proto (guint64 cookie, guint16 pictype, guint8 flags) {

  guint8 svc_cookie_id;
  guint16 lsq_proto;
  guint8 lsq_dir;

  svc_cookie_id = (guint8)(cookie >> 56) & 0xff;
  lsq_proto = (guint16)((cookie >> 16) & LSQ_L3_PROTO_MASK);
  lsq_dir = (guint8)(cookie >> 24) & 0x3;


  switch (svc_cookie_id) {
  case 0x54:
    switch (pictype) {
    case JUNIPER_PIC_MLPPP:
      return PROTO_PPP;
    case JUNIPER_PIC_MLFR:
      return PROTO_ISO;
    default:
      return PROTO_UNKNOWN;
    }
  case GSP_SVC_REQ_APOLLO:
  case GSP_SVC_REQ_LSQ:
    switch(lsq_proto) {
    case LSQ_L3_PROTO_IPV4:
      switch(pictype) {
      case JUNIPER_PIC_MLPPP:
        /* incoming traffic would have the direction bits set
         * -> this must be IS-IS over PPP
         */
        if ((flags & JUNIPER_FLAG_PKT_IN) == JUNIPER_FLAG_PKT_IN &&
            lsq_dir != (LSQ_COOKIE_RE|LSQ_COOKIE_DIR))
          return PROTO_PPP;
        else
          return PROTO_IP;
      case JUNIPER_PIC_MLFR:
        if (lsq_dir == (LSQ_COOKIE_RE|LSQ_COOKIE_DIR))
          return PROTO_UNKNOWN;
        else
          return PROTO_IP;
      default:
        return PROTO_UNKNOWN;
      }
    case LSQ_L3_PROTO_IPV6:
      return PROTO_IP6;
    case LSQ_L3_PROTO_MPLS:
      return PROTO_MPLS;
    case LSQ_L3_PROTO_ISO:
      return PROTO_ISO;
    default:
      return PROTO_UNKNOWN;
    }
  default:
    return PROTO_UNKNOWN;
  }
}


void
proto_register_juniper(void)
{
  static hf_register_info hf[] = {
    { &hf_juniper_magic,
      { "Magic Number", "juniper.magic-number", FT_UINT24, BASE_HEX,
        NULL, 0x0, NULL, HFILL }},
    { &hf_juniper_direction,
      { "Direction", "juniper.direction", FT_UINT8, BASE_HEX,
        VALS(juniper_direction_vals), 0x0, NULL, HFILL }},
    { &hf_juniper_l2hdr_presence,
      { "L2 header presence", "juniper.l2hdr", FT_UINT8, BASE_HEX,
        VALS(juniper_l2hdr_presence_vals), 0x0, NULL, HFILL }},
    { &hf_juniper_ext_total_len,
      { "Extension(s) Total length", "juniper.ext_total_len", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},
    { &hf_juniper_atm2_cookie,
      { "Cookie", "juniper.atm2.cookie", FT_UINT64, BASE_HEX,
        NULL, 0x0, NULL, HFILL }},
    { &hf_juniper_atm1_cookie,
      { "Cookie", "juniper.atm1.cookie", FT_UINT32, BASE_HEX,
        NULL, 0x0, NULL, HFILL }},
    { &hf_juniper_mlpic_cookie,
      { "Cookie", "juniper.mlpic.cookie", FT_UINT16, BASE_HEX,
        NULL, 0x0, NULL, HFILL }},
    { &hf_juniper_lspic_cookie,
      { "Cookie", "juniper.lspic.cookie", FT_UINT32, BASE_HEX,
        NULL, 0x0, NULL, HFILL }},
    { &hf_juniper_aspic_cookie,
      { "Cookie", "juniper.aspic.cookie", FT_UINT64, BASE_HEX,
        NULL, 0x0, NULL, HFILL }},
    { &hf_juniper_vlan,
      { "VLan ID", "juniper.vlan", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},
    { &hf_juniper_proto,
      { "Protocol", "juniper.proto", FT_UINT16, BASE_DEC,
        VALS(juniper_proto_vals), 0x0, NULL, HFILL }},
    { &hf_juniper_ext_ifd,
      /* Juniper PCAP extensions */
      { "Device Interface Index", "juniper.ext.ifd", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},
    { &hf_juniper_ext_ifl,
      { "Logical Interface Index", "juniper.ext.ifl", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},
    { &hf_juniper_ext_unit,
      { "Logical Unit Number", "juniper.ext.unit", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},
    { &hf_juniper_ext_ifmt,
      { "Device Media Type", "juniper.ext.ifmt", FT_UINT16, BASE_DEC,
        VALS(juniper_ifmt_vals), 0x0, NULL, HFILL }},
    { &hf_juniper_ext_ifle,
      { "Logical Interface Encapsulation", "juniper.ext.ifle", FT_UINT16, BASE_DEC,
        VALS(juniper_ifle_vals), 0x0, NULL, HFILL }},
    { &hf_juniper_ext_ttp_ifmt,
      { "TTP derived Device Media Type", "juniper.ext.ttp_ifmt", FT_UINT16, BASE_DEC,
        VALS(juniper_ifmt_vals), 0x0, NULL, HFILL }},
    { &hf_juniper_ext_ttp_ifle,
      { "TTP derived Logical Interface Encapsulation", "juniper.ext.ttp_ifle", FT_UINT16, BASE_DEC,
        VALS(juniper_ifle_vals), 0x0, NULL, HFILL }},
  };

  static gint *ett[] = {
    &ett_juniper,
  };

  proto_juniper = proto_register_protocol("Juniper", "Juniper", "juniper");
  proto_register_field_array(proto_juniper, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}

void
proto_reg_handoff_juniper(void)
{
  dissector_handle_t juniper_atm1_handle;
  dissector_handle_t juniper_atm2_handle;
  dissector_handle_t juniper_pppoe_handle;
  dissector_handle_t juniper_mlppp_handle;
  dissector_handle_t juniper_mlfr_handle;
  dissector_handle_t juniper_ether_handle;
  dissector_handle_t juniper_ppp_handle;
  dissector_handle_t juniper_frelay_handle;
  dissector_handle_t juniper_chdlc_handle;
  dissector_handle_t juniper_ggsn_handle;
  dissector_handle_t juniper_vp_handle;

  osinl_subdissector_table = find_dissector_table("osinl");
  osinl_excl_subdissector_table = find_dissector_table("osinl.excl");

  eth_handle    = find_dissector("eth_withoutfcs");
  ppp_handle    = find_dissector("ppp");
  llc_handle    = find_dissector("llc");
  ipv4_handle   = find_dissector("ip");
  ipv6_handle   = find_dissector("ipv6");
  mpls_handle   = find_dissector("mpls");
  q933_handle   = find_dissector("q933");
  frelay_handle = find_dissector("fr");
  chdlc_handle  = find_dissector("chdlc");
  data_handle   = find_dissector("data");

  juniper_atm2_handle   = create_dissector_handle(dissect_juniper_atm2,   proto_juniper);
  juniper_atm1_handle   = create_dissector_handle(dissect_juniper_atm1,   proto_juniper);
  juniper_pppoe_handle  = create_dissector_handle(dissect_juniper_pppoe,  proto_juniper);
  juniper_mlppp_handle  = create_dissector_handle(dissect_juniper_mlppp,  proto_juniper);
  juniper_mlfr_handle   = create_dissector_handle(dissect_juniper_mlfr,   proto_juniper);
  juniper_ether_handle  = create_dissector_handle(dissect_juniper_ether,  proto_juniper);
  juniper_ppp_handle    = create_dissector_handle(dissect_juniper_ppp,    proto_juniper);
  juniper_frelay_handle = create_dissector_handle(dissect_juniper_frelay, proto_juniper);
  juniper_chdlc_handle  = create_dissector_handle(dissect_juniper_chdlc,  proto_juniper);
  juniper_ggsn_handle   = create_dissector_handle(dissect_juniper_ggsn,   proto_juniper);
  juniper_vp_handle     = create_dissector_handle(dissect_juniper_vp,     proto_juniper);

  dissector_add_uint("wtap_encap", WTAP_ENCAP_JUNIPER_ATM2,   juniper_atm2_handle);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_JUNIPER_ATM1,   juniper_atm1_handle);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_JUNIPER_PPPOE,  juniper_pppoe_handle);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_JUNIPER_MLPPP,  juniper_mlppp_handle);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_JUNIPER_MLFR,   juniper_mlfr_handle);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_JUNIPER_ETHER,  juniper_ether_handle);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_JUNIPER_PPP,    juniper_ppp_handle);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_JUNIPER_FRELAY, juniper_frelay_handle);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_JUNIPER_CHDLC,  juniper_chdlc_handle);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_JUNIPER_GGSN,   juniper_ggsn_handle);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_JUNIPER_VP,     juniper_vp_handle);

}

