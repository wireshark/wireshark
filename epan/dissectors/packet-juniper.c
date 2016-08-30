/* packet-juniper.c
 * Routines for Juniper Networks, Inc. packet disassembly
 * Copyright 2005 Hannes Gredler <hannes@juniper.net>
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

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/addr_resolv.h>
#include <epan/ppptypes.h>
#include "packet-ppp.h"
#include "packet-juniper.h"
#include <epan/nlpid.h>

void proto_register_juniper(void);
void proto_reg_handoff_juniper(void);

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

/* VN related defines */
#define VN_TLV_HDR_SIZE   2
#define VN_FLAG_ALERT     0x00000002
#define VN_FLAG_DROP      0x00000004
#define VN_FLAG_DENY      0x00000008
#define VN_FLAG_LOG       0x00000010
#define VN_FLAG_PASS      0x00000020
#define VN_FLAG_REJECT    0x00000040
#define VN_FLAG_MIRROR    0x00000080
#define VN_FLAG_DIRECTION 0x40000000
#define VN_FLAG_MASK      0xFFFFFFFF
enum {
    VN_TLV_HOST_IP = 1,
    VN_TLV_FLAGS   = 2,
    VN_TLV_SRC_VN  = 3,
    VN_TLV_DST_VN  = 4,
    VN_TLV_LAST    = 255
};

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
static int hf_juniper_cookie_len = -1;
static int hf_juniper_atm1_cookie = -1;
static int hf_juniper_atm2_cookie = -1;
static int hf_juniper_mlpic_cookie = -1;
static int hf_juniper_lspic_cookie = -1;
static int hf_juniper_aspic_cookie = -1;
static int hf_juniper_vlan = -1;
static int hf_juniper_proto = -1;
static int hf_juniper_payload_type = -1;
static int hf_juniper_encap_type = -1;
static int hf_juniper_ext_ifd = -1;
static int hf_juniper_ext_ifl = -1;
static int hf_juniper_ext_unit = -1;
static int hf_juniper_ext_ifmt = -1;
static int hf_juniper_ext_ifle = -1;
static int hf_juniper_ext_ttp_ifmt = -1;
static int hf_juniper_ext_ttp_ifle = -1;
static int hf_juniper_unknown_data = -1;

static expert_field ei_juniper_no_magic = EI_INIT;
static expert_field ei_juniper_vn_incorrect_format = EI_INIT;

static int hf_juniper_vn_host_ip = -1;
static int hf_juniper_vn_src = -1;
static int hf_juniper_vn_dst = -1;
static int hf_juniper_vn_flags = -1;
static int hf_juniper_vn_flag_alert = -1;
static int hf_juniper_vn_flag_drop = -1;
static int hf_juniper_vn_flag_deny = -1;
static int hf_juniper_vn_flag_log = -1;
static int hf_juniper_vn_flag_pass = -1;
static int hf_juniper_vn_flag_reject = -1;
static int hf_juniper_vn_flag_mirror = -1;
static int hf_juniper_vn_flag_direction = -1;

static gint ett_juniper = -1;
static gint ett_juniper_vn_flags = -1;

static dissector_handle_t ipv4_handle;

static dissector_table_t payload_table;

static int dissect_juniper_payload_proto(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *juniper_subtree, guint proto, guint offset);
static void dissect_juniper_atm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 atm_pictype);
static gboolean ppp_heuristic_guess(guint16 proto);
static guint ip_heuristic_guess(guint8 ip_header_byte);
static guint juniper_svc_cookie_len (guint64 cookie);
static guint juniper_svc_cookie_proto (guint64 cookie, guint16 pictype, guint8 flags);

static const value_string juniper_proto_vals[] = {
  {JUNIPER_PROTO_IP, "IPv4"},
  {JUNIPER_PROTO_MPLS_IP, "MPLS->IPv4"},
  {JUNIPER_PROTO_IP_MPLS, "IPv4->MPLS"},
  {JUNIPER_PROTO_IP6, "IPv6"},
  {JUNIPER_PROTO_MPLS_IP6, "MPLS->IPv6"},
  {JUNIPER_PROTO_IP6_MPLS, "IPv6->MPLS"},
  {JUNIPER_PROTO_PPP, "PPP"},
  {JUNIPER_PROTO_CLNP, "CLNP"},
  {JUNIPER_PROTO_MPLS_CLNP, "MPLS->CLNP"},
  {JUNIPER_PROTO_CLNP_MPLS, "CLNP->MPLS"},
  {JUNIPER_PROTO_ISO, "OSI"},
  {JUNIPER_PROTO_MPLS, "MPLS"},
  {JUNIPER_PROTO_LLC, "LLC"},
  {JUNIPER_PROTO_LLC_SNAP, "LLC/SNAP"},
  {JUNIPER_PROTO_ETHER, "Ethernet"},
  {JUNIPER_PROTO_OAM, "ATM OAM Cell"},
  {JUNIPER_PROTO_Q933, "Q.933"},
  {JUNIPER_PROTO_FRELAY, "Frame-Relay"},
  {JUNIPER_PROTO_CHDLC, "C-HDLC"},
  {0,                    NULL}
};

static const int * vn_flags[] = {
  &hf_juniper_vn_flag_direction,
  &hf_juniper_vn_flag_mirror,
  &hf_juniper_vn_flag_reject,
  &hf_juniper_vn_flag_pass,
  &hf_juniper_vn_flag_log,
  &hf_juniper_vn_flag_deny,
  &hf_juniper_vn_flag_drop,
  &hf_juniper_vn_flag_alert,
  NULL
  };

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
dissect_juniper_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *juniper_subtree, guint8 *flags)
{
  proto_item *tisub, *magic_item;
  guint8     l2hdr_presence,proto,ext_type,ext_len;
  guint16    ext_total_len,ext_offset=6,hdr_len;
  guint32    magic_number,ext_val;

  proto_tree *juniper_ext_subtree = NULL, *juniper_ext_subtree_item = NULL;

  magic_number = tvb_get_ntoh24(tvb, 0);
  *flags = tvb_get_guint8(tvb, 3);
  l2hdr_presence = *flags & JUNIPER_FLAG_NO_L2;

  magic_item = proto_tree_add_item(juniper_subtree, hf_juniper_magic, tvb, 0, 3, ENC_BIG_ENDIAN);

  /* be liberal with magic-number detection -
   * some older JUNOS releases (e.g. 6.4),
   * which are still in the field do not generate magic-numbers */
  if (magic_number != JUNIPER_PCAP_MAGIC) {
    expert_add_info(pinfo, magic_item, &ei_juniper_no_magic);
    return 0;
  }

  proto_tree_add_item(juniper_subtree, hf_juniper_direction, tvb, 3, 1, ENC_NA);

  proto_tree_add_uint(juniper_subtree, hf_juniper_l2hdr_presence, tvb, 3, 1, l2hdr_presence);

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

      juniper_ext_subtree_item = proto_tree_add_subtree_format(juniper_ext_subtree, tvb, ext_offset, EXT_TLV_HEADER_SIZE + ext_len,
                                   ett_juniper, &tisub, "%s Extension TLV #%u, length: %u",
                                   val_to_str_const(ext_type, ext_tlv_vals, "Unknown"),
                                   ext_type,
                                   ext_len);

      ext_val = juniper_ext_get_tlv_value(tvb, ext_type, ext_len, ext_offset+EXT_TLV_HEADER_SIZE);

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
    dissect_juniper_payload_proto(tvb, pinfo, tree, juniper_subtree, proto, hdr_len + 4);
    return -1;
  }

  return hdr_len; /* bytes parsed */

}

/* print the payload protocol  */
static int
dissect_juniper_payload_proto(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                              proto_tree *juniper_subtree, guint proto, guint offset)
{
  proto_item *ti;
  tvbuff_t   *next_tvb;

  ti = proto_tree_add_uint(juniper_subtree, hf_juniper_payload_type, tvb, offset, 0, proto);
  PROTO_ITEM_SET_GENERATED(ti);

  if (proto == 0xa248)
  {
    proto_tree_add_item(juniper_subtree, hf_juniper_unknown_data, tvb, offset, 4, ENC_NA);
    next_tvb = tvb_new_subset_remaining(tvb, offset+4);
    call_dissector(ipv4_handle, next_tvb, pinfo, tree);
  }
  else
  {
    next_tvb = tvb_new_subset_remaining(tvb, offset);

    if (!dissector_try_uint(payload_table, proto, next_tvb, pinfo, tree))
    {
      /* XXX - left in for posterity, dissection was never done */
      /* case JUNIPER_PROTO_OAM: FIXME call OAM dissector without leading HEC byte */

      call_data_dissector(next_tvb, pinfo, tree);
    }
  }

  return 0;
}

/* MLFR dissector */
static int
dissect_juniper_mlfr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  proto_tree* juniper_subtree;
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

  juniper_subtree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_juniper, NULL, "Juniper Multi-Link Frame-Relay (FRF.15)");

  /* parse header, match mgc, extract flags and build first tree */
  bytes_processed = dissect_juniper_header(tvb, pinfo, tree, juniper_subtree, &flags);

  if(bytes_processed == -1)
    return 4;
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
      proto == JUNIPER_PROTO_UNKNOWN &&
      tvb_get_guint8(tvb,offset) == JUNIPER_HDR_LLC_UI) {
    offset += 1;
    proto = JUNIPER_PROTO_ISO;
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
    proto = JUNIPER_PROTO_Q933;
  }

  /* child link of an ML-, LS-, AS-PIC bundle / ML-PIC bundle ? */
  if (cookie_len == 0) {
    if (tvb_get_ntohs(tvb,offset+ML_PIC_COOKIE_LEN) == JUNIPER_HDR_LLC_UI ||
        tvb_get_ntohs(tvb,offset+ML_PIC_COOKIE_LEN) == (JUNIPER_HDR_LLC_UI<<8)) {
      cookie_len = ML_PIC_COOKIE_LEN;
      proto_tree_add_uint(juniper_subtree, hf_juniper_mlpic_cookie,
                          tvb, offset, ML_PIC_COOKIE_LEN, mlpic_cookie);
      offset += 4;
      proto = JUNIPER_PROTO_ISO;
    }
  }

  /* ML-PIC bundle ? */
  if (cookie_len == 0 && tvb_get_guint8(tvb,offset+ML_PIC_COOKIE_LEN) == JUNIPER_HDR_LLC_UI) {
    cookie_len = ML_PIC_COOKIE_LEN;
    proto_tree_add_uint(juniper_subtree, hf_juniper_mlpic_cookie,
                        tvb, offset, ML_PIC_COOKIE_LEN, mlpic_cookie);
    offset += 3;
    proto = JUNIPER_PROTO_ISO;
  }

  ti = proto_tree_add_uint(juniper_subtree, hf_juniper_cookie_len, tvb, offset, 0, cookie_len);
  PROTO_ITEM_SET_GENERATED(ti);

  dissect_juniper_payload_proto(tvb, pinfo, tree, juniper_subtree, proto, offset);

  return tvb_captured_length(tvb);
}



/* MLPPP dissector */
static int
dissect_juniper_mlppp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  proto_tree* juniper_subtree;
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

  juniper_subtree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_juniper, NULL, "Juniper MLPPP");

  /* parse header, match mgc, extract flags and build first tree */
  bytes_processed = dissect_juniper_header(tvb, pinfo, tree, juniper_subtree, &flags);

  if(bytes_processed == -1)
    return 4;
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
    proto = JUNIPER_PROTO_PPP;
    offset += 2;
  }

  /* ML-PIC ? */
  if (cookie_len == 0 && ppp_heuristic_guess(tvb_get_ntohs(tvb, offset+2))) {
    proto = JUNIPER_PROTO_PPP;
    cookie_len = 2;
    mlpic_cookie = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(juniper_subtree, hf_juniper_mlpic_cookie,
                        tvb, offset, ML_PIC_COOKIE_LEN, mlpic_cookie);
  }

  /* child link of an ML-PIC bundle ? */
  if (cookie_len == 0 && ppp_heuristic_guess(tvb_get_ntohs(tvb, offset))) {
    proto = JUNIPER_PROTO_PPP;
  }

  ti = proto_tree_add_uint(juniper_subtree, hf_juniper_cookie_len, tvb, offset, 0, cookie_len);
  PROTO_ITEM_SET_GENERATED(ti);
  offset += cookie_len;

  dissect_juniper_payload_proto(tvb, pinfo, tree, juniper_subtree, proto, offset);

  return tvb_captured_length(tvb);
}


/* PPPoE dissector */
static int
dissect_juniper_pppoe(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_tree* juniper_subtree;
  guint      offset;
  int        bytes_processed;
  guint8     flags;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Juniper PPPoE");
  col_clear(pinfo->cinfo, COL_INFO);

  offset = 0;

  juniper_subtree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_juniper, NULL, "Juniper PPPoE PIC");

  /* parse header, match mgc, extract flags and build first tree */
  bytes_processed = dissect_juniper_header(tvb, pinfo, tree, juniper_subtree, &flags);

  if(bytes_processed == -1)
    return 4;
  else
    offset+=bytes_processed;

  dissect_juniper_payload_proto(tvb, pinfo, tree, juniper_subtree, JUNIPER_PROTO_ETHER, offset);

  return tvb_captured_length(tvb);
}

/* Ethernet dissector */
static int
dissect_juniper_ether(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_tree* juniper_subtree;
  guint      offset;
  int        bytes_processed;
  guint8     flags;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Juniper Ethernet");
  col_clear(pinfo->cinfo, COL_INFO);

  offset = 0;

  juniper_subtree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_juniper, NULL, "Juniper Ethernet");

  /* parse header, match mgc, extract flags and build first tree */
  bytes_processed = dissect_juniper_header(tvb, pinfo, tree, juniper_subtree, &flags);

  if(bytes_processed == -1)
    return 4;
  else
    offset+=bytes_processed;

  dissect_juniper_payload_proto(tvb, pinfo, tree, juniper_subtree, JUNIPER_PROTO_ETHER, offset);

  return tvb_captured_length(tvb);
}

/* PPP dissector */
static int
dissect_juniper_ppp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_tree* juniper_subtree;
  guint      offset;
  int        bytes_processed;
  guint8     flags;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Juniper PPP");
  col_clear(pinfo->cinfo, COL_INFO);

  offset = 0;

  juniper_subtree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_juniper, NULL, "Juniper PPP");

  /* parse header, match mgc, extract flags and build first tree */
  bytes_processed = dissect_juniper_header(tvb, pinfo, tree, juniper_subtree, &flags);

  if(bytes_processed == -1)
    return 4;
  else
    offset+=bytes_processed;

  dissect_juniper_payload_proto(tvb, pinfo, tree, juniper_subtree, JUNIPER_PROTO_PPP, offset+2);

  return tvb_captured_length(tvb);
}

/* Frame-Relay dissector */
static int
dissect_juniper_frelay(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_tree* juniper_subtree;
  guint      offset;
  int        bytes_processed;
  guint8     flags;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Juniper Frame-Relay");
  col_clear(pinfo->cinfo, COL_INFO);

  offset = 0;

  juniper_subtree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_juniper, NULL, "Juniper Frame-Relay");

  /* parse header, match mgc, extract flags and build first tree */
  bytes_processed = dissect_juniper_header(tvb, pinfo, tree, juniper_subtree, &flags);

  if(bytes_processed == -1)
    return 4;
  else
    offset+=bytes_processed;

  dissect_juniper_payload_proto(tvb, pinfo, tree, juniper_subtree, JUNIPER_PROTO_FRELAY, offset);

  return tvb_captured_length(tvb);
}

/* C-HDLC dissector */
static int
dissect_juniper_chdlc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_tree* juniper_subtree;
  guint      offset = 0;
  int        bytes_processed;
  guint8     flags;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Juniper C-HDLC");
  col_clear(pinfo->cinfo, COL_INFO);

  juniper_subtree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_juniper, NULL, "Juniper C-HDLC");

  /* parse header, match mgc, extract flags and build first tree */
  bytes_processed = dissect_juniper_header(tvb, pinfo, tree, juniper_subtree, &flags);

  if(bytes_processed == -1)
    return 4;
  else
    offset+=bytes_processed;

  dissect_juniper_payload_proto(tvb, pinfo, tree, juniper_subtree, JUNIPER_PROTO_CHDLC, offset);

  return tvb_captured_length(tvb);
}



/* wrapper for passing the PIC type to the generic ATM dissector */
static int
dissect_juniper_atm1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  dissect_juniper_atm(tvb,pinfo,tree, JUNIPER_PIC_ATM1);
  return tvb_captured_length(tvb);
}

/* wrapper for passing the PIC type to the generic ATM dissector */
static int
dissect_juniper_atm2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  dissect_juniper_atm(tvb,pinfo,tree, JUNIPER_PIC_ATM2);
  return tvb_captured_length(tvb);
}

/* generic ATM dissector */
static void
dissect_juniper_atm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 atm_pictype)
{
  proto_item *ti;
  proto_tree* juniper_subtree;
  guint8     next_proto = JUNIPER_PROTO_UNKNOWN,atm1_header_len,atm2_header_len,flags;
  guint32    cookie1, proto;
  guint64    cookie2;
  guint      offset = 0;
  int        bytes_processed;
  tvbuff_t   *next_tvb;

  col_clear(pinfo->cinfo, COL_INFO);

  switch (atm_pictype) {
  case JUNIPER_PIC_ATM1:
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Juniper ATM1");
    juniper_subtree = proto_tree_add_subtree(tree, tvb, 0, 0 , ett_juniper, NULL, "Juniper ATM1 PIC");
    break;
  case JUNIPER_PIC_ATM2:
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Juniper ATM2");
    juniper_subtree = proto_tree_add_subtree(tree, tvb, 0, 0 , ett_juniper, NULL, "Juniper ATM2 PIC");
    break;
  default: /* should not happen */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Juniper ATM unknown");
    proto_tree_add_subtree(tree, tvb, 0, 0 , ett_juniper, NULL, "Juniper unknown ATM PIC");
    return;
  }

  /* parse header, match mgc, extract flags and build first tree */
  bytes_processed = dissect_juniper_header(tvb, pinfo, tree, juniper_subtree, &flags);
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
      next_proto = JUNIPER_PROTO_OAM;
  }
  else { /* JUNIPER_PIC_ATM2 */
    proto_tree_add_uint64(juniper_subtree, hf_juniper_atm2_cookie, tvb, offset, 8, cookie2);
    offset += atm2_header_len;
    if (cookie2 & 0x70) /* OAM cell ? */
      next_proto = JUNIPER_PROTO_OAM;
  }

  next_tvb = tvb_new_subset_remaining(tvb, offset);

  if (next_proto == JUNIPER_PROTO_OAM) {
    dissect_juniper_payload_proto(tvb, pinfo, tree, juniper_subtree, JUNIPER_PROTO_OAM, offset);
    return;
  }

  proto = tvb_get_ntoh24(tvb, offset); /* first try: 24-Bit guess */

  if (proto == JUNIPER_HDR_NLPID) {
    /*
     * This begins with something that appears to be an LLC header for
     * OSI; is this LLC-multiplexed traffic?
     */
    dissect_juniper_payload_proto(tvb, pinfo, tree, juniper_subtree, JUNIPER_PROTO_LLC, offset);
    return;
  }

  if (proto == JUNIPER_HDR_SNAP) {
    /*
     * This begins with something that appears to be an LLC header for
     * SNAP; is this LLC-multiplexed traffic?
     */
    dissect_juniper_payload_proto(tvb, pinfo, tree, juniper_subtree, JUNIPER_PROTO_LLC_SNAP, offset);
    return;
  }

  if ((flags & JUNIPER_FLAG_PKT_IN) != JUNIPER_FLAG_PKT_IN && /* ether-over-1483 encaps ? */
      (cookie1 & JUNIPER_ATM2_GAP_COUNT_MASK) &&
      atm_pictype != JUNIPER_PIC_ATM1) {
    dissect_juniper_payload_proto(tvb, pinfo, tree, juniper_subtree, JUNIPER_PROTO_ETHER, offset);
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
    proto_tree_add_uint_format_value(juniper_subtree, hf_juniper_encap_type, tvb, offset, 0, 0, "VC-MUX");
    dissect_juniper_payload_proto(tvb, pinfo, tree, juniper_subtree, JUNIPER_PROTO_PPP, offset);
    return;
  }

  proto = tvb_get_guint8(tvb, offset); /* third try: 8-Bit guess */

  if ( proto == JUNIPER_HDR_LLC_UI ) {
    /*
     * Cisco style NLPID encaps?
     * Is the 0x03 an LLC UI control field?
     */
    proto_tree_add_uint_format_value(juniper_subtree, hf_juniper_encap_type, tvb, offset, 1, 1, "Cisco NLPID");
    dissect_juniper_payload_proto(tvb, pinfo, tree, juniper_subtree, JUNIPER_PROTO_ISO, offset+1);
    return;
  }

  next_proto = ip_heuristic_guess( (guint8) proto);
  if (next_proto != JUNIPER_PROTO_UNKNOWN) { /* last resort: VC-MUX encaps ? */
    /*
     * This begins with something that might be the first byte of
     * an IPv4 or IPv6 packet; is this VC-multiplexed IP?
     */
    proto_tree_add_uint_format_value(juniper_subtree, hf_juniper_encap_type, tvb, offset, 0, 2, "VC-MUX");
    dissect_juniper_payload_proto(tvb, pinfo, tree, juniper_subtree, next_proto, offset);
    return;
  }

  /* could not figure what it is */
  ti = proto_tree_add_uint_format_value(juniper_subtree, hf_juniper_payload_type, tvb, offset, 0, 0xFFFF, "Unknown");
  proto_item_set_len(ti, tvb_reported_length_remaining(tvb, offset));
  call_data_dissector(next_tvb, pinfo, tree);
}


static int dissect_juniper_ggsn(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_) {

  proto_tree* juniper_subtree;
  guint      offset = 0;
  int        bytes_processed;
  guint8     flags;
  guint16    proto;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Juniper GGSN");
  col_clear(pinfo->cinfo, COL_INFO);

  juniper_subtree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_juniper, NULL, "Juniper GGSN");

  /* parse header, match mgc, extract flags and build first tree */
  bytes_processed = dissect_juniper_header(tvb, pinfo, tree, juniper_subtree, &flags);

  if(bytes_processed == -1)
    return 4;
  else
    offset+=bytes_processed;

  proto = tvb_get_letohs(tvb, offset); /* fetch protocol */

  proto_tree_add_uint(juniper_subtree, hf_juniper_proto, tvb, offset, 2, proto);
  proto_tree_add_item(juniper_subtree, hf_juniper_vlan, tvb, offset+2, 2, ENC_LITTLE_ENDIAN);
  offset += 4;

  dissect_juniper_payload_proto(tvb, pinfo, tree, juniper_subtree, proto, offset);

  return tvb_captured_length(tvb);
}

static int dissect_juniper_vp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_) {

  proto_tree* juniper_subtree;
  guint      offset = 0;
  int        bytes_processed;
  guint8     flags;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Juniper Voice PIC");
  col_clear(pinfo->cinfo, COL_INFO);

  juniper_subtree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_juniper, NULL, "Juniper Voice PIC");

  /* parse header, match mgc, extract flags and build first tree */
  bytes_processed = dissect_juniper_header(tvb, pinfo, tree, juniper_subtree, &flags);

  if(bytes_processed == -1)
    return 4;
  else
    offset+=bytes_processed;

  /*
   * Right know IPv4 is the only protocol we may encounter.
   * For the future there should be sufficient space in the 18-byte
   * empty header before payload starts.
   */
  dissect_juniper_payload_proto(tvb, pinfo, tree, juniper_subtree, JUNIPER_PROTO_IP, offset+18);
  return tvb_captured_length(tvb);
}

/* Wrapper for Juniper service PIC coookie dissector */
static int
dissect_juniper_svcs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_tree* juniper_subtree;
  guint      offset = 0;
  int bytes_processed = 0;
  guint8     flags;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Juniper Services");
  col_clear(pinfo->cinfo, COL_INFO);

  juniper_subtree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_juniper, NULL, "Juniper Services cookie");

  /* parse header, match mgc, extract flags and build first tree */
  bytes_processed = dissect_juniper_header(tvb, pinfo, tree, juniper_subtree, &flags);

  if (bytes_processed == -1)
      return 4;
  else
      offset+=bytes_processed;

  if (flags & JUNIPER_FLAG_PKT_IN) {
      proto_tree_add_uint(juniper_subtree, hf_juniper_proto, tvb, offset, 2, JUNIPER_PROTO_IP);
      offset += 16;
  } else {
      offset += 12;
  }

  dissect_juniper_payload_proto(tvb, pinfo, tree, juniper_subtree, JUNIPER_PROTO_IP, offset);
  return tvb_captured_length(tvb);
}

static int dissect_juniper_vn(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
  proto_item *ti;
  proto_tree* juniper_subtree;
  guint offset = 0;
  guint32 tlv_type, tlv_len;

  col_set_str(pinfo->cinfo, COL_PROTOCOL,
          "Juniper Virtual Network Information");
  col_clear(pinfo->cinfo, COL_INFO);

  juniper_subtree = proto_tree_add_subtree(tree, tvb, offset, 20,
          ett_juniper, &ti, "Juniper Virtual Network Information");

  tlv_type = tvb_get_guint8(tvb, offset);
  tlv_len = tvb_get_guint8(tvb, (offset + 1));
  offset += VN_TLV_HDR_SIZE;

  while (tlv_type != 255) {

      switch (tlv_type) {
          case VN_TLV_HOST_IP:
              proto_tree_add_item(juniper_subtree, hf_juniper_vn_host_ip, tvb,
                      offset, 4, ENC_BIG_ENDIAN);
              break;
          case VN_TLV_FLAGS:
              proto_tree_add_bitmask(juniper_subtree, tvb, offset, hf_juniper_vn_flags, ett_juniper_vn_flags, vn_flags, ENC_BIG_ENDIAN);
              break;
          case VN_TLV_SRC_VN:
              proto_tree_add_item(juniper_subtree, hf_juniper_vn_src, tvb, offset, tlv_len, ENC_NA|ENC_ASCII);
              break;
          case VN_TLV_DST_VN:
              proto_tree_add_item(juniper_subtree, hf_juniper_vn_dst, tvb, offset, tlv_len, ENC_NA|ENC_ASCII);
              break;
          default:
              proto_tree_add_expert(juniper_subtree, pinfo, &ei_juniper_vn_incorrect_format, tvb, 0, 0);
              return offset;
      }

      offset += tlv_len;
      tlv_type = tvb_get_guint8(tvb, offset);
      tlv_len = tvb_get_guint8(tvb, (offset + 1));
      offset += VN_TLV_HDR_SIZE;
  }

  offset+=tlv_len;
  dissect_juniper_payload_proto(tvb, pinfo, tree, ti, JUNIPER_PROTO_ETHER, offset);

  return tvb_captured_length(tvb);
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
  case PPP_OSINLCP :
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
    return JUNIPER_PROTO_IP;
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
    return JUNIPER_PROTO_IP6;
  default:
    return JUNIPER_PROTO_UNKNOWN; /* did not find a ip header */
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
      return JUNIPER_PROTO_PPP;
    case JUNIPER_PIC_MLFR:
      return JUNIPER_PROTO_ISO;
    default:
      return JUNIPER_PROTO_UNKNOWN;
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
          return JUNIPER_PROTO_PPP;
        else
          return JUNIPER_PROTO_IP;
      case JUNIPER_PIC_MLFR:
        if (lsq_dir == (LSQ_COOKIE_RE|LSQ_COOKIE_DIR))
          return JUNIPER_PROTO_UNKNOWN;
        else
          return JUNIPER_PROTO_IP;
      default:
        return JUNIPER_PROTO_UNKNOWN;
      }
    case LSQ_L3_PROTO_IPV6:
      return JUNIPER_PROTO_IP6;
    case LSQ_L3_PROTO_MPLS:
      return JUNIPER_PROTO_MPLS;
    case LSQ_L3_PROTO_ISO:
      return JUNIPER_PROTO_ISO;
    default:
      return JUNIPER_PROTO_UNKNOWN;
    }
  default:
    return JUNIPER_PROTO_UNKNOWN;
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
    { &hf_juniper_cookie_len,
      { "Cookie length", "juniper.cookie_len", FT_UINT32, BASE_DEC,
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
    { &hf_juniper_payload_type,
      { "Payload Type", "juniper.payload_type", FT_UINT16, BASE_DEC,
        VALS(juniper_proto_vals), 0x0, NULL, HFILL }},
    { &hf_juniper_encap_type,
      { "Encapsulation Type", "juniper.encap_type", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},
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
    { &hf_juniper_unknown_data,
      { "Unknown data", "juniper.unknown_data", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},
    { &hf_juniper_vn_host_ip,
      { "Host IP", "juniper.vn.host_ip", FT_IPv4, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},
    { &hf_juniper_vn_src,
      { "Src VN", "juniper.vn.src", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},
    { &hf_juniper_vn_dst,
      { "Dst VN", "juniper.vn.dst", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},
    { &hf_juniper_vn_flags,
      { "Flags", "juniper.vn.flags", FT_UINT32, BASE_HEX, NULL, VN_FLAG_MASK,
        NULL, HFILL }},
    { &hf_juniper_vn_flag_alert,
        { "Action Alert", "juniper.vn.flags.alert", FT_BOOLEAN, 32,
          TFS(&tfs_set_notset), VN_FLAG_ALERT, NULL, HFILL }},
    { &hf_juniper_vn_flag_drop,
        { "Action Drop", "juniper.vn.flags.drop", FT_BOOLEAN, 32,
          TFS(&tfs_set_notset), VN_FLAG_DROP, NULL, HFILL }},
    { &hf_juniper_vn_flag_deny,
        { "Action Deny", "juniper.vn.flags.deny", FT_BOOLEAN, 32,
          TFS(&tfs_set_notset), VN_FLAG_DENY, NULL, HFILL }},
    { &hf_juniper_vn_flag_log,
        { "Action Log", "juniper.vn.flags.log", FT_BOOLEAN, 32,
          TFS(&tfs_set_notset), VN_FLAG_LOG, NULL, HFILL }},
    { &hf_juniper_vn_flag_pass,
        { "Action Pass", "juniper.vn.flags.pass", FT_BOOLEAN, 32,
          TFS(&tfs_set_notset), VN_FLAG_PASS, NULL, HFILL }},
    { &hf_juniper_vn_flag_reject,
        { "Action Reject", "juniper.vn.flags.reject", FT_BOOLEAN, 32,
          TFS(&tfs_set_notset), VN_FLAG_REJECT, NULL, HFILL }},
    { &hf_juniper_vn_flag_mirror,
        { "Action Mirror", "juniper.vn.flags.mirror", FT_BOOLEAN, 32,
          TFS(&tfs_set_notset), VN_FLAG_MIRROR, NULL, HFILL }},
    { &hf_juniper_vn_flag_direction,
        { "Direction Ingress", "juniper.vn.flags.direction", FT_BOOLEAN, 32,
          TFS(&tfs_set_notset), VN_FLAG_DIRECTION, NULL, HFILL }},
  };

  static gint *ett[] = {
    &ett_juniper,
    &ett_juniper_vn_flags,
  };

  static ei_register_info ei[] = {
    { &ei_juniper_no_magic, { "juniper.magic-number.none", PI_PROTOCOL, PI_WARN, "No Magic-Number found!", EXPFILL }},
    { &ei_juniper_vn_incorrect_format, { "juniper.vn.incorrect_format", PI_PROTOCOL, PI_WARN, "Incorrect format", EXPFILL }},
  };

  expert_module_t* expert_juniper;

  proto_juniper = proto_register_protocol("Juniper", "Juniper", "juniper");
  proto_register_field_array(proto_juniper, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_juniper = expert_register_protocol(proto_juniper);
  expert_register_field_array(expert_juniper, ei, array_length(ei));

  payload_table = register_dissector_table("juniper.proto", "Juniper payload dissectors", proto_juniper, FT_UINT32, BASE_HEX);

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
  dissector_handle_t juniper_svcs_handle;
  dissector_handle_t juniper_vn_handle;

  ipv4_handle   = find_dissector_add_dependency("ip", proto_juniper);

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
  juniper_svcs_handle   = create_dissector_handle(dissect_juniper_svcs,   proto_juniper);
  juniper_vn_handle     = create_dissector_handle(dissect_juniper_vn,     proto_juniper);

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
  dissector_add_uint("wtap_encap", WTAP_ENCAP_JUNIPER_SVCS,   juniper_svcs_handle);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_JUNIPER_VN,     juniper_vn_handle);
  dissector_add_for_decode_as("udp.port", juniper_vn_handle);
}


/*
 * Editor modelines
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
