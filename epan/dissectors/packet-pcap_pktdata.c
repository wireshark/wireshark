/* packet-pcap_pktdata.c
 * Dissect packet data from a pcap or pcapng file or from a "remote pcap"
 * protocol.
 *
 * Copyright 2015, Michal Labedzki for Tieto Corporation
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

#include <wiretap/wtap.h>
#include <wiretap/pcap-encap.h>

#include <epan/dissectors/packet-pcap_pktdata.h>

void proto_register_pcap_pktdata(void);
void proto_reg_handoff_pcap_pktdata(void);

static int proto_pcap_pktdata = -1;

static int hf_pcap_pktdata_pseudoheader = -1;
static int hf_pcap_pktdata_pseudoheader_bluetooth_direction = -1;
static int hf_pcap_pktdata_undecoded_data = -1;

static gint ett_pcap_pktdata_pseudoheader = -1;

static expert_field ei_pcap_pktdata_linktype_unknown = EI_INIT;
static expert_field ei_pcap_pktdata_cant_generate_phdr = EI_INIT;

static dissector_table_t wtap_encap_table;

/*
 * Link-layer header type values.
 *
 * Includes both the official documented values from
 *
 *    http://www.tcpdump.org/linktypes.html
 *
 * and values not listed there.  The names are, in most cases, the
 * LINKTYPE_ names with LINKTYPE_ stripped off.
 */
const value_string link_type_vals[] = {
    { 0,    "NULL" },
    { 1,    "ETHERNET" },
    { 2,    "EXP_ETHERNET" },            /* 3Mb experimental Ethernet */
    { 3,    "AX25" },
    { 4,    "PRONET" },                 /* Proteon PRONET */
    { 5,    "CHAOS" },                  /* MIT Chaosnet */
    { 6,    "IEEE802_5" },
    { 7,    "ARCNET_BSD" },
    { 8,    "SLIP" },
    { 9,    "PPP" },
    { 10,   "FDDI" },
    { 32,   "REDBACK" },                /* Redback SmartEdge 400/800 */
    { 50,   "PPP_HDLC" },
    { 51,   "PPP_ETHER" },
    { 99,   "SYMANTEC_FIREWALL" },
    { 100,  "ATM_RFC1483" },
    { 101,  "RAW" },
    { 102,  "BSD/OS SLIP" },
    { 103,  "BSD/OS PPP" },
    { 104,  "C_HDLC" },
    { 105,  "IEEE802_11" },
    { 106,  "LINUX_ATM_CLIP" },
    { 107,  "FRELAY" },
    { 108,  "LOOP" },
    { 109,  "ENC" },
    { 110,  "LANE8023" },               /* ATM LANE + 802.3 */
    { 111,  "HIPPI" },                  /* NetBSD HIPPI */
    { 112,  "HDLC" },                   /* NetBSD HDLC framing */
    { 113,  "LINUX_SLL" },
    { 114,  "LTALK" },
    { 115,  "ECONET" },                 /* Acorn Econet */
    { 116,  "IPFILTER" },               /* Reserved for use with OpenBSD ipfilter */
    { 117,  "PFLOG" },
    { 118,  "CISCO_IOS" },              /* for Cisco-internal use */
    { 119,  "IEEE802_11_PRISM" },
    { 120,  "IEEE802_11_AIRONET" },     /* 802.11 plus FreeBSD Aironet drive metadata header */
    { 121,  "HHDLC" },                  /* reserved for Siemens HiPath HDLC - never used */
    { 122,  "IP_OVER_FC" },
    { 123,  "SUNATM" },
    { 124,  "RIO" },                    /* Private use for RapidIO */
    { 125,  "PCI_EXP" },                /* Private use for PCI Express */
    { 126,  "AURORA" },                 /* Xilinx Aurora link layer */
    { 127,  "IEEE802_11_RADIOTAP" },
    { 128,  "TZSP" },                   /* reserved for TZSP encapsulation - never used */
    { 129,  "ARCNET_LINUX" },
    { 130,  "JUNIPER_MLPPP" },          /* Juniper-private, but handled by tcpdump and Wireshark */
    { 131,  "JUNIPER_MLFR" },           /* Juniper-private, but handled by tcpdump and Wireshark */
    { 132,  "JUNIPER_ES" },             /* Juniper-private, but handled by tcpdump */
    { 133,  "JUNIPER_GGSN" },           /* Juniper-private, but handled by tcpdump and Wireshark */
    { 134,  "JUNIPER_MFR" },            /* Juniper-private, but handled by tcpdump and Wireshark */
    { 135,  "JUNIPER_ATM2" },           /* Juniper-private, but handled by tcpdump and Wireshark */
    { 136,  "JUNIPER_SVCS" },           /* Juniper-private, but handled by tcpdump and Wireshark */
    { 137,  "JUNIPER_ATM1" },           /* Juniper-private, but handled by tcpdump and Wireshark */
    { 138,  "APPLE_IP_OVER_IEEE1394" },
    { 139,  "MTP2_WITH_PHDR" },
    { 140,  "MTP2" },
    { 141,  "MTP3" },
    { 142,  "SCCP" },
    { 143,  "DOCSIS" },
    { 144,  "LINUX_IRDA" },
    { 145,  "IBM_SP" },                 /* Reserved for IBM SP switch */
    { 146,  "IBM_SN" },                 /* Reserved for IBM Next Federation switch */
    { 147,  "USER_0" },
    { 148,  "USER_1" },
    { 149,  "USER_2" },
    { 150,  "USER_3" },
    { 151,  "USER_4" },
    { 152,  "USER_5" },
    { 153,  "USER_6" },
    { 154,  "USER_7" },
    { 155,  "USER_8" },
    { 156,  "USER_9" },
    { 157,  "USER_10" },
    { 158,  "USER_11" },
    { 159,  "USER_12" },
    { 160,  "USER_13" },
    { 161,  "USER_14" },
    { 162,  "USER_15" },
    { 163,  "IEEE802_11_AVS" },
    { 164,  "JUNIPER_MONITOR" },        /* Juniper-private, but handled by tcpdump */
    { 165,  "BACNET_MS_TP" },
    { 166,  "PPP_PPPD" },
    { 167,  "JUNIPER_PPPOE" },          /* Juniper-private, but handled by tcpdump and Wireshark */
    { 168,  "JUNIPER_PPPOE_ATM" },      /* Juniper-private, but handled by tcpdump */
    { 169,  "GPRS_LLC" },
    { 170,  "GPF_T" },                  /* GPF-T (ITU-T G.7041/Y.1303) */
    { 171,  "GPF_F" },                  /* GPF-F (ITU-T G.7041/Y.1303) */
    { 172,  "GCOM_TIE1" },              /* Reserved for Gcom's T1/E1 line monitoring equipment */
    { 173,  "GCOM_SERIAL" },            /* Reserved for Gcom's T1/E1 line monitoring equipment */
    { 174,  "JUNIPER_PIC_PEER" },       /* Juniper-private */
    { 175,  "ERF_ETH" },                /* ERF header followed by Ethernet */
    { 176,  "ERF_POS" },                /* ERF header followed by Packet-over-SONET */
    { 177,  "LINUX_LAPD" },
    { 178,  "JUNIPER_ETHER" },          /* Juniper-private, but handled by tcpdump and Wireshark */
    { 179,  "JUNIPER_PPP" },            /* Juniper-private, but handled by tcpdump and Wireshark */
    { 180,  "JUNIPER_FRELAY" },         /* Juniper-private, but handled by tcpdump and Wireshark */
    { 181,  "JUNIPER_CHDLC" },          /* Juniper-private, but handled by tcpdump and Wireshark */
    { 182,  "MFR" },                    /* Multi Link Frame Relay (FRF.16) */
    { 183,  "JUNIPER_VP" },             /* Juniper-private, but handled by tcpdump and Wireshark */
    { 184,  "A429" },                   /* Arinc 429 frames */
    { 185,  "A653_ICM" },               /* Aricn 653 Interpartition Communication messages */
    { 186,  "USB" },                    /* Older USB header */
    { 187,  "BLUETOOTH_HCI_H4" },
    { 188,  "IEEE802_16_MAC_CPS" },     /* IEEE 802.16 MAC Common Part Sublayer */
    { 189,  "USB_LINUX" },
    { 190,  "CAN20B" },                 /* CAN v2.0B packets */
    { 191,  "IEEE802_15_4_LINUX" },     /* IEEE 802.15.4, with address fields padded, as is done by Linux drivers */
    { 192,  "PPI" },
    { 193,  "IEEE802_16_MAC_CPS_RADIO" }, /* 802.16 MAC Common Part Sublayer plus a radiotap radio header */
    { 194,  "JUNIPER_ISM" },            /* Juniper-private */
    { 195,  "IEEE802_15_4" },
    { 196,  "SITA" },
    { 197,  "ERF" },
    { 198,  "RAIF1" },                  /* Special header prepended to Ethernet packets when capturing from a u10 Networks board */
    { 199,  "IPMB" },                   /* IPMB packet for IPMI */
    { 200,  "JUNIPER_ST" },             /* Juniper-private */
    { 201,  "BLUETOOTH_HCI_H4_WITH_PHDR" },
    { 202,  "AX25_KISS" },
    { 203,  "LAPD" },
    { 204,  "PPP_WITH_DIR" },
    { 205,  "C_HDLC_WITH_DIR" },
    { 206,  "FRELAY_WITH_DIR" },
    { 207,  "LAPB_WITH_DIR" },          /* LAPB with direction pseudo-header */
    { 209,  "IPMB_LINUX" },
    { 210,  "FLEXRAY" },                /* FlexRay automotive bus */
    { 211,  "MOST" },                   /* Media Oriented Systems Transport */
    { 212,  "LIN" },                    /* Local Interconnect Network */
    { 213,  "X2E_SERIAL" },             /* X2E-private for serial line capture */
    { 214,  "X2E_XORAYA" },             /* X2E-private for Xoraya data logger family */
    { 215,  "IEEE802_15_4_NONASK_PHY" },
    { 216,  "LINUX_EVDEV" },            /* Linux evdev messages */
    { 217,  "GSMTAP_UM" },              /* "gsmtap" header followed by GSM Um interface packets */
    { 218,  "GSMTAP_UM" },              /* "gsmtap" header followed by GSM Abis interface packets */
    { 219,  "MPLS" },                   /* MPLS label (stack?) as the link-layer header */
    { 220,  "USB_LINUX_MMAPPED" },
    { 221,  "DECT" },                   /* DECT packets, with a pseudo-header */
    { 222,  "AOS" },                    /* AOS Space Data Link Protocol */
    { 223,  "WIHART" },                 /* Wireless HART */
    { 224,  "FC_2" },
    { 225,  "FC_2_WITH_FRAME_DELIMS" },
    { 226,  "IPNET" },
    { 227,  "CAN_SOCKETCAN" },
    { 228,  "IPV4" },
    { 229,  "IPV6" },
    { 230,  "IEEE802_15_4_NOFCS" },
    { 231,  "DBUS" },
    { 232,  "JUNIPER_VS" },             /* Juniper-private */
    { 233,  "JUNIPER_SRX_E2E" },        /* Juniper-private */
    { 234,  "JUNIPER_FIBRECHANNEL" },   /* Juniper-private */
    { 235,  "DVB_CI" },
    { 236,  "MUX27010" },
    { 237,  "STANAG_5066_D_PDU" },
    { 238,  "JUNIPER_ATM_CEMIC" },      /* Juniper-private */
    { 239,  "NFLOG" },
    { 240,  "NETANALYZER" },
    { 241,  "NETANALYZER_TRANSPARENT" },
    { 242,  "IPOIB" },
    { 243,  "MPEG_2_TS" },
    { 244,  "NG40" },
    { 245,  "NFC_LLCP" },
    { 246,  "PFSYNC" },
    { 247,  "INFINIBAND" },
    { 248,  "SCTP" },
    { 249,  "USBPCAP" },
    { 250,  "RTAC_SERIAL" },
    { 251,  "BLUETOOTH_LE_LL" },
    { 252,  "WIRESHARK_UPPER_PDU" },    /* Upper-layer protocol saves from Wireshark */
    { 253,  "NETLINK" },
    { 254,  "BLUETOOTH_LINUX_MONITOR" },
    { 255,  "BLUETOOTH_BREDR_BB" },
    { 256,  "BLUETOOTH_LE_LL_WITH_PHDR" },
    { 257,  "PROFIBUS_DL" },
    { 258,  "PKTAP" },
    { 259,  "EPON" },
    { 260,  "IPMI_HPM_2" },
    { 261,  "ZWAVE_R1_R2" },
    { 262,  "ZWAVE_R3" },
    { 263,  "WATTSTOPPER_DLM" },
    { 264,  "ISO_14443" },
    { 0, NULL }
};

static const value_string pseudoheader_bluetooth_direction_vals[] = {
    { 0,  "Sent" },
    { 1,  "Recv" },
    { 0, NULL }
};

static int
dissect_pcap_pktdata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    gint         offset = 0;
    guint32     *link_type;
    tvbuff_t    *next_tvb;
    proto_item  *pseudoheader_item;
    proto_tree  *pseudoheader_tree = NULL;
    proto_item  *packet_item;
    struct eth_phdr eth;
    void        *phdr;

    DISSECTOR_ASSERT(data);

    link_type = (guint32 *) data;

    /*
     * We're passed a pointer to a LINKTYPE_ value.
     * Find the Wiretap encapsulation for that value.
     */
    pinfo->phdr->pkt_encap = wtap_pcap_encap_to_wtap_encap(*link_type);

    /*
     * Do we know that type?
     */
    if (pinfo->phdr->pkt_encap == WTAP_ENCAP_UNKNOWN) {
        /*
         * Nothing we know.
         * Just report that and give up.
         */
        packet_item = proto_tree_add_item(tree, hf_pcap_pktdata_undecoded_data, tvb, offset, tvb_reported_length(tvb), ENC_NA);
        expert_add_info_format(pinfo, packet_item,
                               &ei_pcap_pktdata_linktype_unknown,
                               "Link-layer header type %u is not supported",
                               *link_type);
        return tvb_captured_length(tvb);
    }

    /*
     * You can't just call an arbitrary subdissector based on a
     * WTAP_ENCAP_ value, because they may expect a particular
     * pseudo-header to be passed to them, and may not accept
     * a null pseudo-header pointer.
     *
     * First, check whether this WTAP_ENCAP_ value corresponds
     * to a link-layer header type where Wiretap generates a
     * pseudo-header from the bytes at the beginning of the
     * packet data.
     */
    if (wtap_encap_requires_phdr(pinfo->phdr->pkt_encap)) {
        /*
         * It does.  Do we have code to do that?
         */
        switch (pinfo->phdr->pkt_encap) {

        case WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR:
            pseudoheader_item = proto_tree_add_item(tree, hf_pcap_pktdata_pseudoheader, tvb, offset, 4, ENC_NA);
            pseudoheader_tree = proto_item_add_subtree(pseudoheader_item, ett_pcap_pktdata_pseudoheader);
            proto_tree_add_item(pseudoheader_tree, hf_pcap_pktdata_pseudoheader_bluetooth_direction, tvb, offset, 4, ENC_BIG_ENDIAN);
            if (tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN) == 0)
                pinfo->p2p_dir = P2P_DIR_SENT;
            else if (tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN) == 1)
                pinfo->p2p_dir = P2P_DIR_RECV;
            else
                pinfo->p2p_dir = P2P_DIR_UNKNOWN;
            offset += 4;
            phdr = NULL;
            break;

        case WTAP_ENCAP_ATM_PDUS:
            /* TODO */
        case WTAP_ENCAP_IRDA:
            /* TODO */
        case WTAP_ENCAP_MTP2_WITH_PHDR:
            /* TODO no description for pseudoheader at http://www.tcpdump.org/linktypes.html */
        case WTAP_ENCAP_LINUX_LAPD:
            /* TODO */
        case WTAP_ENCAP_SITA:
            /* TODO */
        case WTAP_ENCAP_BLUETOOTH_LINUX_MONITOR:
            /* TODO */
	case WTAP_ENCAP_NFC_LLCP:
            /* TODO */
        case WTAP_ENCAP_PPP_WITH_PHDR:
            /* TODO */
        case WTAP_ENCAP_ERF:
            /* TODO no description for pseudoheader at http://www.tcpdump.org/linktypes.html */
        case WTAP_ENCAP_I2C:
            /* TODO */
        default:
            /*
             * No.  Give up.
             */
            packet_item = proto_tree_add_item(tree, hf_pcap_pktdata_undecoded_data, tvb, offset, tvb_reported_length(tvb), ENC_NA);
            expert_add_info_format(pinfo, packet_item,
                                   &ei_pcap_pktdata_cant_generate_phdr,
                                   "No pseudo-header can be generated for link-layer header type %u",
                                   *link_type);
            return tvb_captured_length(tvb);
        }
    } else {
        /*
         * These also require a pseudo-header, but it's not constructed
         * from packet data.
         */
        switch (pinfo->phdr->pkt_encap) {

        case WTAP_ENCAP_ETHERNET:
            eth.fcs_len = -1;    /* Unknown whether we have an FCS */
            phdr = &eth;
            break;

        default:
            phdr = NULL;
            break;
        }
    }

    next_tvb = tvb_new_subset_remaining(tvb, offset);

    offset = dissector_try_uint_new(wtap_encap_table, pinfo->phdr->pkt_encap, next_tvb, pinfo, tree, TRUE, phdr);

    return offset;
}

void
proto_register_pcap_pktdata(void)
{
    static hf_register_info hf[] = {
        { &hf_pcap_pktdata_pseudoheader,
            { "Pseudoheader",                              "pcap_pktdata.data.pseudoheader",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcap_pktdata_pseudoheader_bluetooth_direction,
            { "Direction",                                 "pcap_pktdata.pseudoheader.bluetooth.direction",
            FT_UINT32, BASE_HEX, VALS(pseudoheader_bluetooth_direction_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_pcap_pktdata_undecoded_data,
            { "Undecoded data",                            "pcap_pktdata.undecoded_data",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_pcap_pktdata_pseudoheader,
    };

    static ei_register_info ei[] = {
        { &ei_pcap_pktdata_linktype_unknown, { "pcap_pktdata.linktype_unknown", PI_UNDECODED, PI_NOTE, "That link-layer header type is not supported", EXPFILL }},
        { &ei_pcap_pktdata_cant_generate_phdr, { "pcap_pktdata.cant_generate_phdr", PI_UNDECODED, PI_NOTE, "No pseudo-header can be generated for that link-layer header type", EXPFILL }},
    };

    expert_module_t *expert_pcap_pktdata;

    proto_pcap_pktdata = proto_register_protocol("pcap/pcapng packet data", "pcap_pktdata", "pcap_pktdata");
    proto_register_field_array(proto_pcap_pktdata, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_pcap_pktdata = expert_register_protocol(proto_pcap_pktdata);
    expert_register_field_array(expert_pcap_pktdata, ei, array_length(ei));

    register_dissector("pcap_pktdata", dissect_pcap_pktdata, proto_pcap_pktdata);
}

void
proto_reg_handoff_pcap_pktdata(void)
{
    wtap_encap_table = find_dissector_table("wtap_encap");
}
