/* wtap.h
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef __WTAP_H__
#define __WTAP_H__

#include <glib.h>
#include <time.h>
#include <wsutil/buffer.h>
#include <wsutil/nstime.h>
#include "wtap_opttypes.h"
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Encapsulation types. Choose names that truly reflect
 * what is contained in the packet trace file.
 *
 * WTAP_ENCAP_PER_PACKET is a value passed to "wtap_dump_open()" or
 * "wtap_dump_fd_open()" to indicate that there is no single encapsulation
 * type for all packets in the file; this may cause those routines to
 * fail if the capture file format being written can't support that.
 * It's also returned by "wtap_file_encap()" for capture files that
 * don't have a single encapsulation type for all packets in the file.
 *
 * WTAP_ENCAP_UNKNOWN is returned by "wtap_pcap_encap_to_wtap_encap()"
 * if it's handed an unknown encapsulation.
 *
 * WTAP_ENCAP_FDDI_BITSWAPPED is for FDDI captures on systems where the
 * MAC addresses you get from the hardware are bit-swapped.  Ideally,
 * the driver would tell us that, but I know of none that do, so, for
 * now, we base it on the machine on which we're *reading* the
 * capture, rather than on the machine on which the capture was taken
 * (they're probably likely to be the same).  We assume that they're
 * bit-swapped on everything except for systems running Ultrix, Alpha
 * systems, and BSD/OS systems (that's what "tcpdump" does; I guess
 * Digital decided to bit-swap addresses in the hardware or in the
 * driver, and I guess BSDI bit-swapped them in the driver, given that
 * BSD/OS generally runs on Boring Old PC's).  If we create a wiretap
 * save file format, we'd use the WTAP_ENCAP values to flag the
 * encapsulation of a packet, so there we'd at least be able to base
 * it on the machine on which the capture was taken.
 *
 * WTAP_ENCAP_LINUX_ATM_CLIP is the encapsulation you get with the
 * ATM on Linux code from <http://linux-atm.sourceforge.net/>;
 * that code adds a DLT_ATM_CLIP DLT_ code of 19, and that
 * encapsulation isn't the same as the DLT_ATM_RFC1483 encapsulation
 * presumably used on some BSD systems, which we turn into
 * WTAP_ENCAP_ATM_RFC1483.
 *
 * WTAP_ENCAP_NULL corresponds to DLT_NULL from "libpcap".  This
 * corresponds to
 *
 *  1) PPP-over-HDLC encapsulation, at least with some versions
 *     of ISDN4BSD (but not the current ones, it appears, unless
 *     I've missed something);
 *
 *  2) a 4-byte header containing the AF_ address family, in
 *     the byte order of the machine that saved the capture,
 *     for the packet, as used on many BSD systems for the
 *     loopback device and some other devices, or a 4-byte header
 *     containing the AF_ address family in network byte order,
 *     as used on recent OpenBSD systems for the loopback device;
 *
 *  3) a 4-byte header containing 2 octets of 0 and an Ethernet
 *     type in the byte order from an Ethernet header, that being
 *     what older versions of "libpcap" on Linux turn the Ethernet
 *     header for loopback interfaces into (0.6.0 and later versions
 *     leave the Ethernet header alone and make it DLT_EN10MB). */
#define WTAP_ENCAP_PER_PACKET                   -1
#define WTAP_ENCAP_UNKNOWN                        0
#define WTAP_ENCAP_ETHERNET                       1
#define WTAP_ENCAP_TOKEN_RING                     2
#define WTAP_ENCAP_SLIP                           3
#define WTAP_ENCAP_PPP                            4
#define WTAP_ENCAP_FDDI                           5
#define WTAP_ENCAP_FDDI_BITSWAPPED                6
#define WTAP_ENCAP_RAW_IP                         7
#define WTAP_ENCAP_ARCNET                         8
#define WTAP_ENCAP_ARCNET_LINUX                   9
#define WTAP_ENCAP_ATM_RFC1483                   10
#define WTAP_ENCAP_LINUX_ATM_CLIP                11
#define WTAP_ENCAP_LAPB                          12
#define WTAP_ENCAP_ATM_PDUS                      13
#define WTAP_ENCAP_ATM_PDUS_UNTRUNCATED          14
#define WTAP_ENCAP_NULL                          15
#define WTAP_ENCAP_ASCEND                        16
#define WTAP_ENCAP_ISDN                          17
#define WTAP_ENCAP_IP_OVER_FC                    18
#define WTAP_ENCAP_PPP_WITH_PHDR                 19
#define WTAP_ENCAP_IEEE_802_11                   20
#define WTAP_ENCAP_IEEE_802_11_PRISM             21
#define WTAP_ENCAP_IEEE_802_11_WITH_RADIO        22
#define WTAP_ENCAP_IEEE_802_11_RADIOTAP          23
#define WTAP_ENCAP_IEEE_802_11_AVS               24
#define WTAP_ENCAP_SLL                           25
#define WTAP_ENCAP_FRELAY                        26
#define WTAP_ENCAP_FRELAY_WITH_PHDR              27
#define WTAP_ENCAP_CHDLC                         28
#define WTAP_ENCAP_CISCO_IOS                     29
#define WTAP_ENCAP_LOCALTALK                     30
#define WTAP_ENCAP_OLD_PFLOG                     31
#define WTAP_ENCAP_HHDLC                         32
#define WTAP_ENCAP_DOCSIS                        33
#define WTAP_ENCAP_COSINE                        34
#define WTAP_ENCAP_WFLEET_HDLC                   35
#define WTAP_ENCAP_SDLC                          36
#define WTAP_ENCAP_TZSP                          37
#define WTAP_ENCAP_ENC                           38
#define WTAP_ENCAP_PFLOG                         39
#define WTAP_ENCAP_CHDLC_WITH_PHDR               40
#define WTAP_ENCAP_BLUETOOTH_H4                  41
#define WTAP_ENCAP_MTP2                          42
#define WTAP_ENCAP_MTP3                          43
#define WTAP_ENCAP_IRDA                          44
#define WTAP_ENCAP_USER0                         45
#define WTAP_ENCAP_USER1                         46
#define WTAP_ENCAP_USER2                         47
#define WTAP_ENCAP_USER3                         48
#define WTAP_ENCAP_USER4                         49
#define WTAP_ENCAP_USER5                         50
#define WTAP_ENCAP_USER6                         51
#define WTAP_ENCAP_USER7                         52
#define WTAP_ENCAP_USER8                         53
#define WTAP_ENCAP_USER9                         54
#define WTAP_ENCAP_USER10                        55
#define WTAP_ENCAP_USER11                        56
#define WTAP_ENCAP_USER12                        57
#define WTAP_ENCAP_USER13                        58
#define WTAP_ENCAP_USER14                        59
#define WTAP_ENCAP_USER15                        60
#define WTAP_ENCAP_SYMANTEC                      61
#define WTAP_ENCAP_APPLE_IP_OVER_IEEE1394        62
#define WTAP_ENCAP_BACNET_MS_TP                  63
#define WTAP_ENCAP_NETTL_RAW_ICMP                64
#define WTAP_ENCAP_NETTL_RAW_ICMPV6              65
#define WTAP_ENCAP_GPRS_LLC                      66
#define WTAP_ENCAP_JUNIPER_ATM1                  67
#define WTAP_ENCAP_JUNIPER_ATM2                  68
#define WTAP_ENCAP_REDBACK                       69
#define WTAP_ENCAP_NETTL_RAW_IP                  70
#define WTAP_ENCAP_NETTL_ETHERNET                71
#define WTAP_ENCAP_NETTL_TOKEN_RING              72
#define WTAP_ENCAP_NETTL_FDDI                    73
#define WTAP_ENCAP_NETTL_UNKNOWN                 74
#define WTAP_ENCAP_MTP2_WITH_PHDR                75
#define WTAP_ENCAP_JUNIPER_PPPOE                 76
#define WTAP_ENCAP_GCOM_TIE1                     77
#define WTAP_ENCAP_GCOM_SERIAL                   78
#define WTAP_ENCAP_NETTL_X25                     79
#define WTAP_ENCAP_K12                           80
#define WTAP_ENCAP_JUNIPER_MLPPP                 81
#define WTAP_ENCAP_JUNIPER_MLFR                  82
#define WTAP_ENCAP_JUNIPER_ETHER                 83
#define WTAP_ENCAP_JUNIPER_PPP                   84
#define WTAP_ENCAP_JUNIPER_FRELAY                85
#define WTAP_ENCAP_JUNIPER_CHDLC                 86
#define WTAP_ENCAP_JUNIPER_GGSN                  87
#define WTAP_ENCAP_LINUX_LAPD                    88
#define WTAP_ENCAP_CATAPULT_DCT2000              89
#define WTAP_ENCAP_BER                           90
#define WTAP_ENCAP_JUNIPER_VP                    91
#define WTAP_ENCAP_USB_FREEBSD                   92
#define WTAP_ENCAP_IEEE802_16_MAC_CPS            93
#define WTAP_ENCAP_NETTL_RAW_TELNET              94
#define WTAP_ENCAP_USB_LINUX                     95
#define WTAP_ENCAP_MPEG                          96
#define WTAP_ENCAP_PPI                           97
#define WTAP_ENCAP_ERF                           98
#define WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR        99
#define WTAP_ENCAP_SITA                         100
#define WTAP_ENCAP_SCCP                         101
#define WTAP_ENCAP_BLUETOOTH_HCI                102 /*raw packets without a transport layer header e.g. H4*/
#define WTAP_ENCAP_IPMB                         103
#define WTAP_ENCAP_IEEE802_15_4                 104
#define WTAP_ENCAP_X2E_XORAYA                   105
#define WTAP_ENCAP_FLEXRAY                      106
#define WTAP_ENCAP_LIN                          107
#define WTAP_ENCAP_MOST                         108
#define WTAP_ENCAP_CAN20B                       109
#define WTAP_ENCAP_LAYER1_EVENT                 110
#define WTAP_ENCAP_X2E_SERIAL                   111
#define WTAP_ENCAP_I2C                          112
#define WTAP_ENCAP_IEEE802_15_4_NONASK_PHY      113
#define WTAP_ENCAP_TNEF                         114
#define WTAP_ENCAP_USB_LINUX_MMAPPED            115
#define WTAP_ENCAP_GSM_UM                       116
#define WTAP_ENCAP_DPNSS                        117
#define WTAP_ENCAP_PACKETLOGGER                 118
#define WTAP_ENCAP_NSTRACE_1_0                  119
#define WTAP_ENCAP_NSTRACE_2_0                  120
#define WTAP_ENCAP_FIBRE_CHANNEL_FC2            121
#define WTAP_ENCAP_FIBRE_CHANNEL_FC2_WITH_FRAME_DELIMS 122
#define WTAP_ENCAP_JPEG_JFIF                    123 /* obsoleted by WTAP_ENCAP_MIME*/
#define WTAP_ENCAP_IPNET                        124
#define WTAP_ENCAP_SOCKETCAN                    125
#define WTAP_ENCAP_IEEE_802_11_NETMON           126
#define WTAP_ENCAP_IEEE802_15_4_NOFCS           127
#define WTAP_ENCAP_RAW_IPFIX                    128
#define WTAP_ENCAP_RAW_IP4                      129
#define WTAP_ENCAP_RAW_IP6                      130
#define WTAP_ENCAP_LAPD                         131
#define WTAP_ENCAP_DVBCI                        132
#define WTAP_ENCAP_MUX27010                     133
#define WTAP_ENCAP_MIME                         134
#define WTAP_ENCAP_NETANALYZER                  135
#define WTAP_ENCAP_NETANALYZER_TRANSPARENT      136
#define WTAP_ENCAP_IP_OVER_IB_SNOOP             137
#define WTAP_ENCAP_MPEG_2_TS                    138
#define WTAP_ENCAP_PPP_ETHER                    139
#define WTAP_ENCAP_NFC_LLCP                     140
#define WTAP_ENCAP_NFLOG                        141
#define WTAP_ENCAP_V5_EF                        142
#define WTAP_ENCAP_BACNET_MS_TP_WITH_PHDR       143
#define WTAP_ENCAP_IXVERIWAVE                   144
#define WTAP_ENCAP_SDH                          145
#define WTAP_ENCAP_DBUS                         146
#define WTAP_ENCAP_AX25_KISS                    147
#define WTAP_ENCAP_AX25                         148
#define WTAP_ENCAP_SCTP                         149
#define WTAP_ENCAP_INFINIBAND                   150
#define WTAP_ENCAP_JUNIPER_SVCS                 151
#define WTAP_ENCAP_USBPCAP                      152
#define WTAP_ENCAP_RTAC_SERIAL                  153
#define WTAP_ENCAP_BLUETOOTH_LE_LL              154
#define WTAP_ENCAP_WIRESHARK_UPPER_PDU          155
#define WTAP_ENCAP_STANAG_4607                  156
#define WTAP_ENCAP_STANAG_5066_D_PDU            157
#define WTAP_ENCAP_NETLINK                      158
#define WTAP_ENCAP_BLUETOOTH_LINUX_MONITOR      159
#define WTAP_ENCAP_BLUETOOTH_BREDR_BB           160
#define WTAP_ENCAP_BLUETOOTH_LE_LL_WITH_PHDR    161
#define WTAP_ENCAP_NSTRACE_3_0                  162
#define WTAP_ENCAP_LOGCAT                       163
#define WTAP_ENCAP_LOGCAT_BRIEF                 164
#define WTAP_ENCAP_LOGCAT_PROCESS               165
#define WTAP_ENCAP_LOGCAT_TAG                   166
#define WTAP_ENCAP_LOGCAT_THREAD                167
#define WTAP_ENCAP_LOGCAT_TIME                  168
#define WTAP_ENCAP_LOGCAT_THREADTIME            169
#define WTAP_ENCAP_LOGCAT_LONG                  170
#define WTAP_ENCAP_PKTAP                        171
#define WTAP_ENCAP_EPON                         172
#define WTAP_ENCAP_IPMI_TRACE                   173
#define WTAP_ENCAP_LOOP                         174
#define WTAP_ENCAP_JSON                         175
#define WTAP_ENCAP_NSTRACE_3_5                  176
#define WTAP_ENCAP_ISO14443                     177
#define WTAP_ENCAP_GFP_T                        178
#define WTAP_ENCAP_GFP_F                        179
#define WTAP_ENCAP_IP_OVER_IB_PCAP              180
#define WTAP_ENCAP_JUNIPER_VN                   181
/* After adding new item here, please also add new item to encap_table_base array */

#define WTAP_NUM_ENCAP_TYPES                    wtap_get_num_encap_types()

/* File types/subtypes that can be read by wiretap.
   We support writing many of these file types, too, so we
   distinguish between different subtypes of them, as
   different subtypes need to be written in a different
   fashion. */
#define WTAP_FILE_TYPE_SUBTYPE_UNKNOWN                        0
#define WTAP_FILE_TYPE_SUBTYPE_PCAP                           1
#define WTAP_FILE_TYPE_SUBTYPE_PCAPNG                         2
#define WTAP_FILE_TYPE_SUBTYPE_PCAP_NSEC                      3
#define WTAP_FILE_TYPE_SUBTYPE_PCAP_AIX                       4
#define WTAP_FILE_TYPE_SUBTYPE_PCAP_SS991029                  5
#define WTAP_FILE_TYPE_SUBTYPE_PCAP_NOKIA                     6
#define WTAP_FILE_TYPE_SUBTYPE_PCAP_SS990417                  7
#define WTAP_FILE_TYPE_SUBTYPE_PCAP_SS990915                  8
#define WTAP_FILE_TYPE_SUBTYPE_5VIEWS                         9
#define WTAP_FILE_TYPE_SUBTYPE_IPTRACE_1_0                   10
#define WTAP_FILE_TYPE_SUBTYPE_IPTRACE_2_0                   11
#define WTAP_FILE_TYPE_SUBTYPE_BER                           12
#define WTAP_FILE_TYPE_SUBTYPE_HCIDUMP                       13
#define WTAP_FILE_TYPE_SUBTYPE_CATAPULT_DCT2000              14
#define WTAP_FILE_TYPE_SUBTYPE_NETXRAY_OLD                   15
#define WTAP_FILE_TYPE_SUBTYPE_NETXRAY_1_0                   16
#define WTAP_FILE_TYPE_SUBTYPE_COSINE                        17
#define WTAP_FILE_TYPE_SUBTYPE_CSIDS                         18
#define WTAP_FILE_TYPE_SUBTYPE_DBS_ETHERWATCH                19
#define WTAP_FILE_TYPE_SUBTYPE_ERF                           20
#define WTAP_FILE_TYPE_SUBTYPE_EYESDN                        21
#define WTAP_FILE_TYPE_SUBTYPE_NETTL                         22
#define WTAP_FILE_TYPE_SUBTYPE_ISERIES                       23
#define WTAP_FILE_TYPE_SUBTYPE_ISERIES_UNICODE               24
#define WTAP_FILE_TYPE_SUBTYPE_I4BTRACE                      25
#define WTAP_FILE_TYPE_SUBTYPE_ASCEND                        26
#define WTAP_FILE_TYPE_SUBTYPE_NETMON_1_x                    27
#define WTAP_FILE_TYPE_SUBTYPE_NETMON_2_x                    28
#define WTAP_FILE_TYPE_SUBTYPE_NGSNIFFER_UNCOMPRESSED        29
#define WTAP_FILE_TYPE_SUBTYPE_NGSNIFFER_COMPRESSED          30
#define WTAP_FILE_TYPE_SUBTYPE_NETXRAY_1_1                   31
#define WTAP_FILE_TYPE_SUBTYPE_NETXRAY_2_00x                 32
#define WTAP_FILE_TYPE_SUBTYPE_NETWORK_INSTRUMENTS           33
#define WTAP_FILE_TYPE_SUBTYPE_LANALYZER                     34
#define WTAP_FILE_TYPE_SUBTYPE_PPPDUMP                       35
#define WTAP_FILE_TYPE_SUBTYPE_RADCOM                        36
#define WTAP_FILE_TYPE_SUBTYPE_SNOOP                         37
#define WTAP_FILE_TYPE_SUBTYPE_SHOMITI                       38
#define WTAP_FILE_TYPE_SUBTYPE_VMS                           39
#define WTAP_FILE_TYPE_SUBTYPE_K12                           40
#define WTAP_FILE_TYPE_SUBTYPE_TOSHIBA                       41
#define WTAP_FILE_TYPE_SUBTYPE_VISUAL_NETWORKS               42
#define WTAP_FILE_TYPE_SUBTYPE_PEEKCLASSIC_V56               43
#define WTAP_FILE_TYPE_SUBTYPE_PEEKCLASSIC_V7                44
#define WTAP_FILE_TYPE_SUBTYPE_PEEKTAGGED                    45
#define WTAP_FILE_TYPE_SUBTYPE_MPEG                          46
#define WTAP_FILE_TYPE_SUBTYPE_K12TEXT                       47
#define WTAP_FILE_TYPE_SUBTYPE_NETSCREEN                     48
#define WTAP_FILE_TYPE_SUBTYPE_COMMVIEW                      49
#define WTAP_FILE_TYPE_SUBTYPE_BTSNOOP                       50
#define WTAP_FILE_TYPE_SUBTYPE_TNEF                          51
#define WTAP_FILE_TYPE_SUBTYPE_DCT3TRACE                     52
#define WTAP_FILE_TYPE_SUBTYPE_PACKETLOGGER                  53
#define WTAP_FILE_TYPE_SUBTYPE_DAINTREE_SNA                  54
#define WTAP_FILE_TYPE_SUBTYPE_NETSCALER_1_0                 55
#define WTAP_FILE_TYPE_SUBTYPE_NETSCALER_2_0                 56
#define WTAP_FILE_TYPE_SUBTYPE_JPEG_JFIF                     57 /* obsoleted by WTAP_FILE_TYPE_SUBTYPE_MIME */
#define WTAP_FILE_TYPE_SUBTYPE_IPFIX                         58
#define WTAP_FILE_TYPE_SUBTYPE_MIME                          59
#define WTAP_FILE_TYPE_SUBTYPE_AETHRA                        60
#define WTAP_FILE_TYPE_SUBTYPE_MPEG_2_TS                     61
#define WTAP_FILE_TYPE_SUBTYPE_VWR_80211                     62
#define WTAP_FILE_TYPE_SUBTYPE_VWR_ETH                       63
#define WTAP_FILE_TYPE_SUBTYPE_CAMINS                        64
#define WTAP_FILE_TYPE_SUBTYPE_STANAG_4607                   65
#define WTAP_FILE_TYPE_SUBTYPE_NETSCALER_3_0                 66
#define WTAP_FILE_TYPE_SUBTYPE_LOGCAT                        67
#define WTAP_FILE_TYPE_SUBTYPE_LOGCAT_BRIEF                  68
#define WTAP_FILE_TYPE_SUBTYPE_LOGCAT_PROCESS                69
#define WTAP_FILE_TYPE_SUBTYPE_LOGCAT_TAG                    70
#define WTAP_FILE_TYPE_SUBTYPE_LOGCAT_THREAD                 71
#define WTAP_FILE_TYPE_SUBTYPE_LOGCAT_TIME                   72
#define WTAP_FILE_TYPE_SUBTYPE_LOGCAT_THREADTIME             73
#define WTAP_FILE_TYPE_SUBTYPE_LOGCAT_LONG                   74
#define WTAP_FILE_TYPE_SUBTYPE_COLASOFT_CAPSA                75
#define WTAP_FILE_TYPE_SUBTYPE_COLASOFT_PACKET_BUILDER       76
#define WTAP_FILE_TYPE_SUBTYPE_JSON                          77
#define WTAP_FILE_TYPE_SUBTYPE_NETSCALER_3_5                 78
#define WTAP_FILE_TYPE_SUBTYPE_NETTRACE_3GPP_32_423          79
#define WTAP_FILE_TYPE_SUBTYPE_MPLOG                         80

#define WTAP_NUM_FILE_TYPES_SUBTYPES  wtap_get_num_file_types_subtypes()

/* timestamp precision (currently only these values are supported) */
#define WTAP_TSPREC_UNKNOWN    -2
#define WTAP_TSPREC_PER_PACKET -1  /* as a per-file value, means per-packet */
#define WTAP_TSPREC_SEC         0
#define WTAP_TSPREC_DSEC        1
#define WTAP_TSPREC_CSEC        2
#define WTAP_TSPREC_MSEC        3
#define WTAP_TSPREC_USEC        6
#define WTAP_TSPREC_NSEC        9
/* if you add to the above, update wtap_tsprec_string() */

/*
 * Maximum packet size we'll support.
 * 262144 is the largest snapshot length that libpcap supports, so we
 * use that.
 */
#define WTAP_MAX_PACKET_SIZE    262144

/*
 * "Pseudo-headers" are used to supply to the clients of wiretap
 * per-packet information that's not part of the packet payload
 * proper.
 *
 * NOTE: do not use pseudo-header structures to hold information
 * used by the code to read a particular capture file type; to
 * keep that sort of state information, add a new structure for
 * that private information to "wtap-int.h", add a pointer to that
 * type of structure to the "capture" member of the "struct wtap"
 * structure, and allocate one of those structures and set that member
 * in the "open" routine for that capture file type if the open
 * succeeds.  See various other capture file type handlers for examples
 * of that.
 */


/* Packet "pseudo-header" information for Ethernet capture files. */
struct eth_phdr {
    gint   fcs_len;  /* Number of bytes of FCS - -1 means "unknown" */
};

/* Packet "pseudo-header" information for X.25 capture files. */
#define FROM_DCE 0x80
struct x25_phdr {
    guint8  flags;   /* ENCAP_LAPB, ENCAP_V120 : 1st bit means From DCE */
};

/* Packet "pseudo-header" information for ISDN capture files. */

/* Direction */
struct isdn_phdr {
    gboolean uton;
    guint8   channel;   /* 0 = D-channel; n = B-channel n */
};

/* Packet "pseudo-header" for ATM capture files.
   Not all of this information is supplied by all capture types.
   These originally came from the Network General (DOS-based)
   ATM Sniffer file format, but we've added some additional
   items. */

/*
 * Status bits.
 */
#define ATM_RAW_CELL         0x01 /* TRUE if the packet is a single cell */
#define ATM_NO_HEC           0x02 /* TRUE if the cell has HEC stripped out */
#define ATM_AAL2_NOPHDR      0x04 /* TRUE if the AAL2 PDU has no pseudo-header */
#define ATM_REASSEMBLY_ERROR 0x08 /* TRUE if this is an incompletely-reassembled PDU */

/*
 * AAL types.
 */
#define AAL_UNKNOWN     0  /* AAL unknown */
#define AAL_1           1  /* AAL1 */
#define AAL_2           2  /* AAL2 */
#define AAL_3_4         3  /* AAL3/4 */
#define AAL_5           4  /* AAL5 */
#define AAL_USER        5  /* User AAL */
#define AAL_SIGNALLING  6  /* Signaling AAL */
#define AAL_OAMCELL     7  /* OAM cell */

/*
 * Traffic types.
 */
#define TRAF_UNKNOWN    0  /* Unknown */
#define TRAF_LLCMX      1  /* LLC multiplexed (RFC 1483) */
#define TRAF_VCMX       2  /* VC multiplexed (RFC 1483) */
#define TRAF_LANE       3  /* LAN Emulation */
#define TRAF_ILMI       4  /* ILMI */
#define TRAF_FR         5  /* Frame Relay */
#define TRAF_SPANS      6  /* FORE SPANS */
#define TRAF_IPSILON    7  /* Ipsilon */
#define TRAF_UMTS_FP    8  /* UMTS Frame Protocol */
#define TRAF_GPRS_NS    9  /* GPRS Network Services */
#define TRAF_SSCOP     10  /* SSCOP */

/*
 * Traffic subtypes.
 */
#define TRAF_ST_UNKNOWN     0   /* Unknown */

/*
 * For TRAF_VCMX:
 */
#define TRAF_ST_VCMX_802_3_FCS   1  /* 802.3 with an FCS */
#define TRAF_ST_VCMX_802_4_FCS   2  /* 802.4 with an FCS */
#define TRAF_ST_VCMX_802_5_FCS   3  /* 802.5 with an FCS */
#define TRAF_ST_VCMX_FDDI_FCS    4  /* FDDI with an FCS */
#define TRAF_ST_VCMX_802_6_FCS   5  /* 802.6 with an FCS */
#define TRAF_ST_VCMX_802_3       7  /* 802.3 without an FCS */
#define TRAF_ST_VCMX_802_4       8  /* 802.4 without an FCS */
#define TRAF_ST_VCMX_802_5       9  /* 802.5 without an FCS */
#define TRAF_ST_VCMX_FDDI       10  /* FDDI without an FCS */
#define TRAF_ST_VCMX_802_6      11  /* 802.6 without an FCS */
#define TRAF_ST_VCMX_FRAGMENTS  12  /* Fragments */
#define TRAF_ST_VCMX_BPDU       13  /* BPDU */

/*
 * For TRAF_LANE:
 */
#define TRAF_ST_LANE_LE_CTRL     1  /* LANE: LE Ctrl */
#define TRAF_ST_LANE_802_3       2  /* LANE: 802.3 */
#define TRAF_ST_LANE_802_5       3  /* LANE: 802.5 */
#define TRAF_ST_LANE_802_3_MC    4  /* LANE: 802.3 multicast */
#define TRAF_ST_LANE_802_5_MC    5  /* LANE: 802.5 multicast */

/*
 * For TRAF_IPSILON:
 */
#define TRAF_ST_IPSILON_FT0      1  /* Ipsilon: Flow Type 0 */
#define TRAF_ST_IPSILON_FT1      2  /* Ipsilon: Flow Type 1 */
#define TRAF_ST_IPSILON_FT2      3  /* Ipsilon: Flow Type 2 */

struct atm_phdr {
    guint32 flags;      /* status flags */
    guint8  aal;        /* AAL of the traffic */
    guint8  type;       /* traffic type */
    guint8  subtype;    /* traffic subtype */
    guint16 vpi;        /* virtual path identifier */
    guint16 vci;        /* virtual circuit identifier */
    guint8  aal2_cid;   /* channel id */
    guint16 channel;    /* link: 0 for DTE->DCE, 1 for DCE->DTE */
    guint16 cells;      /* number of cells */
    guint16 aal5t_u2u;  /* user-to-user indicator */
    guint16 aal5t_len;  /* length of the packet */
    guint32 aal5t_chksum;   /* checksum for AAL5 packet */
};

/* Packet "pseudo-header" for the output from "wandsession", "wannext",
   "wandisplay", and similar commands on Lucent/Ascend access equipment. */

#define ASCEND_MAX_STR_LEN 64

#define ASCEND_PFX_WDS_X    1
#define ASCEND_PFX_WDS_R    2
#define ASCEND_PFX_WDD      3
#define ASCEND_PFX_ISDN_X   4
#define ASCEND_PFX_ISDN_R   5
#define ASCEND_PFX_ETHER    6

struct ascend_phdr {
    guint16 type;                         /* ASCEND_PFX_*, as defined above */
    char    user[ASCEND_MAX_STR_LEN];     /* Username, from wandsession header */
    guint32 sess;                         /* Session number, from wandsession header */
    char    call_num[ASCEND_MAX_STR_LEN]; /* Called number, from WDD header */
    guint32 chunk;                        /* Chunk number, from WDD header */
    guint32 task;                         /* Task number */
};

/* Also defined in epan/packet_info.h */
#define P2P_DIR_UNKNOWN -1
#define P2P_DIR_SENT     0
#define P2P_DIR_RECV     1

/* Packet "pseudo-header" for point-to-point links with direction flags. */
struct p2p_phdr {
    int sent; /* TRUE=sent, FALSE=received, -1=unknown*/
};

/*
 * Packet "pseudo-header" information for 802.11.
 * Radio information is only present in this form for
 * WTAP_ENCAP_IEEE_802_11_WITH_RADIO.  This is used for file formats in
 * which the radio information isn't provided as a pseudo-header in the
 * packet data.  It is also used by the dissectors for the pseudo-headers
 * in the packet data to supply radio information, in a form independent
 * of the file format and pseudo-header format, to the "802.11 radio"
 * dissector.
 *
 * Signal strength, etc. information:
 *
 * Raw signal strength can be measured in milliwatts.
 * It can also be represented as dBm, which is 10 times the log base 10
 * of the signal strength in mW.
 *
 * The Receive Signal Strength Indicator is an integer in the range 0 to 255.
 * The actual RSSI value for a given signal strength is dependent on the
 * vendor (and perhaps on the adapter).  The maximum possible RSSI value
 * is also dependent on the vendor and perhaps the adapter.
 *
 * The signal strength can be represented as a percentage, which is 100
 * times the ratio of the RSSI and the maximum RSSI.
 */

/*
 * PHY types.
 */
#define PHDR_802_11_PHY_UNKNOWN        0 /* PHY not known */
#define PHDR_802_11_PHY_11_FHSS        1 /* 802.11 FHSS */
#define PHDR_802_11_PHY_11_IR          2 /* 802.11 IR */
#define PHDR_802_11_PHY_11_DSSS        3 /* 802.11 DSSS */
#define PHDR_802_11_PHY_11B            4 /* 802.11b */
#define PHDR_802_11_PHY_11A            5 /* 802.11a */
#define PHDR_802_11_PHY_11G            6 /* 802.11g */
#define PHDR_802_11_PHY_11N            7 /* 802.11n */
#define PHDR_802_11_PHY_11AC           8 /* 802.11ac */
#define PHDR_802_11_PHY_11AD           9 /* 802.11ad */

/*
 * PHY-specific information.
 */

/*
 * 802.11 legacy FHSS.
 */
struct ieee_802_11_fhss {
    guint    has_hop_set:1;
    guint    has_hop_pattern:1;
    guint    has_hop_index:1;

    guint8   hop_set;        /* Hop set */
    guint8   hop_pattern;    /* Hop pattern */
    guint8   hop_index;      /* Hop index */
};

/*
 * 802.11b.
 */
struct ieee_802_11b {
    /* Which of this information is present? */
    guint    has_short_preamble:1;

    gboolean short_preamble; /* Short preamble */
};

/*
 * 802.11a.
 */
struct ieee_802_11a {
    /* Which of this information is present? */
    guint    has_channel_type:1;
    guint    has_turbo_type:1;

    guint    channel_type:2;
    guint    turbo_type:2;
};

/*
 * Channel type values.
 */
#define PHDR_802_11A_CHANNEL_TYPE_NORMAL           0
#define PHDR_802_11A_CHANNEL_TYPE_HALF_CLOCKED     1
#define PHDR_802_11A_CHANNEL_TYPE_QUARTER_CLOCKED  2

/*
 * "Turbo" is an Atheros proprietary extension with 40 MHz-wide channels.
 * It can be dynamic or static.
 *
 * See
 *
 *    http://wifi-insider.com/atheros/turbo.htm
 */
#define PHDR_802_11A_TURBO_TYPE_NORMAL           0
#define PHDR_802_11A_TURBO_TYPE_TURBO            1  /* If we don't know wehther it's static or dynamic */
#define PHDR_802_11A_TURBO_TYPE_DYNAMIC_TURBO    2
#define PHDR_802_11A_TURBO_TYPE_STATIC_TURBO     3

/*
 * 802.11g.
 */
struct ieee_802_11g {
    /* Which of this information is present? */
    guint    has_short_preamble:1;
    guint    has_mode:1;

    gboolean short_preamble; /* Short preamble */
    guint32  mode;           /* Various proprietary extensions */
};

/*
 * Mode values.
 */
#define PHDR_802_11G_MODE_NORMAL    0
#define PHDR_802_11G_MODE_SUPER_G   1  /* Atheros Super G */

/*
 * 802.11n.
 */
struct ieee_802_11n {
    /* Which of this information is present? */
    guint    has_mcs_index:1;
    guint    has_bandwidth:1;
    guint    has_short_gi:1;
    guint    has_greenfield:1;
    guint    has_fec:1;
    guint    has_stbc_streams:1;
    guint    has_ness:1;

    guint16  mcs_index;      /* MCS index */
    guint    bandwidth;      /* Bandwidth = 20 MHz, 40 MHz, etc. */
    guint    short_gi:1;     /* True for short guard interval */
    guint    greenfield:1;   /* True for greenfield, short for mixed */
    guint    fec:1;          /* FEC: 0 = BCC, 1 = LDPC */
    guint    stbc_streams:2; /* Number of STBC streams */
    guint    ness;           /* Number of extension spatial streams */
};

/*
 * Bandwidth values; used for both 11n and 11ac.
 */
#define PHDR_802_11_BANDWIDTH_20_MHZ   0  /* 20 MHz */
#define PHDR_802_11_BANDWIDTH_40_MHZ   1  /* 40 MHz */
#define PHDR_802_11_BANDWIDTH_20_20L   2  /* 20 + 20L, 40 MHz */
#define PHDR_802_11_BANDWIDTH_20_20U   3  /* 20 + 20U, 40 MHz */
#define PHDR_802_11_BANDWIDTH_80_MHZ   4  /* 80 MHz */
#define PHDR_802_11_BANDWIDTH_40_40L   5  /* 40 + 40L MHz, 80 MHz */
#define PHDR_802_11_BANDWIDTH_40_40U   6  /* 40 + 40U MHz, 80 MHz */
#define PHDR_802_11_BANDWIDTH_20LL     7  /* ???, 80 MHz */
#define PHDR_802_11_BANDWIDTH_20LU     8  /* ???, 80 MHz */
#define PHDR_802_11_BANDWIDTH_20UL     9  /* ???, 80 MHz */
#define PHDR_802_11_BANDWIDTH_20UU     10 /* ???, 80 MHz */
#define PHDR_802_11_BANDWIDTH_160_MHZ  11 /* 160 MHz */
#define PHDR_802_11_BANDWIDTH_80_80L   12 /* 80 + 80L, 160 MHz */
#define PHDR_802_11_BANDWIDTH_80_80U   13 /* 80 + 80U, 160 MHz */
#define PHDR_802_11_BANDWIDTH_40LL     14 /* ???, 160 MHz */
#define PHDR_802_11_BANDWIDTH_40LU     15 /* ???, 160 MHz */
#define PHDR_802_11_BANDWIDTH_40UL     16 /* ???, 160 MHz */
#define PHDR_802_11_BANDWIDTH_40UU     17 /* ???, 160 MHz */
#define PHDR_802_11_BANDWIDTH_20LLL    18 /* ???, 160 MHz */
#define PHDR_802_11_BANDWIDTH_20LLU    19 /* ???, 160 MHz */
#define PHDR_802_11_BANDWIDTH_20LUL    20 /* ???, 160 MHz */
#define PHDR_802_11_BANDWIDTH_20LUU    21 /* ???, 160 MHz */
#define PHDR_802_11_BANDWIDTH_20ULL    22 /* ???, 160 MHz */
#define PHDR_802_11_BANDWIDTH_20ULU    23 /* ???, 160 MHz */
#define PHDR_802_11_BANDWIDTH_20UUL    24 /* ???, 160 MHz */
#define PHDR_802_11_BANDWIDTH_20UUU    25 /* ???, 160 MHz */

/*
 * 802.11ac.
 */
struct ieee_802_11ac {
    /* Which of this information is present? */
    guint    has_stbc:1;
    guint    has_txop_ps_not_allowed:1;
    guint    has_short_gi:1;
    guint    has_short_gi_nsym_disambig:1;
    guint    has_ldpc_extra_ofdm_symbol:1;
    guint    has_beamformed:1;
    guint    has_bandwidth:1;
    guint    has_fec:1;
    guint    has_group_id:1;
    guint    has_partial_aid:1;

    guint    stbc:1;         /* 1 if all spatial streams have STBC */
    guint    txop_ps_not_allowed:1;
    guint    short_gi:1;     /* True for short guard interval */
    guint    short_gi_nsym_disambig:1;
    guint    ldpc_extra_ofdm_symbol:1;
    guint    beamformed:1;
    guint8   bandwidth;      /* Bandwidth = 20 MHz, 40 MHz, etc. */
    guint8   mcs[4];         /* MCS index per user */
    guint8   nss[4];         /* NSS per user */
    guint8   fec;            /* Bit array of FEC per user: 0 = BCC, 1 = LDPC */
    guint8   group_id;
    guint16  partial_aid;
};

/*
 * 802.11ad.
 */

/*
 * Min and Max frequencies for 802.11ad and a macro for checking for 802.11ad.
 */

#define PHDR_802_11AD_MIN_FREQUENCY    57000
#define PHDR_802_11AD_MAX_FREQUENCY    66000

#define IS_80211AD(frequency) (((frequency) >= PHDR_802_11AD_MIN_FREQUENCY) &&\
                               ((frequency) <= PHDR_802_11AD_MAX_FREQUENCY))

struct ieee_802_11ad {
    /* Which of this information is present? */
    guint    has_mcs_index:1;

    guint8   mcs;            /* MCS index */
};

struct ieee_802_11_phdr {
    gint     fcs_len;        /* Number of bytes of FCS - -1 means "unknown" */
    gboolean decrypted;      /* TRUE if frame is decrypted even if "protected" bit is set */
    gboolean datapad;        /* TRUE if frame has padding between 802.11 header and payload */
    guint    phy;            /* PHY type */
    union {
        struct ieee_802_11_fhss info_11_fhss;
        struct ieee_802_11b info_11b;
        struct ieee_802_11a info_11a;
        struct ieee_802_11g info_11g;
        struct ieee_802_11n info_11n;
        struct ieee_802_11ac info_11ac;
        struct ieee_802_11ad info_11ad;
    } phy_info;

    /* Which of this information is present? */
    guint    has_channel:1;
    guint    has_frequency:1;
    guint    has_data_rate:1;
    guint    has_signal_percent:1;
    guint    has_noise_percent:1;
    guint    has_signal_dbm:1;
    guint    has_noise_dbm:1;
    guint    has_tsf_timestamp:1;
    guint    has_aggregate_info:1;    /* aggregate flags and ID */

    guint16  channel;        /* Channel number */
    guint32  frequency;      /* Channel center frequency */
    guint16  data_rate;      /* Data rate, in .5 Mb/s units */
    guint8   signal_percent; /* Signal level, as a percentage */
    guint8   noise_percent;  /* Noise level, as a percentage */
    gint8    signal_dbm;     /* Signal level, in dBm */
    gint8    noise_dbm;      /* Noise level, in dBm */
    guint64  tsf_timestamp;
    guint32  aggregate_flags; /* A-MPDU flags */
    guint32  aggregate_id;    /* ID for A-MPDU reassembly */
};

/*
 * A-MPDU flags.
 */
#define PHDR_802_11_LAST_PART_OF_A_MPDU    0x00000001 /* this is the last part of an A-MPDU */
#define PHDR_802_11_A_MPDU_DELIM_CRC_ERROR 0x00000002 /* delimiter CRC error after this part */

/* Packet "pseudo-header" for the output from CoSine L2 debug output. */

#define COSINE_MAX_IF_NAME_LEN  128

#define COSINE_ENCAP_TEST      1
#define COSINE_ENCAP_PPoATM    2
#define COSINE_ENCAP_PPoFR     3
#define COSINE_ENCAP_ATM       4
#define COSINE_ENCAP_FR        5
#define COSINE_ENCAP_HDLC      6
#define COSINE_ENCAP_PPP       7
#define COSINE_ENCAP_ETH       8
#define COSINE_ENCAP_UNKNOWN  99

#define COSINE_DIR_TX 1
#define COSINE_DIR_RX 2

struct cosine_phdr {
    guint8  encap;      /* COSINE_ENCAP_* as defined above */
    guint8  direction;  /* COSINE_DIR_*, as defined above */
    char    if_name[COSINE_MAX_IF_NAME_LEN];  /* Encap & Logical I/F name */
    guint16 pro;        /* Protocol */
    guint16 off;        /* Offset */
    guint16 pri;        /* Priority */
    guint16 rm;         /* Rate Marking */
    guint16 err;        /* Error Code */
};

/* Packet "pseudo-header" for IrDA capture files. */

/*
 * Direction of the packet
 */
#define IRDA_INCOMING       0x0000
#define IRDA_OUTGOING       0x0004

/*
 * "Inline" log messages produced by IrCOMM2k on Windows
 */
#define IRDA_LOG_MESSAGE    0x0100  /* log message */
#define IRDA_MISSED_MSG     0x0101  /* missed log entry or frame */

/*
 * Differentiate between frames and log messages
 */
#define IRDA_CLASS_FRAME    0x0000
#define IRDA_CLASS_LOG      0x0100
#define IRDA_CLASS_MASK     0xFF00

struct irda_phdr {
    guint16 pkttype;    /* packet type */
};

/* Packet "pseudo-header" for nettl (HP-UX) capture files. */

struct nettl_phdr {
    guint16 subsys;
    guint32 devid;
    guint32 kind;
    gint32  pid;
    guint16 uid;
};

/* Packet "pseudo-header" for MTP2 files. */

#define MTP2_ANNEX_A_NOT_USED      0
#define MTP2_ANNEX_A_USED          1
#define MTP2_ANNEX_A_USED_UNKNOWN  2

struct mtp2_phdr {
    guint8  sent;
    guint8  annex_a_used;
    guint16 link_number;
};

/* Packet "pseudo-header" for K12 files. */

typedef union {
    struct {
        guint16 vp;
        guint16 vc;
        guint16 cid;
    } atm;

    guint32 ds0mask;
} k12_input_info_t;

struct k12_phdr {
    guint32           input;
    const gchar      *input_name;
    const gchar      *stack_file;
    guint32           input_type;
    k12_input_info_t  input_info;
    guint8           *extra_info;
    guint32           extra_length;
    void*             stuff;
};

#define K12_PORT_DS0S      0x00010008
#define K12_PORT_DS1       0x00100008
#define K12_PORT_ATMPVC    0x01020000

struct lapd_phdr {
    guint16 pkttype;    /* packet type */
    guint8 we_network;
};

struct wtap;
struct catapult_dct2000_phdr
{
    union
    {
        struct isdn_phdr isdn;
        struct atm_phdr  atm;
        struct p2p_phdr  p2p;
    } inner_pseudo_header;
    gint64       seek_off;
    struct wtap *wth;
};

/*
 * Endace Record Format pseudo header
 */
struct erf_phdr {
    guint64 ts;     /* Time stamp */
    guint8  type;
    guint8  flags;
    guint16 rlen;
    guint16 lctr;
    guint16 wlen;
};

struct erf_ehdr {
  guint64 ehdr;
};

/*
 * ERF pseudo header with optional subheader
 * (Multichannel or Ethernet)
 */

#define MAX_ERF_EHDR 8

struct wtap_erf_eth_hdr {
    guint8 offset;
    guint8 pad;
};

struct erf_mc_phdr {
    struct erf_phdr phdr;
    struct erf_ehdr ehdr_list[MAX_ERF_EHDR];
    union
    {
        struct wtap_erf_eth_hdr eth_hdr;
        guint32 mc_hdr;
        guint32 aal2_hdr;
    } subhdr;
};

#define SITA_FRAME_DIR_TXED            (0x00)  /* values of sita_phdr.flags */
#define SITA_FRAME_DIR_RXED            (0x01)
#define SITA_FRAME_DIR                 (0x01)  /* mask */
#define SITA_ERROR_NO_BUFFER           (0x80)

#define SITA_SIG_DSR                   (0x01)  /* values of sita_phdr.signals */
#define SITA_SIG_DTR                   (0x02)
#define SITA_SIG_CTS                   (0x04)
#define SITA_SIG_RTS                   (0x08)
#define SITA_SIG_DCD                   (0x10)
#define SITA_SIG_UNDEF1                (0x20)
#define SITA_SIG_UNDEF2                (0x40)
#define SITA_SIG_UNDEF3                (0x80)

#define SITA_ERROR_TX_UNDERRUN         (0x01)  /* values of sita_phdr.errors2 (if SITA_FRAME_DIR_TXED) */
#define SITA_ERROR_TX_CTS_LOST         (0x02)
#define SITA_ERROR_TX_UART_ERROR       (0x04)
#define SITA_ERROR_TX_RETX_LIMIT       (0x08)
#define SITA_ERROR_TX_UNDEF1           (0x10)
#define SITA_ERROR_TX_UNDEF2           (0x20)
#define SITA_ERROR_TX_UNDEF3           (0x40)
#define SITA_ERROR_TX_UNDEF4           (0x80)

#define SITA_ERROR_RX_FRAMING          (0x01)  /* values of sita_phdr.errors1 (if SITA_FRAME_DIR_RXED) */
#define SITA_ERROR_RX_PARITY           (0x02)
#define SITA_ERROR_RX_COLLISION        (0x04)
#define SITA_ERROR_RX_FRAME_LONG       (0x08)
#define SITA_ERROR_RX_FRAME_SHORT      (0x10)
#define SITA_ERROR_RX_UNDEF1           (0x20)
#define SITA_ERROR_RX_UNDEF2           (0x40)
#define SITA_ERROR_RX_UNDEF3           (0x80)

#define SITA_ERROR_RX_NONOCTET_ALIGNED (0x01)  /* values of sita_phdr.errors2 (if SITA_FRAME_DIR_RXED) */
#define SITA_ERROR_RX_ABORT            (0x02)
#define SITA_ERROR_RX_CD_LOST          (0x04)
#define SITA_ERROR_RX_DPLL             (0x08)
#define SITA_ERROR_RX_OVERRUN          (0x10)
#define SITA_ERROR_RX_FRAME_LEN_VIOL   (0x20)
#define SITA_ERROR_RX_CRC              (0x40)
#define SITA_ERROR_RX_BREAK            (0x80)

#define SITA_PROTO_UNUSED              (0x00)  /* values of sita_phdr.proto */
#define SITA_PROTO_BOP_LAPB            (0x01)
#define SITA_PROTO_ETHERNET            (0x02)
#define SITA_PROTO_ASYNC_INTIO         (0x03)
#define SITA_PROTO_ASYNC_BLKIO         (0x04)
#define SITA_PROTO_ALC                 (0x05)
#define SITA_PROTO_UTS                 (0x06)
#define SITA_PROTO_PPP_HDLC            (0x07)
#define SITA_PROTO_SDLC                (0x08)
#define SITA_PROTO_TOKENRING           (0x09)
#define SITA_PROTO_I2C                 (0x10)
#define SITA_PROTO_DPM_LINK            (0x11)
#define SITA_PROTO_BOP_FRL             (0x12)

struct sita_phdr {
    guint8  sita_flags;
    guint8  sita_signals;
    guint8  sita_errors1;
    guint8  sita_errors2;
    guint8  sita_proto;
};

/*pseudo header for Bluetooth HCI*/
struct bthci_phdr {
    gboolean  sent;
    guint32   channel;
};

#define BTHCI_CHANNEL_COMMAND  1
#define BTHCI_CHANNEL_ACL      2
#define BTHCI_CHANNEL_SCO      3
#define BTHCI_CHANNEL_EVENT    4

/* pseudo header for WTAP_ENCAP_BLUETOOTH_LINUX_MONITOR */
struct btmon_phdr {
    guint16   adapter_id;
    guint16   opcode;
};

/* pseudo header for WTAP_ENCAP_LAYER1_EVENT */
struct l1event_phdr {
    gboolean uton;
};

/* * I2C pseudo header */
struct i2c_phdr {
    guint8  is_event;
    guint8  bus;
    guint32 flags;
};

/* pseudo header for WTAP_ENCAP_GSM_UM */
struct gsm_um_phdr {
    gboolean uplink;
    guint8   channel;
    /* The following are only populated for downlink */
    guint8   bsic;
    guint16  arfcn;
    guint32  tdma_frame;
    guint8   error;
    guint16  timeshift;
};

#define GSM_UM_CHANNEL_UNKNOWN  0
#define GSM_UM_CHANNEL_BCCH     1
#define GSM_UM_CHANNEL_SDCCH    2
#define GSM_UM_CHANNEL_SACCH    3
#define GSM_UM_CHANNEL_FACCH    4
#define GSM_UM_CHANNEL_CCCH     5
#define GSM_UM_CHANNEL_RACH     6
#define GSM_UM_CHANNEL_AGCH     7
#define GSM_UM_CHANNEL_PCH      8

/* Pseudo-header for nstrace packets */
struct nstr_phdr {
    gint64 rec_offset;
    gint32 rec_len;
    guint8 nicno_offset;
    guint8 nicno_len;
    guint8 dir_offset;
    guint8 dir_len;
    guint8 eth_offset;
    guint8 pcb_offset;
    guint8 l_pcb_offset;
    guint8 rec_type;
    guint8 vlantag_offset;
    guint8 coreid_offset;
    guint8 srcnodeid_offset;
    guint8 destnodeid_offset;
    guint8 clflags_offset;
    guint8 src_vmname_len_offset;
    guint8 dst_vmname_len_offset;
    guint8 ns_activity_offset;
    guint8 data_offset;
};

/* Packet "pseudo-header" for Nokia output */
struct nokia_phdr {
    struct eth_phdr eth;
    guint8 stuff[4];    /* mysterious stuff */
};

#define LLCP_PHDR_FLAG_SENT 0
struct llcp_phdr {
    guint8 adapter;
    guint8 flags;
};

/* pseudo header for WTAP_ENCAP_LOGCAT */
struct logcat_phdr {
    gint version;
};

/* Packet "pseudo-header" information for Sysdig events. */

struct sysdig_event_phdr {
    guint record_type;    /* XXX match ft_specific_record_phdr so that we chain off of packet-pcapng_block for now. */
    int byte_order;
    guint16 cpu_id;
    /* guint32 sentinel; */
    guint64 timestamp; /* ns since epoch */
    guint64 thread_id;
    guint32 event_len; /* XXX dup of wtap_pkthdr.len */
    guint16 event_type;
    /* ... Event ... */
};

/* Pseudo-header for file-type-specific records */
struct ft_specific_record_phdr {
    guint record_type;    /* the type of record this is */
};

union wtap_pseudo_header {
    struct eth_phdr     eth;
    struct x25_phdr     x25;
    struct isdn_phdr    isdn;
    struct atm_phdr     atm;
    struct ascend_phdr  ascend;
    struct p2p_phdr     p2p;
    struct ieee_802_11_phdr ieee_802_11;
    struct cosine_phdr  cosine;
    struct irda_phdr    irda;
    struct nettl_phdr   nettl;
    struct mtp2_phdr    mtp2;
    struct k12_phdr     k12;
    struct lapd_phdr    lapd;
    struct catapult_dct2000_phdr dct2000;
    struct erf_mc_phdr  erf;
    struct sita_phdr    sita;
    struct bthci_phdr   bthci;
    struct btmon_phdr   btmon;
    struct l1event_phdr l1event;
    struct i2c_phdr     i2c;
    struct gsm_um_phdr  gsm_um;
    struct nstr_phdr    nstr;
    struct nokia_phdr   nokia;
    struct llcp_phdr    llcp;
    struct logcat_phdr  logcat;
    struct sysdig_event_phdr sysdig_event;
    struct ft_specific_record_phdr ftsrec;
};

/*
 * Record type values.
 *
 * This list will expand over time, so don't assume everything will
 * forever be one of the types listed below.
 *
 * For file-type-specific records, the "ftsrec" field of the pseudo-header
 * contains a file-type-specific subtype value, such as a block type for
 * a pcap-ng file.
 *
 * An "event" is an indication that something happened during the capture
 * process, such as a status transition of some sort on the network.
 * These should, ideally, have a time stamp and, if they're relevant to
 * a particular interface on a multi-interface capture, should also have
 * an interface ID.  The data for the event is file-type-specific and
 * subtype-specific.  These should be dissected and displayed just as
 * packets are.
 *
 * A "report" supplies information not corresponding to an event;
 * for example, a pcap-ng Interface Statistics Block would be a report,
 * as it doesn't correspond to something happening on the network.
 * They may have a time stamp, and should be dissected and displayed
 * just as packets are.
 *
 * We distingiush between "events" and "reports" so that, for example,
 * the packet display can show the delta between a packet and an event
 * but not show the delta between a packet and a report, as the time
 * stamp of a report may not correspond to anything interesting on
 * the network but the time stamp of an event would.
 *
 * XXX - are there any file-type-specific records that *shouldn't* be
 * dissected and displayed?  If so, they should be parsed and the
 * information in them stored somewhere, and used somewhere, whether
 * it's just used when saving the file in its native format or also
 * used to parse *other* file-type-specific records.
 */
#define REC_TYPE_PACKET               0    /**< packet */
#define REC_TYPE_FT_SPECIFIC_EVENT    1    /**< file-type-specific event */
#define REC_TYPE_FT_SPECIFIC_REPORT   2    /**< file-type-specific report */
#define REC_TYPE_SYSCALL              3    /**< system call */

struct wtap_pkthdr {
    guint     rec_type;         /* what type of record is this? */
    guint32   presence_flags;   /* what stuff do we have? */
    nstime_t  ts;               /* time stamp */
    guint32   caplen;           /* data length in the file */
    guint32   len;              /* data length on the wire */
    int       pkt_encap;        /* WTAP_ENCAP_ value for this packet */
    int       pkt_tsprec;       /* WTAP_TSPREC_ value for this packet */
                                /* pcapng variables */
    guint32   interface_id;     /* identifier of the interface. */
                                /* options */
    gchar     *opt_comment;     /* NULL if not available */
    guint64   drop_count;       /* number of packets lost (by the interface and the
                                   operating system) between this packet and the preceding one. */
    guint32   pack_flags;       /* XXX - 0 for now (any value for "we don't have it"?) */
    Buffer    ft_specific_data; /* file-type specific data */

    union wtap_pseudo_header  pseudo_header;
};

/*
 * Bits in presence_flags, indicating which of the fields we have.
 *
 * For the time stamp, we may need some more flags to indicate
 * whether the time stamp is an absolute date-and-time stamp, an
 * absolute time-only stamp (which can make relative time
 * calculations tricky, as you could in theory have two time
 * stamps separated by an unknown number of days), or a time stamp
 * relative to some unspecified time in the past (see mpeg.c).
 *
 * There is no presence flag for len - there has to be *some* length
 * value for the packet.  (The "captured length" can be missing if
 * the file format doesn't report a captured length distinct from
 * the on-the-network length because the application(s) producing those
 * files don't support slicing packets.)
 *
 * There could be a presence flag for the packet encapsulation - if it's
 * absent, use the file encapsulation - but it's not clear that's useful;
 * we currently do that in the module for the file format.
 */
#define WTAP_HAS_TS            0x00000001  /**< time stamp */
#define WTAP_HAS_CAP_LEN       0x00000002  /**< captured length separate from on-the-network length */
#define WTAP_HAS_INTERFACE_ID  0x00000004  /**< interface ID */
#define WTAP_HAS_COMMENTS      0x00000008  /**< comments */
#define WTAP_HAS_DROP_COUNT    0x00000010  /**< drop count */
#define WTAP_HAS_PACK_FLAGS    0x00000020  /**< packet flags */

/**
 * Holds the required data from pcapng:s Section Header block(SHB).
 */
typedef struct wtapng_section_mandatory_s {
    guint64             section_length; /**< 64-bit value specifying the length in bytes of the
                                         *     following section.
                                         *     Section Length equal -1 (0xFFFFFFFFFFFFFFFF) means
                                         *     that the size of the section is not specified
                                         *   Note: if writing to a new file, this length will
                                         *     be invalid if anything changes, such as the other
                                         *     members of this struct, or the packets written.
                                         */
} wtapng_mandatory_section_t;

/** struct holding the information to build IDB:s
 *  the interface_data array holds an array of wtap_block_t
 *  represending IDB of one per interface.
 */
typedef struct wtapng_iface_descriptions_s {
    GArray *interface_data;
} wtapng_iface_descriptions_t;

/**
 * Interface description data
 */
typedef struct wtapng_if_descr_mandatory_s {
    int                    wtap_encap;            /**< link_type translated to wtap_encap */
    guint64                time_units_per_second;
    int                    tsprecision;           /**< WTAP_TSPREC_ value for this interface */

    guint16                link_type;
    guint32                snap_len;

    guint8                 num_stat_entries;
    GArray                *interface_statistics;  /**< An array holding the interface statistics from
                                                   *     pcapng ISB:s or equivalent(?)*/
} wtapng_if_descr_mandatory_t;

/* Interface description data - Option 11 structure */
typedef struct wtapng_if_descr_filter_s {
    gchar                 *if_filter_str;         /**< NULL if not available
                                                   *  libpcap string.
                                                   */
    guint16                bpf_filter_len;        /** variant II BPF filter len 0 if not used*/
    guint8                *if_filter_bpf_bytes;   /** BPF filter or NULL */
} wtapng_if_descr_filter_t;

/**
 * Holds the required data for pcap-ng Interface Statistics Block (ISB).
 */
typedef struct wtapng_if_stats_mandatory_s {
    guint32  interface_id;
    guint32  ts_high;
    guint32  ts_low;
} wtapng_if_stats_mandatory_t;

#ifndef MAXNAMELEN
#define MAXNAMELEN  	64	/* max name length (hostname and port name) */
#endif

typedef struct hashipv4 {
    guint             addr;
    guint8            flags;          /* B0 dummy_entry, B1 resolve, B2 If the address is used in the trace */
    gchar             ip[16];
    gchar             name[MAXNAMELEN];
} hashipv4_t;

typedef struct hashipv6 {
    guint8            addr[16];
    guint8            flags;          /* B0 dummy_entry, B1 resolve, B2 If the address is used in the trace */
    gchar             ip6[46];
    gchar             name[MAXNAMELEN];
} hashipv6_t;

/** A struct with lists of resolved addresses.
 *  Used when writing name resoultion blocks (NRB)
 */
typedef struct addrinfo_lists {
    GList      *ipv4_addr_list; /**< A list of resolved hashipv4_t*/
    GList      *ipv6_addr_list; /**< A list of resolved hashipv6_t*/
} addrinfo_lists_t;

struct wtap_dumper;

typedef struct wtap wtap;
typedef struct wtap_dumper wtap_dumper;

typedef struct wtap_reader *FILE_T;

/* Similar to the wtap_open_routine_info for open routines, the following
 * wtap_wslua_file_info struct is used by wslua code for Lua-based file writers.
 *
 * This concept is necessary because when wslua goes to invoke the
 * registered dump/write_open routine callback in Lua, it needs the ref number representing
 * the hooked function inside Lua.  This will be stored in the thing pointed to
 * by the void* data here.  This 'data' pointer will be copied into the
 * wtap_dumper struct's 'void* data' member when calling the dump_open function,
 * which is how wslua finally retrieves it.  Unlike wtap_dumper's 'priv' member, its
 * 'data' member is not free'd in wtap_dump_close().
 */
typedef struct wtap_wslua_file_info {
    int (*wslua_can_write_encap)(int, void*);   /* a can_write_encap func for wslua uses */
    void* wslua_data;                           /* holds the wslua data */
} wtap_wslua_file_info_t;

/*
 * For registering extensions used for capture file formats.
 *
 * These items are used in dialogs for opening files, so that
 * the user can ask to see all capture files (as identified
 * by file extension) or particular types of capture files.
 *
 * Each file type has a description and a list of extensions the file
 * might have.  Some file types aren't real file types, they're
 * just generic types, such as "text file" or "XML file", that can
 * be used for, among other things, captures we can read, or for
 * extensions such as ".cap" that were unimaginatively chosen by
 * several different sniffers for their file formats.
 */
struct file_extension_info {
    /* the file type name */
    const char *name;

    /* a semicolon-separated list of file extensions used for this type */
    const char *extensions;
};

/*
 * For registering file types that we can open.
 *
 * Each file type has an open routine and an optional list of extensions
 * the file might have.
 *
 * The open routine should return:
 *
 *      WTAP_OPEN_ERROR on an I/O error;
 *
 *      WTAP_OPEN_MINE if the file it's reading is one of the types
 *      it handles;
 *
 *      WTAP_OPEN_NOT_MINE if the file it's reading isn't one of the
 *      types it handles.
 *
 * If the routine handles this type of file, it should set the "file_type"
 * field in the "struct wtap" to the type of the file.
 *
 * Note that the routine does not have to free the private data pointer on
 * error. The caller takes care of that by calling wtap_close on error.
 * (See https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8518)
 *
 * However, the caller does have to free the private data pointer when
 * returning WTAP_OPEN_NOT_MINE, since the next file type will be called
 * and will likely just overwrite the pointer.
 */
typedef enum {
    WTAP_OPEN_NOT_MINE = 0,
    WTAP_OPEN_MINE = 1,
    WTAP_OPEN_ERROR = -1
} wtap_open_return_val;

typedef wtap_open_return_val (*wtap_open_routine_t)(struct wtap*, int *,
    char **);

/*
 * Some file formats have defined magic numbers at fixed offsets from
 * the beginning of the file; those routines should return 1 if and
 * only if the file has the magic number at that offset.  (pcap-ng
 * is a bit of a special case, as it has both the Section Header Block
 * type field and its byte-order magic field; it checks for both.)
 * Those file formats do not require a file name extension in order
 * to recognize them or to avoid recognizing other file types as that
 * type, and have no extensions specified for them.
 *
 * Other file formats don't have defined magic numbers at fixed offsets,
 * so a heuristic is required.  If that file format has any file name
 * extensions used for it, a list of those extensions should be
 * specified, so that, if the name of the file being opened has an
 * extension, the file formats that use that extension are tried before
 * the ones that don't, to handle the case where a file of one type
 * might be recognized by the heuristics for a different file type.
 */

typedef enum {
    OPEN_INFO_MAGIC = 0,
    OPEN_INFO_HEURISTIC = 1
} wtap_open_type;

WS_DLL_PUBLIC void init_open_routines(void);

struct open_info {
    const char *name;
    wtap_open_type type;
    wtap_open_routine_t open_routine;
    const char *extensions;
    gchar **extensions_set; /* populated using extensions member during initialization */
    void* wslua_data; /* should be NULL for C-code file readers */
};
WS_DLL_PUBLIC struct open_info *open_routines;

/*
 * Types of comments.
 */
#define WTAP_COMMENT_PER_SECTION        0x00000001      /* per-file/per-file-section */
#define WTAP_COMMENT_PER_INTERFACE      0x00000002      /* per-interface */
#define WTAP_COMMENT_PER_PACKET         0x00000004      /* per-packet */

struct file_type_subtype_info {
    /* the file type name */
    /* should be NULL for all "pseudo" types that are only internally used and not read/writeable */
    const char *name;

    /* the file type short name, used as a shortcut for the command line tools */
    /* should be NULL for all "pseudo" types that are only internally used and not read/writeable */
    const char *short_name;

    /* the default file extension, used to save this type */
    /* should be NULL if no default extension is known */
    const char *default_file_extension;

    /* a semicolon-separated list of additional file extensions */
    /* used for this type */
    /* should be NULL if no extensions, or no extensions other */
    /* than the default extension, are known */
    const char *additional_file_extensions;

    /* when writing this file format, is seeking required? */
    gboolean writing_must_seek;

    /* does this type support name resolution records? */
    /* should be FALSE is this file type doesn't support name resolution records */
    gboolean has_name_resolution;

    /* what types of comment does this file support? */
    guint32 supported_comment_types;

    /* can this type write this encapsulation format? */
    /* should be NULL is this file type doesn't have write support */
    int (*can_write_encap)(int);

    /* the function to open the capture file for writing */
    /* should be NULL is this file type don't have write support */
    int (*dump_open)(wtap_dumper *, int *);

    /* if can_write_encap returned WTAP_ERR_CHECK_WSLUA, then this is used instead */
    /* this should be NULL for everyone except Lua-based file writers */
    wtap_wslua_file_info_t *wslua_info;
};

#define WTAP_TYPE_AUTO 0

/** On failure, "wtap_open_offline()" returns NULL, and puts into the
 * "int" pointed to by its second argument:
 *
 * @param filename Name of the file to open
 * @param type WTAP_TYPE_AUTO for automatic recognize file format or explicit choose format type
 * @param err a positive "errno" value if the capture file can't be opened;
 * a negative number, indicating the type of error, on other failures.
 * @param err_info for some errors, a string giving more details of
 * the error
 * @param do_random TRUE if random access to the file will be done,
 * FALSE if not
 */
WS_DLL_PUBLIC
struct wtap* wtap_open_offline(const char *filename, unsigned int type, int *err,
    gchar **err_info, gboolean do_random);

/**
 * If we were compiled with zlib and we're at EOF, unset EOF so that
 * wtap_read/gzread has a chance to succeed. This is necessary if
 * we're tailing a file.
 */
WS_DLL_PUBLIC
void wtap_cleareof(wtap *wth);

/**
 * Set callback functions to add new hostnames. Currently pcapng-only.
 * MUST match add_ipv4_name and add_ipv6_name in addr_resolv.c.
 */
typedef void (*wtap_new_ipv4_callback_t) (const guint addr, const gchar *name);
WS_DLL_PUBLIC
void wtap_set_cb_new_ipv4(wtap *wth, wtap_new_ipv4_callback_t add_new_ipv4);

typedef void (*wtap_new_ipv6_callback_t) (const void *addrp, const gchar *name);
WS_DLL_PUBLIC
void wtap_set_cb_new_ipv6(wtap *wth, wtap_new_ipv6_callback_t add_new_ipv6);

/** Returns TRUE if read was successful. FALSE if failure. data_offset is
 * set to the offset in the file where the data for the read packet is
 * located. */
WS_DLL_PUBLIC
gboolean wtap_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset);

WS_DLL_PUBLIC
gboolean wtap_seek_read (wtap *wth, gint64 seek_off,
        struct wtap_pkthdr *phdr, Buffer *buf, int *err, gchar **err_info);

/*** get various information snippets about the current packet ***/
WS_DLL_PUBLIC
struct wtap_pkthdr *wtap_phdr(wtap *wth);
WS_DLL_PUBLIC
guint8 *wtap_buf_ptr(wtap *wth);

/*** initialize a wtap_pkthdr structure ***/
WS_DLL_PUBLIC
void wtap_phdr_init(struct wtap_pkthdr *phdr);

/*** clean up a wtap_pkthdr structure, freeing what wtap_phdr_init() allocated */
WS_DLL_PUBLIC
void wtap_phdr_cleanup(struct wtap_pkthdr *phdr);

/*** get various information snippets about the current file ***/

/** Return an approximation of the amount of data we've read sequentially
 * from the file so far. */
WS_DLL_PUBLIC
gint64 wtap_read_so_far(wtap *wth);
WS_DLL_PUBLIC
gint64 wtap_file_size(wtap *wth, int *err);
WS_DLL_PUBLIC
gboolean wtap_iscompressed(wtap *wth);
WS_DLL_PUBLIC
guint wtap_snapshot_length(wtap *wth); /* per file */
WS_DLL_PUBLIC
int wtap_file_type_subtype(wtap *wth);
WS_DLL_PUBLIC
int wtap_file_encap(wtap *wth);
WS_DLL_PUBLIC
int wtap_file_tsprec(wtap *wth);

/**
 * @brief Gets existing section header block, not for new file.
 * @details Returns the pointer to the existing SHB, without creating a
 *          new one. This should only be used for accessing info, not
 *          for creating a new file based on existing SHB info. Use
 *          wtap_file_get_shb_for_new_file() for that.
 *
 * @param wth The wiretap session.
 * @return The existing section header, which must NOT be g_free'd.
 *
 * XXX - need to be updated to handle multiple SHBs.
 */
WS_DLL_PUBLIC
wtap_block_t wtap_file_get_shb(wtap *wth);

/**
 * @brief Gets new section header block for new file, based on existing info.
 * @details Creates a new wtap_block_t section header block and only
 *          copies appropriate members of the SHB for a new file. In
 *          particular, the comment string is copied, and any custom options
 *          which should be copied are copied. The os, hardware, and
 *          application strings are *not* copied.
 *
 * @note Use wtap_free_shb() to free the returned section header.
 *
 * @param wth The wiretap session.
 * @return The new section header, which must be wtap_free_shb'd.
 */
WS_DLL_PUBLIC
GArray* wtap_file_get_shb_for_new_file(wtap *wth);

/**
 * @brief Sets or replaces the section header comment.
 * @details The passed-in comment string is set to be the comment
 *          for the section header block. The passed-in string's
 *          ownership will be owned by the block, so it should be
 *          duplicated before passing into this function.
 *
 * @param wth The wiretap session.
 * @param comment The comment string.
 */
WS_DLL_PUBLIC
void wtap_write_shb_comment(wtap *wth, gchar *comment);

/**
 * @brief Gets existing interface descriptions.
 * @details Returns a new struct containing a pointer to the existing
 *          description, without creating new descriptions internally.
 * @note The returned pointer must be g_free'd, but its internal
 *       interface_data must not.
 *
 * @param wth The wiretap session.
 * @return A new struct of the existing section descriptions, which must be g_free'd.
 */
WS_DLL_PUBLIC
wtapng_iface_descriptions_t *wtap_file_get_idb_info(wtap *wth);

/**
 * @brief Free's a interface description block and all of its members.
 *
 * @details This free's all of the interface descriptions inside the passed-in
 *     struct, including their members (e.g., comments); and then free's the
 *     passed-in struct as well.
 *
 * @warning Do not use this for the struct returned by
 *     wtap_file_get_idb_info(), as that one did not create the internal
 *     interface descriptions; for that case you can simply g_free() the new
 *     struct.
 */
WS_DLL_PUBLIC
void wtap_free_idb_info(wtapng_iface_descriptions_t *idb_info);

/**
 * @brief Gets a debug string of an interface description.
 * @details Returns a newly allocated string of debug information about
 *          the given interface descrption, useful for debugging.
 * @note The returned pointer must be g_free'd.
 *
 * @param if_descr The interface description.
 * @param indent Number of spaces to indent each line by.
 * @param line_end A string to append to each line (e.g., "\n" or ", ").
 * @return A newly allocated gcahr array string, which must be g_free'd.
 */
WS_DLL_PUBLIC
gchar *wtap_get_debug_if_descr(const wtap_block_t if_descr,
                               const int indent,
                               const char* line_end);

/**
 * @brief Gets existing name resolution block, not for new file.
 * @details Returns the pointer to the existing NRB, without creating a
 *          new one. This should only be used for accessing info, not
 *          for creating a new file based on existing NRB info. Use
 *          wtap_file_get_nrb_for_new_file() for that.
 *
 * @param wth The wiretap session.
 * @return The existing section header, which must NOT be g_free'd.
 *
 * XXX - need to be updated to handle multiple NRBs.
 */
WS_DLL_PUBLIC
wtap_block_t wtap_file_get_nrb(wtap *wth);

/**
 * @brief Gets new name resolution info for new file, based on existing info.
 * @details Creates a new wtap_block_t of name resolution info and only
 *          copies appropriate members for a new file.
 *
 * @note Use wtap_free_nrb() to free the returned pointer.
 *
 * @param wth The wiretap session.
 * @return The new name resolution info, which must be freed.
 */
WS_DLL_PUBLIC
GArray* wtap_file_get_nrb_for_new_file(wtap *wth);

/*** close the file descriptors for the current file ***/
WS_DLL_PUBLIC
void wtap_fdclose(wtap *wth);

/*** reopen the random file descriptor for the current file ***/
WS_DLL_PUBLIC
gboolean wtap_fdreopen(wtap *wth, const char *filename, int *err);

/*** close the current file ***/
WS_DLL_PUBLIC
void wtap_sequential_close(wtap *wth);
WS_DLL_PUBLIC
void wtap_close(wtap *wth);

/*** dump packets into a capture file ***/
WS_DLL_PUBLIC
gboolean wtap_dump_can_open(int filetype);

/**
 * Given a GArray of WTAP_ENCAP_ types, return the per-file encapsulation
 * type that would be needed to write out a file with those types.
 */
WS_DLL_PUBLIC
int wtap_dump_file_encap_type(const GArray *file_encaps);

/**
 * Return TRUE if we can write this capture file format out in
 * compressed form, FALSE if not.
 */
WS_DLL_PUBLIC
gboolean wtap_dump_can_compress(int filetype);

/**
 * Return TRUE if this capture file format supports storing name
 * resolution information in it, FALSE if not.
 */
WS_DLL_PUBLIC
gboolean wtap_dump_has_name_resolution(int filetype);

/**
 * Return TRUE if this capture file format supports all the comment
 * types specified, FALSE if not.
 */
WS_DLL_PUBLIC
gboolean wtap_dump_supports_comment_types(int filetype, guint32 comment_types);

WS_DLL_PUBLIC
wtap_dumper* wtap_dump_open(const char *filename, int file_type_subtype, int encap,
    int snaplen, gboolean compressed, int *err);

/**
 * @brief Opens a new capture file for writing.
 *
 * @note The shb_hdr, idb_inf, and nrb_hdr arguments will be used until
 *     wtap_dump_close() is called, but will not be free'd by the dumper. If
 *     you created them, you must free them yourself after wtap_dump_close().
 *
 * @param filename The new file's name.
 * @param file_type_subtype The WTAP_FILE_TYPE_SUBTYPE_XXX file type.
 * @param encap The WTAP_ENCAP_XXX encapsulation type (WTAP_ENCAP_PER_PACKET for multi)
 * @param snaplen The maximum packet capture length.
 * @param compressed True if file should be compressed.
 * @param shb_hdrs The section header block(s) information, or NULL.
 * @param idb_inf The interface description information, or NULL.
 * @param nrb_hdrs The name resolution blocks(s) comment/custom_opts information, or NULL.
 * @param[out] err Will be set to an error code on failure.
 * @return The newly created dumper object, or NULL on failure.
 */
WS_DLL_PUBLIC
wtap_dumper* wtap_dump_open_ng(const char *filename, int file_type_subtype, int encap,
    int snaplen, gboolean compressed, GArray* shb_hdrs, wtapng_iface_descriptions_t *idb_inf,
    GArray* nrb_hdrs, int *err);

WS_DLL_PUBLIC
wtap_dumper* wtap_dump_open_tempfile(char **filenamep, const char *pfx,
    int file_type_subtype, int encap, int snaplen, gboolean compressed,
    int *err);

/**
 * @brief Creates a dumper for a temporary file.
 *
 * @note The shb_hdr, idb_inf, and nrb_hdr arguments will be used until
 *     wtap_dump_close() is called, but will not be free'd by the dumper. If
 *     you created them, you must free them yourself after wtap_dump_close().
 *
 * @param filenamep Points to a pointer that's set to point to the
 *        pathname of the temporary file; it's allocated with g_malloc()
 * @param pfx A string to be used as the prefix for the temporary file name
 * @param file_type_subtype The WTAP_FILE_TYPE_SUBTYPE_XXX file type.
 * @param encap The WTAP_ENCAP_XXX encapsulation type (WTAP_ENCAP_PER_PACKET for multi)
 * @param snaplen The maximum packet capture length.
 * @param compressed True if file should be compressed.
 * @param shb_hdrs The section header block(s) information, or NULL.
 * @param idb_inf The interface description information, or NULL.
 * @param nrb_hdrs The name resolution blocks(s) comment/custom_opts information, or NULL.
 * @param[out] err Will be set to an error code on failure.
 * @return The newly created dumper object, or NULL on failure.
 */
WS_DLL_PUBLIC
wtap_dumper* wtap_dump_open_tempfile_ng(char **filenamep, const char *pfx,
    int file_type_subtype, int encap, int snaplen, gboolean compressed,
    GArray* shb_hdrs, wtapng_iface_descriptions_t *idb_inf,
    GArray* nrb_hdrs, int *err);

WS_DLL_PUBLIC
wtap_dumper* wtap_dump_fdopen(int fd, int file_type_subtype, int encap, int snaplen,
    gboolean compressed, int *err);

/**
 * @brief Creates a dumper for an existing file descriptor.
 *
 * @note The shb_hdr, idb_inf, and nrb_hdr arguments will be used until
 *     wtap_dump_close() is called, but will not be free'd by the dumper. If
 *     you created them, you must free them yourself after wtap_dump_close().
 *
 * @param fd The file descriptor for which the dumper should be created.
 * @param file_type_subtype The WTAP_FILE_TYPE_SUBTYPE_XXX file type.
 * @param encap The WTAP_ENCAP_XXX encapsulation type (WTAP_ENCAP_PER_PACKET for multi)
 * @param snaplen The maximum packet capture length.
 * @param compressed True if file should be compressed.
 * @param shb_hdrs The section header block(s) information, or NULL.
 * @param idb_inf The interface description information, or NULL.
 * @param nrb_hdrs The name resolution blocks(s) comment/custom_opts information, or NULL.
 * @param[out] err Will be set to an error code on failure.
 * @return The newly created dumper object, or NULL on failure.
 */
WS_DLL_PUBLIC
wtap_dumper* wtap_dump_fdopen_ng(int fd, int file_type_subtype, int encap, int snaplen,
                gboolean compressed, GArray* shb_hdrs, wtapng_iface_descriptions_t *idb_inf,
                GArray* nrb_hdrs, int *err);

WS_DLL_PUBLIC
wtap_dumper* wtap_dump_open_stdout(int file_type_subtype, int encap, int snaplen,
    gboolean compressed, int *err);

/**
 * @brief Creates a dumper for the standard output.
 *
 * @note The shb_hdr, idb_inf, and nrb_hdr arguments will be used until
 *     wtap_dump_close() is called, but will not be free'd by the dumper. If
 *     you created them, you must free them yourself after wtap_dump_close().
 *
 * @param file_type_subtype The WTAP_FILE_TYPE_SUBTYPE_XXX file type.
 * @param encap The WTAP_ENCAP_XXX encapsulation type (WTAP_ENCAP_PER_PACKET for multi)
 * @param snaplen The maximum packet capture length.
 * @param compressed True if file should be compressed.
 * @param shb_hdrs The section header block(s) information, or NULL.
 * @param idb_inf The interface description information, or NULL.
 * @param nrb_hdrs The name resolution blocks(s) comment/custom_opts information, or NULL.
 * @param[out] err Will be set to an error code on failure.
 * @return The newly created dumper object, or NULL on failure.
 */
WS_DLL_PUBLIC
wtap_dumper* wtap_dump_open_stdout_ng(int file_type_subtype, int encap, int snaplen,
                gboolean compressed, GArray* shb_hdrs, wtapng_iface_descriptions_t *idb_inf,
                GArray* nrb_hdrs, int *err);

WS_DLL_PUBLIC
gboolean wtap_dump(wtap_dumper *, const struct wtap_pkthdr *, const guint8 *,
     int *err, gchar **err_info);
WS_DLL_PUBLIC
void wtap_dump_flush(wtap_dumper *);
WS_DLL_PUBLIC
gint64 wtap_get_bytes_dumped(wtap_dumper *);
WS_DLL_PUBLIC
void wtap_set_bytes_dumped(wtap_dumper *wdh, gint64 bytes_dumped);
struct addrinfo;
WS_DLL_PUBLIC
gboolean wtap_dump_set_addrinfo_list(wtap_dumper *wdh, addrinfo_lists_t *addrinfo_lists);
WS_DLL_PUBLIC
gboolean wtap_dump_close(wtap_dumper *, int *);

/**
 * Return TRUE if we can write a file out with the given GArray of file
 * encapsulations and the given bitmask of comment types.
 */
WS_DLL_PUBLIC
gboolean wtap_dump_can_write(const GArray *file_encaps, guint32 required_comment_types);

/**
 * Get a GArray of WTAP_FILE_TYPE_SUBTYPE_ values for file types/subtypes
 * that can be used to save a file of a given type with a given GArray of
 * WTAP_ENCAP_ types and the given bitmask of comment types.
 */
WS_DLL_PUBLIC
GArray *wtap_get_savable_file_types_subtypes(int file_type,
    const GArray *file_encaps, guint32 required_comment_types);

/*** various string converter functions ***/
WS_DLL_PUBLIC
const char *wtap_file_type_subtype_string(int file_type_subtype);
WS_DLL_PUBLIC
const char *wtap_file_type_subtype_short_string(int file_type_subtype);
WS_DLL_PUBLIC
int wtap_short_string_to_file_type_subtype(const char *short_name);

/*** various file extension functions ***/
WS_DLL_PUBLIC
GSList *wtap_get_all_file_extensions_list(void);
WS_DLL_PUBLIC
const char *wtap_default_file_extension(int filetype);
WS_DLL_PUBLIC
GSList *wtap_get_file_extensions_list(int filetype, gboolean include_compressed);
WS_DLL_PUBLIC
void wtap_free_extensions_list(GSList *extensions);

WS_DLL_PUBLIC
const char *wtap_encap_string(int encap);
WS_DLL_PUBLIC
const char *wtap_encap_short_string(int encap);
WS_DLL_PUBLIC
int wtap_short_string_to_encap(const char *short_name);

WS_DLL_PUBLIC
const char* wtap_tsprec_string(int tsprec);

WS_DLL_PUBLIC
const char *wtap_strerror(int err);

/*** get available number of file types and encapsulations ***/
WS_DLL_PUBLIC
int wtap_get_num_file_type_extensions(void);
WS_DLL_PUBLIC
int wtap_get_num_encap_types(void);
WS_DLL_PUBLIC
int wtap_get_num_file_types_subtypes(void);

/*** get information for file type extension ***/
WS_DLL_PUBLIC
const char *wtap_get_file_extension_type_name(int extension_type);
WS_DLL_PUBLIC
GSList *wtap_get_file_extension_type_extensions(guint extension_type);

/*** dynamically register new file types and encapsulations ***/
WS_DLL_PUBLIC
void wtap_register_plugin_types(void);
WS_DLL_PUBLIC
void register_all_wiretap_modules(void);
WS_DLL_PUBLIC
void wtap_register_file_type_extension(const struct file_extension_info *ei);

WS_DLL_PUBLIC
void wtap_register_open_info(struct open_info *oi, const gboolean first_routine);
WS_DLL_PUBLIC
gboolean wtap_has_open_info(const gchar *name);
WS_DLL_PUBLIC
void wtap_deregister_open_info(const gchar *name);

WS_DLL_PUBLIC
unsigned int open_info_name_to_type(const char *name);
WS_DLL_PUBLIC
int wtap_register_file_type_subtypes(const struct file_type_subtype_info* fi, const int subtype);
WS_DLL_PUBLIC
void wtap_deregister_file_type_subtype(const int file_type_subtype);

WS_DLL_PUBLIC
int wtap_register_encap_type(const char* name, const char* short_name);


/**
 * Wiretap error codes.
 */
#define WTAP_ERR_NOT_REGULAR_FILE              -1
    /** The file being opened for reading isn't a plain file (or pipe) */

#define WTAP_ERR_RANDOM_OPEN_PIPE              -2
    /** The file is being opened for random access and it's a pipe */

#define WTAP_ERR_FILE_UNKNOWN_FORMAT           -3
    /** The file being opened is not a capture file in a known format */

#define WTAP_ERR_UNSUPPORTED                   -4
    /** Supported file type, but there's something in the file we
       can't support */

#define WTAP_ERR_CANT_WRITE_TO_PIPE            -5
    /** Wiretap can't save to a pipe in the specified format */

#define WTAP_ERR_CANT_OPEN                     -6
    /** The file couldn't be opened, reason unknown */

#define WTAP_ERR_UNWRITABLE_FILE_TYPE          -7
    /** Wiretap can't save files in the specified format */

#define WTAP_ERR_UNWRITABLE_ENCAP              -8
    /** Wiretap can't read or save files in the specified format with the
       specified encapsulation */

#define WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED  -9
    /** The specified format doesn't support per-packet encapsulations */

#define WTAP_ERR_CANT_WRITE                   -10
    /** An attempt to read failed, reason unknown */

#define WTAP_ERR_CANT_CLOSE                   -11
    /** The file couldn't be closed, reason unknown */

#define WTAP_ERR_SHORT_READ                   -12
    /** An attempt to read read less data than it should have */

#define WTAP_ERR_BAD_FILE                     -13
    /** The file appears to be damaged or corrupted or otherwise bogus */

#define WTAP_ERR_SHORT_WRITE                  -14
    /** An attempt to write wrote less data than it should have */

#define WTAP_ERR_UNC_OVERFLOW                 -15
    /** Uncompressing Sniffer data would overflow buffer */

#define WTAP_ERR_RANDOM_OPEN_STDIN            -16
    /** We're trying to open the standard input for random access */

#define WTAP_ERR_COMPRESSION_NOT_SUPPORTED    -17
    /* The filetype doesn't support output compression */

#define WTAP_ERR_CANT_SEEK                    -18
    /** An attempt to seek failed, reason unknown */

#define WTAP_ERR_CANT_SEEK_COMPRESSED         -19
    /** An attempt to seek on a compressed stream */

#define WTAP_ERR_DECOMPRESS                   -20
    /** Error decompressing */

#define WTAP_ERR_INTERNAL                     -21
    /** "Shouldn't happen" internal errors */

#define WTAP_ERR_PACKET_TOO_LARGE             -22
    /** Packet being written is larger than we support; do not use when
        reading, use WTAP_ERR_BAD_FILE instead */

#define WTAP_ERR_CHECK_WSLUA                  -23
    /** Not really an error: the file type being checked is from a Lua
        plugin, so that the code will call wslua_can_write_encap() instead if it gets this */

#define WTAP_ERR_UNWRITABLE_REC_TYPE          -24
    /** Specified record type can't be written to that file type */

#define WTAP_ERR_UNWRITABLE_REC_DATA          -25
    /** Something in the record data can't be written to that file type */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WTAP_H__ */

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
