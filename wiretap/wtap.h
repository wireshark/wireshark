/* wtap.h
 *
 * $Id$
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

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <glib.h>
#include <time.h>

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
 *	1) PPP-over-HDLC encapsulation, at least with some versions
 *	   of ISDN4BSD (but not the current ones, it appears, unless
 *	   I've missed something);
 *
 *	2) a 4-byte header containing the AF_ address family, in
 *	   the byte order of the machine that saved the capture,
 *	   for the packet, as used on many BSD systems for the
 *	   loopback device and some other devices, or a 4-byte header
 *	   containing the AF_ address family in network byte order,
 *	   as used on recent OpenBSD systems for the loopback device;
 *
 *	3) a 4-byte header containing 2 octets of 0 and an Ethernet
 *	   type in the byte order from an Ethernet header, that being
 *	   what older versions of "libpcap" on Linux turn the Ethernet
 *	   header for loopback interfaces into (0.6.0 and later versions
 *	   leave the Ethernet header alone and make it DLT_EN10MB). */
#define WTAP_ENCAP_PER_PACKET                   -1
#define WTAP_ENCAP_UNKNOWN                      0
#define WTAP_ENCAP_ETHERNET                     1
#define WTAP_ENCAP_TOKEN_RING                   2
#define WTAP_ENCAP_SLIP                         3
#define WTAP_ENCAP_PPP                          4
#define WTAP_ENCAP_FDDI                         5
#define WTAP_ENCAP_FDDI_BITSWAPPED              6
#define WTAP_ENCAP_RAW_IP                       7
#define WTAP_ENCAP_ARCNET                       8
#define WTAP_ENCAP_ARCNET_LINUX                 9
#define WTAP_ENCAP_ATM_RFC1483                  10
#define WTAP_ENCAP_LINUX_ATM_CLIP               11
#define WTAP_ENCAP_LAPB                         12
#define WTAP_ENCAP_ATM_PDUS                     13
#define WTAP_ENCAP_ATM_PDUS_UNTRUNCATED         14
#define WTAP_ENCAP_NULL                         15
#define WTAP_ENCAP_ASCEND                       16
#define WTAP_ENCAP_ISDN                         17
#define WTAP_ENCAP_IP_OVER_FC                   18
#define WTAP_ENCAP_PPP_WITH_PHDR                19
#define WTAP_ENCAP_IEEE_802_11                  20
#define WTAP_ENCAP_PRISM_HEADER                 21
#define WTAP_ENCAP_IEEE_802_11_WITH_RADIO       22
#define WTAP_ENCAP_IEEE_802_11_WLAN_RADIOTAP    23
#define WTAP_ENCAP_IEEE_802_11_WLAN_AVS         24
#define WTAP_ENCAP_SLL                          25
#define WTAP_ENCAP_FRELAY                       26
#define WTAP_ENCAP_FRELAY_WITH_PHDR             27
#define WTAP_ENCAP_CHDLC                        28
#define WTAP_ENCAP_CISCO_IOS                    29
#define WTAP_ENCAP_LOCALTALK                    30
#define WTAP_ENCAP_OLD_PFLOG                    31
#define WTAP_ENCAP_HHDLC                        32
#define WTAP_ENCAP_DOCSIS                       33
#define WTAP_ENCAP_COSINE                       34
#define WTAP_ENCAP_WFLEET_HDLC                  35
#define WTAP_ENCAP_SDLC                         36
#define WTAP_ENCAP_TZSP                         37
#define WTAP_ENCAP_ENC                          38
#define WTAP_ENCAP_PFLOG                        39
#define WTAP_ENCAP_CHDLC_WITH_PHDR              40
#define WTAP_ENCAP_BLUETOOTH_H4                 41
#define WTAP_ENCAP_MTP2                         42
#define WTAP_ENCAP_MTP3                         43
#define WTAP_ENCAP_IRDA                         44
#define WTAP_ENCAP_USER0                        45
#define WTAP_ENCAP_USER1                        46
#define WTAP_ENCAP_USER2                        47
#define WTAP_ENCAP_USER3                        48
#define WTAP_ENCAP_USER4                        49
#define WTAP_ENCAP_USER5                        50
#define WTAP_ENCAP_USER6                        51
#define WTAP_ENCAP_USER7                        52
#define WTAP_ENCAP_USER8                        53
#define WTAP_ENCAP_USER9                        54
#define WTAP_ENCAP_USER10                       55
#define WTAP_ENCAP_USER11                       56
#define WTAP_ENCAP_USER12                       57
#define WTAP_ENCAP_USER13                       58
#define WTAP_ENCAP_USER14                       59
#define WTAP_ENCAP_USER15                       60
#define WTAP_ENCAP_SYMANTEC                     61
#define WTAP_ENCAP_APPLE_IP_OVER_IEEE1394       62
#define WTAP_ENCAP_BACNET_MS_TP                 63
#define WTAP_ENCAP_NETTL_RAW_ICMP               64
#define WTAP_ENCAP_NETTL_RAW_ICMPV6             65
#define WTAP_ENCAP_GPRS_LLC                     66
#define WTAP_ENCAP_JUNIPER_ATM1                 67
#define WTAP_ENCAP_JUNIPER_ATM2                 68
#define WTAP_ENCAP_REDBACK                      69
#define WTAP_ENCAP_NETTL_RAW_IP                 70
#define WTAP_ENCAP_NETTL_ETHERNET               71
#define WTAP_ENCAP_NETTL_TOKEN_RING             72
#define WTAP_ENCAP_NETTL_FDDI                   73
#define WTAP_ENCAP_NETTL_UNKNOWN                74
#define WTAP_ENCAP_MTP2_WITH_PHDR               75
#define WTAP_ENCAP_JUNIPER_PPPOE                76
#define WTAP_ENCAP_GCOM_TIE1                    77
#define WTAP_ENCAP_GCOM_SERIAL                  78
#define WTAP_ENCAP_NETTL_X25                    79
#define WTAP_ENCAP_K12                          80
#define WTAP_ENCAP_JUNIPER_MLPPP                81
#define WTAP_ENCAP_JUNIPER_MLFR                 82
#define WTAP_ENCAP_JUNIPER_ETHER                83
#define WTAP_ENCAP_JUNIPER_PPP                  84
#define WTAP_ENCAP_JUNIPER_FRELAY               85
#define WTAP_ENCAP_JUNIPER_CHDLC                86
#define WTAP_ENCAP_JUNIPER_GGSN                 87
#define WTAP_ENCAP_LINUX_LAPD                   88
#define WTAP_ENCAP_CATAPULT_DCT2000             89
#define WTAP_ENCAP_BER                          90
#define WTAP_ENCAP_JUNIPER_VP                   91
#define WTAP_ENCAP_USB                          92
#define WTAP_ENCAP_IEEE802_16_MAC_CPS           93
#define WTAP_ENCAP_NETTL_RAW_TELNET             94
#define WTAP_ENCAP_USB_LINUX                    95
#define WTAP_ENCAP_MPEG                         96
#define WTAP_ENCAP_PPI                          97
#define WTAP_ENCAP_ERF                          98
#define WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR       99
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
#define WTAP_ENCAP_JPEG_JFIF                    123	/* obsoleted by WTAP_ENCAP_MIME*/
#define WTAP_ENCAP_IPNET                        124
#define WTAP_ENCAP_SOCKETCAN                    125
#define WTAP_ENCAP_IEEE802_11_NETMON_RADIO      126
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
#define WTAP_ENCAP_IP_OVER_IB                   137

#define WTAP_NUM_ENCAP_TYPES                    wtap_get_num_encap_types()

/* File types that can be read by wiretap.
   We support writing some many of these file types, too, so we
   distinguish between different versions of them. */
#define WTAP_FILE_UNKNOWN                       0
#define WTAP_FILE_WTAP                          1
#define WTAP_FILE_PCAP                          2
#define WTAP_FILE_PCAP_NSEC                     3
#define WTAP_FILE_PCAP_AIX                      4
#define WTAP_FILE_PCAP_SS991029                 5
#define WTAP_FILE_PCAP_NOKIA                    6
#define WTAP_FILE_PCAP_SS990417                 7
#define WTAP_FILE_PCAP_SS990915                 8
#define WTAP_FILE_5VIEWS                        9
#define WTAP_FILE_IPTRACE_1_0                   10
#define WTAP_FILE_IPTRACE_2_0                   11
#define WTAP_FILE_BER                           12
#define WTAP_FILE_HCIDUMP                       13
#define WTAP_FILE_CATAPULT_DCT2000              14
#define WTAP_FILE_NETXRAY_OLD                   15
#define WTAP_FILE_NETXRAY_1_0                   16
#define WTAP_FILE_COSINE                        17
#define WTAP_FILE_CSIDS                         18
#define WTAP_FILE_DBS_ETHERWATCH                19
#define WTAP_FILE_ERF                           20
#define WTAP_FILE_EYESDN                        21
#define WTAP_FILE_NETTL                         22
#define WTAP_FILE_ISERIES                       23
#define WTAP_FILE_ISERIES_UNICODE               24
#define WTAP_FILE_I4BTRACE                      25
#define WTAP_FILE_ASCEND                        26
#define WTAP_FILE_NETMON_1_x                    27
#define WTAP_FILE_NETMON_2_x                    28
#define WTAP_FILE_NGSNIFFER_UNCOMPRESSED        29
#define WTAP_FILE_NGSNIFFER_COMPRESSED          30
#define WTAP_FILE_NETXRAY_1_1                   31
#define WTAP_FILE_NETXRAY_2_00x                 32
#define WTAP_FILE_NETWORK_INSTRUMENTS           33
#define WTAP_FILE_LANALYZER                     34
#define WTAP_FILE_PPPDUMP                       35
#define WTAP_FILE_RADCOM                        36
#define WTAP_FILE_SNOOP                         37
#define WTAP_FILE_SHOMITI                       38
#define WTAP_FILE_VMS                           39
#define WTAP_FILE_K12                           40
#define WTAP_FILE_TOSHIBA                       41
#define WTAP_FILE_VISUAL_NETWORKS               42
#define WTAP_FILE_ETHERPEEK_V56                 43
#define WTAP_FILE_ETHERPEEK_V7                  44
#define WTAP_FILE_AIROPEEK_V9                   45
#define WTAP_FILE_MPEG                          46
#define WTAP_FILE_K12TEXT                       47
#define WTAP_FILE_NETSCREEN                     48
#define WTAP_FILE_COMMVIEW                      49
#define WTAP_FILE_PCAPNG                        50
#define WTAP_FILE_BTSNOOP                       51
#define WTAP_FILE_X2E_XORAYA                    52
#define WTAP_FILE_TNEF                          53
#define WTAP_FILE_DCT3TRACE                     54
#define WTAP_FILE_PACKETLOGGER                  55
#define WTAP_FILE_DAINTREE_SNA                  56
#define WTAP_FILE_NETSCALER_1_0                 57
#define WTAP_FILE_NETSCALER_2_0                 58
#define WTAP_FILE_JPEG_JFIF                     59 /* obsoleted by WTAP_FILE_MIME */
#define WTAP_FILE_IPFIX                         60
#define WTAP_FILE_MIME                          61
#define WTAP_FILE_AETHRA			62

#define WTAP_NUM_FILE_TYPES                     wtap_get_num_file_types()

/* timestamp precision (currently only these values are supported) */
#define WTAP_FILE_TSPREC_SEC		0
#define WTAP_FILE_TSPREC_DSEC		1
#define WTAP_FILE_TSPREC_CSEC		2
#define WTAP_FILE_TSPREC_MSEC		3
#define WTAP_FILE_TSPREC_USEC		6
#define WTAP_FILE_TSPREC_NSEC		9

/*
 * Maximum packet size we'll support.
 * 65535 is the largest snapshot length that libpcap supports, so we
 * use that.
 */
#define	WTAP_MAX_PACKET_SIZE			65535

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
};

/* Packet "pseudo-header" information for Ethernet capture files. */
struct eth_phdr {
	gint	fcs_len;	/* Number of bytes of FCS - -1 means "unknown" */
};

/* Packet "pseudo-header" information for X.25 capture files. */
#define FROM_DCE			0x80
struct x25_phdr {
	guint8	flags; /* ENCAP_LAPB, ENCAP_V120 : 1st bit means From DCE */
};

/* Packet "pseudo-header" information for ISDN capture files. */

/* Direction */
struct isdn_phdr {
	gboolean uton;
	guint8	channel;		/* 0 = D-channel; n = B-channel n */
};

/* Packet "pseudo-header" for ATM capture files.
   Not all of this information is supplied by all capture types. */

/*
 * Status bits.
 */
#define ATM_RAW_CELL	0x01	/* TRUE if the packet is a single cell */
#define ATM_NO_HEC	0x02	/* TRUE if the cell has HEC stripped out */
#define ATM_AAL2_NOPHDR	0x04	/* TRUE if the AAL2 PDU has no pseudo-header */

/*
 * AAL types.
 */
#define AAL_UNKNOWN	0	/* AAL unknown */
#define AAL_1		1	/* AAL1 */
#define AAL_2		2	/* AAL2 */
#define AAL_3_4		3	/* AAL3/4 */
#define AAL_5		4	/* AAL5 */
#define AAL_USER	5	/* User AAL */
#define AAL_SIGNALLING	6	/* Signaling AAL */
#define AAL_OAMCELL	7	/* OAM cell */

/*
 * Traffic types.
 */
#define TRAF_UNKNOWN	0	/* Unknown */
#define TRAF_LLCMX	1	/* LLC multiplexed (RFC 1483) */
#define TRAF_VCMX	2	/* VC multiplexed (RFC 1483) */
#define TRAF_LANE	3	/* LAN Emulation */
#define TRAF_ILMI	4	/* ILMI */
#define TRAF_FR		5	/* Frame Relay */
#define TRAF_SPANS	6	/* FORE SPANS */
#define TRAF_IPSILON	7	/* Ipsilon */
#define TRAF_UMTS_FP	8	/* UMTS Frame Protocol */
#define TRAF_GPRS_NS	9 /* GPRS Network Services */

/*
 * Traffic subtypes.
 */
#define	TRAF_ST_UNKNOWN		0	/* Unknown */

/*
 * For TRAF_VCMX:
 */
#define	TRAF_ST_VCMX_802_3_FCS	1	/* 802.3 with an FCS */
#define	TRAF_ST_VCMX_802_4_FCS	2	/* 802.4 with an FCS */
#define	TRAF_ST_VCMX_802_5_FCS	3	/* 802.5 with an FCS */
#define	TRAF_ST_VCMX_FDDI_FCS	4	/* FDDI with an FCS */
#define	TRAF_ST_VCMX_802_6_FCS	5	/* 802.6 with an FCS */
#define	TRAF_ST_VCMX_802_3	7	/* 802.3 without an FCS */
#define	TRAF_ST_VCMX_802_4	8	/* 802.4 without an FCS */
#define	TRAF_ST_VCMX_802_5	9	/* 802.5 without an FCS */
#define	TRAF_ST_VCMX_FDDI	10	/* FDDI without an FCS */
#define	TRAF_ST_VCMX_802_6	11	/* 802.6 without an FCS */
#define	TRAF_ST_VCMX_FRAGMENTS	12	/* Fragments */
#define	TRAF_ST_VCMX_BPDU	13	/* BPDU */

/*
 * For TRAF_LANE:
 */
#define	TRAF_ST_LANE_LE_CTRL	1	/* LANE: LE Ctrl */
#define	TRAF_ST_LANE_802_3	2	/* LANE: 802.3 */
#define	TRAF_ST_LANE_802_5	3	/* LANE: 802.5 */
#define	TRAF_ST_LANE_802_3_MC	4	/* LANE: 802.3 multicast */
#define	TRAF_ST_LANE_802_5_MC	5	/* LANE: 802.5 multicast */

/*
 * For TRAF_IPSILON:
 */
#define	TRAF_ST_IPSILON_FT0	1	/* Ipsilon: Flow Type 0 */
#define	TRAF_ST_IPSILON_FT1	2	/* Ipsilon: Flow Type 1 */
#define	TRAF_ST_IPSILON_FT2	3	/* Ipsilon: Flow Type 2 */

struct atm_phdr {
	guint32	flags;		/* status flags */
	guint8	aal;		/* AAL of the traffic */
	guint8	type;		/* traffic type */
	guint8	subtype;	/* traffic subtype */
	guint16	vpi;		/* virtual path identifier */
	guint16	vci;		/* virtual circuit identifier */
	guint8	aal2_cid;	/* channel id */
	guint16	channel;	/* link: 0 for DTE->DCE, 1 for DCE->DTE */
	guint16	cells;		/* number of cells */
	guint16	aal5t_u2u;	/* user-to-user indicator */
	guint16	aal5t_len;	/* length of the packet */
	guint32	aal5t_chksum;	/* checksum for AAL5 packet */
};

/* Packet "pseudo-header" for the output from "wandsession", "wannext",
   "wandisplay", and similar commands on Lucent/Ascend access equipment. */

#define ASCEND_MAX_STR_LEN 64

#define ASCEND_PFX_WDS_X 1
#define ASCEND_PFX_WDS_R 2
#define ASCEND_PFX_WDD   3
#define ASCEND_PFX_ISDN_X 4
#define ASCEND_PFX_ISDN_R 5
#define ASCEND_PFX_ETHER 6

struct ascend_phdr {
	guint16	type;			/* ASCEND_PFX_*, as defined above */
	char	user[ASCEND_MAX_STR_LEN];   /* Username, from wandsession header */
	guint32	sess;			/* Session number, from wandsession header */
	char	call_num[ASCEND_MAX_STR_LEN];   /* Called number, from WDD header */
	guint32	chunk;			/* Chunk number, from WDD header */
	guint32	task;			/* Task number */
};

/* Also defined in epan/packet_info.h */
#define P2P_DIR_UNKNOWN	-1
#define P2P_DIR_SENT	0
#define P2P_DIR_RECV	1

/* Packet "pseudo-header" for point-to-point links with direction flags. */
struct p2p_phdr {
	int	sent; /* TRUE=sent, FALSE=received, -1=unknown*/
};

/*
 * Packet "pseudo-header" information for 802.11.
 * Radio information is only present for WTAP_ENCAP_IEEE_802_11_WITH_RADIO.
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
struct ieee_802_11_phdr {
	gint	fcs_len;	/* Number of bytes of FCS - -1 means "unknown" */
	guint8	channel;	/* Channel number */
	guint8	data_rate;	/* in .5 Mb/s units */
	guint8	signal_level;	/* percentage */
};

/* Packet "pseudo-header" for the output from CoSine L2 debug output. */

#define COSINE_MAX_IF_NAME_LEN	128

#define COSINE_ENCAP_TEST	1
#define COSINE_ENCAP_PPoATM	2
#define COSINE_ENCAP_PPoFR	3
#define COSINE_ENCAP_ATM	4
#define COSINE_ENCAP_FR		5
#define COSINE_ENCAP_HDLC	6
#define COSINE_ENCAP_PPP	7
#define COSINE_ENCAP_ETH	8
#define COSINE_ENCAP_UNKNOWN	99

#define COSINE_DIR_TX 1
#define COSINE_DIR_RX 2

struct cosine_phdr {
	guint8 encap;		/* COSINE_ENCAP_* as defined above */
	guint8 direction;	/* COSINE_DIR_*, as defined above */
	char if_name[COSINE_MAX_IF_NAME_LEN];  /* Encap & Logical I/F name */
	guint16 pro;		/* Protocol */
	guint16 off;		/* Offset */
	guint16 pri;		/* Priority */
	guint16 rm;		/* Rate Marking */
	guint16 err;		/* Error Code */
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
	guint32 input;
	const gchar* input_name;
	const gchar* stack_file;
	guint32 input_type;
	k12_input_info_t input_info;
	guint8* extra_info;
	guint32 extra_length;
	void* stuff;
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
		struct isdn_phdr  isdn;
		struct atm_phdr   atm;
		struct p2p_phdr   p2p;
	} inner_pseudo_header;
	gint64 seek_off;
	struct wtap *wth;
};

#define LIBPCAP_BT_PHDR_SENT    0
#define LIBPCAP_BT_PHDR_RECV    1

/*
 * Header prepended by libpcap to each bluetooth hci h:4 frame.
 * Values in network byte order
 */
struct libpcap_bt_phdr {
    guint32 direction;     /* Bit 0 hold the frame direction. */
};

#define LIBPCAP_PPP_PHDR_RECV    0
#define LIBPCAP_PPP_PHDR_SENT    1

/*
 * Header prepended by libpcap to each ppp frame.
 */
struct libpcap_ppp_phdr {
    guint8 direction;
};

/*
 * Endace Record Format pseudo header
 */
struct erf_phdr {
  guint64 ts;             /* Time stamp */
  guint8 type;
  guint8 flags;
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

struct erf_mc_phdr {
  struct erf_phdr phdr;
  struct erf_ehdr ehdr_list[MAX_ERF_EHDR];
  union
  {
    guint16 eth_hdr;
    guint32 mc_hdr;
  } subhdr;
};

#define SITA_FRAME_DIR_TXED		(0x00)		/* values of sita_phdr.flags */
#define SITA_FRAME_DIR_RXED		(0x01)
#define SITA_FRAME_DIR			(0x01)		/* mask */
#define SITA_ERROR_NO_BUFFER		(0x80)

#define SITA_SIG_DSR			(0x01)		/* values of sita_phdr.signals */
#define SITA_SIG_DTR			(0x02)
#define SITA_SIG_CTS			(0x04)
#define SITA_SIG_RTS			(0x08)
#define SITA_SIG_DCD			(0x10)
#define SITA_SIG_UNDEF1			(0x20)
#define SITA_SIG_UNDEF2			(0x40)
#define SITA_SIG_UNDEF3			(0x80)

#define SITA_ERROR_TX_UNDERRUN		(0x01)		/* values of sita_phdr.errors2 (if SITA_FRAME_DIR_TXED) */
#define SITA_ERROR_TX_CTS_LOST		(0x02)
#define SITA_ERROR_TX_UART_ERROR	(0x04)
#define SITA_ERROR_TX_RETX_LIMIT	(0x08)
#define SITA_ERROR_TX_UNDEF1		(0x10)
#define SITA_ERROR_TX_UNDEF2		(0x20)
#define SITA_ERROR_TX_UNDEF3		(0x40)
#define SITA_ERROR_TX_UNDEF4		(0x80)

#define SITA_ERROR_RX_FRAMING		(0x01)		/* values of sita_phdr.errors1 (if SITA_FRAME_DIR_RXED) */
#define SITA_ERROR_RX_PARITY		(0x02)
#define SITA_ERROR_RX_COLLISION		(0x04)
#define SITA_ERROR_RX_FRAME_LONG	(0x08)
#define SITA_ERROR_RX_FRAME_SHORT	(0x10)
#define SITA_ERROR_RX_UNDEF1		(0x20)
#define SITA_ERROR_RX_UNDEF2		(0x40)
#define SITA_ERROR_RX_UNDEF3		(0x80)

#define SITA_ERROR_RX_NONOCTET_ALIGNED	(0x01)	/* values of sita_phdr.errors2 (if SITA_FRAME_DIR_RXED) */
#define SITA_ERROR_RX_ABORT		(0x02)
#define SITA_ERROR_RX_CD_LOST		(0x04)
#define SITA_ERROR_RX_DPLL		(0x08)
#define SITA_ERROR_RX_OVERRUN		(0x10)
#define SITA_ERROR_RX_FRAME_LEN_VIOL	(0x20)
#define SITA_ERROR_RX_CRC		(0x40)
#define SITA_ERROR_RX_BREAK		(0x80)

#define SITA_PROTO_UNUSED		(0x00)		/* values of sita_phdr.proto */
#define SITA_PROTO_BOP_LAPB		(0x01)
#define SITA_PROTO_ETHERNET		(0x02)
#define SITA_PROTO_ASYNC_INTIO		(0x03)
#define SITA_PROTO_ASYNC_BLKIO		(0x04)
#define SITA_PROTO_ALC			(0x05)
#define SITA_PROTO_UTS			(0x06)
#define SITA_PROTO_PPP_HDLC		(0x07)
#define SITA_PROTO_SDLC			(0x08)
#define SITA_PROTO_TOKENRING		(0x09)
#define SITA_PROTO_I2C			(0x10)
#define SITA_PROTO_DPM_LINK		(0x11)
#define SITA_PROTO_BOP_FRL		(0x12)

struct sita_phdr {
   guint8  flags;
   guint8  signals;
   guint8  errors1;
   guint8  errors2;
   guint8  proto;
};

/*pseudo header for Bluetooth HCI*/
struct bthci_phdr {
	gboolean sent;
	guint8 channel;
};

#define BTHCI_CHANNEL_COMMAND 1
#define BTHCI_CHANNEL_ACL     2
#define BTHCI_CHANNEL_SCO     3
#define BTHCI_CHANNEL_EVENT   4

/* pseudo header for WTAP_ENCAP_LAYER1_EVENT */
struct l1event_phdr {
	gboolean uton;
};

/* * I2C pseudo header */
struct i2c_phdr {
	guint8 is_event;
	guint8 bus;
	guint32 flags;
};

/* pseudo header for WTAP_ENCAP_GSM_UM */
struct gsm_um_phdr {
	gboolean uplink;
	guint8 channel;
	/* The following are only populated for downlink */
	guint8 bsic;
	guint16 arfcn;
	guint32 tdma_frame;
	guint8 error;
	guint16 timeshift;
};

#define GSM_UM_CHANNEL_UNKNOWN	0
#define GSM_UM_CHANNEL_BCCH	1
#define GSM_UM_CHANNEL_SDCCH	2
#define GSM_UM_CHANNEL_SACCH	3
#define GSM_UM_CHANNEL_FACCH	4
#define GSM_UM_CHANNEL_CCCH	5
#define GSM_UM_CHANNEL_RACH	6
#define GSM_UM_CHANNEL_AGCH	7
#define GSM_UM_CHANNEL_PCH	8

union wtap_pseudo_header {
	struct eth_phdr		eth;
	struct x25_phdr		x25;
	struct isdn_phdr	isdn;
	struct atm_phdr		atm;
	struct ascend_phdr	ascend;
	struct p2p_phdr		p2p;
	struct ieee_802_11_phdr	ieee_802_11;
	struct cosine_phdr	cosine;
	struct irda_phdr	irda;
	struct nettl_phdr	nettl;
	struct mtp2_phdr	mtp2;
	struct k12_phdr		k12;
	struct lapd_phdr	lapd;
	struct catapult_dct2000_phdr dct2000;
	struct erf_mc_phdr	erf;
	struct sita_phdr	sita;
	struct bthci_phdr	bthci;
	struct l1event_phdr	l1event;
	struct i2c_phdr		i2c;
	struct gsm_um_phdr	gsm_um;
	struct nstr_phdr	nstr;
};

struct wtap_nstime {
	time_t	secs;
	int	nsecs;
};

struct wtap_pkthdr {
	struct wtap_nstime ts;
	guint32	caplen;
	guint32 len;
	int pkt_encap;
};

struct Buffer;
struct wtap_dumper;

typedef struct wtap wtap;
typedef struct wtap_dumper wtap_dumper;

typedef struct wtap_reader *FILE_T;

struct file_type_info {
    /* the file type name */
    /* should be NULL for all "pseudo" types that are only internally used and not read/writeable */
    const char *name;

    /* the file type short name, used as a shortcut for the command line tools */
    /* should be NULL for all "pseudo" types that are only internally used and not read/writeable */
    const char *short_name;

    /* the common file extensions for this type (seperated by semicolon) */
    /* should be *.* if no common extension is applicable */
    const char *file_extensions;

    /* the default file extension, used to save this type */
    /* should be NULL if no default extension is known */
    const char *file_extension_default;

    /* when writing this file format, is seeking required? */
    gboolean writing_must_seek;

    /* does this type support name resolution records? */
    /* should be FALSE is this file type doesn't support name resolution records */
    gboolean has_name_resolution;

    /* can this type write this encapsulation format? */
    /* should be NULL is this file type doesn't have write support */
    int (*can_write_encap)(int);

    /* the function to open the capture file for writing */
    /* should be NULL is this file type don't have write support */
    int (*dump_open)(wtap_dumper *, int *);
};


typedef int (*wtap_open_routine_t)(struct wtap*, int *, char **);


/** On failure, "wtap_open_offline()" returns NULL, and puts into the
 * "int" pointed to by its second argument:
 *
 * @param filename Name of the file to open
 * @param err a positive "errno" value if the capture file can't be opened;
 * a negative number, indicating the type of error, on other failures.
 * @param err_info for some errors, a string giving more details of
 * the error
 * @param do_random TRUE if random access to the file will be done,
 * FALSE if not
 */
struct wtap* wtap_open_offline(const char *filename, int *err,
    gchar **err_info, gboolean do_random);

/*
 * If we were compiled with zlib and we're at EOF, unset EOF so that
 * wtap_read/gzread has a chance to succeed. This is necessary if
 * we're tailing a file.
 */
void wtap_cleareof(wtap *wth);

/*
 * Set callback functions to add new hostnames. Currently pcapng-only.
 * MUST match add_ipv4_name and add_ipv6_name in addr_resolv.c.
 */
typedef void (*wtap_new_ipv4_callback_t) (const guint addr, const gchar *name);
void wtap_set_cb_new_ipv4(wtap *wth, wtap_new_ipv4_callback_t add_new_ipv4);

typedef void (*wtap_new_ipv6_callback_t) (const void *addrp, const gchar *name);
void wtap_set_cb_new_ipv6(wtap *wth, wtap_new_ipv6_callback_t add_new_ipv6);

/* Returns TRUE if read was successful. FALSE if failure. data_offset is
 * set to the offset in the file where the data for the read packet is
 * located. */
gboolean wtap_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset);

gboolean wtap_seek_read (wtap *wth, gint64 seek_off,
	union wtap_pseudo_header *pseudo_header, guint8 *pd, int len,
	int *err, gchar **err_info);

/*** get various information snippets about the current packet ***/
struct wtap_pkthdr *wtap_phdr(wtap *wth);
union wtap_pseudo_header *wtap_pseudoheader(wtap *wth);
guint8 *wtap_buf_ptr(wtap *wth);

/*** get various information snippets about the current file ***/

/* Return an approximation of the amount of data we've read sequentially
 * from the file so far. */
gint64 wtap_read_so_far(wtap *wth);
gint64 wtap_file_size(wtap *wth, int *err);
guint wtap_snapshot_length(wtap *wth); /* per file */
int wtap_file_type(wtap *wth);
int wtap_file_encap(wtap *wth);
int wtap_file_tsprecision(wtap *wth);

/*** close the current file ***/
void wtap_sequential_close(wtap *wth);
void wtap_close(wtap *wth);

/*** dump packets into a capture file ***/
gboolean wtap_dump_can_open(int filetype);
gboolean wtap_dump_can_write_encap(int filetype, int encap);
gboolean wtap_dump_can_compress(int filetype);
gboolean wtap_dump_has_name_resolution(int filetype);
wtap_dumper* wtap_dump_open(const char *filename, int filetype, int encap,
	int snaplen, gboolean compressed, int *err);
wtap_dumper* wtap_dump_fdopen(int fd, int filetype, int encap, int snaplen,
	gboolean compressed, int *err);
gboolean wtap_dump(wtap_dumper *, const struct wtap_pkthdr *,
	const union wtap_pseudo_header *pseudo_header, const guint8 *, int *err);
void wtap_dump_flush(wtap_dumper *);
gint64 wtap_get_bytes_dumped(wtap_dumper *);
void wtap_set_bytes_dumped(wtap_dumper *wdh, gint64 bytes_dumped);
struct addrinfo;
gboolean wtap_dump_set_addrinfo_list(wtap_dumper *wdh, struct addrinfo *addrinfo_list);
gboolean wtap_dump_close(wtap_dumper *, int *);

/*** various string converter functions ***/
const char *wtap_file_type_string(int filetype);
const char *wtap_file_type_short_string(int filetype);
int wtap_short_string_to_file_type(const char *short_name);

const char *wtap_file_extensions_string(int filetype);
const char *wtap_file_extension_default_string(int filetype);

const char *wtap_encap_string(int encap);
const char *wtap_encap_short_string(int encap);
int wtap_short_string_to_encap(const char *short_name);

const char *wtap_strerror(int err);

/*** get available number of file types and encapsulations ***/
int wtap_get_num_encap_types(void);
int wtap_get_num_file_types(void);

/*** dynamically register new file types and encapsulations ***/
void wtap_register_open_routine(wtap_open_routine_t, gboolean has_magic);
int wtap_register_file_type(const struct file_type_info* fi);
int wtap_register_encap_type(char* name, char* short_name);


/*
 * Wiretap error codes.
 */
#define	WTAP_ERR_NOT_REGULAR_FILE		-1
	/* The file being opened for reading isn't a plain file (or pipe) */
#define	WTAP_ERR_RANDOM_OPEN_PIPE		-2
	/* The file is being opened for random access and it's a pipe */
#define	WTAP_ERR_FILE_UNKNOWN_FORMAT		-3
	/* The file being opened is not a capture file in a known format */
#define	WTAP_ERR_UNSUPPORTED			-4
	/* Supported file type, but there's something in the file we
	   can't support */
#define	WTAP_ERR_CANT_WRITE_TO_PIPE		-5
	/* Wiretap can't save to a pipe in the specified format */
#define	WTAP_ERR_CANT_OPEN			-6
	/* The file couldn't be opened, reason unknown */
#define	WTAP_ERR_UNSUPPORTED_FILE_TYPE		-7
	/* Wiretap can't save files in the specified format */
#define	WTAP_ERR_UNSUPPORTED_ENCAP		-8
	/* Wiretap can't read or save files in the specified format with the
	   specified encapsulation */
#define	WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED	-9
	/* The specified format doesn't support per-packet encapsulations */
#define	WTAP_ERR_CANT_CLOSE			-10
	/* The file couldn't be closed, reason unknown */
#define	WTAP_ERR_CANT_READ			-11
	/* An attempt to read failed, reason unknown */
#define	WTAP_ERR_SHORT_READ			-12
	/* An attempt to read read less data than it should have */
#define	WTAP_ERR_BAD_RECORD			-13
	/* We read an invalid record */
#define	WTAP_ERR_SHORT_WRITE			-14
	/* An attempt to write wrote less data than it should have */
#define	WTAP_ERR_UNC_TRUNCATED			-15
	/* Sniffer compressed data was oddly truncated */
#define	WTAP_ERR_UNC_OVERFLOW			-16
	/* Uncompressing Sniffer data would overflow buffer */
#define	WTAP_ERR_UNC_BAD_OFFSET			-17
	/* LZ77 compressed data has bad offset to string */
#define	WTAP_ERR_RANDOM_OPEN_STDIN		-18
	/* We're trying to open the standard input for random access */
#define WTAP_ERR_COMPRESSION_NOT_SUPPORTED	-19
	/* The filetype doesn't support output compression */
#define	WTAP_ERR_CANT_SEEK			-20
	/* An attempt to seek failed, reason unknown */
#define WTAP_ERR_DECOMPRESS			-21
	/* Error decompressing */
#define WTAP_ERR_INTERNAL			-22
	/* "Shouldn't happen" internal errors */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WTAP_H__ */
