/* vwr.c
 * Copyright (c) 2011 by Tom Alexander <talexander@ixiacom.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */
#include "config.h"

#include <errno.h>
#include <string.h>

#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "vwr.h"


/* platform-specific definitions for portability */

/* unsigned long long constants */
#   define NS_IN_US             G_GUINT64_CONSTANT(1000)        /* nanoseconds-to-microseconds */
#   define NS_IN_SEC            G_GUINT64_CONSTANT(1000000000)  /* nanoseconds-to-seconds */
#   define US_IN_SEC            G_GUINT64_CONSTANT(1000000)     /* microseconds-to-seconds */
#   define LL_ZERO              G_GUINT64_CONSTANT(0)           /* zero in unsigned long long */

/*
 * Fetch a 64-bit value in "Corey-endian" form.
 */
#define pcoreytohll(p)  ((guint64)*((const guint8 *)(p)+4)<<56|  \
                         (guint64)*((const guint8 *)(p)+5)<<48|  \
                         (guint64)*((const guint8 *)(p)+6)<<40|  \
                         (guint64)*((const guint8 *)(p)+7)<<32|  \
                         (guint64)*((const guint8 *)(p)+0)<<24|  \
                         (guint64)*((const guint8 *)(p)+1)<<16|  \
                         (guint64)*((const guint8 *)(p)+2)<<8|   \
                         (guint64)*((const guint8 *)(p)+3)<<0)

/*
 * Fetch a 48-bit value in "Corey-endian" form; it's stored as
 * a 64-bit Corey-endian value, with the upper 16 bits ignored.
 */
#define pcorey48tohll(p)  ((guint64)*((const guint8 *)(p)+6)<<40|  \
                           (guint64)*((const guint8 *)(p)+7)<<32|  \
                           (guint64)*((const guint8 *)(p)+0)<<24|  \
                           (guint64)*((const guint8 *)(p)+1)<<16|  \
                           (guint64)*((const guint8 *)(p)+2)<<8|   \
                           (guint64)*((const guint8 *)(p)+3)<<0)

/* .vwr log file defines */
#define B_SIZE      32768                           /* max var len message = 32 kB */
#define VT_FRAME    0                               /* varlen msg is a frame */
#define VT_CPMSG    1                               /* varlen msg is a CP<->PP msg */
#define MAX_TRACKED_CLIENTS 1024                    /* track 1024 clients */
#define MAX_TRACKED_FLOWS   65536                   /* and 64K flows */

/*
 * The file consists of a sequence of records.
 * A record begins with a 16-byte header, the first 8 bytes of which
 * begin with a byte containing a command plus transmit-receive flags.
 *
 * Following that are two big-endian 32-bi quantities; for some records
 * one or the other of them is the length of the rest of the record.
 * Other records contain only the header.
 */
#define VW_RECORD_HEADER_LENGTH 16

/* the metadata headers */

/* Size of thhe IxVeriwave common header */
#define STATS_COMMON_FIELDS_LEN (2+2+2+4+2+2+4+4+8+8+4)

/* For VeriWave WLAN and Ethernet metadata headers vw_flags field */
#define VW_FLAGS_TXF        0x01                /* frame was transmitted */
#define VW_FLAGS_FCSERR     0x02                /* FCS error detected */

/* For VeriWave WLAN metadata header vw_flags field */
#define VW_FLAGS_RETRERR    0x04                /* excess retry error detected */
#define VW_FLAGS_DCRERR     0x10                /* decrypt error detected (WLAN) */
#define VW_FLAGS_ENCMSK     0x60                /* encryption type mask */
                                                /* 0 = none, 1 = WEP, 2 = TKIP, 3 = CCKM */
#define VW_FLAGS_IS_WEP     0x20                /* WEP */
#define VW_FLAGS_IS_TKIP    0x40                /* TKIP */
#define VW_FLAGS_IS_CCMP    0x60                /* CCMP */

/* Veriwave WLAN metadata header */

/* Channel flags, for chanflags field */
#define CHAN_CCK            0x0020              /* CCK channel */
#define CHAN_OFDM           0x0040              /* OFDM channel */

/* Flags, for flags field */
#define FLAGS_SHORTPRE      0x0002              /* sent/received with short preamble */
#define FLAGS_WEP           0x0004              /* sent/received with WEP encryption */
#define FLAGS_CHAN_HT       0x0040              /* In HT mode */
#define FLAGS_CHAN_VHT      0x0080              /* VHT Mode */
#define FLAGS_CHAN_SHORTGI  0x0100              /* Short guard interval */
#define FLAGS_CHAN_40MHZ    0x0200              /* 40 Mhz channel bandwidth */
#define FLAGS_CHAN_80MHZ    0x0400              /* 80 Mhz channel bandwidth */
#define FLAGS_CHAN_160MHZ   0x0800              /* 160 Mhz channel bandwidth */

/* Size of the VeriWave WLAN metadata header */
#define EXT_WLAN_FIELDS_LEN (2+2+2+2+1+1+1+1+1+1+1+1+2+2+2+4)

/* Size of the VeriWave Ethernet metadata header */
#define EXT_ETHERNET_FIELDS_LEN (2+2+2+4+4+4)

/* FPGA-generated frame buffer STATS block offsets and definitions */

/* definitions for v2.2 frames, Ethernet format */
#define v22_E_STATS_LEN          44                 /* length of stats block trailer */
#define v22_E_VALID_OFF           0                 /* bit 6 (0x40) is flow-is-valid flag */
#define v22_E_MTYPE_OFF           1                 /* offset of modulation type */
#define v22_E_VCID_OFF            2                 /* offset of VC ID */
#define v22_E_FLOWSEQ_OFF         4                 /* offset of signature sequence number */
#define v22_E_FLOWID_OFF          5                 /* offset of flow ID */
#define v22_E_OCTET_OFF           8                 /* offset of octets */
#define v22_E_ERRORS_OFF         10                 /* offset of error vector */
#define v22_E_PATN_OFF           12                 /* offset of pattern match vector */
#define v22_E_L4ID_OFF           12
#define v22_E_IPLEN_OFF          14
#define v22_E_FRAME_TYPE_OFF     16                 /* offset of frame type, 32 bits */
#define v22_E_RSSI_OFF           21                 /* RSSI (NOTE: invalid for Ethernet) */
#define v22_E_STARTT_OFF         20                 /* offset of start time, 64 bits */
#define v22_E_ENDT_OFF           28                 /* offset of end time, 64 bits */
#define v22_E_LATVAL_OFF         36                 /* offset of latency, 32 bits */
#define v22_E_INFO_OFF           40                 /* NO INFO FIELD IN ETHERNET STATS! */
#define v22_E_DIFFERENTIATOR_OFF  0                 /* offset to determine whether */
                                                    /* eth/802.11, 8 bits */

#define v22_E_MT_10_HALF    0                       /* 10 Mb/s half-duplex */
#define v22_E_MT_10_FULL    1                       /* 10 Mb/s full-duplex */
#define v22_E_MT_100_HALF   2                       /* 100 Mb/s half-duplex */
#define v22_E_MT_100_FULL   3                       /* 100 Mb/s full-duplex */
#define v22_E_MT_1G_HALF    4                       /* 1 Gb/s half-duplex */
#define v22_E_MT_1G_FULL    5                       /* 1 Gb/s full-duplex */

#define v22_E_FCS_ERROR           0x0002            /* FCS error flag in error vector */
#define v22_E_CRYPTO_ERR          0x1f00            /* RX decrypt error flags (UNUSED) */
#define v22_E_SIG_ERR             0x0004            /* signature magic byte mismatch */
#define v22_E_PAYCHK_ERR          0x0008            /* payload checksum failure */
#define v22_E_RETRY_ERR           0x0400            /* excessive retries on TX fail (UNUSED)*/
#define v22_E_IS_RX               0x08              /* TX/RX bit in STATS block */
#define v22_E_MT_MASK             0x07              /* modulation type mask (UNUSED) */
#define v22_E_VCID_MASK           0x03ff            /* VC ID is only 9 bits */
#define v22_E_FLOW_VALID          0x40              /* flow-is-valid flag (else force to 0) */
#define v22_E_DIFFERENTIATOR_MASK 0X3F              /* mask to differentiate ethernet from */
#define v22_E_IS_TCP              0x00000040        /* TCP bit in FRAME_TYPE field */
#define v22_E_IS_UDP              0x00000010        /* UDP bit in FRAME_TYPE field */
#define v22_E_IS_ICMP             0x00000020        /* ICMP bit in FRAME_TYPE field */
#define v22_E_IS_IGMP             0x00000080        /* IGMP bit in FRAME_TYPE field */
#define v22_E_IS_QOS              0x80              /* QoS bit in MTYPE field (WLAN only) */
#define v22_E_IS_VLAN             0x00200000


#define v22_E_RX_DECRYPTS   0x0007                  /* RX-frame-was-decrypted (UNUSED) */
#define v22_E_TX_DECRYPTS   0x0007                  /* TX-frame-was-decrypted (UNUSED) */

#define v22_E_FC_PROT_BIT   0x40                    /* Protected Frame bit in FC1 of frame */


#define v22_E_HEADER_IS_RX  0x21
#define v22_E_HEADER_IS_TX  0x31

#define v22_E_IS_ETHERNET   0x00700000              /* bits set in frame type if ethernet */
#define v22_E_IS_80211      0x7F000000              /* bits set in frame type if 802.11 */

/* definitions for v2.2 frames, WLAN format for VW510006 FPGA*/
#define v22_W_STATS_LEN          64                 /* length of stats block trailer */
#define v22_W_VALID_OFF           0                 /* bit 6 (0x40) is flow-is-valid flag */
#define v22_W_MTYPE_OFF           1                 /* offset of modulation type */
#define v22_W_VCID_OFF            2                 /* offset of VC ID */
#define v22_W_FLOWSEQ_OFF         4                 /* offset of signature sequence number */
#define v22_W_FLOWID_OFF          5                 /* offset of flow ID */
#define v22_W_OCTET_OFF           8                 /* offset of octets */
#define v22_W_ERRORS_OFF         10                 /* offset of error vector */
#define v22_W_PATN_OFF           12
#define v22_W_L4ID_OFF           12
#define v22_W_IPLEN_OFF          14
#define v22_W_FRAME_TYPE_OFF     16                 /* offset of frame type, 32 bits */
#define v22_W_RSSI_OFF           21                 /* RSSI (NOTE: RSSI must be negated!) */
#define v22_W_STARTT_OFF         24                 /* offset of start time, 64 bits */
#define v22_W_ENDT_OFF           32                 /* offset of end time, 64 bits */
#define v22_W_LATVAL_OFF         40                 /* offset of latency, 32 bits */
#define v22_W_INFO_OFF           54                 /* offset of INFO field, 16 LSBs */
#define v22_W_DIFFERENTIATOR_OFF 20                 /* offset to determine whether */
                                                    /*  eth/802.11, 32 bits */

#define v22_W_PLCP_LENGTH_OFF     4                 /* LENGTH field in the plcp header */


#define v22_W_MT_CCKL       0                       /* CCK modulation, long preamble */
#define v22_W_MT_CCKS       1                       /* CCK modulation, short preamble */
#define v22_W_MT_OFDM       2                       /* OFDM modulation */

#define v22_W_IS_TCP            0x00000040                  /* TCP bit in FRAME_TYPE field */
#define v22_W_IS_UDP            0x00000010                  /* UDP bit in FRAME_TYPE field */
#define v22_W_IS_ICMP           0x00000020                  /* ICMP bit in FRAME_TYPE field */
#define v22_W_IS_IGMP           0x00000080                  /* IGMP bit in FRAME_TYPE field */
#define v22_W_IS_QOS            0x80                        /* QoS bit in MTYPE field (WLAN only) */


#define v22_W_FCS_ERROR     0x0002                  /* FCS error flag in error vector */
#define v22_W_CRYPTO_ERR    0x1f00                  /* RX decrypt error flags */
#define v22_W_SIG_ERR       0x0004                  /* signature magic byte mismatch */
#define v22_W_PAYCHK_ERR    0x0008                  /* payload checksum failure */
#define v22_W_RETRY_ERR     0x0400                  /* excessive retries on TX failure */
#define v22_W_IS_RX         0x08                    /* TX/RX bit in STATS block */
#define v22_W_MT_MASK       0x07                    /* modulation type mask */
#define v22_W_VCID_MASK     0x01ff                  /* VC ID is only 9 bits */
#define v22_W_FLOW_VALID    0x40                    /* flow-is-valid flag (else force to 0) */
#define v22_W_DIFFERENTIATOR_MASK 0Xf0ff            /* mask to differentiate ethernet from */
                                                    /* 802.11 capture */

#define v22_W_RX_DECRYPTS   0x0007                  /* RX-frame-was-decrypted bits */
#define v22_W_TX_DECRYPTS   0x0007                  /* TX-frame-was-decrypted bits */

#define v22_W_WEPTYPE       0x0001                  /* WEP frame */
#define v22_W_TKIPTYPE      0x0002                  /* TKIP frame */
#define v22_W_CCMPTYPE      0x0004                  /* CCMP frame */

#define v22_W_HEADER_IS_RX  0x21
#define v22_W_HEADER_IS_TX  0x31

#define v22_W_FC_PROT_BIT   0x40                    /* Protected Frame bit in FC1 of frame */

#define v22_W_IS_ETHERNET   0x00100000              /* bits set in frame type if ethernet */
#define v22_W_IS_80211      0x7F000000              /* bits set in frame type if 802.11 */

/* definitions for VW510021 FPGA, WLAN format */
/* FORMAT:
    16 BYTE header
    8 bytes of stat block
    plcp stuff (11 bytes plcp + 1 byte pad)
    data
    remaining 48 bytes of stat block
*/
/* offsets in the stats block */
#define vVW510021_W_STATS_HEADER_LEN     8          /* length of stats block header at beginning of record data */
#define vVW510021_W_STATS_TRAILER_LEN   48          /* length of stats block trailer after the plcp portion*/
#define vVW510021_W_STARTT_OFF           0          /* offset of start time, 64 bits */
#define vVW510021_W_ENDT_OFF             8          /* offset of end time, 64 bits */
#define vVW510021_W_ERRORS_OFF          16          /* offset of error vector */
#define vVW510021_W_VALID_OFF           20          /* 2 Bytes with different validity bits */
#define vVW510021_W_INFO_OFF            22          /* offset of INFO field, 16 LSBs */
#define vVW510021_W_FRAME_TYPE_OFF      24
#define vVW510021_W_L4ID_OFF            28
#define vVW510021_W_IPLEN_OFF           30          /* offset of IP Total Length field */
#define vVW510021_W_FLOWSEQ_OFF         32          /* offset of signature sequence number */
#define vVW510021_W_FLOWID_OFF          33          /* offset of flow ID */
#define vVW510021_W_LATVAL_OFF          36          /* offset of delay/flowtimestamp, 32b */
#define vVW510021_W_DEBUG_OFF           40          /* offset of debug, 16 bits */
#define S2_W_FPGA_VERSION_OFF           44          /* offset of fpga version, 16 bits */
#define vVW510021_W_MATCH_OFF           47          /* offset of pattern match vector */

/* offsets in the header block */
#define vVW510021_W_HEADER_LEN          16          /* length of FRAME header */
#define vVW510021_W_RXTX_OFF             0          /* rxtx offset, cmd byte of header */
#define vVW510021_W_HEADER_VERSION_OFF   9          /* version, 2bytes */
#define vVW510021_MSG_LENGTH_OFF        10          /* MSG LENGTH, 2bytes */
#define vVW510021_W_DEVICE_TYPE_OFF      8          /* version, 2bytes */

/* offsets that occur right after the header */
#define vVW510021_W_AFTERHEADER_LEN      8          /* length of STATs info directly after header */
#define vVW510021_W_L1P_1_OFF            0          /* offset of 1st byte of layer one info */
#define vVW510021_W_L1P_2_OFF            1          /* offset of 2nd byte of layer one info */
#define vVW510021_W_MTYPE_OFF           vVW510021_W_L1P_2_OFF
#define vVW510021_W_PREAMBLE_OFF        vVW510021_W_L1P_1_OFF
#define vVW510021_W_RSSI_TXPOWER_OFF     2          /* RSSI (NOTE: RSSI must be negated!) */
#define vVW510021_W_MSDU_LENGTH_OFF      3          /* 7:0 of length, next byte 11:8 in top 4 bits */
#define vVW510021_W_BVCV_VALID_OFF       4          /* BV,CV Determine validaity of bssid and txpower */
#define vVW510021_W_VCID_OFF             6          /* offset of VC (client) ID */
#define vVW510021_W_PLCP_LENGTH_OFF     12          /* LENGTH field in the plcp header */

/* Masks and defines */
#define vVW510021_W_IS_BV               0x04        /* BV bit in STATS block */
#define vVW510021_W_IS_CV               0x02        /* BV bit in STATS block */
#define vVW510021_W_FLOW_VALID          0x8000      /* valid_off flow-is-valid flag (else 0) */
#define vVW510021_W_QOS_VALID           0x4000
#define vVW510021_W_HT_VALID            0x2000
#define vVW510021_W_L4ID_VALID          0x1000
#define vVW510021_W_PREAMBLE_MASK       0x40        /* short/long preamble/guard(ofdm) mask */
#define vVW510021_W_MCS_MASK            0x3f        /* mcs index (a/b) type mask */
#define vVW510021_W_MOD_SCHEME_MASK     0x3f        /* modulation type mask */
#define vVW510021_W_PLCPC_MASK          0x03        /* PLPCP type mask */
#define vVW510021_W_SEL_MASK            0x80
#define vVW510021_W_WEP_MASK            0x0001
#define vVW510021_W_CBW_MASK            0xC0

#define vVW510021_W_MT_SEL_LEGACY       0x00
#define vVW510021_W_PLCP_LEGACY         0x00
#define vVW510021_W_PLCP_MIXED          0x01
#define vVW510021_W_PLCP_GREENFIELD     0x02
#define vVW510021_W_PLCP_VHT_MIXED      0x03
#define vVW510021_W_HEADER_IS_RX        0x21
#define vVW510021_W_HEADER_IS_TX        0x31
#define vVW510021_W_IS_WEP              0x0001
#define vVW510021_W_IS_LONGPREAMBLE     0x40

#define vVW510021_W_IS_TCP          0x01000000                  /* TCP bit in FRAME_TYPE field */
#define vVW510021_W_IS_UDP          0x00100000                  /* UDP bit in FRAME_TYPE field */
#define vVW510021_W_IS_ICMP         0x00001000                  /* ICMP bit in FRAME_TYPE field */
#define vVW510021_W_IS_IGMP         0x00010000                  /* IGMP bit in FRAME_TYPE field */


#define vVW510021_W_HEADER_VERSION      0x00
#define vVW510021_W_DEVICE_TYPE         0x15
#define vVW510021_W_11n_DEVICE_TYPE     0x20
#define S2_W_FPGA_VERSION               0x000C
#define vVW510021_W_11n_FPGA_VERSION    0x000D

/* Error masks */
#define vVW510021_W_FCS_ERROR           0x01
#define vVW510021_W_CRYPTO_ERROR        0x50000

#define vVW510021_W_WEPTYPE             0x0001      /* WEP frame */
#define vVW510021_W_TKIPTYPE            0x0002      /* TKIP frame */
#define vVW510021_W_CCMPTYPE            0x0004      /* CCMP frame */

/* definitions for VW510024 FPGA, wired ethernet format */
/* FORMAT:
    16 BYTE header
    52 bytes of stats block trailer
*/
/* offsets in the stats block */
#define vVW510024_E_STATS_LEN           48          /* length of stats block trailer */
#define vVW510024_E_MSDU_LENGTH_OFF      0          /* MSDU 16 BITS */
#define vVW510024_E_BMCV_VALID_OFF       2          /* BM,CV Determine validITY */
#define vVW510024_E_VCID_OFF             2          /* offset of VC (client) ID 13:8, */
                                                    /*  7:0 IN offset 7*/
#define vVW510024_E_STARTT_OFF           4          /* offset of start time, 64 bits */
#define vVW510024_E_ENDT_OFF            12          /* offset of end time, 64 bits */
#define vVW510024_E_ERRORS_OFF          22          /* offset of error vector */
#define vVW510024_E_VALID_OFF           24          /* 2 Bytes with different validity bits */
#define vVW510024_E_INFO_OFF            26          /* offset of INFO field, 16 LSBs */
#define vVW510024_E_FRAME_TYPE_OFF      28
#define vVW510024_E_L4ID_OFF            32
#define vVW510024_E_IPLEN_OFF           34
#define vVW510024_E_FLOWSEQ_OFF         36          /* offset of signature sequence number */
#define vVW510024_E_FLOWID_OFF          37          /* offset of flow ID */
#define vVW510024_E_LATVAL_OFF          40          /* offset of delay/flowtimestamp, 32 bits */
#define vVW510024_E_FPGA_VERSION_OFF    20          /* offset of fpga version, 16 bits */
#define vVW510024_E_MATCH_OFF           51          /* offset of pattern match vector */

/* offsets in the header block */
#define vVW510024_E_HEADER_LEN          vVW510021_W_HEADER_LEN      /* length of FRAME header */
#define vVW510024_E_RXTX_OFF            vVW510021_W_RXTX_OFF        /* rxtx offset, cmd byte */
#define vVW510024_E_HEADER_VERSION_OFF  16                          /* version, 2bytes */
#define vVW510024_E_MSG_LENGTH_OFF      vVW510021_MSG_LENGTH_OFF    /* MSG LENGTH, 2bytes */
#define vVW510024_E_DEVICE_TYPE_OFF     vVW510021_W_DEVICE_TYPE_OFF /* Device Type, 2bytes */

/* Masks and defines */
#define vVW510024_E_IS_BV               0x80                    /* Bm bit in STATS block */
#define vVW510024_E_IS_CV               0x40                    /* cV bit in STATS block */
#define vVW510024_E_FLOW_VALID          0x8000                  /* valid_off flow-is-valid flag (else force to 0) */
#define vVW510024_E_QOS_VALID           0x0000                  /** not valid for ethernet **/
#define vVW510024_E_L4ID_VALID          0x1000
#define vVW510024_E_CBW_MASK            0xC0
#define vVW510024_E_VCID_MASK           0x3FFF

#define vVW510024_E_HEADER_IS_RX        0x21
#define vVW510024_E_HEADER_IS_TX        0x31

#define vVW510024_E_IS_TCP          0x01000000                  /* TCP bit in FRAME_TYPE field */
#define vVW510024_E_IS_UDP          0x00100000                  /* UDP bit in FRAME_TYPE field */
#define vVW510024_E_IS_ICMP         0x00001000                  /* ICMP bit in FRAME_TYPE field */
#define vVW510024_E_IS_IGMP         0x00010000
#define vVW510024_E_IS_VLAN         0x4000

#define vVW510024_E_HEADER_VERSION      0x00
#define vVW510024_E_DEVICE_TYPE         0x18
#define vVW510024_E_FPGA_VERSION        0x0001

#define FPGA_VER_NOT_APPLICABLE         0

#define UNKNOWN_FPGA                    0
#define S2_W_FPGA                       1
#define S1_W_FPGA                       2
#define vVW510012_E_FPGA                3
#define vVW510024_E_FPGA                4
#define S3_W_FPGA                       5

    /* the flow signature is:
    Byte Description
0   Magic Number (0xDD)
1   Chassis Number[7:0]
2   Slot Number[7:0]
3   Port Number[7:0]
4   Flow ID[7:0]
5   Flow ID[15:8]
6   Flow ID[23:16]
7   Flow Sequence Number[7:0]
8   Timestamp[7:0]
9   Timestamp[15:8]
10  Timestamp[23:16]
11  Timestamp[31:24]
12  Timestamp[39:32]
13  Timestamp[47:40]
14  CRC16
15  CRC16

*/
#define SIG_SIZE        16                           /* size of signature field, bytes     */
#define SIG_FID_OFF      4                           /* offset of flow ID in signature     */
#define SIG_FSQ_OFF      7                           /* offset of flow seqnum in signature */
#define SIG_TS_OFF       8                           /* offset of flow seqnum in signature */



/*--------------------------------------------------------------------------------------*/
/* Per-capture file private data structure */

typedef struct {
        /* offsets in stats block; these are dependent on the frame type (Ethernet/WLAN) and */
        /* version number of .vwr file, and are set up by setup_defaults() */
        guint32      STATS_LEN;                      /* length of stats block trailer */
        guint32      STATS_START_OFF;                /* STATS OFF AFTER HEADER */
        guint32      VALID_OFF;                      /* bit 6 (0x40) is flow-is-valid flag */
        guint32      MTYPE_OFF;                      /* offset of modulation type */
        guint32      VCID_OFF;                       /* offset of VC ID */
        guint32      FLOWSEQ_OFF;                    /* offset of signature sequence number */
        guint32      FLOWID_OFF;                     /* offset of flow ID */
        guint32      OCTET_OFF;                      /* offset of octets */
        guint32      ERRORS_OFF;                     /* offset of error vector */
        guint32      PATN_OFF;                       /* offset of pattern match vector */
        guint32      RSSI_OFF;                       /* RSSI (NOTE: RSSI must be negated!) */
        guint32      STARTT_OFF;                     /* offset of start time, 64 bits */
        guint32      ENDT_OFF;                       /* offset of end time, 64 bits */
        guint32      LATVAL_OFF;                     /* offset of latency, 32 bits */
        guint32      INFO_OFF;                       /* offset of INFO field, 16 bits */
        guint32      L1P_1_OFF;                      /* offset 1ST Byte of l1params */
        guint32      L1P_2_OFF;                      /* offset 2nd Byte of l1params */
        guint32      L4ID_OFF;                       /* LAYER 4 id offset*/
        guint32      IPLEN_OFF;                      /* */
        guint32      PLCP_LENGTH_OFF;                /* plcp length offset*/
        guint32      FPGA_VERSION_OFF;               /* offset of fpga version field, 16 bits */
        guint32      HEADER_VERSION_OFF;             /* offset of header version, 16 bits */
        guint32      RXTX_OFF;                       /* offset of CMD bit, rx or tx */
        guint32      FRAME_TYPE_OFF;

        /* other information about the file in question */
        guint32      MT_10_HALF;                     /* 10 Mb/s half-duplex */
        guint32      MT_10_FULL;                     /* 10 Mb/s full-duplex */
        guint32      MT_100_HALF;                    /* 100 Mb/s half-duplex */
        guint32      MT_100_FULL;                    /* 100 Mb/s full-duplex */
        guint32      MT_1G_HALF;                     /* 1 Gb/s half-duplex */
        guint32      MT_1G_FULL;                     /* 1 Gb/s full-duplex */
        guint32      FCS_ERROR;                      /* FCS error in frame */
        guint32      CRYPTO_ERR;                     /* RX decrypt error flags */
        guint32      PAYCHK_ERR;                     /* payload checksum failure */
        guint32      RETRY_ERR;                      /* excessive retries on TX failure */
        guint8       IS_RX;                          /* TX/RX bit in STATS block */
        guint8       MT_MASK;                        /* modulation type mask */
        guint16      VCID_MASK;                      /* VC ID is only 9 bits */
        guint32      FLOW_VALID;                     /* flow-is-valid flag (else force to 0) */
        guint16      QOS_VALID;
        guint32      RX_DECRYPTS;                    /* RX-frame-was-decrypted bits */
        guint32      TX_DECRYPTS;                    /* TX-frame-was-decrypted bits */
        guint32      FC_PROT_BIT;                    /* Protected Frame bit in FC1 of frame */
        guint32      MT_CCKL;                        /* CCK modulation, long preamble */
        guint32      MT_CCKS;                        /* CCK modulation, short preamble */
        guint32      MT_OFDM;                        /* OFDM modulation */
        guint32      MCS_INDEX_MASK;                 /* mcs index type mask */
        guint32      FPGA_VERSION;
        guint32      HEADER_IS_RX;
        guint32      HEADER_IS_TX;
        guint32      WEPTYPE;                        /* frame is WEP */
        guint32      TKIPTYPE;                       /* frame is TKIP */
        guint32      CCMPTYPE;                       /* frame is CCMP */
        guint32      IS_TCP;
        guint32      IS_UDP;
        guint32      IS_ICMP;
        guint32      IS_IGMP;
        guint16      IS_QOS;
        guint32      IS_VLAN;
        guint32      MPDU_OFF;
} vwr_t;

/* internal utility functions */
static int          decode_msg(vwr_t *vwr, register guint8 *, int *, int *);
static guint8       get_ofdm_rate(const guint8 *);
static guint8       get_cck_rate(const guint8 *plcp);
static void         setup_defaults(vwr_t *, guint16);

static gboolean     vwr_read(wtap *, int *, gchar **, gint64 *);
static gboolean     vwr_seek_read(wtap *, gint64, struct wtap_pkthdr *phdr,
                                  Buffer *, int *, gchar **);

static gboolean     vwr_read_rec_header(vwr_t *, FILE_T, int *, int *, int *, gchar **);
static gboolean     vwr_process_rec_data(FILE_T fh, int rec_size,
                                         struct wtap_pkthdr *phdr, Buffer *buf,
                                         vwr_t *vwr, int IS_TX, int *err,
                                         gchar **err_info);

static int          vwr_get_fpga_version(wtap *, int *, gchar **);

static gboolean     vwr_read_s1_W_rec(vwr_t *, struct wtap_pkthdr *, Buffer *,
                                      const guint8 *, int, int *, gchar **);
static gboolean     vwr_read_s2_W_rec(vwr_t *, struct wtap_pkthdr *, Buffer *,
                                      const guint8 *, int, int, int *,
                                      gchar **);
static gboolean     vwr_read_rec_data_ethernet(vwr_t *, struct wtap_pkthdr *,
                                               Buffer *, const guint8 *, int,
                                               int, int *, gchar **);

static int          find_signature(const guint8 *, int, int, register guint32, register guint8);
static guint64      get_signature_ts(const guint8 *, int);
static float        getRate( guint8 plcpType, guint8 mcsIndex, guint16 rflags, guint8 nss );

/* Open a .vwr file for reading */
/* This does very little, except setting the wiretap header for a VWR file type */
/*  and setting the timestamp precision to microseconds.                        */

int vwr_open(wtap *wth, int *err, gchar **err_info)
{
    int    fpgaVer;
    vwr_t *vwr;

    *err = 0;

    fpgaVer = vwr_get_fpga_version(wth, err, err_info);
    if (fpgaVer == -1) {
        return -1; /* I/O error */
    }
    if (fpgaVer == UNKNOWN_FPGA) {
        return 0; /* not a VWR file */
    }

    /* This is a vwr file */
    vwr = (vwr_t *)g_malloc0(sizeof(vwr_t));
    wth->priv = (void *)vwr;

    vwr->FPGA_VERSION = fpgaVer;
    /* set the local module options first */
    setup_defaults(vwr, fpgaVer);

    wth->snapshot_length = 0;
    wth->subtype_read = vwr_read;
    wth->subtype_seek_read = vwr_seek_read;
    wth->tsprecision = WTAP_FILE_TSPREC_USEC;
    wth->file_encap = WTAP_ENCAP_IXVERIWAVE;

    if (fpgaVer == S2_W_FPGA || fpgaVer == S1_W_FPGA || fpgaVer == S3_W_FPGA)
        wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_VWR_80211;
    else if (fpgaVer == vVW510012_E_FPGA || fpgaVer == vVW510024_E_FPGA)
        wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_VWR_ETH;

    return 1;
}


/* Read the next packet */
/* Note that the VWR file format consists of a sequence of fixed 16-byte record headers of */
/*  different types; some types, including frame record headers, are followed by           */
/*  variable-length data.                                                                  */
/* A frame record consists of: the above 16-byte record header, a 1-16384 byte raw PLCP    */
/*  frame, and a 64-byte statistics block trailer.                                         */
/* The PLCP frame consists of a 4-byte or 6-byte PLCP header, followed by the MAC frame    */

static gboolean vwr_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
    vwr_t *vwr      = (vwr_t *)wth->priv;
    int    rec_size = 0, IS_TX;

    /* read the next frame record header in the capture file; if no more frames, return */
    if (!vwr_read_rec_header(vwr, wth->fh, &rec_size, &IS_TX, err, err_info))
        return FALSE;                                   /* Read error or EOF */

    /*
     * We're past the header; return the offset of the header, not of
     * the data past the header.
     */
    *data_offset = (file_tell(wth->fh) - VW_RECORD_HEADER_LENGTH);

    /* got a frame record; read and process it */
    if (!vwr_process_rec_data(wth->fh, rec_size, &wth->phdr,
                              wth->frame_buffer, vwr, IS_TX, err, err_info))
       return FALSE;

    /* If the per-file encapsulation isn't known, set it to this packet's encapsulation. */
    /* If it *is* known, and it isn't this packet's encapsulation, set it to             */
    /*  WTAP_ENCAP_PER_PACKET, as this file doesn't have a single encapsulation for all  */
    /*  packets in the file.                                                             */
    if (wth->file_encap == WTAP_ENCAP_UNKNOWN)
        wth->file_encap = wth->phdr.pkt_encap;
    else {
        if (wth->file_encap != wth->phdr.pkt_encap)
            wth->file_encap = WTAP_ENCAP_PER_PACKET;
    }

    return TRUE;
}

/* read a random record in the middle of a file; the start of the record is @ seek_off */

static gboolean vwr_seek_read(wtap *wth, gint64 seek_off,
    struct wtap_pkthdr *phdr, Buffer *buf, int *err, gchar **err_info)
{
    vwr_t *vwr = (vwr_t *)wth->priv;
    int    rec_size, IS_TX;

    /* first seek to the indicated record header */
    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
        return FALSE;

    /* read in the record header */
    if (!vwr_read_rec_header(vwr, wth->random_fh, &rec_size, &IS_TX, err, err_info))
        return FALSE;                                  /* Read error or EOF */

    return vwr_process_rec_data(wth->random_fh, rec_size, phdr, buf,
                                vwr, IS_TX, err, err_info);
}

/* Scan down in the input capture file to find the next frame header.       */
/* Decode and skip over all non-frame messages that are in the way.         */
/* Return TRUE on success, FALSE on EOF or error.                           */
/* Also return the frame size in bytes and the "is transmitted frame" flag. */

static gboolean vwr_read_rec_header(vwr_t *vwr, FILE_T fh, int *rec_size, int *IS_TX, int *err, gchar **err_info)
{
    int     f_len, v_type;
    guint8  header[VW_RECORD_HEADER_LENGTH];

    errno = WTAP_ERR_CANT_READ;
    *rec_size = 0;

    /* Read out the file data in 16-byte messages, stopping either after we find a frame,  */
    /*  or if we run out of data.                                                          */
    /* Each 16-byte message is decoded; if we run across a non-frame message followed by a */
    /*  variable-length item, we read the variable length item out and discard it.         */
    /* If we find a frame, we return (with the header in the passed buffer).               */
    while (1) {
        if (file_read(header, VW_RECORD_HEADER_LENGTH, fh) != VW_RECORD_HEADER_LENGTH) {
            *err = file_error(fh, err_info);
            return FALSE;
        }

        /* Got a header; invoke decode-message function to parse and process it.     */
        /* If the function returns a length, then a frame or variable-length message */
        /*  follows the 16-byte message.                                             */
        /* If the variable length message is not a frame, simply skip over it.       */
        if ((f_len = decode_msg(vwr, header, &v_type, IS_TX)) != 0) {
            if (f_len > B_SIZE) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = g_strdup_printf("vwr: Invalid message record length %d", f_len);
                return FALSE;
            }
            else if (v_type != VT_FRAME) {
                if (file_seek(fh, f_len, SEEK_CUR, err) < 0)
                    return FALSE;
            }
            else {
                *rec_size = f_len;
                return TRUE;
            }
        }
    }
}

/* Figure out the FPGA version (and also see whether this is a VWR file type. */
/* Return FPGA version if it's a known version, UNKNOWN_FPGA if it's not,     */
/*  and -1 on an I/O error.                                                   */

static int vwr_get_fpga_version(wtap *wth, int *err, gchar **err_info)
{
    guint8   rec[B_SIZE];         /* local buffer (holds input record) */
    guint8   header[VW_RECORD_HEADER_LENGTH];
    int      rec_size     = 0;
    guint8   i;
    guint8  *s_510006_ptr = NULL;
    guint8  *s_510024_ptr = NULL;
    guint8  *s_510012_ptr = NULL; /* stats pointers */
    gint64   filePos      = -1;
    guint32  frame_type   = 0;
    int      f_len, v_type;
    guint16  data_length  = 0;
    guint16  fpga_version;
    int      valid_but_empty_file = -1;

    filePos = file_tell(wth->fh);
    if (filePos == -1) {
        *err = file_error(wth->fh, err_info);
        return -1;
    }

    fpga_version = 1000;
    /* Got a frame record; see if it is vwr  */
    /* If we don't get it all, then declare an error, we can't process the frame.          */
    /* Read out the file data in 16-byte messages, stopping either after we find a frame,  */
    /*  or if we run out of data.                                                          */
    /* Each 16-byte message is decoded; if we run across a non-frame message followed by a */
    /*  variable-length item, we read the variable length item out and discard it.         */
    /* If we find a frame, we return (with the header in the passed buffer).               */
    while ((file_read(header, VW_RECORD_HEADER_LENGTH, wth->fh)) == VW_RECORD_HEADER_LENGTH) {
        /* Got a header; invoke decode-message function to parse and process it.     */
        /* If the function returns a length, then a frame or variable-length message */
        /*  follows the 16-byte message.                                             */
        /* If the variable length message is not a frame, simply skip over it.       */
        if ((f_len = decode_msg(NULL, header, &v_type, NULL)) != 0) {
            if (f_len > B_SIZE) {
                /* Treat this here as an indication that the file probably */
                /*  isn't a vwr file. */
                return UNKNOWN_FPGA;
            }
            else if (v_type != VT_FRAME) {
                if (file_seek(wth->fh, f_len, SEEK_CUR, err) < 0)
                    return -1;
                else if (v_type == VT_CPMSG)
                    valid_but_empty_file = 1;
            }
            else {
                rec_size = f_len;
                /* Got a frame record; read over entire record (frame + trailer) into a local buffer */
                /* If we don't get it all, assume this isn't a vwr file */
                if (file_read(rec, rec_size, wth->fh) != rec_size) {
                    *err = file_error(wth->fh, err_info);
                    if (*err != 0 && *err != WTAP_ERR_SHORT_READ)
                        return -1;
                    return UNKNOWN_FPGA; /* short read - not a vwr file */
                }


                /*  I'll grab the bytes where the Ethernet "octets" field should be and the bytes where */
                /*   the 802.11 "octets" field should be. Then if I do rec_size - octets -              */
                /*   size_of_stats_block and it's 0, I can select the correct type.                     */
                /*  octets + stats_len = rec_size only when octets have been incremented to nearest     */
                /*   number divisible by 4.                                                             */

                /* First check for series I WLAN since the check is more rigorous. */
                if (rec_size > v22_W_STATS_LEN) {
                    s_510006_ptr = &(rec[rec_size - v22_W_STATS_LEN]);      /* point to 510006 WLAN */
                                                                            /* stats block */

                    data_length = pntoh16(&s_510006_ptr[v22_W_OCTET_OFF]);
                    i = 0;
                    while (((data_length + i) % 4) != 0)
                        i = i + 1;

                    frame_type = pntoh32(&s_510006_ptr[v22_W_FRAME_TYPE_OFF]);

                    if (rec_size == (data_length + v22_W_STATS_LEN + i) && (frame_type & v22_W_IS_80211) == 0x1000000) {
                        fpga_version = S1_W_FPGA;
                    }
                }

                /* Next for the series I Ethernet */
                if ((rec_size > v22_E_STATS_LEN) && (fpga_version == 1000)) {
                    s_510012_ptr = &(rec[rec_size - v22_E_STATS_LEN]);      /* point to 510012 enet */
                                                                            /* stats block */
                    data_length = pntoh16(&s_510012_ptr[v22_E_OCTET_OFF]);
                    i = 0;
                    while (((data_length + i) % 4) != 0)
                        i = i + 1;

                    if (rec_size == (data_length + v22_E_STATS_LEN + i))
                        fpga_version = vVW510012_E_FPGA;
                }


                /* Next the series II WLAN */
                if ((rec_size > vVW510021_W_STATS_TRAILER_LEN) && (fpga_version == 1000)) {
                    /* stats block */

                    data_length = (256 * (rec[vVW510021_W_MSDU_LENGTH_OFF + 1] & 0x1f)) + rec[vVW510021_W_MSDU_LENGTH_OFF];

                    i = 0;
                    while (((data_length + i) % 4) != 0)
                        i = i + 1;

                    /*the 12 is from the 12 bytes of plcp header */
                    if (rec_size == (data_length + vVW510021_W_STATS_TRAILER_LEN +vVW510021_W_AFTERHEADER_LEN+12+i))
                        fpga_version = S2_W_FPGA;
                }

                /* Finally the Series II Ethernet */
                if ((rec_size > vVW510024_E_STATS_LEN) && (fpga_version == 1000)) {
                    s_510024_ptr = &(rec[rec_size - vVW510024_E_STATS_LEN]);    /* point to 510024 ENET */
                    data_length = pntoh16(&s_510024_ptr[vVW510024_E_MSDU_LENGTH_OFF]);

                    i = 0;
                    while (((data_length + i) % 4) != 0)
                        i = i + 1;

                    if (rec_size == (data_length + vVW510024_E_STATS_LEN + i))
                        fpga_version = vVW510024_E_FPGA;
                }
                if ((rec_size > vVW510021_W_STATS_TRAILER_LEN) && (fpga_version == 1000)) {
                    /* Check the version of the FPGA */
                    if (header[8] == 48)
                        fpga_version = S3_W_FPGA;
                }
                if (fpga_version != 1000)
                {
                    /* reset the file position offset */
                    if (file_seek (wth->fh, filePos, SEEK_SET, err) == -1) {
                        return (-1);
                    }
                    /* We found an FPGA that works */
                    return fpga_version;
                }
            }
        }
    }

    /* Is this a valid but empty file?  If so, claim it's the S3_W_FPGA FPGA. */
    if (valid_but_empty_file > 0)
        return(S3_W_FPGA);

    *err = file_error(wth->fh, err_info);
    if (*err != 0 && *err != WTAP_ERR_SHORT_READ)
        return -1;
    return UNKNOWN_FPGA; /* short read - not a vwr file */
}

/* Copy the actual packet data from the capture file into the target data block. */
/* The packet is constructed as a 38-byte VeriWave metadata header plus the raw */
/*  MAC octets. */

static gboolean vwr_read_s1_W_rec(vwr_t *vwr, struct wtap_pkthdr *phdr,
                                  Buffer *buf, const guint8 *rec, int rec_size,
                                  int *err, gchar **err_info)
{
    guint8           *data_ptr;
    int              bytes_written = 0;                   /* bytes output to buf so far */
    const guint8     *s_ptr, *m_ptr;                      /* stats pointer */
    guint16          msdu_length, actual_octets;          /* octets in frame */
    guint16          plcp_hdr_len;                        /* PLCP header length */
    guint16          rflags;
    guint8           m_type;                              /* mod type (CCK-L/CCK-S/OFDM), seqnum */
    guint            flow_seq;
    guint64          s_time = LL_ZERO, e_time = LL_ZERO;  /* start/end */
                                                          /* times, nsec */
    guint32          latency;
    guint64          start_time, s_sec, s_usec = LL_ZERO; /* start time, sec + usec */
    guint64          end_time;                            /* end time */
    guint32          info;                                /* INFO/ERRORS fields in stats blk */
    gint8            rssi;                                /* RSSI, signed 8-bit number */
    int              f_tx;                                /* flag: if set, is a TX frame */
    guint8           plcp_type, mcs_index, nss;           /* PLCP type 0: Legacy, 1: Mixed, 2: Green field, 3: VHT Mixed */
    guint16          vc_id, ht_len=0;                     /* VC ID, total ip length */
    guint            flow_id;                             /* flow ID */
    guint32          d_time, errors;                      /* packet duration & errors */
    int              sig_off, pay_off;                    /* MAC+SNAP header len, signature offset */
    guint64          sig_ts;                              /* 32 LSBs of timestamp in signature */
    guint16          phyRate;
    guint16          vw_flags;                            /* VeriWave-specific packet flags */

    /*
     * The record data must be large enough to hold the statistics trailer.
     */
    if (rec_size < v22_W_STATS_LEN) {
        *err_info = g_strdup_printf("vwr: Invalid record length %d (must be at least %u)",
                                    rec_size, v22_W_STATS_LEN);
        *err = WTAP_ERR_BAD_FILE;
        return FALSE;
    }

    /* Calculate the start of the statistics block in the buffer */
    /* Also get a bunch of fields from the stats block */
    s_ptr    = &(rec[rec_size - v22_W_STATS_LEN]); /* point to it */
    m_type   = s_ptr[v22_W_MTYPE_OFF] & 0x7;
    f_tx     = !(s_ptr[v22_W_MTYPE_OFF] & 0x8);
    actual_octets   = pntoh16(&s_ptr[v22_W_OCTET_OFF]);
    vc_id    = pntoh16(&s_ptr[v22_W_VCID_OFF]) & 0x3ff;
    flow_seq = s_ptr[v22_W_FLOWSEQ_OFF];

    latency = (guint32)pcorey48tohll(&s_ptr[v22_W_LATVAL_OFF]);

    flow_id = pntoh16(&s_ptr[v22_W_FLOWID_OFF+1]);  /* only 16 LSBs kept */
    errors  = pntoh16(&s_ptr[v22_W_ERRORS_OFF]);

    info = pntoh16(&s_ptr[v22_W_INFO_OFF]);
    rssi = (s_ptr[v22_W_RSSI_OFF] & 0x80) ? (-1 * (s_ptr[v22_W_RSSI_OFF] & 0x7f)) : s_ptr[v22_W_RSSI_OFF];

    /*
     * Sanity check the octets field to determine if it's greater than
     * the packet data available in the record - i.e., the record size
     * minus the length of the statistics block.
     *
     * Report an error if it is.
     */
    if (actual_octets > rec_size - v22_W_STATS_LEN) {
        *err_info = g_strdup_printf("vwr: Invalid data length %u (runs past the end of the record)",
                                    actual_octets);
        *err = WTAP_ERR_BAD_FILE;
        return FALSE;
    }

    /* Decode OFDM or CCK PLCP header and determine rate and short preamble flag. */
    /* The SIGNAL byte is always the first byte of the PLCP header in the frame.  */
    plcp_type = 0;
    nss = 1;
    if (m_type == vwr->MT_OFDM)
        mcs_index = get_ofdm_rate(rec);
    else if ((m_type == vwr->MT_CCKL) || (m_type == vwr->MT_CCKS))
        mcs_index = get_cck_rate(rec);
    else
        mcs_index = 1;
    rflags  = (m_type == vwr->MT_CCKS) ? FLAGS_SHORTPRE : 0;
    /* Calculate the MPDU size/ptr stuff; MPDU starts at 4 or 6 depending on OFDM/CCK. */
    /* Note that the number of octets in the frame also varies depending on OFDM/CCK,  */
    /*  because the PLCP header is prepended to the actual MPDU.                       */
    plcp_hdr_len = (m_type == vwr->MT_OFDM) ? 4 : 6;
    if (actual_octets >= plcp_hdr_len)
       actual_octets -= plcp_hdr_len;
    else {
        *err_info = g_strdup_printf("vwr: Invalid data length %u (too short to include %u-byte PLCP header)",
                                    actual_octets, plcp_hdr_len);
        *err = WTAP_ERR_BAD_FILE;
        return FALSE;
    }
    m_ptr = &rec[plcp_hdr_len];
    msdu_length = actual_octets;

    /*
     * The MSDU length includes the FCS.
     *
     * The packet data does *not* include the FCS - it's just 4 bytes
     * of junk - so we have to remove it.
     *
     * We'll be stripping off an FCS (?), so make sure we have at
     * least 4 octets worth of FCS.
     */
    if (actual_octets < 4) {
        *err_info = g_strdup_printf("vwr: Invalid data length %u (too short to include %u-byte PLCP header and 4 bytes of FCS)",
                                    actual_octets, plcp_hdr_len);
        *err = WTAP_ERR_BAD_FILE;
        return FALSE;
    }
    actual_octets -= 4;

    /* Calculate start & end times (in sec/usec), converting 64-bit times to usec. */
    /* 64-bit times are "Corey-endian" */
    s_time = pcoreytohll(&s_ptr[v22_W_STARTT_OFF]);
    e_time = pcoreytohll(&s_ptr[v22_W_ENDT_OFF]);

    /* find the packet duration (difference between start and end times) */
    d_time = (guint32)((e_time - s_time) / NS_IN_US);   /* find diff, converting to usec */

    /* also convert the packet start time to seconds and microseconds */
    start_time = s_time / NS_IN_US;                /* convert to microseconds first  */
    s_sec      = (start_time / US_IN_SEC);         /* get the number of seconds      */
    s_usec     = start_time - (s_sec * US_IN_SEC); /* get the number of microseconds */

    /* also convert the packet end time to seconds and microseconds */
    end_time = e_time / NS_IN_US;                       /* convert to microseconds first */

    /* extract the 32 LSBs of the signature timestamp field from the data block*/
    pay_off = 42;    /* 24 (MAC) + 8 (SNAP) + IP */
    sig_off = find_signature(m_ptr, rec_size - 6, pay_off, flow_id, flow_seq);
    if ((m_ptr[sig_off] == 0xdd) && (sig_off + 15 <= (rec_size - v22_W_STATS_LEN)))
        sig_ts = get_signature_ts(m_ptr, sig_off);
    else
        sig_ts = 0;

    /*
     * Fill up the per-packet header.
     *
     * We include the length of the metadata headers in the packet lengths.
     */
    phdr->len = STATS_COMMON_FIELDS_LEN + EXT_WLAN_FIELDS_LEN + actual_octets;
    phdr->caplen = STATS_COMMON_FIELDS_LEN + EXT_WLAN_FIELDS_LEN + actual_octets;

    phdr->ts.secs   = (time_t)s_sec;
    phdr->ts.nsecs  = (int)(s_usec * 1000);
    phdr->pkt_encap = WTAP_ENCAP_IXVERIWAVE;

    phdr->rec_type = REC_TYPE_PACKET;
    phdr->presence_flags = WTAP_HAS_TS;

    buffer_assure_space(buf, phdr->caplen);
    data_ptr = buffer_start_ptr(buf);

    /*
     * Generate and copy out the common metadata headers,
     * set the port type to 0 (WLAN).
     *
     * All values are copied out in little-endian byte order.
     */
    phtoles(&data_ptr[bytes_written], 0); /* port_type */
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], STATS_COMMON_FIELDS_LEN); /* it_len */
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], msdu_length);
    bytes_written += 2;
    phtolel(&data_ptr[bytes_written], flow_id);
    bytes_written += 4;
    phtoles(&data_ptr[bytes_written], vc_id);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], flow_seq);
    bytes_written += 2;
    if (!f_tx && sig_ts != 0) {
        phtolel(&data_ptr[bytes_written], latency);
    } else {
        phtolel(&data_ptr[bytes_written], 0);
    }
    bytes_written += 4;
    phtolel(&data_ptr[bytes_written], sig_ts); /* 32 LSBs of signature timestamp (nsec) */
    bytes_written += 4;
    phtolell(&data_ptr[bytes_written], start_time); /* record start & end times of frame */
    bytes_written += 8;
    phtolell(&data_ptr[bytes_written], end_time);
    bytes_written += 8;
    phtolel(&data_ptr[bytes_written], d_time);
    bytes_written += 4;

    /*
     * Generate and copy out the WLAN metadata headers.
     *
     * All values are copied out in little-endian byte order.
     */
    phtoles(&data_ptr[bytes_written], EXT_WLAN_FIELDS_LEN);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], rflags);
    bytes_written += 2;
    if (m_type == vwr->MT_OFDM) {
        phtoles(&data_ptr[bytes_written], CHAN_OFDM);
    } else {
        phtoles(&data_ptr[bytes_written], CHAN_CCK);
    }
    bytes_written += 2;
    phyRate = (guint16)(getRate(plcp_type, mcs_index, rflags, nss) * 10);
    phtoles(&data_ptr[bytes_written], phyRate);
    bytes_written += 2;
    data_ptr[bytes_written] = plcp_type;
    bytes_written += 1;
    data_ptr[bytes_written] = mcs_index;
    bytes_written += 1;
    data_ptr[bytes_written] = nss;
    bytes_written += 1;
    data_ptr[bytes_written] = rssi;
    bytes_written += 1;
    /* antennae b, c, d signal power */
    data_ptr[bytes_written] = 100;
    bytes_written += 1;
    data_ptr[bytes_written] = 100;
    bytes_written += 1;
    data_ptr[bytes_written] = 100;
    bytes_written += 1;
    /* padding */
    data_ptr[bytes_written] = 0;
    bytes_written += 1;

    /* fill in the VeriWave flags field */
    vw_flags = 0;
    if (f_tx)
        vw_flags |= VW_FLAGS_TXF;
    if (errors & vwr->FCS_ERROR)
        vw_flags |= VW_FLAGS_FCSERR;
    if (!f_tx && (errors & vwr->CRYPTO_ERR))
        vw_flags |= VW_FLAGS_DCRERR;
    if (!f_tx && (errors & vwr->RETRY_ERR))
        vw_flags |= VW_FLAGS_RETRERR;
    if (info & vwr->WEPTYPE)
        vw_flags |= VW_FLAGS_IS_WEP;
    else if (info & vwr->TKIPTYPE)
        vw_flags |= VW_FLAGS_IS_TKIP;
    else if (info & vwr->CCMPTYPE)
        vw_flags |= VW_FLAGS_IS_CCMP;
    phtoles(&data_ptr[bytes_written], vw_flags);
    bytes_written += 2;

    phtoles(&data_ptr[bytes_written], ht_len);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], info);
    bytes_written += 2;
    phtolel(&data_ptr[bytes_written], errors);
    bytes_written += 4;

    /*
     * Finally, copy the whole MAC frame to the packet buffer as-is.
     * This does not include the PLCP; the MPDU starts at 4 or 6
     * depending on OFDM/CCK.
     * This also does not include the last 4 bytes, as those don't
     * contain an FCS, they just contain junk.
     */
    memcpy(&data_ptr[bytes_written], &rec[plcp_hdr_len], actual_octets);

    return TRUE;
}


static gboolean vwr_read_s2_W_rec(vwr_t *vwr, struct wtap_pkthdr *phdr,
                                  Buffer *buf, const guint8 *rec, int rec_size,
                                  int IS_TX, int *err, gchar **err_info)
{
    guint8           *data_ptr;
    int              bytes_written = 0;                   /* bytes output to buf so far */
    register int     i;                                   /* temps */
    const guint8     *s_start_ptr,*s_trail_ptr, *plcp_ptr, *m_ptr; /* stats & MPDU ptr */
    guint32          msdu_length, actual_octets;          /* octets in frame */
    guint8           l1p_1,l1p_2, plcp_type, mcs_index, nss;   /* mod (CCK-L/CCK-S/OFDM) */
    guint            flow_seq;
    guint64          s_time = LL_ZERO, e_time = LL_ZERO;  /* start/end */
                                                          /*  times, nsec */
    guint64          latency = LL_ZERO;
    guint64          start_time, s_sec, s_usec = LL_ZERO; /* start time, sec + usec */
    guint64          end_time;                            /* end time */
    guint16          info;                                /* INFO/ERRORS fields in stats blk */
    guint32          errors;
    gint8            rssi[] = {0,0,0,0};                  /* RSSI, signed 8-bit number */
    int              f_tx;                                /* flag: if set, is a TX frame */
    guint16          vc_id, ht_len=0;                     /* VC ID , total ip length*/
    guint32          flow_id, d_time;                     /* flow ID, packet duration*/
    int              sig_off, pay_off;                    /* MAC+SNAP header len, signature offset */
    guint64          sig_ts, tsid;                        /* 32 LSBs of timestamp in signature */
    guint16          chanflags = 0;                       /* channel flags for WLAN metadata header */
    guint16          radioflags = 0;                      /* flags for WLAN metadata header */
    guint64          delta_b;                             /* Used for calculating latency */
    guint16          phyRate;
    guint16          vw_flags;                            /* VeriWave-specific packet flags */

    /*
     * The record data must be large enough to hold the statistics header
     * and the statistics trailer.
     */
    if (rec_size < vVW510021_W_STATS_HEADER_LEN + vVW510021_W_STATS_TRAILER_LEN) {
        *err_info = g_strdup_printf("vwr: Invalid record length %d (must be at least %u)",
                                    rec_size,
                                    vVW510021_W_STATS_HEADER_LEN + vVW510021_W_STATS_TRAILER_LEN);
        *err = WTAP_ERR_BAD_FILE;
        return FALSE;
    }

    /* Calculate the start of the statistics blocks in the buffer */
    /* Also get a bunch of fields from the stats blocks */
    s_start_ptr = &(rec[0]);                              /* point to stats header */
    s_trail_ptr = &(rec[rec_size - vVW510021_W_STATS_TRAILER_LEN]);      /* point to stats trailer */

    /* L1p info is different for series III and for Series II - need to check */
    l1p_1 = s_start_ptr[vVW510021_W_L1P_1_OFF];
    l1p_2 = s_start_ptr[vVW510021_W_L1P_2_OFF];
    if (vwr->FPGA_VERSION == S2_W_FPGA)
    {
        mcs_index = l1p_1 & 0x3f;
        plcp_type = l1p_2 & 0x03;
        /* we do the range checks at the end before copying the values
           into the wtap header */
        msdu_length = ((s_start_ptr[vVW510021_W_MSDU_LENGTH_OFF+1] & 0x1f) << 8)
	                + s_start_ptr[vVW510021_W_MSDU_LENGTH_OFF];

        vc_id = pntoh16(&s_start_ptr[vVW510021_W_VCID_OFF]);
        if (IS_TX)
        {
            rssi[0] = (s_start_ptr[vVW510021_W_RSSI_TXPOWER_OFF] & 0x80) ?
	               -1 * (s_start_ptr[vVW510021_W_RSSI_TXPOWER_OFF] & 0x7f) :
		       s_start_ptr[vVW510021_W_RSSI_TXPOWER_OFF] & 0x7f;
        }
        else
        {
            rssi[0] = (s_start_ptr[vVW510021_W_RSSI_TXPOWER_OFF] & 0x80) ?
	              (s_start_ptr[vVW510021_W_RSSI_TXPOWER_OFF]- 256) :
		      s_start_ptr[vVW510021_W_RSSI_TXPOWER_OFF];
        }
        rssi[1] = 100;
        rssi[2] = 100;
        rssi[3] = 100;

        nss = 0;
        plcp_ptr = &(rec[8]);
    }
    else
    {
        plcp_type = l1p_2 & 0xf;
        if (plcp_type == vVW510021_W_PLCP_VHT_MIXED)
        {
            mcs_index = l1p_1 & 0x0f;
            nss = (l1p_1 >> 4 & 0x3) + 1; /* The nss is zero based from the fpga - increment it here */
        }
        else
        {
            mcs_index = l1p_1 & 0x3f;
            nss = 0;
        }
        msdu_length = pntoh24(&s_start_ptr[9]);
        vc_id = pntoh16(&s_start_ptr[14]) & 0x3ff;
        for (i = 0; i < 4; i++)
        {
            if (IS_TX)
            {
                rssi[i] = (s_start_ptr[4+i] & 0x80) ? -1 * (s_start_ptr[4+i] & 0x7f) : s_start_ptr[4+i] & 0x7f;
            }
            else
            {
                rssi[i] = (s_start_ptr[4+i] >= 128) ? (s_start_ptr[4+i] - 256) : s_start_ptr[4+i];
            }
        }

        plcp_ptr = &(rec[16]);
    }
    actual_octets = msdu_length;

    /*
     * Sanity check the octets field to determine if it's greater than
     * the packet data available in the record - i.e., the record size
     * minus the sum of (length of statistics header + PLCP) and
     * (length of statistics trailer).
     *
     * Report an error if it is.
     */
    if (actual_octets > rec_size - (vwr->MPDU_OFF + vVW510021_W_STATS_TRAILER_LEN)) {
        *err_info = g_strdup_printf("vwr: Invalid data length %u (runs past the end of the record)",
                                    actual_octets);
        *err = WTAP_ERR_BAD_FILE;
        return FALSE;
    }

    f_tx = IS_TX;
    flow_seq = s_trail_ptr[vVW510021_W_FLOWSEQ_OFF];

    latency = 0x00000000;                        /* clear latency */
    flow_id = pntoh24(&s_trail_ptr[vVW510021_W_FLOWID_OFF]);         /* all 24 bits valid */
    /* For tx latency is duration, for rx latency is timestamp */
    /* Get 48-bit latency value */
    tsid = pcorey48tohll(&s_trail_ptr[vVW510021_W_LATVAL_OFF]);

    errors = pntoh32(&s_trail_ptr[vVW510021_W_ERRORS_OFF]);
    info = pntoh16(&s_trail_ptr[vVW510021_W_INFO_OFF]);
    if ((info & 0xFC00) != 0)
    /* this length includes the Start_Spacing + Delimiter + MPDU + Padding for each piece of the aggregate*/
        ht_len = pletoh16(&s_start_ptr[vwr->PLCP_LENGTH_OFF]);


    /* decode OFDM or CCK PLCP header and determine rate and short preamble flag */
    /* the SIGNAL byte is always the first byte of the PLCP header in the frame */
    if (plcp_type == vVW510021_W_PLCP_LEGACY){
        if (mcs_index < 4) {
            chanflags |= CHAN_CCK;
        }
        else {
            chanflags |= CHAN_OFDM;
        }
    }
    else if (plcp_type == vVW510021_W_PLCP_MIXED) {
        /* set the appropriate flags to indicate HT mode and CB */
        radioflags |= FLAGS_CHAN_HT | ((plcp_ptr[3] & 0x80) ? FLAGS_CHAN_40MHZ : 0) |
                      ((l1p_1 & 0x40) ? 0 : FLAGS_CHAN_SHORTGI);
        chanflags  |= CHAN_OFDM;
    }
    else if (plcp_type == vVW510021_W_PLCP_GREENFIELD) {
        /* set the appropriate flags to indicate HT mode and CB */
        radioflags |= FLAGS_CHAN_HT | ((plcp_ptr[0] & 0x80) ? FLAGS_CHAN_40MHZ : 0) |
                      ((l1p_1 & 0x40) ?  0 : FLAGS_CHAN_SHORTGI);
        chanflags  |= CHAN_OFDM;
    }
    else if (plcp_type == vVW510021_W_PLCP_VHT_MIXED) {
        guint8 SBW = l1p_2 >> 4 & 0xf;
        radioflags |= FLAGS_CHAN_VHT | ((l1p_1 & 0x40) ?  0 : FLAGS_CHAN_SHORTGI);
        chanflags |= CHAN_OFDM;
        if (SBW == 3)
            radioflags |= FLAGS_CHAN_40MHZ;
        else if (SBW == 4)
            radioflags |= FLAGS_CHAN_80MHZ;
    }

    /*
     * The MSDU length includes the FCS.
     *
     * The packet data does *not* include the FCS - it's just 4 bytes
     * of junk - so we have to remove it.
     *
     * We'll be stripping off an FCS (?), so make sure we have at
     * least 4 octets worth of FCS.
     */
    if (actual_octets < 4) {
        *err_info = g_strdup_printf("vwr: Invalid data length %u (too short to include 4 bytes of FCS)",
                                    actual_octets);
        *err = WTAP_ERR_BAD_FILE;
        return FALSE;
    }
    actual_octets -= 4;

    /* Calculate start & end times (in sec/usec), converting 64-bit times to usec. */
    /* 64-bit times are "Corey-endian" */
    s_time = pcoreytohll(&s_trail_ptr[vVW510021_W_STARTT_OFF]);
    e_time = pcoreytohll(&s_trail_ptr[vVW510021_W_ENDT_OFF]);

    /* find the packet duration (difference between start and end times) */
    d_time = (guint32)((e_time - s_time) / NS_IN_US);  /* find diff, converting to usec */

    /* also convert the packet start time to seconds and microseconds */
    start_time = s_time / NS_IN_US;                     /* convert to microseconds first */
    s_sec = (start_time / US_IN_SEC);                   /* get the number of seconds */
    s_usec = start_time - (s_sec * US_IN_SEC);          /* get the number of microseconds */

    /* also convert the packet end time to seconds and microseconds */
    end_time = e_time / NS_IN_US;                       /* convert to microseconds first */

    /* extract the 32 LSBs of the signature timestamp field */
    m_ptr = &(rec[8+12]);
    pay_off = 42;         /* 24 (MAC) + 8 (SNAP) + IP */
    sig_off = find_signature(m_ptr, rec_size - 20, pay_off, flow_id, flow_seq);
    if ((m_ptr[sig_off] == 0xdd) && (sig_off + 15 <= (rec_size - vVW510021_W_STATS_TRAILER_LEN)))
        sig_ts = get_signature_ts(m_ptr, sig_off);
    else
        sig_ts = 0;

    /* Set latency based on rx/tx and signature timestamp */
    if (!IS_TX) {
        if (tsid < s_time) {
            latency = s_time - tsid;
          } else {
            /* Account for the rollover case. Since we cannot use 0x100000000 - l_time + s_time */
            /* we look for a large difference between l_time and s_time. */
            delta_b = tsid - s_time;
            if (delta_b >  0x10000000)
              latency = 0;
            else
              latency = delta_b;
          }
    }

    /*
     * Fill up the per-packet header.
     *
     * We include the length of the metadata headers in the packet lengths.
     */
    phdr->len = STATS_COMMON_FIELDS_LEN + EXT_WLAN_FIELDS_LEN + actual_octets;
    phdr->caplen = STATS_COMMON_FIELDS_LEN + EXT_WLAN_FIELDS_LEN + actual_octets;

    phdr->ts.secs   = (time_t)s_sec;
    phdr->ts.nsecs  = (int)(s_usec * 1000);
    phdr->pkt_encap = WTAP_ENCAP_IXVERIWAVE;

    phdr->rec_type = REC_TYPE_PACKET;
    phdr->presence_flags = WTAP_HAS_TS;

    buffer_assure_space(buf, phdr->caplen);
    data_ptr = buffer_start_ptr(buf);

    /*
     * Generate and copy out the common metadata headers,
     * set the port type to 0 (WLAN).
     *
     * All values are copied out in little-endian byte order.
     */
    phtoles(&data_ptr[bytes_written], 0); /* port_type */
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], STATS_COMMON_FIELDS_LEN); /* it_len */
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], msdu_length);
    bytes_written += 2;
    phtolel(&data_ptr[bytes_written], flow_id);
    bytes_written += 4;
    phtoles(&data_ptr[bytes_written], vc_id);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], flow_seq);
    bytes_written += 2;
    if (!f_tx && sig_ts != 0) {
        phtolel(&data_ptr[bytes_written], latency);
    } else {
        phtolel(&data_ptr[bytes_written], 0);
    }
    bytes_written += 4;
    phtolel(&data_ptr[bytes_written], sig_ts); /* 32 LSBs of signature timestamp (nsec) */
    bytes_written += 4;
    phtolell(&data_ptr[bytes_written], start_time); /* record start & end times of frame */
    bytes_written += 8;
    phtolell(&data_ptr[bytes_written], end_time);
    bytes_written += 8;
    phtolel(&data_ptr[bytes_written], d_time);
    bytes_written += 4;

    /*
     * Generate and copy out the WLAN metadata headers.
     *
     * All values are copied out in little-endian byte order.
     */
    phtoles(&data_ptr[bytes_written], EXT_WLAN_FIELDS_LEN);
    bytes_written += 2;
    if (info & vVW510021_W_IS_WEP)
        radioflags |= FLAGS_WEP;
    if ((l1p_1 & vVW510021_W_PREAMBLE_MASK) != vVW510021_W_IS_LONGPREAMBLE && (plcp_type == vVW510021_W_PLCP_LEGACY))
        radioflags |= FLAGS_SHORTPRE;
    phtoles(&data_ptr[bytes_written], radioflags);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], chanflags);
    bytes_written += 2;
    phyRate = (guint16)(getRate(plcp_type, mcs_index, radioflags, nss) * 10);
    phtoles(&data_ptr[bytes_written], phyRate);
    bytes_written += 2;
    data_ptr[bytes_written] = plcp_type;
    bytes_written += 1;
    data_ptr[bytes_written] = mcs_index;
    bytes_written += 1;
    data_ptr[bytes_written] = nss;
    bytes_written += 1;
    data_ptr[bytes_written] = rssi[0];
    bytes_written += 1;
    data_ptr[bytes_written] = rssi[1];
    bytes_written += 1;
    data_ptr[bytes_written] = rssi[2];
    bytes_written += 1;
    data_ptr[bytes_written] = rssi[3];
    bytes_written += 1;
    /* padding */
    data_ptr[bytes_written] = 0;
    bytes_written += 1;

    /* fill in the VeriWave flags field */
    vw_flags  = 0;
    if (f_tx)
        vw_flags |= VW_FLAGS_TXF;
    if (errors & 0x1f)  /* If any error is flagged, then set the FCS error bit */
        vw_flags |= VW_FLAGS_FCSERR;
    if (!f_tx && (errors & vwr->CRYPTO_ERR))
        vw_flags |= VW_FLAGS_DCRERR;
    if (!f_tx && (errors & vwr->RETRY_ERR))
        vw_flags |= VW_FLAGS_RETRERR;
    if (info & vwr->WEPTYPE)
        vw_flags |= VW_FLAGS_IS_WEP;
    else if (info & vwr->TKIPTYPE)
        vw_flags |= VW_FLAGS_IS_TKIP;
    else if (info & vwr->CCMPTYPE)
        vw_flags |= VW_FLAGS_IS_CCMP;
    phtoles(&data_ptr[bytes_written], vw_flags);
    bytes_written += 2;

    phtoles(&data_ptr[bytes_written], ht_len);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], info);
    bytes_written += 2;
    phtolel(&data_ptr[bytes_written], errors);
    bytes_written += 4;

    /*
     * Finally, copy the whole MAC frame to the packet buffer as-is.
     * This does not include the stats header or the PLCP.
     * This also does not include the last 4 bytes, as those don't
     * contain an FCS, they just contain junk.
     */
    memcpy(&data_ptr[bytes_written], &rec[vwr->MPDU_OFF], actual_octets);

    return TRUE;
}

/* read an Ethernet packet */
/* Copy the actual packet data from the capture file into the target data block.         */
/* The packet is constructed as a 38-byte VeriWave-extended Radiotap header plus the raw */
/*  MAC octets.                                                                          */

static gboolean vwr_read_rec_data_ethernet(vwr_t *vwr, struct wtap_pkthdr *phdr,
                                           Buffer *buf, const guint8 *rec,
                                           int rec_size, int IS_TX, int *err,
                                           gchar **err_info)
{
    guint8           *data_ptr;
    int              bytes_written = 0;                   /* bytes output to buf so far */
    const guint8 *s_ptr, *m_ptr;                          /* stats and MPDU pointers */
    guint16          msdu_length, actual_octets;          /* octets in frame */
    guint            flow_seq;                            /* seqnum */
    guint64          s_time = LL_ZERO, e_time = LL_ZERO;  /* start/end */
                                                          /* times, nsec */
    guint32          latency = 0;
    guint64          start_time, s_sec, s_usec = LL_ZERO; /* start time, sec + usec */
    guint64          end_time;                            /* end time */
    guint            l4id;
    guint16          info, validityBits;                  /* INFO/ERRORS fields in stats */
    guint32          errors;
    guint16          vc_id;                               /* VC ID, total (incl of aggregates) */
    guint32          flow_id, d_time;                     /* packet duration */
    int              f_flow;                              /* flags: flow valid */
    guint32          frame_type;                          /* frame type field */
    int              mac_len, sig_off, pay_off;           /* MAC header len, signature offset */
    /* XXX - the code here fetched tsid, but never used it! */
    guint64          sig_ts/*, tsid*/;                    /* 32 LSBs of timestamp in signature */
    guint64          delta_b;                             /* Used for calculating latency */
    guint16          vw_flags;                            /* VeriWave-specific packet flags */

    if (rec_size < (int)vwr->STATS_LEN) {
        *err_info = g_strdup_printf("vwr: Invalid record length %d (must be at least %u)", rec_size, vwr->STATS_LEN);
        *err = WTAP_ERR_BAD_FILE;
        return FALSE;
    }

    /* Calculate the start of the statistics block in the buffer. */
    /* Also get a bunch of fields from the stats block.           */
    m_ptr = &(rec[0]);                              /* point to the data block */
    s_ptr = &(rec[rec_size - vwr->STATS_LEN]);      /* point to the stats block */

    msdu_length = pntoh16(&s_ptr[vwr->OCTET_OFF]);
    actual_octets = msdu_length;

    /*
     * Sanity check the octets field to determine if it's greater than
     * the packet data available in the record - i.e., the record size
     * minus the length of the statistics block.
     *
     * Report an error if it is.
     */
    if (actual_octets > rec_size - vwr->STATS_LEN) {
        *err_info = g_strdup_printf("vwr: Invalid data length %u (runs past the end of the record)",
                                    actual_octets);
        *err = WTAP_ERR_BAD_FILE;
        return FALSE;
    }

    vc_id = pntoh16(&s_ptr[vwr->VCID_OFF]) & vwr->VCID_MASK;
    flow_seq   = s_ptr[vwr->FLOWSEQ_OFF];
    frame_type = pntoh32(&s_ptr[vwr->FRAME_TYPE_OFF]);

    if (vwr->FPGA_VERSION == vVW510024_E_FPGA) {
        validityBits = pntoh16(&s_ptr[vwr->VALID_OFF]);
        f_flow = validityBits & vwr->FLOW_VALID;

        mac_len = (validityBits & vwr->IS_VLAN) ? 16 : 14;           /* MAC hdr length based on VLAN tag */


        errors = pntoh16(&s_ptr[vwr->ERRORS_OFF]);
    }
    else {
        f_flow  = s_ptr[vwr->VALID_OFF] & vwr->FLOW_VALID;
        mac_len = (frame_type & vwr->IS_VLAN) ? 16 : 14;             /* MAC hdr length based on VLAN tag */


        /* for older fpga errors is only represented by 16 bits) */
        errors = pntoh16(&s_ptr[vwr->ERRORS_OFF]);
    }

    info = pntoh16(&s_ptr[vwr->INFO_OFF]);
    /*  24 LSBs */
    flow_id = pntoh24(&s_ptr[vwr->FLOWID_OFF]);

#if 0
    /* For tx latency is duration, for rx latency is timestamp. */
    /* Get 64-bit latency value. */
    tsid = pcorey48tohll(&s_ptr[vwr->LATVAL_OFF]);
#endif

    l4id = pntoh16(&s_ptr[vwr->L4ID_OFF]);

    /*
     * The MSDU length includes the FCS.
     *
     * The packet data does *not* include the FCS - it's just 4 bytes
     * of junk - so we have to remove it.
     *
     * We'll be stripping off an FCS (?), so make sure we have at
     * least 4 octets worth of FCS.
     */
    if (actual_octets < 4) {
        *err_info = g_strdup_printf("vwr: Invalid data length %u (too short to include 4 bytes of FCS)",
                                    actual_octets);
        *err = WTAP_ERR_BAD_FILE;
        return FALSE;
    }
    actual_octets -= 4;

    /* Calculate start & end times (in sec/usec), converting 64-bit times to usec. */
    /* 64-bit times are "Corey-endian"                                             */
    s_time = pcoreytohll(&s_ptr[vwr->STARTT_OFF]);
    e_time = pcoreytohll(&s_ptr[vwr->ENDT_OFF]);

    /* find the packet duration (difference between start and end times) */
    d_time = (guint32)((e_time - s_time));  /* find diff, leaving in nsec for Ethernet */

    /* also convert the packet start time to seconds and microseconds */
    start_time = s_time / NS_IN_US;                     /* convert to microseconds first */
    s_sec = (start_time / US_IN_SEC);                   /* get the number of seconds */
    s_usec = start_time - (s_sec * US_IN_SEC);          /* get the number of microseconds */

    /* also convert the packet end time to seconds and microseconds */
    end_time = e_time / NS_IN_US;                       /* convert to microseconds first */

    if (frame_type & vwr->IS_TCP)                       /* signature offset for TCP frame */
    {
        pay_off = mac_len + 40;
    }
    else if (frame_type & vwr->IS_UDP)                  /* signature offset for UDP frame */
    {
        pay_off = mac_len + 28;
    }
    else if (frame_type & vwr->IS_ICMP)                 /* signature offset for ICMP frame */
    {
        pay_off = mac_len + 24;
    }
    else if (frame_type & vwr->IS_IGMP)                 /* signature offset for IGMPv2 frame */
    {
        pay_off = mac_len + 28;
    }
    else                                                /* signature offset for raw IP frame */
    {
        pay_off = mac_len + 20;
    }

    sig_off = find_signature(m_ptr, rec_size, pay_off, flow_id, flow_seq);
    if ((m_ptr[sig_off] == 0xdd) && (sig_off + 15 <= msdu_length) && (f_flow != 0))
        sig_ts = get_signature_ts(m_ptr, sig_off);
    else
        sig_ts = 0;

    /* Set latency based on rx/tx and signature timestamp */
    if (!IS_TX) {
        if (sig_ts < s_time) {
            latency = (guint32)(s_time - sig_ts);
        } else {
            /* Account for the rollover case. Since we cannot use 0x100000000 - l_time + s_time */
            /*  we look for a large difference between l_time and s_time.                       */
            delta_b = sig_ts - s_time;
            if (delta_b >  0x10000000) {
                latency = 0;
            } else
                latency = (guint32)delta_b;
        }
    }

    /*
     * Fill up the per-packet header.
     *
     * We include the length of the metadata headers in the packet lengths.
     */
    phdr->len = STATS_COMMON_FIELDS_LEN + EXT_WLAN_FIELDS_LEN + actual_octets;
    phdr->caplen = STATS_COMMON_FIELDS_LEN + EXT_WLAN_FIELDS_LEN + actual_octets;

    phdr->ts.secs   = (time_t)s_sec;
    phdr->ts.nsecs  = (int)(s_usec * 1000);
    phdr->pkt_encap = WTAP_ENCAP_IXVERIWAVE;

    phdr->rec_type = REC_TYPE_PACKET;
    phdr->presence_flags = WTAP_HAS_TS;

    /*etap_hdr.vw_ip_length = (guint16)ip_len;*/

    buffer_assure_space(buf, phdr->caplen);
    data_ptr = buffer_start_ptr(buf);

    /*
     * Generate and copy out the common metadata headers,
     * set the port type to 1 (Ethernet).
     *
     * All values are copied out in little-endian byte order.
     */
    phtoles(&data_ptr[bytes_written], 1);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], STATS_COMMON_FIELDS_LEN);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], msdu_length);
    bytes_written += 2;
    phtolel(&data_ptr[bytes_written], flow_id);
    bytes_written += 4;
    phtoles(&data_ptr[bytes_written], vc_id);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], flow_seq);
    bytes_written += 2;
    if (!IS_TX && (sig_ts != 0)) {
        phtolel(&data_ptr[bytes_written], latency);
    } else {
        phtolel(&data_ptr[bytes_written], 0);
    }
    bytes_written += 4;
    phtolel(&data_ptr[bytes_written], sig_ts);
    bytes_written += 4;
    phtolell(&data_ptr[bytes_written], start_time)                  /* record start & end times of frame */
    bytes_written += 8;
    phtolell(&data_ptr[bytes_written], end_time);
    bytes_written += 8;
    phtolel(&data_ptr[bytes_written], d_time);
    bytes_written += 4;

    /*
     * Generate and copy out the Ethernet metadata headers.
     *
     * All values are copied out in little-endian byte order.
     */
    phtoles(&data_ptr[bytes_written], EXT_ETHERNET_FIELDS_LEN);
    bytes_written += 2;
    vw_flags = 0;
    if (IS_TX)
        vw_flags |= VW_FLAGS_TXF;
    if (errors & vwr->FCS_ERROR)
        vw_flags |= VW_FLAGS_FCSERR;
    phtoles(&data_ptr[bytes_written], vw_flags);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], info);
    bytes_written += 2;
    phtolel(&data_ptr[bytes_written], errors);
    bytes_written += 4;
    phtolel(&data_ptr[bytes_written], l4id);
    bytes_written += 4;

    /* Add in pad */
    phtolel(&data_ptr[bytes_written], 0);
    bytes_written += 4;

    /*
     * Finally, copy the whole MAC frame to the packet buffer as-is.
     * This also does not include the last 4 bytes, as those don't
     * contain an FCS, they just contain junk.
     */
    memcpy(&data_ptr[bytes_written], m_ptr, actual_octets);

    return TRUE;
}

/*--------------------------------------------------------------------------------------*/
/* utility to split up and decode a 16-byte message record */

static int decode_msg(vwr_t *vwr, guint8 *rec, int *v_type, int *IS_TX)
{
    guint8  cmd;                        /* components of message */
    guint32 wd2, wd3;
    int     v_size = 0;                 /* size of var-len message */
                                        /* assume it's zero */

    /* break up the message record into its pieces */
    cmd = rec[0];
    wd2 = pntoh32(&rec[8]);
    wd3 = pntoh32(&rec[12]);

    if (vwr != NULL) {
        if ((cmd & vwr->HEADER_IS_TX) == vwr->HEADER_IS_TX)
            *IS_TX = 1;
        else if ((cmd & vwr->HEADER_IS_RX) == vwr->HEADER_IS_RX)
            *IS_TX = 0;
        else *IS_TX = 2; /*NULL case*/
    }
    /* now decode based on the command byte */
    switch (cmd) {
        case 0x21:
        case 0x31:
            v_size  = (int)(wd2 & 0xffff);
            *v_type = VT_FRAME;
            break;

        case 0xc1:
        case 0x8b:
            v_size  = (int)(wd2 & 0xffff);
            *v_type = VT_CPMSG;
            break;

        case 0xfe:
            v_size  = (int)(wd3 & 0xffff);
            *v_type = VT_CPMSG;
            break;

        default:
            break;
    }

    return v_size;
}


/*---------------------------------------------------------------------------------------*/
/* Utilities to extract and decode the PHY bit rate from 802.11 PLCP headers (OFDM/CCK). */
/* They are passed a pointer to 4 or 6 consecutive bytes of PLCP header.                 */
/* The integer returned by the get_xxx_rate() functions is in units of 0.5 Mb/s.         */
/* The string returned by the decode_xxx_rate() functions is 3 characters wide.          */

static guint8 get_ofdm_rate(const guint8 *plcp)
{
    /* extract the RATE field (LS nibble of first byte) then convert it to the MCS index used by the L1p fields */
    switch (plcp[0] & 0x0f) {
        case 0x0b:  return  4;
        case 0x0f:  return  5;
        case 0x0a:  return  6;
        case 0x0e:  return  7;
        case 0x09:  return  8;
        case 0x0d:  return  9;
        case 0x08:  return 10;
        case 0x0c:  return 11;
        default:    return  0;
    }
}

static guint8 get_cck_rate(const guint8 *plcp)
{
    /* extract rate from the SIGNAL field then convert it to the MCS index used by the L1p fields */
    switch (plcp[0]) {
        case 0x0a:  return 0;
        case 0x14:  return 1;
        case 0x37:  return 2;
        case 0x6e:  return 3;
        default:    return 0;
    }
}

/*--------------------------------------------------------------------------------------*/
/* utility to set up offsets and bitmasks for decoding the stats blocks */

static void setup_defaults(vwr_t *vwr, guint16 fpga)
{
    switch (fpga) {
        /* WLAN frames */
        case S2_W_FPGA:
            vwr->STATS_LEN          = vVW510021_W_STATS_TRAILER_LEN;

            vwr->VALID_OFF          = vVW510021_W_VALID_OFF;
            vwr->MTYPE_OFF          = vVW510021_W_MTYPE_OFF;
            vwr->VCID_OFF           = vVW510021_W_VCID_OFF;
            vwr->FLOWSEQ_OFF        = vVW510021_W_FLOWSEQ_OFF;
            vwr->FLOWID_OFF         = vVW510021_W_FLOWID_OFF;

            /*vwr->OCTET_OFF        = v22_W_OCTET_OFF;*/

            vwr->ERRORS_OFF         = vVW510021_W_ERRORS_OFF;
            vwr->PATN_OFF           = vVW510021_W_MATCH_OFF;
            vwr->RSSI_OFF           = vVW510021_W_RSSI_TXPOWER_OFF;
            vwr->STARTT_OFF         = vVW510021_W_STARTT_OFF;
            vwr->ENDT_OFF           = vVW510021_W_ENDT_OFF;
            vwr->LATVAL_OFF         = vVW510021_W_LATVAL_OFF;
            vwr->INFO_OFF           = vVW510021_W_INFO_OFF;
            vwr->FPGA_VERSION_OFF   = S2_W_FPGA_VERSION_OFF;
            vwr->HEADER_VERSION_OFF = vVW510021_W_HEADER_VERSION_OFF;
            vwr->OCTET_OFF          = vVW510021_W_MSDU_LENGTH_OFF;
            vwr->L1P_1_OFF          = vVW510021_W_L1P_1_OFF;
            vwr->L1P_2_OFF          = vVW510021_W_L1P_2_OFF;
            vwr->L4ID_OFF           = vVW510021_W_L4ID_OFF;
            vwr->IPLEN_OFF          = vVW510021_W_IPLEN_OFF;
            vwr->PLCP_LENGTH_OFF    = vVW510021_W_PLCP_LENGTH_OFF;

            vwr->HEADER_IS_RX       = vVW510021_W_HEADER_IS_RX;
            vwr->HEADER_IS_TX       = vVW510021_W_HEADER_IS_TX;
            vwr->MT_MASK            = vVW510021_W_SEL_MASK;
            vwr->MCS_INDEX_MASK     = vVW510021_W_MCS_MASK;
            vwr->VCID_MASK          = 0xffff;
            vwr->FLOW_VALID         = vVW510021_W_FLOW_VALID;
            vwr->STATS_START_OFF    = vVW510021_W_HEADER_LEN;
            vwr->FCS_ERROR          = vVW510021_W_FCS_ERROR;
            vwr->CRYPTO_ERR         = v22_W_CRYPTO_ERR;
            vwr->RETRY_ERR          = v22_W_RETRY_ERR;

            /*vwr->STATS_START_OFF  = 0;*/

            vwr->RXTX_OFF           = vVW510021_W_RXTX_OFF;

            vwr->MT_10_HALF         = 0;
            vwr->MT_10_FULL         = 0;
            vwr->MT_100_HALF        = 0;
            vwr->MT_100_FULL        = 0;
            vwr->MT_1G_HALF         = 0;
            vwr->MT_1G_FULL         = 0;
            vwr->MT_CCKL            = v22_W_MT_CCKL;
            vwr->MT_CCKS            = v22_W_MT_CCKS;
            /*vwr->MT_OFDM          = vVW510021_W_MT_OFDM;*/

            vwr->WEPTYPE            = vVW510021_W_WEPTYPE;
            vwr->TKIPTYPE           = vVW510021_W_TKIPTYPE;
            vwr->CCMPTYPE           = vVW510021_W_CCMPTYPE;

            vwr->FRAME_TYPE_OFF     =   vVW510021_W_FRAME_TYPE_OFF;
            vwr->IS_TCP             =   vVW510021_W_IS_TCP;
            vwr->IS_UDP             =   vVW510021_W_IS_UDP;
            vwr->IS_ICMP            =   vVW510021_W_IS_ICMP;
            vwr->IS_IGMP            =   vVW510021_W_IS_IGMP;
            vwr->IS_QOS             =   vVW510021_W_QOS_VALID;

            /*
             * The 12 is for 11 bytes of PLCP  and 1 byte of pad
             * before the data.
             */
            vwr->MPDU_OFF           = vVW510021_W_STATS_HEADER_LEN + 12;

            break;

        case S3_W_FPGA:
            vwr->STATS_LEN       = vVW510021_W_STATS_TRAILER_LEN;
            vwr->PLCP_LENGTH_OFF = 16;
            vwr->HEADER_IS_RX    = vVW510021_W_HEADER_IS_RX;
            vwr->HEADER_IS_TX    = vVW510021_W_HEADER_IS_TX;

            /*
             * The 8 is from the 16 bytes of stats block that precede the
             * PLCP; the 16 is for, umm, something.
             */
            vwr->MPDU_OFF        = 16 + 16;

            break;

        case vVW510012_E_FPGA:
            vwr->STATS_LEN      = v22_E_STATS_LEN;

            vwr->VALID_OFF      = v22_E_VALID_OFF;
            vwr->MTYPE_OFF      = v22_E_MTYPE_OFF;
            vwr->VCID_OFF       = v22_E_VCID_OFF;
            vwr->FLOWSEQ_OFF    = v22_E_FLOWSEQ_OFF;
            vwr->FLOWID_OFF     = v22_E_FLOWID_OFF;
            vwr->OCTET_OFF      = v22_E_OCTET_OFF;
            vwr->ERRORS_OFF     = v22_E_ERRORS_OFF;
            vwr->PATN_OFF       = v22_E_PATN_OFF;
            vwr->RSSI_OFF       = v22_E_RSSI_OFF;
            vwr->STARTT_OFF     = v22_E_STARTT_OFF;
            vwr->ENDT_OFF       = v22_E_ENDT_OFF;
            vwr->LATVAL_OFF     = v22_E_LATVAL_OFF;
            vwr->INFO_OFF       = v22_E_INFO_OFF;
            vwr->L4ID_OFF       = v22_E_L4ID_OFF;

            vwr->HEADER_IS_RX   = v22_E_HEADER_IS_RX;
            vwr->HEADER_IS_TX   = v22_E_HEADER_IS_TX;

            vwr->IS_RX          = v22_E_IS_RX;
            vwr->MT_MASK        = v22_E_MT_MASK;
            vwr->VCID_MASK      = v22_E_VCID_MASK;
            vwr->FLOW_VALID     = v22_E_FLOW_VALID;
            vwr->FCS_ERROR      = v22_E_FCS_ERROR;

            vwr->RX_DECRYPTS    = v22_E_RX_DECRYPTS;
            vwr->TX_DECRYPTS    = v22_E_TX_DECRYPTS;
            vwr->FC_PROT_BIT    = v22_E_FC_PROT_BIT;

            vwr->MT_10_HALF     = v22_E_MT_10_HALF;
            vwr->MT_10_FULL     = v22_E_MT_10_FULL;
            vwr->MT_100_HALF    = v22_E_MT_100_HALF;
            vwr->MT_100_FULL    = v22_E_MT_100_FULL;
            vwr->MT_1G_HALF     = v22_E_MT_1G_HALF;
            vwr->MT_1G_FULL     = v22_E_MT_1G_FULL;
            vwr->MT_CCKL        = 0;
            vwr->MT_CCKS        = 0;
            vwr->MT_OFDM        = 0;

            vwr->FRAME_TYPE_OFF =  v22_E_FRAME_TYPE_OFF;
            vwr->IS_TCP         =   v22_E_IS_TCP;
            vwr->IS_UDP         =   v22_E_IS_UDP;
            vwr->IS_ICMP        =   v22_E_IS_ICMP;
            vwr->IS_IGMP        =   v22_E_IS_IGMP;
            vwr->IS_QOS         =   v22_E_IS_QOS;
            vwr->IS_VLAN        =   v22_E_IS_VLAN;

            break;

            /* WLAN frames */
        case S1_W_FPGA:
            vwr->STATS_LEN          = v22_W_STATS_LEN;

            vwr->MTYPE_OFF          = v22_W_MTYPE_OFF;
            vwr->VALID_OFF          = v22_W_VALID_OFF;
            vwr->VCID_OFF           = v22_W_VCID_OFF;
            vwr->FLOWSEQ_OFF        = v22_W_FLOWSEQ_OFF;
            vwr->FLOWID_OFF         = v22_W_FLOWID_OFF;
            vwr->OCTET_OFF          = v22_W_OCTET_OFF;
            vwr->ERRORS_OFF         = v22_W_ERRORS_OFF;
            vwr->PATN_OFF           = v22_W_PATN_OFF;
            vwr->RSSI_OFF           = v22_W_RSSI_OFF;
            vwr->STARTT_OFF         = v22_W_STARTT_OFF;
            vwr->ENDT_OFF           = v22_W_ENDT_OFF;
            vwr->LATVAL_OFF         = v22_W_LATVAL_OFF;
            vwr->INFO_OFF           = v22_W_INFO_OFF;
            vwr->L4ID_OFF           = v22_W_L4ID_OFF;
            vwr->IPLEN_OFF          = v22_W_IPLEN_OFF;
            vwr->PLCP_LENGTH_OFF    = v22_W_PLCP_LENGTH_OFF;

            vwr->FCS_ERROR          = v22_W_FCS_ERROR;
            vwr->CRYPTO_ERR         = v22_W_CRYPTO_ERR;
            vwr->PAYCHK_ERR         = v22_W_PAYCHK_ERR;
            vwr->RETRY_ERR          = v22_W_RETRY_ERR;
            vwr->IS_RX              = v22_W_IS_RX;
            vwr->MT_MASK            = v22_W_MT_MASK;
            vwr->VCID_MASK          = v22_W_VCID_MASK;
            vwr->FLOW_VALID         = v22_W_FLOW_VALID;

            vwr->HEADER_IS_RX       = v22_W_HEADER_IS_RX;
            vwr->HEADER_IS_TX       = v22_W_HEADER_IS_TX;

            vwr->RX_DECRYPTS        = v22_W_RX_DECRYPTS;
            vwr->TX_DECRYPTS        = v22_W_TX_DECRYPTS;
            vwr->FC_PROT_BIT        = v22_W_FC_PROT_BIT;

            vwr->MT_10_HALF         = 0;
            vwr->MT_10_FULL         = 0;
            vwr->MT_100_HALF        = 0;
            vwr->MT_100_FULL        = 0;
            vwr->MT_1G_HALF         = 0;
            vwr->MT_1G_FULL         = 0;
            vwr->MT_CCKL            = v22_W_MT_CCKL;
            vwr->MT_CCKS            = v22_W_MT_CCKS;
            vwr->MT_OFDM            = v22_W_MT_OFDM;

            vwr->WEPTYPE            = v22_W_WEPTYPE;
            vwr->TKIPTYPE           = v22_W_TKIPTYPE;
            vwr->CCMPTYPE           = v22_W_CCMPTYPE;

            vwr->FRAME_TYPE_OFF     =   v22_W_FRAME_TYPE_OFF;
            vwr->IS_TCP             =   v22_W_IS_TCP;
            vwr->IS_UDP             =   v22_W_IS_UDP;
            vwr->IS_ICMP            =   v22_W_IS_ICMP;
            vwr->IS_IGMP            =   v22_W_IS_IGMP;
            vwr->IS_QOS             =   v22_W_IS_QOS;

            break;

        /* Ethernet frames */
        case vVW510024_E_FPGA:
            vwr->STATS_LEN          = vVW510024_E_STATS_LEN;

            vwr->VALID_OFF          = vVW510024_E_VALID_OFF;
            vwr->VCID_OFF           = vVW510024_E_VCID_OFF;
            vwr->FLOWSEQ_OFF        = vVW510024_E_FLOWSEQ_OFF;
            vwr->FLOWID_OFF         = vVW510024_E_FLOWID_OFF;
            vwr->OCTET_OFF          = vVW510024_E_MSDU_LENGTH_OFF;
            vwr->ERRORS_OFF         = vVW510024_E_ERRORS_OFF;
            vwr->PATN_OFF           = vVW510024_E_MATCH_OFF;
            vwr->STARTT_OFF         = vVW510024_E_STARTT_OFF;
            vwr->ENDT_OFF           = vVW510024_E_ENDT_OFF;
            vwr->LATVAL_OFF         = vVW510024_E_LATVAL_OFF;
            vwr->INFO_OFF           = vVW510024_E_INFO_OFF;
            vwr->L4ID_OFF           = vVW510024_E_L4ID_OFF;
            vwr->IPLEN_OFF          = vVW510024_E_IPLEN_OFF;

            vwr->FPGA_VERSION_OFF   = vVW510024_E_FPGA_VERSION_OFF;
            vwr->HEADER_VERSION_OFF = vVW510024_E_HEADER_VERSION_OFF;

            vwr->HEADER_IS_RX       = vVW510024_E_HEADER_IS_RX;
            vwr->HEADER_IS_TX       = vVW510024_E_HEADER_IS_TX;

            vwr->VCID_MASK          = vVW510024_E_VCID_MASK;
            vwr->FLOW_VALID         = vVW510024_E_FLOW_VALID;
            vwr->FCS_ERROR          = v22_E_FCS_ERROR;

            vwr->FRAME_TYPE_OFF     =   vVW510024_E_FRAME_TYPE_OFF;
            vwr->IS_TCP             =   vVW510024_E_IS_TCP;
            vwr->IS_UDP             =   vVW510024_E_IS_UDP;
            vwr->IS_ICMP            =   vVW510024_E_IS_ICMP;
            vwr->IS_IGMP            =   vVW510024_E_IS_IGMP;
            vwr->IS_QOS             =   vVW510024_E_QOS_VALID;
            vwr->IS_VLAN            =   vVW510024_E_IS_VLAN;

            break;
    }
}
#define SIG_SCAN_RANGE  64                          /* range of signature scanning region */

/* Utility routine: check that signature is at specified location; scan for it if not.     */
/* If we can't find a signature at all, then simply return the originally supplied offset. */
int find_signature(const guint8 *m_ptr, int rec_size, int pay_off, guint32 flow_id, guint8 flow_seq)
{
    int     tgt;                /* temps */
    guint32 fid;

    /* initial check is very simple: look for a '0xdd' at the target location */
    if (m_ptr[pay_off] == 0xdd)                         /* if magic byte is present */
        return pay_off;                                 /* got right offset, return it */

    /* Hmmm, signature magic byte is not where it is supposed to be; scan from start of     */
    /*  payload until maximum scan range exhausted to see if we can find it.                */
    /* The scanning process consists of looking for a '0xdd', then checking for the correct */
    /*  flow ID and sequence number at the appropriate offsets.                             */
    for (tgt = pay_off; tgt < (rec_size); tgt++) {
        if (m_ptr[tgt] == 0xdd) {                       /* found magic byte? check fields */
            if (m_ptr[tgt + 15] == 0xe2) {
                if (m_ptr[tgt + 4] != flow_seq)
                    continue;

                fid = pletoh24(&m_ptr[tgt + 1]);

                if (fid != flow_id)
                    continue;

                return (tgt);
            }
            else
            {                                               /* out which one... */
                if (m_ptr[tgt + SIG_FSQ_OFF] != flow_seq)   /* check sequence number */
                    continue;                               /* if failed, keep scanning */

                fid = pletoh24(&m_ptr[tgt + SIG_FID_OFF]);  /* assemble flow ID from signature */
                if (fid != flow_id)                         /* check flow ID against expected */
                    continue;                               /* if failed, keep scanning */

                /* matched magic byte, sequence number, flow ID; found the signature */
                return (tgt);                               /* return offset of signature */
            }
        }
    }

    /* failed to find the signature, return the original offset as default */
    return pay_off;
}

/* utility routine: harvest the signature time stamp from the data frame */
guint64 get_signature_ts(const guint8 *m_ptr,int sig_off)
{
    int     ts_offset;
    guint64 sig_ts;

    if (m_ptr[sig_off + 15] == 0xe2)
        ts_offset = 5;
    else
        ts_offset = 8;

    sig_ts = pletoh32(&m_ptr[sig_off + ts_offset]);

    return (sig_ts & 0xffffffff);
}

static float getRate( guint8 plcpType, guint8 mcsIndex, guint16 rflags, guint8 nss )
{
    /* Rate conversion data */
    float canonical_rate_legacy[]  = {1.0f, 2.0f, 5.5f, 11.0f, 6.0f, 9.0f, 12.0f, 18.0f, 24.0f, 36.0f, 48.0f, 54.0f};

    int   canonical_ndbps_20_ht[]  = {26, 52, 78, 104, 156, 208, 234, 260};
    int   canonical_ndbps_40_ht[]  = {54, 108, 162, 216, 324, 432, 486, 540};

    int   canonical_ndbps_20_vht[] = {26,52, 78, 104, 156, 208, 234, 260, 312};
    int   canonical_ndbps_40_vht[] = {54, 108, 162, 216, 324, 432, 486, 540, 648, 720};
    int   canonical_ndbps_80_vht[] = {117, 234, 351, 468, 702, 936, 1053, 1170, 1404, 1560};

    int   ndbps;
    float symbol_tx_time, bitrate  = 0.0f;

    if (plcpType == 0)
        bitrate =  canonical_rate_legacy[mcsIndex];
    else if (plcpType == 1 || plcpType == 2)
    {
        if ( rflags & FLAGS_CHAN_SHORTGI)
            symbol_tx_time = 3.6f;
        else
            symbol_tx_time = 4.0f;

        if ( rflags & FLAGS_CHAN_40MHZ )
            ndbps = canonical_ndbps_40_ht[ mcsIndex - 8*(int)(mcsIndex/8) ];
        else
            ndbps = canonical_ndbps_20_ht[ mcsIndex - 8*(int)(mcsIndex/8) ];

        bitrate = ( ndbps * (((int)(mcsIndex/8) + 1) )) / symbol_tx_time;
    }
    else
    {
        if ( rflags & FLAGS_CHAN_SHORTGI)
            symbol_tx_time = 3.6f;
        else
            symbol_tx_time = 4.0f;

    /* Check for the out of range mcsIndex.  Should never happen, but if mcs index is greater than 9 assume 9 is the value */
    if (mcsIndex > 9) mcsIndex = 9;
        if ( rflags & FLAGS_CHAN_40MHZ )
            bitrate = (canonical_ndbps_40_vht[ mcsIndex ] * nss) / symbol_tx_time;
        else if (rflags & FLAGS_CHAN_80MHZ )
            bitrate = (canonical_ndbps_80_vht[ mcsIndex ] * nss) / symbol_tx_time;
        else
        {
            if (mcsIndex == 9 && nss == 3)
                bitrate = 1040 / symbol_tx_time;
            else if (mcsIndex < 9)
                bitrate = (canonical_ndbps_20_vht[ mcsIndex ] * nss) / symbol_tx_time;
        }
    }

    return bitrate;
}

static gboolean
vwr_process_rec_data(FILE_T fh, int rec_size,
                     struct wtap_pkthdr *phdr, Buffer *buf, vwr_t *vwr,
                     int IS_TX, int *err, gchar **err_info)
{
    guint8   rec[B_SIZE];       /* local buffer (holds input record) */

    /* Read over the entire record (frame + trailer) into a local buffer.         */
    /* If we don't get it all, then declare an error, we can't process the frame. */
    if (file_read(rec, rec_size, fh) != rec_size) {
        *err = file_error(fh, err_info);
        if (*err == 0)
            *err = WTAP_ERR_SHORT_READ;
        return FALSE;
    }

    /* now format up the frame data */
    switch (vwr->FPGA_VERSION)
    {
        case S1_W_FPGA:
            return vwr_read_s1_W_rec(vwr, phdr, buf, rec, rec_size, err, err_info);
            break;
        case S2_W_FPGA:
        case S3_W_FPGA:
            return vwr_read_s2_W_rec(vwr, phdr, buf, rec, rec_size, IS_TX, err, err_info);
            break;
        case vVW510012_E_FPGA:
        case vVW510024_E_FPGA:
            return vwr_read_rec_data_ethernet(vwr, phdr, buf, rec, rec_size, IS_TX, err, err_info);
            break;
        default:
            g_assert_not_reached();
            return FALSE;
    }
}

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
