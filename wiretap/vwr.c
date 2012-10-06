/* vwr.c
 * Copyright (c) 2011 by Tom Alexander <talexander@ixiacom.com>
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
#   define NS_IN_US             G_GINT64_CONSTANT(1000U)        /* nanoseconds-to-microseconds */
#   define NS_IN_SEC            G_GINT64_CONSTANT(1000000000U)  /* nanoseconds-to-seconds */
#   define US_IN_SEC            G_GINT64_CONSTANT(1000000U)     /* microseconds-to-seconds */
#   define LL_ZERO              G_GINT64_CONSTANT(0U)           /* zero in unsigned long long */

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

/* .vwr log file defines */
#define B_SIZE      32768                           /* max var len message = 32 kB */
#define VT_FRAME    0                               /* varlen msg is a frame */
#define VT_CPMSG    1                               /* varlen msg is a CP<->PP msg */
#define MAX_TRACKED_CLIENTS 1024                    /* track 1024 clients */
#define MAX_TRACKED_FLOWS   65536                   /* and 64K flows */

/* the radiotap header */

/* IxVeriwave common header fields */
typedef struct {
    guint16 vw_port_type;                           /* 0 for WLAN, 1 for Ethernet */
    guint16 it_len;                                 /* WHOLE radiotap header length (incl. */
    guint16 vw_msdu_length;                         /* length of MAC SDU */
    guint32 vw_flowid;                              /* VeriWave-specific flow ID for packet */
    guint16 vw_vcid;                                /* VeriWave-specific vC ID (client id) */
    guint16 vw_seqnum;                              /* VeriWave-specific signature seqnum */
    guint32 vw_latency;                             /* VeriWave-specific packet latency, ns */
    guint32 vw_sig_ts;                              /* signature timestamp, 32 LSBs, nsec */
    guint64 vw_startt;                              /* frame start time (nsec) */
    guint64 vw_endt;                                /* frame end time (nsec) */
    guint32 vw_pktdur;                              /* VeriWave-specific pkt duration, us */

} stats_common_fields;

/* Size of those fields - regardless of how the compiler packs them */
#define STATS_COMMON_FIELDS_LEN	(2+2+2+2+4+2+2+4+4+8+8+4+4)

/* Veriwave-specific extended radiotap header fields (following vwr_rtap_hdr above) */
/* structure elements correspond one-to-one with the RADIOTAP_PRESENT bitmask below */
/* NOTE: must ensure that elements are aligned to their "natural" packing */
/* NOTE: must ensure that "latency" precedes all other packet timing details, because it */
/* is used to start a subtree */
typedef struct {
    guint16 it_len;                                 /* WHOLE radiotap header length (incl. */
    guint16 flags;                                  /* short preamble, WEP, frag */
    guint16 chanflags;                              /* channel flags bitmap */
    guint8  rate;                                   /* PHY bit rate, 500 kb/s units */
    gint8   signal;                                 /* RF signal power, +/- dBm */
    gint8   tx_power;                               /* transmit power, +/- dBm */
    guint8  pad;
    guint16 vw_flags;                               /* VeriWave-specific packet flags */
    guint16 vw_ht_length;                           /* ht length (in plcp header)*/
    guint16 vw_info;                                /* VeriWave-specific information */
    guint32 vw_errors;                              /* VeriWave-specific errors */

} ext_rtap_fields;

/* Size of those fields - regardless of how the compiler packs them */
#define EXT_RTAP_FIELDS_LEN	(2+2+2+1+1+1+1+2+2+2+4)

/* Veriwave-specific Ethernettap header */
typedef struct {
    guint16 it_len;                                 /* WHOLE radiotap header length (incl. */
    guint16 vw_flags;                               /* Veriwave-specific flags (see above) */
    guint16 vw_info;                                /* VeriWave-specific information */
    guint32 vw_errors;                              /* VeriWave-specific flags */
    guint32 vw_l4id;                                /* layer four id*/
    guint32 it_pad2;                                /* pad out header to 16-byte boundary */
} stats_ethernettap_fields;

/* Size of those fields - regardless of how the compiler packs them */
#define STATS_ETHERNETTAP_FIELDS_LEN	(2+2+2+2+4+4+4)

/* the bitmap offsets of the bits in it_present, above */
/* also lists the expected field sizes in bytes */
/* MUST BE IN SAME ORDER AS THE STRUCTURE ELEMENTS ABOVE */
enum radiotap_type {
    VW_RADIOTAP_FLAGS = 0,                              /* 2 bytes */
    VW_RADIOTAP_RATE = 1,                               /* 1 byte */
    VW_RADIOTAP_CHANNEL = 2,                            /* 4 bytes (mhz + chanflags) */
    VW_RADIOTAP_DBM_ANTSIGNAL = 3,                      /* 1 byte */
    VW_RADIOTAP_DBM_TX_POWER = 4,                       /* 1 byte */
    /* start of veriwave addition */
    VW_RADIOTAP_FPGA_VERSION = 5,                       /* 2 bytes */
    VW_RADIOTAP_VW_FLAGS = 6,                           /* 2 bytes */
    VW_RADIOTAP_MSDU_LENGTH = 7,                        /* 2 bytes */
    VW_RADIOTAP_HT_LENGTH = 8,                          /* 2 bytes */
    VW_RADIOTAP_INFO = 9,                               /* 2 bytes */
    VW_RADIOTAP_ERRORS = 10,                            /* 4 bytes */
    VW_RADIOTAP_FLOWID = 11,                            /* 4 bytes */
    VW_RADIOTAP_MCID = 12,                              /* 2 bytes */
    VW_RADIOTAP_SEQNUM = 13,                            /* 2 bytes */
    VW_RADIOTAP_LATENCY = 14,                           /* 4 bytes (MUST COME BEFORE OTHER TIMES)*/
    VW_RADIOTAP_SIG_TS = 15,                            /* 4 bytes */
    VW_RADIOTAP_STARTT = 16,                            /* 8 bytes */
    VW_RADIOTAP_ENDT = 17,                              /* 8 bytes */
    VW_RADIOTAP_PKTDUR = 18,                            /* 4 bytes */
    VW_RADIOTAP_IFG = 19,                               /* 4 bytes */

    /* end of Veriwave addition 6-2007 */

    VW_RADIOTAP_EXT = 31
};

/* standard field-present bitmap corresponding to above fixed-size set of fields */
/* this produces a 16-byte header */
#define VW_RADIOTAP_PRESENT ((1 << VW_RADIOTAP_FLAGS) | \
                             (1 << VW_RADIOTAP_RATE) | \
                             (1 << VW_RADIOTAP_CHANNEL) | \
                             (1 << VW_RADIOTAP_DBM_ANTSIGNAL) | \
                             (1 << VW_RADIOTAP_DBM_TX_POWER))

/* extended field-present bitmap corresponding to above fixed-size set of fields */
/* this produces a 32-byte header */
#define VW_EXT_RTAP_PRESENT ((1 << VW_RADIOTAP_FLAGS) | \
                             (1 << VW_RADIOTAP_RATE) | \
                             (1 << VW_RADIOTAP_CHANNEL) | \
                             (1 << VW_RADIOTAP_DBM_ANTSIGNAL) | \
                             (1 << VW_RADIOTAP_DBM_TX_POWER) | \
                             (1 << VW_RADIOTAP_FPGA_VERSION) | \
                             (1 << VW_RADIOTAP_VW_FLAGS) | \
                             (1 << VW_RADIOTAP_MSDU_LENGTH) | \
                             (1 << VW_RADIOTAP_HT_LENGTH) | \
                             (1 << VW_RADIOTAP_ERRORS) | \
                             (1 << VW_RADIOTAP_INFO) | \
                             (1 << VW_RADIOTAP_MCID) | \
                             (1 << VW_RADIOTAP_FLOWID) | \
                             (1 << VW_RADIOTAP_SEQNUM) | \
                             (1 << VW_RADIOTAP_LATENCY) | \
                             (1 << VW_RADIOTAP_SIG_TS) | \
                             (1 << VW_RADIOTAP_STARTT) | \
                             (1 << VW_RADIOTAP_ENDT) |\
                             (1 << VW_RADIOTAP_PKTDUR) |\
                             (1 << VW_RADIOTAP_IFG))

/*
 * RADIOTAP_FLAGS               u_int8_t        bitmap
 *      See flags definitions below
 *
 * RADIOTAP_RATE                u_int8_t        500kb/s
 *      Tx/Rx data rate
 *
 * RADIOTAP_CHANNEL             2 x u_int16_t   MHz+bitmap
 *      Tx/Rx frequency in MHz, followed by flags (see below).
 *
 * RADIOTAP_DBM_ANTSIGNAL       int8_t          dBm
 *      RF signal power at the antenna, dBm
 *
 * RADIOTAP_DBM_ANTNOISE        int8_t          dBm
 *      RF noise power at the antenna, dBm
 *
 * RADIOTAP_BARKER_CODE_LOCK    u_int16_t       unitless
 *      Quality of Barker code lock. Monotonically nondecreasing with "better" lock strength.
 *      Called "Signal Quality" in datasheets.
 *
 * RADIOTAP_DBM_TX_POWER        int8_t          dBm
 *      Transmit power expressed as dBm.
*/

/* Channel flags for IEEE80211_RADIOTAP_CHANNEL */
#define CHAN_TURBO          0x0010                  /* Turbo channel */
#define CHAN_CCK            0x0020                  /* CCK channel */
#define CHAN_OFDM           0x0040                  /* OFDM channel */
#define CHAN_2GHZ           0x0080                  /* 2 GHz spectrum channel. */
#define CHAN_5GHZ           0x0100                  /* 5 GHz spectrum channel */
#define CHAN_PASSIVE        0x0200                  /* Only passive scan allowed */

/* For RADIOTAP_FLAGS */
#define RADIOTAP_F_CFP          0x001               /* sent/received during CFP */
#define RADIOTAP_F_SHORTPRE     0x002               /* sent/received with short preamble */
#define RADIOTAP_F_WEP          0x004               /* sent/received with WEP encryption */
#define RADIOTAP_F_FRAG         0x008               /* sent/received with fragmentation */
#define RADIOTAP_F_FCS          0x010               /* frame includes FCS */
#define RADIOTAP_F_DATAPAD      0x020               /* padding between 802.11 hdr & payload */
#define RADIOTAP_F_CHAN_HT      0x040               /* In HT mode */
#define RADIOTAP_F_CHAN_40MHZ   0x080               /* 40 Mhz CBW */
#define RADIOTAP_F_CHAN_SHORTGI 0x100               /* Short guard interval */


/* For VeriWave-specific RADIOTAP_FLAGS and ETHERNETTAP_FLAGS */
#define RADIOTAP_VWF_TXF    0x01                    /* frame was transmitted */
#define RADIOTAP_VWF_FCSERR 0x02                    /* FCS error detected */
#define RADIOTAP_VWF_RETRERR 0x04                   /* excess retry error detected */
#define RADIOTAP_VWF_DCRERR 0x10                    /* decrypt error detected (WLAN) */
#define RADIOTAP_VWF_ENCMSK 0x60                    /* encryption type mask */
                                                    /* 0 = none, 1 = WEP, 2 = TKIP, 3 = CCKM */
#define RADIOTAP_VWF_IS_WEP     0x20                /* WEP */
#define RADIOTAP_VWF_IS_TKIP    0x40                /* TKIP */
#define RADIOTAP_VWF_IS_CCMP    0x60                /* CCMP */
#define RADIOTAP_VWF_SEQ_ERR    0x80                /* flow sequence error detected */

/* FPGA-generated frame buffer STATS block offsets and definitions */

/* definitions for v2.2 frames, Ethernet format */
#define v22_E_STATS_LEN     44                      /* length of stats block trailer */
#define v22_E_VALID_OFF     0                       /* bit 6 (0x40) is flow-is-valid flag */
#define v22_E_MTYPE_OFF     1                       /* offset of modulation type */
#define v22_E_VCID_OFF      2                       /* offset of VC ID */
#define v22_E_FLOWSEQ_OFF   4                       /* offset of signature sequence number */
#define v22_E_FLOWID_OFF    5                       /* offset of flow ID */
#define v22_E_OCTET_OFF     8                       /* offset of octets */
#define v22_E_ERRORS_OFF    10                      /* offset of error vector */
#define v22_E_PATN_OFF      12                      /* offset of pattern match vector */
#define v22_E_L4ID_OFF      12
#define v22_E_IPLEN_OFF     14
#define v22_E_FRAME_TYPE_OFF   16                   /* offset of frame type, 32 bits */
#define v22_E_RSSI_OFF      21                      /* RSSI (NOTE: invalid for Ethernet) */
#define v22_E_STARTT_OFF    20                      /* offset of start time, 64 bits */
#define v22_E_ENDT_OFF      28                      /* offset of end time, 64 bits */
#define v22_E_LATVAL_OFF    36                      /* offset of latency, 32 bits */
#define v22_E_INFO_OFF      40                      /* NO INFO FIELD IN ETHERNET STATS! */
#define v22_E_DIFFERENTIATOR_OFF    0               /* offset to determine whether */
                                                    /* eth/802.11, 8 bits */

#define v22_E_MT_10_HALF    0                       /* 10 Mb/s half-duplex */
#define v22_E_MT_10_FULL    1                       /* 10 Mb/s full-duplex */
#define v22_E_MT_100_HALF   2                       /* 100 Mb/s half-duplex */
#define v22_E_MT_100_FULL   3                       /* 100 Mb/s full-duplex */
#define v22_E_MT_1G_HALF    4                       /* 1 Gb/s half-duplex */
#define v22_E_MT_1G_FULL    5                       /* 1 Gb/s full-duplex */

#define v22_E_FCS_ERROR     0x0002                  /* FCS error flag in error vector */
#define v22_E_CRYPTO_ERR    0x1f00                  /* RX decrypt error flags (UNUSED) */
#define v22_E_SIG_ERR       0x0004                  /* signature magic byte mismatch */
#define v22_E_PAYCHK_ERR    0x0008                  /* payload checksum failure */
#define v22_E_RETRY_ERR     0x0400                  /* excessive retries on TX fail (UNUSED)*/
#define v22_E_IS_RX         0x08                    /* TX/RX bit in STATS block */
#define v22_E_MT_MASK       0x07                    /* modulation type mask (UNUSED) */
#define v22_E_VCID_MASK     0x03ff                  /* VC ID is only 9 bits */
#define v22_E_FLOW_VALID    0x40                    /* flow-is-valid flag (else force to 0) */
#define v22_E_DIFFERENTIATOR_MASK 0X3F              /* mask to differentiate ethernet from */
#define v22_E_IS_TCP            0x00000040                  /* TCP bit in FRAME_TYPE field */
#define v22_E_IS_UDP            0x00000010                  /* UDP bit in FRAME_TYPE field */
#define v22_E_IS_ICMP           0x00000020                  /* ICMP bit in FRAME_TYPE field */
#define v22_E_IS_IGMP           0x00000080                  /* IGMP bit in FRAME_TYPE field */
#define v22_E_IS_QOS            0x80                        /* QoS bit in MTYPE field (WLAN only) */
#define v22_E_IS_VLAN           0x00200000


#define v22_E_RX_DECRYPTS   0x0007                  /* RX-frame-was-decrypted (UNUSED) */
#define v22_E_TX_DECRYPTS   0x0007                  /* TX-frame-was-decrypted (UNUSED) */

#define v22_E_FC_PROT_BIT   0x40                    /* Protected Frame bit in FC1 of frame */


#define v22_E_HEADER_IS_RX  0x21
#define v22_E_HEADER_IS_TX  0x31

#define v22_E_IS_ETHERNET   0x00700000              /* bits set in frame type if ethernet */
#define v22_E_IS_80211      0x7F000000              /* bits set in frame type if 802.11 */

/* definitions for v2.2 frames, WLAN format for VW510006 FPGA*/
#define v22_W_STATS_LEN     64                      /* length of stats block trailer */
#define v22_W_VALID_OFF     0                       /* bit 6 (0x40) is flow-is-valid flag */
#define v22_W_MTYPE_OFF     1                       /* offset of modulation type */
#define v22_W_VCID_OFF      2                       /* offset of VC ID */
#define v22_W_FLOWSEQ_OFF   4                       /* offset of signature sequence number */
#define v22_W_FLOWID_OFF    5                       /* offset of flow ID */
#define v22_W_OCTET_OFF     8                       /* offset of octets */
#define v22_W_ERRORS_OFF    10                      /* offset of error vector */
#define v22_W_PATN_OFF      12
#define v22_W_L4ID_OFF      12
#define v22_W_IPLEN_OFF     14
#define v22_W_FRAME_TYPE_OFF        16              /* offset of frame type, 32 bits */
#define v22_W_RSSI_OFF      21                      /* RSSI (NOTE: RSSI must be negated!) */
#define v22_W_STARTT_OFF    24                      /* offset of start time, 64 bits */
#define v22_W_ENDT_OFF      32                      /* offset of end time, 64 bits */
#define v22_W_LATVAL_OFF    40                      /* offset of latency, 32 bits */
#define v22_W_INFO_OFF      54                      /* offset of INFO field, 16 LSBs */
#define v22_W_DIFFERENTIATOR_OFF    20              /* offset to determine whether */
                                                    /*  eth/802.11, 32 bits */

#define v22_W_PLCP_LENGTH_OFF       4               /* LENGTH field in the plcp header */


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
#define vVW510021_W_STATS_LEN           48          /* length of stats block trailer after the plcp portion*/
#define vVW510021_W_STARTT_OFF          0           /* offset of start time, 64 bits */
#define vVW510021_W_ENDT_OFF            8           /* offset of end time, 64 bits */
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
#define vVW510021_W_FPGA_VERSION_OFF    44          /* offset of fpga version, 16 bits */
#define vVW510021_W_MATCH_OFF           47          /* offset of pattern match vector */

/* offsets in the header block */
#define vVW510021_W_HEADER_LEN          16          /* length of FRAME header */
#define vVW510021_W_RXTX_OFF            0           /* rxtx offset, cmd byte of header */
#define vVW510021_W_HEADER_VERSION_OFF  9           /* version, 2bytes */
#define vVW510021_MSG_LENGTH_OFF        10          /* MSG LENGTH, 2bytes */
#define vVW510021_W_DEVICE_TYPE_OFF     8           /* version, 2bytes */

/* offsets that occurs right after the header */
#define vVW510021_W_AFTERHEADER_LEN     8           /* length of STATs info directly after header */
#define vVW510021_W_L1P_1_OFF           0           /* offset of 1st byte of layer one info */
#define vVW510021_W_L1P_2_OFF           1           /* offset of 2nd byte of layer one info */
#define vVW510021_W_MTYPE_OFF           vVW510021_W_L1P_2_OFF
#define vVW510021_W_PREAMBLE_OFF        vVW510021_W_L1P_1_OFF
#define vVW510021_W_RSSI_TXPOWER_OFF    2           /* RSSI (NOTE: RSSI must be negated!) */
#define vVW510021_W_MSDU_LENGTH_OFF     3           /* 7:0 of length, next byte 11:8 in top 4 bits */
#define vVW510021_W_BVCV_VALID_OFF      4           /* BV,CV Determine validaity of bssid and txpower */
#define vVW510021_W_VCID_OFF            6           /* offset of VC (client) ID */
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
#define vVW510021_W_FPGA_VERSION        0x000C
#define vVW510021_W_11n_FPGA_VERSION    0x000D

/* Error masks */
#define vVW510021_W_FCS_ERROR           0x10
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
#define vVW510024_E_MSDU_LENGTH_OFF     0           /* MSDU 16 BITS */
#define vVW510024_E_BMCV_VALID_OFF      2           /* BM,CV Determine validITY */
#define vVW510024_E_VCID_OFF            2           /* offset of VC (client) ID 13:8, */
                                                    /*  7:0 IN offset 7*/
#define vVW510024_E_STARTT_OFF          4           /* offset of start time, 64 bits */
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
#define vVW510024_E_HEADER_LEN          vVW510021_W_HEADER_LEN  /* length of FRAME header */
#define vVW510024_E_RXTX_OFF            vVW510021_W_RXTX_OFF    /* rxtx offset, cmd byte */
#define vVW510024_E_HEADER_VERSION_OFF  16                      /* version, 2bytes */
#define vVW510024_E_MSG_LENGTH_OFF      vVW510021_MSG_LENGTH_OFF    /* MSG LENGTH, 2bytes */
#define vVW510024_E_DEVICE_TYPE_OFF     vVW510021_W_DEVICE_TYPE_OFF /* Device Type, 2bytes */

/* Masks and defines */
#define vVW510024_E_IS_BV               0x80                    /* Bm bit in STATS block */
#define vVW510024_E_IS_CV               0x40                    /* cV bit in STATS block */
#define vVW510024_E_FLOW_VALID          0x8000                  /* valid_off flow-is-valid flag (else force to 0) */
#define vVW510024_E_QOS_VALID           0x0000                  /*not valid for ethernet*/
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
#define vVW510021_W_FPGA                1
#define vVW510006_W_FPGA                2
#define vVW510012_E_FPGA                3
#define vVW510024_E_FPGA                4

    /*the flow signature is:
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
#define SIG_SIZE        16                          /* size of signature field, bytes */
#define SIG_FID_OFF     4                           /* offset of flow ID in signature */
#define SIG_FSQ_OFF     7                           /* offset of flow seqnum in signature */
#define SIG_TS_OFF      8                           /* offset of flow seqnum in signature */



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
} vwr_t;

/* internal utility functions */
static int          decode_msg(vwr_t *vwr, register guint8 *, int *, int *);
static guint8       get_ofdm_rate(guint8 *);
static guint8       get_cck_rate(guint8 *plcp);
static void         setup_defaults(vwr_t *, guint16);

static gboolean     vwr_read(wtap *, int *, gchar **, gint64 *);
static gboolean     vwr_seek_read(wtap *, gint64, union wtap_pseudo_header *, guchar *,
                                  int, int *, gchar **);

static gboolean     vwr_read_rec_header(vwr_t *, FILE_T, int *, int *, int *, gchar **);
static void         vwr_read_rec_data(wtap *, guint8 *, guint8 *, int);

static int          vwr_get_fpga_version(wtap *, int *, gchar **);


static void         vwr_read_rec_data_vVW510021(wtap *, guint8 *, guint8 *, int, int);
static void         vwr_read_rec_data_ethernet(wtap *, guint8 *, guint8 *, int, int);

static int          find_signature(register guint8 *, int, register guint32, register guint8);
static guint64      get_signature_ts(register guint8 *, int);

/* open a .vwr file for reading */
/* this does very little, except setting the wiretap header for a VWR file type */
/* and the timestamp precision to microseconds */

int vwr_open(wtap *wth, int *err, gchar **err_info)
{
    int fpgaVer;
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
    vwr = (vwr_t *)g_malloc(sizeof(vwr_t));
    wth->priv = (void *)vwr;

    vwr->FPGA_VERSION = fpgaVer;
    /* set the local module options first */
    setup_defaults(vwr, fpgaVer);

    wth->snapshot_length = 0;
    wth->subtype_read = vwr_read;
    wth->subtype_seek_read = vwr_seek_read;
    wth->tsprecision = WTAP_FILE_TSPREC_USEC;

    if (fpgaVer == vVW510021_W_FPGA) {
        wth->file_type = WTAP_FILE_VWR_80211;
        wth->file_encap = WTAP_ENCAP_IXVERIWAVE;

    }
    else if (fpgaVer == vVW510006_W_FPGA) {
        wth->file_type = WTAP_FILE_VWR_80211;
        wth->file_encap = WTAP_ENCAP_IXVERIWAVE;

    } 
    else if (fpgaVer == vVW510012_E_FPGA) {
        wth->file_type = WTAP_FILE_VWR_ETH;
        wth->file_encap = WTAP_ENCAP_IXVERIWAVE;

    }
    else if (fpgaVer == vVW510024_E_FPGA) {
        wth->file_type = WTAP_FILE_VWR_ETH;
        wth->file_encap = WTAP_ENCAP_IXVERIWAVE;

    }

    return(1);
}


/* Read the next packet */
/* note that the VWR file format consists of a sequence of fixed 16-byte record headers of */
/* different types; some types, including frame record headers, are followed by */
/* variable-length data */
/* a frame record consists of: the above 16-byte record header, a 1-16384 byte raw PLCP */
/* frame, and a 64-byte statistics block trailer */
/* the PLCP frame consists of a 4-byte or 6-byte PLCP header, followed by the MAC frame */

static gboolean vwr_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
    vwr_t       *vwr = (vwr_t *)wth->priv;
    guint8      rec[B_SIZE];                        /* local buffer (holds input record) */
    int         rec_size = 0, IS_TX;
    guint8      *data_ptr;
    guint16     pkt_len;                            /* length of radiotap headers */

    /* read the next frame record header in the capture file; if no more frames, return */
    if (!vwr_read_rec_header(vwr, wth->fh, &rec_size, &IS_TX, err, err_info))
        return(FALSE);                                  /* Read error or EOF */

    *data_offset = (file_tell(wth->fh) - 16);           /* set offset for random seek @PLCP */

    /* got a frame record; read over entire record (frame + trailer) into a local buffer */
    /* if we don't get it all, then declare an error, we can't process the frame */
    if (file_read(rec, rec_size, wth->fh) != rec_size) {
        *err = file_error(wth->fh, err_info);
        if (*err == 0)
            *err = WTAP_ERR_SHORT_READ;
        return(FALSE);
    }

    

    /* before writing anything out, make sure the buffer has enough space for everything */
    if ((vwr->FPGA_VERSION == vVW510021_W_FPGA) || (vwr->FPGA_VERSION == vVW510006_W_FPGA) )
    /* frames are always 802.11 with an extended radiotap header */
        pkt_len = (guint16)(rec_size + STATS_COMMON_FIELDS_LEN + EXT_RTAP_FIELDS_LEN);
    else
        /* frames are always ethernet with an extended ethernettap header */
        pkt_len = (guint16)(rec_size + STATS_COMMON_FIELDS_LEN + STATS_ETHERNETTAP_FIELDS_LEN);
    buffer_assure_space(wth->frame_buffer, pkt_len);
    data_ptr = buffer_start_ptr(wth->frame_buffer);

    /* now format up the frame data */
    switch (vwr->FPGA_VERSION)
    {
        case vVW510006_W_FPGA:
            vwr_read_rec_data(wth, data_ptr, rec, rec_size);
            break;
        case vVW510021_W_FPGA:
            vwr_read_rec_data_vVW510021(wth, data_ptr, rec, rec_size, IS_TX);
            break;
        case vVW510012_E_FPGA:
            vwr_read_rec_data_ethernet(wth, data_ptr, rec, rec_size, IS_TX);
            break;
        case vVW510024_E_FPGA:
            vwr_read_rec_data_ethernet(wth, data_ptr, rec, rec_size, IS_TX);
            break;
    }

    /* If the per-file encapsulation isn't known, set it to this packet's encapsulation */
    /* If it *is* known, and it isn't this packet's encapsulation, set it to */
    /* WTAP_ENCAP_PER_PACKET, as this file doesn't have a single encapsulation for all */
    /* packets in the file */
    if (wth->file_encap == WTAP_ENCAP_UNKNOWN)
        wth->file_encap = wth->phdr.pkt_encap;
    else {
        if (wth->file_encap != wth->phdr.pkt_encap)
            wth->file_encap = WTAP_ENCAP_PER_PACKET;
    }

    return(TRUE);
}

/* read a random frame in the middle of a file; the start of the PLCP frame is @ seek_off */

static gboolean vwr_seek_read(wtap *wth, gint64 seek_off, union wtap_pseudo_header *pseudo_header _U_, guchar *pd, int pkt_size _U_,
    int *err, gchar **err_info)
{
    vwr_t       *vwr = (vwr_t *)wth->priv;
    guint8      rec[B_SIZE];                        /* local buffer (holds input record) */
    int         rec_size, IS_TX;

    /* first seek to the indicated record header */
    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
        return(FALSE);

    /* read in the record header */
    if (!vwr_read_rec_header(vwr, wth->random_fh, &rec_size, &IS_TX, err, err_info))
        return(FALSE);                                  /* Read error or EOF */

    /* read over the entire record (frame + trailer) into a local buffer */
    /* if we don't get it all, then declare an error, we can't process the frame */
    if (file_read(rec, rec_size, wth->random_fh) != rec_size) {
        *err = file_error(wth->random_fh, err_info);
        if (*err == 0)
            *err = WTAP_ERR_SHORT_READ;
        return(FALSE);
    }

    /* now format up the frame data into the passed buffer, according to the FPGA type */
    switch (vwr->FPGA_VERSION) {
        case vVW510006_W_FPGA:
            vwr_read_rec_data(wth, pd, rec, rec_size);
            break;
        case vVW510021_W_FPGA:
            vwr_read_rec_data_vVW510021(wth, pd, rec, rec_size, IS_TX);
            break;
        case vVW510012_E_FPGA:
            vwr_read_rec_data_ethernet(wth, pd, rec, rec_size, IS_TX);
            break;
        case vVW510024_E_FPGA:
            vwr_read_rec_data_ethernet(wth, pd, rec, rec_size, IS_TX);
            break;
    }

    return(TRUE);
}

/* scan down in the input capture file to find the next frame header */
/* decode and skip over all non-frame messages that are in the way */
/* return TRUE on success, FALSE on EOF or error */
/* also return the frame size in bytes and the "is transmitted frame" flag */

static gboolean vwr_read_rec_header(vwr_t *vwr, FILE_T fh, int *rec_size, int *IS_TX, int *err, gchar **err_info)
{
    int     f_len, v_type;
    guint8  header[16];

    errno = WTAP_ERR_CANT_READ;
    *rec_size = 0;

    /* read out the file data in 16-byte messages, stopping either after we find a frame, */
    /* or if we run out of data */
    /* each 16-byte message is decoded; if we run across a non-frame message followed by a*/
    /* variable-length item, we read the variable length item out and discard it */
    /* if we find a frame, we return (with the header in the passed buffer) */
    while (1) {
        if (file_read(header, 16, fh) != 16) {
            *err = file_error(fh, err_info);
            return(FALSE);
        }

        /* got a header; invoke decode-message function to parse and process it */
        /* if the function returns a length, then a frame or variable-length message */
        /* follows the 16-byte message */
        /* if the variable length message is not a frame, simply skip over it */
        if ((f_len = decode_msg(vwr, header, &v_type, IS_TX)) != 0) {
            if (f_len > B_SIZE) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = g_strdup_printf("vwr: Invalid message record length %d", f_len);
                return(FALSE);
            }
            else if (v_type != VT_FRAME) {
                if (file_seek(fh, f_len, SEEK_CUR, err) < 0)
                    return(FALSE);
            }
            else {
                *rec_size = f_len;
                return(TRUE);
            }
        }
    }
}

/* figure out the FPGA version (and also see whether this is a VWR file type */
/* return FPGA version if it's a known version, UNKNOWN_FPGA if it's not, */
/* and -1 on an I/O error. */

static int vwr_get_fpga_version(wtap *wth, int *err, gchar **err_info)
{
    guint8      rec[B_SIZE];                        /* local buffer (holds input record) */
    guint8      header[16];
    int         rec_size = 0;
    guint8      i;
    guint8      *s_510006_ptr = NULL;
    guint8      *s_510024_ptr = NULL; 
    guint8      *s_510012_ptr = NULL;               /* stats pointers */
    gint64      filePos = -1;
    guint32     frame_type = 0;
    int         f_len, v_type;
    guint16     data_length = 0;
    guint16     fpga_version;

    filePos = file_tell(wth->fh);
    if (filePos == -1) {
        *err = file_error(wth->fh, err_info);
        return(-1);
    }

    fpga_version = 1000;
    /* got a frame record; see if it is vwr  */
    /* if we don't get it all, then declare an error, we can't process the frame */
    /* read out the file data in 16-byte messages, stopping either after we find a frame, */
    /* or if we run out of data */
    /* each 16-byte message is decoded; if we run across a non-frame message followed by a*/
    /* variable-length item, we read the variable length item out and discard it */
    /* if we find a frame, we return (with the header in the passed buffer) */
    while ((file_read(header, 16, wth->fh)) == 16) {
        /* got a header; invoke decode-message function to parse and process it */
        /* if the function returns a length, then a frame or variable-length message */
        /* follows the 16-byte message */
        /* if the variable length message is not a frame, simply skip over it */
        if ((f_len = decode_msg(NULL, header, &v_type, NULL)) != 0) {
            if (f_len > B_SIZE) {
                /* Treat this here as an indication that the file probably */
                /* isn't an vwr file. */
                return(UNKNOWN_FPGA);
            }
            else if (v_type != VT_FRAME) {
                if (file_seek(wth->fh, f_len, SEEK_CUR, err) < 0)
                    return(-1);
            }
            else {
                rec_size = f_len;
                /* got a frame record; read over entire record (frame + trailer) into a local buffer */
                /* if we don't get it all, assume this isn't a vwr file */
                if (file_read(rec, rec_size, wth->fh) != rec_size) {
                    *err = file_error(wth->fh, err_info);
                    if (*err == 0)
                        return(UNKNOWN_FPGA); /* short read - not a vwr file */
                    return(-1);
                }


                /*  I'll grab the bytes where the Ethernet "octets" field should be and the bytes where */
                /*  the 802.11 "octets" field should be. Then if I do rec_size - octets - */
                /*  size_of_stats_block and it's 0, I can select the correct type. */
                /*  octets + stats_len = rec_size only when octets have been incremented to nearest */
                /*  number divisible by 4. */

                /* First check for series I WLAN since the check is more rigorous. */
                if (rec_size > v22_W_STATS_LEN) {
                    s_510006_ptr = &(rec[rec_size - v22_W_STATS_LEN]);      /* point to 510006 WLAN */
                                                                            /* stats block */
                
                    data_length = pntohs(&s_510006_ptr[v22_W_OCTET_OFF]);
                    i = 0;
                    while (((data_length + i) % 4) != 0)
                        i = i + 1;

                    frame_type = pntohl(&s_510006_ptr[v22_W_FRAME_TYPE_OFF]);

                    if (rec_size == (data_length + v22_W_STATS_LEN + i) && (frame_type & v22_W_IS_80211) == 0x1000000) {
                        fpga_version = vVW510006_W_FPGA; 
                    }
                }

                /* Next for the series I Ethernet */
                if ((rec_size > v22_E_STATS_LEN) && (fpga_version == 1000)) {
                    s_510012_ptr = &(rec[rec_size - v22_E_STATS_LEN]);      /* point to 510012 enet */
                                                                            /* stats block */
                    data_length = pntohs(&s_510012_ptr[v22_E_OCTET_OFF]);
                    i = 0;
                    while (((data_length + i) % 4) != 0)
                        i = i + 1;

                    if (rec_size == (data_length + v22_E_STATS_LEN + i))
                        fpga_version = vVW510012_E_FPGA; 
                }


                /* Next the series II WLAN */
                if ((rec_size > vVW510021_W_STATS_LEN) && (fpga_version == 1000)) {
                    /* stats block */

                    data_length = (256 * (rec[vVW510021_W_MSDU_LENGTH_OFF + 1] & 0x1f)) + rec[vVW510021_W_MSDU_LENGTH_OFF];

                    i = 0;
                    while (((data_length + i) % 4) != 0)
                        i = i + 1;

                    /*the 12 is from the 12 bytes of plcp header */
                    if (rec_size == (data_length + vVW510021_W_STATS_LEN +vVW510021_W_AFTERHEADER_LEN+12+i))
                        fpga_version = vVW510021_W_FPGA; 
                }

                /* Finally the Series II Ethernet */
                if ((rec_size > vVW510024_E_STATS_LEN) && (fpga_version == 1000)) {
                    s_510024_ptr = &(rec[rec_size - vVW510024_E_STATS_LEN]);    /* point to 510024 ENET */
                    data_length = pntohs(&s_510024_ptr[vVW510024_E_MSDU_LENGTH_OFF]);

                    i = 0;
                    while (((data_length + i) % 4) != 0)
                        i = i + 1;

                    if (rec_size == (data_length + vVW510024_E_STATS_LEN + i))
                        fpga_version = vVW510024_E_FPGA; 
                }
                if (fpga_version != 1000)
                {
                    /* reset the file position offset */
                    if (file_seek (wth->fh, filePos, SEEK_SET, err) == -1) {
                        return (-1);
                    }
                    /* We found an FPGA that works */
                    return(fpga_version);
                }
            }
        }
    }

    *err = file_error(wth->fh, err_info);
    if (*err == 0)
        return(UNKNOWN_FPGA); /* short read - not a vwr file */
    return(-1);
}

/* copy the actual packet data from the capture file into the target data block */
/* the packet is constructed as a 38-byte VeriWave-extended Radiotap header plus the raw */
/* MAC octets */

static void vwr_read_rec_data(wtap *wth, guint8 *data_ptr, guint8 *rec, int rec_size)
{
    vwr_t           *vwr = (vwr_t *)wth->priv;
    int             bytes_written = 0;              /* bytes output to buf so far */
    register int    i;                              /* temps */
    register guint8 *s_ptr, *m_ptr;                 /* stats and MPDU pointers */
    gint16          octets, msdu_length;            /* octets in frame */
    guint8          m_type, flow_seq;               /* mod type (CCK-L/CCK-S/OFDM), seqnum */
    guint64         s_time = LL_ZERO, e_time = LL_ZERO; /* start/end */
                                                    /* times, nsec */
    guint32         latency;
    guint64         start_time, s_sec, s_usec = LL_ZERO; /* start time, sec + usec */
    guint64         end_time;                       /* end time */
    guint16         info;                           /* INFO/ERRORS fields in stats blk */
    gint16          rssi;                           /* RSSI, signed 16-bit number */
    int             f_tx;                           /* flag: if set, is a TX frame */
    int             f_flow, f_qos;                  /* flags: flow valid, frame is QoS */
    guint32         frame_type;                     /* frame type field */
    int             rate;                           /* PHY bit rate in 0.5 Mb/s units */
    guint16         vc_id, flow_id, ht_len=0;       /* VC ID, flow ID, total ip length */
    guint32         d_time, errors;                 /* packet duration & errors */
    guint16         r_hdr_len;                      /* length of radiotap headers */
    ext_rtap_fields er_fields;                      /* extended radiotap fields */
    stats_common_fields common_fields;              /* extended radiotap fields */
    int             mac_snap, sig_off, pay_off;     /* MAC+SNAP header len, signature offset */
    guint64         sig_ts;                         /* 32 LSBs of timestamp in signature */

    /* calculate the start of the statistics block in the buffer */
    /* also get a bunch of fields from the stats block */
    s_ptr = &(rec[rec_size - vwr->STATS_LEN]);               /* point to it */
    m_type = s_ptr[vwr->MTYPE_OFF] & vwr->MT_MASK;
    f_tx = !(s_ptr[vwr->MTYPE_OFF] & vwr->IS_RX);
    octets = pntohs(&s_ptr[vwr->OCTET_OFF]);
    vc_id = pntohs(&s_ptr[vwr->VCID_OFF]) & vwr->VCID_MASK;
    flow_seq = s_ptr[vwr->FLOWSEQ_OFF];

    f_flow = (s_ptr[vwr->VALID_OFF] & (guint8)vwr->FLOW_VALID) != 0;
    f_qos = (s_ptr[vwr->MTYPE_OFF] & vwr->IS_QOS) != 0;
    frame_type = pntohl(&s_ptr[vwr->FRAME_TYPE_OFF]);

    /* XXX - this is 48 bits, in a weird byte order */
    latency = pntohs(&s_ptr[vwr->LATVAL_OFF + 6]);   /* latency MSbytes */
    for (i = 0; i < 4; i++)
        latency = (latency << 8) | s_ptr[vwr->LATVAL_OFF + i];

    flow_id = pntohs(&s_ptr[vwr->FLOWID_OFF + 1]);   /* only 16 LSBs kept */
    errors = pntohs(&s_ptr[vwr->ERRORS_OFF]);

    info = pntohs(&s_ptr[vwr->INFO_OFF]);
    rssi = (s_ptr[vwr->RSSI_OFF] & 0x80) ? (-1 * (s_ptr[vwr->RSSI_OFF] & 0x7f)) : s_ptr[vwr->RSSI_OFF];
    /*if ((info && AGGREGATE_MASK) != 0)*/
    /* this length includes the Start_Spacing + Delimiter + MPDU + Padding for each piece of the aggregate*/
        /*ht_len = (int)pletohs(&rec[PLCP_LENGTH_OFF]);*/

    /* decode OFDM or CCK PLCP header and determine rate and short preamble flag */
    /* the SIGNAL byte is always the first byte of the PLCP header in the frame */
    if (m_type == vwr->MT_OFDM)
        rate = get_ofdm_rate(rec);
    else if ((m_type == vwr->MT_CCKL) || (m_type == vwr->MT_CCKS))
        rate = get_cck_rate(rec);
    else
        rate = 1;
    /* calculate the MPDU size/ptr stuff; MPDU starts at 4 or 6 depending on OFDM/CCK */
    /* note that the number of octets in the frame also varies depending on OFDM/CCK, */
    /*  because the PLCP header is prepended to the actual MPDU */
    m_ptr = &(rec[((m_type == vwr->MT_OFDM) ? 4 : 6)]);
    octets -= (m_type == vwr->MT_OFDM) ? 4 : 6;

    /* sanity check the octets field to determine if it is OK (or segfaults result) */
    /* if it's greater, then truncate to actual record size */
    if (octets > (rec_size - (int)vwr->STATS_LEN))
        octets = (rec_size - (int)vwr->STATS_LEN);
    msdu_length = octets;


    /* calculate start & end times (in sec/usec), converting 64-bit times to usec */
    /* 64-bit times are "Corey-endian" */
    s_time = pcoreytohll(&s_ptr[vwr->STARTT_OFF]);
    e_time = pcoreytohll(&s_ptr[vwr->ENDT_OFF]);

    /* find the packet duration (difference between start and end times) */
    d_time = (guint32)((e_time - s_time) / NS_IN_US);   /* find diff, converting to usec */

    /* also convert the packet start time to seconds and microseconds */
    start_time = s_time / NS_IN_US;                     /* convert to microseconds first */
    s_sec = (start_time / US_IN_SEC);                   /* get the number of seconds */
    s_usec = start_time - (s_sec * US_IN_SEC);          /* get the number of microseconds */

    /* also convert the packet end time to seconds and microseconds */
    end_time = e_time / NS_IN_US;                       /* convert to microseconds first */

    /* extract the 32 LSBs of the signature timestamp field from the data block*/
    mac_snap = (f_qos ? 34 : 32);                       /* 24 (MAC) + 2 (QoS) + 8 (SNAP) */

    if (frame_type & vwr->IS_TCP)                       /* signature offset for TCP frame */
    {
        pay_off = mac_snap + 40;
    }
    else if (frame_type & vwr->IS_UDP)                  /* signature offset for UDP frame */
    {
        pay_off = mac_snap + 28;
    }
    else if (frame_type & vwr->IS_ICMP)                 /* signature offset for ICMP frame */
    {
        pay_off = mac_snap + 24;
    }
    else if (frame_type & vwr->IS_IGMP)                 /* signature offset for IGMPv2 frame */
    {
        pay_off = mac_snap + 28;
    }
    else                                                /* signature offset for raw IP frame */
    {
        pay_off = mac_snap + 20;
    }

    sig_off = find_signature(m_ptr, pay_off, flow_id, flow_seq);
    if ((m_ptr[sig_off] == 0xdd) && (sig_off + 15 <= msdu_length) && (f_flow != 0))
        sig_ts = get_signature_ts(m_ptr, sig_off);
    else
        sig_ts = 0;

    /* fill up the per-packet header (amazingly like a PCAP packet header! ;-) */
    /* frames are always 802.11, with an extended radiotap header */
    /* caplen is the length that is captured into the file (i.e., the written-out frame */
    /* block), and should always represent the actual number of bytes in the file */
    /* len is the length of the original packet before truncation;  */
    /* the FCS is NOT included */
    r_hdr_len = STATS_COMMON_FIELDS_LEN + EXT_RTAP_FIELDS_LEN;

    wth->phdr.len = (msdu_length - 4) + r_hdr_len;
    wth->phdr.caplen = (octets - 4) + r_hdr_len;

    wth->phdr.presence_flags = WTAP_HAS_TS;

    wth->phdr.ts.secs = (time_t)s_sec;
    wth->phdr.ts.nsecs = (long)(s_usec * 1000);
    wth->phdr.pkt_encap = WTAP_ENCAP_IXVERIWAVE;

    /* generate and copy out the radiotap header, set the port type to 0 (WLAN) */
    common_fields.vw_port_type = 0;
    common_fields.it_len = STATS_COMMON_FIELDS_LEN;
    er_fields.it_len = EXT_RTAP_FIELDS_LEN;

    /* create the extended radiotap header fields */
    er_fields.flags = (m_type == vwr->MT_CCKS) ? RADIOTAP_F_SHORTPRE : 0;

    er_fields.rate = rate;
    er_fields.chanflags = (m_type == vwr->MT_OFDM) ? CHAN_OFDM : CHAN_CCK;
    er_fields.signal = f_tx ? 100 : (gint8)rssi;
    er_fields.tx_power = f_tx ? ((gint8)rssi) : 100;

    /* fill in the VeriWave flags field */
    er_fields.vw_flags = 0;
    if (f_tx)
        er_fields.vw_flags |= RADIOTAP_VWF_TXF;
    if (errors & vwr->FCS_ERROR)
        er_fields.vw_flags |= RADIOTAP_VWF_FCSERR;
    if (!f_tx && (errors & vwr->CRYPTO_ERR))
        er_fields.vw_flags |= RADIOTAP_VWF_DCRERR;
    if (!f_tx && (errors & vwr->RETRY_ERR))
        er_fields.vw_flags |= RADIOTAP_VWF_RETRERR;
    if (info & vwr->WEPTYPE)
        er_fields.vw_flags |= RADIOTAP_VWF_IS_WEP;
    else if (info & vwr->TKIPTYPE)
        er_fields.vw_flags |= RADIOTAP_VWF_IS_TKIP;
    else if (info & vwr->CCMPTYPE)
        er_fields.vw_flags |= RADIOTAP_VWF_IS_CCMP;

    er_fields.vw_errors = (guint32)errors;
    common_fields.vw_vcid = (guint16)vc_id;
    common_fields.vw_flowid = (guint16)flow_id;
    common_fields.vw_seqnum = (guint16)flow_seq;
    if (!f_tx && sig_ts != 0)
        common_fields.vw_latency = (guint32)latency;
    else
        common_fields.vw_latency = 0;
    common_fields.vw_pktdur = (guint32)d_time;
    er_fields.vw_info = (guint16)info;
    common_fields.vw_msdu_length = (guint16)msdu_length;
    er_fields.vw_ht_length = (guint16)ht_len;
    common_fields.vw_sig_ts = (guint32)sig_ts;              /* 32 LSBs of signature timestamp (nsec) */
    common_fields.vw_startt = start_time;                   /* record start & end times of frame */
    common_fields.vw_endt = end_time;

    /* put common_fields into the packet buffer in little-endian byte order */
    phtoles(&data_ptr[bytes_written], common_fields.vw_port_type);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], common_fields.it_len);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], common_fields.vw_msdu_length);
    bytes_written += 2;
    /* padding */
    memset(&data_ptr[bytes_written], 0, 2);
    bytes_written += 2;
    phtolel(&data_ptr[bytes_written], common_fields.vw_flowid);
    bytes_written += 4;
    phtoles(&data_ptr[bytes_written], common_fields.vw_vcid);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], common_fields.vw_seqnum);
    bytes_written += 2;
    phtolel(&data_ptr[bytes_written], common_fields.vw_latency);
    bytes_written += 4;
    phtolel(&data_ptr[bytes_written], common_fields.vw_sig_ts);
    bytes_written += 4;
    phtolell(&data_ptr[bytes_written], common_fields.vw_startt);
    bytes_written += 8;
    phtolell(&data_ptr[bytes_written], common_fields.vw_endt);
    bytes_written += 8;
    phtolel(&data_ptr[bytes_written], common_fields.vw_pktdur);
    bytes_written += 4;
    /* padding */
    memset(&data_ptr[bytes_written], 0, 4);
    bytes_written += 4;

    /* put er_fields into the packet buffer in little-endian byte order */
    phtoles(&data_ptr[bytes_written], er_fields.it_len);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], er_fields.flags);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], er_fields.chanflags);
    bytes_written += 2;
    data_ptr[bytes_written] = er_fields.rate;
    bytes_written += 1;
    data_ptr[bytes_written] = er_fields.signal;
    bytes_written += 1;
    data_ptr[bytes_written] = er_fields.tx_power;
    bytes_written += 1;
    /* padding */
    data_ptr[bytes_written] = 0;
    bytes_written += 1;
    phtoles(&data_ptr[bytes_written], er_fields.vw_flags);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], er_fields.vw_ht_length);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], er_fields.vw_info);
    bytes_written += 2;
    phtolel(&data_ptr[bytes_written], er_fields.vw_errors);
    bytes_written += 4;

    /* finally, copy the whole MAC frame to the packet buffer as-is; exclude FCS */
    if ( rec_size < ((int)msdu_length + (int)vwr->STATS_LEN) ) 
        /*something's been truncated, DUMP AS-IS*/
        memcpy(&data_ptr[bytes_written], m_ptr, octets);
    else if (octets >= 4)
        memcpy(&data_ptr[bytes_written], m_ptr, octets - 4);
    else
        memcpy(&data_ptr[bytes_written], m_ptr, octets);
}

/* Read the next packet for vVW510021 FPGAs */
/* note that the VWR file format consists of a sequence of fixed 16-byte record headers of */
/* different types; some types, including frame record headers, are followed by */
/* variable-length data */
/* a frame record consists of: the above 16-byte record header, a 1-16384 byte raw PLCP */
/* frame, and a 56-byte statistics block trailer */
/* the PLCP frame consists of a 4-byte or 6-byte PLCP header, followed by the MAC frame */
/* copy the actual packet data from the capture file into the target data block */
/* the packet is constructed as a 38-byte VeriWave-extended Radiotap header plus the raw */
/* MAC octets */

static void vwr_read_rec_data_vVW510021(wtap *wth, guint8 *data_ptr, guint8 *rec, int rec_size, int IS_TX)
{
    vwr_t           *vwr = (vwr_t *)wth->priv;
    int             bytes_written = 0;              /* bytes output to buf so far */
    int             PLCP_OFF = 8;
    register int    i;                              /* temps */
    register        guint8  *s_start_ptr,*s_trail_ptr, *m_ptr,*plcp_ptr; /* stats & MPDU ptr */
    gint16          msdu_length, actual_octets;        /* octets in frame */
    guint8          l1p_1,l1p_2, flow_seq, plcp_type, mcs_index;   /* mod (CCK-L/CCK-S/OFDM) */
    guint64         s_time = LL_ZERO, e_time = LL_ZERO; /* start/end */
                                                    /*  times, nsec */
    guint64         latency = LL_ZERO;
    guint64         start_time, s_sec, s_usec = LL_ZERO; /* start time, sec + usec */
    guint64         end_time;                       /* end time */
    guint16         info, validityBits;             /* INFO/ERRORS fields in stats blk */
    guint32         errors;
    gint16          rssi;                           /* RSSI, signed 16-bit number */
    int             f_tx;                           /* flag: if set, is a TX frame */
    int             f_flow, f_qos;                  /* flags: flow valid, frame is QoS */
    guint32         frame_type;                     /* frame type field */
    guint8          rate;                           /* PHY bit rate in 0.5 Mb/s units */
    guint16         vc_id, ht_len=0;                /* VC ID , total ip length*/
    guint32         flow_id, d_time;                /* flow ID, packet duration*/
    guint16         r_hdr_len;                      /* length of radiotap headers */
    ext_rtap_fields er_fields;                      /* extended radiotap fields */
    stats_common_fields common_fields;              /* extended radiotap fields */
    gint8           tx_power = 0;                   /* transmit power value in dBm */
    int             mac_snap, sig_off, pay_off;     /* MAC+SNAP header len, signature offset */
    guint64         sig_ts, tsid;                   /* 32 LSBs of timestamp in signature */
    guint16         chanflags = 0;                  /* extended radio tap channel flags */
    guint16         radioflags = 0;                 /* extended radio tap flags */
    guint64         delta_b;                        /* Used for calculating latency */
    
    /* calculate the start of the statistics block in the buffer */
    /* also get a bunch of fields from the stats block */
    s_start_ptr = &(rec[0]);
    s_trail_ptr = &(rec[rec_size - vwr->STATS_LEN]);             /* point to it */

    l1p_1 = s_start_ptr[vwr->L1P_1_OFF];
    mcs_index = l1p_1 & (guint8)vVW510021_W_MCS_MASK;
    l1p_2 = s_start_ptr[vwr->L1P_2_OFF];
    plcp_type = l1p_2 & (guint8)vVW510021_W_PLCPC_MASK;
    msdu_length = (256 * (s_start_ptr[vwr->OCTET_OFF + 1] & 0x1f)) + s_start_ptr[vwr->OCTET_OFF];
    /* If the packet has an MSDU length of 0, then bail - malformed packet */
    /* if (msdu_length < 4) return; */
    actual_octets = msdu_length;
    

    f_tx = IS_TX;
    vc_id = pntohs(&s_start_ptr[vwr->VCID_OFF]);
    flow_seq = s_trail_ptr[vwr->FLOWSEQ_OFF];
    validityBits = pntohs(&s_trail_ptr[vwr->VALID_OFF]);

    f_flow = (validityBits & vwr->FLOW_VALID) != 0;
    f_qos = (validityBits & vwr->IS_QOS) != 0;

    frame_type = pntohl(&s_trail_ptr[vwr->FRAME_TYPE_OFF]);

    latency = 0x00000000;                                     /* clear latency */
    flow_id = pntoh24(&s_trail_ptr[vwr->FLOWID_OFF]);         /* all 24 bits valid */
    /* for tx latency is duration, for rx latency is timestamp */
    /* get 48-bit latency value */
    tsid = (s_trail_ptr[vwr->LATVAL_OFF + 6] << 8) | (s_trail_ptr[vwr->LATVAL_OFF + 7]);

    for (i = 0; i < 4; i++)
        tsid = (tsid << 8) | s_trail_ptr[vwr->LATVAL_OFF + i];

    errors = pntohl(&s_trail_ptr[vwr->ERRORS_OFF]);
    info = pntohs(&s_trail_ptr[vwr->INFO_OFF]);
    if ((info & 0xFC00) != 0)
    /* this length includes the Start_Spacing + Delimiter + MPDU + Padding for each piece of the aggregate*/
        ht_len = pletohs(&s_start_ptr[vwr->PLCP_LENGTH_OFF]);

    rssi = s_start_ptr[vwr->RSSI_OFF];
    if (f_tx) {
        if (rssi & 0x80)
            tx_power = -1 * (rssi & 0x7f);
        else
            tx_power = rssi & 0x7f;
    } else {
        if (rssi > 128) rssi = rssi - 256;  /* Signed 2's complement */
    }

    /* decode OFDM or CCK PLCP header and determine rate and short preamble flag */
    /* the SIGNAL byte is always the first byte of the PLCP header in the frame */
    plcp_ptr = &(rec[PLCP_OFF]);
    if (plcp_type == vVW510021_W_PLCP_LEGACY){
        if (mcs_index < 4) {
            rate = get_cck_rate(plcp_ptr);
            chanflags |= CHAN_CCK;
        }
        else {
            rate = get_ofdm_rate(plcp_ptr);
            chanflags |= CHAN_OFDM;
        }
    }
    else if (plcp_type == vVW510021_W_PLCP_MIXED) {
        /* pack the rate field with mcs index and gi */
        rate = (plcp_ptr[3] & 0x7f) + (plcp_ptr[6] & 0x80);
        /* set the appropriate flags to indicate HT mode and CB */
        radioflags |= RADIOTAP_F_CHAN_HT | ((plcp_ptr[3] & 0x80) ? RADIOTAP_F_CHAN_40MHZ : 0) |
                      ((plcp_ptr[6] & 0x80) ? RADIOTAP_F_CHAN_SHORTGI : 0);
        chanflags |= CHAN_OFDM;
    }
    else if (plcp_type == vVW510021_W_PLCP_GREENFIELD) {
        /* pack the rate field with mcs index and gi */
        rate = (plcp_ptr[0] & 0x7f) + (plcp_ptr[3] & 0x80);
        /* set the appropriate flags to indicate HT mode and CB */
        radioflags |= RADIOTAP_F_CHAN_HT | ((plcp_ptr[0] & 0x80) ? RADIOTAP_F_CHAN_40MHZ : 0) |
                      ((plcp_ptr[3] & 0x80) ? RADIOTAP_F_CHAN_SHORTGI : 0);
        chanflags |= CHAN_OFDM;
    }
    else {
        rate = 1;
    }
    
    /* calculate the MPDU size/ptr stuff; MPDU starts at 4 or 6 depending on OFDM/CCK */
    /* note that the number of octets in the frame also varies depending on OFDM/CCK, */
    /*  because the PLCP header is prepended to the actual MPDU */
    /*the 8 is from the 8 bytes of stats block that precede the plcps , 
    the 12 is for 11 bytes plcp and 1 byte of pad before the data*/
    m_ptr = &(rec[8+12]);

    /* sanity check the msdu_length field to determine if it is OK (or segfaults result) */
    /* if it's greater, then truncate to the indicated message length */
        /*changed the comparison
        if (msdu_length > (rec_size )) {
        msdu_length = (rec_size );
    }
*/
    if (msdu_length > (rec_size - (int)vwr->STATS_LEN)) {
        msdu_length = (rec_size - (int)vwr->STATS_LEN);
    }

    /* calculate start & end times (in sec/usec), converting 64-bit times to usec */
    /* 64-bit times are "Corey-endian" */
    s_time = pcoreytohll(&s_trail_ptr[vwr->STARTT_OFF]);
    e_time = pcoreytohll(&s_trail_ptr[vwr->ENDT_OFF]);

    /* find the packet duration (difference between start and end times) */
    d_time = (guint32)((e_time - s_time) / NS_IN_US);  /* find diff, converting to usec */

    /* also convert the packet start time to seconds and microseconds */
    start_time = s_time / NS_IN_US;                     /* convert to microseconds first */
    s_sec = (start_time / US_IN_SEC);                   /* get the number of seconds */
    s_usec = start_time - (s_sec * US_IN_SEC);          /* get the number of microseconds */

    /* also convert the packet end time to seconds and microseconds */
    end_time = e_time / NS_IN_US;                       /* convert to microseconds first */

    /* extract the 32 LSBs of the signature timestamp field */
    mac_snap = (f_qos ? 34 : 32);                       /* 24 (MAC) + 2 (QoS) + 8 (SNAP) */

    if (frame_type & vwr->IS_TCP)                            /* signature offset for TCP frame */
    {
        pay_off = mac_snap + 40;
    }
    else if (frame_type & vwr->IS_UDP)                       /* signature offset for UDP frame */
    {
        pay_off = mac_snap + 28;
    }
    else if (frame_type & vwr->IS_ICMP)                      /* signature offset for ICMP frame */
    {
        pay_off = mac_snap + 24;
    }
    else if (frame_type & vwr->IS_IGMP)                      /* signature offset for IGMPv2 frame */
    {
        pay_off = mac_snap + 28;
    }
    else                                                /* signature offset for raw IP frame */
    {
        pay_off = mac_snap + 20;
    }

    sig_off = find_signature(m_ptr, pay_off, flow_id, flow_seq);
    if ((m_ptr[sig_off] == 0xdd) && (sig_off + 15 <= msdu_length) && (f_flow != 0))
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

    /* fill up the per-packet header (amazingly like a PCAP packet header! ;-) */
    /* frames are always 802.11, with an extended radiotap header */
    /* caplen is the length that is captured into the file (i.e., the written-out frame */
    /* block), and should always represent the actual number of bytes in the file */
    /* len is the length of the original packet before truncation */
    /* the FCS is NOT included */
    r_hdr_len = STATS_COMMON_FIELDS_LEN + EXT_RTAP_FIELDS_LEN;
    wth->phdr.len = (actual_octets - 4) + r_hdr_len;
    wth->phdr.caplen = (msdu_length - 4) + r_hdr_len;

    wth->phdr.presence_flags = WTAP_HAS_TS;

    wth->phdr.ts.secs = (time_t)s_sec;
    wth->phdr.ts.nsecs = (long)(s_usec * 1000);
    wth->phdr.pkt_encap = WTAP_ENCAP_IXVERIWAVE;

    /* generate and copy out the radiotap header, set the port type to 0 (WLAN) */
    common_fields.vw_port_type = 0;
    common_fields.it_len = STATS_COMMON_FIELDS_LEN;
    er_fields.it_len = EXT_RTAP_FIELDS_LEN;

    /* create the extended radiotap header fields */
    er_fields.flags = radioflags;
    if (info & vVW510021_W_IS_WEP)
        er_fields.flags |= RADIOTAP_F_WEP;
    if ((l1p_1 & vVW510021_W_PREAMBLE_MASK) != vVW510021_W_IS_LONGPREAMBLE)
        er_fields.flags |= RADIOTAP_F_SHORTPRE;

    er_fields.rate = rate;
    er_fields.chanflags = chanflags; 
    
    if (f_tx) {
        er_fields.tx_power = (gint8)tx_power;
        er_fields.signal = 100;
    }
    else {
        er_fields.tx_power = 100;
        er_fields.signal = (gint8)rssi;
    }

    /* fill in the VeriWave flags field */
    er_fields.vw_flags = 0;
    if (f_tx)
        er_fields.vw_flags |= RADIOTAP_VWF_TXF;
    if (errors & vwr->FCS_ERROR)
        er_fields.vw_flags |= RADIOTAP_VWF_FCSERR;
    if (!f_tx && (errors & vwr->CRYPTO_ERR))
        er_fields.vw_flags |= RADIOTAP_VWF_DCRERR;
    if (!f_tx && (errors & vwr->RETRY_ERR))
        er_fields.vw_flags |= RADIOTAP_VWF_RETRERR;
    if (info & vwr->WEPTYPE)
        er_fields.vw_flags |= RADIOTAP_VWF_IS_WEP;
    else if (info & vwr->TKIPTYPE)
        er_fields.vw_flags |= RADIOTAP_VWF_IS_TKIP;
    else if (info & vwr->CCMPTYPE)
        er_fields.vw_flags |= RADIOTAP_VWF_IS_CCMP;

    er_fields.vw_errors = (guint32)errors;
    common_fields.vw_vcid = (guint16)vc_id;

    common_fields.vw_msdu_length = (guint16)msdu_length;
    er_fields.vw_ht_length = (guint16)ht_len;

    common_fields.vw_flowid = (guint32)flow_id;
    common_fields.vw_seqnum = (guint16)flow_seq;
    if (!f_tx && (sig_ts != 0) )
        common_fields.vw_latency = (guint32)latency;
    else
        common_fields.vw_latency = 0;
    common_fields.vw_pktdur = (guint32)d_time;
    er_fields.vw_info = (guint16)info;
    /*
        er_fields.vw_startt = s_time;
        er_fields.vw_endt = e_time;
    */
    common_fields.vw_startt = start_time;                   /* record start & end times of frame */
    common_fields.vw_endt = end_time;
    common_fields.vw_sig_ts = (guint32)(sig_ts);/* 32 LSBs of signature  */

    /* put common_fields into the packet buffer in little-endian byte order */
    phtoles(&data_ptr[bytes_written], common_fields.vw_port_type);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], common_fields.it_len);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], common_fields.vw_msdu_length);
    bytes_written += 2;
    /* padding */
    memset(&data_ptr[bytes_written], 0, 2);
    bytes_written += 2;
    phtolel(&data_ptr[bytes_written], common_fields.vw_flowid);
    bytes_written += 4;
    phtoles(&data_ptr[bytes_written], common_fields.vw_vcid);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], common_fields.vw_seqnum);
    bytes_written += 2;
    phtolel(&data_ptr[bytes_written], common_fields.vw_latency);
    bytes_written += 4;
    phtolel(&data_ptr[bytes_written], common_fields.vw_sig_ts);
    bytes_written += 4;
    phtolell(&data_ptr[bytes_written], common_fields.vw_startt);
    bytes_written += 8;
    phtolell(&data_ptr[bytes_written], common_fields.vw_endt);
    bytes_written += 8;
    phtolel(&data_ptr[bytes_written], common_fields.vw_pktdur);
    bytes_written += 4;
    /* padding */
    memset(&data_ptr[bytes_written], 0, 4);
    bytes_written += 4;

    /* put er_fields into the packet buffer in little-endian byte order */
    phtoles(&data_ptr[bytes_written], er_fields.it_len);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], er_fields.flags);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], er_fields.chanflags);
    bytes_written += 2;
    data_ptr[bytes_written] = er_fields.rate;
    bytes_written += 1;
    data_ptr[bytes_written] = er_fields.signal;
    bytes_written += 1;
    data_ptr[bytes_written] = er_fields.tx_power;
    bytes_written += 1;
    /* padding */
    data_ptr[bytes_written] = 0;
    bytes_written += 1;
    phtoles(&data_ptr[bytes_written], er_fields.vw_flags);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], er_fields.vw_ht_length);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], er_fields.vw_info);
    bytes_written += 2;
    phtolel(&data_ptr[bytes_written], er_fields.vw_errors);
    bytes_written += 4;

    /* finally, copy the whole MAC frame to the packet buffer as-is; exclude 4-byte FCS */
    if ( rec_size < ((int)actual_octets + (int)vwr->STATS_LEN) ) 
        /*something's been truncated, DUMP AS-IS*/
        memcpy(&data_ptr[bytes_written], m_ptr, msdu_length);
    else if (msdu_length >= 4)
        memcpy(&data_ptr[bytes_written], m_ptr, msdu_length - 4);
    else
        memcpy(&data_ptr[bytes_written], m_ptr, msdu_length);
}

/* read an Ethernet packet */
/* copy the actual packet data from the capture file into the target data block */
/* the packet is constructed as a 38-byte VeriWave-extended Radiotap header plus the raw */
/* MAC octets */

static void vwr_read_rec_data_ethernet(wtap *wth, guint8 *data_ptr, guint8 *rec, int rec_size, int IS_TX)
{
    vwr_t           *vwr = (vwr_t *)wth->priv;
    int             bytes_written = 0;              /* bytes output to buf so far */
    register int    i;                              /* temps */
    register guint8 *s_ptr, *m_ptr;                 /* stats and MPDU pointers */
    guint16         msdu_length,actual_octets;      /* octets in frame */
    guint8          flow_seq;                       /* seqnum */
    guint64         s_time = LL_ZERO, e_time = LL_ZERO; /* start/end */
                                                        /* times, nsec */
    guint32         latency = 0;
    guint64         start_time, s_sec, s_usec = LL_ZERO; /* start time, sec + usec */
    guint64         end_time;                            /* end time */
    guint16         l4id, info, validityBits;            /* INFO/ERRORS fields in stats */
    guint32         errors;
    guint16         vc_id;                          /* VC ID, total (incl of aggregates) */
    guint32         flow_id, d_time;                /* packet duration */
    int             f_flow;                         /* flags: flow valid */
    guint32         frame_type;                     /* frame type field */
    stats_ethernettap_fields    etap_hdr;           /* VWR ethernettap header */
    stats_common_fields common_hdr;                 /* VWR common header */
    guint16         e_hdr_len;                      /* length of ethernettap headers */
    int             mac_len, sig_off, pay_off;      /* MAC header len, signature offset */
    guint64         sig_ts, tsid;                   /* 32 LSBs of timestamp in signature */
    guint64         delta_b;    /* Used for calculating latency */

    /* calculate the start of the statistics block in the buffer */
    /* also get a bunch of fields from the stats block */
    m_ptr = &(rec[0]);                              /* point to the data block */
    s_ptr = &(rec[rec_size - vwr->STATS_LEN]);      /* point to the stats block */
    
    msdu_length = pntohs(&s_ptr[vwr->OCTET_OFF]);
    actual_octets = msdu_length;
    /* sanity check the msdu_length field to determine if it is OK (or segfaults result) */
    /* if it's greater, then truncate to the indicated message length */
    if (msdu_length > (rec_size - (int)vwr->STATS_LEN)) {
        msdu_length = (rec_size - (int)vwr->STATS_LEN);
    }

    vc_id = pntohs(&s_ptr[vwr->VCID_OFF]) & vwr->VCID_MASK;
    flow_seq = s_ptr[vwr->FLOWSEQ_OFF];
    frame_type = pntohl(&s_ptr[vwr->FRAME_TYPE_OFF]);

    if (vwr->FPGA_VERSION == vVW510024_E_FPGA) {
        validityBits = pntohs(&s_ptr[vwr->VALID_OFF]);
        f_flow = validityBits & vwr->FLOW_VALID;

        mac_len = (validityBits & vwr->IS_VLAN) ? 16 : 14;           /* MAC hdr length based on VLAN tag */


        errors = pntohs(&s_ptr[vwr->ERRORS_OFF]);
    }
    else {
        f_flow = s_ptr[vwr->VALID_OFF] & vwr->FLOW_VALID;
        mac_len = (frame_type & vwr->IS_VLAN) ? 16 : 14;             /* MAC hdr length based on VLAN tag */


        /*for older fpga errors is only represented by 16 bits)*/
        errors = pntohs(&s_ptr[vwr->ERRORS_OFF]);
    }

    info = pntohs(&s_ptr[vwr->INFO_OFF]);
    /*  24 LSBs */
    flow_id = pntoh24(&s_ptr[vwr->FLOWID_OFF]);

    /* for tx latency is duration, for rx latency is timestamp */
    /* get 64-bit latency value */
    tsid = (s_ptr[vwr->LATVAL_OFF + 6] << 8) | (s_ptr[vwr->LATVAL_OFF + 7]);
    for (i = 0; i < 4; i++)
        tsid = (tsid << 8) | s_ptr[vwr->LATVAL_OFF + i];


    l4id = pntohs(&s_ptr[vwr->L4ID_OFF]);

    /* calculate start & end times (in sec/usec), converting 64-bit times to usec */
    /* 64-bit times are "Corey-endian" */
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

    sig_off = find_signature(m_ptr, pay_off, flow_id, flow_seq);
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
            /* we look for a large difference between l_time and s_time. */
            delta_b = sig_ts - s_time;
            if (delta_b >  0x10000000) {
                latency = 0;
            } else
                latency = (guint32)delta_b;
        }
    }
    /* fill up the per-packet header (amazingly like a PCAP packet header! ;-) */
    /* frames are always wired ethernet with a wired ethernettap header */
    /* caplen is the length that is captured into the file (i.e., the written-out frame */
    /* block), and should always represent the actual number of bytes in the file */
    /* len is the length of the original packet before truncation*/
    /* the FCS is NEVER included */
    e_hdr_len = STATS_COMMON_FIELDS_LEN + STATS_ETHERNETTAP_FIELDS_LEN;
    wth->phdr.len = (actual_octets - 4) + e_hdr_len;
    wth->phdr.caplen = (msdu_length - 4) + e_hdr_len;

    wth->phdr.presence_flags = WTAP_HAS_TS;

    wth->phdr.ts.secs = (time_t)s_sec;
    wth->phdr.ts.nsecs = (long)(s_usec * 1000);
    wth->phdr.pkt_encap = WTAP_ENCAP_IXVERIWAVE;

    /* generate and copy out the ETHERNETTAP header, set the port type to 1 (Ethernet) */
    common_hdr.vw_port_type = 1;
    common_hdr.it_len = STATS_COMMON_FIELDS_LEN;
    etap_hdr.it_len = STATS_ETHERNETTAP_FIELDS_LEN;

    etap_hdr.vw_errors = (guint32)errors;
    etap_hdr.vw_info = (guint16)info;
    common_hdr.vw_msdu_length = (guint16)msdu_length;
    /*etap_hdr.vw_ip_length = (guint16)ip_len;*/

    common_hdr.vw_flowid = (guint32)flow_id;
    common_hdr.vw_vcid = (guint16)vc_id;
    common_hdr.vw_seqnum = (guint16)flow_seq;

    if (!IS_TX && (sig_ts != 0))
        common_hdr.vw_latency = (guint32)latency;
    else
        common_hdr.vw_latency = 0;
    common_hdr.vw_pktdur = (guint32)d_time;
    etap_hdr.vw_l4id = (guint32)l4id;
    etap_hdr.vw_flags = 0;
    if (IS_TX)
        etap_hdr.vw_flags |= RADIOTAP_VWF_TXF;
    if (errors & vwr->FCS_ERROR)
        etap_hdr.vw_flags |= RADIOTAP_VWF_FCSERR;
    common_hdr.vw_startt = start_time;                  /* record start & end times of frame */
    common_hdr.vw_endt = end_time;
    common_hdr.vw_sig_ts = (guint32)(sig_ts);

    etap_hdr.it_pad2 = 0;

    /* put common_hdr into the packet buffer in little-endian byte order */
    phtoles(&data_ptr[bytes_written], common_hdr.vw_port_type);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], common_hdr.it_len);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], common_hdr.vw_msdu_length);
    bytes_written += 2;
    /* padding */
    memset(&data_ptr[bytes_written], 0, 2);
    bytes_written += 2;
    phtolel(&data_ptr[bytes_written], common_hdr.vw_flowid);
    bytes_written += 4;
    phtoles(&data_ptr[bytes_written], common_hdr.vw_vcid);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], common_hdr.vw_seqnum);
    bytes_written += 2;
    phtolel(&data_ptr[bytes_written], common_hdr.vw_latency);
    bytes_written += 4;
    phtolel(&data_ptr[bytes_written], common_hdr.vw_sig_ts);
    bytes_written += 4;
    phtolell(&data_ptr[bytes_written], common_hdr.vw_startt);
    bytes_written += 8;
    phtolell(&data_ptr[bytes_written], common_hdr.vw_endt);
    bytes_written += 8;
    phtolel(&data_ptr[bytes_written], common_hdr.vw_pktdur);
    bytes_written += 4;
    /* padding */
    memset(&data_ptr[bytes_written], 0, 4);
    bytes_written += 4;

    /* put etap_hdr into the packet buffer in little-endian byte order */
    phtoles(&data_ptr[bytes_written], etap_hdr.it_len);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], etap_hdr.vw_flags);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], etap_hdr.vw_info);
    bytes_written += 2;
    /* padding */
    memset(&data_ptr[bytes_written], 0, 2);
    bytes_written += 2;
    phtolel(&data_ptr[bytes_written], etap_hdr.vw_errors);
    bytes_written += 4;
    phtolel(&data_ptr[bytes_written], etap_hdr.vw_l4id);
    bytes_written += 4;
    /* padding */
    memset(&data_ptr[bytes_written], 0, 4);
    bytes_written += 4;

    /* finally, copy the whole MAC frame to the packet bufffer as-is; ALWAYS exclude 4-byte FCS */
    if ( rec_size < ((int)actual_octets + (int)vwr->STATS_LEN) ) 
        /*something's been truncated, DUMP AS-IS*/
        memcpy(&data_ptr[bytes_written], m_ptr, msdu_length);
    else if (msdu_length >= 4)
        memcpy(&data_ptr[bytes_written], m_ptr, msdu_length - 4);
    else
        memcpy(&data_ptr[bytes_written], m_ptr, msdu_length);
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
    wd2 = pntohl(&rec[8]);
    wd3 = pntohl(&rec[12]);

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
            v_size = (int)(wd2 & 0xffff);
            *v_type = VT_FRAME;
            break;

        case 0xc1:
        case 0x8b:
            v_size = (int)(wd2 & 0xffff);
            *v_type = VT_CPMSG;
            break;

        case 0xfe:
            v_size = (int)(wd3 & 0xffff);
            *v_type = VT_CPMSG;
            break;

        default:
            break;
    }

    return(v_size);
}


/*--------------------------------------------------------------------------------------*/
/* utilities to extract and decode the PHY bit rate from 802.11 PLCP headers (OFDM/CCK) */
/* they are passed a pointer to 4 or 6 consecutive bytes of PLCP header */
/* the integer returned by the get_xxx_rate() functions is in units of 0.5 Mb/s */
/* The string returned by the decode_xxx_rate() functions is 3 characters wide */

static guint8 get_ofdm_rate(guint8 *plcp)
{
    /* extract the RATE field (LS nibble of first byte) then decode it */
    switch (plcp[0] & 0x0f) {
        case 0x0b:  return(6 * 2);
        case 0x0f:  return(9 * 2);
        case 0x0a:  return(12 * 2);
        case 0x0e:  return(18 * 2);
        case 0x09:  return(24 * 2);
        case 0x0d:  return(36 * 2);
        case 0x08:  return(48 * 2);
        case 0x0c:  return(54 * 2);
        default:    return(0);
    }
}

static guint8 get_cck_rate(guint8 *plcp)
{
    /* extract rate from the SIGNAL field, 1 byte */
    switch (plcp[0]) {
        case 0x0a:  return(1 * 2);
        case 0x14:  return(2 * 2);
        case 0x37:  return(11);             /* 5.5 Mb/s */
        case 0x6e:  return(11 * 2);
        default:    return(0);
    }
}

/*--------------------------------------------------------------------------------------*/
/* utility to set up offsets and bitmasks for decoding the stats blocks */

static void setup_defaults(vwr_t *vwr, guint16 fpga)
{
    switch (fpga) {
        /* WLAN frames */
        case vVW510021_W_FPGA:
            vwr->STATS_LEN = vVW510021_W_STATS_LEN;

            vwr->VALID_OFF = vVW510021_W_VALID_OFF;
            vwr->MTYPE_OFF = vVW510021_W_MTYPE_OFF;
            vwr->VCID_OFF = vVW510021_W_VCID_OFF;
            vwr->FLOWSEQ_OFF = vVW510021_W_FLOWSEQ_OFF;
            vwr->FLOWID_OFF = vVW510021_W_FLOWID_OFF;

            /*vwr->OCTET_OFF = v22_W_OCTET_OFF;*/

            vwr->ERRORS_OFF = vVW510021_W_ERRORS_OFF;
            vwr->PATN_OFF = vVW510021_W_MATCH_OFF;
            vwr->RSSI_OFF = vVW510021_W_RSSI_TXPOWER_OFF;
            vwr->STARTT_OFF = vVW510021_W_STARTT_OFF;
            vwr->ENDT_OFF = vVW510021_W_ENDT_OFF;
            vwr->LATVAL_OFF = vVW510021_W_LATVAL_OFF;
            vwr->INFO_OFF = vVW510021_W_INFO_OFF;
            vwr->FPGA_VERSION_OFF = vVW510021_W_FPGA_VERSION_OFF;
            vwr->HEADER_VERSION_OFF = vVW510021_W_HEADER_VERSION_OFF;
            vwr->OCTET_OFF = vVW510021_W_MSDU_LENGTH_OFF;
            vwr->L1P_1_OFF = vVW510021_W_L1P_1_OFF;
            vwr->L1P_2_OFF = vVW510021_W_L1P_2_OFF;
            vwr->L4ID_OFF = vVW510021_W_L4ID_OFF;
            vwr->IPLEN_OFF = vVW510021_W_IPLEN_OFF;
            vwr->PLCP_LENGTH_OFF = vVW510021_W_PLCP_LENGTH_OFF;

            vwr->HEADER_IS_RX = vVW510021_W_HEADER_IS_RX;
            vwr->HEADER_IS_TX = vVW510021_W_HEADER_IS_TX;
            vwr->MT_MASK = vVW510021_W_SEL_MASK;
            vwr->MCS_INDEX_MASK = vVW510021_W_MCS_MASK;
            vwr->VCID_MASK = 0xffff;
            vwr->FLOW_VALID = vVW510021_W_FLOW_VALID;
            vwr->STATS_START_OFF = vVW510021_W_HEADER_LEN;
            vwr->FCS_ERROR = vVW510021_W_FCS_ERROR;
            vwr->CRYPTO_ERR = v22_W_CRYPTO_ERR;
            vwr->RETRY_ERR = v22_W_RETRY_ERR;

            /*vwr->STATS_START_OFF = 0;*/

            vwr->RXTX_OFF = vVW510021_W_RXTX_OFF;

            vwr->MT_10_HALF = 0;
            vwr->MT_10_FULL = 0;
            vwr->MT_100_HALF = 0;
            vwr->MT_100_FULL = 0;
            vwr->MT_1G_HALF = 0;
            vwr->MT_1G_FULL = 0;
            vwr->MT_CCKL = v22_W_MT_CCKL;
            vwr->MT_CCKS = v22_W_MT_CCKS;
            /*vwr->MT_OFDM = vVW510021_W_MT_OFDM;*/

            vwr->WEPTYPE = vVW510021_W_WEPTYPE;
            vwr->TKIPTYPE = vVW510021_W_TKIPTYPE;
            vwr->CCMPTYPE = vVW510021_W_CCMPTYPE;

            vwr->FRAME_TYPE_OFF  =   vVW510021_W_FRAME_TYPE_OFF;
            vwr->IS_TCP      =   vVW510021_W_IS_TCP;
            vwr->IS_UDP      =   vVW510021_W_IS_UDP;
            vwr->IS_ICMP     =   vVW510021_W_IS_ICMP;
            vwr->IS_IGMP     =   vVW510021_W_IS_IGMP;
            vwr->IS_QOS      =   vVW510021_W_QOS_VALID;

            break;

            /* Ethernet frames */
        case vVW510012_E_FPGA:
            vwr->STATS_LEN = v22_E_STATS_LEN;

            vwr->VALID_OFF = v22_E_VALID_OFF;
            vwr->MTYPE_OFF = v22_E_MTYPE_OFF;
            vwr->VCID_OFF = v22_E_VCID_OFF;
            vwr->FLOWSEQ_OFF = v22_E_FLOWSEQ_OFF;
            vwr->FLOWID_OFF = v22_E_FLOWID_OFF;
            vwr->OCTET_OFF = v22_E_OCTET_OFF;
            vwr->ERRORS_OFF = v22_E_ERRORS_OFF;
            vwr->PATN_OFF = v22_E_PATN_OFF;
            vwr->RSSI_OFF = v22_E_RSSI_OFF;
            vwr->STARTT_OFF = v22_E_STARTT_OFF;
            vwr->ENDT_OFF = v22_E_ENDT_OFF;
            vwr->LATVAL_OFF = v22_E_LATVAL_OFF;
            vwr->INFO_OFF = v22_E_INFO_OFF;
            vwr->L4ID_OFF = v22_E_L4ID_OFF;

            vwr->HEADER_IS_RX = v22_E_HEADER_IS_RX;
            vwr->HEADER_IS_TX = v22_E_HEADER_IS_TX;

            vwr->IS_RX = v22_E_IS_RX;
            vwr->MT_MASK = v22_E_MT_MASK;
            vwr->VCID_MASK = v22_E_VCID_MASK;
            vwr->FLOW_VALID = v22_E_FLOW_VALID;
            vwr->FCS_ERROR = v22_E_FCS_ERROR;

            vwr->RX_DECRYPTS = v22_E_RX_DECRYPTS;
            vwr->TX_DECRYPTS = v22_E_TX_DECRYPTS;
            vwr->FC_PROT_BIT = v22_E_FC_PROT_BIT;

            vwr->MT_10_HALF = v22_E_MT_10_HALF;
            vwr->MT_10_FULL = v22_E_MT_10_FULL;
            vwr->MT_100_HALF = v22_E_MT_100_HALF;
            vwr->MT_100_FULL = v22_E_MT_100_FULL;
            vwr->MT_1G_HALF = v22_E_MT_1G_HALF;
            vwr->MT_1G_FULL = v22_E_MT_1G_FULL;
            vwr->MT_CCKL = 0;
            vwr->MT_CCKS = 0;
            vwr->MT_OFDM = 0;

            vwr->FRAME_TYPE_OFF =  v22_E_FRAME_TYPE_OFF;
            vwr->IS_TCP      =   v22_E_IS_TCP;
            vwr->IS_UDP      =   v22_E_IS_UDP;
            vwr->IS_ICMP     =   v22_E_IS_ICMP;
            vwr->IS_IGMP     =   v22_E_IS_IGMP;
            vwr->IS_QOS      =   v22_E_IS_QOS;
            vwr->IS_VLAN     =   v22_E_IS_VLAN;

            break;

            /* WLAN frames */
        case vVW510006_W_FPGA:
            vwr->STATS_LEN = v22_W_STATS_LEN;

            vwr->MTYPE_OFF = v22_W_MTYPE_OFF;
            vwr->VALID_OFF = v22_W_VALID_OFF;
            vwr->VCID_OFF = v22_W_VCID_OFF;
            vwr->FLOWSEQ_OFF = v22_W_FLOWSEQ_OFF;
            vwr->FLOWID_OFF = v22_W_FLOWID_OFF;
            vwr->OCTET_OFF = v22_W_OCTET_OFF;
            vwr->ERRORS_OFF = v22_W_ERRORS_OFF;
            vwr->PATN_OFF = v22_W_PATN_OFF;
            vwr->RSSI_OFF = v22_W_RSSI_OFF;
            vwr->STARTT_OFF = v22_W_STARTT_OFF;
            vwr->ENDT_OFF = v22_W_ENDT_OFF;
            vwr->LATVAL_OFF = v22_W_LATVAL_OFF;
            vwr->INFO_OFF = v22_W_INFO_OFF;
            vwr->L4ID_OFF = v22_W_L4ID_OFF;
            vwr->IPLEN_OFF = v22_W_IPLEN_OFF;
            vwr->PLCP_LENGTH_OFF = v22_W_PLCP_LENGTH_OFF;

            vwr->FCS_ERROR = v22_W_FCS_ERROR;
            vwr->CRYPTO_ERR = v22_W_CRYPTO_ERR;
            vwr->PAYCHK_ERR = v22_W_PAYCHK_ERR;
            vwr->RETRY_ERR = v22_W_RETRY_ERR;
            vwr->IS_RX = v22_W_IS_RX;
            vwr->MT_MASK = v22_W_MT_MASK;
            vwr->VCID_MASK = v22_W_VCID_MASK;
            vwr->FLOW_VALID = v22_W_FLOW_VALID;

            vwr->HEADER_IS_RX = v22_W_HEADER_IS_RX;
            vwr->HEADER_IS_TX = v22_W_HEADER_IS_TX;

            vwr->RX_DECRYPTS = v22_W_RX_DECRYPTS;
            vwr->TX_DECRYPTS = v22_W_TX_DECRYPTS;
            vwr->FC_PROT_BIT = v22_W_FC_PROT_BIT;

            vwr->MT_10_HALF = 0;
            vwr->MT_10_FULL = 0;
            vwr->MT_100_HALF = 0;
            vwr->MT_100_FULL = 0;
            vwr->MT_1G_HALF = 0;
            vwr->MT_1G_FULL = 0;
            vwr->MT_CCKL = v22_W_MT_CCKL;
            vwr->MT_CCKS = v22_W_MT_CCKS;
            vwr->MT_OFDM = v22_W_MT_OFDM;

            vwr->WEPTYPE = v22_W_WEPTYPE;
            vwr->TKIPTYPE = v22_W_TKIPTYPE;
            vwr->CCMPTYPE = v22_W_CCMPTYPE;

            vwr->FRAME_TYPE_OFF =   v22_W_FRAME_TYPE_OFF;
            vwr->IS_TCP      =   v22_W_IS_TCP;
            vwr->IS_UDP      =   v22_W_IS_UDP;
            vwr->IS_ICMP     =   v22_W_IS_ICMP;
            vwr->IS_IGMP     =   v22_W_IS_IGMP;
            vwr->IS_QOS      =   v22_W_IS_QOS;

            break;

        /* Ethernet frames */
        case vVW510024_E_FPGA:
            vwr->STATS_LEN = vVW510024_E_STATS_LEN;

            vwr->VALID_OFF = vVW510024_E_VALID_OFF;
            vwr->VCID_OFF = vVW510024_E_VCID_OFF;
            vwr->FLOWSEQ_OFF = vVW510024_E_FLOWSEQ_OFF;
            vwr->FLOWID_OFF = vVW510024_E_FLOWID_OFF;
            vwr->OCTET_OFF = vVW510024_E_MSDU_LENGTH_OFF;
            vwr->ERRORS_OFF = vVW510024_E_ERRORS_OFF;
            vwr->PATN_OFF = vVW510024_E_MATCH_OFF;
            vwr->STARTT_OFF = vVW510024_E_STARTT_OFF;
            vwr->ENDT_OFF = vVW510024_E_ENDT_OFF;
            vwr->LATVAL_OFF = vVW510024_E_LATVAL_OFF;
            vwr->INFO_OFF = vVW510024_E_INFO_OFF;
            vwr->L4ID_OFF = vVW510024_E_L4ID_OFF;
            vwr->IPLEN_OFF = vVW510024_E_IPLEN_OFF;

            vwr->FPGA_VERSION_OFF = vVW510024_E_FPGA_VERSION_OFF;
            vwr->HEADER_VERSION_OFF = vVW510024_E_HEADER_VERSION_OFF;

            vwr->HEADER_IS_RX = vVW510024_E_HEADER_IS_RX;
            vwr->HEADER_IS_TX = vVW510024_E_HEADER_IS_TX;

            vwr->VCID_MASK = vVW510024_E_VCID_MASK;
            vwr->FLOW_VALID = vVW510024_E_FLOW_VALID;
            vwr->FCS_ERROR = v22_E_FCS_ERROR;

            vwr->FRAME_TYPE_OFF  =   vVW510024_E_FRAME_TYPE_OFF;
            vwr->IS_TCP      =   vVW510024_E_IS_TCP;
            vwr->IS_UDP      =   vVW510024_E_IS_UDP;
            vwr->IS_ICMP     =   vVW510024_E_IS_ICMP;
            vwr->IS_IGMP     =   vVW510024_E_IS_IGMP;
            vwr->IS_QOS      =   vVW510024_E_QOS_VALID;
            vwr->IS_VLAN     =   vVW510024_E_IS_VLAN;

            break;
    }
}
#define SIG_SCAN_RANGE  64                          /* range of signature scanning region */

/* utility routine: check that signature is at specified location; scan for it if not */
/* if we can't find a signature at all, then simply return the originally supplied offset */
int find_signature(guint8 *m_ptr, int pay_off, guint32 flow_id, guint8 flow_seq)
{
    int     tgt;                /* temps */
    guint32 fid;

    /* initial check is very simple: look for a '0xdd' at the target location */
    if (m_ptr[pay_off] == 0xdd)                         /* if magic byte is present */
        return(pay_off);                                /* got right offset, return it */

    /* hmmm, signature magic byte is not where it is supposed to be; scan from start of */
    /* payload until maximum scan range exhausted to see if we can find it */
    /* the scanning process consists of looking for a '0xdd', then checking for the correct */
    /* flow ID and sequence number at the appropriate offsets */
    for (tgt = pay_off; tgt < (pay_off + SIG_SCAN_RANGE); tgt++) {
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
            {                                                  /* out which one... */
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
    return(pay_off);
}

/* utility routine: harvest the signature time stamp from the data frame */
guint64 get_signature_ts(guint8 *m_ptr,int sig_off)
{
    int ts_offset;
    guint64 sig_ts;

    if (m_ptr[sig_off + 15] == 0xe2)
        ts_offset = 5;
    else
        ts_offset = 8;

    sig_ts = pletohl(&m_ptr[sig_off + ts_offset]);

    return(sig_ts & 0xffffffff);
}

