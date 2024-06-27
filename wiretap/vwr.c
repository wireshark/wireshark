/* vwr.c
 * Copyright (c) 2011 by Tom Alexander <talexander@ixiacom.com>
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#include "config.h"
#include "vwr.h"

#include <string.h>

#include "wtap-int.h"
#include "file_wrappers.h"

#include <wsutil/ws_assert.h>

/* platform-specific definitions for portability */

/* unsigned long long constants */
#   define NS_IN_US             UINT64_C(1000)        /* nanoseconds-to-microseconds */
#   define NS_IN_SEC            UINT64_C(1000000000)  /* nanoseconds-to-seconds */
#   define US_IN_SEC            UINT64_C(1000000)     /* microseconds-to-seconds */
#   define LL_ZERO              UINT64_C(0)           /* zero in unsigned long long */

/*
 * Fetch a 64-bit value in "Corey-endian" form.
 */
#define pcoreytohll(p)  ((uint64_t)*((const uint8_t *)(p)+4)<<56|  \
                         (uint64_t)*((const uint8_t *)(p)+5)<<48|  \
                         (uint64_t)*((const uint8_t *)(p)+6)<<40|  \
                         (uint64_t)*((const uint8_t *)(p)+7)<<32|  \
                         (uint64_t)*((const uint8_t *)(p)+0)<<24|  \
                         (uint64_t)*((const uint8_t *)(p)+1)<<16|  \
                         (uint64_t)*((const uint8_t *)(p)+2)<<8|   \
                         (uint64_t)*((const uint8_t *)(p)+3)<<0)

/*
 * Fetch a 48-bit value in "Corey-endian" form; it's stored as
 * a 64-bit Corey-endian value, with the upper 16 bits ignored.
 */
#define pcorey48tohll(p)  ((uint64_t)*((const uint8_t *)(p)+6)<<40|  \
                           (uint64_t)*((const uint8_t *)(p)+7)<<32|  \
                           (uint64_t)*((const uint8_t *)(p)+0)<<24|  \
                           (uint64_t)*((const uint8_t *)(p)+1)<<16|  \
                           (uint64_t)*((const uint8_t *)(p)+2)<<8|   \
                           (uint64_t)*((const uint8_t *)(p)+3)<<0)

/* .vwr log file defines */
#define B_SIZE      32768                           /* max var len message = 32 kB */
#define VT_FRAME    0                               /* varlen msg is a frame */
#define VT_CPMSG    1                               /* varlen msg is a CP<->PP msg */
#define VT_UNKNOWN -1                               /* varlen msg is unknown */
#define MAX_TRACKED_CLIENTS 1024                    /* track 1024 clients */
#define MAX_TRACKED_FLOWS   65536                   /* and 64K flows */

/*
 * The file consists of a sequence of records.
 * A record begins with a 16-byte header, the first 8 bytes of which
 * begin with a byte containing a command plus transmit-receive flags.
 *
 * Following that are two big-endian 32-bit quantities; for some records
 * one or the other of them is the length of the rest of the record.
 * Other records contain only the header.
 */
#define VW_RECORD_HEADER_LENGTH 16

/*
 * Maximum number of bytes to read looking for a valid frame starting
 * with a command byte to determine if this is our file type. Arbitrary.
 */
#define VW_BYTES_TO_CHECK 0x3FFFFFFFU

/* Command byte values */
#define COMMAND_RX   0x21
#define COMMAND_TX   0x31
#define COMMAND_RFN  0x30
#define COMMAND_RF   0x38
#define COMMAND_RFRX 0x39

/*
 * The data in packet records begins with a sequence of metadata headers.
 *
 * For packet records from FPGA versions < 48:
 *
 *    The first header is the IxVeriWave common header, and that's
 *    followed either by a WLAN metadata header or an Ethernet
 *    metadata header.  The port type field indicates whether it's
 *    a WLAN packet or an Ethernet packet.  Following that may, for
 *    WLAN, be 1 octet of information from the FPGA and 16 bytes of
 *    data including the PLCP header.  After that comes the WLAN or
 *    Ethernet frame, beginning with the MAC header.
 *
 * For packet records from FPGA versions >= 48:
 *
 *    The first header contains only a 1-octet port type value, which
 *    has a packet type value in the upper 4 bits and zero in the lower
 *    4 bits.  NOTE: this is indistinguishable from an old FPGA header
 *    if the packet type value is 0.
 *
 *    If the packet type value isn't 3, the port type value is followed
 *    by a 1-octet FPGA version number, which is followed by a timestamp
 *    header.
 *
 *    If the packet type value is 3 or 4, the next item is an RF metadata
 *    header.  For type 3, that immediately follows the port number octet,
 *    otherwise it immediately follows the timestamp header.
 *
 *    If the packet type isn't 3, the next item is a WLAN metadata header,
 *    in a format different from the WLAN metadata header for FPGA versions
 *    < 48.  That is followed by a PLCP header, which is followed by a
 *    header giving additional layer 2 through 4 metadata.
 *
 * Following those headers is the WLAN or Ethernet frame, beginning with
 * the MAC header.
 */

/*
 * IxVeriWave common header:
 *
 * 1 octet - port type
 * 1 octet - FPGA version, or 0
 * 2 octets - length of the common header
 * 2 octets - MSDU length
 * 4 octets - flow ID
 * 2 octets - VC ID
 * 2 octets - flow sequence number
 * 4 octets - latency or 0
 * 4 octets - lower 32 bits of signature time stamp
 * 8 octets - start time
 * 8 octets - end time
 * 4 octets - delta(?) time
 */

/* Size of the IxVeriWave common header */
#define STATS_COMMON_FIELDS_LEN (1+1+2+2+4+2+2+4+4+8+8+4)

/* Port type */
#define WLAN_PORT               0
#define ETHERNET_PORT           1

/* For VeriWave WLAN and Ethernet metadata headers vw_flags field */
#define VW_FLAGS_TXF        0x01                /* frame was transmitted */
#define VW_FLAGS_FCSERR     0x02                /* FCS error detected */

/*
 * VeriWave WLAN metadata header:
 *
 * 2 octets - header length
 * 2 octets - rflags
 * 2 octets - channel flags
 * 2 octets - PHY rate
 * 1 octet - PLCP type
 * 1 octet - MCS index
 * 1 octet - number of spatial streams
 * 1 octet - RSSI
 * 1 octet - antenna b signal power, or 100 if missing
 * 1 octet - antenna c signal power, or 100 if missing
 * 1 octet - antenna d signal power, or 100 if missing
 * 1 octet - padding
 * 2 octets - VeriWave flags
 * 2 octets - HT len
 * 2 octets - info
 * 2 octets - errors
 */

/* Size of the VeriWave WLAN metadata header */
#define EXT_WLAN_FIELDS_LEN (2+2+2+2+1+1+1+1+1+1+1+1+2+2+2+4)

/* Flags, for rflags field */
#define FLAGS_SHORTPRE      0x0002              /* sent/received with short preamble */
#define FLAGS_WEP           0x0004              /* sent/received with WEP encryption */
#define FLAGS_CHAN_HT       0x0040              /* In HT mode */
#define FLAGS_CHAN_VHT      0x0080              /* VHT Mode */
#define FLAGS_CHAN_SHORTGI  0x0100              /* Short guard interval */
#define FLAGS_CHAN_40MHZ    0x0200              /* 40 Mhz channel bandwidth */
#define FLAGS_CHAN_80MHZ    0x0400              /* 80 Mhz channel bandwidth */
#define FLAGS_CHAN_160MHZ   0x0800              /* 160 Mhz channel bandwidth */

/* Channel flags, for channel flags field */
#define CHAN_CCK            0x0020              /* CCK channel */
#define CHAN_OFDM           0x0040              /* OFDM channel */

/* For VeriWave WLAN metadata header vw_flags field */
#define VW_FLAGS_RETRERR    0x04                /* excess retry error detected */
#define VW_FLAGS_DCRERR     0x10                /* decrypt error detected (WLAN) */
#define VW_FLAGS_ENCMSK     0x60                /* encryption type mask */
                                                /* 0 = none, 1 = WEP, 2 = TKIP, 3 = CCKM */
#define VW_FLAGS_IS_WEP     0x20                /* WEP */
#define VW_FLAGS_IS_TKIP    0x40                /* TKIP */
#define VW_FLAGS_IS_CCMP    0x60                /* CCMP */

/*
 * VeriWave Ethernet metadata header:
 *
 * 2 octets - header length
 * 2 octets - VeriWave flags
 * 2 octets - info
 * 4 octets - errors
 * 4 octets - layer 4 ID
 * 4 octets - pad
 *
 * Ethernet frame follows, beginning with the MAC header
 */

/* Size of the VeriWave Ethernet metadata header */
#define EXT_ETHERNET_FIELDS_LEN (2+2+2+4+4+4)

/*
 * OCTO timestamp header.
 *
 * 4 octets - latency or 0
 * 4 octets - lower 32 bits of signature time stamp
 * 8 octets - start time
 * 8 octets - end time
 * 4 octets - delta(?) time
 */

/* Size of Timestamp header */
#define OCTO_TIMESTAMP_FIELDS_LEN   (4+4+8+8+4+4)

/*
 * OCTO layer 1-4 header:
 *
 * 2 octets - header length
 * 1 octet - l1p_1
 * 1 octet - number of spatial streams
 * 2 octets - PHY rate
 * 1 octet - l1p_2
 * 1 octet - RSSI
 * 1 octet - antenna b signal power, or 100 if missing
 * 1 octet - antenna c signal power, or 100 if missing
 * 1 octet - antenna d signal power, or 100 if missing
 * 1 octet - signal bandwidth mask
 * 1 octet - antenna port energy detect and VU_MASK
 * 1 octet - L1InfoC or 0
 * 2 octets - MSDU length
 * 16 octets - PLCP?
 * 4 octets - BM, BV, CV, BSSID and ClientID
 * 2 octets - FV, QT, HT, L4V, TID and WLAN type
 * 1 octets - flow sequence number
 * 3 octets - flow ID
 * 2 octets - layer 4 ID
 * 4 octets - payload decode
 * 3 octets - info
 * 4 octets - errors
 */

/* Size of Layer-1, PLCP, and Layer-2/4 header in case of OCTO version FPGA */
#define OCTO_LAYER1TO4_LEN          (2+14+16+23)

/*
 * OCTO modified RF layer:
 *
 * 1 octet - RF ID
 * 3 octets - unused (zero)
 * 8 octets - noise for 4 ports
 * 8 octets - signal/noise ration for 4 ports
 * 8 octets - PFE for 4 ports
 * 8 octets - EVM SIG data for 4 ports
 * 8 octets - EVM SIG pilot for 4 ports
 * 8 octets - EVM Data data for 4 ports
 * 8 octets - EVM Data pilot for 4 ports
 * 8 octets - EVM worst symbol for 4 ports
 * 8 octets - CONTEXT_P for 4 ports
 *
 * Not supplied:
 * 24 octets of additional data
 */

/* Size of RF header, if all fields were supplied */
#define OCTO_RF_MOD_ACTUAL_LEN      100             /* */

/* Size of RF header with the fields we do supply */
#define OCTO_MODIFIED_RF_LEN        76              /* 24 bytes of RF are not displayed*/

/*Offset of different parameters of RF header for port-1*/
#define RF_PORT_1_NOISE_OFF         4
#define RF_PORT_1_SNR_OFF           6
#define RF_PORT_1_PFE_OFF           8
#define RF_PORT_1_CONTEXT_OFF       10
#define RF_PORT_1_EVM_SD_SIG_OFF    12
#define RF_PORT_1_EVM_SP_SIG_OFF    14
#define RF_PORT_1_EVM_SD_DATA_OFF   16
#define RF_PORT_1_EVM_SP_DATA_OFF   18
#define RF_PORT_1_DSYMBOL_IDX_OFF   22
#define RF_INTER_PORT_GAP_OFF       24              /*As size of RF information per port is 24 bytes*/
#define RF_NUMBER_OF_PORTS          4

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
/* Media types */
#define v22_E_MT_10_HALF    0                       /* 10 Mb/s half-duplex */
#define v22_E_MT_10_FULL    1                       /* 10 Mb/s full-duplex */
#define v22_E_MT_100_HALF   2                       /* 100 Mb/s half-duplex */
#define v22_E_MT_100_FULL   3                       /* 100 Mb/s full-duplex */
#define v22_E_MT_1G_HALF    4                       /* 1 Gb/s half-duplex */
#define v22_E_MT_1G_FULL    5                       /* 1 Gb/s full-duplex */

/* Error flags */
#define v22_E_FCS_ERROR           0x0002            /* FCS error flag in error vector */
#define v22_E_CRYPTO_ERR          0x1f00            /* RX decrypt error flags (UNUSED) */
#define v22_E_SIG_ERR             0x0004            /* signature magic byte mismatch */
#define v22_E_PAYCHK_ERR          0x0008            /* payload checksum failure */
#define v22_E_RETRY_ERR           0x0400            /* excessive retries on TX fail (UNUSED)*/

/* Masks and defines */
#define v22_E_IS_RX               0x08              /* TX/RX bit in STATS block */
#define v22_E_MT_MASK             0x07              /* modulation type mask (UNUSED) */

#define v22_E_VCID_MASK           0x03ff            /* VC ID is only 10 bits */

#define v22_E_FLOW_VALID          0x40              /* flow-is-valid flag (else force to 0) */

#define v22_E_DIFFERENTIATOR_MASK 0x3F              /* mask to differentiate ethernet from */

/* Bits in FRAME_TYPE field */
#define v22_E_IS_TCP              0x00000040        /* TCP bit in FRAME_TYPE field */
#define v22_E_IS_UDP              0x00000010        /* UDP bit in FRAME_TYPE field */
#define v22_E_IS_ICMP             0x00000020        /* ICMP bit in FRAME_TYPE field */
#define v22_E_IS_IGMP             0x00000080        /* IGMP bit in FRAME_TYPE field */

/* Bits in MTYPE field (WLAN only) */
#define v22_E_IS_QOS              0x80              /* QoS bit in MTYPE field (WLAN only) */

#define v22_E_IS_VLAN             0x00200000

#define v22_E_RX_DECRYPTS   0x0007                  /* RX-frame-was-decrypted (UNUSED) */
#define v22_E_TX_DECRYPTS   0x0007                  /* TX-frame-was-decrypted (UNUSED) */

#define v22_E_FC_PROT_BIT   0x40                    /* Protected Frame bit in FC1 of frame */

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

/* Modulation types */
#define v22_W_MT_CCKL       0                       /* CCK modulation, long preamble */
#define v22_W_MT_CCKS       1                       /* CCK modulation, short preamble */
#define v22_W_MT_OFDM       2                       /* OFDM modulation */

/* Bits in FRAME_TYPE field */
#define v22_W_IS_TCP            0x00000040          /* TCP bit in FRAME_TYPE field */
#define v22_W_IS_UDP            0x00000010          /* UDP bit in FRAME_TYPE field */
#define v22_W_IS_ICMP           0x00000020          /* ICMP bit in FRAME_TYPE field */
#define v22_W_IS_IGMP           0x00000080          /* IGMP bit in FRAME_TYPE field */

/* Bits in MTYPE field (WLAN only) */
#define v22_W_IS_QOS            0x80                /* QoS */

/* Error flags */
#define v22_W_FCS_ERROR     0x0002                  /* FCS error flag in error vector */
#define v22_W_CRYPTO_ERR    0x1f00                  /* RX decrypt error flags */
#define v22_W_SIG_ERR       0x0004                  /* signature magic byte mismatch */
#define v22_W_PAYCHK_ERR    0x0008                  /* payload checksum failure */
#define v22_W_RETRY_ERR     0x0400                  /* excessive retries on TX failure */

/* Masks and defines */
#define v22_W_IS_RX         0x08                    /* TX/RX bit in STATS block */
#define v22_W_MT_MASK       0x07                    /* modulation type mask */

#define v22_W_VCID_MASK     0x01ff                  /* VC ID is only 9 bits */

#define v22_W_FLOW_VALID    0x40                    /* flow-is-valid flag (else force to 0) */

#define v22_W_DIFFERENTIATOR_MASK 0xf0ff            /* mask to differentiate ethernet from */
                                                    /* 802.11 capture */

#define v22_W_RX_DECRYPTS   0x0007                  /* RX-frame-was-decrypted bits */
#define v22_W_TX_DECRYPTS   0x0007                  /* TX-frame-was-decrypted bits */

/* Info bits */
#define v22_W_WEPTYPE               0x0001          /* WEP frame */
#define v22_W_TKIPTYPE              0x0002          /* TKIP frame */
#define v22_W_CCMPTYPE              0x0004          /* CCMP frame */
#define v22_W_MPDU_OF_A_MPDU        0x0400          /* MPDU of A-MPDU */
#define v22_W_FIRST_MPDU_OF_A_MPDU  0x0800          /* first MPDU of A-MPDU */
#define v22_W_LAST_MPDU_OF_A_MPDU   0x1000          /* last MPDU of A-MPDU */
#define v22_W_MSDU_OF_A_MSDU        0x2000          /* MSDU of A-MSDU */
#define v22_W_FIRST_MSDU_OF_A_MSDU  0x4000          /* first MSDU of A-MSDU */
#define v22_W_LAST_MSDU_OF_A_MSDU   0x8000          /* last MSDU of A-MSDU */

/* All aggregation flags */
#define v22_W_AGGREGATE_FLAGS \
    (v22_W_MPDU_OF_A_MPDU | \
     v22_W_FIRST_MPDU_OF_A_MPDU | \
     v22_W_LAST_MPDU_OF_A_MPDU | \
     v22_W_MSDU_OF_A_MSDU | \
     v22_W_FIRST_MSDU_OF_A_MSDU | \
     v22_W_LAST_MSDU_OF_A_MSDU)

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
#define vVW510021_W_BVCV_VALID_OFF       4          /* BV,CV Determine validity of bssid and txpower */
#define vVW510021_W_VCID_OFF             6          /* offset of VC (client) ID */
#define vVW510021_W_PLCP_LENGTH_OFF     12          /* LENGTH field in the plcp header */

/* Masks and defines */
#define vVW510021_W_IS_BV               0x04        /* BV bit in STATS block */
#define vVW510021_W_IS_CV               0x02        /* BV bit in STATS block */
#define vVW510021_W_FLOW_VALID          0x8000      /* valid_off flow-is-valid flag (else 0) */
#define vVW510021_W_QOS_VALID           0x4000
#define vVW510021_W_HT_VALID            0x2000
#define vVW510021_W_L4ID_VALID          0x1000
#define vVW510021_W_MCS_MASK            0x3f        /* mcs index (a/b) type mask */
#define vVW510021_W_MOD_SCHEME_MASK     0x3f        /* modulation type mask */
#define vVW510021_W_PLCPC_MASK          0x03        /* PLPCP type mask */
#define vVW510021_W_SEL_MASK            0x80
#define vVW510021_W_WEP_MASK            0x0001
#define vVW510021_W_CBW_MASK            0xC0

#define vVW510024_W_VCID_MASK           0x03ff      /* VC ID is only 10 bits */

#define vVW510021_W_MT_SEL_LEGACY       0x00

#define vVW510021_W_IS_WEP              0x0001

/* L1p byte 1 info */

/* Common to Series II and Series III */

#define vVW510021_W_IS_LONGPREAMBLE     0x40        /* short/long preamble bit */
#define vVW510021_W_IS_LONGGI           0x40        /* short/long guard interval bit */

/* Series II */

/*
 * Pre-HT - contains rate index.
 */
#define vVW510021_W_S2_RATE_INDEX(l1p_1) ((l1p_1) & 0x3f) /* rate index for pre-HT */

/*
 * HT - contains MCS index.
 *
 * XXX - MCS indices for HT go up to 76, which doesn't fit in 6 bits;
 * either the mask is wrong, or the hardware can't receive packets
 * with an MCS of 64 through 76, or the hardware can but misreports
 * the MCS.
 */
#define vVW510021_W_S2_MCS_INDEX_HT(l1p_1) ((l1p_1) & 0x3f)

/*
 * VHT - contains MCS index and number of spatial streams.
 * The number of spatial streams from the FPGA is zero-based, so we add
 * 1 to it.
 */
#define vVW510021_W_S2_MCS_INDEX_VHT(l1p_1) ((l1p_1) & 0x0f) /* MCS index for VHT */
#define vVW510021_W_S2_NSS_VHT(l1p_1)       (((l1p_1) >> 4) + 1) /* NSS */

/* Series III */

/*
 * Pre-HT - contains rate index.
 */
#define vVW510021_W_S3_RATE_INDEX(l1p_1)  ((l1p_1) & 0x3f)

/*
 * HT - contains MCS index.
 *
 * XXX - MCS indices for HT go up to 76, which doesn't fit in 6 bits;
 * either the mask is wrong, or the hardware can't receive packets
 * with an MCS of 64 through 76, or the hardware can but misreports
 * the MCS.
 */
#define vVW510021_W_S3_MCS_INDEX_HT(l1p_1)  ((l1p_1) & 0x3f)

/*
 * VHT - contains MCS index and number of spatial streams.
 * The number of spatial streams from the FPGA is zero-based, so we add
 * 1 to it.
 */
#define vVW510021_W_S3_MCS_INDEX_VHT(l1p_1) ((l1p_1) & 0x0f) /* MCS index */
#define vVW510021_W_S3_NSS_VHT(l1p_1)       ((((l1p_1) >> 4) & 0x03) + 1) /* NSS */

/* L1p byte 2 info */

/* Common to Series II and Series III */
#define vVW510021_W_BANDWIDTH_VHT(l1p_2) (((l1p_2) >> 4) & 0xf)
/* 3 = 40 MHz, 4 = 80 MHz; what about 20 and 160 MHz? */

/* Series II */
#define vVW510021_W_S2_PLCP_TYPE(l1p_2) ((l1p_2) & 0x03) /* PLCP type */

/* Series III */
#define vVW510021_W_S3_PLCP_TYPE(l1p_2) ((l1p_2) & 0x0f) /* PLCP type */

/* PLCP types */
#define vVW510021_W_PLCP_LEGACY         0x00        /* pre-HT (11b/a/g) */
#define vVW510021_W_PLCP_MIXED          0x01        /* HT, mixed (11n) */
#define vVW510021_W_PLCP_GREENFIELD     0x02        /* HT, greenfield (11n) */
#define vVW510021_W_PLCP_VHT_MIXED      0x03        /* VHT (11ac) */

/* Bits in FRAME_TYPE field */
#define vVW510021_W_IS_TCP          0x01000000      /* TCP */
#define vVW510021_W_IS_UDP          0x00100000      /* UDP */
#define vVW510021_W_IS_ICMP         0x00001000      /* ICMP */
#define vVW510021_W_IS_IGMP         0x00010000      /* IGMP */

#define vVW510021_W_HEADER_VERSION      0x00
#define vVW510021_W_DEVICE_TYPE         0x15
#define vVW510021_W_11n_DEVICE_TYPE     0x20
#define S2_W_FPGA_VERSION               0x000C
#define vVW510021_W_11n_FPGA_VERSION    0x000D

/* Error flags */
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
#define vVW510024_E_VCID_MASK           0x3FFF                  /* VCID is only 14 bits */

#define vVW510024_E_IS_TCP          0x01000000                  /* TCP bit in FRAME_TYPE field */
#define vVW510024_E_IS_UDP          0x00100000                  /* UDP bit in FRAME_TYPE field */
#define vVW510024_E_IS_ICMP         0x00001000                  /* ICMP bit in FRAME_TYPE field */
#define vVW510024_E_IS_IGMP         0x00010000
#define vVW510024_E_IS_VLAN         0x00004000

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
    uint32_t     STATS_LEN;                      /* length of stats block trailer */
    uint32_t     STATS_START_OFF;                /* STATS OFF AFTER HEADER */
    uint32_t     VALID_OFF;                      /* bit 6 (0x40) is flow-is-valid flag */
    uint32_t     MTYPE_OFF;                      /* offset of modulation type */
    uint32_t     VCID_OFF;                       /* offset of VC ID */
    uint32_t     FLOWSEQ_OFF;                    /* offset of signature sequence number */
    uint32_t     FLOWID_OFF;                     /* offset of flow ID */
    uint32_t     OCTET_OFF;                      /* offset of octets */
    uint32_t     ERRORS_OFF;                     /* offset of error vector */
    uint32_t     PATN_OFF;                       /* offset of pattern match vector */
    uint32_t     RSSI_OFF;                       /* RSSI (NOTE: RSSI must be negated!) */
    uint32_t     STARTT_OFF;                     /* offset of start time, 64 bits */
    uint32_t     ENDT_OFF;                       /* offset of end time, 64 bits */
    uint32_t     LATVAL_OFF;                     /* offset of latency, 32 bits */
    uint32_t     INFO_OFF;                       /* offset of INFO field, 16 bits */
    uint32_t     L1P_1_OFF;                      /* offset 1ST Byte of l1params */
    uint32_t     L1P_2_OFF;                      /* offset 2nd Byte of l1params */
    uint32_t     L4ID_OFF;                       /* LAYER 4 id offset*/
    uint32_t     IPLEN_OFF;                      /* */
    uint32_t     PLCP_LENGTH_OFF;                /* offset of length field in the PLCP header */
    uint32_t     FPGA_VERSION_OFF;               /* offset of fpga version field, 16 bits */
    uint32_t     HEADER_VERSION_OFF;             /* offset of header version, 16 bits */
    uint32_t     RXTX_OFF;                       /* offset of CMD bit, rx or tx */
    uint32_t     FRAME_TYPE_OFF;

    /* other information about the file in question */
    uint32_t     MT_10_HALF;                     /* 10 Mb/s half-duplex */
    uint32_t     MT_10_FULL;                     /* 10 Mb/s full-duplex */
    uint32_t     MT_100_HALF;                    /* 100 Mb/s half-duplex */
    uint32_t     MT_100_FULL;                    /* 100 Mb/s full-duplex */
    uint32_t     MT_1G_HALF;                     /* 1 Gb/s half-duplex */
    uint32_t     MT_1G_FULL;                     /* 1 Gb/s full-duplex */
    uint32_t     FCS_ERROR;                      /* FCS error in frame */
    uint32_t     CRYPTO_ERR;                     /* RX decrypt error flags */
    uint32_t     PAYCHK_ERR;                     /* payload checksum failure */
    uint32_t     RETRY_ERR;                      /* excessive retries on TX failure */
    uint8_t      IS_RX;                          /* TX/RX bit in STATS block */
    uint8_t      MT_MASK;                        /* modulation type mask */
    uint16_t     VCID_MASK;                      /* VC ID might not be a full 16 bits */
    uint32_t     FLOW_VALID;                     /* flow-is-valid flag (else force to 0) */
    uint16_t     QOS_VALID;
    uint32_t     RX_DECRYPTS;                    /* RX-frame-was-decrypted bits */
    uint32_t     TX_DECRYPTS;                    /* TX-frame-was-decrypted bits */
    uint32_t     FC_PROT_BIT;                    /* Protected Frame bit in FC1 of frame */
    uint32_t     MT_CCKL;                        /* CCK modulation, long preamble */
    uint32_t     MT_CCKS;                        /* CCK modulation, short preamble */
    uint32_t     MT_OFDM;                        /* OFDM modulation */
    uint32_t     MCS_INDEX_MASK;                 /* mcs index type mask */
    uint32_t     FPGA_VERSION;
    uint32_t     WEPTYPE;                        /* frame is WEP */
    uint32_t     TKIPTYPE;                       /* frame is TKIP */
    uint32_t     CCMPTYPE;                       /* frame is CCMP */
    uint32_t     IS_TCP;
    uint32_t     IS_UDP;
    uint32_t     IS_ICMP;
    uint32_t     IS_IGMP;
    uint16_t     IS_QOS;
    uint32_t     IS_VLAN;
    uint32_t     MPDU_OFF;
    uint32_t     OCTO_VERSION;
} vwr_t;

/*
 * NSS for various MCS values.
 */
#define MAX_HT_MCS 76
static unsigned nss_for_mcs[MAX_HT_MCS+1] = {
        1, 1, 1, 1, 1, 1, 1, 1,                               /* 0-7 */
        2, 2, 2, 2, 2, 2, 2, 2,                               /* 8-15 */
        3, 3, 3, 3, 3, 3, 3, 3,                               /* 16-23 */
        4, 4, 4, 4, 4, 4, 4, 4,                               /* 24-31 */
        1,                                                    /* 32 */
        2, 2, 2, 2, 2, 2,                                     /* 33-38 */
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,             /* 39-52 */
        4, 4, 4, 4, 4, 4,                                     /* 53-58 */
        4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4  /* 59-76 */
};

/* internal utility functions */
static int          decode_msg(vwr_t *vwr, register uint8_t *, int *, int *, int *);
static uint8_t      get_ofdm_rate(const uint8_t *);
static uint8_t      get_cck_rate(const uint8_t *plcp);
static void         setup_defaults(vwr_t *, uint16_t);

static bool         vwr_read(wtap *, wtap_rec *, Buffer *, int *,
                             char **, int64_t *);
static bool         vwr_seek_read(wtap *, int64_t, wtap_rec *,
                                  Buffer *, int *, char **);

static bool         vwr_read_rec_header(vwr_t *, FILE_T, int *, int *, int *, int *, char **);
static bool         vwr_process_rec_data(FILE_T fh, int rec_size,
                                         wtap_rec *record, Buffer *buf,
                                         vwr_t *vwr, int IS_TX, int log_mode, int *err,
                                         char **err_info);

static int          vwr_get_fpga_version(wtap *, int *, char **);

static bool         vwr_read_s1_W_rec(vwr_t *, wtap_rec *, Buffer *,
                                      const uint8_t *, int, int *, char **);
static bool         vwr_read_s2_W_rec(vwr_t *, wtap_rec *, Buffer *,
                                      const uint8_t *, int, int, int *,
                                      char **);
/* For FPGA version >= 48 (OCTO Platform), following function will be used */
static bool         vwr_read_s3_W_rec(vwr_t *, wtap_rec *, Buffer *,
                                      const uint8_t *, int, int, int, int *,
                                      char **);
static bool         vwr_read_rec_data_ethernet(vwr_t *, wtap_rec *,
                                               Buffer *, const uint8_t *, int,
                                               int, int *, char **);

static int          find_signature(const uint8_t *, int, int, register uint32_t, register uint8_t);
static uint64_t     get_signature_ts(const uint8_t *, int, int);
static float        get_legacy_rate(uint8_t);
static float        get_ht_rate(uint8_t, uint16_t);
static float        get_vht_rate(uint8_t, uint16_t, uint8_t);

static int vwr_80211_file_type_subtype = -1;
static int vwr_eth_file_type_subtype = -1;

void register_vwr(void);

/* Open a .vwr file for reading */
/* This does very little, except setting the wiretap header for a VWR file type */
/*  and setting the timestamp precision to microseconds.                        */

wtap_open_return_val vwr_open(wtap *wth, int *err, char **err_info)
{
    int    fpgaVer;
    vwr_t *vwr;

    *err = 0;

    fpgaVer = vwr_get_fpga_version(wth, err, err_info);
    if (fpgaVer == -1) {
        return WTAP_OPEN_ERROR; /* I/O error */
    }
    if (fpgaVer == UNKNOWN_FPGA) {
        return WTAP_OPEN_NOT_MINE; /* not a VWR file */
    }

    /* This is a vwr file */
    vwr = g_new0(vwr_t, 1);
    wth->priv = (void *)vwr;

    vwr->FPGA_VERSION = fpgaVer;
    /* set the local module options first */
    setup_defaults(vwr, fpgaVer);

    wth->snapshot_length = 0;
    wth->subtype_read = vwr_read;
    wth->subtype_seek_read = vwr_seek_read;
    wth->file_tsprec = WTAP_TSPREC_USEC;
    wth->file_encap = WTAP_ENCAP_IXVERIWAVE;

    if (fpgaVer == S2_W_FPGA || fpgaVer == S1_W_FPGA || fpgaVer == S3_W_FPGA)
        wth->file_type_subtype = vwr_80211_file_type_subtype;
    else if (fpgaVer == vVW510012_E_FPGA || fpgaVer == vVW510024_E_FPGA)
        wth->file_type_subtype = vwr_eth_file_type_subtype;

    /*
     * Add an IDB; we don't know how many interfaces were
     * involved, so we just say one interface, about which
     * we only know the link-layer type, snapshot length,
     * and time stamp resolution.
     */
    wtap_add_generated_idb(wth);

    return WTAP_OPEN_MINE;
}


/* Read the next packet */
/* Note that the VWR file format consists of a sequence of fixed 16-byte record headers of */
/*  different types; some types, including frame record headers, are followed by           */
/*  variable-length data.                                                                  */
/* A frame record consists of: the above 16-byte record header, a 1-16384 byte raw PLCP    */
/*  frame, and a 64-byte statistics block trailer.                                         */
/* The PLCP frame consists of a 4-byte or 6-byte PLCP header, followed by the MAC frame    */

static bool vwr_read(wtap *wth, wtap_rec *rec, Buffer *buf,
    int *err, char **err_info, int64_t *data_offset)
{
    vwr_t *vwr      = (vwr_t *)wth->priv;
    int    rec_size = 0, IS_TX = 0, log_mode = 0;

    /* read the next frame record header in the capture file; if no more frames, return */
    if (!vwr_read_rec_header(vwr, wth->fh, &rec_size, &IS_TX, &log_mode, err, err_info))
        return false;                                   /* Read error or EOF */

    /*
     * We're past the header; return the offset of the header, not of
     * the data past the header.
     */
    *data_offset = (file_tell(wth->fh) - VW_RECORD_HEADER_LENGTH);

    /* got a frame record; read and process it */
    if (!vwr_process_rec_data(wth->fh, rec_size, rec, buf, vwr, IS_TX,
                              log_mode, err, err_info))
       return false;

    return true;
}

/* read a random record in the middle of a file; the start of the record is @ seek_off */

static bool vwr_seek_read(wtap *wth, int64_t seek_off,
    wtap_rec *record, Buffer *buf, int *err, char **err_info)
{
    vwr_t *vwr = (vwr_t *)wth->priv;
    int    rec_size, IS_TX = 0, log_mode = 0;

    /* first seek to the indicated record header */
    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
        return false;

    /* read in the record header */
    if (!vwr_read_rec_header(vwr, wth->random_fh, &rec_size, &IS_TX, &log_mode, err, err_info))
        return false;                                  /* Read error or EOF */

    return vwr_process_rec_data(wth->random_fh, rec_size, record, buf,
                                vwr, IS_TX, log_mode, err, err_info);
}

/* Scan down in the input capture file to find the next frame header.       */
/* Decode and skip over all non-frame messages that are in the way.         */
/* Return true on success, false on EOF or error.                           */
/* Also return the frame size in bytes and the "is transmitted frame" flag. */

static bool vwr_read_rec_header(vwr_t *vwr, FILE_T fh, int *rec_size, int *IS_TX, int *log_mode, int *err, char **err_info)
{
    int     f_len, v_type;
    uint8_t header[VW_RECORD_HEADER_LENGTH];

    *rec_size = 0;

    /* Read out the file data in 16-byte messages, stopping either after we find a frame,  */
    /*  or if we run out of data.                                                          */
    /* Each 16-byte message is decoded; if we run across a non-frame message followed by a */
    /*  variable-length item, we read the variable length item out and discard it.         */
    /* If we find a frame, we return (with the header in the passed buffer).               */
    while (1) {
        if (!wtap_read_bytes_or_eof(fh, header, VW_RECORD_HEADER_LENGTH, err, err_info))
            return false;

        /* Got a header; invoke decode-message function to parse and process it.     */
        /* If the function returns a length, then a frame or variable-length message */
        /*  follows the 16-byte message.                                             */
        /* If the variable length message is not a frame, simply skip over it.       */
        if ((f_len = decode_msg(vwr, header, &v_type, IS_TX, log_mode)) != 0) {
            if (f_len > B_SIZE) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = ws_strdup_printf("vwr: Invalid message record length %d", f_len);
                return false;
            }
            else if (v_type != VT_FRAME) {
                if (!wtap_read_bytes(fh, NULL, f_len, err, err_info))
                    return false;
            }
            else {
                *rec_size = f_len;
                return true;
            }
        }
    }
}

/* Figure out the FPGA version (and also see whether this is a VWR file type. */
/* Return FPGA version if it's a known version, UNKNOWN_FPGA if it's not,     */
/*  and -1 on an I/O error.                                                   */

static int vwr_get_fpga_version(wtap *wth, int *err, char **err_info)
{
    uint8_t *rec;         /* local buffer (holds input record) */
    uint8_t  header[VW_RECORD_HEADER_LENGTH];
    int      rec_size     = 0;
    uint8_t  i;
    uint8_t *s_510006_ptr = NULL;
    uint8_t *s_510024_ptr = NULL;
    uint8_t *s_510012_ptr = NULL; /* stats pointers */
    int64_t  filePos      = -1;
    uint64_t bytes_read   = 0;
    uint32_t frame_type   = 0;
    int      f_len, v_type;
    uint16_t data_length  = 0;
    uint16_t fpga_version;
    bool valid_but_empty_file = false;

    filePos = file_tell(wth->fh);
    if (filePos == -1) {
        *err = file_error(wth->fh, err_info);
        return -1;
    }

    fpga_version = 1000;
    rec = (uint8_t*)g_malloc(B_SIZE);
    /* Got a frame record; see if it is vwr  */
    /* If we don't get it all, then declare an error, we can't process the frame.          */
    /* Read out the file data in 16-byte messages, stopping either after we find a frame,  */
    /*  or if we run out of data.                                                          */
    /* Each 16-byte message is decoded; if we run across a non-frame message followed by a */
    /*  variable-length item, we read the variable length item out and discard it.         */
    /* If we find a frame, we return (with the header in the passed buffer).               */
    while (wtap_read_bytes(wth->fh, header, VW_RECORD_HEADER_LENGTH, err, err_info)) {
        /* Got a header; invoke decode-message function to parse and process it.     */
        /* If the function returns a length, then a frame or variable-length message */
        /*  follows the 16-byte message.                                             */
        /* If the variable length message is not a frame, simply skip over it.       */
        if ((f_len = decode_msg(NULL, header, &v_type, NULL, NULL)) != 0) {
            if (f_len > B_SIZE) {
                g_free(rec);
                /* Treat this here as an indication that the file probably */
                /*  isn't a vwr file. */
                return UNKNOWN_FPGA;
            }
            else if (v_type != VT_FRAME) {
                if (!wtap_read_bytes(wth->fh, NULL, f_len, err, err_info)) {
                    g_free(rec);
                    if (*err == WTAP_ERR_SHORT_READ)
                        return UNKNOWN_FPGA; /* short read - not a vwr file */
                    return -1;
                }
                else if (v_type == VT_CPMSG)
                    valid_but_empty_file = true;
            }
            else {
                rec_size = f_len;
                /* Got a frame record; read over entire record (frame + trailer) into a local buffer */
                /* If we don't get it all, assume this isn't a vwr file */
                if (!wtap_read_bytes(wth->fh, rec, rec_size, err, err_info)) {
                    g_free(rec);
                    if (*err == WTAP_ERR_SHORT_READ)
                        return UNKNOWN_FPGA; /* short read - not a vwr file */
                    return -1;
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

                    if ((header[8] == 48) || (header[8] == 61) || (header[8] == 68))
                        fpga_version = S3_W_FPGA;
                    else {
                        data_length = (256 * (rec[vVW510021_W_MSDU_LENGTH_OFF + 1] & 0x1f)) + rec[vVW510021_W_MSDU_LENGTH_OFF];

                        i = 0;
                        while (((data_length + i) % 4) != 0)
                            i = i + 1;

                        /*the 12 is from the 12 bytes of plcp header */
                        if (rec_size == (data_length + vVW510021_W_STATS_TRAILER_LEN +vVW510021_W_AFTERHEADER_LEN+12+i))
                            fpga_version = S2_W_FPGA;
                    }
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

                if (fpga_version != 1000)
                {
                    /* reset the file position offset */
                    if (file_seek (wth->fh, filePos, SEEK_SET, err) == -1) {
                        g_free(rec);
                        return (-1);
                    }

                    /* We found an FPGA that works */
                    g_free(rec);
                    return fpga_version;
                }
            }
        }
        bytes_read += VW_RECORD_HEADER_LENGTH;
        if (bytes_read > VW_BYTES_TO_CHECK) {
            /* no frame found in VW_BYTES_TO_CHECK - not a vwr file */
            g_free(rec);
            return UNKNOWN_FPGA;
        }
    }

    /* Is this a valid but empty file?  If so, claim it's the S3_W_FPGA FPGA. */
    if (valid_but_empty_file) {
        g_free(rec);
        return(S3_W_FPGA);
    }

    if (*err == WTAP_ERR_SHORT_READ) {
        g_free(rec);
        return UNKNOWN_FPGA; /* short read - not a vwr file */
    }

    /*
     * Read error.
     */
    g_free(rec);
    return -1;
}

/* Copy the actual packet data from the capture file into the target data block. */
/* The packet is constructed as a 38-byte VeriWave metadata header plus the raw */
/*  MAC octets. */

static bool vwr_read_s1_W_rec(vwr_t *vwr, wtap_rec *record,
                                  Buffer *buf, const uint8_t *rec, int rec_size,
                                  int *err, char **err_info)
{
    uint8_t          *data_ptr;
    int              bytes_written = 0;                   /* bytes output to buf so far */
    const uint8_t    *s_ptr, *m_ptr;                      /* stats pointer */
    uint16_t         msdu_length, actual_octets;          /* octets in frame */
    uint16_t         plcp_hdr_len;                        /* PLCP header length */
    uint16_t         rflags;
    uint8_t          m_type;                              /* mod type (CCK-L/CCK-S/OFDM), seqnum */
    unsigned         flow_seq;
    uint64_t         s_time = LL_ZERO, e_time = LL_ZERO;  /* start/end */
                                                          /* times, nsec */
    uint32_t         latency;
    uint64_t         start_time, s_sec, s_usec = LL_ZERO; /* start time, sec + usec */
    uint64_t         end_time;                            /* end time */
    uint32_t         info;                                /* INFO/ERRORS fields in stats blk */
    int8_t           rssi;                                /* RSSI, signed 8-bit number */
    int              f_tx;                                /* flag: if set, is a TX frame */
    uint8_t          rate_index;                          /* pre-HT only */
    uint16_t         vc_id, ht_len=0;                     /* VC ID, total ip length */
    unsigned         flow_id;                             /* flow ID */
    uint32_t         d_time, errors;                      /* packet duration & errors */
    int              sig_off, pay_off;                    /* MAC+SNAP header len, signature offset */
    uint64_t         sig_ts;                              /* 32 LSBs of timestamp in signature */
    uint16_t         phyRate;
    uint16_t         vw_flags;                            /* VeriWave-specific packet flags */

    /*
     * The record data must be large enough to hold the statistics trailer.
     */
    if (rec_size < v22_W_STATS_LEN) {
        *err_info = ws_strdup_printf("vwr: Invalid record length %d (must be at least %u)",
                                    rec_size, v22_W_STATS_LEN);
        *err = WTAP_ERR_BAD_FILE;
        return false;
    }

    /* Calculate the start of the statistics block in the buffer */
    /* Also get a bunch of fields from the stats block */
    s_ptr    = &(rec[rec_size - v22_W_STATS_LEN]); /* point to it */
    m_type   = s_ptr[v22_W_MTYPE_OFF] & v22_E_MT_MASK;
    f_tx     = !(s_ptr[v22_W_MTYPE_OFF] & v22_E_IS_RX);
    actual_octets   = pntoh16(&s_ptr[v22_W_OCTET_OFF]);
    vc_id    = pntoh16(&s_ptr[v22_W_VCID_OFF]) & v22_E_VCID_MASK;
    flow_seq = s_ptr[v22_W_FLOWSEQ_OFF];

    latency = (uint32_t)pcorey48tohll(&s_ptr[v22_W_LATVAL_OFF]);

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
        *err_info = ws_strdup_printf("vwr: Invalid data length %u (runs past the end of the record)",
                                    actual_octets);
        *err = WTAP_ERR_BAD_FILE;
        return false;
    }

    /* Decode OFDM or CCK PLCP header and determine rate and short preamble flag. */
    /* The SIGNAL byte is always the first byte of the PLCP header in the frame.  */
    if (m_type == vwr->MT_OFDM)
        rate_index = get_ofdm_rate(rec);
    else if ((m_type == vwr->MT_CCKL) || (m_type == vwr->MT_CCKS))
        rate_index = get_cck_rate(rec);
    else
        rate_index = 1;
    rflags  = (m_type == vwr->MT_CCKS) ? FLAGS_SHORTPRE : 0;
    /* Calculate the MPDU size/ptr stuff; MPDU starts at 4 or 6 depending on OFDM/CCK. */
    /* Note that the number of octets in the frame also varies depending on OFDM/CCK,  */
    /*  because the PLCP header is prepended to the actual MPDU.                       */
    plcp_hdr_len = (m_type == vwr->MT_OFDM) ? 4 : 6;
    if (actual_octets >= plcp_hdr_len)
       actual_octets -= plcp_hdr_len;
    else {
        *err_info = ws_strdup_printf("vwr: Invalid data length %u (too short to include %u-byte PLCP header)",
                                    actual_octets, plcp_hdr_len);
        *err = WTAP_ERR_BAD_FILE;
        return false;
    }
    m_ptr = &rec[plcp_hdr_len];
    msdu_length = actual_octets;

    /*
     * The MSDU length includes the FCS.
     *
     * The packet data does *not* include the FCS - it's just 4 bytes
     * of junk - so we have to remove it.
     *
     * We'll be stripping off that junk, so make sure we have at least
     * 4 octets worth of packet data.
     *
     * There seems to be a special case of a length of 0.
     */
    if (actual_octets < 4) {
        if (actual_octets != 0) {
            *err_info = ws_strdup_printf("vwr: Invalid data length %u (too short to include %u-byte PLCP header and 4 bytes of FCS)",
                                        actual_octets, plcp_hdr_len);
            *err = WTAP_ERR_BAD_FILE;
            return false;
        }
    } else {
        actual_octets -= 4;
    }

    /* Calculate start & end times (in sec/usec), converting 64-bit times to usec. */
    /* 64-bit times are "Corey-endian" */
    s_time = pcoreytohll(&s_ptr[v22_W_STARTT_OFF]);
    e_time = pcoreytohll(&s_ptr[v22_W_ENDT_OFF]);

    /* find the packet duration (difference between start and end times) */
    d_time = (uint32_t)((e_time - s_time) / NS_IN_US);   /* find diff, converting to usec */

    /* also convert the packet start time to seconds and microseconds */
    start_time = s_time / NS_IN_US;                /* convert to microseconds first  */
    s_sec      = (start_time / US_IN_SEC);         /* get the number of seconds      */
    s_usec     = start_time - (s_sec * US_IN_SEC); /* get the number of microseconds */

    /* also convert the packet end time to seconds and microseconds */
    end_time = e_time / NS_IN_US;                       /* convert to microseconds first */

    /* extract the 32 LSBs of the signature timestamp field from the data block*/
    pay_off = 42;    /* 24 (MAC) + 8 (SNAP) + IP */
    sig_off = find_signature(m_ptr, rec_size - 6, pay_off, flow_id, flow_seq);
    if (m_ptr[sig_off] == 0xdd)
        sig_ts = get_signature_ts(m_ptr, sig_off, rec_size - v22_W_STATS_LEN);
    else
        sig_ts = 0;

    /*
     * Fill up the per-packet header.
     *
     * We include the length of the metadata headers in the packet lengths.
     *
     * The maximum value of actual_octets is 8191, which, even after
     * adding the lengths of the metadata headers, is less than
     * WTAP_MAX_PACKET_SIZE_STANDARD will ever be, so we don't need to check it.
     */
    record->rec_header.packet_header.len = STATS_COMMON_FIELDS_LEN + EXT_WLAN_FIELDS_LEN + actual_octets;
    record->rec_header.packet_header.caplen = STATS_COMMON_FIELDS_LEN + EXT_WLAN_FIELDS_LEN + actual_octets;

    record->ts.secs   = (time_t)s_sec;
    record->ts.nsecs  = (int)(s_usec * 1000);
    record->rec_header.packet_header.pkt_encap = WTAP_ENCAP_IXVERIWAVE;

    record->rec_type = REC_TYPE_PACKET;
    record->block = wtap_block_create(WTAP_BLOCK_PACKET);
    record->presence_flags = WTAP_HAS_TS;

    ws_buffer_assure_space(buf, record->rec_header.packet_header.caplen);
    data_ptr = ws_buffer_start_ptr(buf);

    /*
     * Generate and copy out the common metadata headers,
     * set the port type to 0 (WLAN).
     *
     * All values are copied out in little-endian byte order.
     */
    /* 1st octet of record for port_type and command (command is 0, hence RX) */
    phtole8(&data_ptr[bytes_written], WLAN_PORT);
    bytes_written += 1;
    /* 2nd octet of record for fpga version (0, hence pre-OCTO) */
    phtole8(&data_ptr[bytes_written], 0);
    bytes_written += 1;

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
    phyRate = (uint16_t)(get_legacy_rate(rate_index) * 10);
    phtoles(&data_ptr[bytes_written], phyRate);
    bytes_written += 2;
    data_ptr[bytes_written] = vVW510021_W_PLCP_LEGACY; /* pre-HT */
    bytes_written += 1;
    data_ptr[bytes_written] = rate_index;
    bytes_written += 1;
    data_ptr[bytes_written] = 1; /* pre-VHT, so NSS = 1 */
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

    return true;
}


static bool vwr_read_s2_W_rec(vwr_t *vwr, wtap_rec *record,
                                  Buffer *buf, const uint8_t *rec, int rec_size,
                                  int IS_TX, int *err, char **err_info)
{
    uint8_t          *data_ptr;
    int              bytes_written = 0;                   /* bytes output to buf so far */
    const uint8_t    *s_start_ptr,*s_trail_ptr, *plcp_ptr, *m_ptr; /* stats & MPDU ptr */
    uint32_t         msdu_length, actual_octets;          /* octets in frame */
    uint8_t          l1p_1, l1p_2, plcp_type, rate_mcs_index, nss;  /* mod (CCK-L/CCK-S/OFDM) */
    unsigned         flow_seq;
    uint64_t         s_time = LL_ZERO, e_time = LL_ZERO;  /* start/end */
                                                          /*  times, nsec */
    uint64_t         latency = LL_ZERO;
    uint64_t         start_time, s_sec, s_usec = LL_ZERO; /* start time, sec + usec */
    uint64_t         end_time;                            /* end time */
    uint16_t         info;                                /* INFO/ERRORS fields in stats blk */
    uint32_t         errors;
    int8_t           rssi[] = {0,0,0,0};                  /* RSSI, signed 8-bit number */
    int              f_tx;                                /* flag: if set, is a TX frame */
    uint16_t         vc_id, ht_len=0;                     /* VC ID , total ip length*/
    uint32_t         flow_id, d_time;                     /* flow ID, packet duration*/
    int              sig_off, pay_off;                    /* MAC+SNAP header len, signature offset */
    uint64_t         sig_ts, tsid;                        /* 32 LSBs of timestamp in signature */
    uint16_t         chanflags = 0;                       /* channel flags for WLAN metadata header */
    uint16_t         radioflags = 0;                      /* flags for WLAN metadata header */
    uint64_t         delta_b;                             /* Used for calculating latency */
    float            rate;
    uint16_t         phyRate;
    uint16_t         vw_flags;                            /* VeriWave-specific packet flags */

    /*
     * The record data must be large enough to hold the statistics header,
     * the PLCP, and the statistics trailer.
     */
    if ((unsigned)rec_size < vwr->MPDU_OFF + vVW510021_W_STATS_TRAILER_LEN) {
        *err_info = ws_strdup_printf("vwr: Invalid record length %d (must be at least %u)",
                                    rec_size,
                                    vwr->MPDU_OFF + vVW510021_W_STATS_TRAILER_LEN);
        *err = WTAP_ERR_BAD_FILE;
        return false;
    }

    /* Calculate the start of the statistics blocks in the buffer */
    /* Also get a bunch of fields from the stats blocks */
    s_start_ptr = &(rec[0]);                              /* point to stats header */
    s_trail_ptr = &(rec[rec_size - vVW510021_W_STATS_TRAILER_LEN]);      /* point to stats trailer */

    l1p_1 = s_start_ptr[vVW510021_W_L1P_1_OFF];
    l1p_2 = s_start_ptr[vVW510021_W_L1P_2_OFF];
    plcp_type = vVW510021_W_S2_PLCP_TYPE(l1p_2);
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

    plcp_ptr = &(rec[8]);

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
        *err_info = ws_strdup_printf("vwr: Invalid data length %u (runs past the end of the record)",
                                    actual_octets);
        *err = WTAP_ERR_BAD_FILE;
        return false;
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
    if ((info & v22_W_AGGREGATE_FLAGS) != 0)
    /* this length includes the Start_Spacing + Delimiter + MPDU + Padding for each piece of the aggregate*/
        ht_len = pletoh16(&s_start_ptr[vwr->PLCP_LENGTH_OFF]);


    /* decode OFDM or CCK PLCP header and determine rate and short preamble flag */
    /* the SIGNAL byte is always the first byte of the PLCP header in the frame */
    switch (plcp_type)
    {
    case vVW510021_W_PLCP_LEGACY:
        /*
         * From IEEE Std 802.11-2012:
         *
         * According to section 17.2.2 "PPDU format", the PLCP header
         * for the High Rate DSSS PHY (11b) has a SIGNAL field that's
         * 8 bits, followed by a SERVICE field that's 8 bits, followed
         * by a LENGTH field that's 16 bits, followed by a CRC field
         * that's 16 bits.  The PSDU follows it.  Section 17.2.3 "PPDU
         * field definitions" describes those fields.
         *
         * According to sections 18.3.2 "PLCP frame format" and 18.3.4
         * "SIGNAL field", the PLCP for the OFDM PHY (11a) has a SIGNAL
         * field that's 24 bits, followed by a service field that's
         * 16 bits, followed by the PSDU.  Section 18.3.5.2 "SERVICE
         * field" describes the SERVICE field.
         *
         * According to section 19.3.2 "PPDU format", the frames for the
         * Extended Rate PHY (11g) either extend the 11b format, using
         * additional bits in the SERVICE field, or extend the 11a
         * format.
         */
        rate_mcs_index = vVW510021_W_S2_RATE_INDEX(l1p_1);
        if (rate_mcs_index < 4) {
            chanflags |= CHAN_CCK;
        }
        else {
            chanflags |= CHAN_OFDM;
        }
        rate = get_legacy_rate(rate_mcs_index);
        nss = 0;
        break;

    case vVW510021_W_PLCP_MIXED:
        /*
         * According to section 20.3.2 "PPDU format", the HT-mixed
         * PLCP header has a "Non-HT SIGNAL field" (L-SIG), which
         * looks like an 11a SIGNAL field, followed by an HT SIGNAL
         * field (HT-SIG) described in section 20.3.9.4.3 "HT-SIG
         * definition".
         *
         * This means that the first octet of HT-SIG is at
         * plcp_ptr[3], skipping the 3 octets of the L-SIG field.
         *
         * 0x80 is the CBW 20/40 bit of HT-SIG.
         */
        /* set the appropriate flags to indicate HT mode and CB */
        rate_mcs_index = vVW510021_W_S2_MCS_INDEX_HT(l1p_1);
        radioflags |= FLAGS_CHAN_HT | ((plcp_ptr[3] & 0x80) ? FLAGS_CHAN_40MHZ : 0) |
                      ((l1p_1 & vVW510021_W_IS_LONGGI) ? 0 : FLAGS_CHAN_SHORTGI);
        chanflags  |= CHAN_OFDM;
        nss = (rate_mcs_index < MAX_HT_MCS) ? nss_for_mcs[rate_mcs_index] : 0;
        rate = get_ht_rate(rate_mcs_index, radioflags);
        break;

    case vVW510021_W_PLCP_GREENFIELD:
        /*
         * According to section 20.3.2 "PPDU format", the HT-greenfield
         * PLCP header just has the HT SIGNAL field (HT-SIG) above, with
         * no L-SIG field.
         *
         * This means that the first octet of HT-SIG is at
         * plcp_ptr[0], as there's no L-SIG field to skip.
         *
         * 0x80 is the CBW 20/40 bit of HT-SIG.
         */
        /* set the appropriate flags to indicate HT mode and CB */
        rate_mcs_index = vVW510021_W_S2_MCS_INDEX_HT(l1p_1);
        radioflags |= FLAGS_CHAN_HT | ((plcp_ptr[0] & 0x80) ? FLAGS_CHAN_40MHZ : 0) |
                      ((l1p_1 & vVW510021_W_IS_LONGGI) ?  0 : FLAGS_CHAN_SHORTGI);
        chanflags  |= CHAN_OFDM;
        nss = (rate_mcs_index < MAX_HT_MCS) ? nss_for_mcs[rate_mcs_index] : 0;
        rate = get_ht_rate(rate_mcs_index, radioflags);
        break;

    case vVW510021_W_PLCP_VHT_MIXED:
        /*
         * According to section 22.3.2 "VHT PPDU format" of IEEE Std
         * 802.11ac-2013, the VHT PLCP header has a "non-HT SIGNAL field"
         * (L-SIG), which looks like an 11a SIGNAL field, followed by
         * a VHT Signal A field (VHT-SIG-A) described in section
         * 22.3.8.3.3 "VHT-SIG-A definition", with training fields
         * between it and a VHT Signal B field (VHT-SIG-B) described
         * in section 22.3.8.3.6 "VHT-SIG-B definition", followed by
         * the PSDU.
         */
        {
            uint8_t SBW = vVW510021_W_BANDWIDTH_VHT(l1p_2);
            rate_mcs_index = vVW510021_W_S2_MCS_INDEX_VHT(l1p_1);
            radioflags |= FLAGS_CHAN_VHT | ((l1p_1 & vVW510021_W_IS_LONGGI) ?  0 : FLAGS_CHAN_SHORTGI);
            chanflags |= CHAN_OFDM;
            if (SBW == 3)
                radioflags |= FLAGS_CHAN_40MHZ;
            else if (SBW == 4)
                radioflags |= FLAGS_CHAN_80MHZ;
            nss = vVW510021_W_S2_NSS_VHT(l1p_1);
            rate = get_vht_rate(rate_mcs_index, radioflags, nss);
        }
        break;

    default:
        rate_mcs_index = 0;
        nss = 0;
        rate = 0.0f;
        break;
    }

    /*
     * The MSDU length includes the FCS.
     *
     * The packet data does *not* include the FCS - it's just 4 bytes
     * of junk - so we have to remove it.
     *
     * We'll be stripping off that junk, so make sure we have at least
     * 4 octets worth of packet data.
     *
     * There seems to be a special case of a length of 0.
     */
    if (actual_octets < 4) {
        if (actual_octets != 0) {
            *err_info = ws_strdup_printf("vwr: Invalid data length %u (too short to include 4 bytes of FCS)",
                                        actual_octets);
            *err = WTAP_ERR_BAD_FILE;
            return false;
        }
    } else {
        actual_octets -= 4;
    }

    /* Calculate start & end times (in sec/usec), converting 64-bit times to usec. */
    /* 64-bit times are "Corey-endian" */
    s_time = pcoreytohll(&s_trail_ptr[vVW510021_W_STARTT_OFF]);
    e_time = pcoreytohll(&s_trail_ptr[vVW510021_W_ENDT_OFF]);

    /* find the packet duration (difference between start and end times) */
    d_time = (uint32_t)((e_time - s_time) / NS_IN_US);  /* find diff, converting to usec */

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
    if (m_ptr[sig_off] == 0xdd)
        sig_ts = get_signature_ts(m_ptr, sig_off, rec_size - vVW510021_W_STATS_TRAILER_LEN);
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
     *
     * The maximum value of actual_octets is 8191, which, even after
     * adding the lengths of the metadata headers, is less than
     * WTAP_MAX_PACKET_SIZE_STANDARD will ever be, so we don't need to check it.
     */
    record->rec_header.packet_header.len = STATS_COMMON_FIELDS_LEN + EXT_WLAN_FIELDS_LEN + actual_octets;
    record->rec_header.packet_header.caplen = STATS_COMMON_FIELDS_LEN + EXT_WLAN_FIELDS_LEN + actual_octets;

    record->ts.secs   = (time_t)s_sec;
    record->ts.nsecs  = (int)(s_usec * 1000);

    record->rec_type = REC_TYPE_PACKET;
    record->block = wtap_block_create(WTAP_BLOCK_PACKET);
    record->presence_flags = WTAP_HAS_TS;

    ws_buffer_assure_space(buf, record->rec_header.packet_header.caplen);
    data_ptr = ws_buffer_start_ptr(buf);

    /*
     * Generate and copy out the common metadata headers,
     * set the port type to 0 (WLAN).
     *
     * All values are copied out in little-endian byte order.
     */
    /*** msdu_length = msdu_length + 16; ***/
    /* 1st octet of record for port_type and command (command is 0, hence RX) */
    phtole8(&data_ptr[bytes_written], WLAN_PORT);
    bytes_written += 1;
    /* 2nd octet of record for fpga version (0, hence pre-OCTO) */
    phtole8(&data_ptr[bytes_written], 0);
    bytes_written += 1;

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
    if (!(l1p_1 & vVW510021_W_IS_LONGPREAMBLE) && (plcp_type == vVW510021_W_PLCP_LEGACY))
        radioflags |= FLAGS_SHORTPRE;
    phtoles(&data_ptr[bytes_written], radioflags);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], chanflags);
    bytes_written += 2;
    phyRate = (uint16_t)(rate * 10);
    phtoles(&data_ptr[bytes_written], phyRate);
    bytes_written += 2;

    data_ptr[bytes_written] = plcp_type;
    bytes_written += 1;

    data_ptr[bytes_written] = rate_mcs_index;
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

    /* Finally, copy the whole MAC frame to the packet buffer as-is.
     * This does not include the stats header or the PLCP.
     * This also does not include the last 4 bytes, as those don't
     * contain an FCS, they just contain junk.
     */
    memcpy(&data_ptr[bytes_written], &rec[vwr->MPDU_OFF], actual_octets);

    return true;
}

static bool vwr_read_s3_W_rec(vwr_t *vwr, wtap_rec *record,
                                  Buffer *buf, const uint8_t *rec, int rec_size,
                                  int IS_TX, int log_mode, int *err,
                                  char **err_info)
{
    uint8_t          *data_ptr;
    int              bytes_written = 0;                  /* bytes output to buf so far */
    int              i;
    int              stats_offset = 0;
    const uint8_t    *s_start_ptr = NULL,*s_trail_ptr = NULL, *plcp_ptr, *m_ptr; /* stats & MPDU ptr */
    uint32_t         msdu_length = 0, actual_octets = 0; /* octets in frame */
    uint8_t          l1p_1 = 0,l1p_2 = 0, plcp_type, rate_mcs_index, nss;   /* mod (CCK-L/CCK-S/OFDM) */
    uint64_t         s_time = LL_ZERO, e_time = LL_ZERO; /* start/end */
                                                         /* times, nsec */
    uint64_t         latency = LL_ZERO;
    uint64_t         start_time = 0, s_sec = 0, s_usec = LL_ZERO; /* start time, sec + usec */
    uint64_t         end_time = 0;                                /* end time */
    uint16_t         info = 0;                           /* INFO/ERRORS fields in stats blk */
    uint32_t         errors = 0;
    int8_t           info_2nd = 0,rssi[] = {0,0,0,0};    /* RSSI, signed 8-bit number */
    int              frame_size;
    uint32_t         d_time = 0, flow_id = 0;            /* packet duration, Flow Signature ID*/
    int              sig_off, pay_off;                   /* MAC+SNAP header len, signature offset */
    uint64_t         sig_ts = 0, tsid;                   /* 32 LSBs of timestamp in signature */
    uint64_t         delta_b;                            /* Used for calculating latency */
    uint8_t          L1InfoC = 0, port_type, ver_fpga = 0;
    uint8_t          flow_seq =0,plcp_hdr_flag = 0,rf_id = 0;    /* indicates plcp hdr info */
    const uint8_t   *rf_ptr = NULL;
    float            rate;
    uint16_t         phyRate;

    /*
     * The record data must be large enough to hold the statistics header,
     * the PLCP, and the statistics trailer.
     */
    if (IS_TX == 3) {       /*IS_TX =3, i.e., command type is RF Modified*/
        if ((unsigned)rec_size < OCTO_MODIFIED_RF_LEN) {
            *err_info = ws_strdup_printf("vwr: Invalid record length %d (must be at least %u)",
                                        rec_size,
                                        OCTO_MODIFIED_RF_LEN);
            *err = WTAP_ERR_BAD_FILE;
            return false;
        }
        rf_ptr = &(rec[0]);
        rf_id = rf_ptr[0];

        /*
         * Fill up the per-packet header.
         *
         * We include the length of the metadata headers in the packet lengths.
         *
         * OCTO_MODIFIED_RF_LEN + 1 is less than WTAP_MAX_PACKET_SIZE_STANDARD will
         * ever be, so we don't need to check it.
         */
        record->rec_header.packet_header.len = OCTO_MODIFIED_RF_LEN + 1;       /* 1st octet is reserved for detecting type of frame while displaying in wireshark */
        record->rec_header.packet_header.caplen = OCTO_MODIFIED_RF_LEN + 1;

        record->ts.secs   = (time_t)s_sec;
        record->ts.nsecs  = (int)(s_usec * 1000);

        record->rec_type = REC_TYPE_PACKET;
        record->block = wtap_block_create(WTAP_BLOCK_PACKET);
        record->presence_flags = WTAP_HAS_TS;

        ws_buffer_assure_space(buf, record->rec_header.packet_header.caplen);
        data_ptr = ws_buffer_start_ptr(buf);

        port_type = IS_TX << 4;

        nss = 0;
        phyRate = 0;
    }
    else {
        /* Calculate the start of the statistics blocks in the buffer */
        /* Also get a bunch of fields from the stats blocks */
        /* 'stats_offset' variable is use to locate the exact offset.
         * When a RX frame contrains RF,
         * the position of Stats, Layer 1-4, PLCP parameters are shifted to
         * + OCTO_RF_MOD_ACTUAL_LEN bytes
         */
        if (IS_TX == 4)     /*IS_TX =4, i.e., command type is RF-RX Modified*/
        {
            stats_offset = OCTO_RF_MOD_ACTUAL_LEN;
            if ((unsigned)rec_size < stats_offset + vwr->MPDU_OFF + vVW510021_W_STATS_TRAILER_LEN) {
                *err_info = ws_strdup_printf("vwr: Invalid record length %d (must be at least %u)",
                                            rec_size,
                                            stats_offset + vwr->MPDU_OFF + vVW510021_W_STATS_TRAILER_LEN);
                *err = WTAP_ERR_BAD_FILE;
                return false;
            }
            rf_ptr = &(rec[0]);
            rf_id = rf_ptr[0];
        }
        else
        {
            stats_offset = 0;
            if ((unsigned)rec_size < vwr->MPDU_OFF + vVW510021_W_STATS_TRAILER_LEN) {
                *err_info = ws_strdup_printf("vwr: Invalid record length %d (must be at least %u)",
                                            rec_size,
                                            vwr->MPDU_OFF + vVW510021_W_STATS_TRAILER_LEN);
                *err = WTAP_ERR_BAD_FILE;
                return false;
            }
        }

        s_start_ptr = &(rec[stats_offset]);         /* point to stats header */
        s_trail_ptr = &(rec[rec_size - vVW510021_W_STATS_TRAILER_LEN] );      /* point to stats trailer */

        l1p_1 = s_start_ptr[vVW510021_W_L1P_1_OFF];
        l1p_2 = s_start_ptr[vVW510021_W_L1P_2_OFF];

        plcp_type = vVW510021_W_S3_PLCP_TYPE(l1p_2);
        switch (plcp_type)
        {
        case vVW510021_W_PLCP_LEGACY:
            /* pre-HT */
            rate_mcs_index = vVW510021_W_S3_RATE_INDEX(l1p_1);
            nss = 0;
            break;

        case vVW510021_W_PLCP_MIXED:
        case vVW510021_W_PLCP_GREENFIELD:
            rate_mcs_index = vVW510021_W_S3_MCS_INDEX_HT(l1p_1);
            nss = (rate_mcs_index < MAX_HT_MCS) ? nss_for_mcs[rate_mcs_index] : 0;
            break;

        case vVW510021_W_PLCP_VHT_MIXED:
            rate_mcs_index = vVW510021_W_S3_MCS_INDEX_VHT(l1p_1);
            nss = vVW510021_W_S3_NSS_VHT(l1p_1);
            plcp_hdr_flag = 1;
            break;

        default:
            rate_mcs_index = 0;
            nss = 0;
            plcp_hdr_flag = 0;
            break;
        }

        for (i = 0; i < 4; i++)
        {
            if (IS_TX == 1)
            {
                rssi[i] = (s_start_ptr[4+i] & 0x80) ? -1 * (s_start_ptr[4+i] & 0x7f) : s_start_ptr[4+i] & 0x7f;
            }
            else
            {
                rssi[i] = (s_start_ptr[4+i] >= 128) ? (s_start_ptr[4+i] - 256) : s_start_ptr[4+i];
            }
        }

        if (IS_TX == 0 || IS_TX == 4){
            L1InfoC = s_start_ptr[8];
        }

        msdu_length = pntoh24(&s_start_ptr[9]);

        /*** 16 bytes of PLCP header + 1 byte of L1P for user position ***/
        plcp_ptr = &(rec[stats_offset+16]);

        /*** Add the PLCP length for S3_W_FPGA version VHT frames for Beamforming decode ***/
        if (log_mode == 3) {
            frame_size = rec_size - (stats_offset + vwr->MPDU_OFF + vVW510021_W_STATS_TRAILER_LEN);
            if (frame_size > ((int) msdu_length))
                actual_octets = msdu_length;
            else {
                /*
                 * XXX - does this mean "the packet was cut short during
                 * capture" or "this is a malformed record"?
                 */
                actual_octets = frame_size;
            }
        }
        else
        {
            actual_octets = msdu_length;
        }
        /*
         * Sanity check the octets field to determine if it's greater than
         * the packet data available in the record - i.e., the record size
         * minus the sum of (length of statistics header + PLCP) and
         * (length of statistics trailer).
         *
         * Report an error if it is.
         */
        if (actual_octets > rec_size - (stats_offset + vwr->MPDU_OFF + vVW510021_W_STATS_TRAILER_LEN)) {
            *err_info = ws_strdup_printf("vwr: Invalid data length %u (runs past the end of the record)",
                                        actual_octets);
            *err = WTAP_ERR_BAD_FILE;
            return false;
        }

        flow_seq = s_trail_ptr[vVW510021_W_FLOWSEQ_OFF];

        latency = 0x00000000;                        /* clear latency */
        flow_id = pntoh24(&s_trail_ptr[vVW510021_W_FLOWID_OFF]);         /* all 24 bits valid */
        /* For tx latency is duration, for rx latency is timestamp */
        /* Get 48-bit latency value */
        tsid = pcorey48tohll(&s_trail_ptr[vVW510021_W_LATVAL_OFF]);

        errors = pntoh32(&s_trail_ptr[vVW510021_W_ERRORS_OFF]);
        info = pntoh16(&s_trail_ptr[vVW510021_W_INFO_OFF]);

        if (IS_TX == 0 || IS_TX == 4)
            info_2nd = s_trail_ptr[41];

        /*** Calculate Data rate based on
        *  PLCP type, MCS index and number of spatial stream
        *  radioflags is temporarily calculated, which is used in
        *  get_ht_rate() and get_vht_rate().
        **/
        switch (plcp_type)
        {
        case vVW510021_W_PLCP_LEGACY:
            rate = get_legacy_rate(rate_mcs_index);
            break;

        case vVW510021_W_PLCP_MIXED:
            /*
             * According to section 20.3.2 "PPDU format", the HT-mixed
             * PLCP header has a "Non-HT SIGNAL field" (L-SIG), which
             * looks like an 11a SIGNAL field, followed by an HT SIGNAL
             * field (HT-SIG) described in section 20.3.9.4.3 "HT-SIG
             * definition".
             *
             * This means that the first octet of HT-SIG is at
             * plcp_ptr[3], skipping the 3 octets of the L-SIG field.
             *
             * 0x80 is the CBW 20/40 bit of HT-SIG.
             */
            {
                /* set the appropriate flags to indicate HT mode and CB */
                uint16_t radioflags = FLAGS_CHAN_HT | ((plcp_ptr[3] & 0x80) ? FLAGS_CHAN_40MHZ : 0) |
                                   ((l1p_1 & vVW510021_W_IS_LONGGI) ? 0 : FLAGS_CHAN_SHORTGI);
                rate = get_ht_rate(rate_mcs_index, radioflags);
            }
            break;

        case vVW510021_W_PLCP_GREENFIELD:
            /*
             * According to section 20.3.2 "PPDU format", the HT-greenfield
             * PLCP header just has the HT SIGNAL field (HT-SIG) above, with
             * no L-SIG field.
             *
             * This means that the first octet of HT-SIG is at
             * plcp_ptr[0], as there's no L-SIG field to skip.
             *
             * 0x80 is the CBW 20/40 bit of HT-SIG.
             */
            {
                /* set the appropriate flags to indicate HT mode and CB */
                uint16_t radioflags = FLAGS_CHAN_HT | ((plcp_ptr[0] & 0x80) ? FLAGS_CHAN_40MHZ : 0) |
                                   ((l1p_1 & vVW510021_W_IS_LONGGI) ?  0 : FLAGS_CHAN_SHORTGI);
                rate = get_ht_rate(rate_mcs_index, radioflags);
            }
            break;

        case vVW510021_W_PLCP_VHT_MIXED:
            /*
             * According to section 22.3.2 "VHT PPDU format" of IEEE Std
             * 802.11ac-2013, the VHT PLCP header has a "non-HT SIGNAL field"
             * (L-SIG), which looks like an 11a SIGNAL field, followed by
             * a VHT Signal A field (VHT-SIG-A) described in section
             * 22.3.8.3.3 "VHT-SIG-A definition", with training fields
             * between it and a VHT Signal B field (VHT-SIG-B) described
             * in section 22.3.8.3.6 "VHT-SIG-B definition", followed by
             * the PSDU.
             */
            {
                uint8_t SBW = vVW510021_W_BANDWIDTH_VHT(l1p_2);
                uint16_t radioflags = FLAGS_CHAN_VHT | ((l1p_1 & vVW510021_W_IS_LONGGI) ?  0 : FLAGS_CHAN_SHORTGI);
                if (SBW == 3)
                    radioflags |= FLAGS_CHAN_40MHZ;
                else if (SBW == 4)
                    radioflags |= FLAGS_CHAN_80MHZ;
                rate = get_vht_rate(rate_mcs_index, radioflags, nss);
            }
            break;

        default:
            rate = 0.0f;
            break;
        }
        phyRate = (uint16_t)(rate * 10);
        /* Calculation of Data rate ends*/

        /* 'ver_fpga' is the 2nd Octet of each frame.
         * msb/lsb nibble indicates log mode/fpga version respectively.
         * where log mode = 0 is normal capture and 1 is reduced capture,
         * lsb nibble is set to 1 always as this function is applicable for only FPGA version >= 48
         */
        if (log_mode == 3) {
            if (frame_size >= (int) msdu_length) {
                /*
                 * The MSDU length includes the FCS.
                 *
                 * The packet data does *not* include the FCS - it's just 4
                 * bytes of junk - so we have to remove it.
                 *
                 * We'll be stripping off that junk, so make sure we have at
                 * least 4 octets worth of packet data.
                 *
                 * XXX - is the FCS actually present here, as it appears to be
                 * if log_mode isn't 3?
                 *
                 * There seems to be a special case of a length of 0.
                 */
                if (actual_octets < 4) {
                    if (actual_octets != 0) {
                        *err_info = ws_strdup_printf("vwr: Invalid data length %u (too short to include 4 bytes of FCS)",
                                                    actual_octets);
                        *err = WTAP_ERR_BAD_FILE;
                        return false;
                    }
                } else {
                    actual_octets -= 4;
                }
            }
            ver_fpga = 0x11;
        } else {
            ver_fpga = 0x01;
        }

        /* Calculate start & end times (in sec/usec), converting 64-bit times to usec. */
        /* 64-bit times are "Corey-endian" */
        s_time = pcoreytohll(&s_trail_ptr[vVW510021_W_STARTT_OFF]);
        e_time = pcoreytohll(&s_trail_ptr[vVW510021_W_ENDT_OFF]);

        /* find the packet duration (difference between start and end times) */
        d_time = (uint32_t)((e_time - s_time) / NS_IN_US);  /* find diff, converting to usec */

        /* also convert the packet start time to seconds and microseconds */
        start_time = s_time / NS_IN_US;                     /* convert to microseconds first */
        s_sec = (start_time / US_IN_SEC);                   /* get the number of seconds */
        s_usec = start_time - (s_sec * US_IN_SEC);          /* get the number of microseconds */

        /* also convert the packet end time to seconds and microseconds */
        end_time = e_time / NS_IN_US;                       /* convert to microseconds first */

        /* extract the 32 LSBs of the signature timestamp field */
        int m_ptr_offset = stats_offset + 8 + 12;
        m_ptr = rec + m_ptr_offset;
        pay_off = 42;         /* 24 (MAC) + 8 (SNAP) + IP */
        sig_off = find_signature(m_ptr, rec_size - m_ptr_offset, pay_off, flow_id, flow_seq);
        if (m_ptr[sig_off] == 0xdd)
            sig_ts = get_signature_ts(m_ptr, sig_off, rec_size - vVW510021_W_STATS_TRAILER_LEN);
        else
            sig_ts = 0;

        /* Set latency based on rx/tx and signature timestamp */
        if (IS_TX == 0 || IS_TX == 4) {
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

        port_type = IS_TX << 4;

        /*
         * Fill up the per-packet header.
         *
         * We include the length of the metadata headers in the packet lengths.
         */
        if (IS_TX == 4) {
            record->rec_header.packet_header.len = OCTO_MODIFIED_RF_LEN + OCTO_TIMESTAMP_FIELDS_LEN + OCTO_LAYER1TO4_LEN + actual_octets;
            record->rec_header.packet_header.caplen = OCTO_MODIFIED_RF_LEN + OCTO_TIMESTAMP_FIELDS_LEN + OCTO_LAYER1TO4_LEN + actual_octets;
        } else {
            record->rec_header.packet_header.len = OCTO_TIMESTAMP_FIELDS_LEN + OCTO_LAYER1TO4_LEN + actual_octets;
            record->rec_header.packet_header.caplen = OCTO_TIMESTAMP_FIELDS_LEN + OCTO_LAYER1TO4_LEN + actual_octets;
        }
        if (record->rec_header.packet_header.caplen > WTAP_MAX_PACKET_SIZE_STANDARD) {
            /*
             * Probably a corrupt capture file; return an error,
             * so that our caller doesn't blow up trying to allocate
             * space for an immensely-large packet.
             */
            *err_info = ws_strdup_printf("vwr: File has %u-byte packet, bigger than maximum of %u",
                                        record->rec_header.packet_header.caplen, WTAP_MAX_PACKET_SIZE_STANDARD);
            *err = WTAP_ERR_BAD_FILE;
            return false;
        }

        record->ts.secs   = (time_t)s_sec;
        record->ts.nsecs  = (int)(s_usec * 1000);

        record->rec_type = REC_TYPE_PACKET;
        record->block = wtap_block_create(WTAP_BLOCK_PACKET);
        record->presence_flags = WTAP_HAS_TS;

        ws_buffer_assure_space(buf, record->rec_header.packet_header.caplen);
        data_ptr = ws_buffer_start_ptr(buf);
    }

    /*
     * Generate and copy out the common metadata headers,
     * set the port type to port_type (XXX).
     *
     * All values are copied out in little-endian byte order.
     */
    /*** msdu_length = msdu_length + 16; ***/

    /* 1st octet of record for port_type and other crud */
    phtole8(&data_ptr[bytes_written], port_type);
    bytes_written += 1;

    if (IS_TX != 3) {
        phtole8(&data_ptr[bytes_written], ver_fpga); /* 2nd octet of record for FPGA version*/
        bytes_written += 1;

        phtoles(&data_ptr[bytes_written], OCTO_TIMESTAMP_FIELDS_LEN); /* it_len */
        bytes_written += 2;

    /*** Time Collapsible header started***/
        if (IS_TX == 1 && sig_ts != 0) {
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
    /*** Time Collapsible header ends ***/
    }

    /*** RF Collapsible header starts***/
    if (IS_TX == 3 || IS_TX == 4) {
        phtole8(&data_ptr[bytes_written], rf_id);
        bytes_written += 1;
        data_ptr[bytes_written] = 0;
        bytes_written += 1;
        data_ptr[bytes_written] = 0;
        bytes_written += 1;
        data_ptr[bytes_written] = 0;
        bytes_written += 1;

        /*** NOISE for all 4 Ports ***/
        for (i = 0; i < RF_NUMBER_OF_PORTS; i++)
        {
            if (pntoh16(&rf_ptr[RF_PORT_1_NOISE_OFF+i*RF_INTER_PORT_GAP_OFF]) == 0) {
                phtoles(&data_ptr[bytes_written], 0);
                bytes_written += 2;
            } else {
                data_ptr[bytes_written] = rf_ptr[RF_PORT_1_NOISE_OFF+i*RF_INTER_PORT_GAP_OFF];
                bytes_written += 1;
                data_ptr[bytes_written] = rf_ptr[RF_PORT_1_NOISE_OFF+1+i*RF_INTER_PORT_GAP_OFF];
                bytes_written += 1;
            }
        }

        /*** SNR for all 4 Ports ***/
        for (i = 0; i < RF_NUMBER_OF_PORTS; i++)
        {
            if (pntoh16(&rf_ptr[RF_PORT_1_SNR_OFF+i*RF_INTER_PORT_GAP_OFF]) == 0) {
                phtoles(&data_ptr[bytes_written], 0);
                bytes_written += 2;
            } else {
                data_ptr[bytes_written] = rf_ptr[RF_PORT_1_SNR_OFF+i*RF_INTER_PORT_GAP_OFF];
                bytes_written += 1;
                data_ptr[bytes_written] = rf_ptr[RF_PORT_1_SNR_OFF+1+i*RF_INTER_PORT_GAP_OFF];
                bytes_written += 1;
            }
        }

        /*** PFE for all 4 Ports ***/
        for (i = 0; i < RF_NUMBER_OF_PORTS; i++)
        {
            if (pntoh16(&rf_ptr[RF_PORT_1_PFE_OFF+i*RF_INTER_PORT_GAP_OFF]) == 0) {
                phtoles(&data_ptr[bytes_written], 0);
                bytes_written += 2;
            } else {
                data_ptr[bytes_written] = rf_ptr[RF_PORT_1_PFE_OFF+i*RF_INTER_PORT_GAP_OFF];
                bytes_written += 1;
                data_ptr[bytes_written] = rf_ptr[RF_PORT_1_PFE_OFF+1+i*RF_INTER_PORT_GAP_OFF];
                bytes_written += 1;
            }
        }

        /*** EVM SIG Data for all 4 Ports ***/
        for (i = 0; i < RF_NUMBER_OF_PORTS; i++)
        {
            if (pntoh16(&rf_ptr[RF_PORT_1_EVM_SD_SIG_OFF+i*RF_INTER_PORT_GAP_OFF]) == 0) {
                phtoles(&data_ptr[bytes_written], 0);
                bytes_written += 2;
            } else {
                data_ptr[bytes_written] = rf_ptr[RF_PORT_1_EVM_SD_SIG_OFF+i*RF_INTER_PORT_GAP_OFF];
                bytes_written += 1;
                data_ptr[bytes_written] = rf_ptr[RF_PORT_1_EVM_SD_SIG_OFF+1+i*RF_INTER_PORT_GAP_OFF];
                bytes_written += 1;
            }
        }

        /*** EVM SIG PILOT for all 4 Ports ***/
        for (i = 0; i < RF_NUMBER_OF_PORTS; i++)
        {
            if (pntoh16(&rf_ptr[RF_PORT_1_EVM_SP_SIG_OFF+i*RF_INTER_PORT_GAP_OFF]) == 0) {
                phtoles(&data_ptr[bytes_written], 0);
                bytes_written += 2;
            } else {
                data_ptr[bytes_written] = rf_ptr[RF_PORT_1_EVM_SP_SIG_OFF+i*RF_INTER_PORT_GAP_OFF];
                bytes_written += 1;
                data_ptr[bytes_written] = rf_ptr[RF_PORT_1_EVM_SP_SIG_OFF+1+i*RF_INTER_PORT_GAP_OFF];
                bytes_written += 1;
            }
        }

        /*** EVM Data Data for all 4 Ports ***/
        for (i = 0; i < RF_NUMBER_OF_PORTS; i++)
        {
            if (pntoh16(&rf_ptr[RF_PORT_1_EVM_SD_DATA_OFF+i*RF_INTER_PORT_GAP_OFF]) == 0) {
                phtoles(&data_ptr[bytes_written], 0);
                bytes_written += 2;
            } else {
                data_ptr[bytes_written] = rf_ptr[RF_PORT_1_EVM_SD_DATA_OFF+i*RF_INTER_PORT_GAP_OFF];
                bytes_written += 1;
                data_ptr[bytes_written] = rf_ptr[RF_PORT_1_EVM_SD_DATA_OFF+1+i*RF_INTER_PORT_GAP_OFF];
                bytes_written += 1;
            }
        }

        /*** EVM Data PILOT for all 4 Ports ***/
        for (i = 0; i < RF_NUMBER_OF_PORTS; i++)
        {
            if (pntoh16(&rf_ptr[RF_PORT_1_EVM_SP_DATA_OFF+i*RF_INTER_PORT_GAP_OFF]) == 0) {
                phtoles(&data_ptr[bytes_written], 0);
                bytes_written += 2;
            } else {
                data_ptr[bytes_written] = rf_ptr[RF_PORT_1_EVM_SP_DATA_OFF+i*RF_INTER_PORT_GAP_OFF];
                bytes_written += 1;
                data_ptr[bytes_written] = rf_ptr[RF_PORT_1_EVM_SP_DATA_OFF+1+i*RF_INTER_PORT_GAP_OFF];
                bytes_written += 1;
            }
        }

        /*** EVM WORST SYMBOL for all 4 Ports ***/
        for (i = 0; i < RF_NUMBER_OF_PORTS; i++)
        {
            if (pntoh16(&rf_ptr[RF_PORT_1_DSYMBOL_IDX_OFF+i*RF_INTER_PORT_GAP_OFF]) == 0) {
                phtoles(&data_ptr[bytes_written], 0);
                bytes_written += 2;
            } else {
                data_ptr[bytes_written] = rf_ptr[RF_PORT_1_DSYMBOL_IDX_OFF+i*RF_INTER_PORT_GAP_OFF];
                bytes_written += 1;
                data_ptr[bytes_written] = rf_ptr[RF_PORT_1_DSYMBOL_IDX_OFF+1+i*RF_INTER_PORT_GAP_OFF];
                bytes_written += 1;
            }
        }

        /*** CONTEXT_P for all 4 Ports ***/
        for (i = 0; i < RF_NUMBER_OF_PORTS; i++)
        {
            if (pntoh16(&rf_ptr[RF_PORT_1_CONTEXT_OFF+i*RF_INTER_PORT_GAP_OFF]) == 0) {
                phtoles(&data_ptr[bytes_written], 0);
                bytes_written += 2;
            } else {
                data_ptr[bytes_written] = rf_ptr[RF_PORT_1_CONTEXT_OFF+i*RF_INTER_PORT_GAP_OFF];
                bytes_written += 1;
                data_ptr[bytes_written] = rf_ptr[RF_PORT_1_CONTEXT_OFF+1+i*RF_INTER_PORT_GAP_OFF];
                bytes_written += 1;
            }
        }

        /*** FOR rest 24 RF data bytes are commented for future use ***/
/***
        for (i = 0; i < RF_NUMBER_OF_PORTS; i++)
        {
            if (pntoh16(&rf_ptr[20+i*RF_INTER_PORT_GAP_OFF]) == 0) {
                phtoles(&data_ptr[bytes_written], 0);
                bytes_written += 2;
            } else {
                data_ptr[bytes_written] = rf_ptr[20+i*RF_INTER_PORT_GAP_OFF];
                bytes_written += 1;
                data_ptr[bytes_written] = rf_ptr[21+i*RF_INTER_PORT_GAP_OFF];
                bytes_written += 1;
            }
        }
        for (i = 0; i < RF_NUMBER_OF_PORTS; i++)
        {
            if (pntoh16(&rf_ptr[24+i*RF_INTER_PORT_GAP_OFF]) == 0) {
                phtoles(&data_ptr[bytes_written], 0);
                bytes_written += 2;
            } else {
                data_ptr[bytes_written] = rf_ptr[24+i*RF_INTER_PORT_GAP_OFF];
                bytes_written += 1;
                data_ptr[bytes_written] = rf_ptr[25+i*RF_INTER_PORT_GAP_OFF];
                bytes_written += 1;
            }
        }
        for (i = 0; i < RF_NUMBER_OF_PORTS; i++)
        {
            if (pntoh16(&rf_ptr[26+i*RF_INTER_PORT_GAP_OFF]) == 0) {
                phtoles(&data_ptr[bytes_written], 0);
                bytes_written += 2;
            } else {
                data_ptr[bytes_written] = rf_ptr[26+i*RF_INTER_PORT_GAP_OFF];
                bytes_written += 1;
                data_ptr[bytes_written] = rf_ptr[27+i*RF_INTER_PORT_GAP_OFF];
                bytes_written += 1;
            }
        }
***/
    }
    /*** RF Collapsible header ends***/

    if (IS_TX != 3) {
        /*
         * Generate and copy out the WLAN metadata headers.
         *
         * All values are copied out in little-endian byte order.
         */
        phtoles(&data_ptr[bytes_written], OCTO_LAYER1TO4_LEN);
        bytes_written += 2;

        /*** Layer-1 Collapsible header started***/
        data_ptr[bytes_written] = l1p_1;
        bytes_written += 1;

        data_ptr[bytes_written] = (nss << 4) | IS_TX;
        bytes_written += 1;

        phtoles(&data_ptr[bytes_written], phyRate);     /* To dosplay Data rate based on the PLCP type & MCS*/
        bytes_written += 2;

        data_ptr[bytes_written] = l1p_2;
        bytes_written += 1;

        data_ptr[bytes_written] = rssi[0];
        bytes_written += 1;
        data_ptr[bytes_written] = rssi[1];
        bytes_written += 1;
        data_ptr[bytes_written] = rssi[2];
        bytes_written += 1;
        data_ptr[bytes_written] = rssi[3];
        bytes_written += 1;

        /* padding may not be required for S3_W*/

        data_ptr[bytes_written] = s_start_ptr[2];    /*** For Signal Bandwidth Mask ***/
        bytes_written += 1;
        data_ptr[bytes_written] = s_start_ptr[3];    /*** For Antenna Port Energy Detect and MU_MASK ***/
        bytes_written += 1;

        if (plcp_hdr_flag == 1 && (IS_TX == 0 || IS_TX == 4)) {
            data_ptr[bytes_written] = L1InfoC;  /*** For Other plcp type = VHT ***/
        } else {
            data_ptr[bytes_written] = 0;    /*** For Other plcp type, this offset is set to 0***/
        }
        bytes_written += 1;

        phtoles(&data_ptr[bytes_written], msdu_length);
        bytes_written += 2;
        /*** Layer-1 Collapsible header Ends ***/

        /*** PLCP Collapsible header Starts ***/
        memcpy(&data_ptr[bytes_written], &rec[stats_offset+16], 16);
        bytes_written += 16;
        /*** PLCP Collapsible header Ends ***/

        /*** Layer 2-4 Collapsible header Starts ***/

        phtolel(&data_ptr[bytes_written], pntoh32(&s_start_ptr[12]));   /*** This 4 bytes includes BM,BV,CV,BSSID and ClientID ***/
        bytes_written += 4;
        phtoles(&data_ptr[bytes_written], pntoh16(&s_trail_ptr[20]));   /*** 2 bytes includes FV,QT,HT,L4V,TID and WLAN type ***/
        bytes_written += 2;
        data_ptr[bytes_written] = flow_seq;
        bytes_written += 1;
        phtole24(&data_ptr[bytes_written], flow_id);
        bytes_written += 3;
        phtoles(&data_ptr[bytes_written], pntoh16(&s_trail_ptr[28]));   /*** 2 bytes for Layer 4 ID ***/
        bytes_written += 2;
        phtolel(&data_ptr[bytes_written], pntoh32(&s_trail_ptr[24]));   /*** 4 bytes for Payload Decode ***/
        bytes_written += 4;

        /*** In case of RX, Info has 3 bytes of data, whereas for TX, 2 bytes ***/
        if (IS_TX == 0 || IS_TX == 4) {
            phtoles(&data_ptr[bytes_written], info);
            bytes_written += 2;
            data_ptr[bytes_written] = info_2nd;
            bytes_written += 1;
        }
        else {
            phtoles(&data_ptr[bytes_written], info);
            bytes_written += 2;
            data_ptr[bytes_written] = 0;
            bytes_written += 1;
        }

        phtolel(&data_ptr[bytes_written], errors);
        bytes_written += 4;
        /*** Layer 2-4 Collapsible header Ends ***/

        /* Finally, copy the whole MAC frame to the packet buffer as-is.
         * This does not include the stats header or the PLCP.
         * This also does not include the last 4 bytes, as those don't
         * contain an FCS, they just contain junk.
         */
        memcpy(&data_ptr[bytes_written], &rec[stats_offset+(vwr->MPDU_OFF)], actual_octets);
    }

    return true;
}

/* read an Ethernet packet */
/* Copy the actual packet data from the capture file into the target data block.         */
/* The packet is constructed as a 38-byte VeriWave-extended Radiotap header plus the raw */
/*  MAC octets.                                                                          */
static bool vwr_read_rec_data_ethernet(vwr_t *vwr, wtap_rec *record,
                                           Buffer *buf, const uint8_t *rec,
                                           int rec_size, int IS_TX, int *err,
                                           char **err_info)
{
    uint8_t          *data_ptr;
    int              bytes_written = 0;                   /* bytes output to buf so far */
    const uint8_t *s_ptr, *m_ptr;                          /* stats and MPDU pointers */
    uint16_t         msdu_length, actual_octets;          /* octets in frame */
    unsigned         flow_seq;                            /* seqnum */
    uint64_t         s_time = LL_ZERO, e_time = LL_ZERO;  /* start/end */
                                                          /* times, nsec */
    uint32_t         latency = 0;
    uint64_t         start_time, s_sec = LL_ZERO, s_usec = LL_ZERO; /* start time, sec + usec */
    uint64_t         end_time;                            /* end time */
    unsigned         l4id;
    uint16_t         info, validityBits;                  /* INFO/ERRORS fields in stats */
    uint32_t         errors;
    uint16_t         vc_id;                               /* VC ID, total (incl of aggregates) */
    uint32_t         flow_id, d_time;                     /* packet duration */
    int              f_flow;                              /* flags: flow valid */
    uint32_t         frame_type;                          /* frame type field */
    int              mac_len, sig_off, pay_off;           /* MAC header len, signature offset */
    /* XXX - the code here fetched tsid, but never used it! */
    uint64_t         sig_ts/*, tsid*/;                    /* 32 LSBs of timestamp in signature */
    uint64_t         delta_b;                             /* Used for calculating latency */
    uint16_t         vw_flags;                            /* VeriWave-specific packet flags */

    if ((unsigned)rec_size < vwr->STATS_LEN) {
        *err_info = ws_strdup_printf("vwr: Invalid record length %d (must be at least %u)", rec_size, vwr->STATS_LEN);
        *err = WTAP_ERR_BAD_FILE;
        return false;
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
        *err_info = ws_strdup_printf("vwr: Invalid data length %u (runs past the end of the record)",
                                    actual_octets);
        *err = WTAP_ERR_BAD_FILE;
        return false;
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
     * We'll be stripping off that junk, so make sure we have at least
     * 4 octets worth of packet data.
     *
     * There seems to be a special case of a length of 0.
     */
    if (actual_octets < 4) {
        if (actual_octets != 0) {
            *err_info = ws_strdup_printf("vwr: Invalid data length %u (too short to include 4 bytes of FCS)",
                                        actual_octets);
            *err = WTAP_ERR_BAD_FILE;
            return false;
        }
    } else {
        actual_octets -= 4;
    }

    /* Calculate start & end times (in sec/usec), converting 64-bit times to usec. */
    /* 64-bit times are "Corey-endian"                                             */
    s_time = pcoreytohll(&s_ptr[vwr->STARTT_OFF]);
    e_time = pcoreytohll(&s_ptr[vwr->ENDT_OFF]);

    /* find the packet duration (difference between start and end times) */
    d_time = (uint32_t)((e_time - s_time));  /* find diff, leaving in nsec for Ethernet */

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
    if ((m_ptr[sig_off] == 0xdd) && (f_flow != 0))
        sig_ts = get_signature_ts(m_ptr, sig_off, msdu_length);
    else
        sig_ts = 0;

    /* Set latency based on rx/tx and signature timestamp */
    if (!IS_TX) {
        if (sig_ts < s_time) {
            latency = (uint32_t)(s_time - sig_ts);
        } else {
            /* Account for the rollover case. Since we cannot use 0x100000000 - l_time + s_time */
            /*  we look for a large difference between l_time and s_time.                       */
            delta_b = sig_ts - s_time;
            if (delta_b >  0x10000000) {
                latency = 0;
            } else
                latency = (uint32_t)delta_b;
        }
    }

    /*
     * Fill up the per-packet header.
     *
     * We include the length of the metadata headers in the packet lengths.
     *
     * The maximum value of actual_octets is 65535, which, even after
     * adding the lengths of the metadata headers, is less than
     * WTAP_MAX_PACKET_SIZE_STANDARD will ever be, so we don't need to check it.
     */
    record->rec_header.packet_header.len = STATS_COMMON_FIELDS_LEN + EXT_ETHERNET_FIELDS_LEN + actual_octets;
    record->rec_header.packet_header.caplen = STATS_COMMON_FIELDS_LEN + EXT_ETHERNET_FIELDS_LEN + actual_octets;

    record->ts.secs   = (time_t)s_sec;
    record->ts.nsecs  = (int)(s_usec * 1000);

    record->rec_type = REC_TYPE_PACKET;
    record->block = wtap_block_create(WTAP_BLOCK_PACKET);
    record->presence_flags = WTAP_HAS_TS;

    /*etap_hdr.vw_ip_length = (uint16_t)ip_len;*/

    ws_buffer_assure_space(buf, record->rec_header.packet_header.caplen);
    data_ptr = ws_buffer_start_ptr(buf);

    /*
     * Generate and copy out the common metadata headers,
     * set the port type to 1 (Ethernet).
     *
     * All values are copied out in little-endian byte order.
     */
    /* 1st octet of record for port_type and command (command is 0, hence RX) */
    phtole8(&data_ptr[bytes_written], ETHERNET_PORT);
    bytes_written += 1;
    /* 2nd octet of record for fpga version (Ethernet, hence non-OCTO) */
    phtole8(&data_ptr[bytes_written], 0);
    bytes_written += 1;

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

    return true;
}

/*--------------------------------------------------------------------------------------*/
/* utility to split up and decode a 16-byte message record */

static int decode_msg(vwr_t *vwr, uint8_t *rec, int *v_type, int *IS_TX, int *log_mode)
{
    uint8_t cmd,fpga_log_mode;          /* components of message */
    uint32_t wd2, wd3;
    int     v_size;                     /* size of var-len message */

    /* break up the message record into its pieces */
    cmd = rec[0];
    fpga_log_mode = rec[1];
    fpga_log_mode = ((fpga_log_mode & 0x30) >> 4);

    wd2 = pntoh32(&rec[8]);
    wd3 = pntoh32(&rec[12]);

    if (vwr != NULL)
        *log_mode = fpga_log_mode;          /* Log mode = 3, when MPDU data is reduced */

    /* now decode based on the command byte */
    switch (cmd) {
        case COMMAND_RX:
            if (vwr != NULL) {
                *IS_TX = 0;
            }
            v_size  = (int)(wd2 & 0xffff);
            *v_type = VT_FRAME;
            break;

        case COMMAND_TX:
            if (vwr != NULL) {
                *IS_TX = 1;
            }
            v_size  = (int)(wd2 & 0xffff);
            *v_type = VT_FRAME;
            break;

/*
        case COMMAND_RFN:
            if (vwr != NULL) {
                *IS_TX = 3;
            }
            v_size  = (int)(wd2 & 0xffff);
            *v_type = VT_FRAME;
            break;
*/

        case COMMAND_RF:   /* For RF Modified only */
            if (vwr != NULL) {
                *IS_TX = 3;
            }
            v_size  = (int)(wd2 & 0xffff);
            *v_type = VT_FRAME;
            break;

        case COMMAND_RFRX: /* For RF_RX Modified only */
            if (vwr != NULL) {
                *IS_TX = 4;
            }
            v_size  = (int)(wd2 & 0xffff);
            *v_type = VT_FRAME;
            break;

        case 0xc1:
        case 0x8b:
        case 0xbb:
            if (vwr != NULL) {
                *IS_TX = 2;
            }
            v_size  = (int)(wd2 & 0xffff);
            *v_type = VT_CPMSG;
            break;

        case 0xfe:
            if (vwr != NULL) {
                *IS_TX = 2;
            }
            v_size  = (int)(wd3 & 0xffff);
            *v_type = VT_CPMSG;
            break;

        default:
            if (vwr != NULL) {
                *IS_TX = 2;
            }
            v_size  = 0;
            *v_type = VT_UNKNOWN;
            break;
    }

    return v_size;
}


/*---------------------------------------------------------------------------------------*/
/* Utilities to extract and decode the PHY bit rate from 802.11 PLCP headers (OFDM/CCK). */
/* They are passed a pointer to 4 or 6 consecutive bytes of PLCP header.                 */
/* The integer returned by the get_xxx_rate() functions is in units of 0.5 Mb/s.         */
/* The string returned by the decode_xxx_rate() functions is 3 characters wide.          */

static uint8_t get_ofdm_rate(const uint8_t *plcp)
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

static uint8_t get_cck_rate(const uint8_t *plcp)
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

static void setup_defaults(vwr_t *vwr, uint16_t fpga)
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
             * vVW510021_W_STATS_HEADER_LEN = 8 is:
             *
             *    2 bytes of l1p_1/l1p_2;
             *    1 byte of RSSI;
             *    2 bytes of MSDU length + other bits
             *    1 byte of XXX;
             *    2 bytes of VCID.
             *
             * The 12 is for 11 bytes of PLCP and 1 byte of pad
             * before the data.
             */
            vwr->MPDU_OFF           = vVW510021_W_STATS_HEADER_LEN + 12;

            break;

        case S3_W_FPGA:
            vwr->STATS_LEN       = vVW510021_W_STATS_TRAILER_LEN;
            vwr->PLCP_LENGTH_OFF = 16;

            /*
             * The 16 + 16 is:
             *
             *    2 bytes of l1p_1/l1p_2;
             *    1 byte of signal bandwidth mask;
             *    1 byte of antenna port energy;
             *    4 bytes of per-antenna RSSI;
             *    1 byte of L1InfoC;
             *    3 bytes of MSDU length;
             *    4 bytes of something;
             *   16 bytes of PLCP.
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
int find_signature(const uint8_t *m_ptr, int rec_size, int pay_off, uint32_t flow_id, uint8_t flow_seq)
{
    int     tgt;                /* temps */
    uint32_t fid;

    /* initial check is very simple: look for a '0xdd' at the target location */
    if (m_ptr[pay_off] == 0xdd)                         /* if magic byte is present */
        return pay_off;                                 /* got right offset, return it */

    /* Hmmm, signature magic byte is not where it is supposed to be; scan from start of     */
    /*  payload until maximum scan range exhausted to see if we can find it.                */
    /* The scanning process consists of looking for a '0xdd', then checking for the correct */
    /*  flow ID and sequence number at the appropriate offsets.                             */
    for (tgt = pay_off; tgt < (rec_size); tgt++) {
        if (m_ptr[tgt] == 0xdd) {                       /* found magic byte? check fields */
            if ((tgt + 15 < rec_size) && (m_ptr[tgt + 15] == 0xe2)) {
                if (m_ptr[tgt + 4] != flow_seq)
                    continue;

                fid = pletoh24(&m_ptr[tgt + 1]);

                if (fid != flow_id)
                    continue;

                return (tgt);
            }
            else if (tgt + SIG_FSQ_OFF < rec_size)
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
uint64_t get_signature_ts(const uint8_t *m_ptr,int sig_off, int sig_max)
{
    int     ts_offset;
    uint64_t sig_ts;

    if (sig_off + 15 >= sig_max)
        return 0;

    if (m_ptr[sig_off + 15] == 0xe2)
        ts_offset = 5;
    else
        ts_offset = 8;

    sig_ts = pletoh32(&m_ptr[sig_off + ts_offset]);

    return (sig_ts & 0xffffffff);
}

static float
get_legacy_rate(uint8_t rate_index)
{
    /* Rate conversion data */
    static const float canonical_rate_legacy[]  = {1.0f, 2.0f, 5.5f, 11.0f, 6.0f, 9.0f, 12.0f, 18.0f, 24.0f, 36.0f, 48.0f, 54.0f};

    float bitrate  = 0.0f;

    if (rate_index < G_N_ELEMENTS(canonical_rate_legacy))
        bitrate =  canonical_rate_legacy[rate_index];

    return bitrate;
}

static float
get_ht_rate(uint8_t mcs_index, uint16_t rflags)
{
    /* Rate conversion data */
    static const int   canonical_ndbps_20_ht[8]  = {26, 52, 78, 104, 156, 208, 234, 260};
    static const int   canonical_ndbps_40_ht[8]  = {54, 108, 162, 216, 324, 432, 486, 540};

    float symbol_tx_time, bitrate;
    int   ndbps;

    if (rflags & FLAGS_CHAN_SHORTGI)
        symbol_tx_time = 3.6f;
    else
        symbol_tx_time = 4.0f;

    if (rflags & FLAGS_CHAN_40MHZ)
        ndbps = canonical_ndbps_40_ht[mcs_index - 8*(int)(mcs_index/8)];
    else
        ndbps = canonical_ndbps_20_ht[mcs_index - 8*(int)(mcs_index/8)];

    bitrate = (ndbps * (((int)(mcs_index >> 3) + 1))) / symbol_tx_time;

    return bitrate;
}

static float
get_vht_rate(uint8_t mcs_index, uint16_t rflags, uint8_t nss)
{
    /* Rate conversion data */
    static const int   canonical_ndbps_20_vht[9] = {26, 52, 78, 104, 156, 208, 234, 260, 312};
    static const int   canonical_ndbps_40_vht[10] = {54, 108, 162, 216, 324, 432, 486, 540, 648, 720};
    static const int   canonical_ndbps_80_vht[10] = {117, 234, 351, 468, 702, 936, 1053, 1170, 1404, 1560};

    float symbol_tx_time, bitrate;

    if (rflags & FLAGS_CHAN_SHORTGI)
        symbol_tx_time = 3.6f;
    else
        symbol_tx_time = 4.0f;

    /*
     * Check for the out of range mcs_index.
     * Should never happen, but if mcs index is greater than 9 just
     * return 0.
     */
    if (mcs_index > 9)
        return 0.0f;
    if (rflags & FLAGS_CHAN_40MHZ)
        bitrate = (canonical_ndbps_40_vht[mcs_index] * nss) / symbol_tx_time;
    else if (rflags & FLAGS_CHAN_80MHZ)
        bitrate = (canonical_ndbps_80_vht[mcs_index] * nss) / symbol_tx_time;
    else
    {
        if (mcs_index == 9)
        {
            /* This is a special case for 20 MHz. */
            if (nss == 3)
                bitrate = 1040 / symbol_tx_time;
            else if (nss == 6)
                bitrate = 2080 / symbol_tx_time;
            else
                bitrate = 0.0f;
        }
        else
            bitrate = (canonical_ndbps_20_vht[mcs_index] * nss) / symbol_tx_time;
    }

    return bitrate;
}

static bool
vwr_process_rec_data(FILE_T fh, int rec_size,
                     wtap_rec *record, Buffer *buf, vwr_t *vwr,
                     int IS_TX, int log_mode, int *err, char **err_info)
{
    uint8_t*   rec;       /* local buffer (holds input record) */
    bool      ret = false;

    rec = (uint8_t*)g_malloc(B_SIZE);

    /* Read over the entire record (frame + trailer) into a local buffer.         */
    /* If we don't get it all, then declare an error, we can't process the frame. */
    if (!wtap_read_bytes(fh, rec, rec_size, err, err_info))
    {
        g_free(rec);
        return false;
    }

    /* now format up the frame data */
    switch (vwr->FPGA_VERSION)
    {
        case S1_W_FPGA:
            ret = vwr_read_s1_W_rec(vwr, record, buf, rec, rec_size, err, err_info);
            break;
        case S2_W_FPGA:
            ret = vwr_read_s2_W_rec(vwr, record, buf, rec, rec_size, IS_TX, err, err_info);
            break;
        case S3_W_FPGA:
            ret = vwr_read_s3_W_rec(vwr, record, buf, rec, rec_size, IS_TX, log_mode, err, err_info);
            break;
        case vVW510012_E_FPGA:
        case vVW510024_E_FPGA:
            ret = vwr_read_rec_data_ethernet(vwr, record, buf, rec, rec_size, IS_TX, err, err_info);
            break;
        default:
            g_free(rec);
            ws_assert_not_reached();
            return ret;
    }

    g_free(rec);
    return ret;
}

static const struct supported_block_type vwr_80211_blocks_supported[] = {
    /*
     * We support packet blocks, with no comments or other options.
     */
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info vwr_80211_info = {
    "Ixia IxVeriWave .vwr Raw 802.11 Capture", "vwr80211", "vwr", NULL,
    false, BLOCKS_SUPPORTED(vwr_80211_blocks_supported),
    NULL, NULL, NULL
};

static const struct supported_block_type vwr_eth_blocks_supported[] = {
    /*
     * We support packet blocks, with no comments or other options.
     */
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info vwr_eth_info = {
    "Ixia IxVeriWave .vwr Raw Ethernet Capture", "vwreth", "vwr", NULL,
    false, BLOCKS_SUPPORTED(vwr_eth_blocks_supported),
    NULL, NULL, NULL
};

void register_vwr(void)
{
    vwr_80211_file_type_subtype = wtap_register_file_type_subtype(&vwr_80211_info);
    vwr_eth_file_type_subtype = wtap_register_file_type_subtype(&vwr_eth_info);

    /*
     * Register names for backwards compatibility with the
     * wtap_filetypes table in Lua.
     */
    wtap_register_backwards_compatibility_lua_name("VWR_80211",
                                                   vwr_80211_file_type_subtype);
    wtap_register_backwards_compatibility_lua_name("VWR_ETH",
                                                   vwr_eth_file_type_subtype);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
