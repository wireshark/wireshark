/*-
 * Copyright (c) 2003, 2004 David Young.  All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * Modifications to fit into the linux IEEE 802.11 stack,
 * Mike Kershaw (dragorn@kismetwireless.net)
 */

#ifndef IEEE80211RADIOTAP_H
#define IEEE80211RADIOTAP_H

#include <glib.h>

/* Base version of the radiotap packet header data */
#define PKTHDR_RADIOTAP_VERSION		0

/* A generic radio capture format is desirable. There is one for
 * Linux, but it is neither rigidly defined (there were not even
 * units given for some fields) nor easily extensible.
 *
 * I suggest the following extensible radio capture format. It is
 * based on a bitmap indicating which fields are present.
 *
 * I am trying to describe precisely what the application programmer
 * should expect in the following, and for that reason I tell the
 * units and origin of each measurement (where it applies), or else I
 * use sufficiently weaselly language ("is a monotonically nondecreasing
 * function of...") that I cannot set false expectations for lawyerly
 * readers.
 */

/* The radio capture header precedes the 802.11 header.
 * All data in the header is little endian on all platforms.
 */
struct ieee80211_radiotap_header {
	guint8 it_version;	/* Version 0. Only increases
				 * for drastic changes,
				 * introduction of compatible
				 * new fields does not count.
				 */
	guint8 it_pad;
	guint16 it_len;		/* length of the whole
				 * header in bytes, including
				 * it_version, it_pad,
				 * it_len, and data fields.
				 */
	guint32 it_present;	/* A bitmap telling which
				 * fields are present. Set bit 31
				 * (0x80000000) to extend the
				 * bitmap by another 32 bits.
				 * Additional extensions are made
				 * by setting bit 31.
				 */
};

/* Name                                 Data type    Units
 * ----                                 ---------    -----
 *
 * IEEE80211_RADIOTAP_TSFT              __le64       microseconds
 *
 *      Value in microseconds of the MAC's 64-bit 802.11 Time
 *      Synchronization Function timer when the first bit of the
 *      MPDU arrived at the MAC. For received frames, only.
 *
 * IEEE80211_RADIOTAP_CHANNEL           2 x guint16   MHz, bitmap
 *
 *      Tx/Rx frequency in MHz, followed by flags (see below).
 *
 * IEEE80211_RADIOTAP_FHSS              guint16       see below
 *
 *      For frequency-hopping radios, the hop set (first byte)
 *      and pattern (second byte).
 *
 * IEEE80211_RADIOTAP_RATE              u8           500kb/s
 *
 *      Tx/Rx data rate
 *
 * IEEE80211_RADIOTAP_DBM_ANTSIGNAL     s8           decibels from
 *                                                   one milliwatt (dBm)
 *
 *      RF signal power at the antenna, decibel difference from
 *      one milliwatt.
 *
 * IEEE80211_RADIOTAP_DBM_ANTNOISE      s8           decibels from
 *                                                   one milliwatt (dBm)
 *
 *      RF noise power at the antenna, decibel difference from one
 *      milliwatt.
 *
 * IEEE80211_RADIOTAP_DB_ANTSIGNAL      u8           decibel (dB)
 *
 *      RF signal power at the antenna, decibel difference from an
 *      arbitrary, fixed reference.
 *
 * IEEE80211_RADIOTAP_DB_ANTNOISE       u8           decibel (dB)
 *
 *      RF noise power at the antenna, decibel difference from an
 *      arbitrary, fixed reference point.
 *
 * IEEE80211_RADIOTAP_LOCK_QUALITY      guint16       unitless
 *
 *      Quality of Barker code lock. Unitless. Monotonically
 *      nondecreasing with "better" lock strength. Called "Signal
 *      Quality" in datasheets.  (Is there a standard way to measure
 *      this?)
 *
 * IEEE80211_RADIOTAP_TX_ATTENUATION    guint16       unitless
 *
 *      Transmit power expressed as unitless distance from max
 *      power set at factory calibration.  0 is max power.
 *      Monotonically nondecreasing with lower power levels.
 *
 * IEEE80211_RADIOTAP_DB_TX_ATTENUATION guint16       decibels (dB)
 *
 *      Transmit power expressed as decibel distance from max power
 *      set at factory calibration.  0 is max power.  Monotonically
 *      nondecreasing with lower power levels.
 *
 * IEEE80211_RADIOTAP_DBM_TX_POWER      s8           decibels from
 *                                                   one milliwatt (dBm)
 *
 *      Transmit power expressed as dBm (decibels from a 1 milliwatt
 *      reference). This is the absolute power level measured at
 *      the antenna port.
 *
 * IEEE80211_RADIOTAP_FLAGS             u8           bitmap
 *
 *      Properties of transmitted and received frames. See flags
 *      defined below.
 *
 * IEEE80211_RADIOTAP_ANTENNA           u8           antenna index
 *
 *      Unitless indication of the Rx/Tx antenna for this packet.
 *      The first antenna is antenna 0.
 *
 * IEEE80211_RADIOTAP_RX_FLAGS          guint16       bitmap
 *
 *     Properties of received frames. See flags defined below.
 *
 * IEEE80211_RADIOTAP_TX_FLAGS          guint16       bitmap
 *
 *     Properties of transmitted frames. See flags defined below.
 *
 * IEEE80211_RADIOTAP_RTS_RETRIES       u8           data
 *
 *     Number of rts retries a transmitted frame used.
 *
 * IEEE80211_RADIOTAP_DATA_RETRIES      u8           data
 *
 *     Number of unicast retries a transmitted frame used.
 *
 * IEEE80211_RADIOTAP_MCS	u8, u8, u8		unitless
 *
 *     Contains a bitmap of known fields/flags, the flags, and
 *     the MCS index.
 *
 * IEEE80211_RADIOTAP_AMPDU_STATUS	u32, u16, u8, u8	unitlesss
 *
 *	Contains the AMPDU information for the subframe.
 *
 * IEEE80211_RADIOTAP_HE		u16, u16, u16, u16, u16, u16 unitless
 *	Contains some information for HE frames.
 *
 * IEEE80211_RADIOTAP_HE_MU		U16, U16, u8[4] unitless
 *
 * IEEE80211_RADIOTAP_HE_MU_USER
 *
 * IEEE80211_RADIOTAP_0_LENGTH_PSDU
 *
 * IEEE80211_RADIOTAP_L_SIG
 *
 * IEEE80211_RADIOTAP_TLVS_PRESENT
 *
 * THERE ARE NO MORE BITS FREE! If you need a new radiotap header you must
 * ask for a TLV value. See www.radiotap.org.
 *
 */
enum ieee80211_radiotap_type {
	IEEE80211_RADIOTAP_TSFT = 0,
	IEEE80211_RADIOTAP_FLAGS = 1,
	IEEE80211_RADIOTAP_RATE = 2,
	IEEE80211_RADIOTAP_CHANNEL = 3,
	IEEE80211_RADIOTAP_FHSS = 4,
	IEEE80211_RADIOTAP_DBM_ANTSIGNAL = 5,
	IEEE80211_RADIOTAP_DBM_ANTNOISE = 6,
	IEEE80211_RADIOTAP_LOCK_QUALITY = 7,
	IEEE80211_RADIOTAP_TX_ATTENUATION = 8,
	IEEE80211_RADIOTAP_DB_TX_ATTENUATION = 9,
	IEEE80211_RADIOTAP_DBM_TX_POWER = 10,
	IEEE80211_RADIOTAP_ANTENNA = 11,
	IEEE80211_RADIOTAP_DB_ANTSIGNAL = 12,
	IEEE80211_RADIOTAP_DB_ANTNOISE = 13,
	IEEE80211_RADIOTAP_RX_FLAGS = 14,
	IEEE80211_RADIOTAP_TX_FLAGS = 15,
	IEEE80211_RADIOTAP_RTS_RETRIES = 16,
	IEEE80211_RADIOTAP_DATA_RETRIES = 17,
	IEEE80211_RADIOTAP_XCHANNEL = 18, /* Unofficial, used by FreeBSD */
	IEEE80211_RADIOTAP_MCS = 19,
	IEEE80211_RADIOTAP_AMPDU_STATUS = 20,
	IEEE80211_RADIOTAP_VHT = 21,
	IEEE80211_RADIOTAP_TIMESTAMP = 22,
	IEEE80211_RADIOTAP_HE = 23,
	IEEE80211_RADIOTAP_HE_MU = 24,
	IEEE80211_RAFIOTAP_HE_MU_USER = 25,
	IEEE80211_RADIOTAP_0_LENGTH_PSDU = 26,
	IEEE80211_RADIOTAP_L_SIG = 27,
	IEEE80211_RADIOTAP_TLVS = 28,

	/* valid in every it_present bitmap, even vendor namespaces */
	IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE = 29,
	IEEE80211_RADIOTAP_VENDOR_NAMESPACE = 30,
	IEEE80211_RADIOTAP_EXT = 31
};

struct ieee80211_radiotap_tlv {
	guint16 type;
	guint16 datalen;
	guint8 data[];
};

/* Channel flags. */
/* 0x00000001 through 0x00000008 undefined (reserved?) */
#define	IEEE80211_CHAN_TURBO	0x00000010 /* Turbo channel */
#define	IEEE80211_CHAN_CCK	0x00000020 /* CCK channel */
#define	IEEE80211_CHAN_OFDM	0x00000040 /* OFDM channel */
#define	IEEE80211_CHAN_2GHZ	0x00000080 /* 2 GHz spectrum channel. */
#define	IEEE80211_CHAN_5GHZ	0x00000100 /* 5 GHz spectrum channel */
#define	IEEE80211_CHAN_PASSIVE	0x00000200 /* Only passive scan allowed */
#define	IEEE80211_CHAN_DYN	0x00000400 /* Dynamic CCK-OFDM channel */
#define	IEEE80211_CHAN_GFSK	0x00000800 /* GFSK channel (FHSS PHY) */

/* Additional XChannel flags. */
#define	IEEE80211_CHAN_GSM	0x00001000 /* 900 MHz spectrum channel */
#define	IEEE80211_CHAN_STURBO	0x00002000 /* 11a static turbo channel only */
#define	IEEE80211_CHAN_HALF	0x00004000 /* Half rate channel */
#define	IEEE80211_CHAN_QUARTER	0x00008000 /* Quarter rate channel */
#define	IEEE80211_CHAN_HT20	0x00010000 /* HT 20 channel */
#define	IEEE80211_CHAN_HT40U	0x00020000 /* HT 40 channel w/ ext above */
#define	IEEE80211_CHAN_HT40D	0x00040000 /* HT 40 channel w/ ext below */

#define	IEEE80211_CHAN_HT40	(IEEE80211_CHAN_HT40U | IEEE80211_CHAN_HT40D)
#define	IEEE80211_CHAN_HT	(IEEE80211_CHAN_HT20 | IEEE80211_CHAN_HT40)

#define	IEEE80211_CHAN_ALL \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_GFSK | \
	 IEEE80211_CHAN_CCK | IEEE80211_CHAN_OFDM | IEEE80211_CHAN_DYN | \
	 IEEE80211_CHAN_HALF | IEEE80211_CHAN_QUARTER | \
	 IEEE80211_CHAN_HT)
#define	IEEE80211_CHAN_ALLTURBO \
	(IEEE80211_CHAN_ALL | IEEE80211_CHAN_TURBO | IEEE80211_CHAN_STURBO)

/* For IEEE80211_RADIOTAP_FLAGS */
#define	IEEE80211_RADIOTAP_F_CFP	0x01	/* sent/received
						 * during CFP
						 */
#define	IEEE80211_RADIOTAP_F_SHORTPRE	0x02	/* sent/received
						 * with short
						 * preamble
						 */
#define	IEEE80211_RADIOTAP_F_WEP	0x04	/* sent/received
						 * with WEP encryption
						 */
#define	IEEE80211_RADIOTAP_F_FRAG	0x08	/* sent/received
						 * with fragmentation
						 */
#define	IEEE80211_RADIOTAP_F_FCS	0x10	/* frame includes FCS */
#define	IEEE80211_RADIOTAP_F_DATAPAD	0x20	/* frame has padding between
						 * 802.11 header and payload
						 * (to 32-bit boundary)
						 */
#define IEEE80211_RADIOTAP_F_BADFCS	0x40	/* frame failed FCS check */

/* For IEEE80211_RADIOTAP_RX_FLAGS */
#define IEEE80211_RADIOTAP_F_RX_BADPLCP	0x0002 /* bad PLCP */

/* For IEEE80211_RADIOTAP_TX_FLAGS */
#define IEEE80211_RADIOTAP_F_TX_FAIL	0x0001	/* failed due to excessive
						 * retries */
#define IEEE80211_RADIOTAP_F_TX_CTS	0x0002	/* used cts 'protection' */
#define IEEE80211_RADIOTAP_F_TX_RTS	0x0004	/* used rts/cts handshake */
#define IEEE80211_RADIOTAP_F_TX_NOACK	0x0008	/* don't expect ACK */
#define IEEE80211_RADIOTAP_F_TX_NOSEQNO	0x0010	/* don't overwrite sequence
						 * number */
#define IEEE80211_RADIOTAP_F_TX_ORDER	0x0020	/* don't reorder injected
						 * frames relative to other
						 * frames with this flag */

/* For IEEE80211_RADIOTAP_MCS */
#define IEEE80211_RADIOTAP_MCS_HAVE_BW		0x01
#define IEEE80211_RADIOTAP_MCS_HAVE_MCS		0x02
#define IEEE80211_RADIOTAP_MCS_HAVE_GI		0x04
#define IEEE80211_RADIOTAP_MCS_HAVE_FMT		0x08
#define IEEE80211_RADIOTAP_MCS_HAVE_FEC		0x10
#define IEEE80211_RADIOTAP_MCS_HAVE_STBC	0x20
#define IEEE80211_RADIOTAP_MCS_HAVE_NESS	0x40
#define IEEE80211_RADIOTAP_MCS_NESS_BIT1	0x80

#define IEEE80211_RADIOTAP_MCS_BW_MASK		0x03
#define		IEEE80211_RADIOTAP_MCS_BW_20	0
#define		IEEE80211_RADIOTAP_MCS_BW_40	1
#define		IEEE80211_RADIOTAP_MCS_BW_20L	2
#define		IEEE80211_RADIOTAP_MCS_BW_20U	3
#define IEEE80211_RADIOTAP_MCS_SGI		0x04
#define IEEE80211_RADIOTAP_MCS_FMT_GF		0x08
#define IEEE80211_RADIOTAP_MCS_FEC_LDPC		0x10
#define IEEE80211_RADIOTAP_MCS_STBC_MASK	0x60
#define IEEE80211_RADIOTAP_MCS_STBC_SHIFT	5
#define		IEEE80211_RADIOTAP_MCS_STBC_1	1
#define		IEEE80211_RADIOTAP_MCS_STBC_2	2
#define		IEEE80211_RADIOTAP_MCS_STBC_3	3
#define IEEE80211_RADIOTAP_MCS_NESS_BIT0	0x80

/* For IEEE80211_RADIOTAP_AMPDU_STATUS */
#define IEEE80211_RADIOTAP_AMPDU_REPORT_ZEROLEN		0x0001
#define IEEE80211_RADIOTAP_AMPDU_IS_ZEROLEN		0x0002
#define IEEE80211_RADIOTAP_AMPDU_LAST_KNOWN		0x0004
#define IEEE80211_RADIOTAP_AMPDU_IS_LAST		0x0008
#define IEEE80211_RADIOTAP_AMPDU_DELIM_CRC_ERR		0x0010
#define IEEE80211_RADIOTAP_AMPDU_DELIM_CRC_KNOWN	0x0020
#define IEEE80211_RADIOTAP_AMPDU_EOF			0x0040
#define IEEE80211_RADIOTAP_AMPDU_EOF_KNOWN		0x0080

/* For IEEE80211_RADIOTAP_VHT */
#define IEEE80211_RADIOTAP_VHT_HAVE_STBC	0x0001
#define IEEE80211_RADIOTAP_VHT_HAVE_TXOP_PS	0x0002
#define IEEE80211_RADIOTAP_VHT_HAVE_GI		0x0004
#define IEEE80211_RADIOTAP_VHT_HAVE_SGI_NSYM_DA	0x0008
#define IEEE80211_RADIOTAP_VHT_HAVE_LDPC_EXTRA	0x0010
#define IEEE80211_RADIOTAP_VHT_HAVE_BF		0x0020
#define IEEE80211_RADIOTAP_VHT_HAVE_BW		0x0040
#define IEEE80211_RADIOTAP_VHT_HAVE_GID		0x0080
#define IEEE80211_RADIOTAP_VHT_HAVE_PAID	0x0100
#define IEEE80211_RADIOTAP_VHT_STBC		0x01
#define IEEE80211_RADIOTAP_VHT_TXOP_PS		0x02
#define IEEE80211_RADIOTAP_VHT_SGI		0x04
#define IEEE80211_RADIOTAP_VHT_SGI_NSYM_DA	0x08
#define IEEE80211_RADIOTAP_VHT_LDPC_EXTRA	0x10
#define IEEE80211_RADIOTAP_VHT_BF		0x20
#define IEEE80211_RADIOTAP_VHT_NSS		0x0f
#define IEEE80211_RADIOTAP_VHT_MCS		0xf0
#define IEEE80211_RADIOTAP_VHT_CODING_LDPC	0x01

#define IEEE80211_RADIOTAP_VHT_BW_MASK		0x1f
#define IEEE80211_RADIOTAP_VHT_BW_20		IEEE80211_RADIOTAP_MCS_BW_20
#define IEEE80211_RADIOTAP_VHT_BW_40		IEEE80211_RADIOTAP_MCS_BW_40
#define IEEE80211_RADIOTAP_VHT_BW_20L		IEEE80211_RADIOTAP_MCS_BW_20L
#define IEEE80211_RADIOTAP_VHT_BW_20U		IEEE80211_RADIOTAP_MCS_BW_20U
#define IEEE80211_RADIOTAP_VHT_BW_80		4
#define IEEE80211_RADIOTAP_VHT_BW_40L		5
#define IEEE80211_RADIOTAP_VHT_BW_40U		6
#define IEEE80211_RADIOTAP_VHT_BW_20LL		7
#define IEEE80211_RADIOTAP_VHT_BW_20LU		8
#define IEEE80211_RADIOTAP_VHT_BW_20UL		9
#define IEEE80211_RADIOTAP_VHT_BW_20UU		10
#define IEEE80211_RADIOTAP_VHT_BW_160		11
#define IEEE80211_RADIOTAP_VHT_BW_80L		12
#define IEEE80211_RADIOTAP_VHT_BW_80U		13
#define IEEE80211_RADIOTAP_VHT_BW_40LL		14
#define IEEE80211_RADIOTAP_VHT_BW_40LU		15
#define IEEE80211_RADIOTAP_VHT_BW_40UL		16
#define IEEE80211_RADIOTAP_VHT_BW_40UU		17
#define IEEE80211_RADIOTAP_VHT_BW_20LLL		18
#define IEEE80211_RADIOTAP_VHT_BW_20LLU		19
#define IEEE80211_RADIOTAP_VHT_BW_20LUL		20
#define IEEE80211_RADIOTAP_VHT_BW_20LUU		21
#define IEEE80211_RADIOTAP_VHT_BW_20ULL		22
#define IEEE80211_RADIOTAP_VHT_BW_20ULU		23
#define IEEE80211_RADIOTAP_VHT_BW_20UUL		24
#define IEEE80211_RADIOTAP_VHT_BW_20UUU		25

/* for IEEE80211_RADIOTAP_TIMESTAMP */
#define IEEE80211_RADIOTAP_TS_UNIT_MASK		0x0F
#define IEEE80211_RADIOTAP_TS_UNIT_MSEC		0x00
#define IEEE80211_RADIOTAP_TS_UNIT_USEC		0x01
#define IEEE80211_RADIOTAP_TS_UNIT_NSEC		0x02
#define IEEE80211_RADIOTAP_TS_SPOS_MASK		0xF0
#define IEEE80211_RADIOTAP_TS_SPOS_SHIFT	4
#define IEEE80211_RADIOTAP_TS_SPOS_MPDU		0x0
#define IEEE80211_RADIOTAP_TS_SPOS_ACQ		0x1
#define IEEE80211_RADIOTAP_TS_SPOS_EOF		0x2
#define IEEE80211_RADIOTAP_TS_SPOS_UNDEF	0xF

/* for IEEE80211_RADIOTAP_HE */
#define IEEE80211_RADIOTAP_HE_PPDU_FORMAT_MASK			0x0003
#define IEEE80211_RADIOTAP_HE_PPDU_FORMAT_HE_SU			0
#define IEEE80211_RADIOTAP_HE_PPDU_FORMAT_HE_EXT_SU		1
#define IEEE80211_RADIOTAP_HE_PPDU_FORMAT_HE_MU			2
#define IEEE80211_RADIOTAP_HE_PPDU_FORMAT_HE_TRIG		3
#define IEEE80211_RADIOTAP_HE_BSS_COLOR_KNOWN			0x0004
#define IEEE80211_RADIOTAP_HE_BEAM_CHANGE_KNOWN			0x0008
#define IEEE80211_RADIOTAP_HE_UL_DL_KNOWN			0x0010
#define IEEE80211_RADIOTAP_HE_DATA_MCS_KNOWN			0x0020
#define IEEE80211_RADIOTAP_HE_DATA_DCM_KNOWN			0x0040
#define IEEE80211_RADIOTAP_HE_CODING_KNOWN			0x0080
#define IEEE80211_RADIOTAP_HE_LDPC_EXTRA_SYMBOL_SEGMENT_KNOWN	0x0100
#define IEEE80211_RADIOTAP_HE_STBC_KNOWN			0x0200
#define IEEE80211_RADIOTAP_HE_SPATIAL_REUSE_KNOWN		0x0400
#define IEEE80211_RADIOTAP_HE_SPATIAL_REUSE_2_KNOWN		0x0800
#define IEEE80211_RADIOTAP_HE_SPATIAL_REUSE_3_KNOWN		0x1000
#define IEEE80211_RADIOTAP_HE_SPATIAL_REUSE_4_KNOWN		0x2000
#define IEEE80211_RADIOTAP_HE_DATA_BW_RU_ALLOCATION_KNOWN	0x4000
#define IEEE80211_RADIOTAP_HE_DOPPLER_KNOWN			0x8000
#define IEEE80211_RADIOTAP_HE_PRI_SEC_80_MHZ_KNOWN		0x0001
#define IEEE80211_RADIOTAP_HE_GI_KNOWN				0x0002
#define IEEE80211_RADIOTAP_HE_NUM_LTF_SYMBOLS_KNOWN		0x0004
#define IEEE80211_RADIOTAP_HE_PRE_FEC_PADDING_FACTOR_KNOWN	0x0008
#define IEEE80211_RADIOTAP_HE_TXBF_KNOWN			0x0010
#define IEEE80211_RADIOTAP_HE_PE_DISAMBIGUITY_KNOWN		0x0020
#define IEEE80211_RADIOTAP_HE_TXOP_KNOWN			0x0040
#define IEEE80211_RADIOTAP_HE_MIDAMBLE_PERIODICITY_KNOWN	0x0080
#define IEEE80211_RADIOTAP_HE_RU_ALLOCATION_OFFSET		0x3F00
#define IEEE80211_RADIOTAP_HE_RU_ALLOCATION_OFFSET_KNOWN	0x4000
#define IEEE80211_RADIOTAP_HE_PRI_SEC_80_MHZ			0x8000
#define IEEE80211_RADIOTAP_HE_BSS_COLOR_MASK			0x003F
#define IEEE80211_RADIOTAP_HE_BEAM_CHANGE			0x0040
#define IEEE80211_RADIOTAP_HE_UL_DL				0x0080
#define IEEE80211_RADIOTAP_HE_DATA_MCS_MASK			0x0F00
#define IEEE80211_RADIOTAP_HE_DATA_DCM				0x1000
#define IEEE80211_RADIOTAP_HE_CODING				0x2000
#define IEEE80211_RADIOTAP_HE_LDPC_EXTRA_SYMBOL_SEGMENT		0x4000
#define IEEE80211_RADIOTAP_HE_STBC				0x8000
/* HE_SU and HE_EXT_SU formap PPDU */
#define IEEE80211_RADIOTAP_HE_SPATIAL_REUSE_MASK		0x000F
#define IEEE80211_RADIOTAP_HE_D4_FFF0				0xFFF0
/* HE_TRIG format PPDU */
#define IEEE80211_RADIOTAP_HE_SPATIAL_REUSE_1_MASK		0X000F
#define IEEE80211_RADIOTAP_HE_SPATIAL_REUSE_2_MASK		0X00F0
#define IEEE80211_RADIOTAP_HE_SPATIAL_REUSE_3_MASK		0X0F00
#define IEEE80211_RADIOTAP_HE_SPATIAL_REUSE_4_MASK		0XF000
/* HE_MU format PPDU-also uses SPATIAL_REUSE_MASK from above */
#define IEEE80211_RADIOTAP_HE_STA_ID_MASK			0x7FF0
#define IEEE80211_RADIOTAP_HE_RESERVED_D4_B15			0x8000

#define IEEE80211_RADIOTAP_HE_DATA_BANDWIDTH_RU_ALLOC_MASK	0x000F
#define IEEE80211_RADIOTAP_HE_GI_MASK				0x0030
#define IEEE80211_RADIOTAP_HE_GI_0_POINT_8_MICRO		0
#define IEEE80211_RADIOTAP_HE_GI_1_POINT_6_MICRO		1
#define IEEE80211_RADIOTAP_HE_GI_3_POINT_2_MICRO		2
#define IEEE80211_RADIOTAP_HE_GI_RESERVED			3
#define IEEE80211_RADIOTAP_HE_LTF_SYMBOL_SIZE			0x00C0
#define IEEE80211_RADIOTAP_HE_NUM_LTF_SYMBOLS_MASK		0x0700
#define IEEE80211_RADIOTAP_HE_RESERVED_D5_B11			0x0800
#define IEEE80211_RADIOTAP_HE_PRE_FEC_PADDING_FACTOR_MASK	0x3000
#define IEEE80211_RADIOTAP_HE_TXBF				0x4000
#define IEEE80211_RADIOTAP_HE_PE_DISAMBIGUITY			0x8000
#define IEEE80211_RADIOTAP_HE_NSTS_MASK				0x000F
#define IEEE80211_RADIOTAP_HE_DOPLER_VALUE			0x0010
#define IEEE80211_RADIOTAP_HE_RESERVED_D6_00E0			0x00E0
#define IEEE80211_RADIOTAP_HE_TXOP_VALUE_MASK			0x7F00
#define IEEE80211_RADIOTAP_HE_MIDAMBLE_PERIODICITY		0x8000

/* For IEEE80211_RADIOTAP_HE_MU */
#define IEEE80211_RADIOTAP_HE_MU_SIG_B_MCS_MASK				0x000F
#define IEEE80211_RADIOTAP_HE_MU_SIG_B_MCS_KNOWN			0x0010
#define IEEE80211_RADIOTAP_HE_MU_SIG_B_DCM				0x0020
#define IEEE80211_RADIOTAP_HE_MU_SIG_B_DCM_KNOWN			0x0040
#define IEEE80211_RADIOTAP_HE_MU_CHAN2_CENTER_26_TONE_RU_BIT_KNOWN	0x0080
#define IEEE80211_RADIOTAP_HE_MU_CHAN1_RUS_KNOWN			0x0100
#define IEEE80211_RADIOTAP_HE_MU_CHAN2_RUS_KNOWN			0x0200
#define IEEE80211_RADIOTAP_HE_MU_RESERVED_F1_B10_B11			0x0C00
#define IEEE80211_RADIOTAP_HE_MU_CHAN1_CENTER_26_TONE_RU_BIT_KNOWN	0x1000
#define IEEE80211_RADIOTAP_HE_MU_CHAN1_CENTER_26_TONE_RU_VALUE		0x2000
#define IEEE80211_RADIOTAP_HE_MU_SIG_B_COMPRESSION_KNOWN		0x4000
#define IEEE80211_RADIOTAP_HE_MU_SYMBOL_CNT_OR_USER_CNT_KNOWN		0x8000
#define IEEE80211_RADIOTAP_HE_MU_BW_FROM_BW_IN_SIG_A_MASK		0x0003
#define IEEE80211_RADIOTAP_HE_MU_BW_FROM_BW_IN_SIG_A_KNOWN		0x0004
#define IEEE80211_RADIOTAP_HE_MU_SIG_B_COMPRESSION_FROM_SIG_A		0x0008
#define IEEE80211_RADIOTAP_HE_MU_SYMBOL_CNT_OR_USER_CNT			0x00F0
#define IEEE80211_RADIOTAP_HE_MU_PREAMBLE_PUNCTURING_MASK		0x0300
#define IEEE80211_RADIOTAP_HE_MU_PREAMBLE_PUNCTURING_KNOWN		0x0400
#define IEEE80211_RADIOTAP_HE_MU_CHAN2_CENTER_26_TONE_RU_VALUE		0x0800
#define IEEE80211_RADIOTAP_HE_MU_RESERVED_F2_B12_B15			0xF000

/* For IEEE80211_RADIOTAP_L_SIG */
#define IEEE80211_RADIOTAP_L_SIG_RATE_KNOWN			0x0001
#define IEEE80211_RADIOTAP_L_SIG_LENGTH_KNOWN			0x0002
#define IEEE80211_RADIOTAP_L_SIG_RESERVED_MASK			0xFFFC
#define IEEE80211_RADIOTAP_L_SIG_RATE_MASK			0x000F
#define IEEE80211_RADIOTAP_L_SIG_LENGTH_MASK			0xFFF0

#define IEEE80211_RADIOTAP_TS_FLG_32BIT		0x01
#define IEEE80211_RADIOTAP_TS_FLG_ACCURACY	0x02

#endif				/* IEEE80211_RADIOTAP_H */
