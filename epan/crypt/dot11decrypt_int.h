/* airpcap_int.h
 *
 * Copyright (c) 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
 */

#ifndef	_DOT11DECRYPT_INT_H
#define	_DOT11DECRYPT_INT_H

/****************************************************************************/
/*	File includes								*/

#include "dot11decrypt_interop.h"
#include "dot11decrypt_system.h"

#include "ws_attributes.h"
#include <wsutil/wsgcrypt.h>

/****************************************************************************/

/****************************************************************************/
/* Definitions									*/

/* IEEE 802.11 packet type values						*/
#define	DOT11DECRYPT_TYPE_MANAGEMENT		0
#define	DOT11DECRYPT_TYPE_CONTROL			1
#define	DOT11DECRYPT_TYPE_DATA			2

/* IEEE 802.11 packet subtype values						*/
#define DOT11DECRYPT_SUBTYPE_ASSOC_REQ		0
#define DOT11DECRYPT_SUBTYPE_ASSOC_RESP		1
#define DOT11DECRYPT_SUBTYPE_REASSOC_REQ		2
#define DOT11DECRYPT_SUBTYPE_REASSOC_RESP		3
#define DOT11DECRYPT_SUBTYPE_PROBE_REQ		4
#define DOT11DECRYPT_SUBTYPE_PROBE_RESP		5
#define DOT11DECRYPT_SUBTYPE_MEASUREMENT_PILOT	6
#define DOT11DECRYPT_SUBTYPE_BEACON			8
#define DOT11DECRYPT_SUBTYPE_ATIM			9
#define DOT11DECRYPT_SUBTYPE_DISASS			10
#define DOT11DECRYPT_SUBTYPE_AUTHENTICATION		11
#define DOT11DECRYPT_SUBTYPE_DEAUTHENTICATION	12
#define DOT11DECRYPT_SUBTYPE_ACTION			13
#define DOT11DECRYPT_SUBTYPE_ACTION_NO_ACK		14

/*
 * Min length of encrypted data (TKIP=21bytes, CCMP=17bytes)
 * CCMP = 8 octets of CCMP header, 1 octet of data, 8 octets of MIC.
 * TKIP = 4 octets of IV/Key ID, 4 octets of Extended IV, 1 octet of data,
 *  8 octets of MIC, 4 octets of ICV
 */
#define	DOT11DECRYPT_CRYPTED_DATA_MINLEN	17

#define DOT11DECRYPT_TA_OFFSET	10

/*										*/
/****************************************************************************/

/****************************************************************************/
/* Macro definitions								*/

/**
 * Macros to get various bits of a 802.11 control frame
 */
#define	DOT11DECRYPT_TYPE(FrameControl_0)		(UINT8)((FrameControl_0 >> 2) & 0x3)
#define	DOT11DECRYPT_SUBTYPE(FrameControl_0)	(UINT8)((FrameControl_0 >> 4) & 0xF)
#define	DOT11DECRYPT_DS_BITS(FrameControl_1)	(UINT8)(FrameControl_1 & 0x3)
#define	DOT11DECRYPT_TO_DS(FrameControl_1)		(UINT8)(FrameControl_1 & 0x1)
#define	DOT11DECRYPT_FROM_DS(FrameControl_1)	(UINT8)((FrameControl_1 >> 1) & 0x1)
#define	DOT11DECRYPT_WEP(FrameControl_1)		(UINT8)((FrameControl_1 >> 6) & 0x1)

/**
 * Get the Key ID from the Initialization Vector (last byte)
 */
#define	DOT11DECRYPT_EXTIV(KeyID)	((KeyID >> 5) & 0x1)

#define	DOT11DECRYPT_KEY_INDEX(KeyID)	((KeyID >> 6) & 0x3)  /** Used to determine TKIP group key from unicast (group = 1, unicast = 0) */

/* Macros to get various bits of an EAPOL frame				*/
#define	DOT11DECRYPT_EAP_KEY_DESCR_VER(KeyInfo_1)	((UCHAR)(KeyInfo_1 & 0x3))
#define	DOT11DECRYPT_EAP_KEY(KeyInfo_1)		((KeyInfo_1 >> 3) & 0x1)
#define	DOT11DECRYPT_EAP_INST(KeyInfo_1)		((KeyInfo_1 >> 6) & 0x1)
#define	DOT11DECRYPT_EAP_ACK(KeyInfo_1)		((KeyInfo_1 >> 7) & 0x1)
#define	DOT11DECRYPT_EAP_MIC(KeyInfo_0)		(KeyInfo_0 & 0x1)
#define	DOT11DECRYPT_EAP_SEC(KeyInfo_0)		((KeyInfo_0 >> 1) & 0x1)

/* Note: copied from net80211/ieee80211.h					*/
#define DOT11DECRYPT_FC1_DIR_MASK                  0x03
#define DOT11DECRYPT_FC1_DIR_DSTODS                0x03    /* AP ->AP  */
#define DOT11DECRYPT_FC0_SUBTYPE_QOS               0x80
#define DOT11DECRYPT_FC0_TYPE_DATA                 0x08
#define DOT11DECRYPT_FC0_TYPE_MASK                 0x0c
#define DOT11DECRYPT_SEQ_FRAG_MASK                 0x000f
#define DOT11DECRYPT_QOS_HAS_SEQ(wh) \
	(((wh)->fc[0] & \
	(DOT11DECRYPT_FC0_TYPE_MASK | DOT11DECRYPT_FC0_SUBTYPE_QOS)) == \
	(DOT11DECRYPT_FC0_TYPE_DATA | DOT11DECRYPT_FC0_SUBTYPE_QOS))

#define DOT11DECRYPT_ADDR_COPY(dst,src) memcpy(dst, src, DOT11DECRYPT_MAC_LEN)

#define DOT11DECRYPT_IS_4ADDRESS(wh) \
	((wh->fc[1] & DOT11DECRYPT_FC1_DIR_MASK) == DOT11DECRYPT_FC1_DIR_DSTODS)
#define DOT11DECRYPT_IS_QOS_DATA(wh) DOT11DECRYPT_QOS_HAS_SEQ(wh)

/****************************************************************************/

/****************************************************************************/
/* Structure definitions							*/

/*
 * XXX - According to the thread at
 * https://www.wireshark.org/lists/wireshark-dev/200612/msg00384.html we
 * shouldn't have to worry about packing our structs, since the largest
 * elements are 8 bits wide.
 */
#ifdef _MSC_VER		/* MS Visual C++ */
#pragma pack(push)
#pragma pack(1)
#endif

/* Definition of IEEE 802.11 frame (without the address 4)			*/
typedef struct _DOT11DECRYPT_MAC_FRAME {
	UCHAR	fc[2];
	UCHAR	dur[2];
	UCHAR	addr1[DOT11DECRYPT_MAC_LEN];
	UCHAR	addr2[DOT11DECRYPT_MAC_LEN];
	UCHAR	addr3[DOT11DECRYPT_MAC_LEN];
	UCHAR	seq[2];
} DOT11DECRYPT_MAC_FRAME, *PDOT11DECRYPT_MAC_FRAME;

/* Definition of IEEE 802.11 frame (with the address 4)			*/
typedef struct _DOT11DECRYPT_MAC_FRAME_ADDR4 {
	UCHAR	fc[2];
	UCHAR	dur[2];
	UCHAR	addr1[DOT11DECRYPT_MAC_LEN];
	UCHAR	addr2[DOT11DECRYPT_MAC_LEN];
	UCHAR	addr3[DOT11DECRYPT_MAC_LEN];
	UCHAR	seq[2];
	UCHAR	addr4[DOT11DECRYPT_MAC_LEN];
} DOT11DECRYPT_MAC_FRAME_ADDR4, *PDOT11DECRYPT_MAC_FRAME_ADDR4;

/* Definition of IEEE 802.11 frame (without the address 4, with QOS)		*/
typedef struct _DOT11DECRYPT_MAC_FRAME_QOS {
	UCHAR	fc[2];
	UCHAR	dur[2];
	UCHAR	addr1[DOT11DECRYPT_MAC_LEN];
	UCHAR	addr2[DOT11DECRYPT_MAC_LEN];
	UCHAR	addr3[DOT11DECRYPT_MAC_LEN];
	UCHAR	seq[2];
	UCHAR	qos[2];
} DOT11DECRYPT_MAC_FRAME_QOS, *PDOT11DECRYPT_MAC_FRAME_QOS;

/* Definition of IEEE 802.11 frame (with the address 4 and QOS)		*/
typedef struct _DOT11DECRYPT_MAC_FRAME_ADDR4_QOS {
	UCHAR	fc[2];
	UCHAR	dur[2];
	UCHAR	addr1[DOT11DECRYPT_MAC_LEN];
	UCHAR	addr2[DOT11DECRYPT_MAC_LEN];
	UCHAR	addr3[DOT11DECRYPT_MAC_LEN];
	UCHAR	seq[2];
	UCHAR	addr4[DOT11DECRYPT_MAC_LEN];
	UCHAR	qos[2];
} DOT11DECRYPT_MAC_FRAME_ADDR4_QOS, *PDOT11DECRYPT_MAC_FRAME_ADDR4_QOS;

#ifdef _MSC_VER		/* MS Visual C++ */
#pragma pack(pop)
#endif

/******************************************************************************/

int Dot11DecryptCcmpDecrypt(
	guint8 *m,
	int mac_header_len,
	int len,
	guint8 *TK1,
	int tk_len,
	int mic_len);

#if GCRYPT_VERSION_NUMBER >= 0x010600 /* 1.6.0 */
int Dot11DecryptGcmpDecrypt(
	guint8 *m,
	int mac_header_len,
	int len,
	guint8 *TK1,
	int tk_len);
#else
static inline int Dot11DecryptGcmpDecrypt(
	guint8 *m _U_,
	int mac_header_len _U_,
	int len _U_,
	guint8 *TK1 _U_,
	int tk_len _U_)
{
	return 1;
}
#endif

INT Dot11DecryptTkipDecrypt(
	UCHAR *tkip_mpdu,
	size_t mpdu_len,
	UCHAR TA[DOT11DECRYPT_MAC_LEN],
	UCHAR TK[DOT11DECRYPT_TK_LEN])
	;

#endif
