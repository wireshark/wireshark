#ifndef	_AIRPDCAP_INT_H
#define	_AIRPDCAP_INT_H

/****************************************************************************/
/*	File includes								*/

#include "airpdcap_interop.h"

/****************************************************************************/

/****************************************************************************/
/* Definitions									*/

/* IEEE 802.11 packet type values						*/
#define	AIRPDCAP_TYPE_MANAGEMENT		0
#define	AIRPDCAP_TYPE_CONTROL			1
#define	AIRPDCAP_TYPE_DATA			2

/* Min length of encrypted data (TKIP=25bytes, CCMP=21bytes)			*/
#define	AIRPDCAP_CRYPTED_DATA_MINLEN	21

#define AIRPDCAP_TA_OFFSET	10

/*										*/
/****************************************************************************/

/****************************************************************************/
/* Macro definitions								*/

/**
 * Macro to get MAC header length (if ToDS and FromDS are set, address 4
 * is present).
 */
#define	AIRPDCAP_HEADER_LEN(FrameControl_1) \
	(UINT8)((FrameControl_1 & 0x3)==3 ? 30 : 24)

/**
 * Macros to get various bits of a 802.11 control frame
 */
#define	AIRPDCAP_TYPE(FrameControl_0)		(UINT8)((FrameControl_0 >> 2) & 0x3)
#define	AIRPDCAP_SUBTYPE(FrameControl_0)	(UINT8)((FrameControl_0 >> 4) & 0xF)
#define	AIRPDCAP_TO_DS(FrameControl_1)		(UINT8)(FrameControl_1 & 0x1)
#define	AIRPDCAP_FROM_DS(FrameControl_1)	(UINT8)((FrameControl_1 >> 1) & 0x1)
#define	AIRPDCAP_WEP(FrameControl_1)		(UINT8)((FrameControl_1 >> 6) & 0x1)

/**
 * Get the Key ID from the Initialization Vector (last byte)
 */
#define	AIRPDCAP_EXTIV(KeyID)	((KeyID >> 5) & 0x1)

/* Macros to get various bits of an EAPOL frame				*/
#define	AIRPDCAP_EAP_KEY_DESCR_VER(KeyInfo_1)	((UCHAR)(KeyInfo_1 & 0x3))
#define	AIRPDCAP_EAP_KEY(KeyInfo_1)		((KeyInfo_1 >> 3) & 0x1)
#define	AIRPDCAP_EAP_INST(KeyInfo_1)		((KeyInfo_1 >> 6) & 0x1)
#define	AIRPDCAP_EAP_ACK(KeyInfo_1)		((KeyInfo_1 >> 7) & 0x1)
#define	AIRPDCAP_EAP_MIC(KeyInfo_0)		(KeyInfo_0 & 0x1)
#define	AIRPDCAP_EAP_SEC(KeyInfo_0)		((KeyInfo_0 >> 1) & 0x1)

/* Note: copied from net80211/ieee80211_airpdcap_tkip.c			*/
#define S_SWAP(a,b) { UINT8 t = S[a]; S[a] = S[b]; S[b] = t; }

/****************************************************************************/

/****************************************************************************/
/* Structure definitions							*/

/*
 * XXX - According to the thread at
 * http://www.wireshark.org/lists/wireshark-dev/200612/msg00384.html we
 * shouldn't have to worry about packing our structs, since the largest
 * elements are 8 bits wide.
 */
#ifdef _MSC_VER		/* MS Visual C++ */
#pragma pack(push)
#pragma pack(1)
#endif

/* Definition of IEEE 802.11 frame (without the address 4)			*/
typedef struct _AIRPDCAP_MAC_FRAME {
	UCHAR	fc[2];
	UCHAR	dur[2];
	UCHAR	addr1[AIRPDCAP_MAC_LEN];
	UCHAR	addr2[AIRPDCAP_MAC_LEN];
	UCHAR	addr3[AIRPDCAP_MAC_LEN];
	UCHAR	seq[2];
} AIRPDCAP_MAC_FRAME, *PAIRPDCAP_MAC_FRAME;

/* Definition of IEEE 802.11 frame (with the address 4)			*/
typedef struct _AIRPDCAP_MAC_FRAME_ADDR4 {
	UCHAR	fc[2];
	UCHAR	dur[2];
	UCHAR	addr1[AIRPDCAP_MAC_LEN];
	UCHAR	addr2[AIRPDCAP_MAC_LEN];
	UCHAR	addr3[AIRPDCAP_MAC_LEN];
	UCHAR	seq[2];
	UCHAR	addr4[AIRPDCAP_MAC_LEN];
} AIRPDCAP_MAC_FRAME_ADDR4, *PAIRPDCAP_MAC_FRAME_ADDR4;

/* Definition of IEEE 802.11 frame (without the address 4, with QOS)		*/
typedef struct _AIRPDCAP_MAC_FRAME_QOS {
	UCHAR	fc[2];
	UCHAR	dur[2];
	UCHAR	addr1[AIRPDCAP_MAC_LEN];
	UCHAR	addr2[AIRPDCAP_MAC_LEN];
	UCHAR	addr3[AIRPDCAP_MAC_LEN];
	UCHAR	seq[2];
	UCHAR	qos[2];
} AIRPDCAP_MAC_FRAME_QOS, *PAIRPDCAP_MAC_FRAME_QOS;

/* Definition of IEEE 802.11 frame (with the address 4 and QOS)		*/
typedef struct _AIRPDCAP_MAC_FRAME_ADDR4_QOS {
	UCHAR	fc[2];
	UCHAR	dur[2];
	UCHAR	addr1[AIRPDCAP_MAC_LEN];
	UCHAR	addr2[AIRPDCAP_MAC_LEN];
	UCHAR	addr3[AIRPDCAP_MAC_LEN];
	UCHAR	seq[2];
	UCHAR	addr4[AIRPDCAP_MAC_LEN];
	UCHAR	qos[2];
} AIRPDCAP_MAC_FRAME_ADDR4_QOS, *PAIRPDCAP_MAC_FRAME_ADDR4_QOS;

#ifdef _MSC_VER		/* MS Visual C++ */
#pragma pack(pop)
#endif

/******************************************************************************/

#endif
