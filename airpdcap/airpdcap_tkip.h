#ifndef	_AIRPDCAP_TKIP_H
#define	_AIRPDCAP_TKIP_H

/******************************************************************************/
/*	File includes																					*/
/*																										*/
#include "airpdcap_interop.h"
/*																										*/
/*																										*/
/******************************************************************************/

#define AIRPDCAP_TK_LEN	16

/******************************************************************************/
/*	External function prototypes declarations												*/
/*																										*/
/* Note: copied and modified from net80211/ieee80211_airpdcap_tkip.c				*/
INT AirPDcapTkipDecrypt(
							 UCHAR *tkip_mpdu,
							 size_t mpdu_len,
							 UCHAR TA[AIRPDCAP_MAC_LEN],
							 UCHAR TK[AIRPDCAP_TK_LEN])
								  ;
/*																										*/
/******************************************************************************/

#endif