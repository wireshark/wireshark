#ifndef	_AIRPDCAP_MD5
#define	_AIRPDCAP_MD5

/******************************************************************************/
/*	File includes																					*/
/*																										*/
#include "airpdcap_interop.h"
/*																										*/
/*																										*/
/******************************************************************************/

/******************************************************************************/
/*	External function prototypes declarations												*/
/*																										*/
void AirPDcapAlgHmacMd5(
				  UCHAR *key,	/* pointer to authentication key */
				  INT key_len,			/* length of authentication key */
				  const UCHAR *text,	/* pointer to data stream */
				  const INT text_len,			/* length of data stream */
				  UCHAR *digest)		/* caller digest to be filled in */
				  ;
/*																										*/
/******************************************************************************/

#endif