#ifndef	_AIRPDCAP_RIJNDAEL
#define	_AIRPDCAP_RIJNDAEL

/******************************************************************************/
/*	File includes																					*/
/*																										*/
#include "airpdcap_interop.h"
/*																										*/
/*																										*/
/******************************************************************************/

/******************************************************************************/
/*	Definitions																						*/
/*																										*/
/* Note: copied AirPDcap/rijndael/rijndael.h												*/
#define RIJNDAEL_MAXKC  (256/32)
#define RIJNDAEL_MAXKB  (256/8)
#define RIJNDAEL_MAXNR  14
/*																										*/
/******************************************************************************/

/******************************************************************************/
/*	Type definitions																				*/
/*																										*/
/* Note: copied AirPDcap/rijndael/rijndael.h												*/
typedef struct s_rijndael_ctx {
	INT     decrypt;
	INT     Nr;             /* key-length-dependent number of rounds */
	UINT32 ek[4 * (RIJNDAEL_MAXNR + 1)];  /* encrypt key schedule */
	UINT32 dk[4 * (RIJNDAEL_MAXNR + 1)];  /* decrypt key schedule */
} rijndael_ctx;
/*																										*/
/******************************************************************************/

/******************************************************************************/
/*	External function prototypes declarations												*/
/*																										*/
void rijndael_encrypt(
							 const rijndael_ctx *ctx,
							 const UCHAR *src,
							 UCHAR *dst)
							 ;


void rijndael_set_key(
					  rijndael_ctx *ctx,
					  const u_char *key,
					  INT bits)
					  ;
/*																										*/
/******************************************************************************/

/******************************************************************************/
/*	External function definition																*/
/*																										*/
static __inline void xor_block(
										 UINT8 *b,
										 const UINT8 *a,
										 size_t len)
{
	INT i;
	for (i = 0; i < (INT)len; i++)
		b[i] ^= a[i];
}
/*																										*/
/******************************************************************************/

#endif