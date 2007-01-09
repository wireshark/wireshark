#ifndef	_AIRPDCAP_SHA1
#define	_AIRPDCAP_SHA1

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
/* Maximum HMAC block length																	*/
#define HMAC_MAX_BLOCK_LEN	SHA2_512_HMAC_BLOCK_LEN
#define HMAC_IPAD_VAL	0x36
#define HMAC_OPAD_VAL	0x5C
/*																										*/
/******************************************************************************/

typedef /******************************************************************************/
/*	Type definitions																				*/
/*																										*/
/* Note: copied from FreeBSD source code, RELENG 6, sys/crypto/sha1.h, 41		*/
struct _SHA1_CONTEXT {
	union {
		UCHAR b8[20];
		UINT b32[5];
	} h;
	union {
		UCHAR b8[8];
		ULONGLONG b64[1];
	} c;
	union {
		UCHAR b8[64];
		UINT b32[16];
	} m;
	size_t count;
} SHA1_CONTEXT;
/*																										*/
/******************************************************************************/

/******************************************************************************/
/*	External function prototypes declarations												*/
/*																										*/
/*																										*/
/******************************************************************************/
void sha1_init(SHA1_CONTEXT *ctxt);
void sha1_result(SHA1_CONTEXT *ctxt, UCHAR *digest0);
void sha1_loop(SHA1_CONTEXT *ctxt, const UCHAR *input, size_t len);

#endif
