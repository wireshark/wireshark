/******************************************************************************/
/*	File includes																					*/
/*																										*/
#include "airpdcap_sha1.h"

#include	"airpdcap_debug.h"
/*																										*/
/******************************************************************************/

/******************************************************************************/
/*	Internal definitions																			*/
/*																										*/
/* Definition used in HMAC-SHA1 algorithm													*/
/* Note: copied from FreeBSD source code, RELENG 6, sys/opencrypto/cryptodev.h*/
#define HMAC_IPAD_VAL				0x36
#define HMAC_OPAD_VAL				0x5C

/* HMAC values																						*/
#define SHA1_HMAC_BLOCK_LEN		(64/8)
#define SHA2_512_HMAC_BLOCK_LEN	(128/8)

/* Maximum HMAC block length																	*/
#define HMAC_MAX_BLOCK_LEN			SHA2_512_HMAC_BLOCK_LEN
/*																										*/
/******************************************************************************/

/******************************************************************************/
/*	Type definitions																				*/
/*																										*/
/* Note: copied from FreeBSD source code, RELENG 6, sys/crypto/sha1.h, 41		*/
typedef struct _SHA1_CONTEXT {
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
/*	Internal macros																				*/
/*																										*/
/* Shortcuts used in HMAC-SHA1																*/
/* Note: copied from FreeBSD source code, RELENG 6, sys/crypto/sha1.c			*/
#define H(n)	(ctxt->h.b32[(n)])
#define COUNT	(ctxt->count)
#define BCOUNT	(ctxt->c.b64[0] / 8)
#define W(n)	(ctxt->m.b32[(n)])

static UINT32 _K[] = { 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6 };
#define K(t)	_K[(t) / 20]

#define F0(b, c, d)	(((b) & (c)) | ((~(b)) & (d)))
#define F1(b, c, d)	(((b) ^ (c)) ^ (d))
#define F2(b, c, d)	(((b) & (c)) | ((b) & (d)) | ((c) & (d)))
#define F3(b, c, d)	(((b) ^ (c)) ^ (d))

#define S(n, x)         (((x) << (n)) | ((x) >> (32 - n)))

#define PUTPAD(x)	{						\
	ctxt->m.b8[(COUNT % 64)] = (x);	\
	COUNT++;									\
	COUNT %= 64;							\
	if (COUNT % 64 == 0)					\
		sha1_step(ctxt);              \
}
/*																										*/
/******************************************************************************/

/******************************************************************************/
/*	Function prototypes used internally														*/
/*																										*/
void sha1_init(
					SHA1_CONTEXT *ctxt)
					;
void sha1_result(
					  SHA1_CONTEXT *ctxt,
					  UCHAR *digest0)
					  ;
void sha1_pad(
				  SHA1_CONTEXT *ctxt)
				  ;

static void sha1_step(
							 SHA1_CONTEXT *ctxt)
							 ;

/*																										*/
/******************************************************************************/

/* TODO: check for little-endian, big-endian	*/

/******************************************************************************/
/*	Function definitions																			*/
/*																										*/
/* Note: copied from FreeBSD source code, RELENG 6, sys/crypto/sha1.c, 176		*/
void sha1_init(
					SHA1_CONTEXT *ctxt)
{
	memset(ctxt, 0, sizeof(SHA1_CONTEXT));
	H(0) = 0x67452301;
	H(1) = 0xefcdab89;
	H(2) = 0x98badcfe;
	H(3) = 0x10325476;
	H(4) = 0xc3d2e1f0;
}

/* Note: copied from FreeBSD source code, RELENG 6, sys/crypto/sha1.c, 223		*/
void sha1_loop(
					SHA1_CONTEXT *ctxt,
					const UCHAR *input,
					size_t len)
{
	size_t gaplen;
	size_t gapstart;
	size_t off;
	size_t copysiz;
	off = 0;

	while (off < len) {
		gapstart = COUNT % 64;
		gaplen = 64 - gapstart;

		copysiz = (gaplen < len - off) ? gaplen : len - off;
		memcpy(&ctxt->m.b8[gapstart], input+off, copysiz);
		COUNT += (UCHAR)copysiz;
		COUNT %= 64;
		ctxt->c.b64[0] += copysiz * 8;
		if (COUNT % 64 == 0)
			sha1_step(ctxt);
		off += copysiz;
	}
}

/* Note: copied from FreeBSD source code, RELENG 6, sys/crypto/sha1.c, 91		*/
static void sha1_step(
							 SHA1_CONTEXT *ctxt)
{
	UINT32 a, b, c, d, e;
	size_t t, s;
	UINT32 tmp;

	SHA1_CONTEXT tctxt;
	memcpy(&tctxt.m.b8[0], &ctxt->m.b8[0], 64);
	ctxt->m.b8[0] = tctxt.m.b8[3]; ctxt->m.b8[1] = tctxt.m.b8[2];
	ctxt->m.b8[2] = tctxt.m.b8[1]; ctxt->m.b8[3] = tctxt.m.b8[0];
	ctxt->m.b8[4] = tctxt.m.b8[7]; ctxt->m.b8[5] = tctxt.m.b8[6];
	ctxt->m.b8[6] = tctxt.m.b8[5]; ctxt->m.b8[7] = tctxt.m.b8[4];
	ctxt->m.b8[8] = tctxt.m.b8[11]; ctxt->m.b8[9] = tctxt.m.b8[10];
	ctxt->m.b8[10] = tctxt.m.b8[9]; ctxt->m.b8[11] = tctxt.m.b8[8];
	ctxt->m.b8[12] = tctxt.m.b8[15]; ctxt->m.b8[13] = tctxt.m.b8[14];
	ctxt->m.b8[14] = tctxt.m.b8[13]; ctxt->m.b8[15] = tctxt.m.b8[12];
	ctxt->m.b8[16] = tctxt.m.b8[19]; ctxt->m.b8[17] = tctxt.m.b8[18];
	ctxt->m.b8[18] = tctxt.m.b8[17]; ctxt->m.b8[19] = tctxt.m.b8[16];
	ctxt->m.b8[20] = tctxt.m.b8[23]; ctxt->m.b8[21] = tctxt.m.b8[22];
	ctxt->m.b8[22] = tctxt.m.b8[21]; ctxt->m.b8[23] = tctxt.m.b8[20];
	ctxt->m.b8[24] = tctxt.m.b8[27]; ctxt->m.b8[25] = tctxt.m.b8[26];
	ctxt->m.b8[26] = tctxt.m.b8[25]; ctxt->m.b8[27] = tctxt.m.b8[24];
	ctxt->m.b8[28] = tctxt.m.b8[31]; ctxt->m.b8[29] = tctxt.m.b8[30];
	ctxt->m.b8[30] = tctxt.m.b8[29]; ctxt->m.b8[31] = tctxt.m.b8[28];
	ctxt->m.b8[32] = tctxt.m.b8[35]; ctxt->m.b8[33] = tctxt.m.b8[34];
	ctxt->m.b8[34] = tctxt.m.b8[33]; ctxt->m.b8[35] = tctxt.m.b8[32];
	ctxt->m.b8[36] = tctxt.m.b8[39]; ctxt->m.b8[37] = tctxt.m.b8[38];
	ctxt->m.b8[38] = tctxt.m.b8[37]; ctxt->m.b8[39] = tctxt.m.b8[36];
	ctxt->m.b8[40] = tctxt.m.b8[43]; ctxt->m.b8[41] = tctxt.m.b8[42];
	ctxt->m.b8[42] = tctxt.m.b8[41]; ctxt->m.b8[43] = tctxt.m.b8[40];
	ctxt->m.b8[44] = tctxt.m.b8[47]; ctxt->m.b8[45] = tctxt.m.b8[46];
	ctxt->m.b8[46] = tctxt.m.b8[45]; ctxt->m.b8[47] = tctxt.m.b8[44];
	ctxt->m.b8[48] = tctxt.m.b8[51]; ctxt->m.b8[49] = tctxt.m.b8[50];
	ctxt->m.b8[50] = tctxt.m.b8[49]; ctxt->m.b8[51] = tctxt.m.b8[48];
	ctxt->m.b8[52] = tctxt.m.b8[55]; ctxt->m.b8[53] = tctxt.m.b8[54];
	ctxt->m.b8[54] = tctxt.m.b8[53]; ctxt->m.b8[55] = tctxt.m.b8[52];
	ctxt->m.b8[56] = tctxt.m.b8[59]; ctxt->m.b8[57] = tctxt.m.b8[58];
	ctxt->m.b8[58] = tctxt.m.b8[57]; ctxt->m.b8[59] = tctxt.m.b8[56];
	ctxt->m.b8[60] = tctxt.m.b8[63]; ctxt->m.b8[61] = tctxt.m.b8[62];
	ctxt->m.b8[62] = tctxt.m.b8[61]; ctxt->m.b8[63] = tctxt.m.b8[60];

	a = H(0); b = H(1); c = H(2); d = H(3); e = H(4);

	for (t = 0; t < 20; t++) {
		s = t & 0x0f;
		if (t >= 16) {
			W(s) = S(1, W((s+13) & 0x0f) ^ W((s+8) & 0x0f) ^ W((s+2) & 0x0f) ^ W(s));
		}
		tmp = S(5, a) + F0(b, c, d) + e + W(s) + K(t);
		e = d; d = c; c = S(30, b); b = a; a = tmp;
	}
	for (t = 20; t < 40; t++) {
		s = t & 0x0f;
		W(s) = S(1, W((s+13) & 0x0f) ^ W((s+8) & 0x0f) ^ W((s+2) & 0x0f) ^ W(s));
		tmp = S(5, a) + F1(b, c, d) + e + W(s) + K(t);
		e = d; d = c; c = S(30, b); b = a; a = tmp;
	}
	for (t = 40; t < 60; t++) {
		s = t & 0x0f;
		W(s) = S(1, W((s+13) & 0x0f) ^ W((s+8) & 0x0f) ^ W((s+2) & 0x0f) ^ W(s));
		tmp = S(5, a) + F2(b, c, d) + e + W(s) + K(t);
		e = d; d = c; c = S(30, b); b = a; a = tmp;
	}
	for (t = 60; t < 80; t++) {
		s = t & 0x0f;
		W(s) = S(1, W((s+13) & 0x0f) ^ W((s+8) & 0x0f) ^ W((s+2) & 0x0f) ^ W(s));
		tmp = S(5, a) + F3(b, c, d) + e + W(s) + K(t);
		e = d; d = c; c = S(30, b); b = a; a = tmp;
	}

	H(0) = H(0) + a;
	H(1) = H(1) + b;
	H(2) = H(2) + c;
	H(3) = H(3) + d;
	H(4) = H(4) + e;

	memset(&ctxt->m.b8[0], 0, 64);
}

/* Note: copied from FreeBSD source code, RELENG 6, sys/crypto/sha1.c, 188		*/
void sha1_pad(
				  SHA1_CONTEXT *ctxt)
{
	size_t padlen;          /*pad length in bytes*/
	size_t padstart;

	PUTPAD(0x80);

	padstart = COUNT % 64;
	padlen = 64 - padstart;
	if (padlen < 8) {
		memset(&ctxt->m.b8[padstart], 0, padlen);
		COUNT += padlen;
		COUNT %= 64;
		sha1_step(ctxt);
		padstart = COUNT % 64;  /* should be 0 */
		padlen = 64 - padstart; /* should be 64 */
	}
	memset(&ctxt->m.b8[padstart], 0, padlen - 8);
	COUNT += (padlen - 8);
	COUNT %= 64;

	PUTPAD(ctxt->c.b8[7]); PUTPAD(ctxt->c.b8[6]);
	PUTPAD(ctxt->c.b8[5]); PUTPAD(ctxt->c.b8[4]);
	PUTPAD(ctxt->c.b8[3]); PUTPAD(ctxt->c.b8[2]);
	PUTPAD(ctxt->c.b8[1]); PUTPAD(ctxt->c.b8[0]);
}

/* Note: copied from FreeBSD source code, RELENG 6, sys/crypto/sha1.c, 251		*/
void sha1_result(
					  SHA1_CONTEXT *ctxt,
					  UCHAR *digest0)
{
	UINT8 *digest;

	digest = (UINT8 *)digest0;
	sha1_pad(ctxt);

	digest[0] = ctxt->h.b8[3]; digest[1] = ctxt->h.b8[2];
	digest[2] = ctxt->h.b8[1]; digest[3] = ctxt->h.b8[0];
	digest[4] = ctxt->h.b8[7]; digest[5] = ctxt->h.b8[6];
	digest[6] = ctxt->h.b8[5]; digest[7] = ctxt->h.b8[4];
	digest[8] = ctxt->h.b8[11]; digest[9] = ctxt->h.b8[10];
	digest[10] = ctxt->h.b8[9]; digest[11] = ctxt->h.b8[8];
	digest[12] = ctxt->h.b8[15]; digest[13] = ctxt->h.b8[14];
	digest[14] = ctxt->h.b8[13]; digest[15] = ctxt->h.b8[12];
	digest[16] = ctxt->h.b8[19]; digest[17] = ctxt->h.b8[18];
	digest[18] = ctxt->h.b8[17]; digest[19] = ctxt->h.b8[16];
}

void AirPDcapAlgHmacSha1(
								 const UCHAR *key_len,
								 const size_t keylen,
								 UCHAR *buffer,
								 const size_t digest_len,
								 UCHAR digest[20])
{
	//INT i;
	//SHA1_CONTEXT ictx;
	//SHA1_CONTEXT octx;
	//UCHAR tmpkey[64];
	//UCHAR tmp[HMAC_MAX_BLOCK_LEN];

	//memset(tmpkey, 0, sizeof(tmpkey));
	//memset(tmp, 0, sizeof(tmp));

	//memcpy(tmpkey, key_len, keylen);

	//for(i = 0; i<keylen; i++)
	//	tmpkey[i] ^= HMAC_IPAD_VAL;

	//sha1_init(&ictx);
	//sha1_loop(&ictx, tmpkey, keylen);
	//sha1_loop(&ictx, tmp, HMAC_MAX_BLOCK_LEN-keylen);

	//for(i = 0; i<keylen; i++)
	//	tmpkey[i] ^= (HMAC_IPAD_VAL ^ HMAC_OPAD_VAL);

	//sha1_init(&octx);
	//sha1_loop(&octx, tmpkey, keylen);
	//sha1_loop(&octx, tmp, HMAC_MAX_BLOCK_LEN-keylen);

	//for(i = 0; i<keylen; i++)
	//	tmpkey[i] ^= HMAC_OPAD_VAL;

	//sha1_loop(&ictx, buffer, digest_len);
	//sha1_result(&ictx, digest);
	//sha1_loop(&octx, digest, 20);
	//sha1_result(&octx, digest);

	INT i;
	SHA1_CONTEXT ictx, octx;
	UCHAR tmpkey[64];
	UCHAR tmp[20];

	memset(tmpkey, 0, sizeof(tmpkey));
	memcpy(tmpkey, key_len, keylen);

	for(i = 0; i<64; i++)
		tmpkey[i] ^= HMAC_IPAD_VAL;

	sha1_init(&ictx);
	sha1_loop(&ictx, tmpkey, 64);

	for(i = 0; i<64; i++)
		tmpkey[i] ^= (HMAC_IPAD_VAL ^ HMAC_OPAD_VAL);

	sha1_init(&octx);
	sha1_loop(&octx, tmpkey, 64);

	sha1_loop(&ictx, buffer, digest_len);
	sha1_result(&ictx, tmp);
	sha1_loop(&octx, tmp, 20);
	sha1_result(&octx, digest);

	//INT i;
	//SHA1_CONTEXT sha1ctx;
	//UCHAR k_ipad[64];
	//UCHAR k_opad[64];
	//UCHAR tmp[20];

	//memset(k_ipad, 0, sizeof(k_ipad));
	//memset(k_opad, 0, sizeof(k_opad));

	//memcpy(k_ipad, key_len, keylen);
	//memcpy(k_opad, key_len, keylen);

	//for(i = 0; i<64; i++)
	//{
	//	k_ipad[i] ^= HMAC_IPAD_VAL;
	//	k_opad[i] ^= HMAC_OPAD_VAL;
	//}

	//sha1_init(&sha1ctx);
	//sha1_loop(&sha1ctx, k_ipad, 64);
	//sha1_loop(&sha1ctx, buffer, digest_len);
	//sha1_result(&sha1ctx, tmp);

	//sha1_init(&sha1ctx);
	//sha1_loop(&sha1ctx, k_opad, 64);
	//sha1_loop(&sha1ctx, tmp, 20);
	//sha1_result(&sha1ctx, digest);
}
/*																										*/
/******************************************************************************/