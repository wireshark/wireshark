/******************************************************************************/
/*	File includes																					*/
/*																										*/
#include "airpdcap_system.h"
#include "airpdcap_int.h"

#include "airpdcap_wep.h"

#include "airpdcap_debug.h"
/*																										*/
/******************************************************************************/

/******************************************************************************/
/*	Internal definitions																			*/
/*																										*/
#define PHASE1_LOOP_COUNT	8

#define AIRPDCAP_TTAK_LEN	6
/*																										*/
/******************************************************************************/

/******************************************************************************/
/*	Internal function prototypes declarations												*/
/*																										*/
void AirPDcapTkipMixingPhase1(
	UINT16 *TTAK,
	const UINT8 *TK,
	const UINT8 *TA,
	UINT32 TSC)
	;

static void AirPDcapTkipMixingPhase2(
	UINT8 *wep_seed,
	const UINT8 *TK,
	UINT16 *PPK,
	UINT16 TSC16)
	;

/*																										*/
/******************************************************************************/

/******************************************************************************/
/*	Global variables																				*/
/*																										*/
/* Note: copied from FreeBSD source code, RELENG 6,									*/
/*		sys/net80211/ieee80211_crypto_tkip.c, 471											*/
static const UINT16 Sbox[256] = {
	0xC6A5, 0xF884, 0xEE99, 0xF68D, 0xFF0D, 0xD6BD, 0xDEB1, 0x9154,
	0x6050, 0x0203, 0xCEA9, 0x567D, 0xE719, 0xB562, 0x4DE6, 0xEC9A,
	0x8F45, 0x1F9D, 0x8940, 0xFA87, 0xEF15, 0xB2EB, 0x8EC9, 0xFB0B,
	0x41EC, 0xB367, 0x5FFD, 0x45EA, 0x23BF, 0x53F7, 0xE496, 0x9B5B,
	0x75C2, 0xE11C, 0x3DAE, 0x4C6A, 0x6C5A, 0x7E41, 0xF502, 0x834F,
	0x685C, 0x51F4, 0xD134, 0xF908, 0xE293, 0xAB73, 0x6253, 0x2A3F,
	0x080C, 0x9552, 0x4665, 0x9D5E, 0x3028, 0x37A1, 0x0A0F, 0x2FB5,
	0x0E09, 0x2436, 0x1B9B, 0xDF3D, 0xCD26, 0x4E69, 0x7FCD, 0xEA9F,
	0x121B, 0x1D9E, 0x5874, 0x342E, 0x362D, 0xDCB2, 0xB4EE, 0x5BFB,
	0xA4F6, 0x764D, 0xB761, 0x7DCE, 0x527B, 0xDD3E, 0x5E71, 0x1397,
	0xA6F5, 0xB968, 0x0000, 0xC12C, 0x4060, 0xE31F, 0x79C8, 0xB6ED,
	0xD4BE, 0x8D46, 0x67D9, 0x724B, 0x94DE, 0x98D4, 0xB0E8, 0x854A,
	0xBB6B, 0xC52A, 0x4FE5, 0xED16, 0x86C5, 0x9AD7, 0x6655, 0x1194,
	0x8ACF, 0xE910, 0x0406, 0xFE81, 0xA0F0, 0x7844, 0x25BA, 0x4BE3,
	0xA2F3, 0x5DFE, 0x80C0, 0x058A, 0x3FAD, 0x21BC, 0x7048, 0xF104,
	0x63DF, 0x77C1, 0xAF75, 0x4263, 0x2030, 0xE51A, 0xFD0E, 0xBF6D,
	0x814C, 0x1814, 0x2635, 0xC32F, 0xBEE1, 0x35A2, 0x88CC, 0x2E39,
	0x9357, 0x55F2, 0xFC82, 0x7A47, 0xC8AC, 0xBAE7, 0x322B, 0xE695,
	0xC0A0, 0x1998, 0x9ED1, 0xA37F, 0x4466, 0x547E, 0x3BAB, 0x0B83,
	0x8CCA, 0xC729, 0x6BD3, 0x283C, 0xA779, 0xBCE2, 0x161D, 0xAD76,
	0xDB3B, 0x6456, 0x744E, 0x141E, 0x92DB, 0x0C0A, 0x486C, 0xB8E4,
	0x9F5D, 0xBD6E, 0x43EF, 0xC4A6, 0x39A8, 0x31A4, 0xD337, 0xF28B,
	0xD532, 0x8B43, 0x6E59, 0xDAB7, 0x018C, 0xB164, 0x9CD2, 0x49E0,
	0xD8B4, 0xACFA, 0xF307, 0xCF25, 0xCAAF, 0xF48E, 0x47E9, 0x1018,
	0x6FD5, 0xF088, 0x4A6F, 0x5C72, 0x3824, 0x57F1, 0x73C7, 0x9751,
	0xCB23, 0xA17C, 0xE89C, 0x3E21, 0x96DD, 0x61DC, 0x0D86, 0x0F85,
	0xE090, 0x7C42, 0x71C4, 0xCCAA, 0x90D8, 0x0605, 0xF701, 0x1C12,
	0xC2A3, 0x6A5F, 0xAEF9, 0x69D0, 0x1791, 0x9958, 0x3A27, 0x27B9,
	0xD938, 0xEB13, 0x2BB3, 0x2233, 0xD2BB, 0xA970, 0x0789, 0x33A7,
	0x2DB6, 0x3C22, 0x1592, 0xC920, 0x8749, 0xAAFF, 0x5078, 0xA57A,
	0x038F, 0x59F8, 0x0980, 0x1A17, 0x65DA, 0xD731, 0x84C6, 0xD0B8,
	0x82C3, 0x29B0, 0x5A77, 0x1E11, 0x7BCB, 0xA8FC, 0x6DD6, 0x2C3A,
};
/*																										*/
/******************************************************************************/

/* TODO: check for little-endian, big-endian	*/

/******************************************************************************/
/*	Function definitions																			*/
/*																										*/
/* Note: any functions were copied from FreeBSD source code, RELENG 6,			*/
/*		sys/net80211/ieee80211_crypto_tkip.c												*/
static __inline UINT16 RotR1(
	UINT16 val)
{
	return (UINT16)((val >> 1) | (val << 15));
}

static __inline UINT8 Lo8(
	UINT16 val)
{
	return (UINT8)(val & 0xff);
}

static __inline UINT8 Hi8(
	UINT16 val)
{
	return (UINT8)(val >> 8);
}

static __inline UINT16 Lo16(
	UINT32 val)
{
	return (UINT16)(val & 0xffff);
}

static __inline UINT16 Hi16(
	UINT32 val)
{
	return (UINT16)(val >> 16);
}

static __inline UINT16 Mk16(
	UINT8 hi,
	UINT8 lo)
{
	return (UINT16)(lo | (((UINT16) hi) << 8));
}

static __inline UINT16 Mk16_le(const UINT16 *v)
{
	return (UINT16)*v;
}

static __inline UINT16 _S_(
	UINT16 v)
{
	UINT16 t = Sbox[Hi8(v)];
	return (UINT16)(Sbox[Lo8(v)] ^ ((t << 8) | (t >> 8)));
}

static __inline UINT64 READ_6(
	UINT8 b0,
	UINT8 b1,
	UINT8 b2,
	UINT8 b3,
	UINT8 b4,
	UINT8 b5)
{
	UINT32 iv32 = (b0 << 0) | (b1 << 8) | (b2 << 16) | (b3 << 24);
	UINT16 iv16 = (UINT16)((b4 << 0) | (b5 << 8));
	return (((UINT64)iv16) << 32) | iv32;
}

void AirPDcapTkipMixingPhase1(
	UINT16 *TTAK,
	const UINT8 *TK,
	const UINT8 *TA,
	UINT32 TSC)
{
	UINT16 i, j;

	/* Initialize the 80-bit TTAK from TSC (TSC) and TA[0..5] */
	TTAK[0] = Lo16(TSC);
	TTAK[1] = Hi16(TSC);
	TTAK[2] = Mk16(TA[1], TA[0]);
	TTAK[3] = Mk16(TA[3], TA[2]);
	TTAK[4] = Mk16(TA[5], TA[4]);

	for (i = 0; i < PHASE1_LOOP_COUNT; i++) {
		j = (UINT16)(2 * (i & 1));
		TTAK[0] = (UINT16)(TTAK[0] + _S_((UINT16)(TTAK[4] ^ Mk16(TK[1 + j], TK[0 + j]))));
		TTAK[1] = (UINT16)(TTAK[1] + _S_((UINT16)(TTAK[0] ^ Mk16(TK[5 + j], TK[4 + j]))));
		TTAK[2] = (UINT16)(TTAK[2] + _S_((UINT16)(TTAK[1] ^ Mk16(TK[9 + j], TK[8 + j]))));
		TTAK[3] = (UINT16)(TTAK[3] + _S_((UINT16)(TTAK[2] ^ Mk16(TK[13 + j], TK[12 + j]))));
		TTAK[4] = (UINT16)(TTAK[4] + _S_((UINT16)(TTAK[3] ^ Mk16(TK[1 + j], TK[0 + j]))) + i);
	}
}

static void AirPDcapTkipMixingPhase2(
	UINT8 *wep_seed,
	const UINT8 *TK,
	UINT16 *TTAK,
	UINT16 TSC16)
{
	INT i;
	TTAK[5] = (UINT16)(TTAK[4] + TSC16);

	/* Step 2 - 96-bit bijective mixing using S-box */
	TTAK[0] = (UINT16)(TTAK[0] + _S_((UINT16)(TTAK[5] ^ Mk16_le((const UINT16 *) &TK[0]))));
	TTAK[1] = (UINT16)(TTAK[1] + _S_((UINT16)(TTAK[0] ^ Mk16_le((const UINT16 *) &TK[2]))));
	TTAK[2] = (UINT16)(TTAK[2] + _S_((UINT16)(TTAK[1] ^ Mk16_le((const UINT16 *) &TK[4]))));
	TTAK[3] = (UINT16)(TTAK[3] + _S_((UINT16)(TTAK[2] ^ Mk16_le((const UINT16 *) &TK[6]))));
	TTAK[4] = (UINT16)(TTAK[4] + _S_((UINT16)(TTAK[3] ^ Mk16_le((const UINT16 *) &TK[8]))));
	TTAK[5] = (UINT16)(TTAK[5] + _S_((UINT16)(TTAK[4] ^ Mk16_le((const UINT16 *) &TK[10]))));

	TTAK[0] = (UINT16)(TTAK[0] + RotR1((UINT16)(TTAK[5] ^ Mk16_le((const UINT16 *) &TK[12]))));
	TTAK[1] = (UINT16)(TTAK[1] + RotR1((UINT16)(TTAK[0] ^ Mk16_le((const UINT16 *) &TK[14]))));
	TTAK[2] = (UINT16)(TTAK[2] + RotR1(TTAK[1]));
	TTAK[3] = (UINT16)(TTAK[3] + RotR1(TTAK[2]));
	TTAK[4] = (UINT16)(TTAK[4] + RotR1(TTAK[3]));
	TTAK[5] = (UINT16)(TTAK[5] + RotR1(TTAK[4]));

	/* Step 3 - bring in last of TK bits, assign 24-bit WEP IV value
	* wep_seed[0..2] is transmitted as WEP IV */
	wep_seed[0] = Hi8(TSC16);
	wep_seed[1] = (UINT8)((Hi8(TSC16) | 0x20) & 0x7F);
	wep_seed[2] = Lo8(TSC16);
	wep_seed[3] = Lo8((UINT16)((TTAK[5] ^ Mk16_le((const UINT16 *) &TK[0])) >> 1));

	for (i = 0; i < 6; i++)
	{
		wep_seed[4 + ( 2 * i)] = Lo8( TTAK[i] );
		wep_seed[5 + ( 2 * i)] = Hi8( TTAK[i] );
	}
}

/* Note: taken from FreeBSD source code, RELENG 6,										*/
/*		sys/net80211/ieee80211_crypto_tkip.c, 936											*/
INT AirPDcapTkipDecrypt(
	UCHAR *tkip_mpdu,
	size_t mpdu_len,
	UCHAR TA[AIRPDCAP_MAC_LEN],
	UCHAR TK[AIRPDCAP_TK_LEN])
{
	UINT32 TSC;
	UINT16 TSC16;
	UINT8 *IV;
	UINT16 TTAK[AIRPDCAP_TTAK_LEN];
	UINT8 wep_seed[AIRPDCAP_WEP_128_KEY_LEN];

	IV = tkip_mpdu;

	TSC16 = (UINT16)READ_6(IV[2], IV[0], IV[4], IV[5], IV[6], IV[7]);

	TSC = (UINT32)TSC16 >> 16;

	AirPDcapTkipMixingPhase1(TTAK, TK, TA, TSC);

	AirPDcapTkipMixingPhase2(wep_seed, TK, TTAK, TSC16);

	return AirPDcapWepDecrypt(
		wep_seed,
		AIRPDCAP_WEP_128_KEY_LEN,
		tkip_mpdu + AIRPDCAP_TKIP_HEADER,
		mpdu_len-(AIRPDCAP_TKIP_HEADER+AIRPDCAP_WEP_ICV));	/* MPDU - TKIP_HEADER - MIC	*/

	/* TODO check (IEEE 802.11i-2004, pg. 44)												*/

}
/*																										*/
/******************************************************************************/
