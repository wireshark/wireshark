/**
 * airpdcap_rijndael.h
 *
 * $Id$
 *
 * @version 3.0 (December 2000)
 *
 * Optimised ANSI C code for the Rijndael cipher (now AES)
 *
 * @author Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
 * @author Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>
 * @author Paulo Barreto <paulo.barreto@terra.com.br>
 *
 * This code is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

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
	const UCHAR *key,
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
