/**
 * aes.h
 *
 * Copied from airpdcap_rijndael.h
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

/* Note: copied AirPDcap/rijndael/rijndael.h */

#ifndef	_AES
#define	_AES

#include "ws_symbol_export.h"

#define RIJNDAEL_MAXKC  (256/32)
#define RIJNDAEL_MAXKB  (256/8)
#define RIJNDAEL_MAXNR  14

typedef struct s_rijndael_ctx {
	gint     Nr;             /* key-length-dependent number of rounds */
	guint32  ek[4 * (RIJNDAEL_MAXNR + 1)];  /* encrypt key schedule */
	guint32  dk[4 * (RIJNDAEL_MAXNR + 1)];  /* decrypt key schedule */
} rijndael_ctx;


WS_DLL_PUBLIC
void rijndael_set_key(
	rijndael_ctx *ctx,
	const guchar *key,
	gint bits);

WS_DLL_PUBLIC
void rijndael_encrypt(
	const rijndael_ctx *ctx,
	const guchar *src,
	guchar *dst);

WS_DLL_PUBLIC
void rijndael_decrypt(
	const rijndael_ctx *ctx,
	const guchar *src,
	guchar *dst);

typedef struct s_aes_cmac_ctx {
	rijndael_ctx aes;
	guint key_len;
	guint input_used;
	guint8 state[RIJNDAEL_MAXKB];
	guint8 input[RIJNDAEL_MAXKB];
} aes_cmac_ctx;

/**
 * Initialize AES-CMAC calculation with the provided key.
 * @param [OUT] ctx Context to initialize
 * @param [IN]  key Key to used
 * @param [IN]  key_len Key length in bytes
 */
WS_DLL_PUBLIC
void aes_cmac_encrypt_starts(
	aes_cmac_ctx *ctx,
	const guint8 *key,
	guint key_len);

/**
 * Add a new buffer for AES-CMAC calculation
 * @param [IN] ctx Context (initialize with @ref AES_CMAC_encrypt_starts)
 * @param [IN] input Buffer to add in AES-CMAC calculation
 * @param [IN] length Length of input buffer (in bytes)
 */
WS_DLL_PUBLIC
void aes_cmac_encrypt_update(
	aes_cmac_ctx *ctx,
	const guint8 *input,
	guint length);

/**
 * Ends AES-CMAC calculation
 * @param [IN] ctx Context (initialize with @ref AES_CMAC_encrypt_starts)
 * @param [OUT] output Buffer to store MAC (must be at least key_len long)
 */
WS_DLL_PUBLIC
void aes_cmac_encrypt_finish(
	aes_cmac_ctx *ctx,
	guint8 *output);

#endif
