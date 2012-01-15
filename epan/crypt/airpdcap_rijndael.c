/**
 * airpdcap_rijndael.c
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

/******************************************************************************/
/*	File includes																					*/
/*																										*/
#include "airpdcap_rijndael.h"

#include	"airpdcap_debug.h"
#include <glib.h>
#include "aes.h"

/* Based on RFC 3394 and NIST AES Key Wrap Specification pseudo-code.

This function is used to unwrap an encrypted AES key.  One example of its use is
in the WPA-2 protocol to get the group key.
*/
UCHAR
AES_unwrap(UCHAR *kek, UINT16 key_len, UCHAR *cipher_text, UINT16 cipher_len, UCHAR *output)
{
	UCHAR a[8], b[16];
	UCHAR *r;
	UCHAR *c;
	gint16 i, j, n;
	rijndael_ctx  ctx;

	if (! kek || cipher_len < 16 || ! cipher_text || ! output) {
		return 1; /* We don't do anything with the return value */
	}

	/* Initialize variables */

	n = (cipher_len/8)-1;  /* the algorithm works on 64-bits at a time */
	memcpy(a, cipher_text, 8);
	r = output;
	c = cipher_text;
	memcpy(r, c+8, cipher_len - 8);

	/* Compute intermediate values */

	for (j=5; j >= 0; --j){
		r = output + (n - 1) * 8;
		/* DEBUG_DUMP("r1", (r-8), 8); */
		/* DEBUG_DUMP("r2", r, 8); */
		for (i = n; i >= 1; --i){
			UINT16 t = (n*j) + i;
			/* DEBUG_DUMP("a", a, 8); */
			memcpy(b, a, 8);
			b[7] ^= t;
			/* DEBUG_DUMP("a plus t", b, 8); */
			memcpy(b+8, r, 8);
			rijndael_set_key(&ctx, kek, key_len*8 /*bits*/);
			rijndael_decrypt(&ctx, b, b);  /* NOTE: we are using the same src and dst buffer. It's ok. */
			/* DEBUG_DUMP("aes decrypt", b, 16) */
			memcpy(a,b,8);
			memcpy(r, b+8, 8);
			r -= 8;
		}
	}

	/* DEBUG_DUMP("a", a, 8); */
	/* DEBUG_DUMP("output", output, cipher_len - 8); */

	return 0;
}

/*																										*/
/******************************************************************************/
