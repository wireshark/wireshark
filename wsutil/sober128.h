/** @file
   This file is derived from sober128 implementation in corosync
   cluster engine. corosync cluster engine borrows the implementation
   from LibTomCrypt.

   The latest version of the original code can be found at
   http://www.libtom.net/LibTomCrypt/ according to which this code is in the
   Public Domain
*/

/* About LibTomCrypt:
 * ---------------------------------------------------------------------
 * LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@iahu.ca, http://www.libtom.net/LibTomCrypt/
 */

#ifndef _SOBER127_H
#define _SOBER127_H

#include "ws_symbol_export.h"

typedef struct _sober128_prng {
    unsigned long      R[17],          /* Working storage for the shift register */
                 initR[17],      /* saved register contents */
                 konst,          /* key dependent constant */
                 sbuf;           /* partial word encryption buffer */

    int          nbuf,           /* number of part-word stream bits buffered */
                 flag,           /* first add_entropy call or not? */
                 set;            /* did we call add_entropy to set key? */

} sober128_prng;

/**
 * @brief Initialize a Sober128 PRNG instance.
 *
 * @param prng Pointer to a `sober128_prng` structure to initialize.
 * @return     `0` on success, or a non-zero value on failure.
 */
WS_DLL_PUBLIC
int sober128_start(sober128_prng *prng);

/**
 * @brief Inject entropy into a Sober128 PRNG instance.
 *
 * Adds external entropy to the PRNG state, improving randomness quality.
 *
 * @param buf   Pointer to entropy bytes.
 * @param len   Number of bytes in `buf`.
 * @param prng  Pointer to an initialized `sober128_prng` structure.
 * @return      `0` on success, or a non-zero value on failure.
 */
WS_DLL_PUBLIC
int sober128_add_entropy(const unsigned char *buf, unsigned long len, sober128_prng *prng);

/**
 * @brief Generate random bytes from a Sober128 PRNG instance.
 *
 * Fills the output buffer with pseudo-random bytes from the PRNG.
 * The PRNG must be initialized and seeded with entropy before use.
 *
 * @param buf   Pointer to buffer to receive random bytes.
 * @param len   Number of bytes to generate.
 * @param prng  Pointer to a seeded `sober128_prng` structure.
 * @return      Number of bytes written to `buf`.
 */
WS_DLL_PUBLIC
unsigned long sober128_read(unsigned char *buf, unsigned long len, sober128_prng *prng);

#endif	/* sober128.h */
