/* This file is derived from sober128 implementation in corosync
   cluster engine. corosync cluster engine borrows the implementation
   from LibTomCrypt.

   The latest version of the original code can be found at
   http://libtom.org/?page=features according to which this code is in the
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
 * Tom St Denis, tomstdenis@iahu.ca, http://libtom.org/?page=features
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

WS_DLL_PUBLIC
int sober128_start(sober128_prng *prng);
WS_DLL_PUBLIC
int sober128_add_entropy(const unsigned char *buf, unsigned long len, sober128_prng *prng);
WS_DLL_PUBLIC
unsigned long sober128_read(unsigned char *buf, unsigned long len, sober128_prng *prng);

#endif	/* sober128.h */
