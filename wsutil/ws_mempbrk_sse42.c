/* strcspn with SSE4.2 intrinsics
   Copyright (C) 2009-2014 Free Software Foundation, Inc.
   Contributed by Intel Corporation.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */


#include "config.h"

#ifdef HAVE_SSE4_2

#include <glib.h>


#ifdef WIN32
  #include <tmmintrin.h>
  #include <stdint.h>
#endif

#include <nmmintrin.h>
#include <string.h>
#include "ws_mempbrk.h"



/* Helper for variable shifts of SSE registers.
   Copyright (C) 2010 Free Software Foundation, Inc.
 */

static const int8_t ___m128i_shift_right[31] =
  {
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
  };

static inline __m128i
__m128i_shift_right (__m128i value, unsigned long int offset)
{
  /* _mm_loadu_si128() works with unaligned data, cast safe */
  return _mm_shuffle_epi8 (value,
                           _mm_loadu_si128 ((__m128i *) (void *) (___m128i_shift_right + offset)));
}

/* We use 0x2:
        _SIDD_SBYTE_OPS
        | _SIDD_CMP_EQUAL_ANY
        | _SIDD_POSITIVE_POLARITY
        | _SIDD_LEAST_SIGNIFICANT
   on pcmpistri to compare xmm/mem128

   0 1 2 3 4 5 6 7 8 9 A B C D E F
   X X X X X X X X X X X X X X X X

   against xmm

   0 1 2 3 4 5 6 7 8 9 A B C D E F
   A A A A A A A A A A A A A A A A

   to find out if the first 16byte data element has any byte A and
   the offset of the first byte.  There are 3 cases:

   1. The first 16byte data element has the byte A at the offset X.
   2. The first 16byte data element has EOS and doesn't have the byte A.
   3. The first 16byte data element is valid and doesn't have the byte A.

   Here is the table of ECX, CFlag, ZFlag and SFlag for 2 cases:

    1            X        1      0/1      0
    2           16        0       1       0
    3           16        0       0       0

   We exit from the loop for cases 1 and 2 with jbe which branches
   when either CFlag or ZFlag is 1.  If CFlag == 1, ECX has the offset
   X for case 1.  */

const char *
_ws_mempbrk_sse42(const char *s, size_t slen, const char *a)
{
  const char *aligned;
  __m128i mask;
  int offset;

  offset = (int) ((size_t) a & 15);
  aligned = (const char *) ((size_t) a & -16L);
  if (offset != 0)
    {
      int length;

      /* Load masks.  */
      /* cast safe - _mm_load_si128() it's 16B aligned */
      mask = __m128i_shift_right(_mm_load_si128 ((__m128i *) (void *) aligned), offset);

      /* Find where the NULL terminator is.  */
      length = _mm_cmpistri (mask, mask, 0x3a);
      if (length == 16 - offset)
        {
          /* There is no NULL terminator.  */
          __m128i mask1 = _mm_load_si128 ((__m128i *) (void *) (aligned + 16));
          int idx = _mm_cmpistri (mask1, mask1, 0x3a);
          length += idx;

          /* Don't use SSE4.2 if the length of A > 16.  */
          if (length > 16)
            return _ws_mempbrk(s, slen, a);

          if (idx != 0)
            {
              /* Combine mask0 and mask1.  We could play games with
                 palignr, but frankly this data should be in L1 now
                 so do the merge via an unaligned load.  */
              mask = _mm_loadu_si128 ((__m128i *) (void *) a);
            }
        }
    }
  else
    {
      int length;

      /* A is aligned.  (cast safe) */
      mask = _mm_load_si128 ((__m128i *) (void *) a);

      /* Find where the NULL terminator is.  */
      length = _mm_cmpistri (mask, mask, 0x3a);
      if (length == 16)
        {
          /* There is no NULL terminator.  Don't use SSE4.2 if the length
             of A > 16.  */
          if (a[16] != 0)
            return _ws_mempbrk(s, slen, a);
        }
    }

  offset = (int) ((size_t) s & 15);
  aligned = (const char *) ((size_t) s & -16L);
  if (offset != 0)
    {
      /* Check partial string. cast safe it's 16B aligned */
      __m128i value = __m128i_shift_right (_mm_load_si128 ((__m128i *) (void *) aligned), offset);

      int length = _mm_cmpistri (mask, value, 0x2);
      /* No need to check ZFlag since ZFlag is always 1.  */
      int cflag = _mm_cmpistrc (mask, value, 0x2);
      int idx = _mm_cmpistri (value, value, 0x3a);

      if (cflag)
        return s + length;
      /* Find where the NULL terminator is.  */
      if (idx < 16 - offset)
      {
         /* fond NUL @ 'idx', need to switch to slower mempbrk */
         return _ws_mempbrk(s + idx + 1, slen - idx - 1, a); /* slen is bigger than 16 & idx < 16 so no undeflow here */
      }
      aligned += 16;
      slen -= (16 - offset);
    }
  else
    aligned = s;

  while (slen >= 16)
    {
      __m128i value = _mm_load_si128 ((__m128i *) (void *) aligned);
      int idx = _mm_cmpistri (mask, value, 0x2);
      int cflag = _mm_cmpistrc (mask, value, 0x2);
      int zflag = _mm_cmpistrz (mask, value, 0x2);

      if (cflag)
        return aligned + idx;
      if (zflag)
      {
         /* found NUL, need to switch to slower mempbrk */
         return _ws_mempbrk(aligned, slen, a);
      }
      aligned += 16;
      slen -= 16;
    }

    /* XXX, use mempbrk_slow here? */
    return _ws_mempbrk(aligned, slen, a);
}

#endif /* HAVE_SSE4_2 */
/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
