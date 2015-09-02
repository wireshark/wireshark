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
#include "ws_cpuid.h"

#ifdef _WIN32
  #include <tmmintrin.h>
#endif

#include <nmmintrin.h>
#include <string.h>
#include "ws_mempbrk.h"
#include "ws_mempbrk_int.h"

/* __has_feature(address_sanitizer) is used later for Clang, this is for
 * compatibility with other compilers (such as GCC and MSVC) */
#ifndef __has_feature
#   define __has_feature(x) 0
#endif

#define cast_128aligned__m128i(p) ((const __m128i *) (const void *) (p))

/* Helper for variable shifts of SSE registers.
   Copyright (C) 2010 Free Software Foundation, Inc.
 */

static const gint8 ___m128i_shift_right[31] =
  {
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
  };

static inline __m128i
__m128i_shift_right (__m128i value, unsigned long int offset)
{
  /* _mm_loadu_si128() works with unaligned data, cast safe */
  return _mm_shuffle_epi8 (value,
                           _mm_loadu_si128 (cast_128aligned__m128i(___m128i_shift_right + offset)));
}


void
ws_mempbrk_sse42_compile(ws_mempbrk_pattern* pattern, const gchar *needles)
{
    size_t length = strlen(needles);

    pattern->use_sse42 = ws_cpuid_sse42() && (length <= 16);

    if (pattern->use_sse42) {
        pattern->mask = _mm_setzero_si128();
        memcpy(&(pattern->mask), needles, length);
    }
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
ws_mempbrk_sse42_exec(const char *s, size_t slen, const ws_mempbrk_pattern* pattern, guchar *found_needle)
{
  const char *aligned;
  int offset;

  offset = (int) ((size_t) s & 15);
  aligned = (const char *) ((size_t) s & -16L);
  if (offset != 0)
    {
      /* Check partial string. cast safe it's 16B aligned */
      __m128i value = __m128i_shift_right (_mm_load_si128 (cast_128aligned__m128i(aligned)), offset);

      int length = _mm_cmpistri (pattern->mask, value, 0x2);
      /* No need to check ZFlag since ZFlag is always 1.  */
      int cflag = _mm_cmpistrc (pattern->mask, value, 0x2);
      /* XXX: why does this compare value with value? */
      int idx = _mm_cmpistri (value, value, 0x3a);

      if (cflag) {
        if (found_needle)
                *found_needle = *(s + length);
        return s + length;
      }

      /* Find where the NULL terminator is.  */
      if (idx < 16 - offset)
      {
         /* found NUL @ 'idx', need to switch to slower mempbrk */
         return ws_mempbrk_portable_exec(s + idx + 1, slen - idx - 1, pattern, found_needle); /* slen is bigger than 16 & idx < 16 so no undeflow here */
      }
      aligned += 16;
      slen -= (16 - offset);
    }
  else
    aligned = s;

  while (slen >= 16)
    {
      __m128i value = _mm_load_si128 (cast_128aligned__m128i(aligned));
      int idx = _mm_cmpistri (pattern->mask, value, 0x2);
      int cflag = _mm_cmpistrc (pattern->mask, value, 0x2);
      int zflag = _mm_cmpistrz (pattern->mask, value, 0x2);

      if (cflag) {
        if (found_needle)
            *found_needle = *(aligned + idx);
        return aligned + idx;
      }

      if (zflag)
      {
         /* found NUL, need to switch to slower mempbrk */
         return ws_mempbrk_portable_exec(aligned, slen, pattern, found_needle);
      }
      aligned += 16;
      slen -= 16;
    }

    /* XXX, use mempbrk_slow here? */
    return ws_mempbrk_portable_exec(aligned, slen, pattern, found_needle);
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
