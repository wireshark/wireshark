/* range.c
 * Range routines
 *
 * Dick Gooris <gooris@lucent.com>
 * Ulf Lamping <ulf.lamping@web.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#include <glib.h>

#include <epan/frame_data.h>

#include <epan/range.h>
#include <epan/emem.h>
#include <stdio.h>

/*
 * Size of the header of a range_t.
 */
#define RANGE_HDR_SIZE (sizeof (range_t) - sizeof (range_admin_t))

/* Allocate an empty range. */
range_t *range_empty(void)
{
   range_t *range;

   range = (range_t *)g_malloc(RANGE_HDR_SIZE);
   range->nranges = 0;
   return range;
}

/******************** Range Entry Parser *********************************/

/* Converts a range string to a fast comparable array of ranges.
 * The parameter 'es' points to the string to be converted.
 * The parameter 'max_value' specifies the maximum value in a
 * range.
 *
 * This function allocates a range_t large enough to hold the number
 * of ranges specified, and fills the array range->ranges containing
 * low and high values with the number of ranges being range->nranges.
 * After having called this function, the function value_is_in_range()
 * determines whether a given number is within the range or not.
 *
 * In case of a single number, we make a range where low is equal to high.
 * We take care on wrongly entered ranges; opposite order will be taken
 * care of.
 *
 * The following syntax is accepted :
 *
 *   1-20,30-40     Range from 1 to 20, and packets 30 to 40
 *   -20,30         Range from 1 to 20, and packet 30
 *   20,30,40-      20, 30, and the range from 40 to the end
 *   20-10,30-25    Range from 10 to 20, and from 25 to 30
 *   -              All values
 */

convert_ret_t
range_convert_str(range_t **rangep, const gchar *es, guint32 max_value)
{
   return range_convert_str_work(rangep, es, max_value, TRUE);
}

/*  This version of range_convert_str() allows the caller to specify whether
 *  values in excess of the range's specified maximum should cause an error or
 *  be silently lowered.
 *  XXX - both the function and the variable could probably use better names.
 */
convert_ret_t
range_convert_str_work(range_t **rangep, const gchar *es, guint32 max_value,
		       gboolean err_on_max)
{

   range_t       *range;
   guint         nranges;
   const gchar   *p;
   char          *endp;
   gchar         c;
   guint         i;
   guint32       tmp;
   unsigned long val;

   if ( (rangep == NULL) || (es == NULL) )
       return CVT_SYNTAX_ERROR;

   /* Allocate a range; this has room for one subrange. */
   range = (range_t *)g_malloc(RANGE_HDR_SIZE + sizeof (range_admin_t));
   range->nranges = 0;
   nranges = 1;

   /* Process the ranges separately until we get a comma or end of string.
    *
    * We build a structure array called ranges of high and low values. After the
    * following loop, we have the nranges variable which tells how many ranges
    * were found. The number of individual ranges is limited to 'MaxRanges'
    */

   p = es;
   for (;;) {
      /* Skip white space. */
      while ((c = *p) == ' ' || c == '\t')
	 p++;
      if (c == '\0')
	 break;

      /* This must be a subrange.  Make sure we have room for it. */
      if (range->nranges >= nranges) {
	 /* Grow the structure.
	  * 4 is an arbitrarily chosen number.
	  * We start with 1, under the assumption that people
	  * will often give a single number or range, and then
	  * proceed to keep it a multiple of 4.
	  */
	 if (nranges == 1)
	    nranges = 4;
	 else
	    nranges += 4;
	 range = (range_t *)g_realloc(range, RANGE_HDR_SIZE +
			   nranges*sizeof (range_admin_t));
      }

      if (c == '-') {
	 /* Subrange starts with 1. */
	 range->ranges[range->nranges].low = 1;
      } else if (isdigit((unsigned char)c)) {
	 /* Subrange starts with the specified number */
	 errno = 0;
	 val = strtoul(p, &endp, 10);
	 if (p == endp) {
	    /* That wasn't a valid number. */
	    g_free(range);
	    return CVT_SYNTAX_ERROR;
	 }
	 if (errno == ERANGE || val > max_value) {
	    /* That was valid, but it's too big.  Return an error if requested
	     * (e.g., except when reading from the preferences file).
	     */
	    if (err_on_max) {
	        g_free(range);
	        return CVT_NUMBER_TOO_BIG;
	    } else {
		/* Silently use the range's maximum value */
	        val = max_value;
	    }
	 }
	 p = endp;
	 range->ranges[range->nranges].low = (guint32)val;

	 /* Skip white space. */
	 while ((c = *p) == ' ' || c == '\t')
	    p++;
      } else {
	 /* Neither empty nor a number. */
	 g_free(range);
	 return CVT_SYNTAX_ERROR;
      }

      if (c == '-') {
	 /* There's a hyphen in the range.  Skip past it. */
	 p++;

	 /* Skip white space. */
	 while ((c = *p) == ' ' || c == '\t')
	    p++;

	 if (c == ',' || c == '\0') {
	   /* End of subrange string; that means the subrange ends
	    * with max_value.
	    */
	   range->ranges[range->nranges].high = max_value;
	 } else if (isdigit((unsigned char)c)) {
	    /* Subrange ends with the specified number. */
	    errno = 0;
	    val = strtoul(p, &endp, 10);
	    if (p == endp) {
	       /* That wasn't a valid number. */
	       g_free(range);
	       return CVT_SYNTAX_ERROR;
	    }
	    if (errno == ERANGE || val > max_value) {
		/* That was valid, but it's too big.  Return an error if requested
		 * (e.g., except when reading from the preferences file).
		 */
		if (err_on_max) {
		    g_free(range);
		    return CVT_NUMBER_TOO_BIG;
		} else {
		    /* Silently use the range's maximum value */
		    val = max_value;
		}
	    }
	    p = endp;
	    range->ranges[range->nranges].high = (guint32)val;

	    /* Skip white space. */
	    while ((c = *p) == ' ' || c == '\t')
	       p++;
	 } else {
	    /* Neither empty nor a number. */
	    g_free(range);
	    return CVT_SYNTAX_ERROR;
	 }
      } else if (c == ',' || c == '\0') {
	 /* End of subrange string; that means there's no hyphen
	  * in the subrange, so the start and the end are the same.
	  */
	 range->ranges[range->nranges].high = range->ranges[range->nranges].low;
      } else {
	 /* Invalid character. */
	 g_free(range);
	 return CVT_SYNTAX_ERROR;
      }
      range->nranges++;

      if (c == ',') {
	 /* Subrange is followed by a comma; skip it. */
	 p++;
      }
   }

   /* Now we are going through the low and high values, and check
    * whether they are in a proper order. Low should be equal or lower
    * than high. So, go through the loop and swap if needed.
    */
   for (i=0; i < range->nranges; i++) {
      if (range->ranges[i].low > range->ranges[i].high) {
	 tmp = range->ranges[i].low;
	 range->ranges[i].low  = range->ranges[i].high;
	 range->ranges[i].high = tmp;
      }
   }

   /* In case we want to know what the result ranges are :
    *
    * for (i=0; i < range->nranges; i++) {
    *  printf("Function : range_convert_str L=%u \t H=%u\n",range->ranges[i].low,range->ranges[i].high);
    * }
    *
    */
   *rangep = range;
   return CVT_NO_ERROR;
} /* range_convert_str */

/* This function returns TRUE if a given value is within one of the ranges
 * stored in the ranges array.
 */
gboolean
value_is_in_range(range_t *range, guint32 val)
{
   guint i;

   if (range) {
      for (i=0; i < range->nranges; i++) {
         if (val >= range->ranges[i].low && val <= range->ranges[i].high)
	     return TRUE;
      }
   }
   return(FALSE);
}

/* This function returns TRUE if the two given range_t's are equal.
 */
gboolean
ranges_are_equal(range_t *a, range_t *b)
{
   guint i;

   if ( (a == NULL) || (b == NULL) )
       return FALSE;

   if (a->nranges != b->nranges)
      return FALSE;

   for (i=0; i < a->nranges; i++) {
      if (a->ranges[i].low != b->ranges[i].low)
	 return FALSE;

      if (a->ranges[i].high != b->ranges[i].high)
	 return FALSE;
   }

   return TRUE;

}

/* This function calls the provided callback function for each value in
 * in the range.
 */
void
range_foreach(range_t *range, void (*callback)(guint32 val))
{
   guint32 i, j;

   if (range && callback) {
      for (i=0; i < range->nranges; i++) {
         for (j = range->ranges[i].low; j <= range->ranges[i].high; j++)
	    callback(j);
      }
   }
}

/* This function converts a range_t to a (ep_alloc()-allocated) string.  */
char *
range_convert_range(range_t *range)
{
   guint32 i;
   gboolean prepend_comma = FALSE;
   emem_strbuf_t *strbuf;

   strbuf=ep_strbuf_new(NULL);

   if (range) {
      for (i=0; i < range->nranges; i++) {
         if (range->ranges[i].low == range->ranges[i].high) {
            ep_strbuf_append_printf(strbuf, "%s%u", prepend_comma?",":"", range->ranges[i].low);
         } else {
            ep_strbuf_append_printf(strbuf, "%s%u-%u", prepend_comma?",":"", range->ranges[i].low, range->ranges[i].high);
         }
         prepend_comma = TRUE;
      }
   }
   return strbuf->str;
}

/* Create a copy of a range. */
range_t *
range_copy(range_t *src)
{
   range_t *dst;
   size_t range_size;

   if (src == NULL)
       return NULL;

   range_size = RANGE_HDR_SIZE + src->nranges*sizeof (range_admin_t);
   dst = (range_t *)g_malloc(range_size);
   memcpy(dst, src, range_size);
   return dst;
}

#if 0
/* This is a debug function to check the range functionality */
static void
value_is_in_range_check(range_t *range, guint32 val)
{
  /* Print the result for a given value */
  printf("Function : value_is_in_range_check Number %u\t",val);

  if (value_is_in_range(range, val)) {
     printf("is in range\n");
  } else {
     printf("is not in range\n");
  }
}
#endif

