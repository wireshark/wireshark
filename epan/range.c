/* range.c
 * Range routines
 *
 * $Id$
 *
 * Dick Gooris <gooris@lucent.com>
 * Ulf Lamping <ulf.lamping@web.de>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <ctype.h>

#include <glib.h>

#include <epan/frame_data.h>

#include <epan/range.h>

#include "globals.h"

/* init the range struct */
void range_init(range_t *range) {

  range->nranges            = 0;
  range->ranges[range->nranges].low  = 0L;
  range->ranges[range->nranges].high = 0L;
}

/******************** Range Entry Parser *********************************/

/* Converts a range string to a fast comparable array of ranges.
 * The parameter 'es' points to the string to be converted.
 * The parameter 'max_value' specifies the maximum value in a
 * range.
 *
 * This function fills the array ranges containing low and high values indexed 
 * by a global variable nranges. After having called this function, the
 * function value_is_in_range() determines whether a given number is within 
 * the range or not. 
 *
 * In case of a single number, we make a range where low is equal to high. 
 * We strip any characters other than commas, digits, or hyphens. We take care 
 * on wrongly entered ranges; opposite order will be taken care of.
 * 
 * The following syntax is accepted :
 *
 *   1-20,30-40     Range from 1 to 20, and packets 30 to 40
 *   -20,30         Range from 1 to 20, and packet 30
 *   20,30,40-      20, 30, and the range from 40 to the end
 *   20-10,30-25    Range from 10 to 20, and from 25 to 30
 *   -              All values
 */

void range_convert_str(range_t *range, const gchar *es, guint32 max_value)
{
    gchar     EntryStr[255], OrgStr[255], value[255], p;
    guint     i, j=0;
    guint32   tmp, val;
    gboolean  hyphenseen;

    /* Reset the number of ranges we are going to find */
    range->nranges = 0;
    range->ranges[range->nranges].low  = 0L;
    range->ranges[range->nranges].high = 0L;

    /* Make a copy of the string, and check the validity of the input */
    strcpy(OrgStr,es);
    if (strlen(OrgStr) == 0 ) {
        return;
    }

    /* Only keep digits, commas, and hyphens. */
    for (i=0; i<=strlen(OrgStr); i++) {
      if ( isdigit((guchar)OrgStr[i]) || OrgStr[i] == '-' || OrgStr[i] == ',' ) {
         EntryStr[j++] = OrgStr[i];
      }
    }
    EntryStr[j] = '\0';

    /* Remove any starting commas */
    strcpy(OrgStr,EntryStr);
    i = 0;
    while (OrgStr[i] == ',') {
       i++;
    }
    strcpy(EntryStr,OrgStr+i);

    /* Remove any double commas */
    strcpy(OrgStr,EntryStr);
    p = ',';
    j = 0;
    for (i=0; i<=strlen(OrgStr); i++) {
      if ( OrgStr[i] != ',' || p != ',') {
         EntryStr[j++] = OrgStr[i];
      }
      p = OrgStr[i];
    }
    EntryStr[j] = '\0';

    /* Remove any double hyphens */
    strcpy(OrgStr,EntryStr);
    p = '-';
    j = 0;
    for (i=0; i<=strlen(OrgStr); i++) {
      if (OrgStr[i] != '-' || p != '-' || i == 0) {
         EntryStr[j++] = OrgStr[i];
      }
      p = OrgStr[i];
    }
    EntryStr[j] = '\0';

    /* Remove any trailing commas */
    i = strlen(EntryStr) - 1;
    while (EntryStr[i] == ',') {
       EntryStr[i] = '\0';
       i--;
    }

    /* The entry string is now filtered, and ready for further parsing */
    /* printf("Function : range_convert_str EntryStr = %s\n",EntryStr); */

    /* Now we are going to process the ranges separately until we get a comma,
     * or end of string.
     *
     * We build a structure array called ranges of high and low values. After the
     * following loop, we have the nranges variable which tells how many ranges
     * were found. The number of individual ranges is limited to 'MaxRanges'
     */

    j = 0;
    hyphenseen = FALSE;
    for (i=0; i<=strlen(EntryStr);i++) {

       /* Copy the digit string until a no-digit character is seen */
       if (isdigit((guchar)EntryStr[i])) {
          value[j++] = EntryStr[i];
          continue;
       }

       /* Terminate the digit string, and convert it */
       value[j] = '\0';
       val=atol(value);
       j=0;

       /* In case we see a hyphen, store the value we read in the low part 
        * of ranges. In case it is a trailer hyphen, store the low value, and
        * set the high value to the maximum of packets captured.
        */
       if (EntryStr[i] == '-') {
          /* If this is a trailer hyphen, then treat it in a different
           * way, then the high value is the maximum value and we are ready 
           */
          if (i == strlen(EntryStr)-1) {
             range->ranges[range->nranges].low  = val;
             range->ranges[range->nranges].high = max_value;
             range->nranges++;
             break;
          } else {
             /* Store the low value of the range */
             range->ranges[range->nranges].low  = val;
          }
          hyphenseen=TRUE;
          continue;
       }

       /* In case we see a comma, or end of string */
       if (EntryStr[i] == ',' || i == strlen(EntryStr)) {
          if (hyphenseen) {
             /* Normal treatment: store the high value range in ranges */
             range->ranges[range->nranges].high = val;
          } else {
             /* We did not see a hyphen and we get a comma, then this must
              * be a single number */
             range->ranges[range->nranges].low  = val;
             range->ranges[range->nranges].high = val;
          }
          hyphenseen=FALSE;
       }

       /* Increase the index for the number of ranges we found, and protect
        * against wildly outside array bound jumps */
       range->nranges++;
       if (range->nranges > MaxRange) {
           range->nranges--;
       }
    }
    range->nranges--;

    /*  Now we are going through the low and high values, and check
     *  whether they are in a proper order. Low should be equal or lower
     *  than high. So, go through the loop and swap if needed.
     */
    for (i=0; i <= range->nranges; i++) {
       if (range->ranges[i].low > range->ranges[i].high) {
          tmp = range->ranges[i].low;
          range->ranges[i].low  = range->ranges[i].high;
          range->ranges[i].high = tmp;
       }
    }

    /* In case we want to know what the result ranges are :
     *
     * for (i=0; i <= nranges; i++) {
     *  printf("Function : range_convert_str L=%u \t H=%u\n",ranges[i].low,ranges[i].high);
     * }
     *
     */
} /* range_convert_str */

/* This function returns TRUE if a given value is within one of the ranges
 * stored in the ranges array.
 */
gboolean value_is_in_range(range_t *range, guint32 val)
{
   guint i;

   for (i=0; i <= range->nranges; i++) {
      if (val >= range->ranges[i].low && val <= range->ranges[i].high)
         return TRUE;
   }
   return(FALSE);
}

#if 0
/* This is a debug function to check the range functionality */
static void value_is_in_range_check(range_t *range, guint32 val)
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
