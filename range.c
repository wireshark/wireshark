/* range.c
 * Packet range routines (save, print, ...)
 *
 * $Id: range.c,v 1.5 2004/01/07 00:10:17 ulfl Exp $
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


#include "range.h"

#include "globals.h"


static gboolean packet_is_in_range(guint32 val);


/* Range parser variables */
#define MaxRange  30

struct range_admin {
       guint32    low;
       guint32    high;
};

static guint         GLnrange=0;
struct range_admin   GLrange[MaxRange];
static guint32       max_packets;


void packet_range_calc(packet_range_t *range) {
  guint32       current_count;
  guint32       mark_low;
  guint32       mark_high;
  guint32       displayed_mark_low;
  guint32       displayed_mark_high;
  frame_data    *packet;

  
  mark_low              = 0L;
  mark_high             = 0L;
  range->mark_range     = 0L;

  displayed_mark_low    = 0L;
  displayed_mark_high   = 0L;
  range->displayed_cnt  = 0L;
  range->displayed_marked_cnt = 0L;
  range->displayed_mark_range = 0L;

  /* The next for-loop is used to obtain the amount of packets to be saved
   * and is used to present the information in the Save/Print As widget.
   * We have different types of saving : All the packets, the number
   * of packets of a marked range, a single packet, and a manually 
   * entered packet range. The last one is not calculated since this
   * data must be entered in the widget by the user.
   */

  current_count = 0;
  for(packet = cfile.plist; packet != NULL; packet = packet->next) {
      current_count++;
      if (cfile.current_frame == packet) {
          range->selected_packet = current_count;
      }
      if (packet->flags.passed_dfilter) {
          range->displayed_cnt++;
      }
      if (packet->flags.marked) {
            if (packet->flags.passed_dfilter) {
                range->displayed_marked_cnt++;
                if (displayed_mark_low == 0) {
                   displayed_mark_low = current_count;
                }
                if (current_count > displayed_mark_high) {
                   displayed_mark_high = current_count;
                }
            }

            if (mark_low == 0) {
               mark_low = current_count;
            }
            if (current_count > mark_high) {
               mark_high = current_count;
            }
      }
  }
        
  current_count = 0;
  for(packet = cfile.plist; packet != NULL; packet = packet->next) {
      current_count++;

      if (current_count >= mark_low && 
          current_count <= mark_high)
      {
          range->mark_range++;
      }

      if (current_count >= displayed_mark_low && 
          current_count <= displayed_mark_high)
      {
          if (packet->flags.passed_dfilter) {
            range->displayed_mark_range++;
          }
      }
  }

  /* in case we marked just one packet, we add 1. */
  /*if (cfile.marked_count != 0) {
    range->mark_range = mark_high - mark_low + 1;
  }*/
        
  /* in case we marked just one packet, we add 1. */
  /*if (range->displayed_marked_cnt != 0) {
    range->displayed_mark_range = displayed_mark_high - displayed_mark_low + 1;
  }*/
        
  /* make this global, to be used in function packet_range_convert_str()  */
  max_packets = cfile.count;
}

void packet_range_init(packet_range_t *range) {

  /* "enumeration" values */
  range->markers            = cfile.marked_count;
  range->range_active       = FALSE;
  range->process_curr_done  = FALSE;

  packet_range_calc(range);
}


/* do we have to process all packets? */
gboolean packet_range_process_all(packet_range_t *range) {
    return range->process == range_process_all && !range->process_filtered;
}

/* do we have to process this packet? */
range_process_e packet_range_process(packet_range_t *range, frame_data *fdata) {

    /* do we have to process this packet at all? */
    if (
         (!range->process_filtered && range->process != range_process_marked) ||
          (range->process_filtered && fdata->flags.passed_dfilter && range->process != range_process_marked) ||
          (range->process_filtered && range->process == range_process_marked && fdata->flags.passed_dfilter && fdata->flags.marked) ||
          (range->process == range_process_marked && fdata->flags.marked && !range->process_filtered) ||
          (range->process == range_process_curr)  ||
          (range->process == range_process_marked_range) ||
          (range->process == range_process_manual_range) ||
          (range->range_active)
      ) {
        /* yes, we have to */
    } else {
        return range_process_next;
    }

    /* In case we process a manual range, we check whether the packet number
     * is in any of the ranges as defined the array GLrange, see file_dlg.c
     * If a match is found, we process it, else we process the next packet.
     */
    if (range->process == range_process_manual_range) {
       if (range->process_filtered) {
          if (fdata->flags.passed_dfilter == FALSE) {
             return range_process_next;
          }
       }
       if (packet_is_in_range(fdata->num) == FALSE) {
          return range_process_next;
       }
    }

    /* For processing a marked range, ignore any packet until we get the first marked packet.
     * At that time we set the range_active to TRUE, and decrement the markers count. Then continue
     * accepting each packet, until we find the last marker (markers count becomes zero)
     * We then reset range_active to FALSE to ignore any packet from then on.
     */
    if (range->process == range_process_marked_range) {
       if (range->markers == 0) {
          return range_processing_finished;
       }
       if (fdata->flags.marked == TRUE) {
          range->range_active = TRUE;
            range->markers--;
       }
       if (range->process_filtered) {
          if (fdata->flags.passed_dfilter == FALSE) {
             return range_process_next;
          }
       }
       if (range->range_active == FALSE ) {
          return range_process_next;
       }
    }

    /* Only process the selected packet */
    if (range->process == range_process_curr) {
       if (range->process_curr_done) {
          return range_processing_finished;
       }
       if (fdata->num != cfile.current_frame->num) {
          return range_process_next;
       }
       range->process_curr_done = TRUE;
    }

    /* We fell through the conditions above, so we accept this packet */
    return range_process_this;
}




/******************** Range Entry Parser *********************************/

/* Converts a range string to a fast comparable array of ranges.
 * The parameter 'es' points to the string to be converted, and is defined in
 * the Save/Print-As widget.
 *
 * This function fills the array GLrange containing low and high values indexed 
 * by a global variable GLnrange. After having called this function, the function 
 * packet_is_in_range() determines whether a given (packet) number is within 
 * the range or not. 
 *
 * In case of a single packet number, we make a range where low is equal to high. 
 * We strip any characters other than commas, digits, or hyphens. We take care 
 * on wrongly entered ranges; opposite order will be taken care of.
 * 
 * The following syntax is accepted :
 *
 *   1-20,30-40     Range from 1 to 20, and packets 30 to 40
 *   -20,30         Range from 1 to 20, and packet 30
 *   20,30,40-      Packet number 20, 30, and the range from 40 to the end
 *   20-10,30-25    Range from 10 to 20, and from 25 to 30
 *   -              All packets
 */

void packet_range_convert_str(const gchar *es)
{
    gchar     EntryStr[255], OrgStr[255], value[255], p;
    guint     i, j=0;
    guint32   tmp, val;
    gboolean  hyphenseen;

    /* Reset the number of ranges we are going to find */
    GLnrange = 0;
    GLrange[GLnrange].low  = 0L;
    GLrange[GLnrange].high = 0L;

    /* Make a copy of the string, and check the validity of the input */
    strcpy(OrgStr,es);
    if (strlen(OrgStr) == 0 ) {
        return;
    }

    /* Only keep digits, commas, and hyphens. */
    for (i=0; i<=strlen(OrgStr); i++) {
      if ( isdigit(OrgStr[i]) || OrgStr[i] == '-' || OrgStr[i] == ',' ) {
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
    /* printf("Function : packet_range_convert_str EntryStr = %s\n",EntryStr); */

    /* Now we are going to process the ranges separately until we get a comma,
     * or end of string.
     *
     * We build a structure array called GLrange of high and low values. After the
     * following loop, we have the GLnrange variable which tells how many ranges
     * were found. The number of individual ranges is limited to 'MaxRanges'
     */

    j = 0;
    hyphenseen = FALSE;
    for (i=0; i<=strlen(EntryStr);i++) {

       /* Copy the digit string until a no-digit character is seen */
       if (isdigit(EntryStr[i])) {
          value[j++] = EntryStr[i];
          continue;
       }

       /* Terminate the digit string, and convert it */
       value[j] = '\0';
       val=atol(value);
       j=0;

       /* In case we see a hyphen, store the value we read in the low part 
        * of GLrange. In case it is a trailer hyphen, store the low value, and
        * set the high value to the maximum of packets captured.
        */
       if (EntryStr[i] == '-') {
          /* If this is a trailer hyphen, then treat it in a different
           * way, then the high value is the maximum number of packets counted
           * and we are ready 
           */
          if (i == strlen(EntryStr)-1) {
             GLrange[GLnrange].low  = val;
             GLrange[GLnrange].high = max_packets;
             GLnrange++;
             break;
          } else {
             /* Store the low value of the range */
             GLrange[GLnrange].low  = val;
          }
          hyphenseen=TRUE;
          continue;
       }

       /* In case we see a comma, or end of string */
       if (EntryStr[i] == ',' || i == strlen(EntryStr)) {
          if (hyphenseen) {
             /* Normal treatment: store the high value range in GLrange */
             GLrange[GLnrange].high = val;
          } else {
             /* We did not see a hyphen and we get a comma, then this must
              * be a single packet number */
             GLrange[GLnrange].low  = val;
             GLrange[GLnrange].high = val;
          }
          hyphenseen=FALSE;
       }

       /* Increase the index for the number of ranges we found, and protect
        * against wildly outside array bound jumps */
       GLnrange++;
       if (GLnrange > MaxRange) {
           GLnrange--;
       }
    }
    GLnrange--;

    /*  Now we are going through the low and high values, and check
     *  whether they are in a proper order. Low should be equal or lower
     *  than high. So, go through the loop and swap if needed.
     */
    for (i=0; i <= GLnrange; i++) {
       if (GLrange[i].low > GLrange[i].high) {
          tmp = GLrange[i].low;
          GLrange[i].low  = GLrange[i].high;
          GLrange[i].high = tmp;
       }
    }

    /* In case we want to know what the result ranges are :
     *
     * for (i=0; i <= GLnrange; i++) {
     *  printf("Function : packet_range_convert_str L=%u \t H=%u\n",GLrange[i].low,GLrange[i].high);
     * }
     *
     */

    /* End of packet_range_convert_str() */
    return;
}

/* This function returns TRUE if a given value is within one of the ranges
 * stored in the GLrange array.
 */
static gboolean packet_is_in_range(guint32 val)
{
   guint i;

   for (i=0; i <= GLnrange; i++) {
      if (val >= GLrange[i].low && val <= GLrange[i].high)
         return TRUE;
   }
   return(FALSE);
}

/* This is a debug function to check the range functionality */
static void packet_is_in_range_check(guint32 val)
{

  /* Print the result for a given value */
  printf("Function : packet_is_in_range_check Number %u\t",val);

  if (packet_is_in_range(val)) {
     printf("is in range\n");
  } else {
     printf("is not in range\n");
  }
}

