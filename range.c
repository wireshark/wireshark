/* range.c
 * Packet range routines (save, print, ...)
 *
 * $Id: range.c,v 1.2 2003/12/30 22:48:14 guy Exp $
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

void packet_range_init(packet_range_t *range) {
  guint32       current_count;	
  guint32       displayed_count;
  guint32       mark_low;	
  guint32       mark_high;
  frame_data    *packet;

  /* This is needed to calculate the number of packets for each variation
   * like the total amount of packets, the number of marked packets, and
   * the number between the packets. This is for information only
   */

  /* "enumeration" values */
  range->markers            = cfile.marked_count;
  range->range_active       = FALSE;
  range->process_curr_done  = FALSE;

  displayed_count   = 0L;
  mark_low          = 0L;
  mark_high         = 0L;	
  range->mark_range = 0L;		
  
  current_count = 0;
  for(packet = cfile.plist; packet != NULL; packet = packet->next) {
      current_count++;
      if (cfile.current_frame == packet) {
          range->selected_packet = current_count;
      }
      if (packet->flags.passed_dfilter) {
          displayed_count++;
      }
      if (packet->flags.marked) {
	    if (mark_low == 0) {
	       mark_low = current_count;
	    }
	    if (current_count > mark_high) {
	       mark_high = current_count;
	    }
      }
  }
  /* in case we marked just one packet, we add 1. */
  if (cfile.marked_count != 0) {
    range->mark_range = mark_high - mark_low + 1;
  }
  /* make this global, to be used in function conv_str_range()  */
  max_packets = cfile.count;
}


/* do we have to process all packets? */
gboolean packet_range_process_all(packet_range_t *range) {
    return range->process_all && !range->process_filtered;
}

/* do we have to process this packet? */
range_process_e packet_range_process(packet_range_t *range, frame_data *fdata) {

    /* do we have to process this packet at all? */
    if (
      (!range->process_filtered && !range->process_marked) ||
	  (range->process_filtered && fdata->flags.passed_dfilter && !range->process_marked) ||
	  (range->process_marked && fdata->flags.marked && !range->process_filtered) ||
	  (range->process_filtered && range->process_marked && fdata->flags.passed_dfilter && fdata->flags.marked) ||
	  (range->process_curr)  ||	  
	  (range->process_marked_range) ||
	  (range->process_manual_range) ||	  
	  (range->range_active)
      ) {
        /* yes, we have to */
    } else {
        return range_process_next;   
    }

	/* In case we process a manual range, we check the packet number
	 * with the range as defined in the array GLrange, see file_dlg.c
	 * If a match is found, we process it, otherwise we simply go to check
	 * the next packet. 
	 */
	if (range->process_manual_range) {
	   if (range->process_filtered) {
	      if (fdata->flags.passed_dfilter == FALSE) {
	         return range_process_next;
	      }		
	   }
           if (packet_is_in_range(fdata->num) == FALSE) { 
	         return range_process_next;
	   }
	} 
	      
	/* For processing a marked range, skip the frames not marked in the first place
	 * until the first marked frame comes by. Then continue processing until we found the
	 * last marked frame. We set the range_active to FALSE in the first place until
	 * a marked frame is found (fdata->flags.marked == TRUE) From now on range_active
	 * is TRUE, and the large 'if' statement will pass by any frame. It will stop doing
	 * so once the markers count got 0.  process_marked_range got set in gtk/file_dlg.c
	 */
	if (range->process_marked_range) {
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
	      
	/* Only process the selected frame. If accomplished, finish */
	if (range->process_curr) {
	   if (range->process_curr_done) {
	      return range_processing_finished;
	   }		
	   if (fdata->num != cfile.current_frame->num) {
	         return range_process_next;
	   }
	   range->process_curr_done = TRUE;
	} 

    return range_process_this;
}




/******************** Range Entry Parser *********************************/

/* Convert the entry range string in a fast comparable array of ranges.
 * In the first place get rid of spaces, and any other characters than
 * commas, digits, and hyphens. The parameter es points to the string to be processed
 *
 * This function is only called once when a range string is provided in the Save/Print As
 * widget. This function fills an array of low and high values indexed by a global
 * varaiable GLnrange. After having called this function, the function isin(val) 
 * determines whether the value is with the range or not.
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
	
    /* only keep digits, commas, and hyphens. */
    for (i=0; i<=strlen(OrgStr); i++) {
      if ( isdigit(OrgStr[i]) || OrgStr[i] == '-' || OrgStr[i] == ',' ) {
	 EntryStr[j++] = OrgStr[i];
      }  
    }
    EntryStr[j] = '\0';
  
    /* remove any starting commas */
    strcpy(OrgStr,EntryStr);
    i = 0;
    while (OrgStr[i] == ',') {
       i++;
    }
    strcpy(EntryStr,OrgStr+i);
 
    /* remove any double commas within the entry string */
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

    /* remove any double hyphens within the entry string */
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
 
    /* remove any trailing commas */
    i = strlen(EntryStr) - 1;
    while (EntryStr[i] == ',') {
       EntryStr[i] = '\0';	    
       i--;
    }
 
    /* The entry string is now filtered, and ready for further parsing */
    /* printf("str=%s\n",EntryStr); */

    /* Now we are going to process the ranges separately until we get a comma, 
     * or end of string. The following input are interpreted all right :
     *
     *   0-20,30-40    -=>   Range from 0 to 20, and packets 30 to 40
     *   -20,30        -=>   Range from 0 to 20, and packet 30
     *   20,30,40-     -=>   Packet number 20, 30, and the range from 40 to the end
     *   20-10,30-25   -=>   Range from 10 to 20, and from 25 to 30
     *   -             -=>   All packets
     *
     * We build a structure array called GLrange of high and low values. After the
     * following loop, we have the GLnrange variable which tells how many ranges
     * are found. 
     * The number of different ranges is limited to 'MaxRanges'
     */

    j = 0;    
    hyphenseen = FALSE;
    for (i=0; i<=strlen(EntryStr);i++) {

       /* copy the digit string until a no-digit character is seen */
       if (isdigit(EntryStr[i])) {
          value[j++] = EntryStr[i];
	  continue;
       }
	    
       /* Terminate the digit string, and convert it */
       value[j] = '\0';
       val=atol(value);
       j=0;	       

       /* treatment in case we see a hyphen */
       if (EntryStr[i] == '-') {
	  /* if this is a trailer hyphen, then treat it in a different
	   * way, then the high value is the maximum number of packets counted
	   * and we are ready */
	  if (i == strlen(EntryStr)-1) {
             GLrange[GLnrange].low  = val;
             GLrange[GLnrange].high = max_packets;
	     GLnrange++;
	     break;
	  } else {
	     /* if no digits were actually seen, the outcome of
	      * a zeroed string conversion to interger is also 0. */
             GLrange[GLnrange].low  = val;
	  }
	  hyphenseen=TRUE;
	  continue;
       }
	    
       /* treatment in case we see a comma, or end of string */
       if (EntryStr[i] == ',' || i == strlen(EntryStr)) {
	  if (hyphenseen) {
             GLrange[GLnrange].high = val;	
	  } else {
	     /* in this case we got a single packet number */
             GLrange[GLnrange].low  = val;
             GLrange[GLnrange].high = val;
	  }
	  hyphenseen=FALSE;		  	  
       }
	    
       /* Increase the index for ranges found, and protect
        * against wildly outside array bounds */
       GLnrange++;
       if (GLnrange > MaxRange) {
	   GLnrange--;
       }
    }
    GLnrange--;

    /*  Now we are going through the low and high values, and check
     *  whether they are in a proper order. Low should be equal or lower
     *  than high. So, go through the loop and swap if needed
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
     *  printf("L=%u\tH=%u\n",GLrange[i].low,GLrange[i].high);
     * }
     * 
     */
    
    /* End of conv_str_range() */
    return;
}
	   
/* This function returns TRUE is the given value is within the range 
 *  of the input range entered via (Save/Print As). This is supposed to
 *  be a tiny and quick procedure since this is called for every packet
 *  to be potentially saved.
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

static void packet_is_in_range_check(guint32 val)
{
  printf("Checking %d\t",val);
  if (packet_is_in_range(val)) {
     printf("TRUE\n");
  } else {
     printf("FALSE\n");
  }
}

