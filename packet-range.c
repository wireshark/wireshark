/* packet-range.c
 * Packet range routines (save, print, ...)
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <ctype.h>

#include <glib.h>

#include <epan/frame_data.h>

#include "globals.h"

#include "packet-range.h"

/* (re-)calculate the packet counts (except the user specified range) */
static void packet_range_calc(packet_range_t *range) {
  guint32       current_count;
  guint32       mark_low;
  guint32       mark_high;
  guint32       displayed_mark_low;
  guint32       displayed_mark_high;
  frame_data    *packet;


  range->selected_packet        = 0L;

  mark_low                      = 0L;
  mark_high                     = 0L;
  range->mark_range_cnt         = 0L;

  displayed_mark_low            = 0L;
  displayed_mark_high           = 0L;
  range->displayed_cnt          = 0L;
  range->displayed_marked_cnt   = 0L;
  range->displayed_mark_range_cnt=0L;

  /* The next for-loop is used to obtain the amount of packets to be processed
   * and is used to present the information in the Save/Print As widget.
   * We have different types of ranges: All the packets, the number
   * of packets of a marked range, a single packet, and a user specified 
   * packet range. The last one is not calculated here since this
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
          range->mark_range_cnt++;
      }

      if (current_count >= displayed_mark_low && 
          current_count <= displayed_mark_high)
      {
          if (packet->flags.passed_dfilter) {
            range->displayed_mark_range_cnt++;
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
}


/* (re-)calculate the user specified packet range counts */
static void packet_range_calc_user(packet_range_t *range) {
  guint32       current_count;
  frame_data    *packet;

  range->user_range_cnt             = 0L;
  range->displayed_user_range_cnt   = 0L;

  current_count = 0;
  for(packet = cfile.plist; packet != NULL; packet = packet->next) {
      current_count++;

      if (value_is_in_range(range->user_range, current_count)) {
          range->user_range_cnt++;
          if (packet->flags.passed_dfilter) {
            range->displayed_user_range_cnt++;
          }
      }
  }
}


/* init the range struct */
void packet_range_init(packet_range_t *range) {

  range->process            = range_process_all;
  range->process_filtered   = FALSE;
  range->user_range         = range_empty();

  /* calculate all packet range counters */
  packet_range_calc(range);
  packet_range_calc_user(range);
}

/* check whether the packet range is OK */
convert_ret_t packet_range_check(packet_range_t *range) {
  if (range->process == range_process_user_range && range->user_range == NULL) {
    /* Not valid - return the error. */
    return range->user_range_status;
  }
  return CVT_NO_ERROR;
}

/* init the processing run */
void packet_range_process_init(packet_range_t *range) {
  /* Check that, if an explicit range was selected, it's valid. */
  /* "enumeration" values */
  range->marked_range_active    = FALSE;
  range->selected_done          = FALSE;

  if (range->process_filtered == FALSE) {
    range->marked_range_left = range->mark_range_cnt;
  } else {
    range->marked_range_left = range->displayed_mark_range_cnt;
  }
}

/* do we have to process all packets? */
gboolean packet_range_process_all(packet_range_t *range) {
    return range->process == range_process_all && !range->process_filtered;
}

/* do we have to process this packet? */
range_process_e packet_range_process_packet(packet_range_t *range, frame_data *fdata) {

    switch(range->process) {
    case(range_process_all):
        break;
    case(range_process_selected):
        if (range->selected_done) {
          return range_processing_finished;
        }
        if (fdata->num != cfile.current_frame->num) {
          return range_process_next;
        }
        range->selected_done = TRUE;
        break;
    case(range_process_marked):
        if (fdata->flags.marked == FALSE) {
          return range_process_next;
        }
        break;
    case(range_process_marked_range):
        if (range->marked_range_left == 0) {
          return range_processing_finished;
        }
        if (fdata->flags.marked == TRUE) {
          range->marked_range_active = TRUE;
        }
        if (range->marked_range_active == FALSE ) {
          return range_process_next;
        }
        if (!range->process_filtered ||
          (range->process_filtered && fdata->flags.passed_dfilter == TRUE))
        {
          range->marked_range_left--;
        }
        break;
    case(range_process_user_range):
        if (value_is_in_range(range->user_range, fdata->num) == FALSE) {
          return range_process_next;
        }
        break;
    default:
        g_assert_not_reached();
    }

    /* this packet has to pass the display filter but didn't? -> try next */
    if (range->process_filtered && fdata->flags.passed_dfilter == FALSE) {
        return range_process_next;
    }

    /* We fell through the conditions above, so we accept this packet */
    return range_process_this;
}


/******************** Range Entry Parser *********************************/

/* Converts a range string to a user range.
 * The parameter 'es' points to the string to be converted, and is defined in
 * the Save/Print-As widget.
 */

void packet_range_convert_str(packet_range_t *range, const gchar *es)
{
    range_t *new_range;
    convert_ret_t ret;

    if (range->user_range != NULL)
        g_free(range->user_range);
    ret = range_convert_str(&new_range, es, cfile.count);
    if (ret != CVT_NO_ERROR) {
        /* range isn't valid */
        range->user_range                 = NULL;
        range->user_range_status          = ret;
        range->user_range_cnt             = 0L;
        range->displayed_user_range_cnt   = 0L;
        return;
    }
    range->user_range = new_range;

    /* calculate new user specified packet range counts */
    packet_range_calc_user(range);
} /* packet_range_convert_str */
