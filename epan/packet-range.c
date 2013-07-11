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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <glib.h>

#include <epan/frame_data.h>

#include "packet-range.h"

/* (re-)calculate the packet counts (except the user specified range) */
static void packet_range_calc(packet_range_t *range) {
    guint32       framenum;
    guint32       mark_low;
    guint32       mark_high;
    guint32       displayed_mark_low;
    guint32       displayed_mark_high;
    frame_data    *packet;


    range->selected_packet        = 0L;

    mark_low                      = 0L;
    mark_high                     = 0L;
    range->mark_range_cnt         = 0L;
    range->ignored_cnt            = 0L;
    range->ignored_marked_cnt     = 0L;
    range->ignored_mark_range_cnt = 0L;
    range->ignored_user_range_cnt = 0L;

    displayed_mark_low            = 0L;
    displayed_mark_high           = 0L;
    range->displayed_cnt          = 0L;
    range->displayed_marked_cnt   = 0L;
    range->displayed_mark_range_cnt=0L;
    range->displayed_plus_dependents_cnt    = 0L;
    range->displayed_ignored_cnt            = 0L;
    range->displayed_ignored_marked_cnt     = 0L;
    range->displayed_ignored_mark_range_cnt = 0L;
    range->displayed_ignored_user_range_cnt = 0L;

    g_assert(range->cf != NULL);

    /* XXX - this doesn't work unless you have a full set of frame_data
     * structures for all packets in the capture, which is not,
     * for example, the case when TShark is doing a one-pass
     * read of a file or a live capture.
     *
     * It's also horribly slow on large captures, causing it to
     * take a long time for the Save As dialog to pop up, for
     * example.  We should really keep these statistics in
     * the capture_file structure, updating them whenever we
     * filter the display, etc..
     */
    if (range->cf->frames != NULL) {
        /* The next for-loop is used to obtain the amount of packets
         * to be processed and is used to present the information in
         * the Save/Print As widget.
         * We have different types of ranges: All the packets, the number
         * of packets of a marked range, a single packet, and a user specified
         * packet range. The last one is not calculated here since this
         * data must be entered in the widget by the user.
         */

        for(framenum = 1; framenum <= range->cf->count; framenum++) {
            packet = frame_data_sequence_find(range->cf->frames, framenum);

            if (range->cf->current_frame == packet) {
                range->selected_packet = framenum;
            }
            if (packet->flags.passed_dfilter) {
                range->displayed_cnt++;
            }
            if (packet->flags.passed_dfilter ||
		packet->flags.dependent_of_displayed) {
                range->displayed_plus_dependents_cnt++;
            }
            if (packet->flags.marked) {
                if (packet->flags.ignored) {
                    range->ignored_marked_cnt++;
                }
                if (packet->flags.passed_dfilter) {
                    range->displayed_marked_cnt++;
                    if (packet->flags.ignored) {
                        range->displayed_ignored_marked_cnt++;
                    }
                    if (displayed_mark_low == 0) {
                       displayed_mark_low = framenum;
                    }
                    if (framenum > displayed_mark_high) {
                       displayed_mark_high = framenum;
                    }
                }

                if (mark_low == 0) {
                   mark_low = framenum;
                }
                if (framenum > mark_high) {
                   mark_high = framenum;
                }
            }
            if (packet->flags.ignored) {
                range->ignored_cnt++;
                if (packet->flags.passed_dfilter) {
                    range->displayed_ignored_cnt++;
                }
            }
        }

        for(framenum = 1; framenum <= range->cf->count; framenum++) {
            packet = frame_data_sequence_find(range->cf->frames, framenum);

            if (framenum >= mark_low &&
                framenum <= mark_high)
            {
                range->mark_range_cnt++;
                if (packet->flags.ignored) {
                    range->ignored_mark_range_cnt++;
                }
            }

            if (framenum >= displayed_mark_low &&
                framenum <= displayed_mark_high)
            {
                if (packet->flags.passed_dfilter) {
                    range->displayed_mark_range_cnt++;
                    if (packet->flags.ignored) {
                        range->displayed_ignored_mark_range_cnt++;
                    }
                }
            }
        }

#if 0
        /* in case we marked just one packet, we add 1. */
        if (range->cf->marked_count != 0) {
            range->mark_range = mark_high - mark_low + 1;
        }

        /* in case we marked just one packet, we add 1. */
        if (range->displayed_marked_cnt != 0) {
            range->displayed_mark_range = displayed_mark_high - displayed_mark_low + 1;
        }
#endif
    }
}


/* (re-)calculate the user specified packet range counts */
static void packet_range_calc_user(packet_range_t *range) {
    guint32       framenum;
    frame_data    *packet;

    range->user_range_cnt             = 0L;
    range->ignored_user_range_cnt     = 0L;
    range->displayed_user_range_cnt   = 0L;
    range->displayed_ignored_user_range_cnt = 0L;

    g_assert(range->cf != NULL);

    /* XXX - this doesn't work unless you have a full set of frame_data
     * structures for all packets in the capture, which is not,
     * for example, the case when TShark is doing a one-pass
     * read of a file or a live capture.
     *
     * It's also horribly slow on large captures, causing it to
     * take a long time for the Save As dialog to pop up, for
     * example.  This obviously can't be kept in the capture_file
     * structure and recalculated whenever we filter the display
     * or mark frames as ignored, as the results of this depend
     * on what the user specifies.  In some cases, limiting the
     * frame_data structures at which we look to the ones specified
     * by the user might help, but if most of the frames are in
     * the range, that won't help.  In that case, if we could
     * examine the *complement* of the range, and *subtract* them
     * from the statistics for the capture as a whole, that might
     * help, but if the user specified about *half* the packets in
     * the range, that won't help, either.
     */
    if (range->cf->frames != NULL) {
        for(framenum = 1; framenum <= range->cf->count; framenum++) {
            packet = frame_data_sequence_find(range->cf->frames, framenum);

            if (value_is_in_range(range->user_range, framenum)) {
                range->user_range_cnt++;
                if (packet->flags.ignored) {
                    range->ignored_user_range_cnt++;
                }
                if (packet->flags.passed_dfilter) {
                    range->displayed_user_range_cnt++;
                    if (packet->flags.ignored) {
                        range->displayed_ignored_user_range_cnt++;
                    }
                }
            }
        }
    }
}


/* init the range struct */
void packet_range_init(packet_range_t *range, capture_file *cf) {

    memset(range, 0, sizeof(packet_range_t));
    range->process    = range_process_all;
    range->user_range = range_empty();
    range->cf         = cf;

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
    return range->process == range_process_all && !range->process_filtered && !range->remove_ignored;
}

/* do we have to process this packet? */
range_process_e packet_range_process_packet(packet_range_t *range, frame_data *fdata) {

    if (range->remove_ignored && fdata->flags.ignored) {
        return range_process_next;
    }

    g_assert(range->cf != NULL);

    switch(range->process) {
    case(range_process_all):
        break;
    case(range_process_selected):
        if (range->selected_done) {
          return range_processing_finished;
        }
        if (fdata->num != range->cf->current_frame->num) {
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

    /* This packet has to pass the display filter but didn't?
     * Try next, but only if we're not including dependent packets and this
     * packet happens to be a dependency on something that is displayed.
     */
    if ((range->process_filtered && fdata->flags.passed_dfilter == FALSE) &&
	!(range->include_dependents && fdata->flags.dependent_of_displayed)) {
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

    g_assert(range->cf != NULL);

    ret = range_convert_str(&new_range, es, range->cf->count);
    if (ret != CVT_NO_ERROR) {
        /* range isn't valid */
        range->user_range                 = NULL;
        range->user_range_status          = ret;
        range->user_range_cnt             = 0L;
        range->ignored_user_range_cnt     = 0L;
        range->displayed_user_range_cnt   = 0L;
        range->displayed_ignored_user_range_cnt = 0L;
        return;
    }
    range->user_range = new_range;

    /* calculate new user specified packet range counts */
    packet_range_calc_user(range);
} /* packet_range_convert_str */
