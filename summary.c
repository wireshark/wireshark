/* summary.c
 * Routines for capture file summary info
 *
 * $Id$
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
# include "config.h"
#endif

#include <epan/packet.h>
#include "cfile.h"
#include "summary.h"
#ifdef HAVE_LIBPCAP
#include "capture_ui_utils.h"
#endif


static void
tally_frame_data(frame_data *cur_frame, summary_tally *sum_tally)
{
  double cur_time;

  cur_time = nstime_to_sec(&cur_frame->abs_ts);

  if (cur_time < sum_tally->start_time) {
    sum_tally->start_time = cur_time;
  }
  if (cur_time > sum_tally->stop_time){
    sum_tally->stop_time = cur_time;
  }
  sum_tally->bytes += cur_frame->pkt_len;
  if (cur_frame->flags.passed_dfilter){
    if (sum_tally->filtered_count==0){
	    sum_tally->filtered_start= cur_time;
	    sum_tally->filtered_stop = cur_time;
    } else {
	    if (cur_time < sum_tally->filtered_start) {
		    sum_tally->start_time = cur_time;
	    }
	    if (cur_time > sum_tally->filtered_stop) {
		    sum_tally->filtered_stop = cur_time;
	    }
    }
    sum_tally->filtered_count++;
    sum_tally->filtered_bytes += cur_frame->pkt_len ;
  }
  if (cur_frame->flags.marked)
    sum_tally->marked_count++;

}

void
summary_fill_in(capture_file *cf, summary_tally *st)
{

  frame_data    *first_frame, *cur_frame;
  int 		i;
  frame_data    *cur_glist;

  st->start_time = 0;
  st->stop_time = 0;
  st->bytes = 0;
  st->filtered_count = 0;
  st->filtered_start = 0;
  st->filtered_stop   = 0;
  st->filtered_bytes = 0;
  st->marked_count = 0;

  /* initialize the tally */
  if (cf->plist != NULL) {
    first_frame = cf->plist;
    st->start_time 	= nstime_to_sec(&first_frame->abs_ts);
    st->stop_time = nstime_to_sec(&first_frame->abs_ts);
    cur_glist = cf->plist;

    for (i = 0; i < cf->count; i++) {
      cur_frame = cur_glist;
      tally_frame_data(cur_frame, st);
      cur_glist = cur_glist->next;
    }
  }

  st->filename = cf->filename;
  st->file_length = cf->f_datalen;
  st->encap_type = cf->cd_t;
  st->has_snap = cf->has_snap;
  st->snap = cf->snap;
  st->elapsed_time = nstime_to_sec(&cf->elapsed_time);
  st->packet_count = cf->count;
  st->drops_known = cf->drops_known;
  st->drops = cf->drops;
  st->dfilter = cf->dfilter;

  /* capture related */
  st->cfilter = NULL;
  st->iface = NULL;
  st->iface_descr = NULL;
}


#ifdef HAVE_LIBPCAP
void
summary_fill_in_capture(capture_options *capture_opts, summary_tally *st)
{
  st->cfilter = capture_opts->cfilter;
  st->iface = capture_opts->iface;
  if(st->iface) {
    st->iface_descr = get_interface_descriptive_name(st->iface);
  } else {
    st->iface_descr = NULL;
  }
}
#endif
