/* summary.c
 * Routines for capture file summary info
 *
 * $Id$
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
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
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

  sum_tally->bytes += cur_frame->pkt_len;
  if (cur_frame->flags.passed_dfilter){
    sum_tally->filtered_count++;
    sum_tally->filtered_bytes += cur_frame->pkt_len;
  }
  if (cur_frame->flags.marked){
    sum_tally->marked_count++;
    sum_tally->marked_bytes += cur_frame->pkt_len;
  }
  if (cur_frame->flags.ignored){
    sum_tally->ignored_count++;
  }

  if (cur_frame->flags.has_ts) {
    /* This packet has a time stamp. */
    cur_time = nstime_to_sec(&cur_frame->abs_ts);

    sum_tally->packet_count_ts++;
    if (cur_time < sum_tally->start_time) {
      sum_tally->start_time = cur_time;
    }
    if (cur_time > sum_tally->stop_time){
      sum_tally->stop_time = cur_time;
    }
    if (cur_frame->flags.passed_dfilter){
      sum_tally->filtered_count_ts++;
      /*
       * If we've seen one filtered packet, this is the first
       * one.
       */
      if (sum_tally->filtered_count == 1){
        sum_tally->filtered_start= cur_time;
        sum_tally->filtered_stop = cur_time;
      } else {
        if (cur_time < sum_tally->filtered_start) {
          sum_tally->filtered_start = cur_time;
        }
        if (cur_time > sum_tally->filtered_stop) {
          sum_tally->filtered_stop = cur_time;
        }
      }
    }
    if (cur_frame->flags.marked){
      sum_tally->marked_count_ts++;
      /*
       * If we've seen one marked packet, this is the first
       * one.
       */
      if (sum_tally->marked_count == 1){
        sum_tally->marked_start= cur_time;
        sum_tally->marked_stop = cur_time;
      } else {
        if (cur_time < sum_tally->marked_start) {
          sum_tally->marked_start = cur_time;
        }
        if (cur_time > sum_tally->marked_stop) {
          sum_tally->marked_stop = cur_time;
        }
      }
    }
  }
}

void
summary_fill_in(capture_file *cf, summary_tally *st)
{

  frame_data    *first_frame, *cur_frame;
  guint32        framenum;
  wtapng_section_t* shb_inf;

  st->packet_count_ts = 0;
  st->start_time = 0;
  st->stop_time = 0;
  st->bytes = 0;
  st->filtered_count = 0;
  st->filtered_count_ts = 0;
  st->filtered_start = 0;
  st->filtered_stop = 0;
  st->filtered_bytes = 0;
  st->marked_count = 0;
  st->marked_count_ts = 0;
  st->marked_start = 0;
  st->marked_stop = 0;
  st->marked_bytes = 0;
  st->ignored_count = 0;

  /* initialize the tally */
  if (cf->count != 0) {
    first_frame = frame_data_sequence_find(cf->frames, 1);
    st->start_time = nstime_to_sec(&first_frame->abs_ts);
    st->stop_time = nstime_to_sec(&first_frame->abs_ts);

    for (framenum = 1; framenum <= cf->count; framenum++) {
      cur_frame = frame_data_sequence_find(cf->frames, framenum);
      tally_frame_data(cur_frame, st);
    }
  }

  st->filename = cf->filename;
  st->file_length = cf->f_datalen;
  st->file_type = cf->cd_t;
  st->is_tempfile = cf->is_tempfile;
  st->encap_type = cf->lnk_t;
  st->has_snap = cf->has_snap;
  st->snap = cf->snap;
  st->elapsed_time = nstime_to_sec(&cf->elapsed_time);
  st->packet_count = cf->count;
  st->drops_known = cf->drops_known;
  st->drops = cf->drops;
  st->dfilter = cf->dfilter;

  /* Get info from SHB */
  shb_inf = wtap_file_get_shb_info(cf->wth);

  shb_inf = wtap_file_get_shb_info(cf->wth);
  if(shb_inf == NULL){
	  st->opt_comment    = NULL;
	  st->shb_hardware   = NULL;
	  st->shb_os         = NULL;
	  st->shb_user_appl  = NULL;
  }else{
	  st->opt_comment    = shb_inf->opt_comment;
	  st->shb_hardware   = shb_inf->shb_hardware;
	  st->shb_os         = shb_inf->shb_os;
	  st->shb_user_appl  = shb_inf->shb_user_appl;
	  g_free(shb_inf);
  }

  st->ifaces  = g_array_new(FALSE, FALSE, sizeof(iface_options));
}


#ifdef HAVE_LIBPCAP
void
summary_fill_in_capture(capture_file *cf,capture_options *capture_opts, summary_tally *st)
{
  iface_options iface;
  interface_t device;
  guint i;
  wtapng_iface_descriptions_t* idb_info;
  wtapng_if_descr_t wtapng_if_descr;

  while (st->ifaces->len > 0) {
    iface = g_array_index(st->ifaces, iface_options, 0);
    st->ifaces = g_array_remove_index(st->ifaces, 0);
    g_free(iface.name);
    g_free(iface.descr);
    g_free(iface.cfilter);
  }
  if (st->is_tempfile) {
    for (i = 0; i < capture_opts->all_ifaces->len; i++) {
      device = g_array_index(capture_opts->all_ifaces, interface_t, i);
      if (!device.selected) {
        continue;
      }
      iface.cfilter = g_strdup(device.cfilter);
      iface.name = g_strdup(device.name);
      iface.descr = g_strdup(device.display_name);
      iface.drops_known = cf->drops_known;
      iface.drops = cf->drops;
      iface.has_snap = device.has_snaplen;
      iface.snap = device.snaplen;
      iface.linktype = device.active_dlt;
      g_array_append_val(st->ifaces, iface);
    }
  } else {
    idb_info = wtap_file_get_idb_info(cf->wth);
    for (i = 0; i < idb_info->number_of_interfaces; i++) {
      wtapng_if_descr = g_array_index(idb_info->interface_data, wtapng_if_descr_t, i);
      iface.cfilter = g_strdup(wtapng_if_descr.if_filter_str);
      iface.name = g_strdup(wtapng_if_descr.if_name);
      iface.descr = g_strdup(wtapng_if_descr.if_description);
      iface.drops_known = FALSE;
      iface.drops = 0;
      iface.snap = wtapng_if_descr.snap_len;
      iface.has_snap = (iface.snap != 65535);
      iface.linktype = wtapng_if_descr.link_type;
      g_array_append_val(st->ifaces, iface);
    }
    g_free(idb_info);
  }
}
#endif

void
summary_update_comment(capture_file *cf, gchar *comment)
{

  /* Get info from SHB */
  wtap_write_shb_comment(cf->wth, comment);

}
