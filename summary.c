/* summary.c
 * Routines for capture file summary info
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

#include <config.h>

#include <wiretap/pcap-encap.h>
#include <wiretap/wtap_opttypes.h>
#include <wiretap/pcapng.h>

#include <epan/packet.h>
#include "cfile.h"
#include "summary.h"
#if 0
#include "ui/capture_ui_utils.h"
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
  wtap_optionblock_t shb_inf;
  iface_options iface;
  guint i;
  wtapng_iface_descriptions_t* idb_info;
  wtap_optionblock_t wtapng_if_descr;
  wtapng_if_descr_mandatory_t *wtapng_if_descr_mand;
  wtap_optionblock_t if_stats;
  guint64 isb_ifdrop;
  char* if_string;
  wtapng_if_descr_filter_t* if_filter;

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
  st->iscompressed = cf->iscompressed;
  st->is_tempfile = cf->is_tempfile;
  st->file_encap_type = cf->lnk_t;
  st->packet_encap_types = cf->linktypes;
  st->has_snap = cf->has_snap;
  st->snap = cf->snap;
  st->elapsed_time = nstime_to_sec(&cf->elapsed_time);
  st->packet_count = cf->count;
  st->drops_known = cf->drops_known;
  st->drops = cf->drops;
  st->dfilter = cf->dfilter;

  /* Get info from SHB */
  shb_inf = wtap_file_get_shb(cf->wth);
  if(shb_inf == NULL){
    st->opt_comment    = NULL;
    st->shb_hardware   = NULL;
    st->shb_os         = NULL;
    st->shb_user_appl  = NULL;
  }else{
    wtap_optionblock_get_option_string(shb_inf, OPT_COMMENT, &st->opt_comment);
    wtap_optionblock_get_option_string(shb_inf, OPT_SHB_HARDWARE, &st->shb_hardware);
    wtap_optionblock_get_option_string(shb_inf, OPT_SHB_OS, &st->shb_os);
    wtap_optionblock_get_option_string(shb_inf, OPT_SHB_USERAPPL, (char**)&st->shb_user_appl);
  }

  st->ifaces  = g_array_new(FALSE, FALSE, sizeof(iface_options));
  idb_info = wtap_file_get_idb_info(cf->wth);
  for (i = 0; i < idb_info->interface_data->len; i++) {
    wtapng_if_descr = g_array_index(idb_info->interface_data, wtap_optionblock_t, i);
    wtapng_if_descr_mand = (wtapng_if_descr_mandatory_t*)wtap_optionblock_get_mandatory_data(wtapng_if_descr);
    wtap_optionblock_get_option_custom(wtapng_if_descr, OPT_IDB_FILTER, (void**)&if_filter);
    iface.cfilter = g_strdup(if_filter->if_filter_str);
    wtap_optionblock_get_option_string(wtapng_if_descr, OPT_IDB_NAME, &if_string);
    iface.name = g_strdup(if_string);
    wtap_optionblock_get_option_string(wtapng_if_descr, OPT_IDB_DESCR, &if_string);
    iface.descr = g_strdup(if_string);
    iface.drops_known = FALSE;
    iface.drops = 0;
    iface.snap = wtapng_if_descr_mand->snap_len;
    iface.has_snap = (iface.snap != 65535);
    iface.encap_type = wtapng_if_descr_mand->wtap_encap;
    iface.isb_comment = NULL;
    if(wtapng_if_descr_mand->num_stat_entries == 1){
      /* dumpcap only writes one ISB, only handle that for now */
      if_stats = g_array_index(wtapng_if_descr_mand->interface_statistics, wtap_optionblock_t, 0);
      wtap_optionblock_get_option_uint64(if_stats, OPT_ISB_IFDROP, &isb_ifdrop);
      if (isb_ifdrop != G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF)) {
        iface.drops_known = TRUE;
        iface.drops = isb_ifdrop;
      }
      /* XXX: this doesn't get used, and might need to be g_strdup'ed when it does */
      wtap_optionblock_get_option_string(if_stats, OPT_COMMENT, &iface.isb_comment);
    }
    g_array_append_val(st->ifaces, iface);
  }
  g_free(idb_info);
}

#ifdef HAVE_LIBPCAP
void
summary_fill_in_capture(capture_file *cf,capture_options *capture_opts, summary_tally *st)
{
  iface_options iface;
  interface_t device;
  guint i;

  if (st->ifaces->len == 0) {
    /*
     * XXX - do this only if we have a live capture.
     */
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
      iface.encap_type = wtap_pcap_encap_to_wtap_encap(device.active_dlt);
      g_array_append_val(st->ifaces, iface);
    }
  }
}
#endif

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
