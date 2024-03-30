/* summary.c
 * Routines for capture file summary info
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <wiretap/pcap-encap.h>
#include <wiretap/wtap_opttypes.h>

#include <epan/packet.h>
#include <wsutil/file_util.h>
#include <gcrypt.h>
#include "cfile.h"
#include "ui/summary.h"

// Strongest to weakest
#define HASH_SIZE_SHA256 32
#define HASH_SIZE_SHA1   20

#define HASH_BUF_SIZE (1024 * 1024)

static void
tally_frame_data(frame_data *cur_frame, summary_tally *sum_tally)
{
    double cur_time;

    sum_tally->bytes += cur_frame->pkt_len;
    if (cur_frame->passed_dfilter){
        sum_tally->filtered_count++;
        sum_tally->filtered_bytes += cur_frame->pkt_len;
    }
    if (cur_frame->marked){
        sum_tally->marked_count++;
        sum_tally->marked_bytes += cur_frame->pkt_len;
    }
    if (cur_frame->ignored){
        sum_tally->ignored_count++;
    }

    if (cur_frame->has_ts) {
        /* This packet has a time stamp. */
        cur_time = nstime_to_sec(&cur_frame->abs_ts);

        sum_tally->packet_count_ts++;
        if (cur_time < sum_tally->start_time) {
            sum_tally->start_time = cur_time;
        }
        if (cur_time > sum_tally->stop_time){
            sum_tally->stop_time = cur_time;
        }
        if (cur_frame->passed_dfilter){
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
        if (cur_frame->marked){
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

static void
hash_to_str(const unsigned char *hash, size_t length, char *str) {
  int i;

  for (i = 0; i < (int) length; i++) {
    snprintf(str+(i*2), 3, "%02x", hash[i]);
  }
}

void
summary_fill_in(capture_file *cf, summary_tally *st)
{
    frame_data    *first_frame, *cur_frame;
    uint32_t       framenum;
    iface_summary_info iface;
    unsigned i;
    wtapng_iface_descriptions_t* idb_info;
    wtap_block_t wtapng_if_descr;
    wtapng_if_descr_mandatory_t *wtapng_if_descr_mand;
    wtap_block_t if_stats;
    uint64_t isb_ifdrop;
    char* if_string;
    if_filter_opt_t if_filter;

    FILE  *fh;
    char  *hash_buf;
    gcry_md_hd_t hd;
    size_t hash_bytes;

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
        first_frame = frame_data_sequence_find(cf->provider.frames, 1);
        st->start_time = nstime_to_sec(&first_frame->abs_ts);
        st->stop_time = nstime_to_sec(&first_frame->abs_ts);

        for (framenum = 1; framenum <= cf->count; framenum++) {
            cur_frame = frame_data_sequence_find(cf->provider.frames, framenum);
            tally_frame_data(cur_frame, st);
        }
    }

    st->filename = cf->filename;
    st->file_length = cf->f_datalen;
    st->file_type = cf->cd_t;
    st->compression_type = cf->compression_type;
    st->is_tempfile = cf->is_tempfile;
    st->file_encap_type = cf->lnk_t;
    st->packet_encap_types = cf->linktypes;
    st->snap = cf->snap;
    st->elapsed_time = nstime_to_sec(&cf->elapsed_time);
    st->packet_count = cf->count;
    st->drops_known = cf->drops_known;
    st->drops = cf->drops;
    st->dfilter = cf->dfilter;

    st->ifaces  = g_array_new(false, false, sizeof(iface_summary_info));
    idb_info = wtap_file_get_idb_info(cf->provider.wth);
    for (i = 0; i < idb_info->interface_data->len; i++) {
        wtapng_if_descr = g_array_index(idb_info->interface_data, wtap_block_t, i);
        wtapng_if_descr_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(wtapng_if_descr);
        if (wtap_block_get_if_filter_option_value(wtapng_if_descr, OPT_IDB_FILTER, &if_filter) == WTAP_OPTTYPE_SUCCESS) {
            if (if_filter.type == if_filter_pcap) {
                iface.cfilter = g_strdup(if_filter.data.filter_str);
            } else {
                /* Not a pcap filter string; punt for now */
                iface.cfilter = NULL;
            }
        } else {
            iface.cfilter = NULL;
        }
        if (wtap_block_get_string_option_value(wtapng_if_descr, OPT_IDB_NAME, &if_string) == WTAP_OPTTYPE_SUCCESS) {
            iface.name = g_strdup(if_string);
        } else {
            iface.name = NULL;
        }
        if (wtap_block_get_string_option_value(wtapng_if_descr, OPT_IDB_DESCRIPTION, &if_string) == WTAP_OPTTYPE_SUCCESS) {
            iface.descr = g_strdup(if_string);
        } else {
            iface.descr = NULL;
        }
        iface.drops_known = false;
        iface.drops = 0;
        iface.snap = wtapng_if_descr_mand->snap_len;
        iface.encap_type = wtapng_if_descr_mand->wtap_encap;
        iface.isb_comment = NULL;
        if(wtapng_if_descr_mand->num_stat_entries == 1){
            /* dumpcap only writes one ISB, only handle that for now */
            if_stats = g_array_index(wtapng_if_descr_mand->interface_statistics, wtap_block_t, 0);
            if (wtap_block_get_uint64_option_value(if_stats, OPT_ISB_IFDROP, &isb_ifdrop) == WTAP_OPTTYPE_SUCCESS) {
                iface.drops_known = true;
                iface.drops = isb_ifdrop;
            }
            /* XXX: this doesn't get used, and might need to be g_strdup'ed when it does */
            /* XXX - support multiple comments */
            if (wtap_block_get_nth_string_option_value(if_stats, OPT_COMMENT, 0, &iface.isb_comment) != WTAP_OPTTYPE_SUCCESS) {
                iface.isb_comment = NULL;
            }
        }
        g_array_append_val(st->ifaces, iface);
    }
    g_free(idb_info);

    (void) g_strlcpy(st->file_sha256, "<unknown>", HASH_STR_SIZE);
    (void) g_strlcpy(st->file_sha1, "<unknown>", HASH_STR_SIZE);

    gcry_md_open(&hd, GCRY_MD_SHA256, 0);
    if (hd) {
        gcry_md_enable(hd, GCRY_MD_SHA1);
    }
    hash_buf = (char *)g_malloc(HASH_BUF_SIZE);

    fh = ws_fopen(cf->filename, "rb");
    if (fh && hash_buf && hd) {
        while((hash_bytes = fread(hash_buf, 1, HASH_BUF_SIZE, fh)) > 0) {
            gcry_md_write(hd, hash_buf, hash_bytes);
        }
        gcry_md_final(hd);
        hash_to_str(gcry_md_read(hd, GCRY_MD_SHA256), HASH_SIZE_SHA256, st->file_sha256);
        hash_to_str(gcry_md_read(hd, GCRY_MD_SHA1), HASH_SIZE_SHA1, st->file_sha1);
    }
    if (fh) fclose(fh);
    g_free(hash_buf);
    gcry_md_close(hd);
}

#ifdef HAVE_LIBPCAP
void
summary_fill_in_capture(capture_file *cf,capture_options *capture_opts, summary_tally *st)
{
    iface_summary_info iface;
    interface_t *device;
    unsigned i;

    if (st->ifaces->len == 0) {
        /*
         * XXX - do this only if we have a live capture.
         */
        for (i = 0; i < capture_opts->all_ifaces->len; i++) {
            device = &g_array_index(capture_opts->all_ifaces, interface_t, i);
            if (!device->selected) {
                continue;
            }
            iface.cfilter = g_strdup(device->cfilter);
            iface.name = g_strdup(device->name);
            iface.descr = g_strdup(device->display_name);
            iface.drops_known = cf->drops_known;
            iface.drops = cf->drops;
            iface.snap = device->snaplen;
            iface.encap_type = wtap_pcap_encap_to_wtap_encap(device->active_dlt);
            g_array_append_val(st->ifaces, iface);
        }
    }
}
#endif
