/* frame_data.c
 * Routines for packet disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include <epan/epan.h>
#include <epan/frame_data.h>
#include <epan/column-utils.h>
#include <epan/timestamp.h>
#include <wiretap/wtap.h>
#include <wsutil/ws_assert.h>

#define COMPARE_FRAME_NUM()     ((fdata1->num < fdata2->num) ? -1 : \
                                 (fdata1->num > fdata2->num) ? 1 : \
                                 0)

#define COMPARE_NUM(f)  ((fdata1->f < fdata2->f) ? -1 : \
                         (fdata1->f > fdata2->f) ? 1 : \
                         COMPARE_FRAME_NUM())

/* Compare time stamps.
   A packet whose time is a reference time is considered to have
   a lower time stamp than any frame with a non-reference time;
   if both packets' times are reference times, we compare the
   times of the packets. */
#define COMPARE_TS_REAL(time1, time2) \
                ((fdata1->ref_time && !fdata2->ref_time) ? -1 : \
                 (!fdata1->ref_time && fdata2->ref_time) ? 1 : \
                 ((time1).secs < (time2).secs) ? -1 : \
                 ((time1).secs > (time2).secs) ? 1 : \
                 ((time1).nsecs < (time2).nsecs) ? -1 :\
                 ((time1).nsecs > (time2).nsecs) ? 1 : \
                 COMPARE_FRAME_NUM())

#define COMPARE_TS(ts) COMPARE_TS_REAL(fdata1->ts, fdata2->ts)

void
frame_delta_abs_time(const struct epan_session *epan, const frame_data *fdata, uint32_t prev_num, nstime_t *delta)
{
  const nstime_t *prev_abs_ts = (prev_num) ? epan_get_frame_ts(epan, prev_num) : NULL;

  if (prev_abs_ts) {
    nstime_delta(delta, &fdata->abs_ts, prev_abs_ts);
  } else {
    /* If we don't have the time stamp of the previous packet,
       it's because we have no displayed/captured packets prior to this.
       Set the delta time to zero. */
    nstime_set_zero(delta);
  }
}

static int
frame_data_time_delta_compare(const struct epan_session *epan, const frame_data *fdata1, const frame_data *fdata2)
{
  nstime_t del_cap_ts1, del_cap_ts2;

  frame_delta_abs_time(epan, fdata1, fdata1->num - 1, &del_cap_ts1);
  frame_delta_abs_time(epan, fdata2, fdata2->num - 1, &del_cap_ts2);

  return COMPARE_TS_REAL(del_cap_ts1, del_cap_ts2);
}

static int
frame_data_time_delta_rel_compare(const struct epan_session *epan, const frame_data *fdata1, const frame_data *fdata2)
{
  nstime_t del_rel_ts1, del_rel_ts2;

  frame_delta_abs_time(epan, fdata1, fdata1->frame_ref_num, &del_rel_ts1);
  frame_delta_abs_time(epan, fdata2, fdata2->frame_ref_num, &del_rel_ts2);

  return COMPARE_TS_REAL(del_rel_ts1, del_rel_ts2);
}

static int
frame_data_time_delta_dis_compare(const struct epan_session *epan, const frame_data *fdata1, const frame_data *fdata2)
{
  nstime_t del_dis_ts1, del_dis_ts2;

  frame_delta_abs_time(epan, fdata1, fdata1->prev_dis_num, &del_dis_ts1);
  frame_delta_abs_time(epan, fdata2, fdata2->prev_dis_num, &del_dis_ts2);

  return COMPARE_TS_REAL(del_dis_ts1, del_dis_ts2);
}

int
frame_data_compare(const struct epan_session *epan, const frame_data *fdata1, const frame_data *fdata2, int field)
{
  switch (field) {
  case COL_NUMBER:
    return COMPARE_FRAME_NUM();

  case COL_CLS_TIME:
    switch (timestamp_get_type()) {
    case TS_ABSOLUTE:
    case TS_ABSOLUTE_WITH_YMD:
    case TS_ABSOLUTE_WITH_YDOY:
    case TS_UTC:
    case TS_UTC_WITH_YMD:
    case TS_UTC_WITH_YDOY:
    case TS_EPOCH:
      return COMPARE_TS(abs_ts);

    case TS_RELATIVE:
      return frame_data_time_delta_rel_compare(epan, fdata1, fdata2);

    case TS_DELTA:
      return frame_data_time_delta_compare(epan, fdata1, fdata2);

    case TS_DELTA_DIS:
      return frame_data_time_delta_dis_compare(epan, fdata1, fdata2);

    case TS_NOT_SET:
      return 0;
    }
    return 0;

  case COL_ABS_TIME:
  case COL_ABS_YMD_TIME:
  case COL_ABS_YDOY_TIME:
  case COL_UTC_TIME:
  case COL_UTC_YMD_TIME:
  case COL_UTC_YDOY_TIME:
    return COMPARE_TS(abs_ts);

  case COL_REL_TIME:
    return frame_data_time_delta_rel_compare(epan, fdata1, fdata2);

  case COL_DELTA_TIME:
    return frame_data_time_delta_compare(epan, fdata1, fdata2);

  case COL_DELTA_TIME_DIS:
    return frame_data_time_delta_dis_compare(epan, fdata1, fdata2);

  case COL_PACKET_LENGTH:
    return COMPARE_NUM(pkt_len);

  case COL_CUMULATIVE_BYTES:
    return COMPARE_NUM(cum_bytes);

  }
  g_return_val_if_reached(0);
}

void
frame_data_init(frame_data *fdata, uint32_t num, const wtap_rec *rec,
                int64_t offset, uint32_t cum_bytes)
{
  fdata->pfd = NULL;
  fdata->num = num;
  fdata->file_off = offset;
  fdata->passed_dfilter = 1;
  fdata->dependent_of_displayed = 0;
  fdata->dependent_frames = NULL;
  fdata->encoding = PACKET_CHAR_ENC_CHAR_ASCII;
  fdata->visited = 0;
  fdata->marked = 0;
  fdata->ref_time = 0;
  fdata->ignored = 0;
  fdata->has_ts = (rec->presence_flags & WTAP_HAS_TS) ? 1 : 0;
  fdata->tcp_snd_manual_analysis = 0;
  switch (rec->rec_type) {

  case REC_TYPE_PACKET:
    fdata->pkt_len = rec->rec_header.packet_header.len;
    fdata->cum_bytes = cum_bytes + rec->rec_header.packet_header.len;
    fdata->cap_len = rec->rec_header.packet_header.caplen;
    break;

  case REC_TYPE_FT_SPECIFIC_EVENT:
  case REC_TYPE_FT_SPECIFIC_REPORT:
    /*
     * XXX
     */
    fdata->pkt_len = rec->rec_header.ft_specific_header.record_len;
    fdata->cum_bytes = cum_bytes + rec->rec_header.ft_specific_header.record_len;
    fdata->cap_len = rec->rec_header.ft_specific_header.record_len;
    break;

  case REC_TYPE_SYSCALL:
    /*
     * XXX - is cum_bytes supposed to count non-packet bytes?
     */
    fdata->pkt_len = rec->rec_header.syscall_header.event_len;
    fdata->cum_bytes = cum_bytes + rec->rec_header.syscall_header.event_len;
    fdata->cap_len = rec->rec_header.syscall_header.event_filelen;
    break;

  case REC_TYPE_SYSTEMD_JOURNAL_EXPORT:
    /*
     * XXX - is cum_bytes supposed to count non-packet bytes?
     */
    fdata->pkt_len = rec->rec_header.systemd_journal_export_header.record_len;
    fdata->cum_bytes = cum_bytes + rec->rec_header.systemd_journal_export_header.record_len;
    fdata->cap_len = rec->rec_header.systemd_journal_export_header.record_len;
    break;

  case REC_TYPE_CUSTOM_BLOCK:
    /*
     * XXX - is cum_bytes supposed to count non-packet bytes?
     */
    switch (rec->rec_header.custom_block_header.pen) {
    case PEN_NFLX:
      fdata->pkt_len = rec->rec_header.custom_block_header.length - 4;
      fdata->cum_bytes = cum_bytes + rec->rec_header.custom_block_header.length - 4;
      fdata->cap_len = rec->rec_header.custom_block_header.length - 4;
      break;
    default:
      fdata->pkt_len = rec->rec_header.custom_block_header.length;
      fdata->cum_bytes = cum_bytes + rec->rec_header.custom_block_header.length;
      fdata->cap_len = rec->rec_header.custom_block_header.length;
      break;
    }
    break;

  }

  /* To save some memory, we coerce it into 4 bits */
  ws_assert(rec->tsprec <= 0xF);
  fdata->tsprec = (unsigned int)rec->tsprec;
  fdata->abs_ts = rec->ts;
  fdata->has_modified_block = 0;
  fdata->need_colorize = 0;
  fdata->color_filter = NULL;
  fdata->shift_offset.secs = 0;
  fdata->shift_offset.nsecs = 0;
  fdata->frame_ref_num = 0;
  fdata->prev_dis_num = 0;
}

void
frame_data_set_before_dissect(frame_data *fdata,
                nstime_t *elapsed_time,
                const frame_data **frame_ref,
                const frame_data *prev_dis)
{
  nstime_t rel_ts;

  /* If this frame doesn't have a time stamp, don't set it as the
   * reference frame used for calculating time deltas, set elapsed
   * time, etc. We also won't need to calculate the delta of this
   * frame's timestamp to any other frame.
   */
  if (!fdata->has_ts) {
    /* If it was marked as a reference time frame anyway (should we
     * allow that?), clear the existing reference frame so that the
     * next frame with a time stamp will become the reference frame.
     */
    if(fdata->ref_time) {
      *frame_ref = NULL;
    }
    return;
  }

  /* Don't have the reference frame, set to current */
  if (*frame_ref == NULL)
    *frame_ref = fdata;

  /* if this frames is marked as a reference time frame,
     set reference frame this frame */
  if(fdata->ref_time)
    *frame_ref = fdata;

  /* Get the time elapsed between the first packet and this packet. */
  nstime_delta(&rel_ts, &fdata->abs_ts, &(*frame_ref)->abs_ts);

  /* If it's greater than the current elapsed time, set the elapsed time
     to it (we check for "greater than" so as not to be confused by
     time moving backwards). */
  if ((int32_t)elapsed_time->secs < rel_ts.secs
    || ((int32_t)elapsed_time->secs == rel_ts.secs && (int32_t)elapsed_time->nsecs < rel_ts.nsecs)) {
    *elapsed_time = rel_ts;
  }

  fdata->frame_ref_num = (*frame_ref != fdata) ? (*frame_ref)->num : 0;
  fdata->prev_dis_num = (prev_dis) ? prev_dis->num : 0;
}

void
frame_data_set_after_dissect(frame_data *fdata,
                uint32_t *cum_bytes)
{
  /* This frame either passed the display filter list or is marked as
     a time reference frame.  All time reference frames are displayed
     even if they don't pass the display filter */
  if(fdata->ref_time){
    /* if this was a TIME REF frame we should reset the cul bytes field */
    *cum_bytes = fdata->pkt_len;
    fdata->cum_bytes = *cum_bytes;
  } else {
    /* increase cum_bytes with this packets length */
    *cum_bytes += fdata->pkt_len;
    fdata->cum_bytes = *cum_bytes;
  }
}

void
frame_data_reset(frame_data *fdata)
{
  fdata->visited = 0;

  if (fdata->pfd) {
    g_slist_free(fdata->pfd);
    fdata->pfd = NULL;
  }

  if (fdata->dependent_frames) {
    g_hash_table_destroy(fdata->dependent_frames);
    fdata->dependent_frames = NULL;
  }
}

void
frame_data_destroy(frame_data *fdata)
{
  if (fdata->pfd) {
    g_slist_free(fdata->pfd);
    fdata->pfd = NULL;
  }

  if (fdata->dependent_frames) {
    g_hash_table_destroy(fdata->dependent_frames);
    fdata->dependent_frames = NULL;
  }
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
