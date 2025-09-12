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

static bool
frame_delta_abs_time(const struct epan_session *epan, const frame_data *fdata, uint32_t prev_num, nstime_t *delta)
{
  const nstime_t *prev_abs_ts = (prev_num) ? epan_get_frame_ts(epan, prev_num) : NULL;

  if (!fdata->has_ts) {
    /* We don't have a time stamp for this packet. Set the delta time
       to zero, and return false. */
    nstime_set_zero(delta);
    return false;
  }

  if (prev_num == 0) {
    /* The previous frame doesn't exist.  Set the delta time to zero,
       and return false. */
    nstime_set_zero(delta);
    return false;
  }

  /* Ge the previous frame's time stamp, if it has one. */
  prev_abs_ts = epan_get_frame_ts(epan, prev_num);
  if (prev_abs_ts == NULL) {
    /* The previous frame doesn't have a time stamp.  Set the delta
       time to zero, and return false. */
    nstime_set_zero(delta);
    return false;
  }

  /* This frame has a time stamp, the previous frame exists and has a
     time stamp; compute the delta between this frame's time stamp and
     the previous frame's time stamp, and return true. */
  nstime_delta(delta, &fdata->abs_ts, prev_abs_ts);
  return true;
}

static int
frame_compare_time_deltas(const frame_data *fdata1, bool have_ts1, const nstime_t *ts1,
                          const frame_data *fdata2, bool have_ts2, const nstime_t *ts2)
{
  if (!have_ts1) {
    if (!have_ts2) {
      /* We don't have either delta time; sort them the same. */
      return 0;
    }

    /*
     * We don't have ts1 but do have ts2; treat the first
     * as sorting lower than the second.
     */
    return -1;
  }
  if (!have_ts2) {
    /*
     * We have ts1 but don't have ts2; treat the first as
     * sorting greater than the second.
     */
    return 1;
  }

  /*
   * We have ts1 and ts2; compare them.
   */
  return COMPARE_TS_REAL(*ts1, *ts2);
}

bool
frame_rel_first_frame_time(const struct epan_session *epan,
                           const frame_data *fdata, nstime_t *delta)
{
    /*
     * Time relative to the first frame in the capture.
     */
    return frame_delta_abs_time(epan, fdata, 1, delta);
}

bool
frame_rel_time(const struct epan_session *epan, const frame_data *fdata,
               nstime_t *delta)
{
    /*
     * Time relative to the previous reference frame or, if there is no
     * previous reference frame, the first frame in the capture.
     */
    return frame_delta_abs_time(epan, fdata,
                                fdata->frame_ref_num == 0 ? 1 : fdata->frame_ref_num,
                                delta);
}

bool
frame_rel_start_time(const struct epan_session *epan, const frame_data *fdata,
                     nstime_t *delta)
{
  if (!fdata->has_ts) {
    /* We don't have a time stamp for this packet. Set the delta time
       to zero, and return false. */
    /* XXX - Would it make more sense to set the delta time to "unset"
     * rather than zero here and in similar functions when returning
     * false? */
    nstime_set_zero(delta);
    return false;
  }

  const nstime_t *start_ts = epan_get_start_ts(epan);

  if (start_ts == NULL || nstime_is_unset(start_ts)) {
    /* There isn't an explicit start time.  Set the delta
       time to zero, and return false. */
    nstime_set_zero(delta);
    return false;
  }

  /* This frame has a time stamp and the start time stamp exists;
     compute the delta between this frame's time stamp and
     the start time stamp, and return true. */
  nstime_delta(delta, &fdata->abs_ts, start_ts);
  return true;
}

static int
frame_compare_rel_times(const struct epan_session *epan,
                        const frame_data *fdata1, const frame_data *fdata2)
{
  nstime_t del_rel_ts1, del_rel_ts2;
  bool have_del_rel_ts1, have_del_rel_ts2;

  have_del_rel_ts1 = frame_rel_time(epan, fdata1, &del_rel_ts1);
  have_del_rel_ts2 = frame_rel_time(epan, fdata2, &del_rel_ts2);

  return frame_compare_time_deltas(fdata1, have_del_rel_ts1, &del_rel_ts1,
                                   fdata2, have_del_rel_ts2, &del_rel_ts2);
}

bool
frame_delta_time_prev_captured(const struct epan_session *epan,
                               const frame_data *fdata, nstime_t *delta)
{
    return frame_delta_abs_time(epan, fdata, fdata->num - 1, delta);
}

static int
frame_compare_delta_times_prev_captured(const struct epan_session *epan,
                                        const frame_data *fdata1,
                                        const frame_data *fdata2)
{
  nstime_t del_cap_ts1, del_cap_ts2;
  bool have_del_cap_ts1, have_del_cap_ts2;

  have_del_cap_ts1 = frame_delta_time_prev_captured(epan, fdata1, &del_cap_ts1);
  have_del_cap_ts2 = frame_delta_time_prev_captured(epan, fdata2, &del_cap_ts2);

  return frame_compare_time_deltas(fdata1, have_del_cap_ts1, &del_cap_ts1,
                                   fdata2, have_del_cap_ts2, &del_cap_ts2);
}

bool
frame_delta_time_prev_displayed(const struct epan_session *epan,
                                const frame_data *fdata, nstime_t *delta)
{
    return frame_delta_abs_time(epan, fdata, fdata->prev_dis_num, delta);
}

static int
frame_compare_delta_times_prev_displayed(const struct epan_session *epan, const frame_data *fdata1, const frame_data *fdata2)
{
  nstime_t del_dis_ts1, del_dis_ts2;
  bool have_del_dis_ts1, have_del_dis_ts2;

  have_del_dis_ts1 = frame_delta_time_prev_displayed(epan, fdata1, &del_dis_ts1);
  have_del_dis_ts2 = frame_delta_time_prev_displayed(epan, fdata2, &del_dis_ts2);

  return frame_compare_time_deltas(fdata1, have_del_dis_ts1, &del_dis_ts1,
                                   fdata2, have_del_dis_ts2, &del_dis_ts2);
}

static int
frame_data_aggregation_values_compare(GSList* list1, GSList* list2) {
  GHashTable* set = g_hash_table_new(g_str_hash, g_str_equal);
  for (GSList* node = list1; node; node = node->next)
    g_hash_table_add(set, node->data);

  for (GSList* node = list2; node; node = node->next) {
    if (g_hash_table_contains(set, node->data)) {
      g_hash_table_destroy(set);
      return 0;
    }
  }
  g_hash_table_destroy(set);
  return 1;
}

void
free_aggregation_key(gpointer data) {
  aggregation_key* key = (aggregation_key*)data;
  if (!key) return;

  if (key->field) {
    g_free(key->field);
    key->field = NULL;
  }

  if (key->values) {
    g_slist_free_full(key->values, g_free);
    key->values = NULL;
  }

  g_free(key);
}

int
frame_data_compare(const struct epan_session *epan, const frame_data *fdata1, const frame_data *fdata2, int field)
{
  switch (field) {
  case COL_NUMBER:
    return COMPARE_FRAME_NUM();

  case COL_NUMBER_DIS:
    return COMPARE_NUM(dis_num);

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
      return frame_compare_rel_times(epan, fdata1, fdata2);

    case TS_DELTA:
      return frame_compare_delta_times_prev_captured(epan, fdata1, fdata2);

    case TS_DELTA_DIS:
      return frame_compare_delta_times_prev_displayed(epan, fdata1, fdata2);

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
    return frame_compare_rel_times(epan, fdata1, fdata2);

  case COL_DELTA_TIME:
    return frame_compare_delta_times_prev_captured(epan, fdata1, fdata2);

  case COL_DELTA_TIME_DIS:
    return frame_compare_delta_times_prev_displayed(epan, fdata1, fdata2);

  case COL_PACKET_LENGTH:
    return COMPARE_NUM(pkt_len);

  case COL_CUMULATIVE_BYTES:
    return COMPARE_NUM(cum_bytes);

  }
  g_return_val_if_reached(0);
}

int
frame_data_aggregation_compare(const frame_data* fdata1, const frame_data* fdata2)
{
  unsigned length = g_slist_length(fdata1->aggregation_keys);
  if (length != g_slist_length(fdata2->aggregation_keys)) {
    return 1;
  }
  unsigned i = 0;
  while (i < length) {
    const aggregation_key* key1 = (aggregation_key*)g_slist_nth_data(fdata1->aggregation_keys, i);
    const aggregation_key* key2 = (aggregation_key*)g_slist_nth_data(fdata2->aggregation_keys, i);
    if (g_strcmp0(key1->field, key2->field) != 0 ||
      frame_data_aggregation_values_compare(key1->values, key2->values) == 1) {
      return 1;
    }
    i++;
  }
  return 0;
}

void
frame_data_init(frame_data *fdata, uint32_t num, const wtap_rec *rec,
                int64_t offset, uint32_t cum_bytes)
{
  fdata->pfd = NULL;
  fdata->num = num;
  fdata->dis_num = num;
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
    fdata->pkt_len = rec->rec_header.syscall_header.event_data_len;
    fdata->cum_bytes = cum_bytes + rec->rec_header.syscall_header.event_data_len;
    fdata->cap_len = rec->rec_header.syscall_header.event_data_len;
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
    fdata->pkt_len = rec->rec_header.custom_block_header.length;
    fdata->cum_bytes = cum_bytes + rec->rec_header.custom_block_header.length;
    fdata->cap_len = rec->rec_header.custom_block_header.length;
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
  fdata->aggregation_keys = NULL;
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
  if (nstime_cmp(elapsed_time, &rel_ts) < 0) {
    *elapsed_time = rel_ts;
  }

  fdata->frame_ref_num = (*frame_ref)->num;
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

  frame_data_destroy(fdata);
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

  frame_data_aggregation_free(fdata);
}

void frame_data_aggregation_free(frame_data* fdata)
{
  if (fdata->aggregation_keys) {
    g_slist_free_full(fdata->aggregation_keys, free_aggregation_key);
    fdata->aggregation_keys = NULL;
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
