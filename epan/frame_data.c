/* frame_data.c
 * Routines for packet disassembly
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
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

#include <glib.h>

#include <wiretap/wtap.h>
#include <epan/frame_data.h>
#include <epan/packet.h>
#include <epan/wmem/wmem.h>
#include <epan/timestamp.h>


/* Protocol-specific data attached to a frame_data structure - protocol
   index and opaque pointer. */
typedef struct _frame_proto_data {
  int   proto;
  void *proto_data;
} frame_proto_data;

/* XXX - I declared this static, because it only seems to be used by
 * p_get_proto_data and p_add_proto_data
 */
static gint
p_compare(gconstpointer a, gconstpointer b)
{
  const frame_proto_data *ap = (const frame_proto_data *)a;
  const frame_proto_data *bp = (const frame_proto_data *)b;

  if (ap -> proto > bp -> proto)
    return 1;
  else if (ap -> proto == bp -> proto)
    return 0;
  else
    return -1;

}

void
p_add_proto_data(frame_data *fd, int proto, void *proto_data)
{
  frame_proto_data *p1 = wmem_alloc(wmem_file_scope(), sizeof(frame_proto_data));

  p1->proto = proto;
  p1->proto_data = proto_data;

  /* Add it to the GSLIST */

  fd -> pfd = g_slist_insert_sorted(fd -> pfd,
                    (gpointer *)p1,
                    p_compare);
}

void *
p_get_proto_data(frame_data *fd, int proto)
{
  frame_proto_data  temp, *p1;
  GSList           *item;

  temp.proto = proto;
  temp.proto_data = NULL;

  item = g_slist_find_custom(fd->pfd, (gpointer *)&temp, p_compare);

  if (item) {
    p1 = (frame_proto_data *)item->data;
    return p1->proto_data;
  }

  return NULL;

}

void
p_remove_proto_data(frame_data *fd, int proto)
{
  frame_proto_data  temp;
  GSList           *item;

  temp.proto = proto;
  temp.proto_data = NULL;

  item = g_slist_find_custom(fd->pfd, (gpointer *)&temp, p_compare);

  if (item) {
    fd->pfd = g_slist_remove(fd->pfd, item->data);
  }
}

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
                ((fdata1->flags.ref_time && !fdata2->flags.ref_time) ? -1 : \
                 (!fdata1->flags.ref_time && fdata2->flags.ref_time) ? 1 : \
                 ((time1).secs < (time2).secs) ? -1 : \
                 ((time1).secs > (time2).secs) ? 1 : \
                 ((time1).nsecs < (time2).nsecs) ? -1 :\
                 ((time1).nsecs > (time2).nsecs) ? 1 : \
                 COMPARE_FRAME_NUM())

#define COMPARE_TS(ts) COMPARE_TS_REAL(fdata1->ts, fdata2->ts)

void
frame_delta_abs_time(const frame_data *fdata, const frame_data *prev, nstime_t *delta)
{
  if (prev) {
    nstime_delta(delta, &fdata->abs_ts, &prev->abs_ts);
  } else {
    /* If we don't have the time stamp of the previous packet,
       it's because we have no displayed/captured packets prior to this.
       Set the delta time to zero. */
    nstime_set_zero(delta);
  }
}

static gint
frame_data_time_delta_compare(const frame_data *fdata1, const frame_data *fdata2)
{
  nstime_t del_cap_ts1, del_cap_ts2;

  frame_delta_abs_time(fdata1, fdata1->prev_cap, &del_cap_ts1);
  frame_delta_abs_time(fdata2, fdata2->prev_cap, &del_cap_ts2);

  return COMPARE_TS_REAL(del_cap_ts1, del_cap_ts2);
}

static gint
frame_data_time_delta_dis_compare(const frame_data *fdata1, const frame_data *fdata2)
{
  nstime_t del_dis_ts1, del_dis_ts2;

  frame_delta_abs_time(fdata1, fdata1->prev_dis, &del_dis_ts1);
  frame_delta_abs_time(fdata2, fdata2->prev_dis, &del_dis_ts2);

  return COMPARE_TS_REAL(del_dis_ts1, del_dis_ts2);
}

gint
frame_data_compare(const frame_data *fdata1, const frame_data *fdata2, int field)
{
  switch (field) {
  case COL_NUMBER:
    return COMPARE_FRAME_NUM();

  case COL_CLS_TIME:
    switch (timestamp_get_type()) {
    case TS_ABSOLUTE:
    case TS_ABSOLUTE_WITH_DATE:
    case TS_UTC:
    case TS_UTC_WITH_DATE:
    case TS_EPOCH:
      return COMPARE_TS(abs_ts);

    case TS_RELATIVE:
      return COMPARE_TS(rel_ts);

    case TS_DELTA:
      return frame_data_time_delta_compare(fdata1, fdata2);

    case TS_DELTA_DIS:
      return frame_data_time_delta_dis_compare(fdata1, fdata2);

    case TS_NOT_SET:
      return 0;
    }
    return 0;

  case COL_ABS_TIME:
  case COL_ABS_DATE_TIME:
  case COL_UTC_TIME:
  case COL_UTC_DATE_TIME:
    return COMPARE_TS(abs_ts);

  case COL_REL_TIME:
    return COMPARE_TS(rel_ts);

  case COL_DELTA_TIME:
    return frame_data_time_delta_compare(fdata1, fdata2);

  case COL_DELTA_TIME_DIS:
    return frame_data_time_delta_dis_compare(fdata1, fdata2);

  case COL_PACKET_LENGTH:
    return COMPARE_NUM(pkt_len);

  case COL_CUMULATIVE_BYTES:
    return COMPARE_NUM(cum_bytes);

  }
  g_return_val_if_reached(0);
}

void
frame_data_init(frame_data *fdata, guint32 num,
                const struct wtap_pkthdr *phdr, gint64 offset,
                guint32 cum_bytes)
{
  fdata->pfd = NULL;
  fdata->num = num;
  fdata->interface_id = phdr->interface_id;
  fdata->pkt_len = phdr->len;
  fdata->cum_bytes = cum_bytes + phdr->len;
  fdata->cap_len = phdr->caplen;
  fdata->file_off = offset;
  fdata->subnum = 0;
  /* To save some memory, we coerce it into a gint16 */
  g_assert(phdr->pkt_encap <= G_MAXINT16);
  fdata->lnk_t = (gint16) phdr->pkt_encap;
  fdata->flags.passed_dfilter = 0;
  fdata->flags.dependent_of_displayed = 0;
  fdata->flags.encoding = PACKET_CHAR_ENC_CHAR_ASCII;
  fdata->flags.visited = 0;
  fdata->flags.marked = 0;
  fdata->flags.ref_time = 0;
  fdata->flags.ignored = 0;
  fdata->flags.has_ts = (phdr->presence_flags & WTAP_HAS_TS) ? 1 : 0;
  fdata->flags.has_if_id = (phdr->presence_flags & WTAP_HAS_INTERFACE_ID) ? 1 : 0;
  fdata->color_filter = NULL;
  fdata->abs_ts.secs = phdr->ts.secs;
  fdata->abs_ts.nsecs = phdr->ts.nsecs;
  fdata->shift_offset.secs = 0;
  fdata->shift_offset.nsecs = 0;
  fdata->rel_ts.secs = 0;
  fdata->rel_ts.nsecs = 0;
  fdata->prev_dis = NULL;
  fdata->prev_cap = NULL;
  fdata->opt_comment = phdr->opt_comment;
}

void
frame_data_set_before_dissect(frame_data *fdata,
                nstime_t *elapsed_time,
                nstime_t *first_ts,
                const frame_data *prev_dis,
                const frame_data *prev_cap)
{
  /* If we don't have the time stamp of the first packet in the
     capture, it's because this is the first packet.  Save the time
     stamp of this packet as the time stamp of the first packet. */
  if (nstime_is_unset(first_ts))
    *first_ts = fdata->abs_ts;

  /* if this frames is marked as a reference time frame, reset
     firstsec and firstusec to this frame */
  if(fdata->flags.ref_time)
    *first_ts = fdata->abs_ts;

  /* Get the time elapsed between the first packet and this packet. */
  nstime_delta(&fdata->rel_ts, &fdata->abs_ts, first_ts);

  /* If it's greater than the current elapsed time, set the elapsed time
     to it (we check for "greater than" so as not to be confused by
     time moving backwards). */
  if ((gint32)elapsed_time->secs < fdata->rel_ts.secs
    || ((gint32)elapsed_time->secs == fdata->rel_ts.secs && (gint32)elapsed_time->nsecs < fdata->rel_ts.nsecs)) {
    *elapsed_time = fdata->rel_ts;
  }

  fdata->prev_dis = prev_dis;
  fdata->prev_cap = prev_cap;
}

void
frame_data_set_after_dissect(frame_data *fdata,
                guint32 *cum_bytes)
{
  /* This frame either passed the display filter list or is marked as
     a time reference frame.  All time reference frames are displayed
     even if they dont pass the display filter */
  if(fdata->flags.ref_time){
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
frame_data_cleanup(frame_data *fdata)
{
  if (fdata->pfd) {
    g_slist_free(fdata->pfd);
    fdata->pfd = NULL;
  }

  /* XXX, frame_data_cleanup() is called when redissecting (rescan_packets()),
   *      which might be triggered by lot of things, like: preferences change,
   *      setting manual address resolve, etc.. (grep by redissect_packets)
   *      fdata->opt_comment can be set by user, which we must not discard when redissecting.
   */
#if 0
  if (fdata->opt_comment) {
    g_free(fdata->opt_comment);
    fdata->opt_comment = NULL;
  }
#endif
}
