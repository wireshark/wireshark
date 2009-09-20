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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <wiretap/wtap.h>
#include <epan/frame_data.h>
#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/timestamp.h>
#include "cfile.h"

#include <glib.h>

/* Protocol-specific data attached to a frame_data structure - protocol
   index and opaque pointer. */
typedef struct _frame_proto_data {
  int proto;
  void *proto_data;
} frame_proto_data;

/* XXX - I declared this static, because it only seems to be used by
 * p_get_proto_data and p_add_proto_data
 */
static gint p_compare(gconstpointer a, gconstpointer b)
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
  frame_proto_data *p1 = se_alloc(sizeof(frame_proto_data));

  g_assert(p1 != NULL);

  p1 -> proto = proto;
  p1 -> proto_data = proto_data;

  /* Add it to the GSLIST */

  fd -> pfd = g_slist_insert_sorted(fd -> pfd,
				    (gpointer *)p1,
				    p_compare);

}

void *
p_get_proto_data(frame_data *fd, int proto)
{
  frame_proto_data temp, *p1;
  GSList *item;

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
  frame_proto_data temp;
  GSList *item;

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
#define COMPARE_TS(ts) \
                ((fdata1->flags.ref_time && !fdata2->flags.ref_time) ? -1 : \
                 (!fdata1->flags.ref_time && fdata2->flags.ref_time) ? 1 : \
                 (fdata1->ts.secs < fdata2->ts.secs) ? -1 : \
                 (fdata1->ts.secs > fdata2->ts.secs) ? 1 : \
                 (fdata1->ts.nsecs < fdata2->ts.nsecs) ? -1 :\
                 (fdata1->ts.nsecs > fdata2->ts.nsecs) ? 1 : \
                 COMPARE_FRAME_NUM())

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
				case TS_EPOCH:
					return COMPARE_TS(abs_ts);

				case TS_RELATIVE:
					return COMPARE_TS(rel_ts);

				case TS_DELTA:
					return COMPARE_TS(del_cap_ts);

				case TS_DELTA_DIS:
					return COMPARE_TS(del_dis_ts);

				case TS_NOT_SET:
					return 0;
			}
			return 0;

		case COL_ABS_TIME:
		case COL_ABS_DATE_TIME:
			return COMPARE_TS(abs_ts);

		case COL_REL_TIME:
			return COMPARE_TS(rel_ts);

		case COL_DELTA_TIME:
			return COMPARE_TS(del_cap_ts);

		case COL_DELTA_TIME_DIS:
			return COMPARE_TS(del_dis_ts);

		case COL_PACKET_LENGTH:
			return COMPARE_NUM(pkt_len);

		case COL_CUMULATIVE_BYTES:
			return COMPARE_NUM(cum_bytes);

	}
	g_return_val_if_reached(0);
}

frame_data_init(frame_data *fdata, capture_file *cf,
                const struct wtap_pkthdr *phdr, gint64 offset,
                guint32 *cum_bytes,
                nstime_t *first_ts,
                nstime_t *prev_dis_ts,
                nstime_t *prev_cap_ts)
{
  fdata->next = NULL;
  fdata->prev = NULL;
  fdata->pfd = NULL;
  fdata->num = cf->count;
  fdata->pkt_len = phdr->len;
  *cum_bytes += phdr->len;
  fdata->cum_bytes  = *cum_bytes;
  fdata->cap_len = phdr->caplen;
  fdata->file_off = offset;
  /* To save some memory, we coarcese it into a gint8 */
  g_assert(phdr->pkt_encap <= G_MAXINT8);
  fdata->lnk_t = (gint8) phdr->pkt_encap;
  fdata->abs_ts.secs = phdr->ts.secs;
  fdata->abs_ts.nsecs = phdr->ts.nsecs;
  fdata->flags.passed_dfilter = 0;
  fdata->flags.encoding = CHAR_ASCII;
  fdata->flags.visited = 0;
  fdata->flags.marked = 0;
  fdata->flags.ref_time = 0;
  fdata->color_filter = NULL;

  /* If we don't have the time stamp of the first packet in the
     capture, it's because this is the first packet.  Save the time
     stamp of this packet as the time stamp of the first packet. */
  if (nstime_is_unset(first_ts)) {
    *first_ts = fdata->abs_ts;
  }

  /* If we don't have the time stamp of the previous captured packet,
     it's because this is the first packet.  Save the time
     stamp of this packet as the time stamp of the previous captured
     packet. */
  if (nstime_is_unset(prev_cap_ts)) {
    *prev_cap_ts = fdata->abs_ts;
  }

  /* Get the time elapsed between the first packet and this packet. */
  nstime_delta(&fdata->rel_ts, &fdata->abs_ts, first_ts);

  /* If it's greater than the current elapsed time, set the elapsed time
     to it (we check for "greater than" so as not to be confused by
     time moving backwards). */
  if ((gint32)cf->elapsed_time.secs < fdata->rel_ts.secs
	|| ((gint32)cf->elapsed_time.secs == fdata->rel_ts.secs && (gint32)cf->elapsed_time.nsecs < fdata->rel_ts.nsecs)) {
    cf->elapsed_time = fdata->rel_ts;
  }

  /* If we don't have the time stamp of the previous displayed packet,
     it's because this is the first packet that's being displayed.  Save the time
     stamp of this packet as the time stamp of the previous displayed
     packet. */
  if (nstime_is_unset(prev_dis_ts))
    *prev_dis_ts = fdata->abs_ts;

  /* Get the time elapsed between the previous displayed packet and
     this packet. */
  nstime_delta(&fdata->del_dis_ts, &fdata->abs_ts, prev_dis_ts);

  /* Get the time elapsed between the previous captured packet and
     this packet. */
  nstime_delta(&fdata->del_cap_ts, &fdata->abs_ts, prev_cap_ts);
  *prev_cap_ts = fdata->abs_ts;
}

void
frame_data_cleanup(frame_data *fdata)
{
  if (fdata->pfd)
    g_slist_free(fdata->pfd);

  fdata->pfd = NULL;
}

