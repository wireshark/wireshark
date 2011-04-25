/* frame_data.h
 * Definitions for frame_data structures and routines
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

#ifndef __FRAME_DATA_H__
#define __FRAME_DATA_H__

#include <epan/column_info.h>
#include <epan/tvbuff.h>
#include <epan/nstime.h>

#define PINFO_FD_NUM(pinfo)       ((pinfo)->fd->num)
#define PINFO_FD_VISITED(pinfo)   ((pinfo)->fd->flags.visited)

/** @todo XXX - some of this stuff is used only while a packet is being dissected;
   should we keep that stuff in the "packet_info" structure, instead, to
   save memory? */

/** The frame number is the ordinal number of the frame in the capture, so
   it's 1-origin.  In various contexts, 0 as a frame number means "frame
   number unknown". */
typedef struct _frame_data {
  GSList      *pfd;         /**< Per frame proto data */
  guint32      num;         /**< Frame number */
  guint32      pkt_len;     /**< Packet length */
  guint32      cap_len;     /**< Amount actually captured */
  guint32      cum_bytes;   /**< Cumulative bytes into the capture */
  gint64       file_off;    /**< File offset */
  guint16      subnum;      /**< subframe number, for protocols that require this */
  gint16       lnk_t;       /**< Per-packet encapsulation/data-link type */
  struct {
    unsigned int passed_dfilter : 1; /**< 1 = display, 0 = no display */
    unsigned int encoding       : 2; /**< Character encoding (ASCII, EBCDIC...) */
    unsigned int visited        : 1; /**< Has this packet been visited yet? 1=Yes,0=No*/
    unsigned int marked         : 1; /**< 1 = marked by user, 0 = normal */
    unsigned int ref_time       : 1; /**< 1 = marked as a reference time frame, 0 = normal */
    unsigned int ignored        : 1; /**< 1 = ignore this frame, 0 = normal */
  } flags;

  const void *color_filter; /**< Per-packet matching color_filter_t object */

  nstime_t     abs_ts;      /**< Absolute timestamp */
  nstime_t     rel_ts;      /**< Relative timestamp (yes, it can be negative) */
  nstime_t     del_dis_ts;  /**< Delta timestamp to previous displayed frame (yes, it can be negative) */
  nstime_t     del_cap_ts;  /**< Delta timestamp to previous captured frame (yes, it can be negative) */

  gchar        **col_text;    /**< The column text for some columns, see colum_utils */
  guint        *col_text_len; /**< The length of the column text strings in 'col_text' */
} frame_data;

/**
 * A data source.
 * Has a tvbuff and a name.
 */
typedef struct {
  tvbuff_t *tvb;
  gboolean name_initialized;
  const char *name;
} data_source;

/* Utility routines used by packet*.c */

extern void p_add_proto_data(frame_data *fd, int proto, void *proto_data);
extern void *p_get_proto_data(frame_data *fd, int proto);
extern void p_remove_proto_data(frame_data *fd, int proto);

/** compare two frame_datas */
extern gint frame_data_compare(const frame_data *fdata1, const frame_data *fdata2, int field);

extern void frame_data_cleanup(frame_data *fdata);

extern void frame_data_init(frame_data *fdata, guint32 num,
                const struct wtap_pkthdr *phdr, gint64 offset,
                guint32 cum_bytes);
/**
 * Sets the frame data struct values before dissection.
 */
extern void frame_data_set_before_dissect(frame_data *fdata,
                nstime_t *elapsed_time,
                nstime_t *first_ts,
                nstime_t *prev_dis_ts,
                nstime_t *prev_cap_ts);

extern void frame_data_set_after_dissect(frame_data *fdata,
                guint32 *cum_bytes,
                nstime_t *prev_dis_ts);

#endif  /* __FRAME_DATA__ */

