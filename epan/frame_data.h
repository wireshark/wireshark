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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

/* Types of character encodings */
typedef enum {
	PACKET_CHAR_ENC_CHAR_ASCII	 = 0,	/* ASCII */
	PACKET_CHAR_ENC_CHAR_EBCDIC	 = 1	/* EBCDIC */
} packet_char_enc;

/** The frame number is the ordinal number of the frame in the capture, so
   it's 1-origin.  In various contexts, 0 as a frame number means "frame
   number unknown". */
typedef struct _frame_data {
  GSList      *pfd;          /**< Per frame proto data */
  guint32      num;          /**< Frame number */
  guint32      interface_id; /**< identifier of the interface. */
  guint32      pkt_len;      /**< Packet length */
  guint32      cap_len;      /**< Amount actually captured */
  guint32      cum_bytes;    /**< Cumulative bytes into the capture */
  gint64       file_off;     /**< File offset */
  guint16      subnum;       /**< subframe number, for protocols that require this */
  gint16       lnk_t;        /**< Per-packet encapsulation/data-link type */
  struct {
    unsigned int passed_dfilter : 1; /**< 1 = display, 0 = no display */
    unsigned int dependent_of_displayed : 1; /**< 1 if a displayed frame depends on this frame */
    packet_char_enc encoding    : 1; /**< Character encoding (ASCII, EBCDIC...) */
    unsigned int visited        : 1; /**< Has this packet been visited yet? 1=Yes,0=No*/
    unsigned int marked         : 1; /**< 1 = marked by user, 0 = normal */
    unsigned int ref_time       : 1; /**< 1 = marked as a reference time frame, 0 = normal */
    unsigned int ignored        : 1; /**< 1 = ignore this frame, 0 = normal */
    unsigned int has_ts         : 1; /**< 1 = has time stamp, 0 = no time stamp */
    unsigned int has_if_id      : 1; /**< 1 = has interface ID, 0 = no interface ID */
  } flags;

  const void *color_filter;  /**< Per-packet matching color_filter_t object */

  nstime_t     abs_ts;       /**< Absolute timestamp */
  nstime_t     shift_offset; /**< How much the abs_tm of the frame is shifted */
  nstime_t     rel_ts;       /**< Relative timestamp (yes, it can be negative) */
  const struct _frame_data *prev_dis;   /**< Previous displayed frame */
  const struct _frame_data *prev_cap;   /**< Previous captured frame */
  gchar        *opt_comment; /**< NULL if not available */
} frame_data;

#ifdef WANT_PACKET_EDITOR
/* XXX, where this struct should go? */
typedef struct {
  struct wtap_pkthdr phdr; /**< Modified packet header */
  char *pd;                /**< Modified packet data */
} modified_frame_data;
#endif

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

extern void frame_delta_abs_time(const frame_data *fdata,
                const frame_data *prev, nstime_t *delta);
/**
 * Sets the frame data struct values before dissection.
 */
extern void frame_data_set_before_dissect(frame_data *fdata,
                nstime_t *elapsed_time,
                nstime_t *first_ts,
                const frame_data *prev_dis,
                const frame_data *prev_cap);

extern void frame_data_set_after_dissect(frame_data *fdata,
                guint32 *cum_bytes);

#endif  /* __FRAME_DATA__ */
