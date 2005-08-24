/* frame_data.h
 * Definitions for frame_data structures and routines
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

#ifndef __FRAME_DATA_H__
#define __FRAME_DATA_H__

#include "column_info.h"
#include "tvbuff.h"
#include <epan/nstime.h>

#if 0
/* Defined in color.h */
#ifndef __COLOR_H__
typedef struct _color_t /* {
	guint32 pixel;
	guint16 red;
	guint16 green;
	guint16 blue;
} */ color_t;
#endif
#endif

/* XXX - some of this stuff is used only while a packet is being dissected;
   should we keep that stuff in the "packet_info" structure, instead, to
   save memory? */
typedef struct _frame_data {
  struct _frame_data *next; /* Next element in list */
  struct _frame_data *prev; /* Previous element in list */
  GSList      *pfd;         /* Per frame proto data */
  guint32      num;         /* Frame number */
  guint32      pkt_len;     /* Packet length */
  guint32      cap_len;     /* Amount actually captured */
  guint32      cum_bytes;   /* Cumulative bytes into the capture */
  nstime_t     abs_ts;      /* Absolute timestamp */
  nstime_t     rel_ts;      /* Relative timestamp (yes, it can be negative) */
  nstime_t     del_ts;      /* Delta timestamp (yes, it can be negative) */
  long         file_off;    /* File offset */
  int          lnk_t;       /* Per-packet encapsulation/data-link type */
  struct {
	unsigned int passed_dfilter	: 1; /* 1 = display, 0 = no display */
  	unsigned int encoding		: 2; /* Character encoding (ASCII, EBCDIC...) */
	unsigned int visited		: 1; /* Has this packet been visited yet? 1=Yes,0=No*/
	unsigned int marked             : 1; /* 1 = marked by user, 0 = normal */
	unsigned int ref_time		: 1; /* 1 = marked as a reference time frame, 0 = normal */
  } flags;
  void *color_filter;       /* Per-packet matching color_filter_t object */
} frame_data;

/*
 * A data source.
 * Has a tvbuff and a name.
 */
typedef struct {
  tvbuff_t *tvb;
  char *name;
} data_source;

/* Utility routines used by packet*.c */

extern void p_add_proto_data(frame_data *, int, void *);
extern void *p_get_proto_data(frame_data *, int);
extern void p_rem_proto_data(frame_data *fd, int proto);

#endif  /* __FRAME_DATA__ */
