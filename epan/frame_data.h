/* frame_data.h
 * Definitions for frame_data structures and routines
 *
 * $Id: frame_data.h,v 1.4 2002/02/18 01:08:41 guy Exp $
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

/* XXX - some of this stuff is used only while a packet is being dissected;
   should we keep that stuff in the "packet_info" structure, instead, to
   save memory? */
typedef struct _frame_data {
  struct _frame_data *next; /* Next element in list */
  struct _frame_data *prev; /* Previous element in list */
  GSList      *pfd;         /* Per frame proto data */
  GSList      *data_src;    /* Frame data sources */
  guint32      num;         /* Frame number */
  guint32      pkt_len;     /* Packet length */
  guint32      cap_len;     /* Amount actually captured */
  gint32       rel_secs;    /* Relative seconds (yes, it can be negative) */
  gint32       rel_usecs;   /* Relative microseconds (yes, it can be negative) */
  guint32      abs_secs;    /* Absolute seconds */
  guint32      abs_usecs;   /* Absolute microseconds */
  gint32       del_secs;    /* Delta seconds (yes, it can be negative) */
  gint32       del_usecs;   /* Delta microseconds (yes, it can be negative) */
  long         file_off;    /* File offset */
  int          lnk_t;       /* Per-packet encapsulation/data-link type */
  struct {
	unsigned int passed_dfilter	: 1; /* 1 = display, 0 = no display */
  	unsigned int encoding		: 2; /* Character encoding (ASCII, EBCDIC...) */
	unsigned int visited		: 1; /* Has this packet been visited yet? 1=Yes,0=No*/
	unsigned int marked             : 1; /* 1 = marked by user, 0 = normal */
  } flags;
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

void       p_add_proto_data(frame_data *, int, void *);
void       *p_get_proto_data(frame_data *, int);

/* An init routine to be called by epan_init */
void frame_data_init(void);

/* A cleanup routine to be called by epan_cleanup */
void frame_data_cleanup(void);

#endif  /* __FRAME_DATA__ */
