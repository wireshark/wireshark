/* range.h
 * Packet range routines (save, print, ...)
 *
 * $Id: range.h,v 1.8 2004/01/09 18:10:40 ulfl Exp $
 *
 * Dick Gooris <gooris@lucent.com>
 * Ulf Lamping <ulf.lamping@web.de>
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

#ifndef __PRINT_RANGE_H__
#define __PRINT_RANGE_H__

#include <glib.h>

#include <epan/frame_data.h>

extern guint32  curr_selected_frame;

typedef enum {
    range_process_all,
    range_process_selected,
    range_process_marked,
    range_process_marked_range,
    range_process_user_range
} packet_range_e;

/* Range parser variables */
#define MaxRange  30

typedef struct range_admin_tag {
    guint32 low;
    guint32 high;
} range_admin_t;


typedef struct packet_range_tag {
    /* values coming from the UI */
    packet_range_e  process;            /* which range to process */
    gboolean        process_filtered;   /* captured or filtered packets */

    /* user specified range(s) */
    guint           nranges;        /* number of entries in ranges (0 based) */
    range_admin_t   ranges[MaxRange];

    /* calculated values */
    guint32  selected_packet;       /* the currently selected packet */

    /* current packet counts (captured) */
    /* cfile.count */               /* packets in capture file */
    /* cfile.marked_count */        /* packets marked */
    guint32  mark_range_cnt;        /* packets in marked range */
    guint32  user_range_cnt;        /* packets in user specified range */

    /* current packet counts (displayed) */
    guint32  displayed_cnt;
    guint32  displayed_marked_cnt;
    guint32  displayed_mark_range_cnt;
    guint32  displayed_user_range_cnt;

    /* "enumeration" values */
    gboolean marked_range_active;   /* marked range is currently processed */
    guint32  marked_range_left;     /* marked range packets left to do */
    gboolean selected_done;         /* selected packet already processed */
} packet_range_t;

typedef enum {
    range_process_this,             /* process this packet */
    range_process_next,             /* skip this packet, process next */
    range_processing_finished       /* stop processing, required packets done */
} range_process_e;

/* init the range structure */
extern void packet_range_init(packet_range_t *range);

/* init the processing run */
void packet_range_process_init(packet_range_t *range);

/* do we have to process all packets? */
extern gboolean packet_range_process_all(packet_range_t *range);

/* do we have to process this packet? */
extern range_process_e packet_range_process_packet(packet_range_t *range, frame_data *fdata);

/* convert user given string to the internal user specified range representation */
extern void packet_range_convert_str(packet_range_t *range, const gchar *es);


#endif /* __PRINT_RANGE_H__ */
