/* summary.h
 * Definitions for capture file summary windows
 *
 * $Id: summary.h,v 1.2 1999/07/07 22:52:00 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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

#ifndef __SUMMARY_H__
#define __SUMMARY_H__

typedef struct _summary_tally {
    guint32  bytes;
    double  start_time;
    double  stop_time;
    guint32  filtered_count;
} summary_tally;



void   summary_prep_cb(GtkWidget *, gpointer);
void   summary_prep_close_cb(GtkWidget *, gpointer);

#endif /* summary.h */





