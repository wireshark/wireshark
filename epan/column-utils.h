/* column-utils.h
 * Definitions for column utility structures and routines
 *
 * $Id: column-utils.h,v 1.1 2001/04/01 07:32:35 hagbard Exp $
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


#ifndef __COLUMN_UTILS_H__
#define __COLUMN_UTILS_H__

#include <glib.h>

#define COL_MAX_LEN 256
#define COL_MAX_INFO_LEN 4096

#include "column_info.h"
#include "frame_data.h"

/* Allocate all the data structures for constructing column data, given
   the number of columns. */
void                 col_init(column_info *, gint);

/* Utility routines used by packet*.c */

void	   col_set_writable(frame_data *fd, gboolean writable);
gint       check_col(frame_data *, gint);
void       col_clear(frame_data *, gint);
void       col_set_str(frame_data *, gint, gchar *);
#if __GNUC__ == 2
void       col_add_fstr(frame_data *, gint, gchar *, ...)
    __attribute__((format (printf, 3, 4)));
void       col_append_fstr(frame_data *, gint, gchar *, ...)
    __attribute__((format (printf, 3, 4)));
#else
void       col_add_fstr(frame_data *, gint, gchar *, ...);
void       col_append_fstr(frame_data *, gint, gchar *, ...);
#endif
void       col_add_str(frame_data *, gint, const gchar *);
void       col_append_str(frame_data *, gint, gchar *);
void       col_set_cls_time(frame_data *, int);
void       fill_in_columns(frame_data *);

#endif /* __COLUMN_UTILS_H__ */



