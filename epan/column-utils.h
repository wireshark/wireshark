/* column-utils.h
 * Definitions for column utility structures and routines
 *
 * $Id: column-utils.h,v 1.6 2002/01/29 08:44:49 guy Exp $
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

#ifndef __COLUMN_UTILS_H__
#define __COLUMN_UTILS_H__

#include <glib.h>

#define COL_MAX_LEN 256
#define COL_MAX_INFO_LEN 4096

#include "column_info.h"
#include "packet_info.h"

/* Allocate all the data structures for constructing column data, given
   the number of columns. */
extern void	col_init(column_info *, gint);

/* Utility routines used by packet*.c */

extern void	col_set_writable(column_info *, gboolean);
extern gint	check_col(column_info *, gint);
extern void	col_clear(column_info *, gint);
extern void	col_set_str(column_info *, gint, gchar *);
#if __GNUC__ >= 2
extern void	col_add_fstr(column_info *, gint, gchar *, ...)
    __attribute__((format (printf, 3, 4)));
extern void	col_append_fstr(column_info *, gint, gchar *, ...)
    __attribute__((format (printf, 3, 4)));
extern void	col_prepend_fstr(column_info *, gint, gchar *, ...)
    __attribute__((format (printf, 3, 4)));
#else
extern void	col_add_fstr(column_info *, gint, gchar *, ...);
extern void	col_append_fstr(column_info *, gint, gchar *, ...);
extern void	col_prepend_fstr(column_info *, gint, gchar *, ...);
#endif
extern void	col_add_str(column_info *, gint, const gchar *);
extern void	col_append_str(column_info *, gint, gchar *);
extern void	col_set_cls_time(frame_data *, column_info *, int);
extern void	fill_in_columns(packet_info *);

#endif /* __COLUMN_UTILS_H__ */
