/* filters.c
 * Declarations of routines for reading and writing the filters file.
 *
 * $Id: filters.h,v 1.1 2001/01/28 04:43:24 guy Exp $
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

/*
 * List of filters.
 */
extern GList       *fl;

/*
 * Item in a list of filters.
 */
typedef struct {
  char *name;		/* filter name */
  char *strval;		/* filter expression */
} filter_def;

void get_filter_list(void);

void save_filter_list(void);
