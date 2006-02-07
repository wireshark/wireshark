/*
 *  ex-opt.h
 *
 * eXtension command line options
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
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

#ifndef _EX_OPT_H
#define _EX_OPT_H

/* will be called by main each time a -X option is found */
extern gboolean ex_opt_add(const gchar* optarg);

/* yields the number of arguments of a given key obviously returns 0 if there aren't */
extern gint ex_opt_count(const gchar* key);

/* fetches the nth argument of a given key returns NULL if there isn't */
extern const gchar* ex_opt_get_index(const gchar* key, guint index);

/* extracts the next value of a given key */
extern const gchar* ex_opt_get_next(const gchar* key);

#endif