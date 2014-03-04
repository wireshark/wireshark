/* filters.h
 * Declarations of routines for reading and writing the filters file.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef FILTERS_H
#define FILTERS_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Filter lists.
 */
typedef enum {
	CFILTER_LIST,	        /* capture filter list - saved */
	DFILTER_LIST,	        /* display filter list - saved */
	CFILTER_EDITED_LIST,	/* capture filter list - currently edited */
	DFILTER_EDITED_LIST	/* display filter list - currently edited */
} filter_list_type_t;

/*
 * Item in a list of filters.
 */
typedef struct {
  char *name;		/* filter name */
  char *strval;		/* filter expression */
} filter_def;

/*
 * Read in a list of filters.
 *
 * On success, "*pref_path_return" is set to NULL.
 * On error, "*pref_path_return" is set to point to the pathname of
 * the file we tried to read - it should be freed by our caller -
 * and "*errno_return" is set to the error.
 */
void read_filter_list(filter_list_type_t list_type, char **pref_path_return,
    int *errno_return);

/*
 * Get a pointer to the first entry in a filter list.
 */
GList *get_filter_list_first(filter_list_type_t list);

/*
 * Add a new filter to the end of a list.
 * Returns a pointer to the newly-added entry.
 */
GList *add_to_filter_list(filter_list_type_t list, const char *name,
    const char *expression);

/*
 * Remove a filter from a list.
 */
void remove_from_filter_list(filter_list_type_t list, GList *fl_entry);

/*
 * Write out a list of filters.
 *
 * On success, "*pref_path_return" is set to NULL.
 * On error, "*pref_path_return" is set to point to the pathname of
 * the file we tried to read - it should be freed by our caller -
 * and "*errno_return" is set to the error.
 */
void save_filter_list(filter_list_type_t list_type, char **pref_path_return,
    int *errno_return);

/*
 * Clone the filter list so it can be edited.
 */
void copy_filter_list(filter_list_type_t dest_type, filter_list_type_t src_type);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* FILTERS_H */
