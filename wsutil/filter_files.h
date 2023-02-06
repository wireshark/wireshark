/** @file
 *
 * Declarations of routines for reading and writing the filters file.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __FILTER_FILES_H__
#define __FILTER_FILES_H__

#include <wireshark.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Old filter file name.
 */
#define FILTER_FILE_NAME      "filters"

/*
 * Capture filter file name.
 */
#define CFILTER_FILE_NAME     "cfilters"

/*
 * Display filter file name.
 */
#define DFILTER_FILE_NAME     "dfilters"

/*
 * Filter lists.
 */
typedef enum {
    CFILTER_LIST,        /* capture filter list - saved */
    DFILTER_LIST        /* display filter list - saved */
} filter_list_type_t;

/*
 * Item in a list of filters.
 */
typedef struct {
    char *name;          /* filter name */
    char *strval;        /* filter expression */
} filter_def;

/*
 * Read in a list of filters.
 *
 * On error, report the error via the UI.
 */
WS_DLL_PUBLIC
void read_filter_list(filter_list_type_t list_type);

/*
 * Get a pointer to the first entry in a filter list.
 */
WS_DLL_PUBLIC
GList *get_filter_list_first(filter_list_type_t list);

/*
 * Add a new filter to the end of a list.
 * Returns a pointer to the newly-added entry.
 */
WS_DLL_PUBLIC
GList *add_to_filter_list(filter_list_type_t list, const char *name,
                          const char *expression);

/*
 * Remove a filter from a list.
 */
WS_DLL_PUBLIC
void remove_from_filter_list(filter_list_type_t list, GList *fl_entry);

/*
 * Write out a list of filters.
 *
 * On error, report the error via the UI.
 */
WS_DLL_PUBLIC
void save_filter_list(filter_list_type_t list_type);

/*
 * Free all filter lists
 */
WS_DLL_PUBLIC
void free_filter_lists(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FILTER_FILES_H__ */
