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
 * Capture filter file name.
 */
#define CFILTER_FILE_NAME     "cfilters"

/*
 * Display filter file name.
 */
#define DFILTER_FILE_NAME     "dfilters"

/*
 * Display filter file name.
 */
#define DMACROS_FILE_NAME     "dmacros"

/*
 * Filter lists.
 */
typedef enum {
    CFILTER_LIST,        /* capture filter list - saved */
    DFILTER_LIST,        /* display filter list - saved */
    DMACROS_LIST,        /* display filter macro list - saved */
} filter_list_type_t;

/*
 * Item in a list of filters.
 */
typedef struct {
    char *name;          /* filter name */
    char *strval;        /* filter expression */
} filter_def;

typedef struct {
    filter_list_type_t type;
    GList *list;
} filter_list_t;

/*
 * Read in a list of filters.
 *
 * On error, report the error via the UI.
 */
WS_DLL_PUBLIC
WS_RETNONNULL
filter_list_t *ws_filter_list_read(filter_list_type_t list_type);

/*
 * Add a new filter to the end of a list.
 * Returns a pointer to the newly-added entry.
 */
WS_DLL_PUBLIC
void ws_filter_list_add(filter_list_t *list, const char *name,
                          const char *expression);

/*
 * Find a filter in a list by name.
 * Returns a pointer to the found entry.
 */
WS_DLL_PUBLIC
GList *ws_filter_list_find(filter_list_t *list, const char *name);

/*
 * Remove a filter from a list.
 */
WS_DLL_PUBLIC
bool ws_filter_list_remove(filter_list_t *list, const char *name);

/*
 * Write out a list of filters.
 *
 * On error, report the error via the UI.
 */
WS_DLL_PUBLIC
void ws_filter_list_write(filter_list_t *list);

/*
 * Free all filter lists
 */
WS_DLL_PUBLIC
void ws_filter_list_free(filter_list_t *list);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FILTER_FILES_H__ */
