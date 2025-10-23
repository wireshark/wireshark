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

/**
 * @enum filter_list_type_t
 * @brief Types of filter lists supported.
 *
 * Represents the category of filters being managed or persisted.
 */
typedef enum {
    CFILTER_LIST, /**< Capture filter list (saved) */
    DFILTER_LIST, /**< Display filter list (saved) */
    DMACROS_LIST  /**< Display filter macro list (saved) */
} filter_list_type_t;

/**
 * @struct filter_def
 * @brief Represents a single filter entry.
 *
 * Contains the name and expression of a filter used in capture or display operations.
 */
typedef struct {
    char *name;    /**< Filter name */
    char *strval;  /**< Filter expression string */
} filter_def;

/**
 * @struct filter_list_t
 * @brief Represents a list of filters of a specific type.
 *
 * Holds a collection of filters and metadata about the list type.
 */
typedef struct {
    filter_list_type_t type; /**< Type of filter list */
    GList *list;             /**< List of filter_def entries */
} filter_list_t;

/**
 * @brief Reads a list of filters from persistent storage.
 *
 * Loads the specified type of filter list (e.g., display, capture) from disk or configuration.
 * On error, a message is reported via the UI.
 *
 * @param list_type The type of filter list to read.
 * @return A pointer to the loaded filter list. Never returns NULL.
 */
WS_DLL_PUBLIC
WS_RETNONNULL
filter_list_t *ws_filter_list_read(filter_list_type_t list_type);

/**
 * @brief Adds a new filter to the end of a filter list.
 *
 * Appends a filter with the given name and expression to the specified list.
 *
 * @param list The filter list to modify.
 * @param name The name of the new filter.
 * @param expression The filter expression (e.g., display or capture syntax).
 */
WS_DLL_PUBLIC
void ws_filter_list_add(filter_list_t *list, const char *name,
                        const char *expression);

/**
 * @brief Finds a filter in a list by name.
 *
 * Searches the filter list for an entry matching the given name.
 *
 * @param list The filter list to search.
 * @param name The name of the filter to find.
 * @return A pointer to the matching filter entry, or NULL if not found.
 */
WS_DLL_PUBLIC
GList *ws_filter_list_find(filter_list_t *list, const char *name);

/**
 * @brief Removes a filter from a list by name.
 *
 * Deletes the filter entry with the specified name from the list.
 *
 * @param list The filter list to modify.
 * @param name The name of the filter to remove.
 * @return true if the filter was found and removed, false otherwise.
 */
WS_DLL_PUBLIC
bool ws_filter_list_remove(filter_list_t *list, const char *name);

/**
 * @brief Writes a filter list to persistent storage.
 *
 * Saves the current filter list to disk or configuration. On error, a message is reported via the UI.
 *
 * @param list The filter list to write.
 */
WS_DLL_PUBLIC
void ws_filter_list_write(filter_list_t *list);

/**
 * @brief Frees all memory associated with a filter list.
 *
 * Cleans up and releases resources used by the filter list.
 *
 * @param list The filter list to free.
 */
WS_DLL_PUBLIC
void ws_filter_list_free(filter_list_t *list);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FILTER_FILES_H__ */
