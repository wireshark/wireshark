/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _DFILTER_MACRO_H
#define _DFILTER_MACRO_H

#include <wireshark.h>
#include "dfilter.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Represents a display filter macro, including its name, template text, and parsed argument structure.
 */
typedef struct _dfilter_macro_t {
    char*  name;     /**< The macro identifier (name used to invoke the macro). */
    char*  text;     /**< Raw macro template text as read from the macros file. */
    bool   usable;   /**< Whether the macro has been successfully parsed and is ready for use. */
    char** parts;    /**< Array of literal text segments between argument insertion points. */
    int*   args_pos; /**< Array of argument indices indicating what is inserted between each pair of parts. */
    int    argc;     /**< Expected number of arguments the macro accepts. */
    void*  priv;     /**< Private copy of text backing the C-strings stored in parts; owns that memory. */
} dfilter_macro_t;

/**
 * @brief Parses a macro and processes its components.
 *
 * This function takes a pointer to a dfilter_macro_t structure and parses it,
 * extracting parts and arguments as necessary and storing it within the dfilter_macro_t.
 *
 * @param m Pointer to the dfilter_macro_t structure to be parsed.
 */
void macro_parse(dfilter_macro_t *m);

/**
 * @brief Applies macros to a given text.
 *
 * @param text The input text containing macros.
 * @param error Pointer to a df_error_t object for storing errors, if any.
 * @return A new string with macros applied, or NULL on failure.
 */
char* dfilter_macro_apply(const char* text, df_error_t** error);

/**
 * @brief Initialize the dfilter macro system with a given application environment variable prefix.
 *
 * This function initializes the dfilter macro system by creating a new hash table for storing macros and reloading them using the provided prefix.
 *
 * @param app_env_var_prefix The prefix of the application environment variables to use for loading macros.
 */
void dfilter_macro_init(const char* app_env_var_prefix);

/**
 * @brief Reloads dfilter macros from a configuration file.
 *
 * This function reloads dfilter macros by converting an old configuration file if necessary,
 * removing all existing macros, and reading new macros from a filter list.
 *
 * @param app_env_var_prefix The prefix for the application environment variable.
 */
WS_DLL_PUBLIC
void dfilter_macro_reload(const char* app_env_var_prefix);

/**
 * @brief Cleans up the macro table by destroying it and setting the pointer to NULL.
 *
 * This function is responsible for freeing all resources associated with the macro table,
 * including any dynamically allocated memory, and resetting the pointer to ensure that
 * subsequent operations on the macro table will fail gracefully.
 */
void dfilter_macro_cleanup(void);

/**
 * @brief Iterator for traversing the display filter macro hash table.
 */
struct dfilter_macro_table_iter {
    GHashTableIter iter; /**< Underlying GLib hash table iterator used to walk macro table entries. */
};

/**
 * @brief Returns the count of macros in the macro table.
 *
 * This function returns the number of macros currently stored in the macro table.
 *
 * @return The count of macros in the macro table.
 */
WS_DLL_PUBLIC
size_t
dfilter_macro_table_count(void);

/**
 * @brief Initialize an iterator for traversing a macro table.
 *
 * @param iter Pointer to the iterator structure that will be initialized.
 */
WS_DLL_PUBLIC
void
dfilter_macro_table_iter_init(struct dfilter_macro_table_iter *iter);

/**
 * @brief Move to the next macro in the iterator.
 *
 * @param iter Iterator for the macro table.
 * @param name_ptr Pointer to store the name of the current macro, if not NULL.
 * @param text_ptr Pointer to store the text of the current macro, if not NULL.
 * @return true If there is a next macro, false otherwise.
 */
WS_DLL_PUBLIC
bool
dfilter_macro_table_iter_next(struct dfilter_macro_table_iter *iter,
				const char **name_ptr, const char **text_ptr);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _DFILTER_MACRO_H */
