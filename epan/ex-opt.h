/** @file
 *
 * eXtension command line options
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include <stdbool.h>

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* will be called by main each time a -X option is found */
/**
 * @brief Adds an option to a hash table.
 *
 * @param ws_optarg The argument string to be added.
 * @return true if the addition is successful, false otherwise.
 */
WS_DLL_PUBLIC bool ex_opt_add(const char* ws_optarg);

/**
 * @brief Counts the number of options associated with a given key.
 *
 * @param key The key for which to count options.
 * @return int The number of options associated with the key, or 0 if no such key exists.
 */
WS_DLL_PUBLIC int ex_opt_count(const char* key);

/**
 * @brief Retrieves the nth option value for a given key.
 *
 * @param key The key to look up in the options hash table.
 * @param key_index The index of the option to retrieve.
 * @return The value of the nth option, or NULL if not found.
 */
WS_DLL_PUBLIC const char* ex_opt_get_nth(const char* key, unsigned key_index);

/**
 * @brief Retrieves and removes the next option value associated with a given key.
 *
 * Note that the caller must free the returned pointer.
 *
 * @param key The key for which to retrieve the next option value.
 * @return char* A pointer to the retrieved option value, or NULL if no more values are available.
 */
WS_DLL_PUBLIC char* ex_opt_get_next(const char* key);

#ifdef __cplusplus
}
#endif /* __cplusplus */
