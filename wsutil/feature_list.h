/** @file
 * Declarations of routines for gathering and handling lists of
 * present/absent features (usually actually dependencies)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSUTIL_FEATURE_LIST_H__
#define __WSUTIL_FEATURE_LIST_H__

#include <glib.h>
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


 /**
 * @brief Semi-opaque handle to a list of features or dependencies.
 *
 * Functions that collect or modify feature sets
 * will receive a `feature_list` handle, which can be updated via
 * `with_feature()` or `without_feature()` calls.
 *
 * @note Ownership and lifetime are managed by the caller; this typedef
 * provides clarity and encapsulation for feature tracking APIs.
 */
typedef GList **feature_list;

/*
 * The format of entries in a feature_list is a char* starting with a
 * '+' or '-' character indicating if the feature is respectively
 * present or absent, followed by the unchanged feature description.
 * This allows the insert order of features to be preserved,
 * while still preserving the present/absent status in a simple way.
 */


/**
 * @brief Pointer to a function which gathers a list of features.
 */
typedef void(*gather_feature_func)(feature_list l);

/**
 * @brief Pointer to a function which gets a version string.
 */
typedef const char* (*get_version_func)(void);



/**
 * @brief Mark a feature as present in the provided list.
 *
 * @param l   Mutable feature list to update.
 * @param fmt Format string describing the feature.
 * @param ... Arguments for the format string.
 */
WS_DLL_PUBLIC
void with_feature(feature_list l, const char *fmt, ...) G_GNUC_PRINTF(2,3);

/**
 * @brief Mark a feature as absent in the given list.
 *
 * @param l   Mutable feature list to update.
 * @param fmt Format string describing the absent feature.
 * @param ... Arguments for the format string.
 */
WS_DLL_PUBLIC
void without_feature(feature_list l, const char *fmt, ...) G_GNUC_PRINTF(2,3);

/**
 * @brief Sort a feature list alphabetically by feature name.
 *
 * Reorders the entries in the given `feature_list` in ascending alphabetical
 * order, ignoring any leading '+' or '-' indicators.
 *
 * @note The function is currently unused.
 *
 * @param l Mutable feature list to be sorted in-place.
 */
WS_DLL_PUBLIC
void sort_features(feature_list l);

/**
 * @brief Split a feature list into present and absent feature subsets.
 *
 * Iterates over the input `feature_list` and separates entries into two
 * output lists: `with_list` for present features (prefixed with '+') and
 * `without_list` for absent features (prefixed with '-'). The prefixes are
 * preserved in the output lists.
 *
 * Both output lists must be empty when first passed to this function.
 *
 * @param l            Input feature list to be partitioned.
 * @param with_list    Output list for present features (prefixed with '+').
 * @param without_list Output list for absent features (prefixed with '-').
 */
WS_DLL_PUBLIC
void separate_features(feature_list l, feature_list with_list, feature_list without_list);

/**
 * @brief Free all memory associated with a feature list.
 *
 * Releases all entries in the given `feature_list` and resets the pointer
 * to `NULL`.
 *
 * @param l Pointer to the feature list to be freed and nulled.
 */
WS_DLL_PUBLIC
void free_features(feature_list l);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WSUTIL_FEATURE_LIST_H__ */
