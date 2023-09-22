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

/*
 * Handle to a list of features/dependencies.
 * Semi-opaque. Functions which gather the list of features
 * will be passed one of these to use with
 * `with_feature()`/`without_feature()` (below).
 */
typedef GList **feature_list;

/*
 * The format of entries in a feature_list is a char* starting with a
 * '+' or '-' character indicating if the feature is respectively
 * present or absent, followed by the unchanged feature description.
 * This allows the insert order of features to be preserved,
 * while still preserving the present/absent status in a simple way.
 */


/*
 * Pointer to a function which gathers a list of features.
 */
typedef void(*gather_feature_func)(feature_list l);

/*
 * Add an indicator to the given feature_list that the named
 * feature is present.
 */
WS_DLL_PUBLIC
void with_feature(feature_list l, const char *fmt, ...) G_GNUC_PRINTF(2,3);

/*
 * Add an indicator to the given feature_list that the named
 * feature is absent.
 */
WS_DLL_PUBLIC
void without_feature(feature_list l, const char *fmt, ...) G_GNUC_PRINTF(2,3);

/*
 * Sort the given feature list, alphabetically by feature name.
 * (The leading '+' or '-' is not factored into the sort.)
 * Currently unused.
 */
WS_DLL_PUBLIC
void sort_features(feature_list l);

/*
 * Free the memory used by the feature list,
 * and reset its pointer to NULL.
 */
WS_DLL_PUBLIC
void free_features(feature_list l);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WSUTIL_FEATURE_LIST_H__ */
