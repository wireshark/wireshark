/** @file
 * Routines for parsing media type parameters as per RFC 822 and RFC 2045
 * Copyright 2004, Anders Broman.
 * Copyright 2004, Olivier Biot.
 *
 * Refer to the AUTHORS file or the AUTHORS section in the man page
 * for contacting the author(s) of this file.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include <epan/wmem_scopes.h>

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Finds a media type parameter in a given set of parameters.
 *
 * Searches for a parameter with a specified key within a string containing multiple parameters.
 *
 * @param scope Memory allocator scope.
 * @param parameters String containing the parameters to search through.
 * @param key The key of the parameter to find.
 * @return Pointer to the value of the found parameter, or NULL if not found.
 */
WS_DLL_PUBLIC char *
ws_find_media_type_parameter(wmem_allocator_t *scope, const char *parameters, const char *key);

#ifdef __cplusplus
}
#endif /* __cplusplus */
