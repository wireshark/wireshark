/* media_params.h
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

#ifndef __MEDIA_PARAMS_H__
#define __MEDIA_PARAMS_H__

#include <epan/wmem/wmem.h>

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

WS_DLL_PUBLIC char *
ws_find_media_type_parameter(wmem_allocator_t *scope, const char *parameters, const char *key);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* media_params.h */
