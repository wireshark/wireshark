/* copyright_info.h
 * Declarations of outines to report copyright information for stuff used
 * by Wireshark
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSUTIL_COPYRIGHT_INFO_H__
#define __WSUTIL_COPYRIGHT_INFO_H__

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Get copyright information.
 */
WS_DLL_PUBLIC const char *get_copyright_info(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WSUTIL_COPYRIGHT_INFO_H__ */
