/* strptime.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __STRPTIME_H__
#define __STRPTIME_H__

#include "ws_symbol_export.h"

/*
 * Version of "strptime()", for the benefit of OSes that don't have it.
 */
WS_DLL_PUBLIC char *strptime(const char *, const char *, struct tm *);

#endif
