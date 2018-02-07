/* type_util.h
 * Types utility definitions
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TYPE_UTIL_H__
#define __TYPE_UTIL_H__

#include <glib.h>
#include "ws_symbol_export.h"

/*
 * guint64 to gdouble conversions taken from gstutils.h of GStreamer project
 *
 * GStreamer
 * Copyright (C) 1999,2000 Erik Walthinsen <omega@cse.ogi.edu>
 *                    2000 Wim Taymans <wtay@chello.be>
 *                    2002 Thomas Vander Stichele <thomas@apestaart.org>
 *
 * gstutils.h: Header for various utility functions
 *
 * GNU GPL v2
 *
 */

WS_DLL_PUBLIC
guint64         type_util_gdouble_to_guint64(gdouble value);
WS_DLL_PUBLIC
gdouble         type_util_guint64_to_gdouble(guint64 value);

#ifdef _WIN32
#define         gdouble_to_guint64(value)   type_util_gdouble_to_guint64(value)
#define         guint64_to_gdouble(value)   type_util_guint64_to_gdouble(value)
#else
#define         gdouble_to_guint64(value)   ((guint64)(value))
#define         guint64_to_gdouble(value)   ((gdouble)(value))
#endif

#endif /* __TYPE_UTIL_H__ */
