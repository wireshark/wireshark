/* type_util.h
 * Types utility definitions
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __TYPE_UTIL_H__
#define __TYPE_UTIL_H__

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
