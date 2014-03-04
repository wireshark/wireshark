/* type_util.c
 * Types utility routines
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

#include "config.h"

#include <glib.h>
#include "type_util.h"

/*
 * guint64 to gdouble conversions taken from gstutils.c of GStreamer project
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

/* work around error C2520: conversion from unsigned __int64 to double
 * not implemented, use signed __int64
 *
 * These are implemented as functions because on some platforms a 64bit int to
 * double conversion is not defined/implemented.
 */

gdouble
type_util_guint64_to_gdouble(guint64 value)
{
  if (value & G_GINT64_CONSTANT (0x8000000000000000))
    return (gdouble) ((gint64) value) + (gdouble) 18446744073709551616.;
  else
    return (gdouble) ((gint64) value);
}

guint64
type_util_gdouble_to_guint64(gdouble value)
{
  if (value < (gdouble) 9223372036854775808.)   /* 1 << 63 */
    return ((guint64) ((gint64) value));

  value -= (gdouble) 18446744073709551616.;
  return ((guint64) ((gint64) value));
}
