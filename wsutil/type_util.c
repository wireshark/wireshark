/* type_util.c
 * Types utility routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include "type_util.h"

/*
 * uint64_t to double conversions taken from gstutils.c of GStreamer project
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

double
type_util_guint64_to_gdouble(uint64_t value)
{
  if (value & UINT64_C (0x8000000000000000))
    return (double) ((int64_t) value) + (double) 18446744073709551616.;
  else
    return (double) ((int64_t) value);
}

uint64_t
type_util_gdouble_to_guint64(double value)
{
  if (value < (double) 9223372036854775808.)   /* 1 << 63 */
    return ((uint64_t) ((int64_t) value));

  value -= (double) 18446744073709551616.;
  return ((uint64_t) ((int64_t) value));
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
