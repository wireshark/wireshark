/** @file
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

#include <inttypes.h>
#include "ws_symbol_export.h"

/*
 * uint64_t to double conversions taken from gstutils.h of GStreamer project
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

/**
 * @brief Converts a double-precision floating-point value to a 64-bit unsigned integer.
 *
 * Safely casts a `double` to a `uint64_t`, truncating any fractional part.
 *
 * @param value The double value to convert.
 * @return The corresponding `uint64_t` value.
 */
WS_DLL_PUBLIC
uint64_t type_util_double_to_uint64(double value);

/**
 * @brief Converts a 64-bit unsigned integer to a double-precision floating-point value.
 *
 * Casts a `uint64_t` to a `double`, preserving the full integer value.
 *
 * @param value The `uint64_t` value to convert.
 * @return The corresponding `double` value.
 */
WS_DLL_PUBLIC
double type_util_uint64_to_double(uint64_t value);

#ifdef _WIN32
#define         double_to_uint64(value)   type_util_double_to_uint64(value)
#define         uint64_to_double(value)   type_util_uint64_to_double(value)
#else
#define         double_to_uint64(value)   ((uint64_t)(value))
#define         uint64_to_double(value)   ((double)(value))
#endif

#endif /* __TYPE_UTIL_H__ */
