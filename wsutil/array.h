/** @file
 * Utility functions/macros for handling arrays, C and/or glib.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSUTIL_ARRAY_H__
#define __WSUTIL_ARRAY_H__

/** Useful when you have an array whose size is known at compile-time. */
#define array_length(x)	(sizeof (x) / sizeof (x)[0])

/** glib doesn't have g_ptr_array_len, of all things! */
#ifndef g_ptr_array_len
#define g_ptr_array_len(a)      ((a) ? (a)->len : 0)
#endif

#endif /* __WSUTIL_ARRAY_H__ */
