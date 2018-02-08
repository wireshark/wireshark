/* garrayfix.h
 * Macros to work around the "data" field of a GArray having type guint8 *,
 * rather than void *, so that, even though the GArray code should be
 * ensuring that the data is aligned strictly enough for any data type,
 * we still get warnings with -Wcast-align.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2007 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __GARRAYFIX_H__
#define __GARRAYFIX_H__

#ifdef g_array_index
#undef g_array_index
#define g_array_index(a,t,i)      (((t*) (void*) (a)->data) [(i)])
#endif

#define g_array_data(a)	((void*) (a)->data)

#endif /* __GARRAYFIX_H__ */
