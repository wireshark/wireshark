/* g_gnuc_malloc.h
 * Definitions of macro to conditionally do GCC malloc optimization
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __G_GNUC_MALLOC_H__
#define __G_GNUC_MALLOC_H__

/**
 * GLib 2.6 has the ability to enable better optimization of malloc functions.
 * Hide the differences between different glib versions in this G_GNUC_MALLOC macro.
 */
#if ! GLIB_CHECK_VERSION(2,6,0)
	#define G_GNUC_MALLOC
#endif

#endif /* g_gnuc_malloc.h */
