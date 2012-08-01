/* iface_lists.h
 * Declarations of routines to manage the global list of interfaces and to
 * update widgets/windows displaying items from those lists
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __IFACE_LISTS_H__
#define __IFACE_LISTS_H__

#ifdef HAVE_LIBPCAP
/*
 * Used when sorting an interface list into alphabetical order by
 * their descriptions.
 */
extern gint if_list_comparator_alph(const void *first_arg, const void *second_arg);

/*
 * Get the global interface list.  Generate it if we haven't
 * done so already.
 */
extern void fill_in_local_interfaces(void);

/*
 * Update the global interface list.
 */
extern void scan_local_interfaces(void);

extern void hide_interface(gchar* new_hide);
#endif /* HAVE_LIBPCAP */

#endif /* __IFACE_LISTS_H__ */
