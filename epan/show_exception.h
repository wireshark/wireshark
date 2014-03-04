/* show_exception.h
 *
 * Routines to put exception information into the protocol tree
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2000 Gerald Combs
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

/*
 * Called to register the pseudo-protocols used for exceptions.
 */
void register_show_exception(void);

/*
 * Routine used to add an indication of an arbitrary exception to the tree.
 */
WS_DLL_PUBLIC
void show_exception(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    unsigned long exception, const char *exception_message);

/*
 * Routine used to add an indication of a ReportedBoundsError exception
 * to the tree.
 */
void
show_reported_bounds_error(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
