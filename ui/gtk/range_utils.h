/* range_utils.h
 * Declarations of utilities to with range_utils.c (packet range dialog)
 *
 * $Id$
 *
 * Ulf Lamping <ulf.lamping@web.de>
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

#ifndef __RANGE_UTILS_H__
#define __RANGE_UTILS_H__

/** @file
 *  Packet range widget used for example in the "Save" and "Print" dialogs.
 */

/** Check the validity of a packet_range_t, and put up an alert box if
 ** it's not valid.
 *
 * @param range the range to check
 * @return a Boolean that's TRUE if it's valid and FALSE if it isn't
 */
extern gboolean range_check_validity(packet_range_t *range);

/** Create a new range widget.
 *
 * @param range the range to set
 * @param saving TRUE if range is selecting packets to save
 * @return the new range widget
 */
extern GtkWidget *range_new(packet_range_t *range, gboolean saving);

/* Update all "dynamic" range things.
 *
 * @param data range widget
 */
extern void range_update_dynamics(gpointer data);

#endif
