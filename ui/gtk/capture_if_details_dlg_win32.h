/* capture_if_details_dlg.h
 * Definitions for capture interface details window (only Win32!)
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

#ifndef __CAPTURE_IF_DETAILS_DLG_H__
#define __CAPTURE_IF_DETAILS_DLG_H__

/** @file
 *  Capture "Interface Details" dialog box
 *  @ingroup dialog_group
 */

/** Open the dialog box.
 *
 * @param iface the interface name to show
 */
extern void capture_if_details_open(char *iface);

/** See if we have a detail-able interface.
 *
 * @param iface the interface name to test
 */
extern gboolean capture_if_has_details(char *iface);

#endif /* __CAPTURE_IF_DETAILS_DLG_H__ */
