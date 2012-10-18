/* export_object.h
 * Common routines for tracking & saving objects found in streams of data
 * Copyright 2007, Stephen Fisher (see AUTHORS file)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#ifndef __EXPORT_OBJECT_DLG_H__
#define __EXPORT_OBJECT_DLG_H__

/* Protocol specific */
void eo_dicom_cb(GtkWidget *widget _U_, gpointer data _U_);
void eo_http_cb(GtkWidget *widget _U_, gpointer data _U_);
void eo_smb_cb(GtkWidget *widget _U_, gpointer data _U_);

#endif /* __EXPORT_OBJECT_DLG_H__ */
