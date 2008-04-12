/* compat_macros.h
 * GTK-related Global defines, etc.
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

#ifndef __COMPAT_MACROS_H__
#define __COMPAT_MACROS_H__


/** @file
 *
 * Helper macros for gtk1.x / gtk2.x compatibility. Use these macros instead of the GTK deprecated functions,
 * to keep compatibility between GTK 1.x and 2.x.
 * For example in gtk2.x, gtk_signal_xxx is deprecated in favor of g_signal_xxx,
 *          gtk_object_xxx is deprecated in favor of g_object_xxx,
 *          gtk_widget_set_usize is deprecated in favor of
 *              gtk_widget_set_size_request, ...
 */

/* for details, see "Pango Text Attribute Markup" */
/* maybe it's a good idea to keep this macro beyond the ongoing GTK1 cleanup!
   If we want to change the look of the dialog boxes primary line the other day,
   we can easily do so, without changing lot's of places */
/* XXX - moving it to a better place (file) might be a good idea anyway */
#define PRIMARY_TEXT_START "<span weight=\"bold\" size=\"larger\">"
#define PRIMARY_TEXT_END "</span>"

#endif /* __COMPAT_MACROS_H__ */
