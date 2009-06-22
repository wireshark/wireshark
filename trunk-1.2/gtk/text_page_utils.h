/* text_page.h
 * Declarations of routine to construct a simple text page from a file.
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

#ifndef __TEXT_PAGE_H__
#define __TEXT_PAGE_H__

/** @file
 *  Construct a simple text page widget from a file.
 */

/** Construct a simple text page widget from a file (UTF8 encoded).
 *
 * @param absolute_path the path to the text file
 * @return the new widget
 */
extern GtkWidget * text_page_new(const char *absolute_path);

/** Clear and insert the file content (again).
 *
 * @param page the text_page from text_page_new()
 * @param absolute_path the path to the text file
 */
extern void text_page_redraw(GtkWidget *page, const char *absolute_path);

#endif /* __TEXT_PAGE_H__ */
