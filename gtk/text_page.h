/* text_page.h
 * Declarations of routine to construct a simple text page from a file.
 *
 * $Id: text_page.h,v 1.3 2004/06/03 14:54:26 ulfl Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 *  @todo move this and the implementation to ui_util.
 */

/** Construct a simple text page widget from a file (UTF8 encoded).
 *
 * @param absolute_path the path to the text file
 * @return the new widget
 */
extern GtkWidget * text_page_new(const char *absolute_path);

#endif /* __TEXT_PAGE_H__ */
