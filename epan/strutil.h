/* strutil.h
 * String utility definitions
 *
 * $Id: strutil.h,v 1.10 2003/07/04 03:41:00 gram Exp $
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

#ifndef __STRUTIL_H__
#define __STRUTIL_H__

/* ... thus, config.h needs to be #included */

const guchar *find_line_end(const guchar *data, const guchar *dataend,
    const guchar **eol);
int        get_token_len(const guchar *linep, const guchar *lineend,
    const guchar **next_token);
gchar*     format_text(const guchar *line, int len);
gchar*     bytes_to_str(const guint8 *, int);
gchar*     bytes_to_str_punct(const guint8 *, int, gchar punct);

/* Surround a string or a macro, resolved to a string, with double quotes */
#define _STRINGIFY(a)           # a
#define STRINGIFY(a)            _STRINGIFY(a)

#endif /* __STRUTIL_H__ */
