/* util.h
 * Utility definitions
 *
 * $Id: strutil.h,v 1.3 2000/09/11 23:31:05 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>	/* for u_char */
#endif

#ifdef HAVE_WINSOCK_H
# include <winsock.h>	/* for u_char */
#endif

const u_char *find_line_end(const u_char *data, const u_char *dataend,
    const u_char **eol);
int        get_token_len(const u_char *linep, const u_char *lineend,
    const u_char **next_token);
gchar*     format_text(const u_char *line, int len);


#endif /* __STRUTIL_H__ */
