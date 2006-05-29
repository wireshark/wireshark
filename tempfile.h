/* tempfile.h
 * Declarations of routines to create temporary files
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

#ifndef __TEMPFILE_H__
#define __TEMPFILE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* create a tempfile with the given prefix (e.g. "ether")
 * namebuf (and namebuflen) should be 128+1 bytes long (BTW: why?)
 * returns the file descriptor of the new tempfile and
 * the name of the new file in namebuf 
 */
int create_tempfile(char *namebuf, int namebuflen, const char *pfx);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TEMPFILE_H__ */
