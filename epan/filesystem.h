/* filesystem.h
 * Filesystem utility definitions
 *
 * $Id: filesystem.h,v 1.2 2000/12/22 22:26:19 nneul Exp $
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

#ifndef FILESYSTEM_H
#define FILESYSTEM_H

/* Returns the user's home directory, via the HOME environment
 * variable, or a default directory if HOME is not set */
const char* get_home_dir(void);

#endif /* FILESYSTEM_H */
