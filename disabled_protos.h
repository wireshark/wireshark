/* disabled_protos.h
 * Declarations of routines for reading and writing the disabled protocols file.
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
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

/*
 * Item in a list of disabled protocols.
 */
typedef struct {
  char *name;		/* protocol name */
} protocol_def;

/*
 * Read in a list of disabled protocols.
 *
 * On success, "*pref_path_return" is set to NULL.
 * On error, "*pref_path_return" is set to point to the pathname of
 * the file we tried to read - it should be freed by our caller -
 * and "*open_errno_return" is set to the error if we couldn't open the file
 * or "*read_errno_return" is set to the error if we got an error reading
 * the file.
 */
void read_disabled_protos_list(char **gpath_return, int *gopen_errno_return,
			       int *gread_errno_return,
			       char **path_return, int *open_errno_return,
			       int *read_errno_return);

/*
 * Disable protocols as per the stored configuration
 */
void set_disabled_protos_list(void);

/*
 * Write out a list of disabled protocols.
 *
 * On success, "*pref_path_return" is set to NULL.
 * On error, "*pref_path_return" is set to point to the pathname of
 * the file we tried to read - it should be freed by our caller -
 * and "*errno_return" is set to the error.
 */
void save_disabled_protos_list(char **pref_path_return, int *errno_return);
