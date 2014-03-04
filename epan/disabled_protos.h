/* disabled_protos.h
 * Declarations of routines for reading and writing the disabled protocols file.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef DISABLED_PROTOS_H
#define DISABLED_PROTOS_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

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
WS_DLL_PUBLIC void
read_disabled_protos_list(char **gpath_return, int *gopen_errno_return,
			  int *gread_errno_return,
			  char **path_return, int *open_errno_return,
			  int *read_errno_return);

/*
 * Disable protocols as per the stored configuration
 */
WS_DLL_PUBLIC void
set_disabled_protos_list(void);

/*
 * Write out a list of disabled protocols.
 *
 * On success, "*pref_path_return" is set to NULL.
 * On error, "*pref_path_return" is set to point to the pathname of
 * the file we tried to read - it should be freed by our caller -
 * and "*errno_return" is set to the error.
 */
WS_DLL_PUBLIC void
save_disabled_protos_list(char **pref_path_return, int *errno_return);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* DISABLED_PROTOS_H */
