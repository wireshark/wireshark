/* last_open_dir.h
 * Routines to fetch the last directory in which a file was opened;
 * its implementation is GUI-dependent, but the API isn't
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __UI_LAST_OPEN_DIR_H__
#define __UI_LAST_OPEN_DIR_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** Get the latest opened directory.
 *
 * @return the dirname
 */
extern char *get_last_open_dir(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __UI_LAST_OPEN_DIR_H__ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
