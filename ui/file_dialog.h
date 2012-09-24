/* file_dialog.h
 * Common file dialog definitions
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2006 Gerald Combs
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

#ifndef __FILE_DIALOG_H__
#define __FILE_DIALOG_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum {
  SAVE,
  SAVE_WITHOUT_COMMENTS,
  SAVE_IN_ANOTHER_FORMAT,
  CANCELLED
} check_savability_t;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FILE_DIALOG_H__ */
