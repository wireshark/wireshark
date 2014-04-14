/* packet_list_utils.h
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#ifndef __PACKET_LIST_UTILS_H__
#define __PACKET_LIST_UTILS_H__

#include "cfile.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * Check to see if a column should be right justified.
 *
 * @param [in] col The column number.
 * @param [in] cf The capture file containing the packet data.
 *
 * @return TRUE if the column should be right justified, FALSE otherwise.
 */
gboolean right_justify_column (gint col, capture_file *cf);

/**
 * Check to see if a column's data should be resolved.
 *
 * @param [in] col The column number.
 * @param [in] cf The capture file containing the packet data.
 *
 * @return TRUE if resolution is required, FALSE otherwise.
 */
gboolean resolve_column (gint col, capture_file *cf);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __PACKET_LIST_UTILS_H__ */

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
