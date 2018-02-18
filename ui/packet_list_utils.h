/* packet_list_utils.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
