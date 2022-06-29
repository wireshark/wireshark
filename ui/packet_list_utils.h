/** @file
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

/**
 * @brief The following methods have to be implemented by any class that
 * whishes to represent a packet list.
 */

/** Write all packet list geometry values to the recent file.
 *
 *  @param rf recent file handle from caller
 */
extern void packet_list_recent_write_all(FILE *rf);

extern void packet_list_clear(void);
extern void packet_list_freeze(void);
extern void packet_list_recreate_visible_rows(void);
extern void packet_list_thaw(void);
extern guint packet_list_append(column_info *cinfo, frame_data *fdata);
extern void packet_list_queue_draw(void);
extern gboolean packet_list_select_row_from_data(frame_data *fdata_needle);
extern gboolean packet_list_multi_select_active(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __PACKET_LIST_UTILS_H__ */
