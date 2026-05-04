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

#include <epan/cfile.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Check to see if a column should be right justified.
 *
 * @param [in] col The column number.
 * @param [in] cf The capture file containing the packet data.
 *
 * @return true if the column should be right justified, false otherwise.
 */
bool right_justify_column (int col, capture_file *cf);

/**
 * @brief Check to see if a column's data can be displayed as strings.
 *
 * @param [in] col The column number.
 * @param [in] cf The capture file containing the packet data.
 *
 * @return true if name displayed as strings is allowed, false otherwise.
 */
bool display_column_strings (int col, capture_file *cf);

/**
 * @brief Check to see if a column's data can be displayed as packet details.
 *
 * @param [in] col The column number.
 * @param [in] cf The capture file containing the packet data.
 *
 * @return true if displayed as details is allowed, false otherwise.
 */
bool display_column_details (int col, capture_file *cf);

/**
 * @brief The following methods have to be implemented by any class that
 * whishes to represent a packet list.
 */

/**
 * @brief Write all packet list geometry values to the recent file.
 *
 * @param rf recent file handle from caller
 */
extern void packet_list_recent_write_all(FILE *rf);

/**
 * @brief Clears the current packet list.
 */
extern void packet_list_clear(void);

/**
 * @brief Freeze the packet list.
 *
 * This function is used to freeze the packet list, preventing any updates or modifications until it is thawed.
 */
extern void packet_list_freeze(void);

/**
 * @brief Recreate the visible rows in the packet list.
 *
 * This function is called to recreate the visible rows in the packet list, typically after changes have been made to the underlying data.
 */
extern void packet_list_recreate_visible_rows(void);

/**
 * @brief Indicates that the visible rows in the packet list need to be recreated.
 *
 * This function is called to signal that the visible rows in the packet list need to be recreated, typically after changes have been made to the underlying data.
 */
extern void packet_list_need_recreate_visible_rows(void);

/**
 * @brief Thaw the packet list.
 *
 * This function is used to thaw the packet list, allowing further modifications and updates.
 */
extern void packet_list_thaw(void);

/**
 * @brief Recreates visible rows in the packet list.
 *
 * This function is called to recreate the visible rows in the packet list.
 */
extern unsigned packet_list_append(column_info *cinfo, frame_data *fdata);

/**
 * @brief Queue a redraw of the packet list.
 */
extern void packet_list_queue_draw(void);

/**
 * @brief Select a row in the packet list based on frame data.
 *
 * This function selects a row in the packet list that corresponds to the provided frame data.
 *
 * @param fdata_needle The frame data used to identify the row to select.
 * @return true if a matching row was found and selected, false otherwise.
 */
extern bool packet_list_select_row_from_data(frame_data *fdata_needle);

/**
 * @brief Select a field in the packet list based on field information.
 *
 * This function selects a field in the packet list that corresponds to the provided field information.
 *
 * @param fi The field information used to identify the field to select.
 * @return true if a matching field was found and selected, false otherwise.
 */
extern bool packet_list_select_finfo(field_info *fi);

/**
 * @brief Check if multi-selection is active in the packet list.
 *
 * @return true if multi-selection is active, false otherwise.
 */
extern bool packet_list_multi_select_active(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __PACKET_LIST_UTILS_H__ */
