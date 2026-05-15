/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_LIST_RECORD_H
#define PACKET_LIST_RECORD_H

#include <config.h>

#include <epan/cfile.h>

#include <epan/column.h>
#include <epan/packet.h>

#include <QByteArray>
#include <QCache>
#include <QList>
#include <QVariant>

struct conversation;
struct _GStringChunk;

/**
 * @brief Represents a single record within the packet list.
 */
class PacketListRecord
{
public:
    /**
     * @brief Constructs a PacketListRecord.
     * @param frameData Pointer to the frame data for this record.
     */
    PacketListRecord(frame_data *frameData);

    /**
     * @brief Destroys the PacketListRecord.
     */
    virtual ~PacketListRecord();

    /**
     * @brief Ensure that the record is colorized.
     * @param cap_file The capture file containing the packet.
     */
    void ensureColorized(capture_file *cap_file);

    /**
     * @brief Return the string value for a column. Data is cached if possible.
     * @param cap_file The capture file containing the packet.
     * @param column The column index.
     * @param colorized Whether to fetch the colorized string.
     * @return The string value for the specified column.
     */
    const QString columnString(capture_file *cap_file, int column, bool colorized = false);

    /**
     * @brief Gets the underlying frame data.
     * @return Pointer to the frame data.
     */
    frame_data *frameData() const { return fdata_; }

    /**
     * @brief packet_list->col_to_text in gtk/packet_list_store.c
     * @param column The column index.
     * @return The corresponding text column.
     */
    static int textColumn(int column) { return cinfo_column_.value(column, -1); }

    /**
     * @brief Checks if the record is currently colorized up to date.
     * @return True if properly colorized, false otherwise.
     */
    bool colorized() { return colorized_ && (color_ver_ == rows_color_ver_); }

    /**
     * @brief Retrieves the conversation index.
     * @return The conversation index.
     */
    unsigned int conversation() { return conv_index_; }

    /**
     * @brief Get list of all matching color filters
     * @return Pointer to the GSList of matching color filters.
     */
    const GSList* matchingColorFilters() const { return color_filters_; }

    /**
     * @brief Check if packet has multiple color matches
     * @return True if there are multiple matches, false otherwise.
     */
    bool hasMultipleColors() const { return color_filter_count_ > 1; }

    /**
     * @brief Get count of matching color filters
     * @return The number of matched color filters.
     */
    int colorFilterCount() const { return color_filter_count_; }

    /**
     * @brief Calculates the size of the column text.
     * @param str The string to measure.
     * @return The text size in appropriate units.
     */
    int columnTextSize(const char *str);

    /**
     * @brief Invalidates the current colorized state, forcing a re-evaluation.
     */
    void invalidateColorized() { colorized_ = false; }

    /**
     * @brief Removes this specific record from the column text cache.
     */
    void invalidateRecord() { col_text_cache_.remove(fdata_->num); }

    /**
     * @brief Clears the column text cache for all records.
     */
    static void invalidateAllRecords() { col_text_cache_.clear(); }

    /**
     * @brief Sets the maximum capacity of the column text cache.
     *
     * In Qt 6, QCache maxCost is a qsizetype, but the QAbstractItemModel
     * number of rows is still an int, so we're limited to INT_MAX anyway.
     *
     * @param cost The maximum cost (capacity) for the cache.
     */
    static void setMaxCache(int cost) { col_text_cache_.setMaxCost(cost); }

    /**
     * @brief Resets the columns configuration.
     * @param cinfo Pointer to the new column information.
     */
    static void resetColumns(column_info *cinfo);

    /**
     * @brief Increments the global color version to reset colorization for all.
     */
    static void resetColorization() { rows_color_ver_++; }

    /**
     * @brief Sets whether packet dissection is currently paused.
     * @param paused True to pause dissection, false to resume.
     */
    static void setDissectionPaused(bool paused) { dissection_paused_ = paused; }

    /**
     * @brief Gets the number of lines this record spans.
     * @return The line count.
     */
    inline int lineCount() { return lines_; }

    /**
     * @brief Gets whether the line count has changed.
     * @return Non-zero if changed, zero otherwise.
     */
    inline int lineCountChanged() { return line_count_changed_; }

    /**
     * @brief Sets the logical row index for this record.
     * @param row The row index.
     */
    inline void setRow(int row) { row_ = row; }

    /**
     * @brief Gets the logical row index of this record.
     * @return The row index.
     */
    inline int row() const { return row_; }

    /**
     * @brief Gets the highest expert information severity found in the packet.
     * @return The expert severity level.
     */
    inline uint32_t expertSeverity() const { return expert_severity_; }

private:
    static QCache<uint32_t, QStringList> col_text_cache_; /**< The column text for some columns */
    static bool dissection_paused_; /**< Flag indicating if dissection is globally paused. */

    frame_data *fdata_; /**< Pointer to the underlying frame data. */
    int lines_; /**< The number of lines the record spans. */
    bool line_count_changed_; /**< Flag indicating if the line count has changed. */
    static QMap<int, int> cinfo_column_; /**< Mapping from column index to text column index. */

    static unsigned int rows_color_ver_; /**< Has this record been colorized? (global version track) */
    unsigned int color_ver_; /**< The local colorization version for this record. */
    bool colorized_; /**< Flag indicating if this record has been evaluated for colors. */

    unsigned int conv_index_; /**< Conversation. Used by RelatedPacketDelegate */

    bool read_failed_; /**< Flag indicating if reading the frame data failed. */
    int row_; /**< The logical row index in the model. */
    uint32_t expert_severity_; /**< The highest expert information severity flag. */

    GSList *color_filters_; /**< All matching color filters (only if multi-color enabled) */
    int color_filter_count_; /**< The count of matching color filters. */

    /**
     * @brief Dissects the packet to evaluate columns and/or coloring.
     * @param cap_file The capture file containing the packet.
     * @param dissect_columns True to run dissection for column data.
     * @param dissect_color True to run dissection for color filters.
     */
    void dissect(capture_file *cap_file, bool dissect_columns, bool dissect_color = false);

    /**
     * @brief Populates the cache with column strings based on the dissected packet.
     * @param cinfo Pointer to the column information structure.
     */
    void cacheColumnStrings(column_info *cinfo);
};

#endif // PACKET_LIST_RECORD_H
