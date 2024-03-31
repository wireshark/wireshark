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

#include "cfile.h"

#include <epan/column.h>
#include <epan/packet.h>

#include <QByteArray>
#include <QCache>
#include <QList>
#include <QVariant>

struct conversation;
struct _GStringChunk;

class PacketListRecord
{
public:
    PacketListRecord(frame_data *frameData);
    virtual ~PacketListRecord();

    // Ensure that the record is colorized.
    void ensureColorized(capture_file *cap_file);
    // Return the string value for a column. Data is cached if possible.
    const QString columnString(capture_file *cap_file, int column, bool colorized = false);
    frame_data *frameData() const { return fdata_; }
    // packet_list->col_to_text in gtk/packet_list_store.c
    static int textColumn(int column) { return cinfo_column_.value(column, -1); }
    bool colorized() { return colorized_ && (color_ver_ == rows_color_ver_); }
    unsigned int conversation() { return conv_index_; }

    int columnTextSize(const char *str);

    void invalidateColorized() { colorized_ = false; }
    void invalidateRecord() { col_text_cache_.remove(fdata_->num); }
    static void invalidateAllRecords() { col_text_cache_.clear(); }
    /* In Qt 6, QCache maxCost is a qsizetype, but the QAbstractItemModel
     * number of rows is still an int, so we're limited to INT_MAX anyway.
     */
    static void setMaxCache(int cost) { col_text_cache_.setMaxCost(cost); }
    static void resetColumns(column_info *cinfo);
    static void resetColorization() { rows_color_ver_++; }

    inline int lineCount() { return lines_; }
    inline int lineCountChanged() { return line_count_changed_; }

private:
    /** The column text for some columns */
    static QCache<uint32_t, QStringList> col_text_cache_;

    frame_data *fdata_;
    int lines_;
    bool line_count_changed_;
    static QMap<int, int> cinfo_column_;

    /** Has this record been colorized? */
    static unsigned int rows_color_ver_;
    unsigned int color_ver_;
    bool colorized_;

    /** Conversation. Used by RelatedPacketDelegate */
    unsigned int conv_index_;

    bool read_failed_;

    void dissect(capture_file *cap_file, bool dissect_columns, bool dissect_color = false);
    void cacheColumnStrings(column_info *cinfo);
};

#endif // PACKET_LIST_RECORD_H
