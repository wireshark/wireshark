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

#include <glib.h>

#include "cfile.h"

#include <epan/column.h>
#include <epan/packet.h>

#include <QByteArray>
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
    bool colorized() { return colorized_; }
    unsigned int conversation() { return conv_index_; }

    int columnTextSize(const char *str);
    static void invalidateAllRecords() { col_data_ver_++; }
    static void resetColumns(column_info *cinfo);
    static void resetColorization() { rows_color_ver_++; }

    inline int lineCount() { return lines_; }
    inline int lineCountChanged() { return line_count_changed_; }

private:
    /** The column text for some columns */
    QStringList col_text_;

    frame_data *fdata_;
    int lines_;
    bool line_count_changed_;
    static QMap<int, int> cinfo_column_;

    /** Data versions. Used to invalidate col_text_ */
    static unsigned col_data_ver_;
    unsigned data_ver_;
    /** Has this record been colorized? */
    static unsigned int rows_color_ver_;
    unsigned int color_ver_;
    bool colorized_;

    /** Conversation. Used by RelatedPacketDelegate */
    unsigned int conv_index_;

    bool read_failed_;

    void dissect(capture_file *cap_file, bool dissect_color = false);
    void cacheColumnStrings(column_info *cinfo);
};

#endif // PACKET_LIST_RECORD_H
